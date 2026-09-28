"""端到端场景测试。

覆盖：正常升级、签名错误、镜像篡改、manifest 篡改、降级拒绝、
白名单回滚、写入中断（多阶段掉电）、首次启动失败、未确认重启回滚、
未确认状态下拒绝更新、更新器不依赖私钥、日志记录等。

运行：
    python -m unittest discover -s tests -v
    或 ./run_tests.sh
"""

from __future__ import annotations

import json
import os

from ota import FaultInjector, Updater
from ota.errors import (
    ImageIntegrityError,
    InvalidStateError,
    NoBootableSlotError,
    SignatureError,
    UpdateInterrupted,
    VersionPolicyError,
)
from ota.manifest import IMAGE_FILENAME, MANIFEST_FILENAME, verify_package
from ota.policy import VersionPolicy, compare_versions, parse_version
from ota.updater import (
    STAGE_POSTCHECK,
    STAGE_SWITCH,
    STAGE_VERIFY,
    STAGE_WRITE,
)

from .helpers import OTATestCase


class ProvisioningTests(OTATestCase):
    def test_factory_provisioning_is_committed_and_bootable(self):
        dev = self.provision_device("1.0.0")
        self.assertEqual(dev.active_slot, "a")
        self.assertEqual(dev.active_version, "1.0.0")
        self.assertEqual(dev.boot_status, "committed")
        self.assertTrue(dev.slot_info("a").bootable)
        self.assertFalse(dev.slot_info("b").present)

        result = dev.boot()
        self.assertTrue(result.success)
        self.assertEqual(result.slot, "a")
        self.assertFalse(result.rolled_back)

    def test_state_file_is_valid_json_on_disk(self):
        dev = self.provision_device()
        with open(dev.state_path, "r", encoding="utf-8") as f:
            state = json.load(f)
        self.assertEqual(state["active_slot"], "a")
        self.assertEqual(state["boot_status"], "committed")


class NormalUpdateTests(OTATestCase):
    def test_full_upgrade_flow(self):
        """正常升级：验证 → 写 B 槽 → 切换 → 首次启动 → 确认。"""
        dev = self.provision_device("1.0.0")
        pkg = self.build_firmware("2.0.0")

        report = Updater(dev, self.public_key).update(pkg)
        self.assertEqual(report.from_version, "1.0.0")
        self.assertEqual(report.to_version, "2.0.0")
        self.assertEqual(report.target_slot, "b")

        # 切换后：active=b，等待首次启动；旧 A 槽仍完整可回滚。
        self.assertEqual(dev.active_slot, "b")
        self.assertEqual(dev.boot_status, "pending")
        self.assertTrue(dev.slot_info("a").bootable)
        self.assertTrue(dev.slot_info("b").bootable)

        # 首次启动新固件成功，但在 confirm 之前仍未提交。
        result = dev.boot()
        self.assertTrue(result.success)
        self.assertTrue(result.pending_confirmation)
        self.assertEqual(result.version, "2.0.0")
        self.assertEqual(dev.boot_status, "unconfirmed")

        # 掉电重开（状态从磁盘恢复）后确认，升级完成。
        dev = self.reopen_device()
        dev.confirm_boot()
        self.assertEqual(dev.boot_status, "committed")
        self.assertEqual(dev.active_slot, "b")
        self.assertEqual(dev.active_version, "2.0.0")

        # 确认后重启运行在 committed 的新固件上。
        result = self.reopen_device().boot()
        self.assertTrue(result.success)
        self.assertFalse(result.pending_confirmation)
        self.assertEqual(result.version, "2.0.0")

    def test_two_successive_upgrades_use_alternating_slots(self):
        dev = self.provision_device("1.0.0")
        updater = Updater(dev, self.public_key)

        updater.update(self.build_firmware("2.0.0", name="p200"))
        dev.boot()
        dev.confirm_boot()
        self.assertEqual(dev.active_slot, "b")

        updater.update(self.build_firmware("3.0.0", name="p300"))
        # update() 返回时已完成原子切换：非活动槽 A 被写入并激活。
        self.assertEqual(dev.active_slot, "a")
        dev.boot()
        dev.confirm_boot()
        self.assertEqual(dev.active_version, "3.0.0")

    def test_confirm_before_boot_is_rejected(self):
        dev = self.provision_device()
        Updater(dev, self.public_key).update(self.build_firmware("2.0.0"))
        with self.assertRaises(InvalidStateError):
            dev.confirm_boot()  # pending 状态，新固件还没启动


class SignatureTests(OTATestCase):
    def test_package_signed_by_unknown_key_is_rejected(self):
        """用另一把私钥签名 → 更新器持有原公钥，签名校验失败。"""
        dev = self.provision_device("1.0.0")
        evil_pkg = self.build_firmware("2.0.0", keys=self.other_keys)

        with self.assertRaises(SignatureError):
            Updater(dev, self.public_key).update(evil_pkg)

        # 失败后设备完全不变，仍运行旧固件。
        self.assertEqual(dev.active_slot, "a")
        self.assertEqual(dev.active_version, "1.0.0")
        self.assertEqual(dev.boot_status, "committed")

    def test_verify_package_directly_detects_bad_signature(self):
        pkg = self.build_firmware("1.0.0", keys=self.other_keys)
        with self.assertRaises(SignatureError):
            verify_package(pkg, self.public_key)

    def test_manifest_tampering_after_signing_is_rejected(self):
        """改 manifest 里的版本号但不重签 → canonical 字节变了，签名失败。"""
        dev = self.provision_device()
        pkg = self.build_firmware("2.0.0")
        self.tamper_manifest(pkg)

        with self.assertRaises(SignatureError):
            Updater(dev, self.public_key).update(pkg)
        self.assertEqual(dev.active_version, "1.0.0")

    def test_signature_hex_must_be_valid(self):
        pkg = self.build_firmware("2.0.0")
        path = os.path.join(pkg, MANIFEST_FILENAME)
        with open(path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        manifest["signature"] = "not-hex!!"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest, f)
        with self.assertRaises(SignatureError):
            Updater(self.provision_device(), self.public_key).update(pkg)


class ImageTamperTests(OTATestCase):
    def test_image_tampering_is_rejected_by_sha256(self):
        """镜像被改一字节：签名仍有效（签名只签 manifest），
        但 SHA-256 对不上 → 拒绝。"""
        dev = self.provision_device("1.0.0")
        pkg = self.build_firmware("2.0.0")
        self.tamper_image(pkg)

        with self.assertRaises(ImageIntegrityError):
            Updater(dev, self.public_key).update(pkg)
        self.assertEqual(dev.active_version, "1.0.0")

    def test_truncated_image_is_rejected_by_size(self):
        dev = self.provision_device("1.0.0")
        pkg = self.build_firmware("2.0.0")
        self.truncate_image(pkg)

        with self.assertRaises(ImageIntegrityError):
            Updater(dev, self.public_key).update(pkg)
        self.assertEqual(dev.active_version, "1.0.0")

    def test_slot_image_corrupt_before_boot_fails_and_rolls_back(self):
        """切换后、首次启动前篡改槽位镜像 → 启动失败，下次启动自动回滚。"""
        dev = self.provision_device("1.0.0")
        Updater(dev, self.public_key).update(self.build_firmware("2.0.0"))

        # 直接损坏 B 槽镜像（模拟落盘后损坏）。
        slot_img = dev._slot_image_path("b")
        with open(slot_img, "rb") as f:
            data = bytearray(f.read())
        data[0] ^= 0xFF
        with open(slot_img, "wb") as f:
            f.write(data)

        first = dev.boot()
        self.assertFalse(first.success)

        # 下一次启动必须自动回滚旧版本。
        second = self.reopen_device().boot()
        self.assertTrue(second.success)
        self.assertTrue(second.rolled_back)
        self.assertEqual(second.version, "1.0.0")
        self.assertEqual(second.slot, "a")


class VersionPolicyTests(OTATestCase):
    def test_downgrade_is_rejected_by_default(self):
        dev = self.provision_device("2.0.0")
        pkg = self.build_firmware("1.0.0")
        with self.assertRaises(VersionPolicyError):
            Updater(dev, self.public_key).update(pkg)
        self.assertEqual(dev.active_version, "2.0.0")
        self.assertEqual(dev.active_slot, "a")

    def test_downgrade_rejected_even_if_not_in_whitelist(self):
        dev = self.provision_device("2.0.0")
        policy = VersionPolicy.create(allowed_rollback_versions=("1.5.0",))
        pkg = self.build_firmware("1.0.0")
        with self.assertRaises(VersionPolicyError):
            Updater(dev, self.public_key, policy=policy).update(pkg)

    def test_explicitly_allowed_rollback_version(self):
        """白名单中的旧版本允许回滚，回滚后同样走首启+确认流程。"""
        dev = self.provision_device("2.0.0")
        policy = VersionPolicy.create(allowed_rollback_versions=("1.0.0",))

        # 先升级到 2.0.0 并确认，再回滚 1.0.0。
        updater = Updater(dev, self.public_key, policy=policy)
        updater.update(self.build_firmware("3.0.0", name="p300"))
        dev.boot()
        dev.confirm_boot()
        self.assertEqual(dev.active_version, "3.0.0")

        updater.update(self.build_firmware("1.0.0", name="p100-back"))
        result = dev.boot()
        self.assertTrue(result.success)
        self.assertEqual(result.version, "1.0.0")
        dev.confirm_boot()
        self.assertEqual(dev.active_version, "1.0.0")
        self.assertEqual(dev.boot_status, "committed")

    def test_version_comparison_helper(self):
        self.assertEqual(compare_versions("1.0.0", "1.0.0"), 0)
        self.assertEqual(compare_versions("1.0", "1.0.0"), 0)
        self.assertEqual(compare_versions("2.0.1", "2.0.0"), 1)
        self.assertEqual(compare_versions("1.9.9", "1.10.0"), -1)
        self.assertEqual(parse_version("v1.2.3-rc1"), (1, 2, 3, 0))


class InterruptionTests(OTATestCase):
    def _assert_device_still_boots_old_firmware(self, dev, version="1.0.0"):
        """中断后的核心不变量：设备仍指向完整可启动的旧槽。"""
        self.assertEqual(dev.boot_status, "committed")
        self.assertEqual(dev.active_version, version)
        self.assertTrue(dev.slot_info(dev.active_slot).bootable)
        result = self.reopen_device().boot()
        self.assertTrue(result.success)
        self.assertEqual(result.version, version)
        self.assertFalse(result.rolled_back)

    def test_interruption_before_write_leaves_active_slot_intact(self):
        dev = self.provision_device("1.0.0")
        updater = Updater(dev, self.public_key)
        with self.assertRaises(UpdateInterrupted):
            # stage=write 且未指定 after_bytes：在真正写入前中断。
            updater.update(
                self.build_firmware("2.0.0"),
                fault=FaultInjector(stage=STAGE_WRITE),
            )
        self._assert_device_still_boots_old_firmware(dev)

    def test_interruption_mid_write_leaves_active_slot_intact(self):
        """写非活动槽中途掉电：暂存文件作废，活动槽不受影响，可重试成功。"""
        dev = self.provision_device("1.0.0")
        pkg = self.build_firmware(
            "2.0.0", content=b"firmware-2.0.0" * 10000  # 约 130KB
        )
        updater = Updater(dev, self.public_key, chunk_size=4096)

        with self.assertRaises(UpdateInterrupted):
            updater.update(
                pkg, fault=FaultInjector(stage=STAGE_WRITE, after_bytes=20000)
            )
        self._assert_device_still_boots_old_firmware(dev)

        # B 槽还没有完整镜像（暂存文件不会被当作槽位镜像）。
        self.assertFalse(dev.slot_info("b").bootable)
        b_files = os.listdir(dev._slot_dir("b"))
        self.assertFalse(
            any(n == IMAGE_FILENAME for n in b_files),
            "写入中途失败不得留下被当作正式镜像的 image.bin",
        )

        # 掉电重开后重试同一更新，必须成功。
        dev = self.reopen_device()
        Updater(dev, self.public_key, chunk_size=4096).update(pkg)
        result = dev.boot()
        self.assertTrue(result.success)
        self.assertEqual(result.version, "2.0.0")

    def test_interruption_at_each_stage_preserves_bootability(self):
        """参数化：除 switch 之后外，各阶段中断设备都能启动旧固件。"""
        for stage in (STAGE_VERIFY, STAGE_POSTCHECK, STAGE_SWITCH):
            with self.subTest(stage=stage):
                self.setUp()
                try:
                    dev = self.provision_device("1.0.0")
                    fault = FaultInjector(stage=stage)
                    with self.assertRaises(UpdateInterrupted):
                        Updater(dev, self.public_key).update(
                            self.build_firmware(f"2.0.0-{stage}"), fault=fault
                        )
                    # switch 阶段注入点在切换之前，因此仍是旧固件。
                    self._assert_device_still_boots_old_firmware(dev)
                finally:
                    self.tearDown()

    def test_interruption_after_switch_rolls_back_on_next_boot(self):
        """切换槽位成功后、首次启动前掉电 → 下次启动跑新固件首检；
        若一直不确认，再次启动自动回滚旧版本。"""
        dev = self.provision_device("1.0.0")
        updater = Updater(dev, self.public_key)
        updater.update(self.build_firmware("2.0.0"))
        self.assertEqual(dev.boot_status, "pending")

        # 模拟"掉电"：重新打开设备后新固件首次启动成功但未确认。
        dev = self.reopen_device()
        first = dev.boot()
        self.assertTrue(first.success)
        self.assertTrue(first.pending_confirmation)

        # 又掉电了，且始终没有 confirm_boot → 下一次启动自动回滚。
        second = self.reopen_device().boot()
        self.assertTrue(second.success)
        self.assertTrue(second.rolled_back)
        self.assertEqual(second.version, "1.0.0")

        # 回滚后设备 committed，正常启动旧版本。
        self.assertEqual(self.reopen_device().boot_status, "committed")


class FirstBootFailureTests(OTATestCase):
    def test_failed_health_check_then_auto_rollback(self):
        """新固件首次启动健康检查失败 → 下一次启动自动回滚旧版本。"""
        # 健康检查：2.0.0 失败，其余版本通过。
        def health(slot, version, image_path):
            return version != "2.0.0"

        dev = self.provision_device("1.0.0", health_check=health)
        Updater(dev, self.public_key).update(self.build_firmware("2.0.0"))

        first = dev.boot()
        self.assertFalse(first.success)
        self.assertEqual(first.version, "2.0.0")
        self.assertFalse(first.rolled_back)  # 当次不回滚，下次启动回滚
        with self.assertRaises(InvalidStateError):
            dev.confirm_boot()  # 健康检查失败不能确认

        # 掉电后下次启动自动回滚。
        second = self.reopen_device(health_check=health).boot()
        self.assertTrue(second.success)
        self.assertTrue(second.rolled_back)
        self.assertEqual(second.slot, "a")
        self.assertEqual(second.version, "1.0.0")
        self.assertEqual(self.reopen_device().boot_status, "committed")

    def test_health_check_exception_counts_as_boot_failure(self):
        def health(slot, version, image_path):
            if version == "2.0.0":
                raise RuntimeError("simulated firmware crash")
            return True

        dev = self.provision_device("1.0.0", health_check=health)
        Updater(dev, self.public_key).update(self.build_firmware("2.0.0"))
        self.assertFalse(dev.boot().success)

        second = self.reopen_device(health_check=health).boot()
        self.assertTrue(second.rolled_back)
        self.assertEqual(second.version, "1.0.0")

    def test_rollback_when_new_firmware_never_confirmed(self):
        """新固件首检通过，但没有确认就重启 → 必须自动回滚。"""
        dev = self.provision_device("1.0.0")
        Updater(dev, self.public_key).update(self.build_firmware("2.0.0"))
        self.assertTrue(dev.boot().success)  # 首检通过，unconfirmed
        self.assertEqual(dev.boot_status, "unconfirmed")

        # 不调用 confirm_boot，直接"重启"。
        result = self.reopen_device().boot()
        self.assertTrue(result.rolled_back)
        self.assertEqual(result.version, "1.0.0")

    def test_update_rejected_while_previous_update_unconfirmed(self):
        """未确认新固件时下发另一个更新 → 拒绝，避免覆盖回滚槽。"""
        dev = self.provision_device("1.0.0")
        updater = Updater(dev, self.public_key)
        updater.update(self.build_firmware("2.0.0", name="p200"))
        dev.boot()  # unconfirmed

        with self.assertRaises(InvalidStateError):
            updater.update(self.build_firmware("2.1.0", name="p210"))

        # 回滚恢复后可以重新更新。
        self.reopen_device().boot()  # 自动回滚 → committed
        Updater(self.reopen_device(), self.public_key).update(
            self.build_firmware("2.1.0", name="p210b")
        )
        # 已切换到 2.1.0，但在首次启动确认前仍是 pending。
        reopened = self.reopen_device()
        self.assertEqual(reopened.active_version, "2.1.0")
        self.assertEqual(reopened.boot_status, "pending")


class SecurityBoundaryTests(OTATestCase):
    def test_updater_only_takes_public_key(self):
        """Updater 的构造参数只有公钥；更新流程不读取任何私钥文件。"""
        import inspect

        sig = inspect.signature(Updater.__init__)
        self.assertIn("public_key", sig.parameters)
        self.assertNotIn("private_key", sig.parameters)

        # 删掉私钥后，更新与验证仍正常（私钥只在打包阶段需要）。
        dev = self.provision_device("1.0.0")
        pkg = self.build_firmware("2.0.0")
        # 本测试里私钥从未落盘；再显式验证包只靠公钥即可通过。
        manifest, image_path = verify_package(pkg, self.public_key)
        self.assertEqual(manifest.version, "2.0.0")
        Updater(dev, self.public_key).update(pkg)
        self.assertTrue(dev.boot().success)

    def test_replayed_older_signed_package_blocked_by_policy(self):
        """即使是合法签名的旧包（重放攻击），降级策略也会拦截。"""
        dev = self.provision_device("3.0.0")
        old_pkg = self.build_firmware("2.0.0")  # 合法签名，但是旧版本
        with self.assertRaises(VersionPolicyError):
            Updater(dev, self.public_key).update(old_pkg)


class LoggingTests(OTATestCase):
    def test_update_and_rollback_are_logged(self):
        def health(slot, version, image_path):
            return version != "2.0.0"

        dev = self.provision_device("1.0.0", health_check=health)
        Updater(dev, self.public_key).update(self.build_firmware("2.0.0"))
        dev.boot()  # 失败
        self.reopen_device(health_check=health).boot()  # 回滚

        events = [e["event"] for e in dev.read_log()]
        self.assertIn("device.provisioned", events)
        self.assertIn("update.slot_switched", events)
        self.assertIn("update.complete", events)
        self.assertIn("boot.health_failed", events)
        self.assertIn("boot.rollback", events)

        rollback_entry = [e for e in dev.read_log()
                          if e["event"] == "boot.rollback"][-1]
        self.assertEqual(rollback_entry["rollback_slot"], "a")
        self.assertEqual(rollback_entry["version"], "1.0.0")


class NoBootableSlotTests(OTATestCase):
    def test_corrupt_active_with_no_fallback_raises(self):
        dev = self.provision_device("1.0.0")
        # 损坏 A 槽且 B 槽从未写入。
        path = dev._slot_image_path("a")
        with open(path, "wb") as f:
            f.write(b"garbage")
        with self.assertRaises(NoBootableSlotError):
            dev.boot()
