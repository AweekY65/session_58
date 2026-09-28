"""恢复与回滚测试：写入中断、首次启动失败、未确认重启、断电一致性。"""

from __future__ import annotations

from ota.errors import WriteInterrupted
from ota.storage import BOOT_NORMAL, BOOT_PENDING, SLOT_FAILED, SLOT_VALID

from tests.helpers import OTATestCase


class WriteInterruptionTest(OTATestCase):
    def test_fault_during_write_leaves_active_intact(self):
        dev, _, _ = self.provision_device("1.0.0", payload_size=64)
        # 足够大的镜像，使分块写入在中途可被打断
        _, _, image_path, manifest_path = self.make_signed_image(
            "1.1.0", payload_size=200_000
        )
        before = dev.snapshot()

        with self.assertRaises(WriteInterrupted):
            dev.update(manifest_path, image_path, fault_after_bytes=70_000)

        # active 槽位字节未被触碰，状态未切换
        self.assertEqual(dev.active_slot, "a")
        self.assertEqual(dev.boot_state, BOOT_NORMAL)
        self.assertEqual(
            dev.storage.slot_sha256("a"), before["slots"]["a"]["sha256"]
        )
        # 暂存文件已清理，目标槽位不存在陈旧文件
        self.assertFalse(__import__("os").path.isfile(dev.storage.tmp_path("b")))
        self.assertEqual(dev.state["slots"]["b"]["status"], "empty")
        self.assertIn("write_interrupted", self.log_events(dev))
        self.assert_active_bootable(dev, "1.0.0")

    def test_device_restarts_after_interrupted_write(self):
        dev, _, _ = self.provision_device("1.0.0", payload_size=64)
        _, _, image_path, manifest_path = self.make_signed_image(
            "1.1.0", payload_size=150_000
        )
        with self.assertRaises(WriteInterrupted):
            dev.update(manifest_path, image_path, fault_after_bytes=30_000)

        # 模拟重启：重新构造设备，状态仍指向完整可启动的 A
        dev = self.reload_device()
        self.assertEqual(dev.boot_state, BOOT_NORMAL)
        self.assertEqual(dev.active_version(), "1.0.0")
        self.assert_active_bootable(dev, "1.0.0")

    def test_retry_after_interrupted_write_succeeds(self):
        dev, _, _ = self.provision_device("1.0.0", payload_size=64)
        _, _, image_path, manifest_path = self.make_signed_image(
            "1.1.0", payload_size=150_000
        )
        with self.assertRaises(WriteInterrupted):
            dev.update(manifest_path, image_path, fault_after_bytes=10)

        # 清理临时状态（重新打开设备）后重试，更新成功
        dev = self.reload_device()
        dev.update(manifest_path, image_path)
        dev.boot()
        dev.confirm()
        self.assertEqual(dev.active_version(), "1.1.0")

    def test_crash_after_slot_replace_keeps_booting_old_firmware(self):
        # 槽位文件已 os.replace 落盘，但 state.json 尚未切换时断电：
        # state 仍完整指向旧槽位；新槽位文件虽存在却未登记，重启后不受影响。
        dev, _, _ = self.provision_device("1.0.0")
        _, _, image_path, manifest_path = self.make_signed_image("1.1.0")

        with self.assertRaises(WriteInterrupted):
            dev.update(
                manifest_path, image_path, crash_after_replace=True
            )

        dev = self.reload_device()
        self.assertEqual(dev.boot_state, BOOT_NORMAL)
        self.assertEqual(dev.boot_slot, "a")
        self.assertEqual(dev.active_version(), "1.0.0")
        self.assert_active_bootable(dev, "1.0.0")
        # 同一更新可重新执行并成功
        dev.update(manifest_path, image_path)
        dev.boot()
        dev.confirm()
        self.assertEqual(dev.active_version(), "1.1.0")


class FirstBootFailureTest(OTATestCase):
    def test_bad_health_firmware_rolls_back_immediately(self):
        dev, _, _ = self.provision_device("1.0.0")
        _, _, image_path, manifest_path = self.make_signed_image(
            "1.1.0", health="bad"
        )  # 合法签名，但启动健康检查会失败
        dev.update(manifest_path, image_path)
        self.assertEqual(dev.boot_state, BOOT_PENDING)

        result = dev.boot()
        self.assertTrue(result.rolled_back)
        self.assertEqual(result.rollback_from, "b")
        self.assertIn("健康", result.rollback_reason)

        # 已自动回滚：启动指针恢复到 A，候选槽位标记 failed
        self.assertEqual(dev.boot_state, BOOT_NORMAL)
        self.assertEqual(dev.boot_slot, "a")
        self.assertEqual(dev.active_slot, "a")
        self.assertEqual(dev.state["slots"]["b"]["status"], SLOT_FAILED)
        self.assertIn("rollback", self.log_events(dev))

        # 下一次启动进入旧版本 1.0.0
        result2 = dev.boot()
        self.assertEqual(result2.booted_slot, "a")
        self.assertEqual(result2.booted_version, "1.0.0")
        self.assertFalse(result2.rolled_back)

    def test_rollback_rejected_candidate_cannot_be_confirmed(self):
        dev, _, _ = self.provision_device("1.0.0")
        _, _, image_path, manifest_path = self.make_signed_image("1.1.0", health="bad")
        dev.update(manifest_path, image_path)
        dev.boot()  # 失败并回滚

        from ota.errors import InvalidStateError

        with self.assertRaises(InvalidStateError):
            dev.confirm()

    def test_bad_health_rollback_survives_restart(self):
        dev, _, _ = self.provision_device("1.0.0")
        _, _, image_path, manifest_path = self.make_signed_image("1.1.0", health="bad")
        dev.update(manifest_path, image_path)

        # 更新后重启，pending 保持；boot 仍正确识别坏镜像并回滚
        dev = self.reload_device()
        self.assertEqual(dev.boot_state, BOOT_PENDING)
        result = dev.boot()
        self.assertTrue(result.rolled_back)

        dev = self.reload_device()
        self.assertEqual(dev.active_version(), "1.0.0")
        self.assert_active_bootable(dev, "1.0.0")

    def test_corrupted_candidate_before_first_boot_recovered_on_restart(self):
        # pending 期间槽位被物理损坏 → 重启 reconcile 直接回到 active
        dev, _, _ = self.provision_device("1.0.0")
        _, _, image_path, manifest_path = self.make_signed_image("1.1.0")
        dev.update(manifest_path, image_path)
        with open(dev.storage.slot_path("b"), "r+b") as f:
            f.seek(-1, 2)
            f.write(b"\x00")

        dev = self.reload_device()
        self.assertEqual(dev.boot_state, BOOT_NORMAL)
        self.assertEqual(dev.boot_slot, "a")
        self.assertEqual(dev.state["slots"]["b"]["status"], SLOT_FAILED)
        self.assert_active_bootable(dev, "1.0.0")


class UnconfirmedRebootTest(OTATestCase):
    def test_reboot_without_confirm_rolls_back(self):
        dev, _, _ = self.provision_device("1.0.0")
        _, _, image_path, manifest_path = self.make_signed_image("1.1.0")
        dev.update(manifest_path, image_path)

        first = dev.boot()  # 首次启动成功，进入 testing
        self.assertEqual(first.booted_version, "1.1.0")
        self.assertEqual(dev.boot_state, "testing")

        # 用户/看门狗没有 confirm 就重启了 → 自动回滚旧版本
        result = dev.boot()
        self.assertTrue(result.rolled_back)
        self.assertEqual(result.rollback_from, "b")
        self.assertEqual(dev.boot_slot, "a")
        self.assertEqual(dev.active_slot, "a")
        self.assertEqual(dev.boot_state, BOOT_NORMAL)
        self.assertEqual(dev.state["slots"]["b"]["status"], SLOT_FAILED)

        # 再次启动进入的是旧固件
        again = dev.boot()
        self.assertEqual(again.booted_version, "1.0.0")

    def test_unconfirmed_reboot_after_device_power_cycle_rolls_back(self):
        dev, _, _ = self.provision_device("1.0.0")
        _, _, image_path, manifest_path = self.make_signed_image("1.1.0")
        dev.update(manifest_path, image_path)
        dev.boot()  # testing

        # 真实断电重开设备，testing 状态持久化；新的一次启动仍触发回滚
        dev = self.reload_device()
        self.assertEqual(dev.boot_state, "testing")
        result = dev.boot()
        self.assertTrue(result.rolled_back)
        self.assertEqual(dev.active_version(), "1.0.0")

    def test_confirmed_firmware_persists_across_restarts(self):
        dev, _, _ = self.provision_device("1.0.0")
        _, _, image_path, manifest_path = self.make_signed_image("1.1.0")
        dev.update(manifest_path, image_path)
        dev.boot()
        dev.confirm()

        dev = self.reload_device()
        self.assertEqual(dev.boot_state, BOOT_NORMAL)
        self.assertEqual(dev.active_slot, "b")
        result = dev.boot()
        self.assertEqual(result.booted_version, "1.1.0")
        self.assertFalse(result.rolled_back)


class InvariantTest(OTATestCase):
    def test_active_slot_bytes_never_during_update(self):
        # 更新全程 active 槽位的字节哈希保持不变
        dev, _, _ = self.provision_device("1.0.0", payload_size=64)
        active = dev.active_slot
        before_hash = dev.storage.slot_sha256(active)
        before_bytes = dev.storage.read_slot(active)

        _, _, image_path, manifest_path = self.make_signed_image(
            "1.1.0", payload_size=100_000
        )
        try:
            dev.update(manifest_path, image_path, fault_after_bytes=50_000)
        except WriteInterrupted:
            pass
        self.assertEqual(dev.storage.slot_sha256(active), before_hash)
        self.assertEqual(dev.storage.read_slot(active), before_bytes)

        dev = self.reload_device()
        dev.update(manifest_path, image_path)
        dev.boot()
        dev.confirm()
        # 提交后 active 已换成 B；旧 A 槽位内容仍与最初完全一致
        self.assertEqual(dev.storage.slot_sha256("a"), before_hash)

    def test_tmp_files_cleaned_on_reboot(self):
        import os

        dev, _, _ = self.provision_device("1.0.0")
        _, _, image_path, manifest_path = self.make_signed_image(
            "1.1.0", payload_size=100_000
        )
        with self.assertRaises(WriteInterrupted):
            dev.update(manifest_path, image_path, fault_after_bytes=100)
        self.reload_device()  # 重启清理
        for name in os.listdir(dev.storage.slots_dir):
            self.assertFalse(name.endswith(".tmp"))
