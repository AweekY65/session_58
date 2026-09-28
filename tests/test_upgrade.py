"""正常升级、签名错误、镜像篡改、降级策略测试。"""

from __future__ import annotations

import json

from ota.errors import DowngradeRejected, ImageCorruptError, SignatureError
from ota.keys import generate_keypair, save_private_key
from ota.manifest import verify_signature
from ota.storage import BOOT_NORMAL, BOOT_PENDING, BOOT_TESTING, SLOT_VALID

from tests.helpers import OTATestCase


class NormalUpgradeTest(OTATestCase):
    def test_full_upgrade_a_to_b_and_back(self):
        dev, _, _ = self.provision_device("1.0.0")
        self.assertEqual(dev.active_slot, "a")
        self.assertEqual(dev.active_version(), "1.0.0")

        _, _, image_path, manifest_path = self.make_signed_image("1.1.0", payload_size=256)
        dev.update(manifest_path, image_path)

        # 更新只切换 boot 指针：active 仍是旧槽位 a
        self.assertEqual(dev.active_slot, "a")
        self.assertEqual(dev.boot_slot, "b")
        self.assertEqual(dev.boot_state, BOOT_PENDING)
        self.assertEqual(dev.state["slots"]["a"]["status"], SLOT_VALID)
        self.assertEqual(dev.state["slots"]["b"]["version"], "1.1.0")

        # 首次启动：健康检查通过，进入 testing（尚未提交）
        result = dev.boot()
        self.assertEqual(result.booted_slot, "b")
        self.assertEqual(result.booted_version, "1.1.0")
        self.assertEqual(dev.boot_state, BOOT_TESTING)
        self.assertEqual(dev.active_slot, "a")  # 确认前 active 不变

        # 确认后原子提交
        dev.confirm()
        self.assertEqual(dev.boot_state, BOOT_NORMAL)
        self.assertEqual(dev.active_slot, "b")
        self.assertEqual(dev.boot_slot, "b")
        self.assertEqual(dev.active_version(), "1.1.0")
        # 旧槽位仍完整保留（下一次更新的目标 + 回滚保险）
        self.assertEqual(dev.state["slots"]["a"]["status"], SLOT_VALID)
        self.assertEqual(dev.state["slots"]["a"]["version"], "1.0.0")

        # 再升一级：这次写入非活动槽位 a
        _, _, image_path2, manifest_path2 = self.make_signed_image("1.2.0")
        dev.update(manifest_path2, image_path2)
        self.assertEqual(dev.boot_slot, "a")
        dev.boot()
        dev.confirm()
        self.assertEqual(dev.active_slot, "a")
        self.assertEqual(dev.active_version(), "1.2.0")

        events = self.log_events(dev)
        for expected in (
            "factory_installed", "update_pending", "boot_ok", "confirmed",
            "update_pending", "boot_ok", "confirmed",
        ):
            self.assertIn(expected, events)

    def test_upgrade_survives_restart_before_confirm(self):
        dev, _, _ = self.provision_device("1.0.0")
        _, _, image_path, manifest_path = self.make_signed_image("1.1.0")
        dev.update(manifest_path, image_path)

        # 重启后状态保持 pending，仍可正常验证并确认
        dev = self.reload_device()
        self.assertEqual(dev.boot_state, BOOT_PENDING)
        dev.boot()
        dev = self.reload_device()
        self.assertEqual(dev.boot_state, BOOT_TESTING)
        dev.confirm()
        self.assertEqual(dev.active_version(), "1.1.0")

    def test_image_resolves_from_manifest_directory(self):
        # 不传 --image 时，按 manifest 的 image 字段同目录解析
        dev, _, _ = self.provision_device("1.0.0")
        _, _, _, manifest_path = self.make_signed_image("1.1.0")
        dev.update(manifest_path)  # 无 image_path
        self.assertEqual(dev.boot_state, BOOT_PENDING)


class BadSignatureTest(OTATestCase):
    def test_manifest_signed_by_other_key_rejected(self):
        dev, _, _ = self.provision_device("1.0.0")
        other_priv, _ = generate_keypair()
        _, _, image_path, manifest_path = self.make_signed_image(
            "1.1.0", private_key=other_priv
        )
        before = dev.snapshot()
        with self.assertRaises(SignatureError):
            dev.update(manifest_path, image_path)
        # 状态完全不变
        self.assertEqual(dev.snapshot(), before)
        self.assertIn("signature_rejected", self.log_events(dev))

    def test_manifest_field_tampered_after_signing_rejected(self):
        dev, _, _ = self.provision_device("1.0.0")
        _, manifest, _, manifest_path = self.make_signed_image("1.1.0")
        with open(manifest_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        doc["version"] = "2.0.0"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(doc, f)

        before = dev.snapshot()
        with self.assertRaises(SignatureError):
            dev.update(manifest_path)
        self.assertEqual(dev.snapshot(), before)

    def test_signature_bytes_tampered_rejected(self):
        dev, _, _ = self.provision_device("1.0.0")
        _, _, _, manifest_path = self.make_signed_image("1.1.0")
        with open(manifest_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        import base64

        sig = bytearray(base64.b64decode(doc["signature"]))
        sig[0] ^= 0xFF
        doc["signature"] = base64.b64encode(bytes(sig)).decode()
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        with self.assertRaises(SignatureError):
            dev.update(manifest_path)


class ImageTamperTest(OTATestCase):
    def test_image_byte_flipped_before_update_rejected(self):
        dev, _, _ = self.provision_device("1.0.0")
        data, _, image_path, manifest_path = self.make_signed_image("1.1.0")
        tampered = bytearray(data)
        tampered[-1] ^= 0x01
        with open(image_path, "wb") as f:
            f.write(tampered)

        before = dev.snapshot()
        with self.assertRaises(ImageCorruptError):
            dev.update(manifest_path, image_path)
        self.assertEqual(dev.snapshot(), before)
        self.assertIn("image_rejected", self.log_events(dev))
        # 被拒镜像绝不能被登记进任何槽位
        for meta in dev.snapshot()["slots"].values():
            if meta.get("version"):
                self.assertNotEqual(meta["version"], "1.1.0")

    def test_size_truncated_image_rejected(self):
        dev, _, _ = self.provision_device("1.0.0")
        data, _, image_path, manifest_path = self.make_signed_image("1.1.0")
        with open(image_path, "wb") as f:
            f.write(data[:-5])
        with self.assertRaises(ImageCorruptError):
            dev.update(manifest_path, image_path)
        self.assertEqual(dev.active_version(), "1.0.0")

    def test_slot_file_corrupted_after_write_never_confirmed(self):
        # 候选槽位落盘后被破坏：重启 reconcile 把它标 failed 并回到 active，
        # 损坏槽位永远无法被 confirm。
        dev, _, _ = self.provision_device("1.0.0")
        _, _, image_path, manifest_path = self.make_signed_image("1.1.0")
        dev.update(manifest_path, image_path)

        slot_b = dev.storage.slot_path("b")
        with open(slot_b, "r+b") as f:
            f.seek(0)
            f.write(b"XXXXXXXX")

        dev = self.reload_device()
        self.assertEqual(dev.boot_state, BOOT_NORMAL)
        self.assertEqual(dev.boot_slot, "a")
        self.assertEqual(dev.state["slots"]["b"]["status"], "failed")
        self.assert_active_bootable(dev, "1.0.0")
        with self.assertRaises(Exception):
            dev.confirm()  # 已回滚到 normal，confirm 非法

    def test_garbage_image_file_rejected(self):
        dev, _, _ = self.provision_device("1.0.0")
        _, _, image_path, manifest_path = self.make_signed_image("1.1.0")
        with open(image_path, "wb") as f:
            f.write(b"this is not a firmware image")
        with self.assertRaises(ImageCorruptError):
            dev.update(manifest_path, image_path)


class VersionPolicyTest(OTATestCase):
    def test_downgrade_rejected_by_default(self):
        dev, _, _ = self.provision_device("1.1.0")
        _, _, image_path, manifest_path = self.make_signed_image("1.0.0")
        before = dev.snapshot()
        with self.assertRaises(DowngradeRejected):
            dev.update(manifest_path, image_path)
        self.assertEqual(dev.snapshot(), before)
        self.assertIn("downgrade_rejected", self.log_events(dev))

    def test_equal_version_allowed(self):
        dev, _, _ = self.provision_device("1.1.0")
        _, _, image_path, manifest_path = self.make_signed_image(
            "1.1.0", payload_size=128
        )
        dev.update(manifest_path, image_path)  # 同版本重刷不视为降级
        self.assertEqual(dev.boot_state, BOOT_PENDING)

    def test_explicit_allowed_rollback_version(self):
        dev, _, _ = self.provision_device("1.1.0")
        _, _, image_path, manifest_path = self.make_signed_image("1.0.0")

        # 加入白名单后允许回滚
        dev.add_allowed_rollback_version("1.0.0")
        dev.update(manifest_path, image_path)
        dev.boot()
        dev.confirm()
        self.assertEqual(dev.active_version(), "1.0.0")
        self.assertIn("rollback_allowed", self.log_events(dev))

    def test_other_downgrade_still_rejected_with_whitelist(self):
        dev, _, _ = self.provision_device("2.0.0")
        dev.set_allowed_rollback_versions(["1.5.0"])
        _, _, image_path, manifest_path = self.make_signed_image("1.0.0")
        with self.assertRaises(DowngradeRejected):
            dev.update(manifest_path, image_path)

    def test_version_ordering_numeric_not_string(self):
        from ota.device import parse_version

        self.assertLess(parse_version("1.9.0"), parse_version("1.10.0"))
