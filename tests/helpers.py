"""测试辅助：临时目录、即时密钥、签名镜像构造。"""

from __future__ import annotations

import os
import tempfile
import unittest

from ota.keys import generate_keypair, save_private_key, save_public_key
from ota.manifest import sha256_hex, sign_manifest
from ota.image import build_image


class OTATestCase(unittest.TestCase):
    """每个用例独立的临时设备目录 + 独立测试密钥对。"""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ota-test-")
        self.devdir = os.path.join(self.tmpdir, "dev")
        self.keydir = os.path.join(self.tmpdir, "keys")
        os.makedirs(self.keydir)
        self.private_key, self.public_key = generate_keypair()
        self.priv_path = os.path.join(self.keydir, "priv.pem")
        self.pub_path = os.path.join(self.keydir, "pub.pem")
        save_private_key(self.private_key, self.priv_path)
        save_public_key(self.public_key, self.pub_path)

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ---- 镜像/manifest 工厂 ----

    def make_signed_image(
        self,
        version: str,
        health: str = "good",
        payload_size: int = 64,
        name: str | None = None,
        private_key=None,
    ) -> tuple[bytes, "object", str, str]:
        """构造并签名一个镜像，写入临时目录，返回 (image_bytes, manifest, 镜像路径, manifest路径)。"""
        private_key = private_key or self.private_key
        data = build_image(version=version, health=health, payload_size=payload_size)
        image_name = name or f"firmware-{version}.bin"
        image_path = os.path.join(self.tmpdir, image_name)
        manifest_path = os.path.join(self.tmpdir, image_name + ".json")
        fields = {
            "version": version,
            "image": image_name,
            "size": len(data),
            "sha256": sha256_hex(data),
            "created_at": "2026-09-28T00:00:00Z",
        }
        manifest = sign_manifest(fields, private_key)
        with open(image_path, "wb") as f:
            f.write(data)
        manifest.save(manifest_path)
        return data, manifest, image_path, manifest_path

    def provision_device(self, version: str = "1.0.0", payload_size: int = 64):
        """烧录出厂固件并返回 (device, image_bytes, manifest)。"""
        from ota.device import Device

        data, manifest, image_path, manifest_path = self.make_signed_image(
            version, payload_size=payload_size
        )
        Device.provision(
            self.devdir,
            public_key_path=self.pub_path,
            factory_manifest_path=manifest_path,
            factory_image_path=image_path,
        )
        return Device(self.devdir), data, manifest

    def reload_device(self):
        """重新打开设备 —— 模拟设备重启（会触发 _reconcile）。"""
        from ota.device import Device

        return Device(self.devdir)

    # ---- 断言辅助 ----

    def assert_active_bootable(self, dev, expected_version: str | None = None):
        """核心不变量：active 槽位完整、哈希一致、镜像可解析并可正常启动。

        该检查不改变设备状态（只读校验，不调用 boot()）。
        """
        from ota.storage import SLOT_VALID

        state = dev.snapshot()
        self.assertEqual(state["boot_state"], "normal")
        slot = state["active_slot"]
        meta = state["slots"][slot]
        self.assertEqual(meta["status"], SLOT_VALID)
        self.assertTrue(dev.storage.has_slot_image(slot))
        self.assertEqual(dev.storage.slot_sha256(slot), meta["sha256"])
        health, reason = dev._check_candidate_health(slot)
        self.assertIsNone(reason, msg=f"活动槽位不可启动: {reason}")
        self.assertEqual(health, "good")
        if expected_version is not None:
            self.assertEqual(meta["version"], expected_version)
        return slot

    def log_events(self, dev):
        return [entry["event"] for entry in dev.logs()]
