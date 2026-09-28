"""测试共用辅助：临时设备目录、测试密钥、固件包构建与篡改工具。

所有测试都在 tempfile 临时目录里运行，不访问任何外部服务，
每个测试用例独立生成一次性 Ed25519 密钥对（私钥只用于打包测试镜像）。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from typing import Optional

from nacl import signing

from ota import Device, build_package
from ota.keys import KeyPair, generate_test_keypair
from ota.manifest import MANIFEST_FILENAME, IMAGE_FILENAME


class OTATestCase(unittest.TestCase):
    """每个用例一个独立的临时工作区。"""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ota-test-")
        self.device_dir = os.path.join(self.tmpdir, "device")
        self.keys = generate_test_keypair()
        self.other_keys = generate_test_keypair()
        self._pkg_counter = 0

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ---- 路径 ----

    def package_dir(self, name: str) -> str:
        return os.path.join(self.tmpdir, "packages", name)

    @property
    def public_key(self) -> signing.VerifyKey:
        return self.keys.public

    # ---- 设备 ----

    def provision_device(
        self,
        version: str = "1.0.0",
        content: Optional[bytes] = None,
        health_check=None,
    ) -> Device:
        if content is None:
            content = f"firmware-{version}".encode("utf-8")
        return Device.provision(
            self.device_dir,
            factory_image=content,
            factory_version=version,
            health_check=health_check,
        )

    def reopen_device(self, health_check=None) -> Device:
        """模拟掉电/进程重启后重新打开设备（状态全部从磁盘恢复）。"""
        return Device.open(self.device_dir, health_check=health_check)

    # ---- 固件包 ----

    def build_firmware(
        self,
        version: str,
        content: Optional[bytes] = None,
        *,
        keys: Optional[KeyPair] = None,
        name: Optional[str] = None,
    ) -> str:
        self._pkg_counter += 1
        pkg = self.package_dir(name or f"pkg-{version}-{self._pkg_counter}")
        if content is None:
            content = f"firmware-{version}".encode("utf-8")
        used = keys or self.keys
        build_package(pkg, content, version, used.private)
        return pkg

    # ---- 篡改工具 ----

    def tamper_image(self, package_dir: str) -> None:
        """翻转镜像第一个字节，制造篡改（签名仍有效，哈希必然失效）。"""
        path = os.path.join(package_dir, IMAGE_FILENAME)
        with open(path, "rb") as f:
            data = bytearray(f.read())
        data[0] ^= 0xFF
        with open(path, "wb") as f:
            f.write(data)

    def tamper_manifest(self, package_dir: str) -> None:
        """直接改 manifest 声明的版本但不重新签名 -> 签名校验失败。"""
        path = os.path.join(package_dir, MANIFEST_FILENAME)
        with open(path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        manifest["version"] = manifest["version"] + "-tampered"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest, f)

    def truncate_image(self, package_dir: str, keep: int = 1) -> None:
        """截断镜像文件（模拟损坏/写入不完整）。"""
        path = os.path.join(package_dir, IMAGE_FILENAME)
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(data[: max(0, len(data) - keep)])
