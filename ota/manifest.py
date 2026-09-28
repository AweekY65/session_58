"""固件 manifest 与本地固件包。

固件包是一个本地目录（不依赖任何压缩/外部存储）：

    <package_dir>/
        manifest.json     版本、镜像大小、SHA-256、签名
        image.bin         固件镜像本体

``manifest.json`` 结构（signature 只覆盖除 signature 之外的规范编码字节）::

    {
      "version": "1.2.0",
      "image":   "image.bin",
      "size":    12345,
      "sha256":  "<64 hex>",
      "signature": "<128 hex Ed25519，对 canonical manifest 的签名>"
    }

签名验证流程（verify_package）：
1. 用公钥验证 canonical manifest 的 Ed25519 签名（manifest 元数据防篡改）；
2. 重新计算镜像 SHA-256 并与 manifest 比对；
3. 校验镜像大小。
任一步失败都抛出异常，调用方绝不能激活该固件。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

from nacl import exceptions as nacl_exceptions
from nacl import signing

from ._atomic import read_json, sha256_bytes, sha256_file, write_json_atomic
from .errors import ImageIntegrityError, OTAError, SignatureError

PathLike = Union[str, os.PathLike]

IMAGE_FILENAME = "image.bin"
MANIFEST_FILENAME = "manifest.json"
SIGNATURE_KEY = "signature"


@dataclass(frozen=True)
class Manifest:
    """固件 manifest 的内存表示。"""

    version: str
    size: int
    sha256: str
    image: str = IMAGE_FILENAME
    signature: Optional[str] = None

    def to_dict(self, include_signature: bool = True) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "version": self.version,
            "image": self.image,
            "size": self.size,
            "sha256": self.sha256,
        }
        if include_signature and self.signature is not None:
            d[SIGNATURE_KEY] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Manifest":
        try:
            return cls(
                version=str(d["version"]),
                size=int(d["size"]),
                sha256=str(d["sha256"]),
                image=str(d.get("image", IMAGE_FILENAME)),
                signature=d.get(SIGNATURE_KEY),
            )
        except (KeyError, TypeError, ValueError) as e:
            raise OTAError(f"manifest 格式不合法: {e}") from e


def canonical_bytes(manifest: Union[Manifest, Dict[str, Any]]) -> bytes:
    """计算被签名的 canonical manifest 字节。

    固定 UTF-8、sort_keys、紧凑分隔符，使任何语言/机器上结果一致；
    签名字段本身被排除，签名不签自身。
    """
    if isinstance(manifest, Manifest):
        d = manifest.to_dict(include_signature=False)
    else:
        d = {k: v for k, v in manifest.items() if k != SIGNATURE_KEY}
    return json.dumps(
        d, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def sign_manifest(manifest: Manifest, private_key: signing.SigningKey) -> Manifest:
    """用测试私钥对 canonical manifest 做 Ed25519 签名。"""
    sig = private_key.sign(canonical_bytes(manifest)).signature
    return Manifest(
        version=manifest.version,
        size=manifest.size,
        sha256=manifest.sha256,
        image=manifest.image,
        signature=sig.hex(),
    )


def verify_manifest_signature(
    manifest: Union[Manifest, Dict[str, Any]], public_key: signing.VerifyKey
) -> None:
    """仅验证 manifest 签名；失败抛 SignatureError。"""
    if isinstance(manifest, dict):
        sig_hex = manifest.get(SIGNATURE_KEY)
    else:
        sig_hex = manifest.signature
    if not sig_hex:
        raise SignatureError("manifest 缺少数字签名")
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError as e:
        raise SignatureError("manifest 签名编码不合法") from e
    try:
        public_key.verify(canonical_bytes(manifest), sig)
    except nacl_exceptions.BadSignatureError as e:
        raise SignatureError("manifest 数字签名验证失败") from e


def build_package(
    package_dir: PathLike,
    image: bytes,
    version: str,
    private_key: signing.SigningKey,
) -> Manifest:
    """生成一个本地固件包：写镜像、计算 SHA-256、签名并写 manifest。

    仅供测试镜像生成工具使用，需要私钥。
    """
    package_dir = os.fspath(package_dir)
    os.makedirs(package_dir, exist_ok=True)
    image_path = os.path.join(package_dir, IMAGE_FILENAME)
    from ._atomic import write_bytes_atomic

    write_bytes_atomic(image_path, image)

    unsigned = Manifest(
        version=version,
        size=len(image),
        sha256=sha256_bytes(image),
    )
    signed = sign_manifest(unsigned, private_key)
    write_json_atomic(
        os.path.join(package_dir, MANIFEST_FILENAME), signed.to_dict()
    )
    return signed


def read_package(package_dir: PathLike) -> tuple:
    """读取本地固件包，返回 (Manifest, image_path)。不做任何验证。"""
    package_dir = os.fspath(package_dir)
    manifest_path = os.path.join(package_dir, MANIFEST_FILENAME)
    if not os.path.isfile(manifest_path):
        raise OTAError(f"固件包缺少 manifest: {manifest_path}")
    manifest = Manifest.from_dict(read_json(manifest_path))
    image_path = os.path.join(package_dir, manifest.image)
    if not os.path.isfile(image_path):
        raise OTAError(f"固件包缺少镜像文件: {image_path}")
    return manifest, image_path


def verify_package(
    package_dir: PathLike, public_key: signing.VerifyKey
) -> tuple:
    """完整验证固件包：签名 → 镜像大小 → SHA-256。

    成功返回 (Manifest, image_path)；任一校验失败抛
    SignatureError / ImageIntegrityError，且绝不向调用方放行该包。
    """
    manifest, image_path = read_package(package_dir)

    # 1. 数字签名（同时保护 version/size/sha256 等元数据）。
    verify_manifest_signature(manifest, public_key)

    # 2. 镜像大小。
    actual_size = os.path.getsize(image_path)
    if actual_size != manifest.size:
        raise ImageIntegrityError(
            f"镜像大小不匹配: manifest={manifest.size}, 实际={actual_size}"
        )

    # 3. 镜像 SHA-256。
    actual_sha = sha256_file(image_path)
    if actual_sha != manifest.sha256.lower():
        raise ImageIntegrityError("镜像 SHA-256 不匹配，镜像已被篡改或损坏")

    return manifest, image_path


__all__ = [
    "IMAGE_FILENAME",
    "MANIFEST_FILENAME",
    "Manifest",
    "build_package",
    "canonical_bytes",
    "read_package",
    "verify_package",
    "sign_manifest",
    "verify_manifest_signature",
]
