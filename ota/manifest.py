"""固件 manifest：元数据 + Ed25519 数字签名。

manifest 是一个 JSON 文档：

    {
      "version":    "1.1.0",                 # 语义化版本号
      "image":      "firmware-1.1.0.bin",    # 镜像文件名（仅作引用）
      "size":       4096,                    # 镜像字节数
      "sha256":     "<64 位十六进制摘要>",     # 镜像整体 SHA-256
      "created_at": "2026-09-28T10:00:00Z",
      "signature":  "<base64 Ed25519 签名>"
    }

签名对象是排除 signature 字段后的规范化 JSON
（sort_keys、无多余空白），保证可重复验签。
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import ManifestError, SignatureError

SIGNATURE_FIELD = "signature"
REQUIRED_FIELDS = ("version", "image", "size", "sha256", "created_at")


@dataclass(frozen=True)
class Manifest:
    """不可变的 manifest 视图。"""

    version: str
    image: str
    size: int
    sha256: str
    created_at: str
    signature: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "image": self.image,
            "size": self.size,
            "sha256": self.sha256,
            "created_at": self.created_at,
            SIGNATURE_FIELD: base64.b64encode(self.signature).decode("ascii"),
        }

    # ---- 签名原语 ----

    def signing_payload(self) -> bytes:
        return canonical_payload(self.to_dict())

    # ---- 序列化 ----

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True) + "\n"

    def save(self, path: str) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        tmp = os.path.join(directory, f".{os.path.basename(path)}.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(self.to_json())
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    # ---- 校验 ----

    def verify_signature(self, public_key: Ed25519PublicKey) -> None:
        """验签失败抛出 SignatureError。"""
        verify_signature(self.to_dict(), public_key)

    def verify_image(self, image_data: bytes) -> None:
        """校验镜像大小与 SHA-256；不符抛出 ImageCorruptError。"""
        # 局部 import 避免 image<->manifest 循环依赖
        from .image import verify_image_against_manifest

        verify_image_against_manifest(image_data, self)


def canonical_payload(doc: dict[str, Any]) -> bytes:
    """排除 signature 后的规范化 JSON 字节（即被签名的内容）。"""
    if SIGNATURE_FIELD not in doc:
        unsigned = doc
    else:
        unsigned = {k: v for k, v in doc.items() if k != SIGNATURE_FIELD}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(
    fields: dict[str, Any], private_key: Ed25519PrivateKey
) -> Manifest:
    """用私钥对 manifest 字段签名，构造完整 Manifest。"""
    for name in REQUIRED_FIELDS:
        if name not in fields:
            raise ManifestError(f"manifest 缺少必填字段: {name}")
    payload = canonical_payload(fields)
    signature = private_key.sign(payload)
    return Manifest(
        version=str(fields["version"]),
        image=str(fields["image"]),
        size=int(fields["size"]),
        sha256=str(fields["sha256"]),
        created_at=str(fields["created_at"]),
        signature=signature,
    )


def verify_signature(doc: dict[str, Any], public_key: Ed25519PublicKey) -> None:
    """对 manifest 字典验签。任何篡改都会导致签名不匹配。"""
    if not isinstance(doc, dict) or SIGNATURE_FIELD not in doc:
        raise SignatureError("manifest 中不存在 signature 字段")
    try:
        signature = base64.b64decode(doc[SIGNATURE_FIELD], validate=True)
    except Exception as exc:  # noqa: BLE001 - base64 错误统一转成验签错误
        raise SignatureError(f"signature 不是合法的 base64: {exc}") from exc
    try:
        public_key.verify(signature, canonical_payload(doc))
    except InvalidSignature as exc:
        raise SignatureError("manifest 签名验证失败（签名错误或内容被篡改）") from exc


def manifest_from_dict(doc: dict[str, Any]) -> Manifest:
    """从已验签的 JSON 字典构造 Manifest，并校验字段完整性。"""
    if not isinstance(doc, dict):
        raise ManifestError("manifest 必须是 JSON 对象")
    missing = [name for name in REQUIRED_FIELDS if name not in doc]
    if missing:
        raise ManifestError(f"manifest 缺少必填字段: {', '.join(missing)}")
    if SIGNATURE_FIELD not in doc:
        raise SignatureError("manifest 中不存在 signature 字段")
    try:
        signature = base64.b64decode(doc[SIGNATURE_FIELD], validate=True)
    except Exception as exc:  # noqa: BLE001
        raise SignatureError(f"signature 不是合法的 base64: {exc}") from exc
    if not isinstance(doc["size"], int) or doc["size"] < 0:
        raise ManifestError("manifest.size 必须是非负整数")
    if len(str(doc["sha256"])) != 64:
        raise ManifestError("manifest.sha256 必须是 64 位十六进制字符串")
    int(str(doc["sha256"]), 16)
    return Manifest(
        version=str(doc["version"]),
        image=str(doc["image"]),
        size=int(doc["size"]),
        sha256=str(doc["sha256"]).lower(),
        created_at=str(doc["created_at"]),
        signature=signature,
    )


def load_manifest(path: str) -> Manifest:
    """读取并解析 manifest（不验签 —— 调用方须再调用 verify_signature）。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"无法读取 manifest {path}: {exc}") from exc
    return manifest_from_dict(doc)


def load_and_verify(path: str, public_key: Ed25519PublicKey) -> Manifest:
    """读取 manifest 文件并验签，返回 Manifest。"""
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    verify_signature(doc, public_key)
    return manifest_from_dict(doc)


def sha256_hex(data: bytes) -> str:
    """便捷工具：计算字节串的 SHA-256 十六进制摘要。"""
    return hashlib.sha256(data).hexdigest()


def unsigned_view(manifest: Manifest) -> dict[str, Any]:
    """返回去掉 signature 的字段（测试辅助）。"""
    doc = manifest.to_dict()
    return {k: v for k, v in doc.items() if k != SIGNATURE_FIELD}


def with_tampered_field(manifest: Manifest, field: str, value: Any) -> dict[str, Any]:
    """在保留签名的情况下篡改某字段（测试辅助：必然验签失败）。"""
    doc = copy.deepcopy(manifest.to_dict())
    doc[field] = value
    return doc
