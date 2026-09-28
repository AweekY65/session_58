"""测试固件镜像格式。

镜像结构（全部为本地构造的字节串，不代表任何真实固件）：

    b"OTAFW001\\n"
    + UTF-8 JSON 头部（单行，含 version、health、payload_size、payload_sha256）
    + b"\\n"
    + 任意二进制载荷

镜像头部中的 ``health`` 字段用于模拟首次启动健康检查结果：
``good`` 表示固件能正常启动，``bad`` 表示启动即失败。
镜像整体（magic + 头 + 载荷）参与 manifest 的 SHA-256，
因此任何字节被篡改都会导致与 manifest 不匹配。
"""

from __future__ import annotations

import hashlib
import json

from .errors import ImageCorruptError

MAGIC = b"OTAFW001\n"
HEALTH_GOOD = "good"
HEALTH_BAD = "bad"


def build_image(version: str, health: str = HEALTH_GOOD, payload_size: int = 0,
                payload: bytes | None = None) -> bytes:
    """构造一个测试固件镜像。

    - payload 给定时直接使用（忽略 payload_size）；
    - 否则生成 payload_size 字节的确定性填充内容（不依赖随机数）。
    """
    if health not in (HEALTH_GOOD, HEALTH_BAD):
        raise ValueError(f"health 必须是 good 或 bad，得到: {health!r}")
    if payload is None:
        if payload_size < 0:
            raise ValueError("payload_size 不能为负")
        payload = _fill(payload_size)
    header = {
        "version": version,
        "health": health,
        "payload_size": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return MAGIC + header_bytes + b"\n" + payload


def _fill(size: int) -> bytes:
    """确定性填充：重复的 0..255 字节序列。"""
    block = bytes(range(256))
    q, r = divmod(size, 256)
    return block * q + block[:r]


def parse_image(data: bytes) -> dict:
    """解析镜像头，返回头部字典。镜像损坏时抛出 ImageCorruptError。"""
    if not data.startswith(MAGIC):
        raise ImageCorruptError("镜像 magic 不匹配，不是合法的 OTAFW 镜像")
    rest = data[len(MAGIC):]
    newline = rest.find(b"\n")
    if newline < 0:
        raise ImageCorruptError("镜像头部缺少结束换行符")
    try:
        header = json.loads(rest[:newline].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImageCorruptError(f"镜像头部不是合法 JSON: {exc}") from exc
    for field in ("version", "health", "payload_size", "payload_sha256"):
        if field not in header:
            raise ImageCorruptError(f"镜像头部缺少字段: {field}")
    payload = rest[newline + 1:]
    if len(payload) != header["payload_size"]:
        raise ImageCorruptError(
            f"镜像载荷长度 {len(payload)} 与头部声明 {header['payload_size']} 不一致"
        )
    if hashlib.sha256(payload).hexdigest() != header["payload_sha256"]:
        raise ImageCorruptError("镜像载荷 SHA-256 与头部声明不一致")
    return header


def image_health(data: bytes) -> str:
    """读取镜像声明的健康状态（good/bad）。"""
    return str(parse_image(data)["health"])


def image_version(data: bytes) -> str:
    """读取镜像头中的版本号。"""
    return str(parse_image(data)["version"])


def verify_image_against_manifest(data: bytes, manifest) -> None:
    """校验镜像整体大小与 SHA-256 是否与 manifest 一致。"""
    if len(data) != manifest.size:
        raise ImageCorruptError(
            f"镜像大小 {len(data)} 与 manifest 声明 {manifest.size} 不一致"
        )
    actual = hashlib.sha256(data).hexdigest()
    if actual != manifest.sha256:
        raise ImageCorruptError("镜像 SHA-256 与 manifest 声明不一致（镜像可能被篡改）")
    parse_image(data)  # 顺带校验镜像内部结构
