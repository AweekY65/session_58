"""Ed25519 测试密钥管理。

- 打包工具（tools/build_firmware.py）使用 *私钥* 对 manifest 签名；
- 更新器（Updater）只接受并持有 *公钥*，永远不需要私钥。

私钥文件是 32 字节原始 Ed25519 seed，公钥文件是 32 字节原始公钥。
这些密钥仅供本地测试镜像生成，绝不可用于真实设备或生产环境。
"""

from __future__ import annotations

import os
from typing import NamedTuple, Union

from nacl import signing

PathLike = Union[str, os.PathLike]


class KeyPair(NamedTuple):
    private: signing.SigningKey
    public: signing.VerifyKey


def generate_test_keypair() -> KeyPair:
    """生成一对新的 Ed25519 测试密钥。"""
    sk = signing.SigningKey.generate()
    return KeyPair(private=sk, public=sk.verify_key)


def save_keypair(keys: KeyPair, private_path: PathLike, public_path: PathLike) -> None:
    """将私钥/公钥分别以原始字节写入文件（仅测试用途）。"""
    from ._atomic import write_bytes_atomic

    write_bytes_atomic(private_path, bytes(keys.private))
    write_bytes_atomic(public_path, bytes(keys.public))


def load_private_key(path: PathLike) -> signing.SigningKey:
    with open(os.fspath(path), "rb") as f:
        return signing.SigningKey(f.read())


def load_public_key(path: PathLike) -> signing.VerifyKey:
    with open(os.fspath(path), "rb") as f:
        return signing.VerifyKey(f.read())


def key_pair_from_seed(seed: bytes) -> KeyPair:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed 必须为 32 字节")
    sk = signing.SigningKey(seed)
    return KeyPair(private=sk, public=sk.verify_key)


def public_key_hex(verify_key: signing.VerifyKey) -> str:
    return bytes(verify_key).hex()


__all__ = [
    "KeyPair",
    "generate_test_keypair",
    "save_keypair",
    "load_private_key",
    "load_public_key",
    "key_pair_from_seed",
    "public_key_hex",
]
