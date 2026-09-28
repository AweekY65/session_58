"""Ed25519 测试密钥的生成与加载（PEM）。

测试密钥仅用于本地镜像签名与验证，不用于任何真实设备。
"""

from __future__ import annotations

import argparse
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

PRIVATE_NAME = "test_private.pem"
PUBLIC_NAME = "test_public.pem"


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """生成一对全新的 Ed25519 密钥。"""
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def save_private_key(priv: ed25519.Ed25519PrivateKey, path: str) -> None:
    data = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _atomic_write(path, data, mode=0o600)


def save_public_key(pub: ed25519.Ed25519PublicKey, path: str) -> None:
    data = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _atomic_write(path, data, mode=0o644)


def load_private_key(path: str) -> ed25519.Ed25519PrivateKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    assert isinstance(key, ed25519.Ed25519PrivateKey)
    return key


def load_public_key(path: str) -> ed25519.Ed25519PublicKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    assert isinstance(key, ed25519.Ed25519PublicKey)
    return key


def generate_and_save(keydir: str) -> tuple[str, str]:
    """在 keydir 下生成测试密钥对，返回 (私钥路径, 公钥路径)。"""
    os.makedirs(keydir, exist_ok=True)
    priv, pub = generate_keypair()
    priv_path = os.path.join(keydir, PRIVATE_NAME)
    pub_path = os.path.join(keydir, PUBLIC_NAME)
    save_private_key(priv, priv_path)
    save_public_key(pub, pub_path)
    return priv_path, pub_path


def _atomic_write(path: str, data: bytes, mode: int) -> None:
    """临时文件 + os.replace 原子落盘。"""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = os.path.join(directory, f".{os.path.basename(path)}.tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def main() -> None:
    parser = argparse.ArgumentParser(description="生成本地测试用 Ed25519 密钥对")
    parser.add_argument("--dir", required=True, help="密钥输出目录")
    args = parser.parse_args()
    priv_path, pub_path = generate_and_save(args.dir)
    print(f"私钥（仅镜像签名工具使用）: {priv_path}")
    print(f"公钥（烧录到模拟设备）:     {pub_path}")


if __name__ == "__main__":
    main()
