#!/usr/bin/env python3
"""用测试私钥构建一个本地固件包（manifest + 镜像 + Ed25519 签名）。

用法示例::

    # 用确定的文本内容生成 1.0.0 固件
    python -m tools.build_firmware --package packages/v1.0.0 \\
        --version 1.0.0 --content "firmware-1.0.0"

    # 生成指定大小的伪随机镜像（用 seed 保证可复现）
    python -m tools.build_firmware --package packages/v2.0.0 \\
        --version 2.0.0 --size 262144 --seed 42

    # 从已有文件构建
    python -m tools.build_firmware --package packages/v1.1.0 \\
        --version 1.1.0 --from-file ./some_image.bin
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ota.keys import load_private_key  # noqa: E402
from ota.manifest import build_package  # noqa: E402

DEFAULT_KEY = os.path.join("keys", "test_private.key")


def _deterministic_bytes(version: str, size: int, seed: int) -> bytes:
    """生成可复现的伪镜像字节（不需要任何外部库/服务）。"""
    base = f"firmware|version={version}|seed={seed}|".encode("utf-8")
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(hashlib.sha256(base + counter.to_bytes(8, "little")).digest())
        counter += 1
    return bytes(out[:size])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="构建已签名的本地测试固件包")
    parser.add_argument("--package", required=True, help="固件包输出目录")
    parser.add_argument("--version", required=True, help="固件版本，如 1.2.0")
    parser.add_argument(
        "--key", default=DEFAULT_KEY, help=f"测试私钥路径（默认 {DEFAULT_KEY}）"
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--content", help="直接用该文本（UTF-8）作为镜像内容")
    src.add_argument("--size", type=int, help="生成指定字节数的可复现伪镜像")
    src.add_argument("--from-file", help="从该文件读取镜像内容")
    parser.add_argument(
        "--seed", type=int, default=0, help="--size 模式的随机种子（默认 0）"
    )
    parser.add_argument(
        "--force", action="store_true", help="固件包目录已存在时允许写入"
    )
    args = parser.parse_args(argv)

    if os.path.exists(args.package) and os.listdir(args.package) and not args.force:
        parser.error(f"{args.package} 非空（使用 --force 覆盖其中文件）")

    if args.from_file:
        with open(args.from_file, "rb") as f:
            image = f.read()
    elif args.size is not None:
        if args.size < 0:
            parser.error("--size 不能为负数")
        image = _deterministic_bytes(args.version, args.size, args.seed)
    else:
        content = args.content if args.content is not None else f"firmware-{args.version}"
        image = content.encode("utf-8")

    if not os.path.isfile(args.key):
        parser.error(f"找不到测试私钥 {args.key}，请先运行: python -m tools.gen_keys")
    private_key = load_private_key(args.key)

    manifest = build_package(args.package, image, args.version, private_key)
    print(f"已构建固件包: {args.package}")
    print(f"  version : {manifest.version}")
    print(f"  size    : {manifest.size} bytes")
    print(f"  sha256  : {manifest.sha256}")
    print(f"  sig     : {manifest.signature[:32]}...（Ed25519）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
