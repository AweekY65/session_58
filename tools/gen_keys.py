#!/usr/bin/env python3
"""生成一对本地测试用 Ed25519 密钥。

用法::

    python -m tools.gen_keys
    python -m tools.gen_keys --private keys/dev_private.key \\
        --public keys/dev_public.key --force

警告：生成的私钥只能用于给本地测试固件镜像签名，
绝不能用于真实设备，也不要在生产环境中分发。
"""

from __future__ import annotations

import argparse
import os
import sys

# 允许直接 `python tools/gen_keys.py` 运行。
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ota.keys import generate_test_keypair, save_keypair  # noqa: E402

DEFAULT_PRIVATE = os.path.join("keys", "test_private.key")
DEFAULT_PUBLIC = os.path.join("keys", "test_public.key")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="生成 Ed25519 本地测试密钥对")
    parser.add_argument("--private", default=DEFAULT_PRIVATE, help="私钥输出路径")
    parser.add_argument("--public", default=DEFAULT_PUBLIC, help="公钥输出路径")
    parser.add_argument(
        "--force", action="store_true", help="目标文件已存在时覆盖"
    )
    args = parser.parse_args(argv)

    for path in (args.private, args.public):
        if os.path.exists(path) and not args.force:
            parser.error(f"{path} 已存在（使用 --force 覆盖）")

    keys = generate_test_keypair()
    save_keypair(keys, args.private, args.public)
    print(f"已生成 Ed25519 测试密钥对：")
    print(f"  私钥（仅打包测试镜像用，勿分发）: {args.private}")
    print(f"  公钥（更新器持有）              : {args.public}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
