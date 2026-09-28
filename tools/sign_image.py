#!/usr/bin/env python3
"""本地测试镜像签名工具（离线“镜像工厂”）。

这是整个工程中 **唯一** 会读取 Ed25519 私钥的组件，用来模拟厂商在
出厂环境中构造并签名固件镜像。设备侧更新器（ota 包、ota.cli）只持有
公钥，任何时候都不要求、也无法访问私钥。

用法示例：

    # 生成密钥（只需一次）
    python3 -m ota.keys --dir /tmp/ota-demo/keys

    # 签名一个健康的 1.1.0 镜像
    python3 tools/sign_image.py \\
        --priv-key /tmp/ota-demo/keys/test_private.pem \\
        --image-out /tmp/ota-demo/fw110.bin \\
        --manifest-out /tmp/ota-demo/fw110.json \\
        --version 1.1.0 --size 4096

    # 签名一个“启动即失败”的镜像（用于演示健康检查回滚）
    python3 tools/sign_image.py ... --version 1.2.0 --health bad
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys

# 允许从仓库根目录直接运行该脚本
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ota.image import HEALTH_BAD, HEALTH_GOOD, build_image  # noqa: E402
from ota.keys import load_private_key  # noqa: E402
from ota.manifest import Manifest, sha256_hex, sign_manifest  # noqa: E402


def build_and_sign(
    private_key,
    version: str,
    image_name: str,
    health: str = HEALTH_GOOD,
    payload_size: int = 0,
    created_at: str | None = None,
) -> tuple[bytes, Manifest]:
    """构造测试镜像并签名 manifest，返回 (镜像字节, Manifest)。"""
    data = build_image(version=version, health=health, payload_size=payload_size)
    fields = {
        "version": version,
        "image": image_name,
        "size": len(data),
        "sha256": sha256_hex(data),
        "created_at": created_at
        or datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    manifest = sign_manifest(fields, private_key)
    return data, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="构造并用 Ed25519 私钥签名测试固件")
    parser.add_argument("--priv-key", required=True, help="Ed25519 私钥 PEM 路径")
    parser.add_argument("--image-out", required=True, help="签名镜像输出路径")
    parser.add_argument("--manifest-out", required=True, help="manifest 输出路径")
    parser.add_argument("--version", required=True, help="固件版本，例如 1.1.0")
    parser.add_argument(
        "--health",
        choices=(HEALTH_GOOD, HEALTH_BAD),
        default=HEALTH_GOOD,
        help="模拟的首次启动健康状态（默认 good）",
    )
    parser.add_argument("--size", type=int, default=0, help="载荷填充字节数")
    args = parser.parse_args()

    private_key = load_private_key(args.priv_key)
    image_name = os.path.basename(args.image_out)
    data, manifest = build_and_sign(
        private_key,
        version=args.version,
        image_name=image_name,
        health=args.health,
        payload_size=args.size,
    )

    os.makedirs(os.path.dirname(os.path.abspath(args.image_out)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.manifest_out)), exist_ok=True)
    with open(args.image_out, "wb") as f:
        f.write(data)
    manifest.save(args.manifest_out)

    print(f"已生成镜像:     {args.image_out} ({len(data)} 字节, health={args.health})")
    print(f"已生成 manifest: {args.manifest_out} (version={args.version})")
    print(f"SHA-256: {manifest.sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
