#!/usr/bin/env python3
"""端到端演示：用本地文件模拟完整的 OTA 生命周期。

场景：
  1. 设备出厂烧录 1.0.0（A 槽）；
  2. 升级到 2.0.0：验证签名/哈希 → 写 B 槽 → 原子切换 → 首检 → 确认；
  3. 演示降级默认被拒绝；
  4. 升级 3.0.0（写回 A 槽），首检失败 → 下次启动自动回滚 2.0.0；
  5. 配置回滚白名单后，合法回滚到 1.0.0。

运行: python demo.py
所有产物都在 ./_demo_workspace/ 下，纯本地，无任何网络访问。
"""

from __future__ import annotations

import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ota import Device, Updater
from ota.errors import VersionPolicyError
from ota.keys import generate_test_keypair, save_keypair
from ota.manifest import build_package
from ota.policy import VersionPolicy

WORKSPACE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_demo_workspace")
DEVICE_DIR = os.path.join(WORKSPACE, "device")
KEYS_DIR = os.path.join(WORKSPACE, "keys")
PACKAGES_DIR = os.path.join(WORKSPACE, "packages")

# 首检失败的"坏固件"版本集合。
BROKEN_VERSIONS = {"3.0.0"}


def health_check(slot: str, version, image_path: str) -> bool:
    """模拟设备侧健康检查：3.0.0 启动即失败，其余正常。"""
    ok = version not in BROKEN_VERSIONS
    print(f"      [健康检查] slot={slot} version={version} -> {'通过' if ok else '失败'}")
    return ok


def step(title: str) -> None:
    print()
    print("=" * 68)
    print(title)
    print("=" * 68)


def show(dev: Device) -> None:
    state = dev.state_snapshot()
    a, b = dev.slot_info("a"), dev.slot_info("b")
    print(f"  状态: active={state['active_slot']}  boot_status={state['boot_status']}")
    print(f"  A 槽: present={a.present} version={a.version} bootable={a.bootable}")
    print(f"  B 槽: present={b.present} version={b.version} bootable={b.bootable}")


def main() -> int:
    if os.path.isdir(WORKSPACE):
        shutil.rmtree(WORKSPACE)
    os.makedirs(KEYS_DIR)
    os.makedirs(PACKAGES_DIR)

    # 1) 测试密钥（私钥只给打包用；更新器只拿公钥）。
    keys = generate_test_keypair()
    private_path = os.path.join(KEYS_DIR, "test_private.key")
    public_path = os.path.join(KEYS_DIR, "test_public.key")
    save_keypair(keys, private_path, public_path)

    def pkg(version: str, content: bytes = None) -> str:
        path = os.path.join(PACKAGES_DIR, f"v{version}")
        build_package(path, content or f"firmware-{version}".encode(),
                      version, keys.private)
        return path

    # 2) 出厂烧录。
    step("1. 出厂烧录 1.0.0 到 A 槽")
    dev = Device.provision(
        DEVICE_DIR,
        factory_image=b"firmware-1.0.0",
        factory_version="1.0.0",
        health_check=health_check,
    )
    show(dev)

    # 3) 正常升级 1.0.0 -> 2.0.0。
    step("2. OTA 升级 1.0.0 -> 2.0.0（写 B 槽，原子切换，首检后确认）")
    updater = Updater(dev, keys.public)
    report = updater.update(pkg("2.0.0"))
    print(f"  更新结果: {report.from_version} -> {report.to_version}, "
          f"写入槽位={report.target_slot}")
    show(dev)
    r = dev.boot()
    print(f"  首次启动: success={r.success} 待确认={r.pending_confirmation}")
    dev.confirm_boot()
    print("  已确认，boot_status 回到 committed")
    show(dev)

    # 4) 默认拒绝降级。
    step("3. 尝试降级 2.0.0 -> 1.0.0（默认策略：拒绝）")
    try:
        updater.update(pkg("1.0.0"))
    except VersionPolicyError as e:
        print(f"  更新器拒绝: {e}")

    # 5) 升级到坏固件 3.0.0，首检失败，自动回滚。
    step("4. 升级 3.0.0（坏固件：健康检查失败 → 下次启动自动回滚 2.0.0）")
    updater.update(pkg("3.0.0"))
    first = dev.boot()
    print(f"  新固件首次启动: success={first.success}")
    # 模拟重启。
    dev = Device.open(DEVICE_DIR, health_check=health_check)
    second = dev.boot()
    print(f"  再次启动: rolled_back={second.rolled_back} "
          f"version={second.version} slot={second.slot}")
    show(dev)

    # 6) 配置白名单后合法回滚。
    step("5. 配置允许回滚版本 [1.0.0]，回滚 2.0.0 -> 1.0.0（写 A 槽）")
    policy = VersionPolicy.create(allowed_rollback_versions=("1.0.0",))
    Updater(dev, keys.public, policy=policy).update(pkg("1.0.0"))
    r = dev.boot()
    print(f"  回滚后首次启动: success={r.success} version={r.version}")
    dev.confirm_boot()
    show(dev)

    step("演示完成。查看设备日志：")
    log_path = os.path.join(DEVICE_DIR, "update.log")
    print(f"  tail -n 8 {log_path}")
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    for line in lines[-8:]:
        print("   ", line.rstrip())
    print(f"\n所有产物位于: {WORKSPACE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
