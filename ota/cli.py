"""设备侧命令行（只持有公钥，无私钥参数）。

子命令：
    init     初始化设备：烧录公钥与出厂固件（必须是合法签名镜像）
    status   查看 A/B 槽位与启动状态
    update   校验并写入更新到非活动槽位（可带 --allow-rollback 白名单）
    boot     模拟一次启动（含首次健康检查/自动回滚）
    confirm  确认当前 testing 固件健康，原子切换 active 槽位
    log      打印 JSONL 更新日志

示例：
    python3 -m ota.cli init --dir ./dev --pub-key keys/test_public.pem \\
        --factory-manifest fw100.json --factory-image fw100.bin
    python3 -m ota.cli update --dir ./dev --manifest fw110.json --image fw110.bin
    python3 -m ota.cli boot --dir ./dev
    python3 -m ota.cli confirm --dir ./dev
"""

from __future__ import annotations

import argparse
import json
import sys

from .device import Device
from .errors import OTAError


def cmd_init(args) -> int:
    Device.provision(
        args.dir,
        public_key_path=args.pub_key,
        factory_manifest_path=args.factory_manifest,
        factory_image_path=args.factory_image,
    )
    dev = Device(args.dir)
    print(f"设备已初始化: {args.dir}")
    print(_status_text(dev))
    return 0


def cmd_status(args) -> int:
    dev = Device(args.dir)
    print(_status_text(dev))
    return 0


def cmd_update(args) -> int:
    dev = Device(args.dir)
    for version in args.allow_rollback or []:
        dev.add_allowed_rollback_version(version)
    manifest = dev.update(args.manifest, args.image)
    print(
        f"更新已写入非活动槽位 {dev.boot_slot}（version={manifest.version}），"
        f"状态 pending，等待 boot 验证。"
    )
    return 0


def cmd_boot(args) -> int:
    dev = Device(args.dir)
    result = dev.boot()
    if result.rolled_back:
        print(f"启动失败，已自动回滚到旧版本。原因: {result.rollback_reason}")
        # 回滚本身意味着旧固件恢复为待启动；下一次 boot 会真正进入旧固件
        again = dev.boot()
        print(f"已从槽位 {again.booted_slot}（version={again.booted_version}）启动。")
        return 0
    if dev.boot_state == "testing":
        print(
            f"新固件在槽位 {result.booted_slot}（version={result.booted_version}）"
            f"首次启动健康检查通过，状态 testing；确认良好请执行 confirm，"
            f"否则下次启动将自动回滚。"
        )
    else:
        print(f"已从槽位 {result.booted_slot}（version={result.booted_version}）正常启动。")
    return 0


def cmd_confirm(args) -> int:
    dev = Device(args.dir)
    dev.confirm()
    print(f"已确认，active 槽位切换为 {dev.active_slot}（version={dev.active_version()}）。")
    return 0


def cmd_log(args) -> int:
    dev = Device(args.dir)
    for entry in dev.logs():
        print(json.dumps(entry, ensure_ascii=False, sort_keys=True))
    return 0


def _status_text(dev: Device) -> str:
    state = dev.snapshot()
    lines = [
        f"设备目录:   {dev.devdir}",
        f"active槽位: {state['active_slot']}（version={dev.active_version()}）",
        f"boot槽位:   {state['boot_slot']}",
        f"boot状态:   {state['boot_state']}",
        f"回滚白名单: {state.get('allowed_rollback_versions', [])}",
        "槽位详情:",
    ]
    for slot in ("a", "b"):
        meta = state["slots"][slot]
        if meta.get("status") == "valid":
            lines.append(
                f"  {slot}: status=valid version={meta['version']} "
                f"size={meta['size']} sha256={meta['sha256'][:16]}…"
            )
        else:
            lines.append(f"  {slot}: status={meta.get('status', 'empty')}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="本地安全固件 OTA 更新模拟器（设备侧）")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="初始化设备并烧录出厂固件")
    p_init.add_argument("--dir", required=True)
    p_init.add_argument("--pub-key", required=True, help="出厂烧录的 Ed25519 公钥")
    p_init.add_argument("--factory-manifest", required=True)
    p_init.add_argument("--factory-image", required=True)
    p_init.set_defaults(func=cmd_init)

    p_status = sub.add_parser("status", help="查看设备状态")
    p_status.add_argument("--dir", required=True)
    p_status.set_defaults(func=cmd_status)

    p_update = sub.add_parser("update", help="写入 OTA 更新到非活动槽位")
    p_update.add_argument("--dir", required=True)
    p_update.add_argument("--manifest", required=True)
    p_update.add_argument("--image", default=None, help="默认取 manifest 同目录的 image 字段")
    p_update.add_argument(
        "--allow-rollback",
        action="append",
        default=[],
        metavar="VERSION",
        help="把版本加入允许回滚白名单（可重复指定）",
    )
    p_update.set_defaults(func=cmd_update)

    p_boot = sub.add_parser("boot", help="模拟启动（含健康检查与自动回滚）")
    p_boot.add_argument("--dir", required=True)
    p_boot.set_defaults(func=cmd_boot)

    p_confirm = sub.add_parser("confirm", help="确认 testing 固件并提交槽位切换")
    p_confirm.add_argument("--dir", required=True)
    p_confirm.set_defaults(func=cmd_confirm)

    p_log = sub.add_parser("log", help="打印更新日志（JSONL）")
    p_log.add_argument("--dir", required=True)
    p_log.set_defaults(func=cmd_log)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except OTAError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
