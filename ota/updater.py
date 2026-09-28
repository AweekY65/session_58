"""OTA 更新器：编排"验证 → 策略 → 写非活动槽 → 复核 → 原子切换"。

更新器只接收 Ed25519 *公钥*，用于验证固件包签名；它永远不需要、
也不读取私钥（私钥只在 tools/build_firmware.py 打包测试镜像时使用）。

更新阶段（任一阶段异常中断，设备仍指向完整可启动的槽位）：

1. verify_package  用公钥验证 manifest 签名，再验镜像大小与 SHA-256；
2. policy          版本策略检查（默认拒绝降级，白名单版本可回滚）；
3. write           只向 *非活动槽* 写镜像（临时文件暂存，写完才替换）；
4. postcheck       复核落盘槽位的大小与哈希；
5. switch          原子翻转 state.json 的启动槽位（旧槽成为回滚槽）。

切换之后由 Device.boot() 执行首次启动健康检查；未确认前掉电/重启，
下一次启动自动回滚。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional, Union

from nacl import signing

from .device import Device
from .errors import (
    OTAError,
    UpdateInterrupted,
)
from .manifest import verify_package
from .policy import VersionPolicy

PathLike = Union[str, os.PathLike]

# 更新阶段名（FaultInjector 可在这些点模拟掉电/异常中断）。
STAGE_VERIFY = "verify"
STAGE_POLICY = "policy"
STAGE_WRITE = "write"
STAGE_POSTCHECK = "postcheck"
STAGE_SWITCH = "switch"
ALL_STAGES = (STAGE_VERIFY, STAGE_POLICY, STAGE_WRITE,
              STAGE_POSTCHECK, STAGE_SWITCH)


@dataclass
class FaultInjector:
    """测试用故障注入：在指定阶段（或写入指定字节后）抛 UpdateInterrupted。

    模拟"更新过程中任意阶段异常中断"。
      stage:       在哪个阶段中断
      after_bytes: 仅 stage="write" 时有效，写入累计达到该字节数后中断
    """

    stage: str
    after_bytes: Optional[int] = None
    _triggered: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.stage not in ALL_STAGES:
            raise ValueError(f"未知的故障注入阶段: {self.stage}")
        if self.after_bytes is not None and self.stage != STAGE_WRITE:
            raise ValueError("after_bytes 只支持 write 阶段")

    def maybe_interrupt(self, stage: str, detail: str = "") -> None:
        if not self._triggered and self.stage == stage:
            self._triggered = True
            raise UpdateInterrupted(
                f"模拟异常中断（阶段={stage}）{(': ' + detail) if detail else ''}"
            )

    @property
    def triggered(self) -> bool:
        return self._triggered


@dataclass(frozen=True)
class UpdateReport:
    """一次成功更新的结果（此时新槽已 pending，等待首次启动与确认）。"""

    from_version: Optional[str]
    to_version: str
    target_slot: str
    package_dir: str
    stages_executed: tuple


class Updater:
    """无状态更新器（所有持久状态都在 Device 中）。"""

    def __init__(
        self,
        device: Device,
        public_key: signing.VerifyKey,
        policy: Optional[VersionPolicy] = None,
        chunk_size: int = 64 * 1024,
    ):
        self.device = device
        self.public_key = public_key
        self.policy = policy or VersionPolicy()
        self.chunk_size = chunk_size

    def update(
        self,
        package_dir: PathLike,
        fault: Optional[FaultInjector] = None,
    ) -> UpdateReport:
        """执行一次 OTA 更新。校验失败抛 SignatureError /
        ImageIntegrityError / VersionPolicyError；
        注入故障抛 UpdateInterrupted。成功返回 UpdateReport。
        """
        dev = self.device
        stages: List[str] = []

        def hit(stage: str, detail: str = "") -> None:
            if fault is not None:
                fault.maybe_interrupt(stage, detail)

        # 前置条件：没有未确认的更新。
        state = dev._require_committed()

        # 1. 验证整个固件包（签名 + 大小 + SHA-256）。
        hit(STAGE_VERIFY, "验证前")
        manifest, image_path = verify_package(package_dir, self.public_key)
        stages.append(STAGE_VERIFY)
        hit(STAGE_VERIFY, "验证后")

        # 2. 版本策略（默认拒绝降级，白名单可回滚）。
        hit(STAGE_POLICY)
        current_info = dev.slot_info(state["active_slot"])
        self.policy.check(current_info.version, manifest.version)
        stages.append(STAGE_POLICY)

        # 3. 写入非活动槽（设备当前可启动槽绝不受影响）。
        target_slot = (
            "b" if state["active_slot"] == "a" else "a"
        )
        hit(STAGE_WRITE, "写入前")

        def on_chunk(written: int) -> None:
            if (
                fault is not None
                and fault.stage == STAGE_WRITE
                and fault.after_bytes is not None
                and written >= fault.after_bytes
                and not fault.triggered
            ):
                fault._triggered = True
                raise UpdateInterrupted(
                    f"模拟写入中断：已写入 {written} 字节后掉电"
                )

        dev._stage_image(
            target_slot,
            image_path,
            manifest,
            chunk_size=self.chunk_size,
            on_chunk=on_chunk,
        )
        stages.append(STAGE_WRITE)
        hit(STAGE_WRITE, "写入后")

        # 4. 落盘复核：不信任写入，重新校验槽位完整性。
        hit(STAGE_POSTCHECK)
        if not dev.is_slot_bootable(target_slot):
            raise OTAError(f"写入后复核失败：槽位 {target_slot} 不完整")
        stages.append(STAGE_POSTCHECK)

        # 5. 原子切换启动槽位（一次性翻转 state.json）。
        hit(STAGE_SWITCH, "切换前")
        dev._switch_slot_atomically(target_slot, manifest)
        stages.append(STAGE_SWITCH)
        hit(STAGE_SWITCH, "切换后")

        dev._log(
            "update.complete",
            from_version=current_info.version,
            to_version=manifest.version,
            target_slot=target_slot,
            awaiting_boot_confirmation=True,
        )
        return UpdateReport(
            from_version=current_info.version,
            to_version=manifest.version,
            target_slot=target_slot,
            package_dir=os.fspath(package_dir),
            stages_executed=tuple(stages),
        )
