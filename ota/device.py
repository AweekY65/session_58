"""设备侧 A/B OTA 状态机。

状态转移一览（详见 README）::

                provision()
                    │
                    ▼
        ┌──────────────────────┐
        │ boot_state = normal  │◄──────────────────────────┐
        │ active = boot = A    │                           │
        └──────────┬───────────┘                           │
                   │ update() 写入非活动槽位 B，原子切换指针  │
                   ▼                                       │
        ┌──────────────────────┐    boot() 健康检查失败      │
        │ boot_state = pending │───────► _rollback() ───────┤
        │ boot = B, active = A │                           │
        └──────────┬───────────┘                           │
                   │ boot() 健康检查通过                     │
                   ▼                                       │
        ┌──────────────────────┐    未 confirm 再次 boot()  │
        │ boot_state = testing │───────► _rollback() ───────┤
        │ boot = B, active = A │                           │
        └──────────┬───────────┘                           │
                   │ confirm() 原子提交                     │
                   ▼                                       │
        ┌──────────────────────┐                           │
        │ boot_state = normal  │                           │
        │ active = boot = B    │                           │
        └──────────────────────┘  （A 仍完整保留，作为下次更新目标）

不变量：active_slot 指向的槽位在任何时刻都完整、可启动；
更新只触碰非活动槽位与 *.tmp 暂存文件。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization

from .errors import (
    BootFailed,
    DowngradeRejected,
    ImageCorruptError,
    InvalidStateError,
    SignatureError,
    WriteInterrupted,
)
from .image import image_health, parse_image, verify_image_against_manifest
from .keys import load_public_key
from .manifest import Manifest, load_and_verify
from .storage import (
    BOOT_NORMAL,
    BOOT_PENDING,
    BOOT_TESTING,
    SLOT_A,
    SLOT_B,
    SLOT_FAILED,
    SLOT_VALID,
    SLOTS,
    SLOT_EMPTY,
    SlotStorage,
    copy_public_key,
)


@dataclass
class BootResult:
    """一次 boot() 尝试的结果。"""

    booted_slot: str | None
    booted_version: str | None
    health: str | None
    rolled_back: bool = False
    rollback_from: str | None = None
    rollback_reason: str | None = None

    @property
    def running(self) -> bool:
        return self.booted_slot is not None


class Device:
    """模拟一台带 A/B 分区的本地设备。

    每次构造 Device 都相当于设备重新上电：会执行崩溃恢复（_reconcile），
    丢弃暂存文件、修正悬空的 pending/testing 指针。
    """

    def __init__(self, devdir: str):
        self.devdir = devdir
        self.storage = SlotStorage(devdir)
        if not self.storage.exists():
            raise FileNotFoundError(f"设备未初始化: {devdir}（缺少 state.json）")
        self.public_key = load_public_key(self.storage.pubkey_path)
        self.state: dict[str, Any] = self.storage.read_state()
        self._reconcile()

    # ------------------------------------------------------------------
    # 出厂
    # ------------------------------------------------------------------

    @classmethod
    def provision(
        cls,
        devdir: str,
        public_key_path: str,
        factory_manifest_path: str,
        factory_image_path: str,
    ) -> "Device":
        """初始化一台新设备：烧录公钥 + 出厂固件到 A 槽。

        出厂固件与普通更新一样必须通过签名与哈希校验 —— 模拟器中
        不存在“可信但未签名”的固件。
        """
        pem = copy_public_key(public_key_path, devdir)
        storage = SlotStorage.initialize(devdir, pem)
        public_key = load_public_key(storage.pubkey_path)
        manifest = load_and_verify(factory_manifest_path, public_key)
        with open(factory_image_path, "rb") as f:
            data = f.read()
        verify_image_against_manifest(data, manifest)
        if image_health(data) != "good":
            raise ValueError("出厂固件的健康标志必须是 good")

        storage.write_slot_from_data(SLOT_A, data, manifest.size, manifest.sha256)
        state = storage.read_state()
        state["slots"][SLOT_A] = _slot_meta(manifest)
        storage.write_state(state)
        storage.append_log(
            "factory_installed", slot=SLOT_A, version=manifest.version
        )

        device = object.__new__(cls)
        device.devdir = devdir
        device.storage = storage
        device.public_key = public_key
        device.state = state
        return device

    # ------------------------------------------------------------------
    # 状态访问
    # ------------------------------------------------------------------

    @property
    def active_slot(self) -> str:
        return self.state["active_slot"]

    @property
    def boot_slot(self) -> str:
        return self.state["boot_slot"]

    @property
    def boot_state(self) -> str:
        return self.state["boot_state"]

    def active_version(self) -> str | None:
        meta = self.state["slots"].get(self.active_slot, {})
        return meta.get("version") if meta.get("status") == SLOT_VALID else None

    def snapshot(self) -> dict[str, Any]:
        """返回状态的深拷贝（测试断言用）。"""
        import copy

        return copy.deepcopy(self.state)

    def logs(self) -> list[dict[str, Any]]:
        return self.storage.read_log()

    # ------------------------------------------------------------------
    # 版本策略
    # ------------------------------------------------------------------

    def set_allowed_rollback_versions(self, versions: list[str]) -> None:
        """显式配置允许回滚到的版本白名单（原子持久化）。"""
        self.state["allowed_rollback_versions"] = list(versions)
        self._persist()

    def add_allowed_rollback_version(self, version: str) -> None:
        versions = self.state.setdefault("allowed_rollback_versions", [])
        if version not in versions:
            versions.append(version)
            self._persist()

    def _check_version_policy(self, manifest: Manifest) -> None:
        current = self.active_version()
        if current is None:
            return  # 尚无活动固件（provision 之外不应出现）
        if parse_version(manifest.version) < parse_version(current):
            allowed = self.state.get("allowed_rollback_versions", [])
            if manifest.version not in allowed:
                self.storage.append_log(
                    "downgrade_rejected",
                    current=current,
                    requested=manifest.version,
                )
                raise DowngradeRejected(
                    f"拒绝降级：当前版本 {current}，目标版本 {manifest.version}；"
                    f"允许回滚的版本白名单: {allowed}"
                )
            self.storage.append_log(
                "rollback_allowed",
                current=current, requested=manifest.version,
            )

    # ------------------------------------------------------------------
    # 更新
    # ------------------------------------------------------------------

    def update(
        self,
        manifest_path: str,
        image_path: str | None = None,
        fault_after_bytes: int | None = None,
        crash_after_replace: bool = False,
    ) -> Manifest:
        """执行一次 OTA 更新。

        顺序（每一步失败都保证 active 槽位不受影响）：
        1. 读取并 **Ed25519 验签** manifest（先验签，后做任何事）；
        2. 校验镜像大小与 SHA-256（镜像篡改在此被拦截）；
        3. 版本策略：默认拒绝降级，白名单内版本允许回滚；
        4. 分块写入非活动槽位的 *.tmp（可注入 fault_after_bytes 模拟断电）；
        5. 复核暂存镜像 → os.replace 原子落盘；
        6. 单次原子写 state.json：登记槽位、boot_slot 指向候选、boot_state=pending。
        """
        if self.boot_state != BOOT_NORMAL:
            raise InvalidStateError(
                f"当前 boot_state={self.boot_state}，必须先确认或回滚上一次更新"
            )

        # 1. 验签（任何写入之前）
        try:
            manifest = load_and_verify(manifest_path, self.public_key)
        except SignatureError:
            self.storage.append_log("signature_rejected", manifest=manifest_path)
            raise

        # 2. 读镜像 + 哈希校验
        image_path = self._resolve_image_path(manifest_path, image_path, manifest)
        with open(image_path, "rb") as f:
            data = f.read()
        try:
            verify_image_against_manifest(data, manifest)
        except ImageCorruptError:
            self.storage.append_log(
                "image_rejected", reason="hash_or_size_mismatch",
                version=manifest.version,
            )
            raise

        # 3. 版本策略
        self._check_version_policy(manifest)

        # 4/5. 写入非活动槽位
        target = self._inactive_slot()
        self.storage.append_log(
            "update_started", target=target, version=manifest.version
        )
        try:
            self.storage.write_slot_from_data(
                target,
                data,
                manifest.size,
                manifest.sha256,
                fault_after_bytes=fault_after_bytes,
                crash_after_replace=crash_after_replace,
            )
        except (OSError, ImageCorruptError) as exc:
            self.storage.discard_tmp(target)
            interrupted = isinstance(exc, OSError)
            self.storage.append_log(
                "write_interrupted" if interrupted else "write_verification_failed",
                target=target,
                version=manifest.version,
                error=str(exc),
            )
            if interrupted:
                raise WriteInterrupted(str(exc)) from exc
            raise

        # 6. 原子切换启动指针（active_slot 保持不变）
        self.state["slots"][target] = _slot_meta(manifest)
        self.state["boot_slot"] = target
        self.state["boot_state"] = BOOT_PENDING
        self.state["boot_attempts"] = 0
        self._persist()
        self.storage.append_log("update_pending", slot=target, version=manifest.version)
        return manifest

    # ------------------------------------------------------------------
    # 启动 / 健康检查 / 回滚 / 确认
    # ------------------------------------------------------------------

    def boot(self) -> BootResult:
        """模拟一次启动。

        - normal：启动已确认的 active 槽位；
        - pending：对候选槽位做首次健康检查 —— 失败立即回滚，成功进入 testing；
        - testing：未确认就再次启动 —— 自动回滚旧版本。
        """
        state = self.state

        if state["boot_state"] == BOOT_NORMAL:
            return self._boot_active()

        candidate = state["boot_slot"]
        active = state["active_slot"]

        if state["boot_state"] == BOOT_TESTING:
            reason = "新固件未确认成功即重启，按策略自动回滚"
            return self._rollback(candidate, active, reason)

        # pending：首次启动健康检查
        health, reason = self._check_candidate_health(candidate)
        if health is None:
            return self._rollback(candidate, active, f"首次启动健康检查失败：{reason}")
        if health != "good":
            return self._rollback(
                candidate, active, "首次启动健康检查报告固件不健康（health=bad）"
            )

        version = state["slots"][candidate]["version"]
        state["boot_state"] = BOOT_TESTING
        state["boot_attempts"] = 1
        self._persist()
        self.storage.append_log(
            "boot_ok", slot=candidate, version=version, awaiting_confirm=True
        )
        return BootResult(
            booted_slot=candidate, booted_version=version, health="good"
        )

    def confirm(self) -> None:
        """确认 testing 中的新固件运行良好，原子提交为 active。"""
        if self.boot_state != BOOT_TESTING:
            raise InvalidStateError(
                f"仅 boot_state=testing 时可以 confirm，当前为 {self.boot_state}"
            )
        slot = self.state["boot_slot"]
        version = self.state["slots"][slot]["version"]
        self.state["active_slot"] = slot
        self.state["boot_state"] = BOOT_NORMAL
        self.state["boot_attempts"] = 0
        self._persist()
        self.storage.append_log("confirmed", slot=slot, version=version)

    def _boot_active(self) -> BootResult:
        """normal 状态下启动 active 槽位。"""
        slot = self.active_slot
        meta = self.state["slots"].get(slot, {})
        health, reason = self._check_candidate_health(slot)
        if health is None:
            # active 槽位在运行时损坏：尝试另一槽位（极端情况）
            other = self._inactive_slot()
            other_meta = self.state["slots"].get(other, {})
            if other_meta.get("status") == SLOT_VALID:
                self.storage.append_log(
                    "active_slot_corrupt_fallback", slot=slot, fallback=other,
                    reason=reason,
                )
                return BootResult(
                    booted_slot=other,
                    booted_version=other_meta["version"],
                    health="good",
                )
            raise BootFailed(f"活动槽位 {slot} 损坏且无备用槽位：{reason}")
        self.storage.append_log(
            "boot_normal", slot=slot, version=meta.get("version")
        )
        return BootResult(
            booted_slot=slot, booted_version=meta.get("version"), health=health
        )

    def _rollback(self, candidate: str, active: str, reason: str) -> BootResult:
        """回滚：恢复启动 active 旧槽位，候选槽位标记 failed。"""
        self.state["slots"].setdefault(candidate, {})["status"] = SLOT_FAILED
        self.state["boot_slot"] = active
        self.state["boot_state"] = BOOT_NORMAL
        self.state["boot_attempts"] = 0
        self._persist()
        self.storage.append_log(
            "rollback", candidate=candidate, restored=active, reason=reason
        )
        result = BootResult(
            booted_slot=None,
            booted_version=None,
            health=None,
            rolled_back=True,
            rollback_from=candidate,
            rollback_reason=reason,
        )
        return result

    # ------------------------------------------------------------------
    # 崩溃恢复
    # ------------------------------------------------------------------

    def _reconcile(self) -> None:
        """重新上电后的一致性检查与恢复。

        - 删除所有 *.tmp 写入暂存；
        - 登记为 valid 的槽位若文件缺失/哈希不符 → 标记 failed；
        - pending/testing 候选若已不完整 → 启动指针立刻回到 active；
        - 正常状态下 active 槽位必须完整，否则尝试用另一槽位兜底。
        """
        self.storage.discard_tmp()
        state = self.state
        changed = False

        for slot in SLOTS:
            meta = state["slots"].setdefault(slot, {"status": SLOT_EMPTY})
            if meta.get("status") == SLOT_VALID:
                actual = self.storage.slot_sha256(slot)
                if actual != meta["sha256"]:
                    meta["status"] = SLOT_FAILED
                    changed = True
                    self.storage.append_log(
                        "recovered_slot_corrupt", slot=slot,
                        expected=meta.get("sha256"), actual=actual,
                    )

        if state["boot_state"] in (BOOT_PENDING, BOOT_TESTING) and changed:
            if state["slots"][state["boot_slot"]]["status"] != SLOT_VALID:
                state["boot_slot"] = state["active_slot"]
                state["boot_state"] = BOOT_NORMAL
                state["boot_attempts"] = 0
                changed = True
                self.storage.append_log(
                    "recovered_to_active",
                    reason="pending/testing 候选槽位不完整",
                )

        if changed:
            self._persist()

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    def _inactive_slot(self) -> str:
        return SLOT_B if self.active_slot == SLOT_A else SLOT_A

    def _check_candidate_health(self, slot: str) -> tuple[str | None, str | None]:
        """返回 (health, reason)。成功时 reason 为 None；失败时 health 为 None。"""
        meta = self.state["slots"].get(slot, {})
        if meta.get("status") != SLOT_VALID:
            return None, f"槽位 {slot} 状态为 {meta.get('status')}"
        if not self.storage.has_slot_image(slot):
            return None, f"槽位 {slot} 镜像文件缺失"
        actual = self.storage.slot_sha256(slot)
        if actual != meta["sha256"]:
            return None, f"槽位 {slot} SHA-256 与登记值不一致"
        data = self.storage.read_slot(slot)
        try:
            header = parse_image(data)
        except ImageCorruptError as exc:
            return None, str(exc)
        return str(header["health"]), None

    @staticmethod
    def _resolve_image_path(
        manifest_path: str, image_path: str | None, manifest: Manifest
    ) -> str:
        if image_path is not None:
            if not os.path.isfile(image_path):
                raise ImageCorruptError(f"镜像文件不存在: {image_path}")
            return image_path
        # 回退：manifest 中的 image 字段相对于 manifest 目录解析
        candidate = os.path.join(
            os.path.dirname(os.path.abspath(manifest_path)), manifest.image
        )
        if not os.path.isfile(candidate):
            raise ImageCorruptError(f"镜像文件不存在: {candidate}")
        return candidate

    def _persist(self) -> None:
        self.storage.write_state(self.state)


def _slot_meta(manifest: Manifest) -> dict[str, Any]:
    return {
        "status": SLOT_VALID,
        "version": manifest.version,
        "sha256": manifest.sha256,
        "size": manifest.size,
    }


def parse_version(version: str) -> tuple[int, ...]:
    """把 "1.2.3" 解析为可比较的整数元组。非数字段回退为 0。"""
    parts = []
    for raw in str(version).split("."):
        try:
            parts.append(int(raw))
        except ValueError:
            parts.append(0)
    return tuple(parts)
