"""模拟 A/B 双分区设备与启动状态机。

存储布局（全部为本地文件）::

    <device_dir>/
        state.json              设备状态（权威，原子写入）
        update.log              JSON Lines 更新/启动/回滚日志
        slots/
            a/
                slot.json       {"version", "size", "sha256"}
                image.bin       槽位固件镜像
            b/
                slot.json
                image.bin

状态机（state.json 中的 boot_status）::

    committed    当前 active_slot 运行的是已确认的好固件，正常状态
    pending      更新已切换槽位但新固件还没启动过（首次启动尚未发生）
    unconfirmed  新固件已启动（至少一次），但还未被 confirm_boot() 确认

不变量（任何阶段掉电都成立）：
* state.json 原子替换，磁盘上永远是完整的旧状态或完整的新状态；
* 更新只写非活动槽；state.json 翻转发生在镜像完整写入并校验之后，
  因此旧活动槽在切换前始终完整，切换后即成为回滚槽；
* active_slot 指向的槽位在 committed 状态下必然完整可启动。

启动策略：
* pending/unconfirmed 的新固件若启动失败，或一直未被确认成功，
  下一次 boot() 自动回滚到 rollback_slot（旧版本）并提交为 committed。
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Union

from ._atomic import (
    read_json,
    sha256_file,
    write_bytes_atomic,
    write_json_atomic,
)
from .errors import InvalidStateError, NoBootableSlotError, OTAError
from .manifest import Manifest

PathLike = Union[str, os.PathLike]

SLOT_A = "a"
SLOT_B = "b"
SLOTS = (SLOT_A, SLOT_B)

STATUS_COMMITTED = "committed"
STATUS_PENDING = "pending"
STATUS_UNCONFIRMED = "unconfirmed"

STATE_FILENAME = "state.json"
LOG_FILENAME = "update.log"
SLOT_META_FILENAME = "slot.json"
IMAGE_FILENAME = "image.bin"
STAGING_TMP_PREFIX = ".image.bin.tmp-"

# 健康检查钩子：(slot_name, version, image_path) -> bool（返回 False 或抛异常即失败）。
HealthCheck = Callable[[str, Optional[str], str], bool]


@dataclass(frozen=True)
class SlotInfo:
    """一个槽位的当前信息。bootable=True 表示元数据与镜像完整且哈希一致。"""

    name: str
    present: bool
    version: Optional[str]
    size: Optional[int]
    sha256: Optional[str]
    bootable: bool


@dataclass(frozen=True)
class BootResult:
    """一次 boot() 的结果。"""

    success: bool
    slot: str
    version: Optional[str]
    rolled_back: bool
    reason: Optional[str] = None
    pending_confirmation: bool = False


def _initial_state(active_slot: str = SLOT_A) -> Dict:
    return {
        "active_slot": active_slot,
        "boot_status": STATUS_COMMITTED,
        "pending_slot": None,
        "boot_attempts": 0,
        "rollback_slot": None,
        "rollback_version": None,
        "previous_slot": None,
        "last_health": None,
        "last_boot": None,
        "boot_count": 0,
    }


class Device:
    """A/B 设备模拟器。"""

    # ---- 构造与工厂 ----

    def __init__(self, device_dir: PathLike, health_check: Optional[HealthCheck] = None):
        self.device_dir = os.fspath(device_dir)
        self.health_check = health_check
        self.state_path = os.path.join(self.device_dir, STATE_FILENAME)
        self.log_path = os.path.join(self.device_dir, LOG_FILENAME)
        self.slots_dir = os.path.join(self.device_dir, "slots")

    @classmethod
    def provision(
        cls,
        device_dir: PathLike,
        factory_image: bytes,
        factory_version: str,
        health_check: Optional[HealthCheck] = None,
    ) -> "Device":
        """出厂烧录：在 A 槽写入首个固件并提交为 committed。"""
        device = cls(device_dir, health_check)
        os.makedirs(os.path.join(device.slots_dir, SLOT_A), exist_ok=True)
        os.makedirs(os.path.join(device.slots_dir, SLOT_B), exist_ok=True)

        from ._atomic import sha256_bytes

        manifest = Manifest(
            version=factory_version,
            size=len(factory_image),
            sha256=sha256_bytes(factory_image),
        )
        device._write_slot_meta(SLOT_A, manifest)
        write_bytes_atomic(device._slot_image_path(SLOT_A), factory_image)

        write_json_atomic(device.state_path, _initial_state(SLOT_A))
        device._log(
            "device.provisioned",
            slot=SLOT_A,
            version=factory_version,
            size=len(factory_image),
        )
        return device

    @classmethod
    def open(
        cls, device_dir: PathLike, health_check: Optional[HealthCheck] = None
    ) -> "Device":
        """重新打开一个已有设备（模拟重启进程/掉电后恢复）。"""
        device = cls(device_dir, health_check)
        if not os.path.isfile(device.state_path):
            raise InvalidStateError(f"设备未初始化，缺少 {STATE_FILENAME}")
        # 读一次确保状态文件可解析。
        read_json(device.state_path)
        return device

    # ---- 路径与状态 ----

    def _slot_dir(self, slot: str) -> str:
        return os.path.join(self.slots_dir, slot)

    def _slot_image_path(self, slot: str) -> str:
        return os.path.join(self._slot_dir(slot), IMAGE_FILENAME)

    def _slot_meta_path(self, slot: str) -> str:
        return os.path.join(self._slot_dir(slot), SLOT_META_FILENAME)

    def _load_state(self) -> Dict:
        return read_json(self.state_path)

    def _save_state(self, state: Dict) -> None:
        write_json_atomic(self.state_path, state)

    def _log(self, event: str, **fields) -> None:
        entry = {"event": event}
        entry.update(fields)
        line = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def read_log(self) -> List[Dict]:
        if not os.path.isfile(self.log_path):
            return []
        entries: List[Dict] = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    # ---- 槽位检查 ----

    def _read_slot_meta(self, slot: str) -> Optional[Dict]:
        path = self._slot_meta_path(slot)
        if not os.path.isfile(path):
            return None
        try:
            return read_json(path)
        except (OSError, ValueError):
            return None

    def is_slot_bootable(self, slot: str) -> bool:
        """槽位完整可启动：元数据存在、镜像存在、大小与 SHA-256 全部一致。"""
        meta = self._read_slot_meta(slot)
        image_path = self._slot_image_path(slot)
        if not meta or not os.path.isfile(image_path):
            return False
        try:
            if os.path.getsize(image_path) != int(meta["size"]):
                return False
            if sha256_file(image_path) != str(meta["sha256"]).lower():
                return False
        except (OSError, KeyError, TypeError, ValueError):
            return False
        return True

    def slot_info(self, slot: str) -> SlotInfo:
        meta = self._read_slot_meta(slot)
        bootable = self.is_slot_bootable(slot)
        if meta is None:
            return SlotInfo(slot, False, None, None, None, bootable)
        return SlotInfo(
            name=slot,
            present=True,
            version=meta.get("version"),
            size=meta.get("size"),
            sha256=meta.get("sha256"),
            bootable=bootable,
        )

    def _write_slot_meta(self, slot: str, manifest: Manifest) -> None:
        write_json_atomic(
            self._slot_meta_path(slot),
            {
                "version": manifest.version,
                "size": manifest.size,
                "sha256": manifest.sha256,
            },
        )

    # ---- 只读视图 ----

    @property
    def active_slot(self) -> str:
        return self._load_state()["active_slot"]

    @property
    def active_version(self) -> Optional[str]:
        state = self._load_state()
        info = self.slot_info(state["active_slot"])
        return info.version

    @property
    def inactive_slot(self) -> str:
        return SLOT_B if self.active_slot == SLOT_A else SLOT_A

    @property
    def boot_status(self) -> str:
        return self._load_state()["boot_status"]

    def is_update_committed(self) -> bool:
        """当前没有等待启动/确认的更新（只有 committed 时才允许下发新更新）。"""
        return self._load_state()["boot_status"] == STATUS_COMMITTED

    def state_snapshot(self) -> Dict:
        """状态的深拷贝快照（供检查与测试）。"""
        return json.loads(json.dumps(self._load_state()))

    # ---- 更新器使用的内部接口 ----

    def _require_committed(self) -> Dict:
        state = self._load_state()
        if state["boot_status"] != STATUS_COMMITTED:
            raise InvalidStateError(
                f"设备当前有未完成的更新（boot_status={state['boot_status']}），"
                "必须先确认新固件或完成回滚后才能再次更新"
            )
        return state

    def _stage_image(
        self,
        slot: str,
        src_image_path: str,
        manifest: Manifest,
        chunk_size: int = 64 * 1024,
        on_chunk: Optional[Callable[[int], None]] = None,
    ) -> None:
        """把已验证的固件镜像写入 *非活动槽* slot。

        先写临时文件、校验大小与 SHA-256，再原子替换 image.bin，
        最后写 slot.json。中途任何异常都不会破坏活动槽，
        也不会让 state.json 引用该槽 —— 设备始终可从活动槽启动。
        """
        slot_dir = self._slot_dir(slot)
        os.makedirs(slot_dir, exist_ok=True)

        # 清理上一次中断可能残留的暂存文件。
        for name in os.listdir(slot_dir):
            if name.startswith(STAGING_TMP_PREFIX):
                os.unlink(os.path.join(slot_dir, name))

        fd, tmp_path = _mkstemp_in(slot_dir)
        written = 0
        try:
            with os.fdopen(fd, "wb") as out, open(src_image_path, "rb") as src:
                while True:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    out.write(chunk)
                    written += len(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                    if on_chunk is not None:
                        on_chunk(written)
            if written != manifest.size:
                raise OTAError(
                    f"写入不完整: 期望 {manifest.size} 字节，实际 {written} 字节"
                )
            actual_sha = sha256_file(tmp_path)
            if actual_sha != manifest.sha256.lower():
                raise OTAError("写入槽位后的镜像 SHA-256 校验失败，中止激活")
            # 镜像完整：原子替换，再落元数据（元数据是暂存完成的标记）。
            os.replace(tmp_path, self._slot_image_path(slot))
            self._write_slot_meta(slot, manifest)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise

    def _switch_slot_atomically(self, slot: str, manifest: Manifest) -> Dict:
        """原子切换启动槽位：新槽已完整验证，旧槽成为回滚槽。

        整个切换是对 state.json 的一次原子替换，断电时要么完全没切、
        要么已经切完，不存在"指到半截槽位"的中间状态。
        """
        state = self._load_state()
        if state["boot_status"] != STATUS_COMMITTED:
            raise InvalidStateError("只有 committed 状态才能切换槽位")
        old_slot = state["active_slot"]
        if not self.is_slot_bootable(slot):
            raise InvalidStateError(f"目标槽位 {slot} 不完整，拒绝切换")

        old_meta = self._read_slot_meta(old_slot) or {}
        new_state = _initial_state(old_slot)  # 先复制基线，再整体覆盖
        new_state.update(
            {
                "active_slot": slot,
                "boot_status": STATUS_PENDING,
                "pending_slot": slot,
                "boot_attempts": 0,
                "rollback_slot": old_slot,
                "rollback_version": old_meta.get("version"),
                "previous_slot": None,
                "last_health": None,
                "last_boot": None,
                "boot_count": state.get("boot_count", 0),
            }
        )
        self._save_state(new_state)
        self._log(
            "update.slot_switched",
            active_slot=slot,
            version=manifest.version,
            rollback_slot=old_slot,
            rollback_version=old_meta.get("version"),
        )
        return new_state

    # ---- 启动与健康检查 ----

    def _run_health_check(
        self, slot: str, version: Optional[str], image_path: str
    ) -> tuple:
        """运行健康检查钩子，返回 (ok, reason)。钩子抛异常也视为启动失败。"""
        if self.health_check is None:
            return True, None
        try:
            ok = bool(self.health_check(slot, version, image_path))
        except Exception as e:  # 钩子异常 = 新固件启动失败
            return False, f"health check 异常: {e}"
        if ok:
            return True, None
        return False, "health check 返回失败"

    def boot(self) -> BootResult:
        """模拟一次设备启动。

        * committed：正常启动活动槽；
        * pending：首次启动新固件，健康检查通过后进入 unconfirmed 等待确认，
          健康检查失败则记录失败，下一次启动自动回滚；
        * unconfirmed：新固件从未被确认成功（启动失败或未确认），
          本次启动立即自动回滚到旧版本并启动旧槽。
        """
        state = self._load_state()
        status = state["boot_status"]
        self._log("boot.start", active_slot=state["active_slot"], boot_status=status)

        if status in (STATUS_PENDING, STATUS_UNCONFIRMED):
            return self._boot_new_firmware(state)

        return self._boot_committed(state)

    def _boot_new_firmware(self, state: Dict) -> BootResult:
        new_slot = state["pending_slot"]
        attempts = int(state.get("boot_attempts", 0))

        # unconfirmed 再次进入启动：上一轮新固件没被确认成功 → 自动回滚。
        if state["boot_status"] == STATUS_UNCONFIRMED:
            if state.get("last_health") == "failed":
                reason = "新固件首次启动健康检查失败，自动回滚到旧版本"
            else:
                reason = "新固件启动后未被确认成功，自动回滚到旧版本"
            return self._auto_rollback(state, reason)

        # pending：首次启动新固件。
        state["boot_status"] = STATUS_UNCONFIRMED
        state["boot_attempts"] = attempts + 1
        self._save_state(state)

        info = self.slot_info(new_slot)
        if not info.bootable:
            # 槽位镜像/元数据不完整（例如被篡改），记为启动失败。
            state = self._load_state()
            state["last_health"] = "failed"
            state["last_boot"] = {
                "slot": new_slot,
                "version": info.version,
                "result": "failed",
                "reason": "目标槽位不完整或哈希校验失败",
            }
            state["boot_count"] = int(state.get("boot_count", 0)) + 1
            self._save_state(state)
            self._log("boot.health_failed", slot=new_slot,
                      reason="slot not bootable")
            return BootResult(
                success=False,
                slot=new_slot,
                version=info.version,
                rolled_back=False,
                reason="目标槽位不完整或哈希校验失败",
                pending_confirmation=False,
            )

        ok, reason = self._run_health_check(new_slot, info.version,
                                           self._slot_image_path(new_slot))
        state = self._load_state()
        state["boot_count"] = int(state.get("boot_count", 0)) + 1
        if not ok:
            state["last_health"] = "failed"
            state["last_boot"] = {
                "slot": new_slot,
                "version": info.version,
                "result": "failed",
                "reason": reason,
            }
            self._save_state(state)
            self._log("boot.health_failed", slot=new_slot,
                      version=info.version, reason=reason)
            return BootResult(
                success=False,
                slot=new_slot,
                version=info.version,
                rolled_back=False,
                reason=reason,
                pending_confirmation=False,
            )

        # 新固件启动成功，但必须等 confirm_boot() 才算数。
        state["last_health"] = "ok"
        state["last_boot"] = {
            "slot": new_slot,
            "version": info.version,
            "result": "success_unconfirmed",
            "reason": None,
        }
        self._save_state(state)
        self._log("boot.new_firmware_running", slot=new_slot,
                  version=info.version, awaiting_confirmation=True)
        return BootResult(
            success=True,
            slot=new_slot,
            version=info.version,
            rolled_back=False,
            reason=None,
            pending_confirmation=True,
        )

    def _boot_committed(self, state: Dict) -> BootResult:
        slot = state["active_slot"]
        info = self.slot_info(slot)
        if not info.bootable:
            # 活动槽损坏：尝试另一个完整槽位；都没有则明确报错。
            other = SLOT_B if slot == SLOT_A else SLOT_A
            if self.is_slot_bootable(other):
                self._log("boot.active_slot_corrupt", slot=slot,
                          fallback=other)
                return self._auto_rollback(
                    state, f"活动槽 {slot} 损坏，回退到另一完整槽位"
                )
            raise NoBootableSlotError("没有任何完整且可启动的固件槽位")

        ok, reason = self._run_health_check(slot, info.version,
                                           self._slot_image_path(slot))
        state = self._load_state()
        state["boot_count"] = int(state.get("boot_count", 0)) + 1
        if not ok:
            state["last_boot"] = {
                "slot": slot,
                "version": info.version,
                "result": "failed",
                "reason": reason,
            }
            self._save_state(state)
            self._log("boot.health_failed", slot=slot,
                      version=info.version, reason=reason)
            return BootResult(False, slot, info.version, False, reason, False)

        state["last_boot"] = {
            "slot": slot,
            "version": info.version,
            "result": "success",
            "reason": None,
        }
        self._save_state(state)
        self._log("boot.committed_running", slot=slot, version=info.version)
        return BootResult(True, slot, info.version, False, None, False)

    def _auto_rollback(self, state: Dict, reason: str) -> BootResult:
        """把启动目标切回旧槽并启动，提交为 committed。"""
        failed_slot = state.get("pending_slot") or state.get("active_slot")
        rb_slot = state.get("rollback_slot")
        # committed 活动槽损坏时可能没有记录 rollback_slot，
        # 退而求其次：选择另一个完整槽位。
        if not rb_slot or not self.is_slot_bootable(rb_slot):
            other = SLOT_B if failed_slot == SLOT_A else SLOT_A
            if self.is_slot_bootable(other):
                rb_slot = other
        if not rb_slot or not self.is_slot_bootable(rb_slot):
            raise NoBootableSlotError(
                f"需要回滚但回滚槽 {rb_slot!r} 不完整，无可启动固件"
            )

        rb_info = self.slot_info(rb_slot)
        boot_count = int(state.get("boot_count", 0)) + 1
        new_state = _initial_state(rb_slot)
        new_state.update(
            {
                "previous_slot": failed_slot,
                "last_health": None,
                "last_boot": {
                    "slot": rb_slot,
                    "version": rb_info.version,
                    "result": "rollback",
                    "reason": reason,
                },
                "boot_count": boot_count,
            }
        )
        self._save_state(new_state)
        self._log(
            "boot.rollback",
            failed_slot=failed_slot,
            rollback_slot=rb_slot,
            version=rb_info.version,
            reason=reason,
        )

        # 回滚后对旧槽再做一次健康检查（默认钩子恒成功）。
        ok, hc_reason = self._run_health_check(
            rb_slot, rb_info.version, self._slot_image_path(rb_slot)
        )
        if not ok:
            return BootResult(
                success=False,
                slot=rb_slot,
                version=rb_info.version,
                rolled_back=True,
                reason=f"已回滚但旧固件健康检查失败: {hc_reason}",
                pending_confirmation=False,
            )
        return BootResult(
            success=True,
            slot=rb_slot,
            version=rb_info.version,
            rolled_back=True,
            reason=reason,
            pending_confirmation=False,
        )

    def confirm_boot(self) -> None:
        """新固件首次启动健康检查通过后，由设备/用户显式确认成功。

        确认后 boot_status 回到 committed，回滚槽信息清除，
        本次升级正式完成。未确认前重启会自动回滚。
        """
        state = self._load_state()
        if state["boot_status"] == STATUS_COMMITTED:
            raise InvalidStateError("当前没有等待确认的新固件")
        if state["boot_status"] == STATUS_PENDING:
            raise InvalidStateError("新固件尚未启动，不能确认")
        slot = state["pending_slot"]
        if state.get("last_health") != "ok":
            raise InvalidStateError("新固件健康检查未通过，不能确认；下次启动将回滚")
        version = self.slot_info(slot).version
        new_state = _initial_state(slot)
        new_state["boot_count"] = state.get("boot_count", 0)
        new_state["last_boot"] = {
            "slot": slot,
            "version": version,
            "result": "confirmed",
            "reason": None,
        }
        self._save_state(new_state)
        self._log("boot.confirmed", slot=slot, version=version)


def _mkstemp_in(directory: str):
    return tempfile.mkstemp(prefix=STAGING_TMP_PREFIX, dir=directory)
