"""设备本地存储：A/B 槽位文件、原子 state.json、JSONL 更新日志。

设备目录布局::

    devdir/
    ├── state.json        # 唯一的权威状态（原子写入）
    ├── pubkey.pem        # 出厂烧录的验签公钥（根信任）
    ├── update.log        # 追加式 JSONL 事件日志
    └── slots/
        ├── a.bin         # A 槽位固件
        ├── b.bin         # B 槽位固件
        ├── a.tmp / b.tmp # 更新写入暂存（崩溃后可安全删除）

所有对 state.json 的修改都经过 "写临时文件 + fsync + os.replace"，
槽位切换同样通过 os.replace 原子完成，因此掉电后状态要么是旧的、
要么是新的，永远不会出现半写状态。
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any

SLOT_A = "a"
SLOT_B = "b"
SLOTS = (SLOT_A, SLOT_B)

STATE_NAME = "state.json"
LOG_NAME = "update.log"
PUBKEY_NAME = "pubkey.pem"
SLOTS_DIRNAME = "slots"

# state.json 中 boot_state 的取值
BOOT_NORMAL = "normal"    # 当前固件已确认，正常运行
BOOT_PENDING = "pending"  # 更新已写入，等待下一次启动验证
BOOT_TESTING = "testing"  # 新固件首次启动中，等待健康确认

# 槽位状态
SLOT_EMPTY = "empty"
SLOT_VALID = "valid"      # 固件完整且元数据已登记
SLOT_FAILED = "failed"    # 曾作为候选但健康检查失败

CHUNK_SIZE = 64 * 1024


class SlotStorage:
    """对设备目录下文件布局的封装。"""

    def __init__(self, devdir: str):
        self.devdir = devdir
        self.slots_dir = os.path.join(devdir, SLOTS_DIRNAME)
        self.state_path = os.path.join(devdir, STATE_NAME)
        self.log_path = os.path.join(devdir, LOG_NAME)
        self.pubkey_path = os.path.join(devdir, PUBKEY_NAME)

    # ---- 目录 / 初始化 ----

    @classmethod
    def initialize(cls, devdir: str, public_key_pem: bytes) -> "SlotStorage":
        """创建全新的设备目录并写入出厂状态与公钥。"""
        storage = cls(devdir)
        os.makedirs(storage.slots_dir, exist_ok=True)
        _atomic_bytes(storage.pubkey_path, public_key_pem, mode=0o644)
        state = {
            "active_slot": SLOT_A,
            "boot_slot": SLOT_A,
            "boot_state": BOOT_NORMAL,
            "boot_attempts": 0,
            "slots": {
                SLOT_A: {"status": SLOT_EMPTY},
                SLOT_B: {"status": SLOT_EMPTY},
            },
            "allowed_rollback_versions": [],
        }
        storage.write_state(state)
        return storage

    def exists(self) -> bool:
        return os.path.isfile(self.state_path)

    # ---- state.json ----

    def read_state(self) -> dict[str, Any]:
        with open(self.state_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def write_state(self, state: dict[str, Any]) -> None:
        """原子写入完整状态。"""
        data = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8")
        _atomic_bytes(self.state_path, data, mode=0o644)

    def public_key_pem(self) -> bytes:
        with open(self.pubkey_path, "rb") as f:
            return f.read()

    # ---- 槽位文件 ----

    def slot_path(self, slot: str) -> str:
        return os.path.join(self.slots_dir, f"{slot}.bin")

    def tmp_path(self, slot: str) -> str:
        return os.path.join(self.slots_dir, f"{slot}.tmp")

    def has_slot_image(self, slot: str) -> bool:
        return os.path.isfile(self.slot_path(slot))

    def read_slot(self, slot: str) -> bytes:
        with open(self.slot_path(slot), "rb") as f:
            return f.read()

    def write_slot_from_data(
        self,
        slot: str,
        data: bytes,
        expected_size: int,
        expected_sha256: str,
        fault_after_bytes: int | None = None,
        crash_after_replace: bool = False,
    ) -> None:
        """把镜像分块写入非活动槽位。

        流程：写 ``slot.tmp``（可注入写入中断）→ 校验 tmp → os.replace 原子
        落盘为 ``slot.bin``。``crash_after_replace`` 模拟 replace 之后、
        state.json 更新之前掉电。
        """
        tmp = self.tmp_path(slot)
        # 干净起步：上一次崩溃残留的暂存文件直接覆盖
        with open(tmp, "wb") as f:
            written = 0
            for chunk in _iter_chunks(data, CHUNK_SIZE):
                if fault_after_bytes is not None and written >= fault_after_bytes:
                    f.flush()
                    os.fsync(f.fileno())
                    raise IOError(
                        f"模拟写入中断：已写入 {written} 字节后断电（目标槽位 {slot}）"
                    )
                f.write(chunk)
                written += len(chunk)
            f.flush()
            os.fsync(f.fileno())

        # 写入完成后、替换前先校验暂存文件自身完整性
        with open(tmp, "rb") as f:
            staged = f.read()
        from .image import verify_image_against_manifest
        from .manifest import Manifest

        placeholder = Manifest(
            version="0", image="", size=expected_size,
            sha256=expected_sha256, created_at="", signature=b"",
        )
        verify_image_against_manifest(staged, placeholder)

        os.replace(tmp, self.slot_path(slot))
        self._sync_dir()
        if crash_after_replace:
            raise IOError("模拟断电：槽位已原子落盘，但 state.json 尚未切换")

    def discard_tmp(self, slot: str | None = None) -> None:
        """清理写入暂存（更新失败或崩溃恢复时调用）。"""
        targets = (slot,) if slot is not None else SLOTS
        for name in targets:
            tmp = self.tmp_path(name)
            if os.path.isfile(tmp):
                os.remove(tmp)

    def slot_sha256(self, slot: str) -> str | None:
        """槽位文件的实际 SHA-256；不存在时返回 None。"""
        import hashlib

        path = self.slot_path(slot)
        if not os.path.isfile(path):
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                h.update(chunk)
        return h.hexdigest()

    # ---- 日志 ----

    def append_log(self, event: str, **fields: Any) -> None:
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "event": event, **fields}
        line = json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

    def read_log(self) -> list[dict[str, Any]]:
        if not os.path.isfile(self.log_path):
            return []
        entries = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    # ---- 维护 ----

    def _sync_dir(self) -> None:
        """fsync 目录，保证 os.replace 在掉电后也持久化。"""
        try:
            fd = os.open(self.slots_dir, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            # 某些平台不支持目录 fsync（本地模拟可忽略）
            pass


def _atomic_bytes(path: str, data: bytes, mode: int | None = None) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.isfile(tmp):
            os.remove(tmp)
        raise


def _iter_chunks(data: bytes, size: int):
    for i in range(0, len(data), size):
        yield data[i:i + size]


def copy_public_key(src_pubkey_path: str, devdir: str) -> bytes:
    """把出厂公钥读入并返回 PEM 字节（由 initialize 落盘）。"""
    with open(src_pubkey_path, "rb") as f:
        pem = f.read()
    # 校验是合法的 Ed25519 公钥
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(pem)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("出厂公钥不是 Ed25519 密钥")
    return pem
