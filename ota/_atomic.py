"""原子文件写入与文件辅助函数。

所有设备元数据（state.json、slot.json）都通过 ``write_json_atomic`` 落盘：
先写同目录临时文件、fsync，再用 ``os.replace`` 原子替换目标文件，
保证任意时刻磁盘上要么是完整的旧内容，要么是完整的新内容，
不会出现半截 JSON。这是"异常中断后状态仍可启动"的基础。
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from typing import Any, Union

PathLike = Union[str, os.PathLike]


def fsync_dir(path: PathLike) -> None:
    """fsync 目录，保证其中的 rename/替换在掉电后仍生效。"""
    fd = os.open(os.fspath(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_bytes_atomic(path: PathLike, data: bytes) -> None:
    """原子写入字节文件（tmp + fsync + os.replace + 目录 fsync）。"""
    path = os.fspath(path)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
            fsync_dir(directory)
        except BaseException:
            # 写入或替换失败时清理临时文件；替换成功后文件已不存在。
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise
    except BaseException:
        # os.fdopen 失败时 fd 仍需关闭。
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def write_json_atomic(path: PathLike, obj: Any) -> None:
    """原子写入 JSON（带末尾换行，UTF-8、键排序保证字节稳定）。"""
    payload = json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
    write_bytes_atomic(path, payload.encode("utf-8"))


def read_json(path: PathLike) -> Any:
    with open(os.fspath(path), "r", encoding="utf-8") as f:
        return json.load(f)


def sha256_file(path: PathLike, chunk_size: int = 1024 * 1024) -> str:
    """分块计算文件 SHA-256，返回十六进制字符串。"""
    h = hashlib.sha256()
    with open(os.fspath(path), "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
