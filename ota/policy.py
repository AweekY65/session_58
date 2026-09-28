"""版本升级策略。

* 默认拒绝降级：目标版本必须 >= 当前版本；
* 可显式配置 ``allowed_rollback_versions``：仅列表中的旧版本允许回滚，
  其它降级一律拒绝；
* 同版本重装（version == current）默认允许（用于测试与修复刷写）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional, Tuple

from .errors import VersionPolicyError

_VERSION_PART = re.compile(r"^(\d+)(?:[.\-+].*)?$")


def parse_version(value: str) -> Tuple[int, ...]:
    """把点分数字版本解析为整数元组用于比较。

    支持 "1"、"1.2"、"1.2.3"，以及带后缀的 "1.2.3-rc1"（后缀忽略，
    只比较数字段）。非数字段按 0 处理并补齐到 4 段。
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"非法版本号: {value!r}")
    parts = []
    for raw in value.strip().lstrip("v").split("."):
        m = _VERSION_PART.match(raw)
        parts.append(int(m.group(1)) if m else 0)
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)


def compare_versions(a: str, b: str) -> int:
    """返回 -1/0/1：a < b / a == b / a > b。"""
    pa, pb = parse_version(a), parse_version(b)
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


@dataclass
class VersionPolicy:
    """版本策略。

    allow_reinstall=True 时允许刷同版本；allowed_rollback_versions
    是显式允许回滚到的旧版本白名单（精确匹配版本字符串）。
    """

    allowed_rollback_versions: Tuple[str, ...] = field(default_factory=tuple)
    allow_reinstall: bool = True

    @classmethod
    def create(
        cls,
        allowed_rollback_versions: Optional[Iterable[str]] = None,
        allow_reinstall: bool = True,
    ) -> "VersionPolicy":
        return cls(
            allowed_rollback_versions=tuple(allowed_rollback_versions or ()),
            allow_reinstall=allow_reinstall,
        )

    def check(self, current_version: Optional[str], target_version: str) -> None:
        """违反策略抛 VersionPolicyError。"""
        if current_version is None:
            return  # 无当前版本（不应发生），不阻拦。

        cmp = compare_versions(target_version, current_version)
        if cmp > 0:
            return  # 正常升级。
        if cmp == 0:
            if self.allow_reinstall:
                return
            raise VersionPolicyError(
                f"拒绝同版本刷写: 当前 {current_version} == 目标 {target_version}"
            )

        # cmp < 0：降级，仅白名单版本允许。
        if target_version in self.allowed_rollback_versions:
            return
        raise VersionPolicyError(
            f"拒绝降级: 当前 {current_version} -> 目标 {target_version}；"
            f"允许回滚的版本白名单: {list(self.allowed_rollback_versions) or '空'}"
        )
