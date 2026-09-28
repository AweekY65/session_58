"""OTA 更新流程各阶段的异常类型。"""


class OTAError(Exception):
    """所有 OTA 相关错误的基类。"""


class SignatureError(OTAError):
    """manifest 签名缺失或验签失败。"""


class ManifestError(OTAError):
    """manifest 格式非法或字段缺失。"""


class ImageCorruptError(OTAError):
    """镜像大小或 SHA-256 与 manifest 不一致，或镜像格式损坏。"""


class DowngradeRejected(OTAError):
    """版本策略拒绝了降级更新。"""


class WriteInterrupted(OTAError):
    """镜像写入非活动槽位期间发生中断（测试中用于模拟断电）。"""


class BootFailed(OTAError):
    """没有任何可启动的槽位（理论上不应发生）。"""


class InvalidStateError(OTAError):
    """在错误的 boot_state 下调用了操作（例如未处于 testing 却 confirm）。"""
