"""OTA 模拟器异常类型。"""


class OTAError(Exception):
    """所有 OTA 相关错误的基类。"""


class SignatureError(OTAError):
    """manifest 数字签名验证失败。"""


class ImageIntegrityError(OTAError):
    """镜像大小或 SHA-256 校验失败（镜像被篡改或写入不完整）。"""


class VersionPolicyError(OTAError):
    """违反版本策略：默认拒绝降级，且目标版本不在允许回滚列表中。"""


class UpdateInterrupted(OTAError):
    """更新过程中被模拟的异常中断（如掉电）。"""


class InvalidStateError(OTAError):
    """设备状态不允许请求的操作（如未确认新固件时再次下发更新）。"""


class NoBootableSlotError(OTAError):
    """找不到完整且可启动的固件槽位（模拟器中不应发生，发生即状态机缺陷）。"""
