"""本地安全固件 OTA 更新模拟器。

仅使用本地文件与内存，不连接任何真实设备、OTA 平台或外部服务。
"""

from .device import BootResult, Device, SlotInfo
from .errors import (
    ImageIntegrityError,
    InvalidStateError,
    OTAError,
    SignatureError,
    UpdateInterrupted,
    VersionPolicyError,
)
from .keys import (
    generate_test_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
)
from .manifest import Manifest, build_package, read_package, verify_package
from .updater import FaultInjector, UpdateReport, Updater

__all__ = [
    "BootResult",
    "Device",
    "SlotInfo",
    "FaultInjector",
    "UpdateReport",
    "Updater",
    "Manifest",
    "build_package",
    "read_package",
    "verify_package",
    "generate_test_keypair",
    "load_private_key",
    "load_public_key",
    "save_keypair",
    "OTAError",
    "SignatureError",
    "ImageIntegrityError",
    "VersionPolicyError",
    "UpdateInterrupted",
    "InvalidStateError",
]
