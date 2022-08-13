"""
This file contains AUTOSAR identification of memory slots.

"""

from SecureHardwareExtension.key_slots.base import KeySlots

__all__ = ["AutosarKeySlots"]


class AutosarKeySlots(KeySlots):
    """
    Enum holds memory slot identification based on
    `Specification of Secure Hardware Extensions, AUTOSAR FO R19-11`.
    https://www.autosar.org/fileadmin/user_upload/standards/foundation/19-11/AUTOSAR_TR_SecureHardwareExtensions.pdf

    """

    SECRET_KEY = 0x0
    MASTER_ECU_KEY = 0x1
    BOOT_MAC_KEY = 0x2
    BOOT_MAC = 0x3
    KEY_1 = 0x4
    KEY_2 = 0x5
    KEY_3 = 0x6
    KEY_4 = 0x7
    KEY_5 = 0x8
    KEY_6 = 0x9
    KEY_7 = 0xA
    KEY_8 = 0xB
    KEY_9 = 0xC
    KEY_10 = 0xD
    RAM_KEY = 0xE
