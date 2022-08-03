"""
This file contains base Enum of memory slots.
"""

from enum import Enum

__all__ = ["KeySlots"]


class KeySlots(Enum):
    """
    Enum to be inherited by user.
    Every OEM may want it's own key slot identification.
    """
