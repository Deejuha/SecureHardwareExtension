"""
This file contains base Enum of memory slots.

"""

from enum import Enum

__all__ = ["KeySlots"]


class KeySlots(Enum):
    """
    Enum to be inherited by user.
    Every silicon manufacturer may implements it's own key slot identification.

    """
