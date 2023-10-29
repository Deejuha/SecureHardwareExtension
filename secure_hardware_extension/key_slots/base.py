"""
This file contains base Enum of memory slots.

"""

__all__ = ["KeySlots"]

from enum import Enum



class KeySlots(Enum):
    """
    Enum to be inherited by user.
    Every silicon manufacturer may implements it's own key slot identification.

    """
