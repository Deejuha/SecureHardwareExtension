"""
Module contains types using within the project.

"""

__all__ = ["MemoryUpdateInfo", "MemoryUpdateMessages", "SecurityFlags", "she_bytes"]

from typing import Union

from key_slots.base import KeySlots

BITS_IN_BYTE = 8
HexType = Union[str, bytes]


class she_bytes(bytes):
    """
    Class inherited from bytes in order to implement lacking features.

    """

    def __xor__(self, other):
        """
        Overrides xor operator in order to xor bytes.

        Parameters
        ----------
        other : `bytes`
            Bytes to XOR with.

        Returns
        -------
        `bytes`
            Result of XOR.

        """
        if len(self) != len(other):
            raise ValueError("Cannot XOR bytes with different lengths.")
        return she_bytes(x ^ y for x, y in zip(self, other))


class SheDescriptor:
    def __set_name__(self, owner, name):
        self._attribute_name = name

    def __init__(self, bit_size: int):
        self._bit_size = bit_size

    def __get__(self, obj, objtype=None):
        return getattr(obj, f"_{self._attribute_name}")


class SheBytes(SheDescriptor):
    def __set__(self, obj, value):
        if isinstance(value, str):
            if not value:
                raise ValueError(
                    f"Given empty string to construct {self._attribute_name}."
                )
            if len(value) % 2:
                raise ValueError(
                    f"{self._attribute_name} as hexstring shall have odd value of nibbles. Given string: {value}."
                )
            try:
                value = she_bytes.fromhex(value)
            except ValueError:
                raise ValueError(
                    f"{self._attribute_name} as string contains non hex-string characters."
                )
        elif isinstance(value, bytes):
            if not len(value):
                raise ValueError(
                    f"Given empty bytes to construct {self._attribute_name}."
                )
            value = she_bytes(value)
        else:
            raise TypeError(
                f"{self._attribute_name} shall be type of str or bytes instead of {type(value)}."
            )
        if len(value) != self._bit_size // 8:
            raise ValueError(
                f"{self._attribute_name} size ({len(value)} bytes) shall be equal to {self._bit_size // 8} bytes."
            )
        setattr(obj, f"_{self._attribute_name}", value)


class SheInteger(SheDescriptor):
    def __set__(self, obj, value):
        if not isinstance(value, int):
            raise TypeError(
                f"{self._attribute_name} shall be type of int instead of {type(value)}."
            )
        if value < 0:
            raise ValueError(
                f"{self._attribute_name} shall be equal or greater than 0. Value given: {value}."
            )
        max_value = 2**self._bit_size - 1
        if value > max_value:
            raise ValueError(
                f"{self._attribute_name} shall be lesser than {max_value} (bit size {self._bit_size}). Value given: {value}."
            )
        setattr(obj, f"_{self._attribute_name}", value)


class SheKeySlot(SheInteger):
    def __set__(self, obj, setter_value):
        if isinstance(setter_value, KeySlots):
            setter_value = setter_value.value
        super().__set__(obj, setter_value)


class SecurityFlag(SheDescriptor):
    def __init__(self, bit_index: int):
        self._bit_index = bit_index

    def __set__(self, obj, value):
        if not isinstance(value, bool):
            raise TypeError(
                f"Security flag {self._attribute_name} shall be type of bool."
            )
        if value:
            obj._fid = obj._fid | (1 << self._bit_index)
        else:
            obj._fid = obj._fid & ~(1 << self._bit_index)
        setattr(obj, f"_{self._attribute_name}", value)


class SecurityFlags:
    write_protection: bool = SecurityFlag(0)
    boot_failure: bool = SecurityFlag(1)
    debugger_activation: bool = SecurityFlag(2)
    wildcard_usage: bool = SecurityFlag(3)
    key_usage: bool = SecurityFlag(4)
    plain_key: bool = SecurityFlag(5)

    def __init__(self):
        self._fid: int = 0
        self.write_protection = False
        self.boot_failure = False
        self.debugger_activation = False
        self.wildcard_usage = False
        self.key_usage = False
        self.plain_key = False

    @property
    def fid(self):
        return self._fid


class MemoryUpdateInfo:
    new_key: she_bytes = SheBytes(16 * BITS_IN_BYTE)
    auth_key: she_bytes = SheBytes(16 * BITS_IN_BYTE)
    new_key_id: int = SheKeySlot(4)
    auth_key_id: int = SheKeySlot(4)
    counter: int = SheInteger(28)
    uid: she_bytes = SheBytes(15 * BITS_IN_BYTE)
    fid: int = SheInteger(5)
    flags: SecurityFlags()

    def __init__(
        self,
        new_key: HexType,
        auth_key: HexType,
        new_key_id: Union[KeySlots, int],
        auth_key_id: Union[KeySlots, int],
        counter: int,
        uid: HexType,
        flags: SecurityFlags,
    ):
        self.new_key = new_key
        self.auth_key = auth_key
        self.new_key_id = new_key_id
        self.auth_key_id = auth_key_id
        self.counter = counter
        self.uid = uid
        self._flags = flags
        self.fid = flags.fid

    @property
    def flags(self):
        return self._flags

    @flags.setter
    def flags(self, flags):
        if not isinstance(flags, SecurityFlags):
            raise TypeError(
                f"Memory Update Info flags attribute shall be type of {type(SecurityFlags)}."
            )
        self._flags = flags
        self.fid = flags.fid


class MemoryUpdateMessages:
    M1: she_bytes = SheBytes(16 * BITS_IN_BYTE)
    M2: she_bytes = SheBytes(32 * BITS_IN_BYTE)
    M3: she_bytes = SheBytes(16 * BITS_IN_BYTE)
    M4: she_bytes = SheBytes(32 * BITS_IN_BYTE)
    M5: she_bytes = SheBytes(16 * BITS_IN_BYTE)

    def __init__(self, m1: HexType, m2: HexType, m3: HexType, m4: HexType, m5: HexType):
        self.M1 = m1
        self.M2 = m2
        self.M3 = m3
        self.M4 = m4
        self.M5 = m5
