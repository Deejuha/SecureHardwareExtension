"""
Module contains types using within the project.

"""

__all__ = ["MemoryUpdateInfo", "MemoryUpdateMessages", "SecurityFlags", "she_bytes"]

from typing import Optional, Union

from secure_hardware_extension.key_slots.base import KeySlots

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

        Raises
        ------
        `ValueError`
            When bytes to XOR has different length.

        """
        if len(self) != len(other):
            raise ValueError("Cannot XOR bytes with different lengths.")
        return she_bytes(x ^ y for x, y in zip(self, other))


class SheDescriptor:
    """
    Base descriptor to be used in SHE datatypes.

    """

    def __set_name__(self, owner, name):
        self._attribute_name = name

    def __init__(self, bit_size: int):
        self._bit_size = bit_size

    def __get__(self, obj, objtype=None):
        return getattr(obj, f"_{self._attribute_name}")


class SheBytes(SheDescriptor):
    """
    Descriptor to be used to validate and utilize she_bytes type within SHE datatypes.

    """

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
    """
    Descriptor to be used to validate and utilize integer type within SHE datatypes.

    """

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
    """
    Descriptor to be used to validate and utilize KeySlots type within SHE datatypes.

    """

    def __set__(self, obj, setter_value):
        if isinstance(setter_value, KeySlots):
            setter_value = setter_value.value
        super().__set__(obj, setter_value)


class SecurityFlag(SheDescriptor):
    """
    Descriptor to be used to validate and utilize SecurityFlags type within SHE datatypes.

    """

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

    def __get__(self, obj, objtype=None):
        return bool(obj._fid & (1 << self._bit_index))


class SecurityFlags:
    """
    Class holds Secure Hardware Extension flags (FID).

    Examples
    --------
    >>> flags = SecurityFlags()
    >>> flags.write_protection = True
    >>> flags.fid
        32
    >>> another_flags = SecurityFlags(fid=20)
    >>> another_flags.wildcard
        False
    >>> another_flags.boot_protection
        True

    """

    write_protection: bool = SecurityFlag(5)
    boot_protection: bool = SecurityFlag(4)
    debugger_protection: bool = SecurityFlag(3)
    key_usage: bool = SecurityFlag(2)
    wildcard: bool = SecurityFlag(1)
    cmac_usage: bool = SecurityFlag(0)

    def __init__(self, fid: Optional[int] = None) -> None:
        """
        Initializes flags.

        Parameters
        ----------
        fid : `int`, optional
            Integer representation of chosen bit flags.

        """
        self._fid = 0
        self.fid = fid if fid else 0

    @property
    def fid(self) -> int:
        """
        Property of fid.

        Returns
        -------
        `int`
            Integer representation of chosen bit flags.

        """
        return self._fid

    @fid.setter
    def fid(self, value: int) -> None:
        """
        Sets flags accordingly to chosen fid integer value.

        Parameters
        ----------
        value : `int`
            Integer representation of chosen bit flags.

        Raises
        ------
        `TypeError`
            When improper type will be set.

        `ValueError`
            When fid has improper integer value.

        """
        if not isinstance(value, int):
            raise TypeError(f"fid shall be type of int. Type given: {type(value)}")
        if not 0 <= value <= 63:
            raise ValueError(f"fid shall be between 0 and 63. Value {value} given.")
        self.write_protection = True if value & 0b100000 else False
        self.boot_protection = True if value & 0b010000 else False
        self.debugger_protection = True if value & 0b001000 else False
        self.key_usage = True if value & 0b000100 else False
        self.wildcard = True if value & 0b000010 else False
        self.cmac_usage = True if value & 0b000001 else False


class MemoryUpdateInfo:
    """
    Class holds SHE update protocol required information.

    Examples
    --------
    >>> MemoryUpdateInfo(
            new_key="0f0e0d0c0b0a09080706050403020100",
            auth_key="000102030405060708090a0b0c0d0e0f",
            new_key_id=4,
            auth_key_id=1,
            counter=1,
            uid="00" * 15,
            flags=SecurityFlags(),
        )

    """

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
    ) -> None:
        """
        Initializes class with necessary items.

        Parameters
        ----------
        new_key : `HexType`
            Key which shall be updated (128bits).

        auth_key : `HexType`
            Key which shall be used for authentication (128bits).

        new_key_id : `Union` [`KeySlots`, `int`]
            Key slot of key to update.

        auth_key_id : `Union` [`KeySlots`, `int`]
            Key slot of authentication key.

        counter : `int`
            Counter of update operations.

        uid : `HexType`
            Unique Identification Identifier (120bits).

        flags : `SecurityFlags`
            Flags to select key parameters.

        """
        self.new_key = new_key
        self.auth_key = auth_key
        self.new_key_id = new_key_id
        self.auth_key_id = auth_key_id
        self.counter = counter
        self.uid = uid
        self._flags = flags
        self.fid = flags.fid

    @property
    def flags(self) -> SecurityFlags:
        """
        Getter of flags.

        Returns
        -------
        `SecurityFlags`
            Properties of key slot.

        """
        return self._flags

    @flags.setter
    def flags(self, flags: SecurityFlags) -> None:
        """
        Validates and sets flags.

        Parameters
        ----------
        flags : `SecurityFlags`
            Value of setter.

        Raises
        ------
        `TypeError`
            When setter value won't be as specified.

        """
        if not isinstance(flags, SecurityFlags):
            raise TypeError(
                f"Memory Update Info flags attribute shall be type of {type(SecurityFlags)}."
            )
        self._flags = flags
        self.fid = flags.fid


class MemoryUpdateMessages:
    """
    Class holds information about messages which may be used to get memory update info.

    """

    auth_key: she_bytes = SheBytes(16 * BITS_IN_BYTE)
    M1: she_bytes = SheBytes(16 * BITS_IN_BYTE)
    M2: she_bytes = SheBytes(32 * BITS_IN_BYTE)

    def __init__(self, auth_key: HexType, m1: HexType, m2: HexType):
        """
        Initializes necessary properties.

        Parameters
        ----------
        auth_key : `HexType`
            Key used for authentication of messages M1 and M2.

        m1 : `HexType`
            SHE M1 message.

        m2 : `HexType`
            SHE M2 message.

        """
        self.auth_key = auth_key
        self.M1 = m1
        self.M2 = m2
