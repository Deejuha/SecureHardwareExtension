"""
Module contains types using within the project.

"""

__all__ = ["SecurityFlag", "she_bytes"]


class she_bytes(bytes):
    """
    Class inherited from bytes in order to implement lacking features.

    """

    def __xor__(self, other: bytes) -> bytes:
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
        return bytes(x ^ y for x, y in zip(self, other))


class SecurityFlag:
    def __set_name__(self, owner, name):
        self._attribute_name = name

    def __init__(self, bit_index: int):
        self._bit_index = bit_index

    def __get__(self, obj, objtype=None):
        return getattr(obj, f"_{self._attribute_name}")

    def __set__(self, obj, value):
        if not isinstance(value, bool):
            raise TypeError("Security flag shall be type of bool.")
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
