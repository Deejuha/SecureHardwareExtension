"""
Module contains types using within the project.

"""

__all__ = ["she_bytes"]


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
        return bytes(x ^ y for x, y in zip(self, other))
