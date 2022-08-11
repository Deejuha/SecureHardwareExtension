"""
Module contains Secure Hardware Extesion memory update protocol

"""

from typing import Union

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from SecureHardwareExtension.constants import SheConstants
from SecureHardwareExtension.datatypes import (MemoryUpdateInfo,
                                               MemoryUpdateMessages,
                                               SecurityFlags, she_bytes)

__all__ = ["MemoryUpdateProtocol"]

class MemoryUpdateProtocol:
    """
    Class designed to calculate messages from update info and vice versa.

    """

    def __init__(self, update: Union[MemoryUpdateInfo, MemoryUpdateMessages]) -> None:
        """
        Initializes update info by using arguments.

        Parameters
        ----------
        update : `Union` [`MemoryUpdateInfo`, `MemoryUpdateMessages`]
            Information necessary to create object and fill required update info attributes.

        Raises
        ------
        `TypeError`
            When argument type doesn't match.

        """
        if isinstance(update, MemoryUpdateMessages):
            self.update_info = self._decrypt_using_messages(update)
        elif isinstance(update, MemoryUpdateInfo):
            self.update_info = update
        else:
            raise TypeError(
                f"update shall be type of Union[MemoryUpdateInfo, MemoryUpdateMessages] instead of {type(update)}."
            )

    @staticmethod
    def _compress(*args: she_bytes) -> she_bytes:
        """
        Miyaguchi-Preneel one-way compression function, uses AES-ECB under the hood.

        Parameters
        ----------
        *args : `she_bytes`
            Messages to be compressed.

        Returns
        -------
        `she_bytes`
            Compressed messages.

        """
        key = she_bytes.fromhex("00" * 16)
        for message in args:
            aes_result = AES.new(key, AES.MODE_ECB).encrypt(message)
            key = key ^ aes_result
            key = key ^ message
        return key

    def _decrypt_using_messages(
        self, update_messages: MemoryUpdateMessages
    ) -> MemoryUpdateInfo:
        """
        Parses update messages in order to get plain update info.

        Parameters
        ----------
        update_messages : `MemoryUpdateMessages`
            Messages to parse.

        Returns
        -------
        `MemoryUpdateInfo`
            Parsed memory update info.

        """
        uid = she_bytes(update_messages.M1[:15])
        auth_key_id = update_messages.M1[15] & 0b1111
        new_key_id = (update_messages.M1[15] & 0b11110000) >> 4
        k1 = self._compress(update_messages.auth_key, SheConstants.KEY_UPDATE_ENC_C)
        m2_plain = AES.new(k1, AES.MODE_CBC, iv=bytes.fromhex("00" * 16)).decrypt(
            update_messages.M2
        )
        counter = (
            int.from_bytes(m2_plain[:3], byteorder="big") + (m2_plain[3] & 0b11110000)
            >> 4
        )
        fid = ((m2_plain[3] & 0b1111) << 2) + (m2_plain[4] & 0b11000000 >> 6)
        flags = SecurityFlags(fid=fid)
        new_key = m2_plain[16:32]
        return MemoryUpdateInfo(
            new_key=new_key,
            auth_key=update_messages.auth_key,
            new_key_id=new_key_id,
            auth_key_id=auth_key_id,
            counter=counter,
            uid=uid,
            flags=flags,
        )

    @property
    def k1(self):
        return self._compress(self.update_info.auth_key, SheConstants.KEY_UPDATE_ENC_C)

    @property
    def k2(self):
        return self._compress(self.update_info.auth_key, SheConstants.KEY_UPDATE_MAC_C)

    @property
    def k3(self):
        return self._compress(self.update_info.new_key, SheConstants.KEY_UPDATE_ENC_C)

    @property
    def k4(self):
        return self._compress(self.update_info.new_key, SheConstants.KEY_UPDATE_MAC_C)

    @property
    def m1(self):
        return self.update_info.uid + (
            (self.update_info.new_key_id << 4) + self.update_info.auth_key_id
        ).to_bytes(1, byteorder="big")

    @property
    def m2(self):
        cid = (self.update_info.counter & 0xFFFFFFF) << 100
        fid = (self.update_info.fid & 0b111111) << 95
        plain = (cid + fid).to_bytes(16, byteorder="big") + self.update_info.new_key
        return AES.new(self.k1, AES.MODE_CBC, iv=she_bytes.fromhex("00" * 16)).encrypt(
            plain
        )

    @property
    def m3(self):
        cmac = CMAC.new(self.k2, ciphermod=AES)
        cmac.update(self.m1 + self.m2)
        return cmac.digest()

    @property
    def m4(self):
        cid = (self.update_info.counter & 0xFFFFFFF) << 100
        cid = cid | 1 << 99
        cid = cid.to_bytes(16, byteorder="big")
        cid = AES.new(self.k3, AES.MODE_ECB).encrypt(cid)
        return self.m1 + cid

    @property
    def m5(self):
        cmac = CMAC.new(self.k4, ciphermod=AES)
        cmac.update(self.m4)
        return cmac.digest()
