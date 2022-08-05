"""
Module contains Secure Hardware Extesion memory update protocol

"""

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from constants import SheConstants
from datatypes import MemoryUpdateInfo, she_bytes


class MemoryUpdateProtocol:
    def __init__(self, update_info: MemoryUpdateInfo):
        self.update_info = update_info

    @staticmethod
    def _compress(*args: she_bytes) -> she_bytes:
        key = she_bytes.fromhex("00" * 16)
        for message in args:
            aes_result = AES.new(key, AES.MODE_ECB).encrypt(message)
            key = key ^ aes_result
            key = key ^ message
        return key

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
