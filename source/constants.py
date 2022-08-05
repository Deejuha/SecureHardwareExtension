"""
File to keep constants used withinh Secure Hardware Extension.

"""

from datatypes import she_bytes


class classproperty(object):
    def __init__(self, fget):
        self.fget = fget

    def __get__(self, owner_self, owner_cls):
        return self.fget(owner_cls)


class SheConstants:
    @classproperty
    def KEY_UPDATE_ENC_C(cls):
        return she_bytes.fromhex("010153484500800000000000000000B0")

    @classproperty
    def KEY_UPDATE_MAC_C(cls):
        return she_bytes.fromhex("010253484500800000000000000000B0")

    @classproperty
    def DEBUG_KEY_C(cls):
        return she_bytes.fromhex("010353484500800000000000000000B0")

    @classproperty
    def PRNG_KEY_C(cls):
        return she_bytes.fromhex("010453484500800000000000000000B0")

    @classproperty
    def PRNG_SEED_KEY_C(cls):
        return she_bytes.fromhex("010553484500800000000000000000B0")

    @classproperty
    def PRNG_EXTENSION_C(cls):
        return she_bytes.fromhex("80000000000000000000000000000100")
