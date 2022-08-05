from datatypes import (MemoryUpdateInfo, MemoryUpdateMessages, SecurityFlags,
                       she_bytes)
from key_slots.autosar import AutosarKeySlots
from pytest import fixture, mark, raises


@fixture
def security_flags():
    yield SecurityFlags()


@mark.parametrize(
    "a, b, expected",
    (
        ("FF", "FF", "00"),
        ("00", "00", "00"),
        ("FF", "00", "FF"),
        ("FFFFFF", "FFFFFF", "000000"),
        ("FF00FF", "00FF00", "FFFFFF"),
        ("AA55AA55AA55AA55", "0000000000000000", "AA55AA55AA55AA55"),
    ),
)
def test_bytes_xor(a, b, expected):
    bytes_a = she_bytes.fromhex(a)
    bytes_b = she_bytes.fromhex(b)
    bytes_expected = she_bytes.fromhex(expected)
    result = bytes_a ^ bytes_b
    assert bytes_expected == result


def test_bytes_different_lengths():
    bytes_a = she_bytes.fromhex("00")
    bytes_b = she_bytes.fromhex("FFFF")
    with raises(ValueError):
        bytes_a ^ bytes_b


@mark.parametrize(
    "flags_to_set, expected_fid",
    (
        ((), 0),
        (("write_protection",), 0b000001),
        (("boot_failure",), 0b000010),
        (("debugger_activation",), 0b000100),
        (("wildcard_usage",), 0b001000),
        (("key_usage",), 0b010000),
        (("plain_key",), 0b100000),
        (
            (
                "write_protection",
                "boot_failure",
                "debugger_activation",
                "wildcard_usage",
                "key_usage",
                "plain_key",
            ),
            0b111111,
        ),
    ),
)
def test_security_flags_set_fid(security_flags, flags_to_set, expected_fid):
    for flagname in flags_to_set:
        setattr(security_flags, flagname, True)
    assert expected_fid == security_flags.fid


@mark.parametrize(
    "flags_to_clear, expected_fid",
    (
        ((), 0b111111),
        (("write_protection",), 0b111110),
        (("boot_failure",), 0b111101),
        (("debugger_activation",), 0b111011),
        (("wildcard_usage",), 0b110111),
        (("key_usage",), 0b101111),
        (("plain_key",), 0b011111),
        (
            (
                "write_protection",
                "boot_failure",
                "debugger_activation",
                "wildcard_usage",
                "key_usage",
                "plain_key",
            ),
            0b000000,
        ),
    ),
)
def test_security_flags_clear_fid(security_flags, flags_to_clear, expected_fid):
    for attribute in (
        "write_protection",
        "boot_failure",
        "debugger_activation",
        "wildcard_usage",
        "key_usage",
        "plain_key",
    ):
        setattr(security_flags, attribute, True)
    for flagname in flags_to_clear:
        setattr(security_flags, flagname, False)
    assert expected_fid == security_flags.fid


@mark.parametrize("value", (1, "string"))
def test_security_flags_typeerror(security_flags, value):
    with raises(TypeError):
        security_flags.write_protection = value


@mark.parametrize(
    "new_key, auth_key, new_key_id, auth_key_id, counter, uid, flags",
    (
        ("0" * 32, "0" * 32, 0, 0, 0, "0" * 30, SecurityFlags()),
        # new_key
        ("F" * 32, "0" * 32, 0, 0, 0, "0" * 30, SecurityFlags()),
        (bytes.fromhex("0" * 32), "0" * 32, 0, 0, 0, "0" * 30, SecurityFlags()),
        # auth_key
        ("0" * 32, "F" * 32, 0, 0, 0, "0" * 30, SecurityFlags()),
        ("0" * 32, bytes.fromhex("0" * 32), 0, 0, 0, "0" * 30, SecurityFlags()),
        # new_key_id
        ("0" * 32, "0" * 32, 15, 0, 0, "0" * 30, SecurityFlags()),
        ("0" * 32, "0" * 32, AutosarKeySlots.BOOT_MAC, 0, 0, "0" * 30, SecurityFlags()),
        # auth_key_id
        ("0" * 32, "0" * 32, 0, 15, 0, "0" * 30, SecurityFlags()),
        ("0" * 32, "0" * 32, 0, AutosarKeySlots.BOOT_MAC, 0, "0" * 30, SecurityFlags()),
        # counter
        ("0" * 32, "0" * 32, 0, 0, 268435455, "0" * 30, SecurityFlags()),
        # uid
        ("0" * 32, "0" * 32, 0, 0, 0, "F" * 30, SecurityFlags()),
        ("0" * 32, "0" * 32, 0, 0, 0, bytes.fromhex("0" * 30), SecurityFlags()),
    ),
)
def test_update_info_no_exception_raised(
    new_key, auth_key, new_key_id, auth_key_id, counter, uid, flags
):
    MemoryUpdateInfo(
        new_key=new_key,
        auth_key=auth_key,
        new_key_id=new_key_id,
        auth_key_id=auth_key_id,
        counter=counter,
        uid=uid,
        flags=flags,
    )


@mark.parametrize(
    "new_key, auth_key, new_key_id, auth_key_id, counter, uid, flags, errortype",
    (
        # new_key
        ("0" * 34, "0" * 32, 0, 0, 0, "0" * 30, SecurityFlags(), ValueError),
        ("", "0" * 32, 0, 0, 0, "0" * 30, SecurityFlags(), ValueError),
        (bytes(), "0" * 32, 0, 0, 0, "0" * 30, SecurityFlags(), ValueError),
        ("000", "0" * 32, 0, 0, 0, "0" * 30, SecurityFlags(), ValueError),
        ("ZZ", "0" * 32, 0, 0, 0, "0" * 30, SecurityFlags(), ValueError),
        (2.5, "0" * 32, 0, 0, 0, "0" * 30, SecurityFlags(), TypeError),
        # auth_key
        ("0" * 32, "0" * 34, 0, 0, 0, "0" * 30, SecurityFlags(), ValueError),
        ("0" * 32, "", 0, 0, 0, "0" * 30, SecurityFlags(), ValueError),
        ("0" * 32, bytes(), 0, 0, 0, "0" * 30, SecurityFlags(), ValueError),
        ("0" * 32, "000", 0, 0, 0, "0" * 30, SecurityFlags(), ValueError),
        ("0" * 32, "ZZ", 0, 0, 0, "0" * 30, SecurityFlags(), ValueError),
        ("0" * 32, 2.5, 0, 0, 0, "0" * 30, SecurityFlags(), TypeError),
        # new_key_id
        ("0" * 32, "0" * 32, -1, 0, 0, "0" * 30, SecurityFlags(), ValueError),
        (
            "0" * 32,
            "0" * 32,
            16,
            0,
            0,
            "0" * 30,
            SecurityFlags(),
            ValueError,
        ),
        ("0" * 32, "0" * 32, "string", 0, 0, "0" * 30, SecurityFlags(), TypeError),
        # auth_key_id
        ("0" * 32, "0" * 32, 0, -1, 0, "0" * 30, SecurityFlags(), ValueError),
        (
            "0" * 32,
            "0" * 32,
            0,
            16,
            0,
            "0" * 30,
            SecurityFlags(),
            ValueError,
        ),
        ("0" * 32, "0" * 32, 0, "string", 0, "0" * 30, SecurityFlags(), TypeError),
        # counter
        ("0" * 32, "0" * 32, 0, 0, -1, "0" * 30, SecurityFlags(), ValueError),
        ("0" * 32, "0" * 32, 0, 0, 268435456, "0" * 30, SecurityFlags(), ValueError),
        ("0" * 32, "0" * 32, 0, 0, "string", "0" * 30, SecurityFlags(), TypeError),
        # uid
        ("0" * 32, "0" * 32, 0, 0, 0, "0" * 32, SecurityFlags(), ValueError),
        ("0" * 32, "0" * 32, 0, 0, 0, "", SecurityFlags(), ValueError),
        ("0" * 32, "0" * 32, 0, 0, 0, "000", SecurityFlags(), ValueError),
        ("0" * 32, "0" * 32, 0, 0, 0, "ZZ", SecurityFlags(), ValueError),
        ("0" * 32, "0" * 32, 0, 0, 0, bytes(), SecurityFlags(), ValueError),
        ("0" * 32, "0" * 32, 0, 0, 0, 2.5, SecurityFlags(), TypeError),
    ),
)
def test_update_info_raises(
    new_key, auth_key, new_key_id, auth_key_id, counter, uid, flags, errortype
):
    with raises(errortype):
        MemoryUpdateInfo(
            new_key=new_key,
            auth_key=auth_key,
            new_key_id=new_key_id,
            auth_key_id=auth_key_id,
            counter=counter,
            uid=uid,
            flags=flags,
        )


@mark.parametrize(
    "m1, m2, m3, m4, m5",
    (
        ("00" * 16, "00" * 32, "00" * 16, "00" * 32, "00" * 16),
        # m1
        ("FF" * 16, "00" * 32, "00" * 16, "00" * 32, "00" * 16),
        (bytes.fromhex("00" * 16), "00" * 32, "00" * 16, "00" * 32, "00" * 16),
        # m2
        ("00" * 16, "FF" * 32, "00" * 16, "00" * 32, "00" * 16),
        ("00" * 16, bytes.fromhex("00" * 32), "00" * 16, "00" * 32, "00" * 16),
        # m3
        ("00" * 16, "00" * 32, "FF" * 16, "00" * 32, "00" * 16),
        ("00" * 16, "00" * 32, bytes.fromhex("00" * 16), "00" * 32, "00" * 16),
        # m4
        ("00" * 16, "00" * 32, "00" * 16, "FF" * 32, "00" * 16),
        ("00" * 16, "00" * 32, "00" * 16, bytes.fromhex("00" * 32), "00" * 16),
        # m5
        ("00" * 16, "00" * 32, "00" * 16, "00" * 32, "FF" * 16),
        ("00" * 16, "00" * 32, "00" * 16, "00" * 32, bytes.fromhex("00" * 16)),
    ),
)
def test_update_messages_no_exception_raised(m1, m2, m3, m4, m5):
    MemoryUpdateMessages(m1=m1, m2=m2, m3=m3, m4=m4, m5=m5)


@mark.parametrize(
    "m1, m2, m3, m4, m5, errortype",
    (
        # ("00" * 16, "00" * 32, "00" * 16, "00" * 32, "00" * 16, ValueError),
        # m1
        ("00" * 18, "00" * 32, "00" * 16, "00" * 32, "00" * 16, ValueError),
        ("000", "00" * 32, "00" * 16, "00" * 32, "00" * 16, ValueError),
        ("ZZ", "00" * 32, "00" * 16, "00" * 32, "00" * 16, ValueError),
        ("", "00" * 32, "00" * 16, "00" * 32, "00" * 16, ValueError),
        (bytes(), "00" * 32, "00" * 16, "00" * 32, "00" * 16, ValueError),
        (2.5, "00" * 32, "00" * 16, "00" * 32, "00" * 16, TypeError),
        # m2
        ("00" * 16, "00" * 34, "00" * 16, "00" * 32, "00" * 16, ValueError),
        ("00" * 16, "000", "00" * 16, "00" * 32, "00" * 16, ValueError),
        ("00" * 16, "ZZ", "00" * 16, "00" * 32, "00" * 16, ValueError),
        ("00" * 16, "", "00" * 16, "00" * 32, "00" * 16, ValueError),
        ("00" * 16, bytes(), "00" * 16, "00" * 32, "00" * 16, ValueError),
        ("00" * 16, 2.5, "00" * 16, "00" * 32, "00" * 16, TypeError),
        # m3
        ("00" * 16, "00" * 32, "00" * 18, "00" * 32, "00" * 16, ValueError),
        ("00" * 16, "00" * 32, "000", "00" * 32, "00" * 16, ValueError),
        ("00" * 16, "00" * 32, "ZZ" * 16, "00" * 32, "00" * 16, ValueError),
        ("00" * 16, "00" * 32, "", "00" * 32, "00" * 16, ValueError),
        ("00" * 16, "00" * 32, bytes() * 16, "00" * 32, "00" * 16, ValueError),
        ("00" * 16, "00" * 32, 2.5, "00" * 32, "00" * 16, TypeError),
        # m4
        ("00" * 16, "00" * 32, "00" * 16, "00" * 34, "00" * 16, ValueError),
        ("00" * 16, "00" * 32, "00" * 16, "000", "00" * 16, ValueError),
        ("00" * 16, "00" * 32, "00" * 16, "ZZ", "00" * 16, ValueError),
        ("00" * 16, "00" * 32, "00" * 16, "", "00" * 16, ValueError),
        ("00" * 16, "00" * 32, "00" * 16, bytes() * 32, "00" * 16, ValueError),
        ("00" * 16, "00" * 32, "00" * 16, 2.5, "00" * 16, TypeError),
        # m5
        ("00" * 16, "00" * 32, "00" * 16, "00" * 32, "00" * 18, ValueError),
        ("00" * 16, "00" * 32, "00" * 16, "00" * 32, "000", ValueError),
        ("00" * 16, "00" * 32, "00" * 16, "00" * 32, "ZZ", ValueError),
        ("00" * 16, "00" * 32, "00" * 16, "00" * 32, "", ValueError),
        ("00" * 16, "00" * 32, "00" * 16, "00" * 32, bytes(), ValueError),
        ("00" * 16, "00" * 32, "00" * 16, "00" * 32, 2.5, TypeError),
    ),
)
def test_update_messages_raises(m1, m2, m3, m4, m5, errortype):
    with raises(errortype):
        MemoryUpdateMessages(m1=m1, m2=m2, m3=m3, m4=m4, m5=m5)
