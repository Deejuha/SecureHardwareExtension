from datatypes import SecurityFlags, she_bytes
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
