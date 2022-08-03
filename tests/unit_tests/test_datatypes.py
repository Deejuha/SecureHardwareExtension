from datatypes import she_bytes
from pytest import mark


@mark.parametrize(
    "a, b, expected",
    [
        ("FF", "FF", "00"),
        ("00", "00", "00"),
        ("FF", "00", "FF"),
        ("FFFFFF", "FFFFFF", "000000"),
        ("FF00FF", "00FF00", "FFFFFF"),
        ("AA55AA55AA55AA55", "0000000000000000", "AA55AA55AA55AA55")
    ],
)
def test_bytes_xor(a, b, expected):
    bytes_a = she_bytes.fromhex(a)
    bytes_b = she_bytes.fromhex(b)
    bytes_expected = she_bytes.fromhex(expected)
    result = bytes_a ^ bytes_b
    assert bytes_expected == result
