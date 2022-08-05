from datatypes import MemoryUpdateInfo, SecurityFlags, she_bytes
from memory_update import MemoryUpdateProtocol
from unittest.mock import Mock


def test_aes_compress():
    """
    https://www.autosar.org/fileadmin/user_upload/standards/foundation/19-11/AUTOSAR_TR_SecureHardwareExtensions.pdf
    4.13.2.4 Miyaguchi-Preneel compression function

    """
    update_info = Mock()
    expected = she_bytes.fromhex("c7277a0dc1fb853b5f4d9cbd26be40c6")
    update_protocol = MemoryUpdateProtocol(update_info)
    output = update_protocol._compress(
        she_bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        she_bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51"),
        she_bytes.fromhex("80000000000000000000000000000100"),
    )
    assert expected == output


def test_update_protocol():
    update_info = MemoryUpdateInfo(
        new_key="0f0e0d0c0b0a09080706050403020100",
        auth_key="000102030405060708090a0b0c0d0e0f",
        new_key_id=4,
        auth_key_id=1,
        counter=1,
        uid="00" * 14 + "01",
        flags=SecurityFlags(),
    )
    expected_k1 = she_bytes.fromhex("118a46447a770d87828a69c222e2d17e")
    expected_k2 = she_bytes.fromhex("2ebb2a3da62dbd64b18ba6493e9fbe22")
    expected_k3 = she_bytes.fromhex("ed2de7864a47f6bac319a9dc496a788f")
    expected_k4 = she_bytes.fromhex("ec9386fefaa1c598246144343de5f26a")
    expected_m1 = she_bytes.fromhex("00000000000000000000000000000141")
    expected_m2 = she_bytes.fromhex("2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3")
    expected_m3 = she_bytes.fromhex("b9d745e5ace7d41860bc63c2b9f5bb46")
    expected_m4 = she_bytes.fromhex("00000000000000000000000000000141b472e8d8727d70d57295e74849a27917")
    expected_m5 = she_bytes.fromhex("820d8d95dc11b4668878160cb2a4e23e")
    update_protocol = MemoryUpdateProtocol(update_info)
    assert expected_k1 == update_protocol.k1
    assert expected_k2 == update_protocol.k2
    assert expected_k3 == update_protocol.k3
    assert expected_k4 == update_protocol.k4
    assert expected_m1 == update_protocol.m1
    assert expected_m2 == update_protocol.m2
    assert expected_m3 == update_protocol.m3
    assert expected_m4 == update_protocol.m4
    assert expected_m5 == update_protocol.m5
    