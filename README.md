# Secure Hardware Extension

![CICD](https://github.com/Deejuha/SecureHardwareExtension/workflows/python-test/badge.svg?branch=master)
![Python](https://img.shields.io/pypi/pyversions/Django?style=plastic)

A set of tools for AUTOSAR Secure Hardware Extension.

Available features:

- Generate SHE Memory update protocol messages (M1 M2 M3 M4 M5).
- Parse M1 M2 Memory update protocol messages in order to get the update information.

## Disclaimer

Vector's related specification specifies different layout of `flags` - it uses 5 flags instead of 6, described in AUTOSAR specs as this repo fully follows. Please adjust script accordingly then, I would be glad to some PR propositions if you have anything working. Enjoy!

## Prerequisites

With using Python greater than 3.8 install package to your environment.

```bash
pip install SecureHardwareExtension
```

## Examples

### Calculate M1 - M5 messages by using update info

```py
from secure_hardware_extension.datatypes import MemoryUpdateInfo, SecurityFlags
from secure_hardware_extension.key_slots.autosar import AutosarKeySlots
from secure_hardware_extension.memory_update import MemoryUpdateProtocol
update_info = MemoryUpdateInfo(
    new_key="0f0e0d0c0b0a09080706050403020100",  # Hex string or bytes
    auth_key="000102030405060708090a0b0c0d0e0f",  # Hex string or bytes
    new_key_id=AutosarKeySlots.KEY_1,  # Enum or integer
    auth_key_id=AutosarKeySlots.MASTER_ECU_KEY,  # Enum or integer
    counter=1,
    uid="00" * 14 + "01", # Hex string or bytes
    flags=SecurityFlags(),
)
protocol = MemoryUpdateProtocol(update_info)

protocol.m1
>>> b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01A'

protocol.m2
>>> b'+\x11\x1e-\x93\xf4\x86Vk\xcb\xba\x1d\x7fz\x97\x97\xc9FC\xb0P\xfc]M}\xe1L\xffh"\x03\xc3'
```

### Select apprioprate key slot flags

```py
flags = SecurityFlags()
flags.boot_protection = True
update_info = MemoryUpdateInfo(
    ...
    flags=flags,
)

flags = SecurityFlags(fid=20)
update_info = MemoryUpdateInfo(
    ...
    flags=flags,
)
```

### Get update info from M1 and M2 messages

```py
from secure_hardware_extension.datatypes import MemoryUpdateMessages, she_bytes
from secure_hardware_extension.memory_update import MemoryUpdateProtocol
messages = MemoryUpdateMessages(
    auth_key=she_bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
    m1=she_bytes.fromhex("00000000000000000000000000000141"),
    m2=she_bytes.fromhex(
        "2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3"
    ),
)
update_protocol = MemoryUpdateProtocol(messages)

update_protocol.update_info.new_key
>>> b'\x0f\x0e\r\x0c\x0b\n\t\x08\x07\x06\x05\x04\x03\x02\x01\x0
```

## Sources

Accessed 26.07.2025.

[Autosar specification](https://www.autosar.org/fileadmin/standards/R22-11/FO/AUTOSAR_TR_SecureHardwareExtensions.pdf)

[NXP application note](https://www.nxp.com/docs/en/application-note/AN4234.pdf)

[Vector SHE Key Update Protocol](https://support.vector.com/sys_attachment.do?sys_id=534d25eb87548590b9f233770cbb3550)
