"""Known cryptographic container signatures."""
from __future__ import annotations

BITLOCKER_HEADER = b"-FVE-FS-"
LUKS_MAGIC = b"LUKS\xba\xbe"
VERACRYPT_TC_HEADER = b"\x54\x52\x55\x45"  # "TRUE" marker for legacy TrueCrypt-like headers

DEFAULT_SCAN_OFFSETS = [0, 4096, 65536]
HEADER_WINDOW = 8192
