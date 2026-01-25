"""Known cryptographic container signatures."""
from __future__ import annotations

BITLOCKER_HEADER = b"-FVE-FS-"
LUKS_MAGIC = b"LUKS\xba\xbe"

# VeraCrypt/TrueCrypt volumes have no stable plaintext header signature.
# We rely on heuristic hints such as common file extensions instead.
VERACRYPT_EXTENSIONS = {".hc", ".tc"}

DEFAULT_SCAN_OFFSETS = [0, 4096, 65536]
HEADER_WINDOW = 8192
