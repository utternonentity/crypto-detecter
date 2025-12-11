"""VeraCrypt unlock placeholder."""
from __future__ import annotations

from ..detector.signatures import VERACRYPT_TC_HEADER
from .common import UnlockContext, attempt_unlock


def unlock_with_password(context: UnlockContext, header_reader) -> None:
    """Attempt to validate VeraCrypt/TrueCrypt header using a provided password."""
    return attempt_unlock(context, VERACRYPT_TC_HEADER, header_reader)
