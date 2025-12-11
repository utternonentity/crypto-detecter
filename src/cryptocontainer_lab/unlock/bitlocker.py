"""BitLocker unlock placeholder."""
from __future__ import annotations

from ..detector.signatures import BITLOCKER_HEADER
from .common import UnlockContext, attempt_unlock


def unlock_with_password(context: UnlockContext, header_reader) -> None:
    """Attempt to validate BitLocker header using a provided password."""
    return attempt_unlock(context, BITLOCKER_HEADER, header_reader)
