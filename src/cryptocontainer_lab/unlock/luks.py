"""LUKS unlock placeholder."""
from __future__ import annotations

from ..detector.signatures import LUKS_MAGIC
from .common import UnlockContext, attempt_unlock


def unlock_with_password(context: UnlockContext, header_reader) -> None:
    """Attempt to validate LUKS header using a provided password."""
    return attempt_unlock(context, LUKS_MAGIC, header_reader)
