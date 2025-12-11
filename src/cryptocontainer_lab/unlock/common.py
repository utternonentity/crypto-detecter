"""Shared unlocking helpers with placeholder cryptographic routines."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ..core.logging_utils import get_logger
from ..core.models import ContainerCandidate, UnlockAttempt, UnlockResult

LOGGER = get_logger(__name__)


@dataclass
class UnlockContext:
    """State passed into unlock routines."""

    candidate: ContainerCandidate
    secret: str
    method: str
    secret_id: str


def derive_key(secret: str, length: int = 32) -> bytes:
    """Derive a deterministic key using a placeholder KDF (SHA-256-based)."""
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    while len(digest) < length:
        digest += hashlib.sha256(digest).digest()
    return digest[:length]


def verify_magic(header: bytes, expected: bytes) -> bool:
    """Check whether decrypted header data begins with expected magic bytes."""
    return header.startswith(expected)


def attempt_unlock(context: UnlockContext, expected_magic: bytes, header_reader) -> UnlockAttempt:
    """Attempt to verify a container header with a provided secret."""
    try:
        header = header_reader(context.candidate)
        derived = derive_key(context.secret)
        preview = bytes(a ^ b for a, b in zip(header[: len(derived)], derived[: len(header)]))
        if verify_magic(preview, expected_magic):
            result = UnlockAttempt(
                container_id=context.candidate.candidate_id,
                method=context.method,
                secret_id=context.secret_id,
                result=UnlockResult.SUCCESS,
                message="Header verification succeeded",
            )
        else:
            result = UnlockAttempt(
                container_id=context.candidate.candidate_id,
                method=context.method,
                secret_id=context.secret_id,
                result=UnlockResult.FAILURE,
                message="Header verification failed",
            )
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("Unlock attempt errored")
        result = UnlockAttempt(
            container_id=context.candidate.candidate_id,
            method=context.method,
            secret_id=context.secret_id,
            result=UnlockResult.ERROR,
            message=str(exc),
        )
    return result
