"""I/O helpers for evidence handling and case file management."""
from __future__ import annotations

from pathlib import Path
import hashlib
from typing import BinaryIO

BUFFER_SIZE = 1024 * 1024


def compute_sha256(path: Path) -> str:
    """Compute SHA-256 for a file using buffered reads."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(BUFFER_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_block(handle: BinaryIO, size: int) -> bytes:
    """Read a block of bytes from a binary file handle."""
    return handle.read(size)


def ensure_directory(path: Path) -> None:
    """Create a directory if it does not exist."""
    path.mkdir(parents=True, exist_ok=True)
