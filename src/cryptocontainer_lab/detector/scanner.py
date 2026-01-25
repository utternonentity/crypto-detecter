"""Scanning utilities for locating cryptographic containers."""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Callable, Iterable, Optional

from ..core.logging_utils import get_logger
from ..core.models import ContainerCandidate, ContainerType
from ..detector.signatures import BITLOCKER_HEADER, DEFAULT_SCAN_OFFSETS, HEADER_WINDOW, LUKS_MAGIC, VERACRYPT_TC_HEADER

LOGGER = get_logger(__name__)


def _scan_block(block: bytes, offset: int, source_path: Path) -> Iterable[ContainerCandidate]:
    """Analyze a block of bytes for known header patterns."""
    if BITLOCKER_HEADER in block:
        yield ContainerCandidate(
            candidate_id=str(uuid.uuid4()),
            source_path=source_path,
            offset=offset + block.index(BITLOCKER_HEADER),
            container_type=ContainerType.BITLOCKER,
            confidence=0.9,
            notes="Сигнатура заголовка BitLocker (FVE-FS).",
        )
    if LUKS_MAGIC in block:
        yield ContainerCandidate(
            candidate_id=str(uuid.uuid4()),
            source_path=source_path,
            offset=offset + block.index(LUKS_MAGIC),
            container_type=ContainerType.LUKS,
            confidence=0.9,
            notes="Сигнатура заголовка LUKS.",
        )
    if VERACRYPT_TC_HEADER in block:
        yield ContainerCandidate(
            candidate_id=str(uuid.uuid4()),
            source_path=source_path,
            offset=offset + block.index(VERACRYPT_TC_HEADER),
            container_type=ContainerType.VERACRYPT,
            confidence=0.5,
            notes="Маркер заголовка VeraCrypt/TrueCrypt.",
        )


def _iter_files(root: Path) -> Iterable[Path]:
    """Yield file paths inside the provided root."""
    if root.is_dir():
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                yield Path(dirpath) / filename
        return
    yield root


def scan_file_for_containers(
    file_path: Path,
    block_size: int = 1024 * 1024,
) -> list[ContainerCandidate]:
    """Scan a single file/device for container headers."""
    discovered: list[ContainerCandidate] = []
    with file_path.open("rb") as handle:
        for base_offset in DEFAULT_SCAN_OFFSETS:
            handle.seek(base_offset)
            block = handle.read(HEADER_WINDOW)
            for candidate in _scan_block(block, base_offset, file_path):
                discovered.append(candidate)

        handle.seek(0)
        offset = 0
        while True:
            block = handle.read(block_size)
            if not block:
                break
            for candidate in _scan_block(block, offset, file_path):
                discovered.append(candidate)
            offset += len(block)
    return discovered


def scan_path_for_containers(
    root: Path,
    block_size: int = 1024 * 1024,
    on_progress: Optional[Callable[[Path], None]] = None,
    on_result: Optional[Callable[[ContainerCandidate], None]] = None,
    on_error: Optional[Callable[[Path, Exception], None]] = None,
) -> list[ContainerCandidate]:
    """Scan files inside the root path for container signatures."""
    if not root.exists():
        raise FileNotFoundError(f"Путь не найден: {root}")

    results: list[ContainerCandidate] = []
    for file_path in _iter_files(root):
        if on_progress:
            on_progress(file_path)
        try:
            candidates = scan_file_for_containers(file_path, block_size=block_size)
        except Exception as exc:  # noqa: BLE001 - continue scanning other files
            LOGGER.warning("Не удалось просканировать %s: %s", file_path, exc)
            if on_error:
                on_error(file_path, exc)
            continue
        for candidate in candidates:
            results.append(candidate)
            if on_result:
                on_result(candidate)
    LOGGER.info("Сканирование завершено. Найдено контейнеров: %d", len(results))
    return results
