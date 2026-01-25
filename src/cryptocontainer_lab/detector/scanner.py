"""Scanning utilities for locating cryptographic containers."""
from __future__ import annotations

import os
import stat
import uuid
from pathlib import Path
from typing import Callable, Iterable, Optional

from ..core.logging_utils import get_logger
from ..core.models import ContainerCandidate, ContainerType
from ..detector.heuristics import estimate_entropy
from ..detector.signatures import BITLOCKER_HEADER, DEFAULT_SCAN_OFFSETS, HEADER_WINDOW, LUKS_MAGIC, VERACRYPT_EXTENSIONS

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


def _veracrypt_confidence(file_path: Path, header_block: bytes) -> Optional[float]:
    """Return a confidence score for VeraCrypt/TrueCrypt candidates based on heuristics."""
    if file_path.suffix.lower() not in VERACRYPT_EXTENSIONS:
        return None
    if not header_block:
        return 0.35
    if len(header_block) < 1024:
        return 0.4
    entropy = estimate_entropy(header_block[:4096])
    if entropy >= 7.2:
        return 0.65
    if entropy >= 6.8:
        return 0.5
    return 0.4


def _is_reparse_point(path: Path) -> bool:
    """Return True when the path is a Windows reparse point (junction, symlink, etc.)."""
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _iter_files(root: Path) -> Iterable[Path]:
    """Yield file paths inside the provided root."""
    if root.is_dir():
        visited: set[tuple[int, int]] = set()
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            safe_dirnames: list[str] = []
            for dirname in dirnames:
                candidate = Path(dirpath) / dirname
                if candidate.is_symlink() or _is_reparse_point(candidate):
                    continue
                try:
                    stat_result = candidate.stat(follow_symlinks=False)
                except OSError:
                    continue
                key = (stat_result.st_dev, stat_result.st_ino)
                if key in visited:
                    continue
                visited.add(key)
                safe_dirnames.append(dirname)
            dirnames[:] = safe_dirnames
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
    seen: set[tuple[ContainerType, int]] = set()
    max_signature_len = max(len(BITLOCKER_HEADER), len(LUKS_MAGIC))
    overlap = max_signature_len - 1
    with file_path.open("rb") as handle:
        header_block = b""
        for base_offset in DEFAULT_SCAN_OFFSETS:
            handle.seek(base_offset)
            block = handle.read(HEADER_WINDOW)
            if base_offset == 0:
                header_block = block
            for candidate in _scan_block(block, base_offset, file_path):
                key = (candidate.container_type, candidate.offset)
                if key in seen:
                    continue
                seen.add(key)
                discovered.append(candidate)

        if not any(item.container_type in {ContainerType.VERACRYPT, ContainerType.TRUECRYPT} for item in discovered):
            confidence = _veracrypt_confidence(file_path, header_block)
            if confidence is not None:
                note = (
                    "Высокая энтропия заголовка и типичное расширение VeraCrypt/TrueCrypt."
                    if confidence >= 0.6
                    else "Типичное расширение VeraCrypt/TrueCrypt (эвристика)."
                )
                discovered.append(
                    ContainerCandidate(
                        candidate_id=str(uuid.uuid4()),
                        source_path=file_path,
                        offset=0,
                        container_type=ContainerType.VERACRYPT,
                        confidence=confidence,
                        notes=note,
                    )
                )

        handle.seek(0)
        offset = 0
        tail = b""
        while True:
            block = handle.read(block_size)
            if not block:
                break
            combined = tail + block
            base_offset = offset - len(tail)
            for candidate in _scan_block(combined, base_offset, file_path):
                key = (candidate.container_type, candidate.offset)
                if key in seen:
                    continue
                seen.add(key)
                discovered.append(candidate)
            tail = block[-overlap:] if overlap > 0 else b""
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
            if candidate.confidence >= 0.75:
                LOGGER.info(
                    "Обнаружен криптоконтейнер: %s (уверенность %.0f%%) %s @ 0x%X",
                    candidate.container_type.value,
                    candidate.confidence * 100,
                    candidate.source_path,
                    candidate.offset,
                )
    LOGGER.info("Сканирование завершено. Найдено контейнеров: %d", len(results))
    return results
