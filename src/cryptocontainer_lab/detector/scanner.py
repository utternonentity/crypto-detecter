"""Scan disk images for container signatures."""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Iterable

from ..core.logging_utils import get_logger
from ..core.models import Case, ContainerCandidate, ContainerType
from ..core.pipeline import register_container
from ..detector.signatures import BITLOCKER_HEADER, DEFAULT_SCAN_OFFSETS, HEADER_WINDOW, LUKS_MAGIC, VERACRYPT_TC_HEADER

LOGGER = get_logger(__name__)


def _scan_block(block: bytes, offset: int, evidence_id: str) -> Iterable[ContainerCandidate]:
    """Analyze a block of bytes for known header patterns."""
    if BITLOCKER_HEADER in block:
        yield ContainerCandidate(
            candidate_id=str(uuid.uuid4()),
            evidence_id=evidence_id,
            offset=offset + block.index(BITLOCKER_HEADER),
            container_type=ContainerType.BITLOCKER,
            confidence=0.9,
            notes="FVE-FS header signature detected",
        )
    if LUKS_MAGIC in block:
        yield ContainerCandidate(
            candidate_id=str(uuid.uuid4()),
            evidence_id=evidence_id,
            offset=offset + block.index(LUKS_MAGIC),
            container_type=ContainerType.LUKS,
            confidence=0.9,
            notes="LUKS magic detected",
        )
    if VERACRYPT_TC_HEADER in block:
        yield ContainerCandidate(
            candidate_id=str(uuid.uuid4()),
            evidence_id=evidence_id,
            offset=offset + block.index(VERACRYPT_TC_HEADER),
            container_type=ContainerType.VERACRYPT,
            confidence=0.5,
            notes="VeraCrypt/TrueCrypt style header marker",
        )


def scan_image_for_containers(image_path: Path, case: Case, evidence_id: str, block_size: int = 1024 * 1024) -> list[ContainerCandidate]:
    """Scan a disk image for potential cryptographic containers and register findings."""
    LOGGER.info("Scanning %s for containers", image_path)
    discovered: list[ContainerCandidate] = []
    with image_path.open("rb") as handle:
        for base_offset in DEFAULT_SCAN_OFFSETS:
            handle.seek(base_offset)
            block = handle.read(HEADER_WINDOW)
            for candidate in _scan_block(block, base_offset, evidence_id):
                register_container(case, candidate)
                discovered.append(candidate)

        handle.seek(0)
        offset = 0
        while True:
            block = handle.read(block_size)
            if not block:
                break
            for candidate in _scan_block(block, offset, evidence_id):
                register_container(case, candidate)
                discovered.append(candidate)
            offset += len(block)
    LOGGER.info("Detected %d container candidates", len(discovered))
    return discovered
