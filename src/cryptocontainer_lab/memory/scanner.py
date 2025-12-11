"""Memory dump scanning utilities."""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Iterable

from ..core.logging_utils import get_logger
from ..core.models import Artefact, ArtefactType, Case, ContainerType
from ..core.pipeline import add_artefact
from ..detector.signatures import BITLOCKER_HEADER, LUKS_MAGIC, VERACRYPT_TC_HEADER

LOGGER = get_logger(__name__)
CHUNK_SIZE = 1024 * 1024
POTENTIAL_KEY_LENGTH = 32


def _search_keys_near_signature(chunk: bytes, index: int) -> Iterable[bytes]:
    """Return potential key-like sequences near a signature offset."""
    window = chunk[index : index + 256]
    for start in range(0, max(len(window) - POTENTIAL_KEY_LENGTH, 1), POTENTIAL_KEY_LENGTH):
        candidate = window[start : start + POTENTIAL_KEY_LENGTH]
        if len(candidate) == POTENTIAL_KEY_LENGTH:
            yield candidate


def scan_memory_dump(dump_path: Path, case: Case, evidence_id: str) -> list[Artefact]:
    """Scan a memory dump for known signatures and key-like material."""
    LOGGER.info("Scanning memory dump %s", dump_path)
    artefacts: list[Artefact] = []
    with dump_path.open("rb") as handle:
        offset = 0
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            for signature, ctype in [
                (BITLOCKER_HEADER, ContainerType.BITLOCKER),
                (LUKS_MAGIC, ContainerType.LUKS),
                (VERACRYPT_TC_HEADER, ContainerType.VERACRYPT),
            ]:
                idx = chunk.find(signature)
                if idx != -1:
                    artefact = Artefact(
                        artefact_id=str(uuid.uuid4()),
                        description=f"Signature {ctype.value} located in memory",
                        source=evidence_id,
                        artefact_type=ArtefactType.MEMORY,
                        timestamp=None,
                    )
                    add_artefact(case, artefact)
                    artefacts.append(artefact)
                    for key_candidate in _search_keys_near_signature(chunk, idx):
                        key_art = Artefact(
                            artefact_id=str(uuid.uuid4()),
                            description="Potential key material extracted",
                            source=evidence_id,
                            artefact_type=ArtefactType.MEMORY,
                            path=None,
                        )
                        add_artefact(case, key_art)
                        artefacts.append(key_art)
                        LOGGER.debug("Captured candidate key near offset %d", offset + idx)
            offset += len(chunk)
    LOGGER.info("Memory scanning produced %d artefacts", len(artefacts))
    return artefacts
