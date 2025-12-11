"""Placeholder collectors for operating system artefacts."""
from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path

from ..core.logging_utils import get_logger
from ..core.models import Artefact, ArtefactType, Case, TimelineEvent
from ..core.pipeline import add_artefact, add_timeline_event

LOGGER = get_logger(__name__)


def collect_windows_context(root_path: Path, case: Case) -> list[Artefact]:
    """Mock collection of Windows artefacts."""
    artefacts: list[Artefact] = []
    fake_reg = Artefact(
        artefact_id=str(uuid.uuid4()),
        description="Simulated Windows Registry hive with BitLocker traces",
        source=str(root_path),
        artefact_type=ArtefactType.OS_CONTEXT,
        timestamp=datetime.utcnow(),
    )
    add_artefact(case, fake_reg)
    add_timeline_event(case, "Collected Windows registry placeholder", fake_reg.artefact_id)
    artefacts.append(fake_reg)
    LOGGER.info("Windows context collection complete")
    return artefacts


def collect_linux_context(root_path: Path, case: Case) -> list[Artefact]:
    """Mock collection of Linux artefacts."""
    artefacts: list[Artefact] = []
    crypttab = Artefact(
        artefact_id=str(uuid.uuid4()),
        description="Simulated /etc/crypttab entry referencing encrypted volume",
        source=str(root_path),
        artefact_type=ArtefactType.OS_CONTEXT,
        timestamp=datetime.utcnow(),
    )
    add_artefact(case, crypttab)
    add_timeline_event(case, "Collected Linux crypttab placeholder", crypttab.artefact_id)
    artefacts.append(crypttab)
    LOGGER.info("Linux context collection complete")
    return artefacts
