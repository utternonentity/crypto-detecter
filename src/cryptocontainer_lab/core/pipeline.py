"""Pipeline orchestration for expert examination workflows."""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from .io import compute_sha256, ensure_directory
from .logging_utils import get_logger
from .models import (
    Artefact,
    ArtefactType,
    Case,
    CaseMetadata,
    ContainerCandidate,
    CustodyEvent,
    Evidence,
    EvidenceType,
    TimelineEvent,
)

LOGGER = get_logger(__name__)


CASE_FILE = "case.json"


def create_case(root_path: Path, examiner: Optional[str] = None) -> Case:
    """Create a new case directory structure and return the Case instance."""
    ensure_directory(root_path)
    for child in ("logs", "artifacts", "reports"):
        ensure_directory(root_path / child)
    metadata = CaseMetadata(case_id=str(uuid.uuid4()), examiner=examiner, created_at=datetime.utcnow())
    case = Case(root_path=root_path, metadata=metadata)
    save_case(case)
    LOGGER.info("Created case %s", metadata.case_id)
    return case


def load_case(root_path: Path) -> Case:
    """Load an existing case from disk."""
    case_file = root_path / CASE_FILE
    data = json.loads(case_file.read_text(encoding="utf-8"))
    case = Case.from_dict(data)
    LOGGER.info("Loaded case %s", case.metadata.case_id)
    return case


def save_case(case: Case) -> None:
    """Persist case data to disk."""
    case_file = case.root_path / CASE_FILE
    case_file.write_text(json.dumps(case.to_dict(), indent=2), encoding="utf-8")
    LOGGER.debug("Saved case %s", case.metadata.case_id)


def add_evidence(case: Case, path: Path, description: str, evidence_type: EvidenceType) -> Evidence:
    """Register evidence and compute its hash."""
    sha256 = compute_sha256(path)
    evidence = Evidence(
        evidence_id=str(uuid.uuid4()),
        path=path,
        description=description,
        evidence_type=evidence_type,
        sha256=sha256,
        size=path.stat().st_size,
    )
    case.evidence.append(evidence)
    case.custody_log.append(
        CustodyEvent(timestamp=datetime.utcnow(), actor=case.metadata.examiner or "unknown", action=f"Added evidence {evidence.evidence_id}")
    )
    save_case(case)
    LOGGER.info("Registered evidence %s", evidence.evidence_id)
    return evidence


def register_container(case: Case, candidate: ContainerCandidate) -> None:
    """Persist a detected container candidate in the case."""
    case.containers.append(candidate)
    case.artefacts.append(
        Artefact(
            artefact_id=str(uuid.uuid4()),
            description=f"Detected container at offset {candidate.offset}",
            source=candidate.evidence_id,
            artefact_type=ArtefactType.DETECTION,
        )
    )
    save_case(case)
    LOGGER.info("Registered container %s", candidate.candidate_id)


def add_timeline_event(case: Case, description: str, artefact_id: Optional[str] = None) -> TimelineEvent:
    """Append a timeline entry and keep the sequence sorted."""
    event = TimelineEvent(description=description, timestamp=datetime.utcnow(), artefact_id=artefact_id)
    case.timeline.append(event)
    case.timeline.sort(key=lambda e: e.timestamp)
    save_case(case)
    LOGGER.debug("Timeline updated with %s", description)
    return event


def add_artefact(case: Case, artefact: Artefact) -> None:
    """Store a new artefact in the case."""
    case.artefacts.append(artefact)
    save_case(case)
    LOGGER.info("Artefact recorded: %s", artefact.artefact_id)


def add_unlock_attempt(case: Case, attempt) -> None:
    """Record an unlock attempt and persist it."""
    case.unlock_attempts.append(attempt)
    save_case(case)
    LOGGER.info("Unlock attempt for %s stored", attempt.container_id)
