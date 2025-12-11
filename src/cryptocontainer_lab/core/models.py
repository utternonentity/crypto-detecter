"""Data models for cases, evidence, artefacts, and workflow objects."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, List, Optional


class ContainerType(str, Enum):
    """Known container types."""

    BITLOCKER = "bitlocker"
    VERACRYPT = "veracrypt"
    TRUECRYPT = "truecrypt"
    LUKS = "luks"
    UNKNOWN = "unknown"


class EvidenceType(str, Enum):
    """Types of evidence managed by the lab."""

    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    CONFIG = "config"
    OTHER = "other"


class ArtefactType(str, Enum):
    """Categorization of collected artefacts."""

    OS_CONTEXT = "os_context"
    MEMORY = "memory"
    DETECTION = "detection"
    OTHER = "other"


class UnlockResult(str, Enum):
    """Status of an unlock attempt."""

    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"


@dataclass
class Evidence:
    """Representation of an evidence item."""

    evidence_id: str
    path: Path
    description: str
    evidence_type: EvidenceType
    sha256: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["path"] = str(self.path)
        data["evidence_type"] = self.evidence_type.value
        return data

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Evidence":
        return Evidence(
            evidence_id=data["evidence_id"],
            path=Path(data["path"]),
            description=data["description"],
            evidence_type=EvidenceType(data["evidence_type"]),
            sha256=data["sha256"],
            size=int(data["size"]),
        )


@dataclass
class ContainerCandidate:
    """Potential cryptographic container located during scanning."""

    candidate_id: str
    evidence_id: str
    offset: int
    container_type: ContainerType
    confidence: float = 0.0
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "evidence_id": self.evidence_id,
            "offset": self.offset,
            "container_type": self.container_type.value,
            "confidence": self.confidence,
            "notes": self.notes,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "ContainerCandidate":
        return ContainerCandidate(
            candidate_id=data["candidate_id"],
            evidence_id=data["evidence_id"],
            offset=int(data["offset"]),
            container_type=ContainerType(data["container_type"]),
            confidence=float(data.get("confidence", 0.0)),
            notes=data.get("notes", ""),
        )


@dataclass
class Artefact:
    """Evidence artefact collected during analysis."""

    artefact_id: str
    description: str
    source: str
    artefact_type: ArtefactType
    path: Optional[Path] = None
    timestamp: Optional[datetime] = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["path"] = str(self.path) if self.path else None
        data["artefact_type"] = self.artefact_type.value
        data["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return data

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Artefact":
        ts = data.get("timestamp")
        return Artefact(
            artefact_id=data["artefact_id"],
            description=data["description"],
            source=data["source"],
            artefact_type=ArtefactType(data["artefact_type"]),
            path=Path(data["path"]) if data.get("path") else None,
            timestamp=datetime.fromisoformat(ts) if ts else None,
        )


@dataclass
class TimelineEvent:
    """Time-ordered view of collected facts."""

    description: str
    timestamp: datetime
    artefact_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "artefact_id": self.artefact_id,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "TimelineEvent":
        return TimelineEvent(
            description=data["description"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            artefact_id=data.get("artefact_id"),
        )


@dataclass
class CustodyEvent:
    """Log of chain-of-custody actions."""

    timestamp: datetime
    actor: str
    action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "action": self.action,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "CustodyEvent":
        return CustodyEvent(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            actor=data["actor"],
            action=data["action"],
        )


@dataclass
class UnlockAttempt:
    """Capture the result of an unlock trial."""

    container_id: str
    method: str
    secret_id: str
    result: UnlockResult
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "container_id": self.container_id,
            "method": self.method,
            "secret_id": self.secret_id,
            "result": self.result.value,
            "message": self.message,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "UnlockAttempt":
        return UnlockAttempt(
            container_id=data["container_id"],
            method=data["method"],
            secret_id=data["secret_id"],
            result=UnlockResult(data["result"]),
            message=data["message"],
        )


@dataclass
class CaseMetadata:
    """Metadata describing a case."""

    case_id: str
    examiner: Optional[str]
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "examiner": self.examiner,
            "created_at": self.created_at.isoformat(),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "CaseMetadata":
        return CaseMetadata(
            case_id=data["case_id"],
            examiner=data.get("examiner"),
            created_at=datetime.fromisoformat(data["created_at"]),
        )


@dataclass
class Case:
    """Full case representation including artefacts and workflow results."""

    root_path: Path
    metadata: CaseMetadata
    evidence: List[Evidence] = field(default_factory=list)
    containers: List[ContainerCandidate] = field(default_factory=list)
    artefacts: List[Artefact] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    unlock_attempts: List[UnlockAttempt] = field(default_factory=list)
    custody_log: List[CustodyEvent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_path": str(self.root_path),
            "metadata": self.metadata.to_dict(),
            "evidence": [e.to_dict() for e in self.evidence],
            "containers": [c.to_dict() for c in self.containers],
            "artefacts": [a.to_dict() for a in self.artefacts],
            "timeline": [t.to_dict() for t in self.timeline],
            "unlock_attempts": [u.to_dict() for u in self.unlock_attempts],
            "custody_log": [c.to_dict() for c in self.custody_log],
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Case":
        return Case(
            root_path=Path(data["root_path"]),
            metadata=CaseMetadata.from_dict(data["metadata"]),
            evidence=[Evidence.from_dict(e) for e in data.get("evidence", [])],
            containers=[ContainerCandidate.from_dict(c) for c in data.get("containers", [])],
            artefacts=[Artefact.from_dict(a) for a in data.get("artefacts", [])],
            timeline=[TimelineEvent.from_dict(t) for t in data.get("timeline", [])],
            unlock_attempts=[UnlockAttempt.from_dict(u) for u in data.get("unlock_attempts", [])],
            custody_log=[CustodyEvent.from_dict(c) for c in data.get("custody_log", [])],
        )
