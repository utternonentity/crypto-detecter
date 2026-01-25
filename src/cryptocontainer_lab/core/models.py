"""Data models for container detection."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class ContainerType(str, Enum):
    """Known container types."""

    BITLOCKER = "bitlocker"
    VERACRYPT = "veracrypt"
    TRUECRYPT = "truecrypt"
    LUKS = "luks"
    UNKNOWN = "unknown"


@dataclass
class ContainerCandidate:
    """Potential cryptographic container located during scanning."""

    candidate_id: str
    source_path: Path
    offset: int
    container_type: ContainerType
    confidence: float = 0.0
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "source_path": str(self.source_path),
            "offset": self.offset,
            "container_type": self.container_type.value,
            "confidence": self.confidence,
            "notes": self.notes,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "ContainerCandidate":
        return ContainerCandidate(
            candidate_id=data["candidate_id"],
            source_path=Path(data["source_path"]),
            offset=int(data["offset"]),
            container_type=ContainerType(data["container_type"]),
            confidence=float(data.get("confidence", 0.0)),
            notes=data.get("notes", ""),
        )
