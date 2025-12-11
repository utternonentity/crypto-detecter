"""Report format helpers."""
from __future__ import annotations

from datetime import datetime
from typing import Iterable

from ..core.models import Case, ContainerCandidate, Evidence, TimelineEvent

__all__ = [
    "format_bytes",
    "format_timestamp",
    "summarize_evidence",
    "summarize_containers",
    "summarize_timeline",
    "summarize_case",
]


def format_bytes(value: int) -> str:
    """Convert an integer byte value into a human-friendly string."""

    suffixes = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for suffix in suffixes:
        if size < 1024 or suffix == suffixes[-1]:
            return f"{size:.2f} {suffix}" if suffix != "B" else f"{int(size)} {suffix}"
        size /= 1024
    return f"{value} B"


def format_timestamp(timestamp: datetime) -> str:
    """Format a datetime value using ISO 8601 with timezone awareness removed."""

    return timestamp.replace(tzinfo=None).isoformat(timespec="seconds")


def summarize_evidence(evidence: Iterable[Evidence]) -> list[str]:
    """Return bullet-point strings describing evidence items."""

    summaries = []
    for ev in evidence:
        size = format_bytes(ev.size)
        summaries.append(
            f"- `{ev.evidence_id}` {ev.description} ({ev.evidence_type.value}), size={size}, sha256={ev.sha256}"
        )
    return summaries


def summarize_containers(containers: Iterable[ContainerCandidate]) -> list[str]:
    """Return bullet-point strings describing detected containers."""

    entries = []
    for container in containers:
        entries.append(
            f"- `{container.candidate_id}` on evidence `{container.evidence_id}` at offset {container.offset} "
            f"({container.container_type.value}, confidence={container.confidence:.2f})"
        )
    return entries


def summarize_timeline(events: Iterable[TimelineEvent]) -> list[str]:
    """Return bullet-point strings for a set of timeline events."""

    lines = []
    for event in events:
        timestamp = format_timestamp(event.timestamp)
        detail = f" — artefact {event.artefact_id}" if event.artefact_id else ""
        lines.append(f"- {timestamp}: {event.description}{detail}")
    return lines


def summarize_case(case: Case) -> str:
    """Produce a compact multiline summary suitable for console output."""

    lines = [
        f"Case {case.metadata.case_id} (examiner={case.metadata.examiner or 'Unknown'})",
        "Evidence:",
        *summarize_evidence(case.evidence),
        "Detected containers:",
        *summarize_containers(case.containers),
        "Timeline:",
        *summarize_timeline(case.timeline),
    ]
    if not case.timeline:
        lines.append("- No timeline events recorded")
    return "\n".join(lines)
