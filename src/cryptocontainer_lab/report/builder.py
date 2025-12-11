"""Report generation utilities."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.models import Case


def build_json_report(case: Case) -> dict[str, Any]:
    """Return a JSON-serializable representation of the case."""
    payload = case.to_dict()
    payload["notes"] = "Prototype tool; cryptographic operations are simplified for forensic demonstration."
    return payload


def build_markdown_report(case: Case) -> str:
    """Render a Markdown report summarizing case activities."""
    lines = [
        f"# Cryptocontainer Lab Report for Case {case.metadata.case_id}",
        "",
        f"**Examiner:** {case.metadata.examiner or 'Unknown'}",
        f"**Created:** {case.metadata.created_at.isoformat()}",
        "",
        "## Evidence",
    ]
    for ev in case.evidence:
        lines.append(f"- `{ev.evidence_id}`: {ev.description} ({ev.evidence_type.value}), SHA-256: {ev.sha256}")

    lines.append("\n## Detected Containers")
    for c in case.containers:
        lines.append(
            f"- `{c.candidate_id}` from evidence `{c.evidence_id}` at offset {c.offset} bytes; "
            f"type={c.container_type.value}, confidence={c.confidence:.2f}"
        )

    lines.append("\n## Artefacts")
    for a in case.artefacts:
        lines.append(f"- `{a.artefact_id}`: {a.description} (source={a.source}, type={a.artefact_type.value})")

    lines.append("\n## Timeline")
    for t in case.timeline:
        lines.append(f"- {t.timestamp.isoformat()}: {t.description}")

    lines.append("\n## Unlock Attempts")
    for u in case.unlock_attempts:
        lines.append(f"- Container `{u.container_id}` via {u.method} ({u.secret_id}): {u.result.value} – {u.message}")

    lines.append("\n## Chain of Custody")
    for event in case.custody_log:
        lines.append(f"- {event.timestamp.isoformat()} — {event.actor}: {event.action}")

    lines.append("\n## Limitations")
    lines.append("- This report is generated from a prototype tool. Cryptographic validation is simplified.")

    return "\n".join(lines)


def save_report(case: Case, output_path: Path, fmt: str = "json") -> None:
    """Save a report in the desired format to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        output_path.write_text(json.dumps(build_json_report(case), indent=2), encoding="utf-8")
    elif fmt in {"md", "markdown"}:
        output_path.write_text(build_markdown_report(case), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported report format: {fmt}")
