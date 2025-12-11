"""Command line interface for Cryptocontainer Lab."""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from ..core.models import EvidenceType
from ..core.pipeline import add_evidence, create_case, load_case
from ..detector.scanner import scan_image_for_containers
from ..memory.scanner import scan_memory_dump
from ..report.builder import save_report

app = typer.Typer(help="Cryptocontainer Lab CLI")
console = Console()


@app.command()
def version() -> None:
    """Display version information."""
    console.print("Cryptocontainer Lab prototype v0.1.0")


@app.command()
def case_new(path: Path, examiner: str = typer.Option(None, help="Examiner name")) -> None:
    """Create a new case at PATH."""
    case = create_case(path, examiner=examiner)
    console.print(f"Created case {case.metadata.case_id} at {path}")


@app.command()
def case_info(path: Path) -> None:
    """Show summary information for a case."""
    case = load_case(path)
    console.print(f"Case: {case.metadata.case_id}\nExaminer: {case.metadata.examiner}\nEvidence items: {len(case.evidence)}")


@app.command()
def scan_disk(case_path: Path, image: Path, description: str = "Disk image") -> None:
    """Scan a disk image for containers and store findings."""
    case = load_case(case_path)
    ev = add_evidence(case, image, description, EvidenceType.DISK_IMAGE)
    scan_image_for_containers(image, case, ev.evidence_id)
    console.print("Scan complete")


@app.command()
def scan_memory(case_path: Path, dump: Path, description: str = "Memory dump") -> None:
    """Scan a memory dump for signatures."""
    case = load_case(case_path)
    ev = add_evidence(case, dump, description, EvidenceType.MEMORY_DUMP)
    scan_memory_dump(dump, case, ev.evidence_id)
    console.print("Memory scan complete")


@app.command()
def report(case_path: Path, out: Path, fmt: str = typer.Option("json", help="json or md")) -> None:
    """Generate a report for a case."""
    case = load_case(case_path)
    save_report(case, out, fmt=fmt)
    console.print(f"Report written to {out}")


if __name__ == "__main__":
    app()
