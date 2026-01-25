"""Main window definition for the PyQt GUI."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from PyQt6 import QtCore, QtGui, QtWidgets

from ..core.models import (
    Artefact,
    ArtefactType,
    Case,
    CaseMetadata,
    ContainerCandidate,
    ContainerType,
    CustodyEvent,
    Evidence,
    EvidenceType,
    TimelineEvent,
    UnlockAttempt,
    UnlockResult,
)
from ..report.builder import save_report
from .case_view import CaseOverview
from .log_view import LogView


@dataclass
class TableSpec:
    headers: list[str]
    rows: list[list[str]]


class MainWindow(QtWidgets.QMainWindow):
    """Top-level PyQt GUI window for Cryptocontainer Lab."""

    def __init__(self) -> None:
        super().__init__()
        self._case: Optional[Case] = None
        self._tables: dict[str, QtWidgets.QTableWidget] = {}

        self.setWindowTitle("Cryptocontainer Lab")
        self.resize(1200, 800)

        self._log_view = LogView()
        self._case_overview = CaseOverview()

        self._tab_widget = QtWidgets.QTabWidget()
        self._setup_tabs()
        self._setup_toolbar()

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)
        layout.addWidget(self._case_overview)
        layout.addWidget(self._tab_widget, stretch=1)
        layout.addWidget(self._log_view, stretch=1)
        self.setCentralWidget(central)

        self._log_view.append_message("GUI ready. Load a case to begin.")

    def _setup_toolbar(self) -> None:
        toolbar = self.addToolBar("Main")
        toolbar.setMovable(False)

        open_action = QtGui.QAction("Open Case", self)
        open_action.triggered.connect(self._open_case)
        toolbar.addAction(open_action)

        sample_action = QtGui.QAction("Load Sample", self)
        sample_action.triggered.connect(self._load_sample_case)
        toolbar.addAction(sample_action)

        report_action = QtGui.QAction("Generate Report", self)
        report_action.triggered.connect(self._generate_report)
        toolbar.addAction(report_action)

    def _setup_tabs(self) -> None:
        self._tab_widget.addTab(self._create_table_tab("Evidence"), "Evidence")
        self._tab_widget.addTab(self._create_table_tab("Containers"), "Containers")
        self._tab_widget.addTab(self._create_table_tab("Artefacts"), "Artefacts")
        self._tab_widget.addTab(self._create_table_tab("Timeline"), "Timeline")
        self._tab_widget.addTab(self._create_table_tab("Unlock Attempts"), "Unlock Attempts")
        self._tab_widget.addTab(self._create_table_tab("Chain of Custody"), "Chain of Custody")

    def _create_table_tab(self, key: str) -> QtWidgets.QWidget:
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)
        table = QtWidgets.QTableWidget()
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(table)
        self._tables[key] = table
        return widget

    def _open_case(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Open Case",
            "",
            "Case JSON (*.json);;All Files (*)",
        )
        if not path:
            return

        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            case = Case.from_dict(payload)
        except Exception as exc:  # noqa: BLE001 - show full error to user
            QtWidgets.QMessageBox.critical(self, "Failed to load", str(exc))
            self._log_view.append_message(f"Failed to load case: {exc}", level="ERROR")
            return

        self._set_case(case)
        self._log_view.append_message(f"Loaded case from {path}.")

    def _load_sample_case(self) -> None:
        case = Case(
            root_path=Path.cwd(),
            metadata=CaseMetadata(
                case_id="DEMO-001",
                examiner="Analyst 7",
                created_at=datetime.now(),
            ),
            evidence=[
                Evidence(
                    evidence_id="EV-100",
                    path=Path("/evidence/disk01.dd"),
                    description="Laptop disk image",
                    evidence_type=EvidenceType.DISK_IMAGE,
                    sha256="a3f4d2c9...demo",
                    size=128_000_000,
                ),
                Evidence(
                    evidence_id="EV-200",
                    path=Path("/evidence/mem01.raw"),
                    description="Memory snapshot",
                    evidence_type=EvidenceType.MEMORY_DUMP,
                    sha256="b9c10f0a...demo",
                    size=8_000_000,
                ),
            ],
            containers=[
                ContainerCandidate(
                    candidate_id="CC-1",
                    evidence_id="EV-100",
                    offset=1048576,
                    container_type=ContainerType.VERACRYPT,
                    confidence=0.92,
                    notes="Header signature matched.",
                ),
            ],
            artefacts=[
                self._demo_artefact(
                    artefact_id="AR-1",
                    description="Recovered keychain snippet",
                    source="memory",
                    artefact_type=ArtefactType.MEMORY,
                )
            ],
            timeline=[
                TimelineEvent(
                    description="Disk image ingested",
                    timestamp=datetime.now(),
                )
            ],
            unlock_attempts=[
                UnlockAttempt(
                    container_id="CC-1",
                    method="dictionary",
                    secret_id="dict-01",
                    result=UnlockResult.FAILURE,
                    message="No match after 200 attempts.",
                )
            ],
            custody_log=[
                CustodyEvent(
                    timestamp=datetime.now(),
                    actor="Analyst 7",
                    action="Case opened in GUI",
                )
            ],
        )
        self._set_case(case)
        self._log_view.append_message("Loaded sample case.")

    def _generate_report(self) -> None:
        if not self._case:
            QtWidgets.QMessageBox.information(self, "No case", "Load a case before generating a report.")
            return

        path, selected = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save Report",
            "",
            "JSON (*.json);;Markdown (*.md)",
        )
        if not path:
            return

        fmt = "json" if selected.startswith("JSON") else "md"
        try:
            save_report(self._case, Path(path), fmt=fmt)
        except Exception as exc:  # noqa: BLE001 - show full error to user
            QtWidgets.QMessageBox.critical(self, "Failed to save", str(exc))
            self._log_view.append_message(f"Failed to save report: {exc}", level="ERROR")
            return

        self._log_view.append_message(f"Report saved to {path}.")

    def _set_case(self, case: Case) -> None:
        self._case = case
        self._case_overview.set_case(case)
        specs = self._build_table_specs(case)
        for key, spec in specs.items():
            self._populate_table(self._tables[key], spec)

    def _build_table_specs(self, case: Case) -> dict[str, TableSpec]:
        return {
            "Evidence": TableSpec(
                headers=["ID", "Type", "Path", "Size (bytes)", "SHA-256", "Description"],
                rows=[
                    [
                        item.evidence_id,
                        item.evidence_type.value,
                        str(item.path),
                        str(item.size),
                        item.sha256,
                        item.description,
                    ]
                    for item in case.evidence
                ],
            ),
            "Containers": TableSpec(
                headers=["ID", "Evidence", "Type", "Offset", "Confidence", "Notes"],
                rows=[
                    [
                        item.candidate_id,
                        item.evidence_id,
                        item.container_type.value,
                        str(item.offset),
                        f"{item.confidence:.2f}",
                        item.notes,
                    ]
                    for item in case.containers
                ],
            ),
            "Artefacts": TableSpec(
                headers=["ID", "Type", "Source", "Description", "Path", "Timestamp"],
                rows=[
                    [
                        item.artefact_id,
                        item.artefact_type.value,
                        item.source,
                        item.description,
                        str(item.path) if item.path else "—",
                        item.timestamp.isoformat() if item.timestamp else "—",
                    ]
                    for item in case.artefacts
                ],
            ),
            "Timeline": TableSpec(
                headers=["Timestamp", "Description", "Artefact ID"],
                rows=[
                    [
                        item.timestamp.isoformat(),
                        item.description,
                        item.artefact_id or "—",
                    ]
                    for item in case.timeline
                ],
            ),
            "Unlock Attempts": TableSpec(
                headers=["Container", "Method", "Secret", "Result", "Message"],
                rows=[
                    [
                        item.container_id,
                        item.method,
                        item.secret_id,
                        item.result.value,
                        item.message,
                    ]
                    for item in case.unlock_attempts
                ],
            ),
            "Chain of Custody": TableSpec(
                headers=["Timestamp", "Actor", "Action"],
                rows=[
                    [
                        item.timestamp.isoformat(),
                        item.actor,
                        item.action,
                    ]
                    for item in case.custody_log
                ],
            ),
        }

    def _populate_table(self, table: QtWidgets.QTableWidget, spec: TableSpec) -> None:
        table.clear()
        table.setRowCount(len(spec.rows))
        table.setColumnCount(len(spec.headers))
        table.setHorizontalHeaderLabels(spec.headers)

        for row_idx, row in enumerate(spec.rows):
            for col_idx, value in enumerate(row):
                item = QtWidgets.QTableWidgetItem(value)
                item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
                table.setItem(row_idx, col_idx, item)

        header = table.horizontalHeader()
        header.setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Stretch)

    @staticmethod
    def _demo_artefact(
        artefact_id: str,
        description: str,
        source: str,
        artefact_type: ArtefactType,
    ) -> "Artefact":
        return Artefact(
            artefact_id=artefact_id,
            description=description,
            source=source,
            artefact_type=artefact_type,
            path=None,
            timestamp=datetime.now(),
        )
