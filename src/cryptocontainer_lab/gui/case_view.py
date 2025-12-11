"""Widgets for presenting case metadata in the GUI."""
from __future__ import annotations

from typing import Optional

from PySide6 import QtWidgets

from ..core.models import Case


class CaseOverview(QtWidgets.QGroupBox):
    """Display top-level case metadata and counts."""

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__("Case Overview", parent)
        self._case: Optional[Case] = None

        self._case_id_label = QtWidgets.QLabel("")
        self._examiner_label = QtWidgets.QLabel("")
        self._created_label = QtWidgets.QLabel("")
        self._evidence_label = QtWidgets.QLabel("0")
        self._containers_label = QtWidgets.QLabel("0")
        self._artefacts_label = QtWidgets.QLabel("0")

        form = QtWidgets.QFormLayout()
        form.addRow("Case ID", self._case_id_label)
        form.addRow("Examiner", self._examiner_label)
        form.addRow("Created", self._created_label)
        form.addRow("Evidence", self._evidence_label)
        form.addRow("Detected Containers", self._containers_label)
        form.addRow("Artefacts", self._artefacts_label)
        self.setLayout(form)
        self._update_labels()

    def set_case(self, case: Case) -> None:
        """Assign the case and refresh displayed values."""

        self._case = case
        self._update_labels()

    def _update_labels(self) -> None:
        if not self._case:
            self._case_id_label.setText("—")
            self._examiner_label.setText("—")
            self._created_label.setText("—")
            self._evidence_label.setText("0")
            self._containers_label.setText("0")
            self._artefacts_label.setText("0")
            return

        metadata = self._case.metadata
        self._case_id_label.setText(metadata.case_id)
        self._examiner_label.setText(metadata.examiner or "Unknown")
        self._created_label.setText(metadata.created_at.isoformat())
        self._evidence_label.setNum(len(self._case.evidence))
        self._containers_label.setNum(len(self._case.containers))
        self._artefacts_label.setNum(len(self._case.artefacts))
