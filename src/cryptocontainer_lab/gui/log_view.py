"""Lightweight Qt widget for streaming log output."""
from __future__ import annotations

import html
from typing import Iterable, Optional

from PyQt6 import QtCore, QtGui, QtWidgets


class LogView(QtWidgets.QTextEdit):
    """Read-only text area that accepts log messages.

    The widget keeps a rolling buffer of log lines to avoid unbounded
    memory growth. Messages can be appended individually or in bulk.
    """

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None, max_lines: int = 500) -> None:
        super().__init__(parent)
        self._max_lines = max_lines
        self.setReadOnly(True)
        self.setLineWrapMode(QtWidgets.QTextEdit.LineWrapMode.NoWrap)
        self.setFont(QtGui.QFont("Monospace"))
        self.document().setDefaultStyleSheet("pre { margin: 0; }")
        self.setPlaceholderText("Log messages will appear here…")

    @property
    def max_lines(self) -> int:
        """Return the maximum number of lines retained in the buffer."""

        return self._max_lines

    @max_lines.setter
    def max_lines(self, value: int) -> None:
        self._max_lines = max(1, value)
        self._trim()

    def append_message(self, message: str, level: str = "INFO") -> None:
        """Append a message with a simple level prefix."""

        timestamp = QtCore.QDateTime.currentDateTime().toString(QtCore.Qt.DateFormat.ISODate)
        colored = self._format_line(timestamp, level.upper(), message)
        self.append(colored)
        self._trim()

    def extend(self, messages: Iterable[str], level: str = "INFO") -> None:
        """Append multiple messages in a single update."""

        for msg in messages:
            self.append_message(msg, level=level)

    def _trim(self) -> None:
        """Ensure the buffer does not exceed ``max_lines``."""

        doc = self.document()
        while doc.blockCount() > self._max_lines:
            cursor = QtGui.QTextCursor(doc.begin())
            cursor.select(QtGui.QTextCursor.SelectionType.BlockUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar()

    @staticmethod
    def _format_line(timestamp: str, level: str, message: str) -> str:
        palette = {
            "DEBUG": "#6c757d",
            "INFO": "#0d6efd",
            "WARNING": "#fd7e14",
            "ERROR": "#dc3545",
            "CRITICAL": "#842029",
        }
        color = palette.get(level, "#0d6efd")
        escaped = html.escape(message)
        safe = QtGui.QColor(color).name()
        return f"<pre>[{timestamp}] <b style='color:{safe}'>{level}</b> {escaped}</pre>"
