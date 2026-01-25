"""Qt application bootstrap."""
from __future__ import annotations

import sys

from PyQt6 import QtWidgets

from .main_window import MainWindow


def run() -> None:
    """Launch the Qt GUI application."""
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run()
