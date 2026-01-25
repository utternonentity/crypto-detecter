"""Main window definition for the PyQt GUI."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt6 import QtCore, QtWidgets

from ..core.models import ContainerCandidate, ContainerType
from ..detector.scanner import scan_path_for_containers
from .log_view import LogView


class ScanWorker(QtCore.QObject):
    """Background worker for disk scanning."""

    progress = QtCore.pyqtSignal(str)
    found = QtCore.pyqtSignal(object)
    error = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal(int)

    def __init__(self, target: Path) -> None:
        super().__init__()
        self._target = target

    @QtCore.pyqtSlot()
    def run(self) -> None:
        """Execute scan in a background thread."""
        try:
            count = 0

            def handle_progress(path: Path) -> None:
                self.progress.emit(f"Сканирование: {path}")

            def handle_result(candidate: ContainerCandidate) -> None:
                nonlocal count
                count += 1
                self.found.emit(candidate)

            def handle_error(path: Path, exc: Exception) -> None:
                self.error.emit(f"Не удалось прочитать {path}: {exc}")

            scan_path_for_containers(
                self._target,
                on_progress=handle_progress,
                on_result=handle_result,
                on_error=handle_error,
            )
            self.finished.emit(count)
        except Exception as exc:  # noqa: BLE001 - surface to user
            self.error.emit(str(exc))
            self.finished.emit(0)


class MainWindow(QtWidgets.QMainWindow):
    """Main GUI window for scanning disks."""

    def __init__(self) -> None:
        super().__init__()
        self._scan_thread: Optional[QtCore.QThread] = None
        self._scan_worker: Optional[ScanWorker] = None

        self.setWindowTitle("Сканер криптоконтейнеров")
        self.resize(1200, 800)

        self._log_view = LogView()

        self._path_edit = QtWidgets.QLineEdit()
        self._path_edit.setPlaceholderText("Например: C:\\ или /mnt/data")

        browse_dir_button = QtWidgets.QPushButton("Выбрать диск/папку")
        browse_dir_button.clicked.connect(self._select_directory)

        browse_file_button = QtWidgets.QPushButton("Выбрать файл")
        browse_file_button.clicked.connect(self._select_file)

        self._scan_button = QtWidgets.QPushButton("Начать сканирование")
        self._scan_button.clicked.connect(self._start_scan)
        self._scan_button.setDefault(True)

        self._status_label = QtWidgets.QLabel("Готово к сканированию.")

        self._results_table = QtWidgets.QTableWidget()
        self._results_table.setAlternatingRowColors(True)
        self._results_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self._results_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self._results_table.horizontalHeader().setStretchLastSection(True)
        self._apply_table_headers()

        top_form = QtWidgets.QFormLayout()
        path_row = QtWidgets.QHBoxLayout()
        path_row.addWidget(self._path_edit, stretch=1)
        path_row.addWidget(browse_dir_button)
        path_row.addWidget(browse_file_button)
        top_form.addRow("Диск или путь для сканирования:", path_row)
        top_form.addRow("Статус:", self._status_label)

        control_row = QtWidgets.QHBoxLayout()
        control_row.addWidget(self._scan_button)
        control_row.addStretch(1)

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)
        layout.addLayout(top_form)
        layout.addLayout(control_row)
        layout.addWidget(QtWidgets.QLabel("Найденные контейнеры:"))
        layout.addWidget(self._results_table, stretch=1)
        layout.addWidget(QtWidgets.QLabel("Журнал:"))
        layout.addWidget(self._log_view, stretch=1)
        self.setCentralWidget(central)

        self._log_view.append_message("Готово. Выберите диск или файл для сканирования.")

    def _apply_table_headers(self) -> None:
        headers = ["Тип", "Путь", "Смещение (байт)", "Уверенность", "Примечание"]
        self._results_table.setColumnCount(len(headers))
        self._results_table.setHorizontalHeaderLabels(headers)

    def _select_directory(self) -> None:
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Выбор диска или папки")
        if path:
            self._path_edit.setText(path)

    def _select_file(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Выбор файла для сканирования")
        if path:
            self._path_edit.setText(path)

    def _start_scan(self) -> None:
        raw_path = self._path_edit.text().strip()
        if not raw_path:
            QtWidgets.QMessageBox.warning(self, "Нет пути", "Укажите путь к диску, каталогу или файлу.")
            return

        target = Path(raw_path)
        self._results_table.setRowCount(0)
        self._status_label.setText("Сканирование запущено…")
        self._log_view.append_message(f"Запуск сканирования: {target}")
        self._scan_button.setEnabled(False)

        self._scan_thread = QtCore.QThread()
        self._scan_worker = ScanWorker(target)
        self._scan_worker.moveToThread(self._scan_thread)

        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_worker.progress.connect(self._log_view.append_message)
        self._scan_worker.found.connect(self._append_result)
        self._scan_worker.error.connect(lambda msg: self._log_view.append_message(msg, level="WARNING"))
        self._scan_worker.finished.connect(self._scan_finished)
        self._scan_worker.finished.connect(self._scan_thread.quit)
        self._scan_worker.finished.connect(self._scan_worker.deleteLater)
        self._scan_thread.finished.connect(self._scan_thread.deleteLater)

        self._scan_thread.start()

    def _append_result(self, candidate: ContainerCandidate) -> None:
        type_labels = {
            ContainerType.BITLOCKER: "BitLocker",
            ContainerType.LUKS: "LUKS",
            ContainerType.VERACRYPT: "VeraCrypt/TrueCrypt",
            ContainerType.TRUECRYPT: "TrueCrypt",
            ContainerType.UNKNOWN: "Неизвестно",
        }
        row = self._results_table.rowCount()
        self._results_table.insertRow(row)
        values = [
            type_labels.get(candidate.container_type, candidate.container_type.value),
            str(candidate.source_path),
            str(candidate.offset),
            f"{candidate.confidence:.2f}",
            candidate.notes,
        ]
        for col, value in enumerate(values):
            item = QtWidgets.QTableWidgetItem(value)
            item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
            self._results_table.setItem(row, col, item)

    def _scan_finished(self, count: int) -> None:
        self._status_label.setText(f"Сканирование завершено. Найдено: {count}.")
        self._log_view.append_message(f"Сканирование завершено. Найдено контейнеров: {count}.")
        self._scan_button.setEnabled(True)
