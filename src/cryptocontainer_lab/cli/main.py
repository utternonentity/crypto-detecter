"""Command line interface for disk scanning."""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ..core.models import ContainerType
from ..detector.scanner import scan_path_for_containers

app = typer.Typer(help="Сканирование дисков на наличие криптоконтейнеров")
console = Console()


@app.command()
def version() -> None:
    """Показать версию приложения."""
    console.print("Сканер криптоконтейнеров v0.1.0")


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Путь к диску, каталогу или файлу"),
) -> None:
    """Сканировать диск, каталог или файл на наличие контейнеров."""
    console.print(f"Сканирование: {path}")
    results = scan_path_for_containers(path)
    if not results:
        console.print("Контейнеры не обнаружены.")
        return

    table = Table(title="Найденные контейнеры")
    table.add_column("Тип")
    table.add_column("Путь")
    table.add_column("Смещение")
    table.add_column("Уверенность")
    table.add_column("Примечание")

    type_labels = {
        ContainerType.BITLOCKER: "BitLocker",
        ContainerType.LUKS: "LUKS",
        ContainerType.VERACRYPT: "VeraCrypt/TrueCrypt",
        ContainerType.TRUECRYPT: "TrueCrypt",
        ContainerType.UNKNOWN: "Неизвестно",
    }
    for item in results:
        table.add_row(
            type_labels.get(item.container_type, item.container_type.value),
            str(item.source_path),
            str(item.offset),
            f"{item.confidence:.2f}",
            item.notes,
        )

    console.print(table)


if __name__ == "__main__":
    app()
