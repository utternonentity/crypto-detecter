"""Convenience helpers for the Cryptocontainer Lab CLI package."""
from __future__ import annotations

from importlib import metadata
from typing import Optional

import typer

from . import main

__all__ = ["get_version", "build_cli", "run"]


def get_version(distribution_name: str = "cryptocontainer-lab") -> str:
    """Return the installed package version string.

    Parameters
    ----------
    distribution_name:
        The distribution name to look up. Defaults to ``cryptocontainer-lab``
        so that development builds behave the same as installed wheels.
    """

    try:
        return metadata.version(distribution_name)
    except metadata.PackageNotFoundError:
        # When running from a source checkout the metadata may not exist yet.
        return "0.1.0"


def build_cli(help_text: Optional[str] = None) -> typer.Typer:
    """Construct a Typer application embedding the default commands."""

    app = typer.Typer(help=help_text or "Cryptocontainer Lab CLI")
    app.add_typer(main.app)
    return app


def run() -> None:
    """Entry point for invoking the CLI from Python code."""

    main.app()
