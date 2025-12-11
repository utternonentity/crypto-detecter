"""Configuration interface for password/key search (stub)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..core.models import ContainerCandidate
from ..core.logging_utils import get_logger

LOGGER = get_logger(__name__)


@dataclass
class CrackConfig:
    """Configuration for a cracking attempt (not implemented)."""

    container: ContainerCandidate
    wordlist_path: Path | None = None
    max_runtime_seconds: int = 0


class CrackEngine:
    """Stub engine for compliant password search."""

    def __init__(self, config: CrackConfig) -> None:
        self.config = config

    def run(self) -> None:
        """Log that cracking is intentionally not implemented."""
        LOGGER.warning("CrackEngine invoked for %s; not implemented", self.config.container.candidate_id)
        raise NotImplementedError("Password cracking is not implemented in this prototype.")
