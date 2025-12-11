"""Logging helpers for the Cryptocontainer Lab."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional


DEFAULT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def setup_case_logger(log_dir: Path, level: int = logging.INFO) -> logging.Logger:
    """Configure logging for a case-specific session."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "case.log"
    logger = logging.getLogger("cryptocontainer_lab")
    logger.setLevel(level)

    # Avoid duplicate handlers if called multiple times.
    if not any(isinstance(h, logging.FileHandler) and h.baseFilename == str(log_path) for h in logger.handlers):
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(DEFAULT_FORMAT))
        logger.addHandler(file_handler)

    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(level)
        stream_handler.setFormatter(logging.Formatter(DEFAULT_FORMAT))
        logger.addHandler(stream_handler)

    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a module-level logger."""
    return logging.getLogger(name or "cryptocontainer_lab")
