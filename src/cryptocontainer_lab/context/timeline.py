"""Timeline helpers."""
from __future__ import annotations

from ..core.models import Case


def get_sorted_timeline(case: Case):
    """Return timeline events sorted by timestamp."""
    return sorted(case.timeline, key=lambda e: e.timestamp)
