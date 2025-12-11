"""Entropy-based heuristics placeholder."""
from __future__ import annotations

import math


def estimate_entropy(data: bytes) -> float:
    """Rudimentary entropy estimate using Shannon formula."""
    if not data:
        return 0.0
    histogram = {byte: data.count(byte) for byte in set(data)}
    total = len(data)
    entropy = 0.0
    for count in histogram.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy
