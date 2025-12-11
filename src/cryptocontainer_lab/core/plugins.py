"""Simple plugin registry placeholders."""
from __future__ import annotations

from typing import Callable, Dict

Detector = Callable[..., object]


class PluginRegistry:
    """Minimal registry for detector plugins."""

    def __init__(self) -> None:
        self._registry: Dict[str, Detector] = {}

    def register(self, name: str, detector: Detector) -> None:
        self._registry[name] = detector

    def get(self, name: str) -> Detector:
        return self._registry[name]

    def available(self) -> list[str]:
        return sorted(self._registry.keys())


REGISTRY = PluginRegistry()
