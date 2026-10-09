"""Fixed build-24919 settings; each connection receives independent menu state."""
from __future__ import annotations

from dataclasses import dataclass, field

from .menu import validate_menu


@dataclass
class BetaRuntime:
    name: str = "beta-menu"
    settings: dict = field(default_factory=dict)
    extended: bool = False

    def __post_init__(self):
        if not isinstance(self.extended, bool):
            raise ValueError("extended mode must be true or false")
        self.settings = {
            "name": self.name,
            "extended": self.extended,
            "timeout_seconds": 45.0, "session_seconds": None,
            "max_frame_size": 1048576,
            "menu": validate_menu(self.settings.get("menu", {})),
        }


def load_config(preset="beta-menu", path=None):
    # Keep the listener call compatible while rejecting discarded lab presets.
    if preset != "beta-menu" or path is not None:
        raise ValueError("The showcase uses the fixed beta-menu runtime")
    return BetaRuntime()
