"""AGY Guardian — 3-layer fail-closed PreToolUse command approval hook."""

from __future__ import annotations

from .config import GuardianConfig, load_config
from .pipeline import DecisionReport, evaluate_command

__all__ = [
    "DecisionReport",
    "GuardianConfig",
    "evaluate_command",
    "load_config",
]
__version__ = "0.1.0"
