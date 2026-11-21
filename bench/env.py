"""Backwards-compatible re-export shim for bench scripts."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from agy_guardian.config import (  # noqa: E402
    env_bool,
    env_float,
    env_int,
    env_str,
    expand_path,
    load_dotenv,
)

__all__ = [
    "env_bool",
    "env_float",
    "env_int",
    "env_str",
    "expand_path",
    "load_dotenv",
]
