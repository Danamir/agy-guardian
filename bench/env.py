"""Pure-stdlib .env loader and path variable expander (zero third-party dependencies)."""

from __future__ import annotations

import os
from pathlib import Path
from string import Template


def load_dotenv(env_path: Path | str | None = None) -> dict[str, str]:
    """Load KEY=VALUE pairs from a .env file into os.environ without overwriting existing vars."""
    path = Path(env_path) if env_path is not None else Path(__file__).resolve().parent.parent / ".env"
    loaded: dict[str, str] = {}
    if not path.is_file():
        return loaded

    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key not in os.environ:
            os.environ[key] = value
            loaded[key] = value
    return loaded


def env_str(key: str, default: str = "") -> str:
    val = os.environ.get(key)
    return val if val is not None and val != "" else default


def env_int(key: str, default: int) -> int:
    val = os.environ.get(key)
    if val is None or val == "":
        return default
    return int(val)


def env_float(key: str, default: float) -> float:
    val = os.environ.get(key)
    if val is None or val == "":
        return default
    return float(val)


def expand_path(raw: str) -> Path:
    """Expand ${VAR} placeholders from os.environ and ~ user home."""
    substituted = Template(raw).safe_substitute(os.environ)
    return Path(os.path.expandvars(substituted)).expanduser()
