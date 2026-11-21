"""Pure-stdlib configuration and .env loader (zero third-party dependencies).

Precedence: explicit overrides / CLI flags > OS environment variables > .env > code defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from string import Template

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUDIT_LOG = "~/.gemini/config/agy_guardian.log.jsonl"
DEFAULT_POLICY_FILE = "~/.gemini/config/agy_guardian_policies.json"


def load_dotenv(env_path: Path | str | None = None) -> dict[str, str]:
    """Load KEY=VALUE pairs from a .env file into os.environ without overwriting existing vars."""
    path = Path(env_path) if env_path is not None else REPO_ROOT / ".env"
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


def env_bool(key: str, default: bool) -> bool:
    val = os.environ.get(key)
    if val is None or val == "":
        return default
    low = val.strip().lower()
    if low in ("1", "true", "yes", "on"):
        return True
    if low in ("0", "false", "no", "off"):
        return False
    return default


def expand_path(raw: str) -> Path:
    """Expand ${VAR} placeholders from os.environ and ~ user home."""
    substituted = Template(raw).safe_substitute(os.environ)
    return Path(os.path.expandvars(substituted)).expanduser()


@dataclass
class GuardianConfig:
    """Runtime settings for the 3-layer AGY Guardian pipeline."""

    host: str = "127.0.0.1"
    port: int = 8099
    endpoint: str = ""
    backend: str = "systemone"  # "systemone" | "completion" | "auto"
    schema_mode: str = "multi"  # "multi" | "single"
    timeout_sec: float = 4.0
    fallback_endpoint: str = ""
    allow_min_prob: float = 0.90
    deny_min_prob: float = 0.85
    risk_max_prob: float = 0.25
    audit_log_path: str = DEFAULT_AUDIT_LOG
    audit_fail_closed: bool = True
    policy_file: str = DEFAULT_POLICY_FILE
    extra_workspaces: list[str] = field(default_factory=list)
    enable_layer1: bool = True
    enable_layer2: bool = True
    enable_layer3: bool = True

    @property
    def effective_endpoint(self) -> str:
        if self.endpoint:
            return self.endpoint.rstrip("/")
        return f"http://{self.host}:{self.port}"

    @property
    def audit_enabled(self) -> bool:
        val = (self.audit_log_path or "").strip().lower()
        return val not in ("", "off", "none", "false", "0")

    @property
    def resolved_audit_path(self) -> Path | None:
        if not self.audit_enabled:
            return None
        return expand_path(self.audit_log_path)

    @property
    def policy_enabled(self) -> bool:
        val = (self.policy_file or "").strip().lower()
        return val not in ("", "off", "none", "false", "0")

    @property
    def resolved_policy_path(self) -> Path | None:
        if not self.policy_enabled:
            return None
        return expand_path(self.policy_file)


def load_config(env_path: Path | str | None = None) -> GuardianConfig:
    """Load GuardianConfig from OS environment and optional .env file."""
    load_dotenv(env_path)

    host = env_str("AGY_GUARDIAN_HOST", "127.0.0.1")
    port = env_int("AGY_GUARDIAN_PORT", 8099)
    endpoint = env_str("AGY_GUARDIAN_ENDPOINT", "")
    backend = env_str("AGY_GUARDIAN_BACKEND", "systemone").strip().lower()
    if backend not in ("systemone", "completion", "auto"):
        backend = "systemone"
    schema_mode = env_str("AGY_GUARDIAN_SCHEMA_MODE", "multi").strip().lower()
    if schema_mode not in ("multi", "single"):
        schema_mode = "multi"

    raw_audit = os.environ.get("AGY_GUARDIAN_AUDIT_LOG")
    audit_log_path = DEFAULT_AUDIT_LOG if (raw_audit is None or raw_audit.strip() == "") else raw_audit.strip()

    raw_policy = os.environ.get("AGY_GUARDIAN_POLICY_FILE")
    policy_file = DEFAULT_POLICY_FILE if (raw_policy is None or raw_policy.strip() == "") else raw_policy.strip()

    raw_extra_ws = env_str("AGY_GUARDIAN_EXTRA_WORKSPACES", "")
    extra_workspaces = [p.strip() for p in raw_extra_ws.split(";") if p.strip()]

    return GuardianConfig(
        host=host,
        port=port,
        endpoint=endpoint,
        backend=backend,
        schema_mode=schema_mode,
        timeout_sec=env_float("AGY_GUARDIAN_TIMEOUT_SEC", 4.0),
        fallback_endpoint=env_str("AGY_GUARDIAN_FALLBACK_ENDPOINT", "").rstrip("/"),
        allow_min_prob=env_float("AGY_GUARDIAN_ALLOW_THRESHOLD", 0.90),
        deny_min_prob=env_float("AGY_GUARDIAN_DENY_THRESHOLD", 0.85),
        risk_max_prob=env_float("AGY_GUARDIAN_RISK_MAX_PROB", 0.25),
        audit_log_path=audit_log_path,
        audit_fail_closed=env_bool("AGY_GUARDIAN_AUDIT_FAIL_CLOSED", True),
        policy_file=policy_file,
        extra_workspaces=extra_workspaces,
        enable_layer1=env_bool("AGY_GUARDIAN_ENABLE_LAYER1", True),
        enable_layer2=env_bool("AGY_GUARDIAN_ENABLE_LAYER2", True),
        enable_layer3=env_bool("AGY_GUARDIAN_ENABLE_LAYER3", True),
    )
