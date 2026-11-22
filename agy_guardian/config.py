"""Pure-stdlib configuration and .env loader (zero third-party dependencies).

Precedence: explicit overrides / CLI flags > OS environment variables > .env > code defaults.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from string import Template

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUDIT_LOG = "~/.gemini/config/agy_guardian.log.jsonl"
DEFAULT_AUDIT_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB
DEFAULT_AUDIT_BACKUPS = 3
DEFAULT_POLICY_FILE = "~/.gemini/config/agy_guardian_policies.json"
DEFAULT_SESSION_BRAIN_ROOT = "~/.gemini/antigravity-cli/brain"
DEFAULT_GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/decisions"
DEFAULT_GEMINI_MODEL = "gemini-decision-1"
DEFAULT_GEMINI_MAX_USER_INPUT_CHARS = 2000
GEMINI_PAID_USD_PER_MILLION_INPUT_TOKENS = 0.10
VALID_BACKENDS = (
    "systemone",
    "completion",
    "auto",
    "gemini_decision_paid",
    "gemini_decision_free",
    "gemini_decision",
)
VALID_FALLBACK_BACKENDS = (
    "none",
    "gemini_decision_paid",
    "gemini_decision_free",
    "completion",
    "systemone",
)
_SAFE_CONVERSATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$")


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
    backend: str = "systemone"  # "systemone" | "completion" | "auto" | "gemini_decision_paid" | "gemini_decision_free" | "gemini_decision"
    fallback_backend: str = "none"  # "none" | "gemini_decision_paid" | "gemini_decision_free" | "completion" | "systemone"
    schema_mode: str = "multi"  # "multi" | "single"
    timeout_sec: float = 4.0
    fallback_endpoint: str = ""
    gemini_paid_api_key: str = field(default="", repr=False)
    gemini_free_api_key: str = field(default="", repr=False)
    gemini_tier: str = ""  # "paid" | "free" | "" (only used if bare backend="gemini_decision")
    gemini_endpoint: str = DEFAULT_GEMINI_ENDPOINT
    gemini_model: str = DEFAULT_GEMINI_MODEL
    gemini_max_user_input_chars: int = DEFAULT_GEMINI_MAX_USER_INPUT_CHARS
    allow_min_prob: float = 0.85
    deny_min_prob: float = 0.85
    risk_max_prob: float = 0.25
    audit_log_path: str = DEFAULT_AUDIT_LOG
    audit_fail_closed: bool = True
    audit_max_bytes: int = DEFAULT_AUDIT_MAX_BYTES
    audit_backups: int = DEFAULT_AUDIT_BACKUPS
    policy_file: str = DEFAULT_POLICY_FILE
    extra_workspaces: list[str] = field(default_factory=list)
    allow_session_brain: bool = True
    session_brain_root: str = DEFAULT_SESSION_BRAIN_ROOT
    include_last_assistant: bool = True
    last_assistant_max_user_chars: int = 80
    last_assistant_max_chars: int = 500
    include_recent_commands: bool = True
    recent_commands_limit: int = 5
    enable_layer1: bool = True
    enable_layer2: bool = True
    enable_layer3: bool = True

    def __post_init__(self) -> None:
        if not math.isfinite(self.allow_min_prob) or not (0.5 <= self.allow_min_prob <= 1.0):
            raise ValueError(
                f"allow_min_prob must be between 0.5 and 1.0, got {self.allow_min_prob!r}"
            )
        if not math.isfinite(self.deny_min_prob) or not (0.5 <= self.deny_min_prob <= 1.0):
            raise ValueError(
                f"deny_min_prob must be between 0.5 and 1.0, got {self.deny_min_prob!r}"
            )
        if not math.isfinite(self.risk_max_prob) or not (0.0 <= self.risk_max_prob <= 0.5):
            raise ValueError(
                f"risk_max_prob must be between 0.0 and 0.5, got {self.risk_max_prob!r}"
            )

    @property
    def effective_endpoint(self) -> str:
        if self.endpoint:
            return self.endpoint.rstrip("/")
        return f"http://{self.host}:{self.port}"

    def resolve_backend_name(self, name: str | None = None) -> tuple[str | None, str | None]:
        """Resolve a backend name, enforcing explicit tier selection for bare 'gemini_decision'."""
        raw = (self.backend if name is None else name).strip().lower()
        if raw == "gemini_decision":
            tier = (self.gemini_tier or "").strip().lower()
            if tier == "paid":
                return "gemini_decision_paid", None
            if tier == "free":
                return "gemini_decision_free", None
            return None, "Bare 'gemini_decision' backend requires explicit AGY_GUARDIAN_GEMINI_TIER=paid|free"
        if raw in ("systemone", "completion", "auto", "gemini_decision_paid", "gemini_decision_free"):
            return raw, None
        return None, f"Unsupported Layer 3 backend '{raw}'"

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

    def resolve_session_brain_dir(self, conversation_id: str) -> str | None:
        """Resolve the current session's brain directory strictly scoped to conversation_id."""
        if not self.allow_session_brain:
            return None
        cid = (conversation_id or "").strip()
        if not cid or not _SAFE_CONVERSATION_ID_RE.fullmatch(cid):
            return None
        raw_root = (self.session_brain_root or "").strip()
        if not raw_root or raw_root.lower() in ("off", "none", "false", "0"):
            return None
        root = expand_path(raw_root)
        candidate = root / cid
        if candidate.parent != root:
            return None
        return str(candidate)


def load_config(env_path: Path | str | None = None) -> GuardianConfig:
    """Load GuardianConfig from OS environment and optional .env file."""
    load_dotenv(env_path)

    host = env_str("AGY_GUARDIAN_HOST", "127.0.0.1")
    port = env_int("AGY_GUARDIAN_PORT", 8099)
    endpoint = env_str("AGY_GUARDIAN_ENDPOINT", "")
    backend = env_str("AGY_GUARDIAN_BACKEND", "systemone").strip().lower()
    if backend not in VALID_BACKENDS:
        backend = "systemone"
    fallback_backend = env_str("AGY_GUARDIAN_FALLBACK_BACKEND", "none").strip().lower()
    if fallback_backend not in VALID_FALLBACK_BACKENDS:
        fallback_backend = "none"
    schema_mode = env_str("AGY_GUARDIAN_SCHEMA_MODE", "multi").strip().lower()
    if schema_mode not in ("multi", "single"):
        schema_mode = "multi"

    # Strict key isolation:
    # - Paid Tier reads ONLY AGY_GUARDIAN_GEMINI_PAID_API_KEY (never Free or generic GEMINI_API_KEY).
    # - Free Tier reads ONLY AGY_GUARDIAN_GEMINI_FREE_API_KEY (never Paid or generic GEMINI_API_KEY).
    gemini_paid_api_key = env_str("AGY_GUARDIAN_GEMINI_PAID_API_KEY", "")
    gemini_free_api_key = env_str("AGY_GUARDIAN_GEMINI_FREE_API_KEY", "")
    gemini_tier = env_str("AGY_GUARDIAN_GEMINI_TIER", "").strip().lower()
    gemini_endpoint = env_str("AGY_GUARDIAN_GEMINI_ENDPOINT", DEFAULT_GEMINI_ENDPOINT)
    gemini_model = env_str("AGY_GUARDIAN_GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    gemini_max_user_input_chars = env_int(
        "AGY_GUARDIAN_GEMINI_MAX_USER_INPUT_CHARS", DEFAULT_GEMINI_MAX_USER_INPUT_CHARS
    )

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
        fallback_backend=fallback_backend,
        schema_mode=schema_mode,
        timeout_sec=env_float("AGY_GUARDIAN_TIMEOUT_SEC", 4.0),
        fallback_endpoint=env_str("AGY_GUARDIAN_FALLBACK_ENDPOINT", "").rstrip("/"),
        gemini_paid_api_key=gemini_paid_api_key,
        gemini_free_api_key=gemini_free_api_key,
        gemini_tier=gemini_tier,
        gemini_endpoint=gemini_endpoint,
        gemini_model=gemini_model,
        gemini_max_user_input_chars=gemini_max_user_input_chars,
        allow_min_prob=env_float("AGY_GUARDIAN_ALLOW_THRESHOLD", 0.85),
        deny_min_prob=env_float("AGY_GUARDIAN_DENY_THRESHOLD", 0.85),
        risk_max_prob=env_float("AGY_GUARDIAN_RISK_MAX_PROB", 0.25),
        audit_log_path=audit_log_path,
        audit_fail_closed=env_bool("AGY_GUARDIAN_AUDIT_FAIL_CLOSED", True),
        audit_max_bytes=env_int("AGY_GUARDIAN_AUDIT_MAX_BYTES", DEFAULT_AUDIT_MAX_BYTES),
        audit_backups=env_int("AGY_GUARDIAN_AUDIT_BACKUPS", DEFAULT_AUDIT_BACKUPS),
        policy_file=policy_file,
        extra_workspaces=extra_workspaces,
        allow_session_brain=env_bool("AGY_GUARDIAN_ALLOW_SESSION_BRAIN", True),
        session_brain_root=env_str("AGY_GUARDIAN_SESSION_BRAIN_ROOT", DEFAULT_SESSION_BRAIN_ROOT),
        include_last_assistant=env_bool("AGY_GUARDIAN_INCLUDE_LAST_ASSISTANT", True),
        last_assistant_max_user_chars=env_int("AGY_GUARDIAN_LAST_ASSISTANT_MAX_USER_CHARS", 80),
        last_assistant_max_chars=env_int("AGY_GUARDIAN_LAST_ASSISTANT_MAX_CHARS", 500),
        include_recent_commands=env_bool("AGY_GUARDIAN_INCLUDE_RECENT_COMMANDS", True),
        recent_commands_limit=env_int("AGY_GUARDIAN_RECENT_COMMANDS_LIMIT", 5),
        enable_layer1=env_bool("AGY_GUARDIAN_ENABLE_LAYER1", True),
        enable_layer2=env_bool("AGY_GUARDIAN_ENABLE_LAYER2", True),
        enable_layer3=env_bool("AGY_GUARDIAN_ENABLE_LAYER3", True),
    )
