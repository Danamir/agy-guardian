"""Fail-closed JSONL audit logger with secret redaction and locked size-based rotation."""

from __future__ import annotations

import contextlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

if os.name == "nt":
    import msvcrt
else:
    import fcntl

DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB
DEFAULT_BACKUPS = 3
_AUDIT_TAIL_BYTES = 64 * 1024

_REDACT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # HTTP Authorization headers (Bearer / Basic / Token)
    (
        re.compile(r"(Authorization\s*:\s*(?:Bearer|Basic|Token)\s+)[^\s\"']+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # API key / private token HTTP headers
    (
        re.compile(
            r"((?:x-api-key|x-goog-api-key|api-key|private-token)\s*:\s*)[^\s\"']+",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    # URLs with embedded user:password@host credentials
    (
        re.compile(r"(https?://)([^/\s:@]+:[^/\s@]+)(@)", re.IGNORECASE),
        r"\1[REDACTED]\3",
    ),
    # Well-known API key / PAT prefixes
    (
        re.compile(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{16,}\b"
            r"|\bgithub_pat_[A-Za-z0-9_]{20,}\b"
            r"|\bglpat-[A-Za-z0-9_-]{16,}\b"
            r"|\bhf_[A-Za-z0-9]{16,}\b"
            r"|\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b"
            r"|\bAIza[0-9A-Za-z_-]{20,}\b"
            r"|\bAKIA[0-9A-Z]{16}\b"
        ),
        "[REDACTED]",
    ),
    # Explicit secret env/flag assignments (KEY=value)
    (
        re.compile(
            r"(\b(?:[A-Z0-9_]*(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|PASSWORD|PASSWD)"
            r"|HF_TOKEN|GITHUB_TOKEN|GITLAB_TOKEN)\s*=\s*)(?:\"[^\"]*\"|'[^']*'|[^\s;&|]+)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
)


def redact_secrets(text: str) -> str:
    """Mask common bearer tokens, API keys, and credentials before persisting to audit logs."""
    if not text:
        return text
    redacted = text
    for pattern, repl in _REDACT_PATTERNS:
        redacted = pattern.sub(repl, redacted)
    return redacted


@contextlib.contextmanager
def _audit_file_lock(lock_path: Path, timeout_sec: float = 2.0) -> Iterator[None]:
    """Cross-platform exclusive file lock for concurrent audit writes and rotation."""
    fh = lock_path.open("a+b")
    locked = False
    try:
        deadline = time.monotonic() + timeout_sec
        while True:
            try:
                if os.name == "nt":
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Timed out acquiring audit lock: {lock_path}")
                time.sleep(0.005)
        yield
    finally:
        if locked:
            try:
                if os.name == "nt":
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        fh.close()


def build_audit_record(
    *,
    conversation_id: str,
    step_idx: int | None,
    tool_name: str,
    command_line: str,
    cwd: str,
    workspace_paths: list[str],
    layer: str,
    rule_id: str | None,
    decision: str,
    reason: str,
    probs: dict[str, float] | None = None,
    risk_probs: dict[str, float] | None = None,
    latency_ms: float = 0.0,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    estimated_cost_usd: float | None = None,
    error: str | None = None,
    policy_name: str | None = None,
    policy_error: str | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "conversationId": conversation_id,
        "stepIdx": step_idx,
        "toolName": tool_name,
        "commandLine": redact_secrets(command_line),
        "cwd": cwd,
        "workspacePaths": workspace_paths,
        "layer": layer,
        "ruleId": rule_id,
        "decision": decision,
        "reason": reason,
        "probs": probs or {},
        "riskProbs": risk_probs or {},
        "latencyMs": round(latency_ms, 2),
        "error": error,
        "policyName": policy_name,
        "policyError": policy_error,
    }
    if input_tokens is not None:
        record["inputTokens"] = input_tokens
    if output_tokens is not None:
        record["outputTokens"] = output_tokens
    if estimated_cost_usd is not None:
        record["estimatedCostUsd"] = estimated_cost_usd
    return record


def _backup_path(base: Path, index: int) -> Path:
    return base.with_name(f"{base.name}.{index}")


def _rotate_if_needed(path: Path, incoming_bytes: int, max_bytes: int, backups: int) -> None:
    if max_bytes <= 0 or not path.exists():
        return
    if path.is_dir():
        return
    current_size = path.stat().st_size
    if current_size == 0 or current_size + incoming_bytes <= max_bytes:
        return

    if backups <= 0:
        path.unlink(missing_ok=True)
        return

    # Shift .N-1 -> .N, ..., active -> .1
    oldest = _backup_path(path, backups)
    if oldest.exists():
        oldest.unlink()
    for idx in range(backups - 1, 0, -1):
        src = _backup_path(path, idx)
        dst = _backup_path(path, idx + 1)
        if src.exists():
            os.replace(src, dst)
    os.replace(path, _backup_path(path, 1))


def write_audit_entry(
    path: Path,
    record: dict[str, Any],
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backups: int = DEFAULT_BACKUPS,
) -> str | None:
    """Append one JSONL audit record with locked size-based rotation.

    Returns None on success, or an error string on failure (never raises).
    """
    try:
        if path.is_dir():
            raise IsADirectoryError(f"Audit log path is a directory: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        line_bytes = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        lock_path = path.with_name(f"{path.name}.lock")
        with _audit_file_lock(lock_path):
            _rotate_if_needed(path, len(line_bytes), max_bytes=max_bytes, backups=backups)
            with path.open("ab") as fh:
                fh.write(line_bytes)
                fh.flush()
        return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


def extract_recent_commands(
    path: Path | None,
    conversation_id: str,
    *,
    limit: int = 5,
    max_cmd_chars: int = 200,
) -> list[str]:
    """Read up to the last `limit` commandLines for `conversation_id` from the audit log tail.

    Returns an empty list silently if the log is missing, unreadable, or has no matching entries.
    """
    cid = (conversation_id or "").strip()
    if path is None or not cid or limit <= 0:
        return []
    try:
        if not path.is_file():
            return []
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > _AUDIT_TAIL_BYTES:
                fh.seek(size - _AUDIT_TAIL_BYTES)
                fh.readline()
            raw_lines = fh.read().decode("utf-8", errors="replace").splitlines()
    except Exception:
        return []

    recent: list[str] = []
    for line in reversed(raw_lines):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if not isinstance(rec, dict):
            continue
        if rec.get("conversationId") != cid:
            continue
        cmd = rec.get("commandLine")
        if isinstance(cmd, str) and cmd.strip():
            text = cmd.strip()
            if max_cmd_chars > 0 and len(text) > max_cmd_chars:
                text = text[:max_cmd_chars] + "...[truncated]"
            recent.append(text)
            if len(recent) >= limit:
                break
    recent.reverse()
    return recent


def summarize_audit_usage(path: Path, *, backups: int = DEFAULT_BACKUPS) -> dict[str, Any]:
    """Aggregate local token counts and estimated USD spend from JSONL audit logs."""
    files: list[Path] = []
    for idx in range(max(0, backups), 0, -1):
        bp = _backup_path(path, idx)
        if bp.is_file():
            files.append(bp)
    if path.is_file():
        files.append(path)

    total_calls = 0
    total_input_tokens = 0
    total_output_tokens = 0
    total_cost_usd = 0.0
    by_layer: dict[str, dict[str, Any]] = {}

    for fp in files:
        try:
            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if not isinstance(rec, dict):
                continue
            total_calls += 1
            layer = str(rec.get("layer") or "unknown")
            entry = by_layer.setdefault(
                layer,
                {"calls": 0, "inputTokens": 0, "outputTokens": 0, "estimatedCostUsd": 0.0},
            )
            entry["calls"] += 1
            in_tok = rec.get("inputTokens")
            out_tok = rec.get("outputTokens")
            cost = rec.get("estimatedCostUsd")
            if isinstance(in_tok, int):
                total_input_tokens += in_tok
                entry["inputTokens"] += in_tok
            if isinstance(out_tok, int):
                total_output_tokens += out_tok
                entry["outputTokens"] += out_tok
            if isinstance(cost, (int, float)):
                total_cost_usd += float(cost)
                entry["estimatedCostUsd"] = round(entry["estimatedCostUsd"] + float(cost), 8)

    return {
        "filesScanned": len(files),
        "totalCalls": total_calls,
        "totalInputTokens": total_input_tokens,
        "totalOutputTokens": total_output_tokens,
        "totalEstimatedCostUsd": round(total_cost_usd, 8),
        "byLayer": by_layer,
    }
