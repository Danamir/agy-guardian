"""Fail-closed JSONL audit logger with size-based rotation for AGY Guardian."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB
DEFAULT_BACKUPS = 3


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
    error: str | None = None,
    policy_name: str | None = None,
    policy_error: str | None = None,
) -> dict[str, Any]:
    return {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "conversationId": conversation_id,
        "stepIdx": step_idx,
        "toolName": tool_name,
        "commandLine": command_line,
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
    """Append one JSONL audit record with optional size-based rotation.

    Returns None on success, or an error string on failure (never raises).
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        line_bytes = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        _rotate_if_needed(path, len(line_bytes), max_bytes=max_bytes, backups=backups)
        with path.open("ab") as fh:
            fh.write(line_bytes)
            fh.flush()
        return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
