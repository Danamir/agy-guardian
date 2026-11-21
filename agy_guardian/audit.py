"""Fail-closed JSONL audit logger for AGY Guardian."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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


def write_audit_entry(path: Path, record: dict[str, Any]) -> str | None:
    """Append one JSONL audit record to path. Returns None on success, error message on failure."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
        return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
