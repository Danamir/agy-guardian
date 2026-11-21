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
