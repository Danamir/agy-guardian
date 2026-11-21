"""Antigravity PreToolUse hook CLI and diagnostic entrypoint."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from typing import Any

from .audit import build_audit_record, write_audit_entry
from .config import GuardianConfig, load_config
from .pipeline import DecisionReport, evaluate_command


def _emit_hook_response(decision: str, reason: str) -> None:
    safe_decision = decision if decision in ("allow", "ask", "force_ask", "deny") else "ask"
    payload = {"decision": safe_decision, "reason": reason}
    # Always emit pure 7-bit ASCII JSON (\uXXXX escapes) so Windows cmd/cp850/cp1252
    # pipes never raise UnicodeEncodeError or emit invalid UTF-8 bytes to Antigravity.
    sys.stdout.write(json.dumps(payload, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def _read_stdin_utf8() -> str:
    if hasattr(sys.stdin, "buffer"):
        return sys.stdin.buffer.read().decode("utf-8", errors="replace")
    return sys.stdin.read()


def _finalize_with_audit(
    report: DecisionReport,
    *,
    config: GuardianConfig,
    conversation_id: str,
    step_idx: int | None,
    tool_name: str,
    command_line: str,
    cwd: str,
    workspace_paths: list[str],
) -> DecisionReport:
    audit_path = config.resolved_audit_path
    if audit_path is None:
        return report

    record = build_audit_record(
        conversation_id=conversation_id,
        step_idx=step_idx,
        tool_name=tool_name,
        command_line=command_line,
        cwd=cwd,
        workspace_paths=workspace_paths,
        layer=report.layer,
        rule_id=report.rule_id,
        decision=report.decision,
        reason=report.reason,
        probs=report.probs,
        risk_probs=report.risk_probs,
        latency_ms=report.latency_ms,
        error=report.error,
        policy_name=report.policy_name,
        policy_error=report.policy_error,
    )
    err = write_audit_entry(
        audit_path,
        record,
        max_bytes=config.audit_max_bytes,
        backups=config.audit_backups,
    )
    if err is not None:
        report.audit_error = err
        if config.audit_fail_closed and report.decision == "allow":
            report.decision = "ask"
            report.reason = f"Audit log write failed ({err}); downgraded allow to ask (fail-closed)"
    return report


def handle_hook_payload(raw_stdin: str, config: GuardianConfig) -> DecisionReport:
    """Process one Antigravity PreToolUse JSON payload and return a fail-closed DecisionReport."""
    try:
        cleaned = raw_stdin.lstrip("\ufeff").strip()
        if not cleaned:
            return DecisionReport(
                decision="ask",
                reason="Empty PreToolUse stdin payload — failing closed to ask",
                layer="fail_closed",
                error="Empty stdin",
            )
        payload = json.loads(cleaned)
        if not isinstance(payload, dict):
            return DecisionReport(
                decision="ask",
                reason="Malformed PreToolUse payload (not a JSON object) — failing closed to ask",
                layer="fail_closed",
                error="Non-object payload",
            )
    except Exception as exc:
        return DecisionReport(
            decision="ask",
            reason=f"Invalid PreToolUse JSON ({type(exc).__name__}) — failing closed to ask",
            layer="fail_closed",
            error=f"{type(exc).__name__}: {exc}",
        )

    conversation_id = str(payload.get("conversationId") or "")
    step_idx = payload.get("stepIdx") if isinstance(payload.get("stepIdx"), int) else None
    cwd = str(payload.get("cwd") or "")
    raw_ws = payload.get("workspacePaths")
    workspace_paths = [str(p) for p in raw_ws if isinstance(p, str)] if isinstance(raw_ws, list) else []
    last_user_input = str(payload.get("lastUserInput") or "")

    tool_call = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    tool_name = str(tool_call.get("name") or "")
    tool_args = tool_call.get("args") if isinstance(tool_call.get("args"), dict) else {}
    command_line = tool_args.get("CommandLine")
    if not isinstance(command_line, str):
        command_line = tool_args.get("commandLine") if isinstance(tool_args.get("commandLine"), str) else ""

    if tool_name and tool_name != "run_command":
        report = DecisionReport(
            decision="ask",
            reason=f"agy-guardian only gates run_command (received '{tool_name}')",
            layer="fail_closed",
        )
    else:
        report = evaluate_command(
            command_line=command_line,
            cwd=cwd,
            workspace_paths=workspace_paths,
            last_user_input=last_user_input,
            config=config,
        )

    return _finalize_with_audit(
        report,
        config=config,
        conversation_id=conversation_id,
        step_idx=step_idx,
        tool_name=tool_name or "run_command",
        command_line=command_line,
        cwd=cwd,
        workspace_paths=workspace_paths,
    )


def _check_health(endpoint: str, timeout_sec: float = 2.0) -> tuple[bool, str]:
    url = f"{endpoint.rstrip('/')}/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout_sec) as resp:
            body = resp.read().decode("utf-8", errors="replace").strip()
            return resp.status == 200, f"HTTP {resp.status} {body}".strip()
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def main(argv: list[str] | None = None) -> int:
    try:
        args_list = sys.argv[1:] if argv is None else argv
        config = load_config()

        # Fast-path hook mode (zero argparse overhead when called directly by Antigravity)
        if not args_list:
            raw_stdin = _read_stdin_utf8()
            report = handle_hook_payload(raw_stdin, config)
            _emit_hook_response(report.decision, report.reason)
            return 0

        parser = argparse.ArgumentParser(description="AGY Guardian PreToolUse command approval hook.")
        parser.add_argument("--check", default="", help="Manually evaluate a CommandLine instead of reading stdin")
        parser.add_argument("--cwd", default=os.getcwd(), help="Working directory for --check")
        parser.add_argument(
            "--workspace",
            action="append",
            default=[],
            help="Workspace path(s) for --check (defaults to --cwd)",
        )
        parser.add_argument("--user-input", default="", help="Simulated lastUserInput for --check")
        parser.add_argument("--backend", choices=("systemone", "completion", "auto"), default="")
        parser.add_argument("--endpoint", default="", help="Override llama-server endpoint URL")
        parser.add_argument("--policy", default="", help="Override per-project policy JSON path (or 'off')")
        parser.add_argument("--no-audit", action="store_true", help="Disable JSONL audit log for this invocation")
        parser.add_argument("--json", action="store_true", help="Emit full DecisionReport JSON for --check")
        parser.add_argument("--health", action="store_true", help="Check llama-server /health and exit")
        args = parser.parse_args(args_list)

        if args.backend:
            config.backend = args.backend
        if args.endpoint:
            config.endpoint = args.endpoint.rstrip("/")
        if args.policy:
            config.policy_file = args.policy
        if args.no_audit:
            config.audit_log_path = "off"

        if args.health:
            ok, detail = _check_health(config.effective_endpoint, timeout_sec=min(config.timeout_sec, 3.0))
            print(f"{config.effective_endpoint}/health -> {'OK' if ok else 'UNAVAILABLE'} ({detail})")
            return 0 if ok else 1

        if args.check:
            ws = args.workspace or [args.cwd]
            report = evaluate_command(
                command_line=args.check,
                cwd=args.cwd,
                workspace_paths=ws,
                last_user_input=args.user_input,
                config=config,
            )
            report = _finalize_with_audit(
                report,
                config=config,
                conversation_id="cli-check",
                step_idx=None,
                tool_name="run_command",
                command_line=args.check,
                cwd=args.cwd,
                workspace_paths=ws,
            )
            if args.json:
                print(
                    json.dumps(
                        {
                            "decision": report.decision,
                            "layer": report.layer,
                            "ruleId": report.rule_id,
                            "reason": report.reason,
                            "probs": report.probs,
                            "riskProbs": report.risk_probs,
                            "latencyMs": round(report.latency_ms, 2),
                            "policyName": report.policy_name,
                            "policyError": report.policy_error,
                            "error": report.error,
                            "auditError": report.audit_error,
                        },
                        indent=2,
                        ensure_ascii=False,
                    )
                )
            else:
                pol_str = f", policy={report.policy_name}" if report.policy_name else ""
                print(
                    f"[{report.decision.upper()}] ({report.layer}{pol_str}, {report.latency_ms:.1f} ms) {report.reason}"
                )
            return 0

        # If flags like --no-audit or --backend were passed without --check, still run hook stdin mode
        raw_stdin = _read_stdin_utf8()
        report = handle_hook_payload(raw_stdin, config)
        _emit_hook_response(report.decision, report.reason)
        return 0
    except Exception as exc:
        _emit_hook_response("ask", f"agy-guardian internal error ({type(exc).__name__}) - failing closed to ask")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
