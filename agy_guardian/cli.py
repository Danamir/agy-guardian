"""Antigravity PreToolUse hook CLI and diagnostic entrypoint."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from typing import Any

from .audit import build_audit_record, summarize_audit_usage, write_audit_entry
from .config import (
    VALID_BACKENDS,
    VALID_FALLBACK_BACKENDS,
    GuardianConfig,
    load_config,
)
from .pipeline import DecisionReport, evaluate_command


_HOOK_WIRE_DECISION_MAP = {
    "allow": "auto_approve",
    "auto_approve": "auto_approve",
    "ask": "ask",
    "force_ask": "force_ask",
    "deny": "deny",
}


def _emit_hook_response(decision: str, reason: str) -> None:
    safe_decision = _HOOK_WIRE_DECISION_MAP.get(decision, "ask")
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
        input_tokens=report.input_tokens,
        output_tokens=report.output_tokens,
        estimated_cost_usd=report.estimated_cost_usd,
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
            conversation_id=conversation_id,
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
        parser.add_argument("--conversation-id", default="", help="Optional conversationId for --check (enables session brain dir)")
        parser.add_argument("--backend", choices=VALID_BACKENDS, default="")
        parser.add_argument("--fallback-backend", choices=VALID_FALLBACK_BACKENDS, default="")
        parser.add_argument("--endpoint", default="", help="Override llama-server endpoint URL")
        parser.add_argument("--policy", default="", help="Override per-project policy JSON path (or 'off')")
        parser.add_argument("--no-audit", action="store_true", help="Disable JSONL audit log for this invocation")
        parser.add_argument("--json", action="store_true", help="Emit full DecisionReport JSON for --check")
        parser.add_argument("--health", action="store_true", help="Check configured Layer 3 backend readiness and exit")
        parser.add_argument("--usage", action="store_true", help="Summarize local token counts and estimated USD spend from audit logs")
        args = parser.parse_args(args_list)

        if args.backend:
            config.backend = args.backend
        if args.fallback_backend:
            config.fallback_backend = args.fallback_backend
        if args.endpoint:
            config.endpoint = args.endpoint.rstrip("/")
        if args.policy:
            config.policy_file = args.policy
        if args.no_audit:
            config.audit_log_path = "off"

        if args.usage:
            audit_path = config.resolved_audit_path
            if audit_path is None:
                print("Audit logging is disabled; no local usage logs to summarize.")
                return 0
            summary = summarize_audit_usage(audit_path, backups=config.audit_backups)
            if args.json:
                print(json.dumps(summary, indent=2, ensure_ascii=False))
            else:
                print(
                    f"Audit usage ({summary['filesScanned']} file(s), {summary['totalCalls']} calls): "
                    f"input_tokens={summary['totalInputTokens']}, "
                    f"output_tokens={summary['totalOutputTokens']}, "
                    f"estimated_cost_usd=${summary['totalEstimatedCostUsd']:.6f}"
                )
                for layer_name, st in sorted(summary["byLayer"].items()):
                    print(
                        f"  {layer_name}: calls={st['calls']}, "
                        f"input_tokens={st['inputTokens']}, "
                        f"estimated_cost_usd=${st['estimatedCostUsd']:.6f}"
                    )
            return 0

        if args.health:
            def _probe(name: str) -> tuple[bool, str]:
                resolved, err = config.resolve_backend_name(name)
                if err or resolved is None:
                    return False, err or f"Invalid backend '{name}'"
                if resolved in ("systemone", "completion", "auto"):
                    ok_l, detail_l = _check_health(
                        config.effective_endpoint, timeout_sec=min(config.timeout_sec, 3.0)
                    )
                    return ok_l, f"{config.effective_endpoint}/health -> {'OK' if ok_l else 'UNAVAILABLE'} ({detail_l})"
                if resolved == "gemini_decision_paid":
                    has_key = bool((config.gemini_paid_api_key or "").strip())
                    status = "CONFIGURED" if has_key else "MISSING_KEY"
                    return has_key, (
                        f"gemini_decision_paid ({config.gemini_model} @ {config.gemini_endpoint}) -> {status}"
                    )
                if resolved == "gemini_decision_free":
                    has_key = bool((config.gemini_free_api_key or "").strip())
                    status = "CONFIGURED" if has_key else "MISSING_KEY"
                    return has_key, (
                        f"gemini_decision_free ({config.gemini_model} @ {config.gemini_endpoint}) -> {status}"
                    )
                return False, f"Unsupported backend '{resolved}'"

            if not config.enable_layer3:
                print("Layer 3 is disabled (AGY_GUARDIAN_ENABLE_LAYER3=false); deterministic L1/L2 only.")
                return 0

            primary_ok, primary_msg = _probe(config.backend)
            print(f"primary [{config.backend}]: {primary_msg}")
            fb_ok = False
            if config.fallback_backend and config.fallback_backend != "none":
                fb_ok, fb_msg = _probe(config.fallback_backend)
                print(f"fallback [{config.fallback_backend}]: {fb_msg}")
            elif config.fallback_endpoint:
                fb_ok, fb_detail = _check_health(
                    config.fallback_endpoint, timeout_sec=min(config.timeout_sec, 3.0)
                )
                print(
                    f"fallback [completion]: {config.fallback_endpoint}/health -> "
                    f"{'OK' if fb_ok else 'UNAVAILABLE'} ({fb_detail})"
                )
            return 0 if (primary_ok or fb_ok) else 1

        if args.check:
            ws = args.workspace or [args.cwd]
            report = evaluate_command(
                command_line=args.check,
                cwd=args.cwd,
                workspace_paths=ws,
                last_user_input=args.user_input,
                config=config,
                conversation_id=args.conversation_id,
            )
            report = _finalize_with_audit(
                report,
                config=config,
                conversation_id=args.conversation_id or "cli-check",
                step_idx=None,
                tool_name="run_command",
                command_line=args.check,
                cwd=args.cwd,
                workspace_paths=ws,
            )
            if args.json:
                out_obj: dict[str, Any] = {
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
                }
                if report.input_tokens is not None:
                    out_obj["inputTokens"] = report.input_tokens
                if report.output_tokens is not None:
                    out_obj["outputTokens"] = report.output_tokens
                if report.estimated_cost_usd is not None:
                    out_obj["estimatedCostUsd"] = report.estimated_cost_usd
                print(json.dumps(out_obj, indent=2, ensure_ascii=False))
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
