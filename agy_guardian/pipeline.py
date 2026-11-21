"""3-layer fail-closed command evaluation pipeline."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .classifiers import (
    ClassificationResult,
    CompletionClassifier,
    GeminiDecisionClassifier,
    SystemOneClassifier,
    Thresholds,
)
from .config import GEMINI_PAID_USD_PER_MILLION_INPUT_TOKENS, GuardianConfig
from .policy import EffectivePolicy, load_effective_policy
from .rules import check_layer1_deny, check_layer2_allow
from .shell_parser import normalize_windows_path, parse_command


@dataclass
class DecisionReport:
    decision: str  # "allow" | "ask" | "deny"
    reason: str
    layer: str  # "L1_deny" | "L2_allow" | "L3_systemone" | "L3_completion" | "L3_gemini_decision_paid" | "L3_gemini_decision_free" | "fail_closed"
    rule_id: str | None = None
    probs: dict[str, float] = field(default_factory=dict)
    risk_probs: dict[str, float] = field(default_factory=dict)
    latency_ms: float = 0.0
    input_tokens: int | None = None
    output_tokens: int | None = None
    estimated_cost_usd: float | None = None
    error: str | None = None
    audit_error: str | None = None
    policy_name: str | None = None
    policy_error: str | None = None


def _estimate_cost_usd(layer_tag: str, input_tokens: int | None) -> float | None:
    if input_tokens is None:
        return None
    if layer_tag == "L3_gemini_decision_paid":
        return round(input_tokens * GEMINI_PAID_USD_PER_MILLION_INPUT_TOKENS / 1_000_000.0, 8)
    if layer_tag == "L3_gemini_decision_free":
        return 0.0
    return None


def _invoke_backend(
    backend_name: str,
    case: dict[str, Any],
    config: GuardianConfig,
    thresholds: Thresholds,
    *,
    endpoint_override: str | None = None,
) -> tuple[str, ClassificationResult]:
    resolved, err = config.resolve_backend_name(backend_name)
    if err or resolved is None:
        return "L3_gemini_decision", ClassificationResult(decision="ask", error=err or "Invalid backend")

    endpoint = (endpoint_override or config.effective_endpoint).rstrip("/")
    if resolved == "completion":
        clf = CompletionClassifier(
            endpoint=endpoint,
            timeout_sec=config.timeout_sec,
            thresholds=thresholds,
        )
        return "L3_completion", clf.classify(case)

    if resolved in ("systemone", "auto"):
        clf_s1 = SystemOneClassifier(
            endpoint=endpoint,
            schema_mode=config.schema_mode,
            timeout_sec=config.timeout_sec,
            thresholds=thresholds,
        )
        return "L3_systemone", clf_s1.classify(case)

    if resolved == "gemini_decision_paid":
        if not (config.gemini_paid_api_key or "").strip():
            return "L3_gemini_decision_paid", ClassificationResult(
                decision="ask",
                error="Missing AGY_GUARDIAN_GEMINI_PAID_API_KEY for gemini_decision_paid",
            )
        clf_gp = GeminiDecisionClassifier(
            api_key=config.gemini_paid_api_key,
            endpoint=config.gemini_endpoint,
            model=config.gemini_model,
            schema_mode=config.schema_mode,
            timeout_sec=config.timeout_sec,
            thresholds=thresholds,
            max_user_input_chars=config.gemini_max_user_input_chars,
        )
        return "L3_gemini_decision_paid", clf_gp.classify(case)

    if resolved == "gemini_decision_free":
        if not (config.gemini_free_api_key or "").strip():
            return "L3_gemini_decision_free", ClassificationResult(
                decision="ask",
                error="Missing AGY_GUARDIAN_GEMINI_FREE_API_KEY for gemini_decision_free",
            )
        clf_gf = GeminiDecisionClassifier(
            api_key=config.gemini_free_api_key,
            endpoint=config.gemini_endpoint,
            model=config.gemini_model,
            schema_mode=config.schema_mode,
            timeout_sec=config.timeout_sec,
            thresholds=thresholds,
            max_user_input_chars=config.gemini_max_user_input_chars,
        )
        return "L3_gemini_decision_free", clf_gf.classify(case)

    return "fail_closed", ClassificationResult(decision="ask", error=f"Unsupported backend '{resolved}'")


def _format_l3_reason(backend_label: str, res: ClassificationResult) -> str:
    if res.error:
        return f"Layer 3 ({backend_label}) error ({res.error}) — failing closed to ask"
    p_allow = res.probs.get("allow", 0.0)
    p_deny = res.probs.get("deny", 0.0)
    if res.risk_probs:
        max_risk = max(res.risk_probs.values())
        return (
            f"Layer 3 ({backend_label}): {res.decision} "
            f"(P(allow)={p_allow:.2f}, P(deny)={p_deny:.2f}, max_risk={max_risk:.2f})"
        )
    return f"Layer 3 ({backend_label}): {res.decision} (P(allow)={p_allow:.2f}, P(deny)={p_deny:.2f})"


def _run_layer3(
    case: dict[str, Any],
    config: GuardianConfig,
    classifier: Any | None = None,
) -> tuple[str, ClassificationResult]:
    thresholds = Thresholds(
        allow_min_prob=config.allow_min_prob,
        deny_min_prob=config.deny_min_prob,
        risk_max_prob=config.risk_max_prob,
    )

    if classifier is not None:
        return "L3_custom", classifier.classify(case)

    primary_layer, res = _invoke_backend(config.backend, case, config, thresholds)
    if res.error is None:
        return primary_layer, res

    # 1. Explicit fallback_backend configured (e.g., local systemone -> gemini_decision_paid)
    fb_backend = (config.fallback_backend or "none").strip().lower()
    if fb_backend not in ("", "none"):
        resolved_primary, _ = config.resolve_backend_name(config.backend)
        resolved_fb, _ = config.resolve_backend_name(fb_backend)
        if resolved_fb != resolved_primary:
            fb_endpoint_override = (
                config.fallback_endpoint
                if (resolved_fb == "completion" and config.fallback_endpoint)
                else None
            )
            fb_layer, fb_res = _invoke_backend(
                fb_backend,
                case,
                config,
                thresholds,
                endpoint_override=fb_endpoint_override,
            )
            if fb_res.error is None:
                return fb_layer, fb_res
            combined_err = f"primary={res.error}; fallback={fb_res.error}"
            return fb_layer, ClassificationResult(
                decision="ask",
                latency_ms=res.latency_ms + fb_res.latency_ms,
                error=combined_err,
            )

    # 2. Legacy /v1/chat/completions fallback:
    #    - Explicit fallback_endpoint configured -> fall back on any primary error
    #    - backend == "auto" -> fall back on same endpoint ONLY if /v1/systemone is unsupported (404/405/501)
    should_fallback_same = config.backend == "auto" and res.http_status in (404, 405, 501)
    if primary_layer == "L3_systemone" and (config.fallback_endpoint or should_fallback_same):
        fb_endpoint = config.fallback_endpoint or config.effective_endpoint
        fb_layer, fb_res = _invoke_backend(
            "completion",
            case,
            config,
            thresholds,
            endpoint_override=fb_endpoint,
        )
        if fb_res.error is None:
            return fb_layer, fb_res
        combined_err = f"primary={res.error}; fallback={fb_res.error}"
        return fb_layer, ClassificationResult(
            decision="ask",
            latency_ms=res.latency_ms + fb_res.latency_ms,
            error=combined_err,
        )

    return primary_layer, res


_TRANSCRIPT_TAIL_BYTES = 64 * 1024  # Read at most the last 64 KiB of transcript.jsonl


def extract_preceding_assistant_message(
    session_brain_dir: str | None,
    *,
    max_chars: int = 500,
) -> str | None:
    """Read the last user-facing assistant message preceding the latest USER_INPUT in transcript.jsonl.

    Returns None silently if the transcript is missing, unreadable, or has no preceding assistant message.
    """
    if not session_brain_dir or max_chars <= 0:
        return None
    transcript = Path(session_brain_dir) / ".system_generated" / "logs" / "transcript.jsonl"
    try:
        if not transcript.is_file():
            return None
        size = transcript.stat().st_size
        with transcript.open("rb") as fh:
            if size > _TRANSCRIPT_TAIL_BYTES:
                fh.seek(size - _TRANSCRIPT_TAIL_BYTES)
                # Drop potentially partial first line after seeking into the middle of the file
                fh.readline()
            raw_lines = fh.read().decode("utf-8", errors="replace").splitlines()
    except Exception:
        return None

    seen_user_input = False
    for line in reversed(raw_lines):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except Exception:
            continue
        if not isinstance(entry, dict):
            continue
        etype = entry.get("type")
        if not seen_user_input:
            if etype == "USER_INPUT":
                seen_user_input = True
            continue
        if etype == "PLANNER_RESPONSE":
            content = entry.get("content")
            if isinstance(content, str) and content.strip():
                text = content.strip()
                if len(text) > max_chars:
                    return "...[truncated] " + text[-max_chars:]
                return text
    return None


def _merge_workspace_paths(
    workspace_paths: list[str],
    policy: EffectivePolicy,
    extra_paths: list[str] | None = None,
) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for p in (
        list(workspace_paths or [])
        + policy.extra_workspaces
        + policy.allowed_write_paths
        + list(extra_paths or [])
    ):
        cleaned = (p or "").strip()
        if not cleaned:
            continue
        norm = normalize_windows_path(cleaned)
        if norm not in seen:
            seen.add(norm)
            merged.append(cleaned)
    return merged


def evaluate_command(
    command_line: str,
    cwd: str,
    workspace_paths: list[str],
    last_user_input: str = "",
    config: GuardianConfig | None = None,
    classifier: Any | None = None,
    policy: EffectivePolicy | None = None,
    conversation_id: str = "",
) -> DecisionReport:
    """Run the 3-layer fail-closed guardian pipeline on a proposed CommandLine."""
    t0 = time.perf_counter()
    cfg = config or GuardianConfig()

    try:
        if not isinstance(command_line, str) or not command_line.strip():
            return DecisionReport(
                decision="ask",
                reason="Empty or invalid CommandLine — failing closed to ask",
                layer="fail_closed",
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        effective_policy = (
            policy
            if policy is not None
            else load_effective_policy(
                policy_path=cfg.resolved_policy_path,
                cwd=cwd,
                workspace_paths=list(workspace_paths or []),
                env_extra_workspaces=cfg.extra_workspaces,
            )
        )
        session_brain_dir = cfg.resolve_session_brain_dir(conversation_id)
        effective_workspaces = _merge_workspace_paths(
            list(workspace_paths or []),
            effective_policy,
            extra_paths=[session_brain_dir] if session_brain_dir else None,
        )
        policy_label = effective_policy.label

        parsed = parse_command(command_line)

        # Layer 1: Deterministic Hard-Deny (0 ms, non-overridable by project policy)
        if cfg.enable_layer1:
            l1 = check_layer1_deny(parsed, cwd, effective_workspaces)
            if l1 is not None:
                return DecisionReport(
                    decision="deny",
                    reason=l1.reason,
                    layer="L1_deny",
                    rule_id=l1.rule_id,
                    latency_ms=(time.perf_counter() - t0) * 1000.0,
                    policy_name=policy_label,
                    policy_error=effective_policy.error,
                )

        # Layer 2: Deterministic Fast-Allow (0 ms)
        if cfg.enable_layer2:
            l2 = check_layer2_allow(
                parsed,
                cwd,
                effective_workspaces,
                allowed_ssh_read_hosts=effective_policy.allowed_ssh_read_hosts,
            )
            if l2 is not None:
                return DecisionReport(
                    decision="allow",
                    reason=l2.reason,
                    layer="L2_allow",
                    rule_id=l2.rule_id,
                    latency_ms=(time.perf_counter() - t0) * 1000.0,
                    policy_name=policy_label,
                    policy_error=effective_policy.error,
                )

        # Layer 3: Local Decision Model Classifier
        if not cfg.enable_layer3:
            return DecisionReport(
                decision="ask",
                reason="Deferred past Layer 1/2 with Layer 3 disabled — failing closed to ask",
                layer="fail_closed",
                latency_ms=(time.perf_counter() - t0) * 1000.0,
                policy_name=policy_label,
                policy_error=effective_policy.error,
            )

        case: dict[str, Any] = {
            "workspacePaths": effective_workspaces,
            "cwd": cwd or "",
            "lastUserInput": last_user_input or "",
            "commandLine": command_line,
        }
        if cfg.include_last_assistant and session_brain_dir:
            user_len = len((last_user_input or "").strip())
            if cfg.last_assistant_max_user_chars <= 0 or user_len <= cfg.last_assistant_max_user_chars:
                preceding = extract_preceding_assistant_message(
                    session_brain_dir,
                    max_chars=cfg.last_assistant_max_chars,
                )
                if preceding:
                    case["precedingAssistantMessage"] = preceding
        policy_ctx = effective_policy.to_layer3_context()
        if session_brain_dir:
            policy_ctx = dict(policy_ctx or {})
            writes = list(policy_ctx.get("allowedWritePaths", []))
            if normalize_windows_path(session_brain_dir) not in {
                normalize_windows_path(p) for p in writes
            }:
                writes.append(session_brain_dir)
            policy_ctx["allowedWritePaths"] = writes
            brain_note = (
                f"Current session brain directory ({session_brain_dir}) is an authorized "
                "read/write workspace for this session; reading, writing, and running local "
                "helper/scratch scripts inside it is allowed."
            )
            existing_notes = str(policy_ctx.get("notes") or "").strip()
            policy_ctx["notes"] = f"{existing_notes} {brain_note}".strip() if existing_notes else brain_note
        if policy_ctx:
            case["projectPolicy"] = policy_ctx

        layer_tag, res = _run_layer3(case, cfg, classifier=classifier)
        decision = res.decision if res.decision in ("allow", "ask", "deny") else "ask"
        if layer_tag == "L3_systemone":
            backend_label = f"systemone/{cfg.schema_mode}"
        elif layer_tag == "L3_completion":
            backend_label = "completion"
        elif layer_tag == "L3_gemini_decision_paid":
            backend_label = f"gemini_decision_paid/{cfg.schema_mode}"
        elif layer_tag == "L3_gemini_decision_free":
            backend_label = f"gemini_decision_free/{cfg.schema_mode}"
        elif layer_tag == "L3_gemini_decision":
            backend_label = "gemini_decision"
        else:
            backend_label = "custom"
        return DecisionReport(
            decision=decision,
            reason=_format_l3_reason(backend_label, res),
            layer=layer_tag,
            probs=res.probs,
            risk_probs=res.risk_probs,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            input_tokens=res.input_tokens,
            output_tokens=res.output_tokens,
            estimated_cost_usd=_estimate_cost_usd(layer_tag, res.input_tokens),
            error=res.error,
            policy_name=policy_label,
            policy_error=effective_policy.error,
        )
    except Exception as exc:
        return DecisionReport(
            decision="ask",
            reason=f"Internal guardian error ({type(exc).__name__}) — failing closed to ask",
            layer="fail_closed",
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            error=f"{type(exc).__name__}: {exc}",
        )
