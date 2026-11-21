"""3-layer fail-closed command evaluation pipeline."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .classifiers import (
    ClassificationResult,
    CompletionClassifier,
    SystemOneClassifier,
    Thresholds,
)
from .config import GuardianConfig
from .rules import check_layer1_deny, check_layer2_allow
from .shell_parser import parse_command


@dataclass
class DecisionReport:
    decision: str  # "allow" | "ask" | "deny"
    reason: str
    layer: str  # "L1_deny" | "L2_allow" | "L3_systemone" | "L3_completion" | "fail_closed"
    rule_id: str | None = None
    probs: dict[str, float] = field(default_factory=dict)
    risk_probs: dict[str, float] = field(default_factory=dict)
    latency_ms: float = 0.0
    error: str | None = None
    audit_error: str | None = None


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

    endpoint = config.effective_endpoint

    if config.backend == "completion":
        clf = CompletionClassifier(
            endpoint=endpoint,
            timeout_sec=config.timeout_sec,
            thresholds=thresholds,
        )
        return "L3_completion", clf.classify(case)

    # Primary: SystemOne (/v1/systemone)
    primary = SystemOneClassifier(
        endpoint=endpoint,
        schema_mode=config.schema_mode,
        timeout_sec=config.timeout_sec,
        thresholds=thresholds,
    )
    res = primary.classify(case)
    if res.error is None:
        return "L3_systemone", res

    # Optional fallback to /v1/chat/completions:
    # 1. Explicit fallback_endpoint configured -> fall back on any primary error
    # 2. backend == "auto" -> fall back on the same endpoint ONLY if /v1/systemone is unsupported (HTTP 404/405/501)
    should_fallback_same = config.backend == "auto" and res.http_status in (404, 405, 501)
    if config.fallback_endpoint or should_fallback_same:
        fb_endpoint = config.fallback_endpoint or endpoint
        fb_clf = CompletionClassifier(
            endpoint=fb_endpoint,
            timeout_sec=config.timeout_sec,
            thresholds=thresholds,
        )
        fb_res = fb_clf.classify(case)
        if fb_res.error is None:
            return "L3_completion", fb_res
        # Both failed -> preserve diagnostic context and fail closed to ask
        combined_err = f"primary={res.error}; fallback={fb_res.error}"
        return "L3_completion", ClassificationResult(
            decision="ask",
            latency_ms=res.latency_ms + fb_res.latency_ms,
            error=combined_err,
        )

    return "L3_systemone", res


def evaluate_command(
    command_line: str,
    cwd: str,
    workspace_paths: list[str],
    last_user_input: str = "",
    config: GuardianConfig | None = None,
    classifier: Any | None = None,
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

        parsed = parse_command(command_line)

        # Layer 1: Deterministic Hard-Deny (0 ms)
        if cfg.enable_layer1:
            l1 = check_layer1_deny(parsed, cwd, workspace_paths)
            if l1 is not None:
                return DecisionReport(
                    decision="deny",
                    reason=l1.reason,
                    layer="L1_deny",
                    rule_id=l1.rule_id,
                    latency_ms=(time.perf_counter() - t0) * 1000.0,
                )

        # Layer 2: Deterministic Fast-Allow (0 ms)
        if cfg.enable_layer2:
            l2 = check_layer2_allow(parsed, cwd, workspace_paths)
            if l2 is not None:
                return DecisionReport(
                    decision="allow",
                    reason=l2.reason,
                    layer="L2_allow",
                    rule_id=l2.rule_id,
                    latency_ms=(time.perf_counter() - t0) * 1000.0,
                )

        # Layer 3: Local Decision Model Classifier
        if not cfg.enable_layer3:
            return DecisionReport(
                decision="ask",
                reason="Deferred past Layer 1/2 with Layer 3 disabled — failing closed to ask",
                layer="fail_closed",
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        case = {
            "workspacePaths": list(workspace_paths or []),
            "cwd": cwd or "",
            "lastUserInput": last_user_input or "",
            "commandLine": command_line,
        }
        layer_tag, res = _run_layer3(case, cfg, classifier=classifier)
        decision = res.decision if res.decision in ("allow", "ask", "deny") else "ask"
        backend_label = (
            f"systemone/{cfg.schema_mode}"
            if layer_tag == "L3_systemone"
            else ("completion" if layer_tag == "L3_completion" else "custom")
        )
        return DecisionReport(
            decision=decision,
            reason=_format_l3_reason(backend_label, res),
            layer=layer_tag,
            probs=res.probs,
            risk_probs=res.risk_probs,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            error=res.error,
        )
    except Exception as exc:
        return DecisionReport(
            decision="ask",
            reason=f"Internal guardian error ({type(exc).__name__}) — failing closed to ask",
            layer="fail_closed",
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            error=f"{type(exc).__name__}: {exc}",
        )
