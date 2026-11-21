"""Backwards-compatible re-export shim for bench scripts."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from agy_guardian.classifiers import (  # noqa: E402
    COMPLETION_GRAMMAR,
    COMPLETION_SYSTEM_PROMPT,
    DEFAULT_GEMINI_DECISION_ENDPOINT,
    DEFAULT_GEMINI_DECISION_MODEL,
    SYSTEMONE_MULTI_QUESTIONS,
    SYSTEMONE_SINGLE_QUESTIONS,
    ClassificationResult,
    CompletionClassifier,
    GeminiDecisionClassifier,
    SystemOneClassifier,
    Thresholds,
    apply_thresholds,
)

__all__ = [
    "COMPLETION_GRAMMAR",
    "COMPLETION_SYSTEM_PROMPT",
    "DEFAULT_GEMINI_DECISION_ENDPOINT",
    "DEFAULT_GEMINI_DECISION_MODEL",
    "SYSTEMONE_MULTI_QUESTIONS",
    "SYSTEMONE_SINGLE_QUESTIONS",
    "ClassificationResult",
    "CompletionClassifier",
    "GeminiDecisionClassifier",
    "SystemOneClassifier",
    "Thresholds",
    "apply_thresholds",
]
