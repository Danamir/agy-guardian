"""Unit tests for remote Gemini Decision 1 backend, key isolation, fallback routing, and audit usage."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agy_guardian.audit import summarize_audit_usage
from agy_guardian.classifiers import GeminiDecisionClassifier, Thresholds
from agy_guardian.cli import handle_hook_payload, main as cli_main
from agy_guardian.config import GuardianConfig, load_config
from agy_guardian.pipeline import evaluate_command

CWD = r"C:\Users\dev\workspace\my-app"
WS = [r"C:\Users\dev\workspace\my-app"]
FAKE_PAID_KEY = "AIza-FAKE-PAID-KEY-DO-NOT-LEAK-98765"
FAKE_FREE_KEY = "AIza-FAKE-FREE-KEY-DO-NOT-LEAK-12345"


def _make_gemini_response(
    allow: float = 0.96,
    ask: float = 0.03,
    deny: float = 0.01,
    dest: float = 0.01,
    out: float = 0.01,
    inj: float = 0.01,
    input_tokens: int = 680,
) -> dict:
    return {
        "answers": {
            "decision": {
                "type": "choice",
                "choice": "allow" if allow >= max(ask, deny) else ("deny" if deny >= ask else "ask"),
                "probabilities": {"allow": allow, "ask": ask, "deny": deny},
                "confidence": max(allow, ask, deny),
            },
            "destructive": {"type": "noul", "noul": dest, "confidence": 1.0 - dest},
            "outside_workspace": {"type": "noul", "noul": out, "confidence": 1.0 - out},
            "injection_or_obfuscation": {"type": "noul", "noul": inj, "confidence": 1.0 - inj},
        },
        "usage": {
            "total_tokens": input_tokens,
            "total_input_tokens": input_tokens,
            "total_output_tokens": 0,
        },
    }


def _hook_payload(command: str) -> str:
    return json.dumps(
        {
            "conversationId": "conv-gemini-test",
            "workspacePaths": WS,
            "cwd": CWD,
            "lastUserInput": "Run unit tests",
            "hookEventName": "PreToolUse",
            "stepIdx": 3,
            "toolCall": {"id": "toolu_01", "name": "run_command", "args": {"CommandLine": command}},
        }
    )


class TestGeminiDecisionBackend(unittest.TestCase):
    def test_paid_vs_free_key_isolation_in_load_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty_env = Path(tmp) / ".env"
            empty_env.write_text("", encoding="utf-8")

            # Only generic GEMINI_API_KEY and FREE key set -> Paid key MUST stay empty
            env_vars = {
                "AGY_GUARDIAN_BACKEND": "gemini_decision_paid",
                "AGY_GUARDIAN_POLICY_FILE": "off",
                "AGY_GUARDIAN_AUDIT_LOG": "off",
                "GEMINI_API_KEY": FAKE_FREE_KEY,
                "AGY_GUARDIAN_GEMINI_FREE_API_KEY": FAKE_FREE_KEY,
            }
            with patch.dict(os.environ, env_vars, clear=True):
                cfg = load_config(empty_env)
                self.assertEqual(cfg.backend, "gemini_decision_paid")
                self.assertEqual(cfg.gemini_paid_api_key, "")
                self.assertEqual(cfg.gemini_free_api_key, FAKE_FREE_KEY)
                # Keys must not appear in repr(cfg)
                self.assertNotIn(FAKE_FREE_KEY, repr(cfg))

                # Paid backend fails closed without making any HTTP request
                with patch("agy_guardian.classifiers._post_json") as mock_post:
                    rep = evaluate_command("pytest -q", CWD, WS, "run tests", cfg)
                    self.assertEqual(rep.decision, "ask")
                    self.assertEqual(rep.layer, "L3_gemini_decision_paid")
                    self.assertIn("AGY_GUARDIAN_GEMINI_PAID_API_KEY", rep.error or "")
                    mock_post.assert_not_called()

            # Generic or Paid keys are never used for Free Tier, even on explicit opt-in -> fails closed
            with patch.dict(
                os.environ,
                {
                    "AGY_GUARDIAN_BACKEND": "gemini_decision_free",
                    "AGY_GUARDIAN_POLICY_FILE": "off",
                    "AGY_GUARDIAN_AUDIT_LOG": "off",
                    "GEMINI_API_KEY": FAKE_FREE_KEY,
                    "AGY_GUARDIAN_GEMINI_API_KEY": FAKE_FREE_KEY,
                    "AGY_GUARDIAN_GEMINI_PAID_API_KEY": FAKE_PAID_KEY,
                },
                clear=True,
            ):
                cfg_free = load_config(empty_env)
                self.assertEqual(cfg_free.gemini_free_api_key, "")
                self.assertEqual(cfg_free.gemini_paid_api_key, FAKE_PAID_KEY)
                with patch("agy_guardian.classifiers._post_json") as mock_post:
                    rep = evaluate_command("pytest -q", CWD, WS, "run tests", cfg_free)
                    self.assertEqual(rep.decision, "ask")
                    self.assertIn("AGY_GUARDIAN_GEMINI_FREE_API_KEY", rep.error or "")
                    mock_post.assert_not_called()

    def test_bare_gemini_decision_requires_explicit_tier(self) -> None:
        cfg_unset = GuardianConfig(
            backend="gemini_decision",
            gemini_tier="",
            gemini_paid_api_key=FAKE_PAID_KEY,
            gemini_free_api_key=FAKE_FREE_KEY,
            audit_log_path="off",
        )
        with patch("agy_guardian.classifiers._post_json") as mock_post:
            rep = evaluate_command("pytest -q", CWD, WS, "run tests", cfg_unset)
            self.assertEqual(rep.decision, "ask")
            self.assertIn("AGY_GUARDIAN_GEMINI_TIER", rep.error or "")
            mock_post.assert_not_called()

        cfg_paid = GuardianConfig(
            backend="gemini_decision",
            gemini_tier="paid",
            gemini_paid_api_key=FAKE_PAID_KEY,
            audit_log_path="off",
        )
        with patch("agy_guardian.classifiers._post_json", return_value=(_make_gemini_response(), 120.0)):
            rep = evaluate_command("pytest -q", CWD, WS, "run tests", cfg_paid)
            self.assertEqual(rep.decision, "allow")
            self.assertEqual(rep.layer, "L3_gemini_decision_paid")

    def test_payload_schema_policy_forwarding_and_truncation(self) -> None:
        clf = GeminiDecisionClassifier(
            api_key=FAKE_PAID_KEY,
            schema_mode="multi",
            max_user_input_chars=50,
            thresholds=Thresholds(allow_min_prob=0.85, deny_min_prob=0.85, risk_max_prob=0.25),
        )
        long_prompt = "x" * 120
        payload = clf.build_payload(
            {
                "workspacePaths": WS,
                "cwd": CWD,
                "lastUserInput": long_prompt,
                "commandLine": "pytest -q",
                "projectPolicy": {"notes": "Local pytest allowed."},
            }
        )
        self.assertEqual(payload["model"], "gemini-decision-1")
        parsed_input = json.loads(payload["input"])
        self.assertEqual(parsed_input["projectPolicy"], {"notes": "Local pytest allowed."})
        self.assertTrue(parsed_input["lastUserInput"].endswith("...[truncated]"))
        self.assertLessEqual(len(parsed_input["lastUserInput"]), 50 + len("...[truncated]"))

        # Choice question keeps criteria; noul questions omit criteria and fold into instructions
        self.assertIn("criteria", payload["questions"]["decision"])
        for risk_q in ("destructive", "outside_workspace", "injection_or_obfuscation"):
            self.assertEqual(payload["questions"][risk_q]["type"], "noul")
            self.assertNotIn("criteria", payload["questions"][risk_q])
            self.assertIn("Yes if:", payload["questions"][risk_q]["instructions"])

    def test_fail_closed_on_http_errors_timeout_and_malformed_json(self) -> None:
        clf = GeminiDecisionClassifier(api_key=FAKE_PAID_KEY, schema_mode="multi")
        case = {"cwd": CWD, "workspacePaths": WS, "lastUserInput": "test", "commandLine": "pytest -q"}

        for status_code in (401, 403, 429, 500):
            err = urllib.error.HTTPError(
                url=clf.endpoint,
                code=status_code,
                msg="Error",
                hdrs=None,  # type: ignore[arg-type]
                fp=io.BytesIO(b""),
            )
            with patch("agy_guardian.classifiers._post_json", side_effect=err):
                res = clf.classify(case)
                self.assertEqual(res.decision, "ask")
                self.assertEqual(res.http_status, status_code)
                self.assertNotIn(FAKE_PAID_KEY, res.error or "")

        with patch("agy_guardian.classifiers._post_json", side_effect=TimeoutError("timed out")):
            res = clf.classify(case)
            self.assertEqual(res.decision, "ask")
            self.assertIsNotNone(res.error)

        with patch("agy_guardian.classifiers._post_json", return_value=(["not-a-dict"], 20.0)):
            res = clf.classify(case)
            self.assertEqual(res.decision, "ask")

        # Missing risk question in multi mode must fail closed to ask
        incomplete = {
            "answers": {"decision": {"type": "choice", "probabilities": {"allow": 0.99, "ask": 0.01, "deny": 0.0}}},
            "usage": {"total_input_tokens": 500, "total_output_tokens": 0},
        }
        with patch("agy_guardian.classifiers._post_json", return_value=(incomplete, 25.0)):
            res = clf.classify(case)
            self.assertEqual(res.decision, "ask")
            self.assertIn("Missing or malformed risk probabilities", res.error or "")

    def test_local_primary_fallback_to_gemini_paid_and_free(self) -> None:
        # 1. Local llama-server down -> fallback to gemini_decision_paid succeeds
        cfg_paid_fb = GuardianConfig(
            backend="systemone",
            fallback_backend="gemini_decision_paid",
            gemini_paid_api_key=FAKE_PAID_KEY,
            audit_log_path="off",
        )
        with patch(
            "agy_guardian.classifiers._post_json",
            side_effect=[ConnectionRefusedError("llama-server offline"), (_make_gemini_response(input_tokens=1000), 180.0)],
        ) as mock_post:
            rep = evaluate_command("pytest -q", CWD, WS, "run tests", cfg_paid_fb)
            self.assertEqual(rep.decision, "allow")
            self.assertEqual(rep.layer, "L3_gemini_decision_paid")
            self.assertEqual(rep.input_tokens, 1000)
            self.assertEqual(rep.output_tokens, 0)
            self.assertAlmostEqual(rep.estimated_cost_usd or 0.0, 0.0001, places=7)
            self.assertEqual(mock_post.call_count, 2)
            # Key sent strictly in x-goog-api-key header, never in URL
            fb_call = mock_post.call_args_list[1]
            self.assertNotIn(FAKE_PAID_KEY, fb_call[0][0])
            self.assertEqual(fb_call[1]["extra_headers"], {"x-goog-api-key": FAKE_PAID_KEY})

        # 2. Local llama-server down -> fallback to gemini_decision_free succeeds with $0.0 cost
        cfg_free_fb = GuardianConfig(
            backend="systemone",
            fallback_backend="gemini_decision_free",
            gemini_free_api_key=FAKE_FREE_KEY,
            audit_log_path="off",
        )
        with patch(
            "agy_guardian.classifiers._post_json",
            side_effect=[ConnectionRefusedError("llama-server offline"), (_make_gemini_response(input_tokens=700), 190.0)],
        ):
            rep = evaluate_command("pytest -q", CWD, WS, "run tests", cfg_free_fb)
            self.assertEqual(rep.decision, "allow")
            self.assertEqual(rep.layer, "L3_gemini_decision_free")
            self.assertEqual(rep.input_tokens, 700)
            self.assertEqual(rep.estimated_cost_usd, 0.0)

        # 3. Local llama-server down + fallback_backend=none -> fails closed without calling Gemini
        cfg_no_fb = GuardianConfig(
            backend="systemone",
            fallback_backend="none",
            gemini_paid_api_key=FAKE_PAID_KEY,
            audit_log_path="off",
        )
        with patch("agy_guardian.classifiers._post_json", side_effect=ConnectionRefusedError("down")) as mock_post:
            rep = evaluate_command("pytest -q", CWD, WS, "run tests", cfg_no_fb)
            self.assertEqual(rep.decision, "ask")
            self.assertEqual(rep.layer, "L3_systemone")
            self.assertEqual(mock_post.call_count, 1)

    def test_audit_token_usage_summary_and_no_secret_leakage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_file = Path(tmp) / "audit.jsonl"
            cfg_paid = GuardianConfig(
                backend="gemini_decision_paid",
                gemini_paid_api_key=FAKE_PAID_KEY,
                audit_log_path=str(audit_file),
            )
            with patch(
                "agy_guardian.classifiers._post_json",
                return_value=(_make_gemini_response(input_tokens=800), 150.0),
            ):
                rep = handle_hook_payload(_hook_payload("pytest -q"), cfg_paid)
                self.assertEqual(rep.decision, "allow")
                self.assertEqual(rep.layer, "L3_gemini_decision_paid")

            cfg_free = GuardianConfig(
                backend="gemini_decision_free",
                gemini_free_api_key=FAKE_FREE_KEY,
                audit_log_path=str(audit_file),
            )
            with patch(
                "agy_guardian.classifiers._post_json",
                return_value=(_make_gemini_response(input_tokens=600), 160.0),
            ):
                rep2 = handle_hook_payload(_hook_payload("pytest -v"), cfg_free)
                self.assertEqual(rep2.decision, "allow")
                self.assertEqual(rep2.layer, "L3_gemini_decision_free")

            raw_audit = audit_file.read_text(encoding="utf-8")
            self.assertNotIn(FAKE_PAID_KEY, raw_audit)
            self.assertNotIn(FAKE_FREE_KEY, raw_audit)

            summary = summarize_audit_usage(audit_file)
            self.assertEqual(summary["totalCalls"], 2)
            self.assertEqual(summary["totalInputTokens"], 1400)
            self.assertEqual(summary["totalOutputTokens"], 0)
            self.assertAlmostEqual(summary["totalEstimatedCostUsd"], 0.00008, places=7)
            self.assertEqual(summary["byLayer"]["L3_gemini_decision_paid"]["inputTokens"], 800)
            self.assertEqual(summary["byLayer"]["L3_gemini_decision_free"]["estimatedCostUsd"], 0.0)

            # Verify --health never leaks API keys
            buf = io.StringIO()
            with patch.dict(
                os.environ,
                {
                    "AGY_GUARDIAN_BACKEND": "gemini_decision_paid",
                    "AGY_GUARDIAN_FALLBACK_BACKEND": "gemini_decision_free",
                    "AGY_GUARDIAN_GEMINI_PAID_API_KEY": FAKE_PAID_KEY,
                    "AGY_GUARDIAN_GEMINI_FREE_API_KEY": FAKE_FREE_KEY,
                    "AGY_GUARDIAN_AUDIT_LOG": str(audit_file),
                },
                clear=False,
            ):
                with redirect_stdout(buf):
                    rc = cli_main(["--health"])
                self.assertEqual(rc, 0)
                health_out = buf.getvalue()
                self.assertIn("CONFIGURED", health_out)
                self.assertNotIn(FAKE_PAID_KEY, health_out)
                self.assertNotIn(FAKE_FREE_KEY, health_out)


if __name__ == "__main__":
    unittest.main()
