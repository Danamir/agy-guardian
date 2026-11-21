"""Unit tests for Layer 3 classifiers, thresholds, fallback modes, and full 3-layer pipeline."""

from __future__ import annotations

import io
import json
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from agy_guardian.classifiers import (
    ClassificationResult,
    CompletionClassifier,
    SystemOneClassifier,
    Thresholds,
    apply_thresholds,
)
from agy_guardian.config import GuardianConfig
from agy_guardian.pipeline import evaluate_command

CWD = r"C:\Users\dev\workspace\my-app"
WS = [r"C:\Users\dev\workspace\my-app"]
CASES_PATH = Path(__file__).resolve().parent.parent / "bench" / "cases.json"


def _make_systemone_response(
    allow: float,
    ask: float,
    deny: float,
    dest: float = 0.02,
    out: float = 0.02,
    inj: float = 0.02,
) -> dict:
    return {
        "answers": {
            "decision": {"probabilities": {"allow": allow, "ask": ask, "deny": deny}},
            "destructive": {"noul": dest},
            "outside_workspace": {"noul": out},
            "injection_or_obfuscation": {"noul": inj},
        },
        "usage": {"input_tokens": 210, "output_tokens": 0},
    }


def _make_completion_response(token: str = "A", logprob: float = -0.01) -> dict:
    return {
        "choices": [
            {
                "message": {"content": token},
                "logprobs": {
                    "content": [
                        {
                            "token": token,
                            "logprob": logprob,
                            "top_logprobs": [
                                {"token": token, "logprob": logprob},
                                {"token": "Q" if token != "Q" else "A", "logprob": -5.0},
                            ],
                        }
                    ]
                },
            }
        ],
        "usage": {"prompt_tokens": 120, "completion_tokens": 1},
    }


class TestClassifiersAndPipeline(unittest.TestCase):
    def test_apply_thresholds_boundaries(self) -> None:
        t = Thresholds(allow_min_prob=0.90, deny_min_prob=0.85, risk_max_prob=0.25)
        self.assertEqual(apply_thresholds({"allow": 0.90, "ask": 0.09, "deny": 0.01}, {"destructive": 0.25}, t), "allow")
        self.assertEqual(apply_thresholds({"allow": 0.899, "ask": 0.10, "deny": 0.001}, {"destructive": 0.01}, t), "ask")
        self.assertEqual(apply_thresholds({"allow": 0.95, "ask": 0.04, "deny": 0.01}, {"destructive": 0.251}, t), "ask")
        self.assertEqual(apply_thresholds({"allow": 0.95, "ask": 0.04, "deny": 0.01}, {"outside_workspace": 0.30}, t), "ask")
        self.assertEqual(apply_thresholds({"allow": 0.80, "ask": 0.15, "deny": 0.05}, {"injection_or_obfuscation": 0.85}, t), "deny")
        self.assertEqual(apply_thresholds({"allow": 0.01, "ask": 0.14, "deny": 0.85}, {}, t), "deny")

    def test_systemone_fail_closed_on_missing_risk_or_malformed(self) -> None:
        clf = SystemOneClassifier(schema_mode="multi")
        case = {"cwd": CWD, "workspacePaths": WS, "lastUserInput": "test", "commandLine": "pytest -q"}

        # Missing risk dimension must fail closed (risk defaults to 1.0 -> ask)
        incomplete = {"answers": {"decision": {"probabilities": {"allow": 0.99, "ask": 0.01, "deny": 0.0}}}}
        with patch("agy_guardian.classifiers._post_json", return_value=(incomplete, 12.0)):
            res = clf.classify(case)
            self.assertEqual(res.decision, "ask")

        # Connection refused -> ask
        with patch("agy_guardian.classifiers._post_json", side_effect=ConnectionRefusedError("refused")):
            res = clf.classify(case)
            self.assertEqual(res.decision, "ask")
            self.assertIsNotNone(res.error)

        # Malformed non-dict JSON -> ask
        with patch("agy_guardian.classifiers._post_json", return_value=(["bad"], 5.0)):
            res = clf.classify(case)
            self.assertEqual(res.decision, "ask")

    def test_pipeline_3_layers_routing(self) -> None:
        cfg = GuardianConfig(audit_log_path="off")

        # Layer 1 hit does not call Layer 3
        with patch("agy_guardian.classifiers._post_json") as mock_post:
            r1 = evaluate_command("rm -rf /", CWD, WS, "clean", cfg)
            self.assertEqual(r1.decision, "deny")
            self.assertEqual(r1.layer, "L1_deny")
            mock_post.assert_not_called()

        # Layer 2 hit does not call Layer 3
        with patch("agy_guardian.classifiers._post_json") as mock_post:
            r2 = evaluate_command("git status", CWD, WS, "check status", cfg)
            self.assertEqual(r2.decision, "allow")
            self.assertEqual(r2.layer, "L2_allow")
            mock_post.assert_not_called()

        # Deferred command calls Layer 3 SystemOne
        with patch(
            "agy_guardian.classifiers._post_json",
            return_value=(_make_systemone_response(0.95, 0.04, 0.01), 50.0),
        ) as mock_post:
            r3 = evaluate_command("pytest -q", CWD, WS, "run tests", cfg)
            self.assertEqual(r3.decision, "allow")
            self.assertEqual(r3.layer, "L3_systemone")
            mock_post.assert_called_once()
            self.assertTrue(mock_post.call_args[0][0].endswith("/v1/systemone"))

    def test_auto_fallback_on_404_and_explicit_fallback_endpoint(self) -> None:
        http_404 = urllib.error.HTTPError(
            url="http://127.0.0.1:8099/v1/systemone",
            code=404,
            msg="Not Found",
            hdrs=None,  # type: ignore[arg-type]
            fp=io.BytesIO(b""),
        )

        # backend="auto" falls back to /v1/chat/completions on HTTP 404
        cfg_auto = GuardianConfig(backend="auto", audit_log_path="off")
        with patch(
            "agy_guardian.classifiers._post_json",
            side_effect=[http_404, (_make_completion_response("A"), 35.0)],
        ) as mock_post:
            r = evaluate_command("pytest -q", CWD, WS, "run tests", cfg_auto)
            self.assertEqual(r.decision, "allow")
            self.assertEqual(r.layer, "L3_completion")
            self.assertEqual(mock_post.call_count, 2)
            self.assertTrue(mock_post.call_args_list[1][0][0].endswith("/v1/chat/completions"))

        # backend="systemone" (default) does NOT fall back when no fallback_endpoint is set
        cfg_strict = GuardianConfig(backend="systemone", audit_log_path="off")
        with patch("agy_guardian.classifiers._post_json", side_effect=ConnectionRefusedError("down")) as mock_post:
            r = evaluate_command("pytest -q", CWD, WS, "run tests", cfg_strict)
            self.assertEqual(r.decision, "ask")
            self.assertEqual(mock_post.call_count, 1)

        # Explicit fallback_endpoint is used when primary fails
        cfg_fb = GuardianConfig(
            backend="systemone",
            fallback_endpoint="http://127.0.0.1:8100",
            audit_log_path="off",
        )
        with patch(
            "agy_guardian.classifiers._post_json",
            side_effect=[ConnectionRefusedError("primary down"), (_make_completion_response("Q"), 40.0)],
        ) as mock_post:
            r = evaluate_command("git push origin main", CWD, WS, "push", cfg_fb)
            self.assertEqual(r.decision, "ask")
            self.assertEqual(r.layer, "L3_completion")
            self.assertEqual(mock_post.call_args_list[1][0][0], "http://127.0.0.1:8100/v1/chat/completions")

    def test_full_86_cases_fail_closed_when_server_offline(self) -> None:
        """Even with llama-server offline, 0 false-allows across all 86 cases; L1 & L2 still operate."""
        cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        cfg = GuardianConfig(backend="systemone", audit_log_path="off")

        class OfflineClassifier:
            def classify(self, case: dict) -> ClassificationResult:
                return ClassificationResult(decision="ask", error="ConnectionRefusedError: offline")

        clf = OfflineClassifier()
        false_allows = []
        for c in cases:
            rep = evaluate_command(
                command_line=c["commandLine"],
                cwd=c["cwd"],
                workspace_paths=c["workspacePaths"],
                last_user_input=c["lastUserInput"],
                config=cfg,
                classifier=clf,
            )
            if c["expected"] != "allow" and rep.decision == "allow":
                false_allows.append(c["id"])
        self.assertEqual(false_allows, [])

    def test_session_brain_dir_strictly_scoped_to_conversation_id(self) -> None:
        brain_root = r"C:\Users\dev\.gemini\antigravity-cli\brain"
        cid = "833ebcb1-aec1-4523-9637-c90900c2faaa"
        other_cid = "11111111-2222-3333-4444-555555555555"
        expected_brain = rf"{brain_root}\{cid}"

        cfg = GuardianConfig(
            audit_log_path="off",
            policy_file="off",
            allow_session_brain=True,
            session_brain_root=brain_root,
        )

        # Invalid/traversal conversation IDs are strictly rejected
        for bad_cid in ("", "short", "../config", r"..\config", "a/b/cdef1234", "conv with space"):
            self.assertIsNone(cfg.resolve_session_brain_dir(bad_cid))
        self.assertEqual(cfg.resolve_session_brain_dir(cid), expected_brain)

        # Layer 2 fast-allows read-only access inside the CURRENT session brain dir
        with patch("agy_guardian.classifiers._post_json") as mock_post:
            rep = evaluate_command(
                rf"Get-Content {expected_brain}\scratch\notes.md",
                CWD,
                WS,
                "read scratch notes",
                cfg,
                conversation_id=cid,
            )
            self.assertEqual(rep.decision, "allow")
            self.assertEqual(rep.layer, "L2_allow")
            mock_post.assert_not_called()

        # Layer 2 must NOT fast-allow another session's brain dir or ~/.gemini/config
        for forbidden_cmd in (
            rf"Get-Content {brain_root}\{other_cid}\scratch\notes.md",
            r"Get-Content C:\Users\dev\.gemini\config\hooks.json",
        ):
            with patch(
                "agy_guardian.classifiers._post_json",
                return_value=(_make_systemone_response(0.10, 0.85, 0.05, out=0.80), 20.0),
            ) as mock_post:
                rep = evaluate_command(
                    forbidden_cmd,
                    CWD,
                    WS,
                    "read file",
                    cfg,
                    conversation_id=cid,
                )
                self.assertEqual(rep.decision, "ask")
                self.assertEqual(rep.layer, "L3_systemone")
                mock_post.assert_called_once()

        # Layer 3 receives the session brain dir in workspacePaths and projectPolicy.allowedWritePaths
        captured_cases: list[dict] = []

        class CaptureClassifier:
            def classify(self, case: dict) -> ClassificationResult:
                captured_cases.append(case)
                return ClassificationResult(decision="allow", probs={"allow": 0.96, "ask": 0.03, "deny": 0.01})

        rep_write = evaluate_command(
            rf"python {expected_brain}\scratch\gen.py",
            CWD,
            WS,
            "run scratch helper",
            cfg,
            classifier=CaptureClassifier(),
            conversation_id=cid,
        )
        self.assertEqual(rep_write.decision, "allow")
        self.assertEqual(len(captured_cases), 1)
        self.assertIn(expected_brain, captured_cases[0]["workspacePaths"])
        self.assertIn(expected_brain, captured_cases[0]["projectPolicy"]["allowedWritePaths"])
        self.assertIn(expected_brain, captured_cases[0]["projectPolicy"]["notes"])

        # Disabling allow_session_brain prevents the session brain dir from being added
        cfg_off = GuardianConfig(
            audit_log_path="off",
            policy_file="off",
            allow_session_brain=False,
            session_brain_root=brain_root,
        )
        self.assertIsNone(cfg_off.resolve_session_brain_dir(cid))
        captured_cases.clear()
        evaluate_command(
            rf"Get-Content {expected_brain}\scratch\notes.md",
            CWD,
            WS,
            "read scratch notes",
            cfg_off,
            classifier=CaptureClassifier(),
            conversation_id=cid,
        )
        self.assertEqual(len(captured_cases), 1)
        self.assertNotIn(expected_brain, captured_cases[0]["workspacePaths"])


if __name__ == "__main__":
    unittest.main()
