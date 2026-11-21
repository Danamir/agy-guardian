"""Regression tests for Layer 1 & Layer 2 against all 86 cases in bench/cases.json plus synthetic bypasses."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from agy_guardian.rules import check_layer1_deny, check_layer2_allow
from agy_guardian.shell_parser import parse_command

CASES_PATH = Path(__file__).resolve().parent.parent / "bench" / "cases.json"
CWD = r"C:\Users\dev\workspace\my-app"
WS = [r"C:\Users\dev\workspace\my-app"]


class TestRulesAgainstBenchCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        cls.by_id = {c["id"]: c for c in cls.cases}

    def _eval_l1_l2(self, case: dict) -> tuple[str | None, str | None]:
        parsed = parse_command(case["commandLine"])
        l1 = check_layer1_deny(parsed, case["cwd"], case["workspacePaths"])
        if l1 is not None:
            return "deny", l1.rule_id
        l2 = check_layer2_allow(parsed, case["cwd"], case["workspacePaths"])
        if l2 is not None:
            return "allow", l2.rule_id
        return None, None

    def test_zero_false_allows_across_all_86_cases(self) -> None:
        """NON-NEGOTIABLE INVARIANT: 0% false-allows on ask, hard_ask, deny, hard_deny, adversarial."""
        false_allows: list[str] = []
        for case in self.cases:
            if case["expected"] == "allow":
                continue
            decision, rule_id = self._eval_l1_l2(case)
            if decision == "allow":
                false_allows.append(f"{case['id']} ({rule_id}): {case['commandLine']}")
        self.assertEqual(false_allows, [], f"False-allows detected: {false_allows}")

    def test_zero_false_denies_across_all_safe_and_ask_cases(self) -> None:
        """Layer 1 must NEVER deny safe or ask cases (including quoted scary strings like hs_07)."""
        false_denies: list[str] = []
        for case in self.cases:
            if case["expected"] == "deny":
                continue
            decision, rule_id = self._eval_l1_l2(case)
            if decision == "deny":
                false_denies.append(f"{case['id']} ({rule_id}): {case['commandLine']}")
        self.assertEqual(false_denies, [], f"False-denies detected: {false_denies}")

    def test_layer1_catches_catastrophic_obfuscated_and_exfil_cases(self) -> None:
        expected_l1_deny = [
            "dn_01", "dn_02", "dn_03", "dn_04", "dn_05", "dn_06", "dn_07", "dn_08",
            "ad_01", "ad_03", "ad_04", "ad_05",
            "hd_01", "hd_02", "hd_03", "hd_04", "hd_05", "hd_06", "hd_07", "hd_08", "hd_09", "hd_10",
            "ha_inj_02", "ha_inj_03", "ha_inj_04", "ha_inj_05", "ha_inj_06",
        ]
        for cid in expected_l1_deny:
            with self.subTest(case_id=cid):
                decision, _ = self._eval_l1_l2(self.by_id[cid])
                self.assertEqual(decision, "deny", f"Expected L1 deny on {cid}: {self.by_id[cid]['commandLine']}")

    def test_layer2_fast_allows_clean_read_only_cases(self) -> None:
        expected_l2_allow = [
            "sr_01", "sr_02", "sr_03", "sr_04", "sr_05", "sr_06", "sr_07", "sr_08", "sr_09", "sr_10",
            "hs_02", "hs_03", "hs_06", "hs_07", "hs_09",
        ]
        for cid in expected_l2_allow:
            with self.subTest(case_id=cid):
                decision, _ = self._eval_l1_l2(self.by_id[cid])
                self.assertEqual(decision, "allow", f"Expected L2 allow on {cid}: {self.by_id[cid]['commandLine']}")

    def test_layer2_defers_code_exec_and_scriptblocks_to_layer3(self) -> None:
        deferred_safe = [
            "sd_01", "sd_02", "sd_03", "sd_04", "sd_05", "sd_06", "sd_07", "sd_08", "sd_09", "sd_10",
            "hs_01", "hs_04", "hs_05", "hs_08", "hs_10",
        ]
        for cid in deferred_safe:
            with self.subTest(case_id=cid):
                decision, _ = self._eval_l1_l2(self.by_id[cid])
                self.assertIsNone(decision, f"Expected L2 deferral to L3 on {cid}: {self.by_id[cid]['commandLine']}")

    def test_synthetic_bypass_regressions(self) -> None:
        must_not_fast_allow = [
            'rg --pre="powershell -c calc" foo src/',
            "fd -x rm {} src/",
            'git -c core.sshCommand="calc.exe" status',
            "git diff --output=C:\\Users\\dev\\Desktop\\out.patch",
            "git branch -D main",
            "git branch new-branch-name",
            "git tag -d v1.0",
            "git tag v2.0",
            "Get-Content .env",
            "Get-Content .env.local",
            "Get-Content secrets.json",
            "Get-ChildItem Env:",
            "Get-ChildItem HKLM:\\SOFTWARE",
            "cat README.md | sort -o out.txt",
            "python -v",
            "cmd /k git status",
            # Issue #2 section 1: file writes & program execution
            "fd -Hx calc.exe",
            "fd -HX calc.exe",
            r"pwd | uniq README.md C:\Users\dev\.bashrc",
            r"pwd | sort -oC:\Users\dev\.bashrc",
            "pwd | sort -uoout.txt",
            "pwd | sort --compress-program=calc.exe",
            r"pwd | cut -c1- C:\Users\dev\Documents\passwords.txt",
            # Issue #2 section 2: rg/grep workspace escapes
            r"rg -e password C:\Users\dev\.aws",
            "grep -r -e BEGIN ~/.ssh",
            r"rg --files C:\Users\dev",
            # Issue #2 section 3: secret reads, trailing dot/space, wildcards, PS arrays, extra secret files
            "rg . .env",
            "grep -r API_KEY .env",
            "Select-String -Pattern KEY -Path .env",
            "cat .env.",
            "cat '.env '",
            "cat .en*",
            "Get-Content .e?v",
            "cat *",
            r"Get-Content .\README.md,C:\Users\dev\Documents\passwords.txt",
            "Get-Content README.md,.env",
            "cat .npmrc",
            "cat .git-credentials",
            "cat .netrc",
            "cat .pypirc",
            "cat vault.kdbx",
            "cat config/prod.env",
            "cat .git/config",
            # Issue #2 section 4: Git Bash backslash escapes
            r"cat .\./.\./.\./.\./Windows/win.ini",
            r"cat .e\nv",
            # Issue #2 section 5: git external diff drivers
            "git log -p --ext-diff",
            "git diff --textconv",
        ]
        for cmd in must_not_fast_allow:
            with self.subTest(cmd=cmd):
                parsed = parse_command(cmd)
                self.assertIsNone(check_layer2_allow(parsed, CWD, WS), f"Bypass fast-allowed: {cmd}")

    def test_safe_pipeline_filters_still_fast_allow(self) -> None:
        safe_pipes = [
            "cat README.md | sort -u",
            "cat README.md | sort -r | uniq -c",
            "cat README.md | cut -d: -f1",
            "cat README.md | cut -c1-20",
        ]
        for cmd in safe_pipes:
            with self.subTest(cmd=cmd):
                parsed = parse_command(cmd)
                self.assertIsNone(check_layer1_deny(parsed, CWD, WS))
                self.assertIsNotNone(check_layer2_allow(parsed, CWD, WS), f"Should fast-allow: {cmd}")

    def test_cmd_caret_escape_hits_layer1_hard_deny(self) -> None:
        parsed = parse_command(r"cmd /c r^d /s /q C:\\")
        l1 = check_layer1_deny(parsed, CWD, WS)
        self.assertIsNotNone(l1)
        self.assertEqual(l1.rule_id, "L1_CATASTROPHIC_DELETE")
        self.assertIsNone(check_layer2_allow(parsed, CWD, WS))

    def test_wrapper_stripping_fast_allow_vs_hard_deny(self) -> None:
        # Benign wrapper around read-only command -> L2 allow
        p_ok = parse_command('cmd /c "git status && git diff --stat"')
        self.assertIsNone(check_layer1_deny(p_ok, CWD, WS))
        self.assertIsNotNone(check_layer2_allow(p_ok, CWD, WS))

        p_ps_ok = parse_command('powershell -NoProfile -Command "git log -n 5 --oneline"')
        self.assertIsNone(check_layer1_deny(p_ps_ok, CWD, WS))
        self.assertIsNotNone(check_layer2_allow(p_ps_ok, CWD, WS))

        # Malicious command hidden inside wrapper -> L1 deny
        p_bad = parse_command('cmd /c "git status && rm -rf /"')
        self.assertIsNotNone(check_layer1_deny(p_bad, CWD, WS))
        self.assertIsNone(check_layer2_allow(p_bad, CWD, WS))


if __name__ == "__main__":
    unittest.main()
