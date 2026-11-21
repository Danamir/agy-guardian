"""Unit tests for bench/run_bench.py model existence filtering."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

BENCH_DIR = Path(__file__).resolve().parents[1] / "bench"
if str(BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(BENCH_DIR))

import run_bench  # noqa: E402


class TestFilterExistingModels(unittest.TestCase):
    def test_partitions_existing_and_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            present_file = root / "present.gguf"
            present_file.write_bytes(b"gguf")
            missing_file = root / "missing.gguf"
            dir_not_file = root / "subdir"
            dir_not_file.mkdir()

            manifest = [
                {"name": "present", "backend": "systemone", "path": str(present_file)},
                {"name": "missing", "backend": "systemone", "path": str(missing_file)},
                {"name": "dir_entry", "backend": "systemone", "path": str(dir_not_file)},
            ]

            existing, missing = run_bench.filter_existing_models(manifest, skip_server=False)
            self.assertEqual([m["name"] for m in existing], ["present"])
            self.assertEqual([m["name"] for m, _ in missing], ["missing", "dir_entry"])
            self.assertEqual(missing[0][1], missing_file)

    def test_skip_server_keeps_all_models(self) -> None:
        manifest = [
            {"name": "missing", "backend": "systemone", "path": "/does/not/exist.gguf"},
        ]
        existing, missing = run_bench.filter_existing_models(manifest, skip_server=True)
        self.assertEqual([m["name"] for m in existing], ["missing"])
        self.assertEqual(missing, [])


class TestMainMissingModels(unittest.TestCase):
    def test_main_warns_and_runs_only_existing_models(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            present_file = root / "present.gguf"
            present_file.write_bytes(b"gguf")
            missing_file = root / "missing.gguf"

            manifest_path = root / "models.json"
            manifest_path.write_text(
                json.dumps(
                    [
                        {"name": "present-model", "backend": "systemone", "path": str(present_file)},
                        {"name": "missing-model", "backend": "systemone", "path": str(missing_file)},
                    ]
                ),
                encoding="utf-8",
            )
            cases_path = root / "cases.json"
            cases_path.write_text("[]", encoding="utf-8")
            out_dir = root / "out"

            called_models: list[str] = []

            def fake_run_model(entry, *_args, **_kwargs):
                called_models.append(entry["name"])
                return {
                    "run_tag": f"{entry['name']}__multi",
                    "backend": entry["backend"],
                    "status": "ok",
                    "metrics": {
                        "false_allow_count": 0,
                        "false_allow_ids": [],
                        "deny_bypass_count": 0,
                        "safe_recall_pct": 100.0,
                        "deny_recall_pct": 100.0,
                        "exact_acc_pct": 100.0,
                        "min_p_allow_safe": 0.95,
                        "max_p_allow_unsafe": 0.1,
                        "safety_margin": 0.85,
                        "brier_allow": 0.01,
                        "p50_ms": 10.0,
                        "p95_ms": 12.0,
                        "vram_delta_mib": 100,
                        "errors": 0,
                        "by_category": {},
                        "sweep": {
                            k: {"false_allows": 0, "safe_recall_pct": 100.0}
                            for k in ("0.70", "0.80", "0.85", "0.90", "0.95")
                        },
                    },
                }

            stderr_buf = io.StringIO()
            argv = [
                "run_bench.py",
                "--manifest",
                str(manifest_path),
                "--cases",
                str(cases_path),
                "--output-dir",
                str(out_dir),
                "--llama-server",
                "fake-llama-server",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(run_bench, "load_dotenv"),
                mock.patch.object(run_bench, "run_model", side_effect=fake_run_model),
                redirect_stderr(stderr_buf),
            ):
                rc = run_bench.main()

            self.assertEqual(rc, 0)
            self.assertEqual(called_models, ["present-model"])
            self.assertIn("[WARN] Skipping missing model 'missing-model'", stderr_buf.getvalue())

    def test_main_returns_nonzero_when_all_models_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manifest_path = root / "models.json"
            manifest_path.write_text(
                json.dumps(
                    [
                        {"name": "missing-a", "backend": "systemone", "path": str(root / "a.gguf")},
                        {"name": "missing-b", "backend": "systemone", "path": str(root / "b.gguf")},
                    ]
                ),
                encoding="utf-8",
            )
            cases_path = root / "cases.json"
            cases_path.write_text("[]", encoding="utf-8")
            out_dir = root / "out"

            stderr_buf = io.StringIO()
            argv = [
                "run_bench.py",
                "--manifest",
                str(manifest_path),
                "--cases",
                str(cases_path),
                "--output-dir",
                str(out_dir),
                "--llama-server",
                "fake-llama-server",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(run_bench, "load_dotenv"),
                redirect_stderr(stderr_buf),
            ):
                rc = run_bench.main()

            self.assertEqual(rc, 1)
            err_text = stderr_buf.getvalue()
            self.assertIn("[WARN] Skipping missing model 'missing-a'", err_text)
            self.assertIn("[WARN] Skipping missing model 'missing-b'", err_text)
            self.assertIn("None of the matched models exist on disk", err_text)
            self.assertFalse((out_dir / "report.md").exists())

    def test_main_handles_cp1252_stdout_without_unicode_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            present_file = root / "present.gguf"
            present_file.write_bytes(b"gguf")
            manifest_path = root / "models.json"
            manifest_path.write_text(
                json.dumps([{"name": "present-model", "backend": "systemone", "path": str(present_file)}]),
                encoding="utf-8",
            )
            cases_path = root / "cases.json"
            cases_path.write_text("[]", encoding="utf-8")
            out_dir = root / "out"

            def fake_run_model(entry, *_args, **_kwargs):
                return {
                    "run_tag": f"{entry['name']}__multi",
                    "backend": entry["backend"],
                    "status": "ok",
                    "metrics": {
                        "false_allow_count": 0,
                        "false_allow_ids": [],
                        "deny_bypass_count": 0,
                        "safe_recall_pct": 100.0,
                        "deny_recall_pct": 100.0,
                        "exact_acc_pct": 100.0,
                        "min_p_allow_safe": 0.95,
                        "max_p_allow_unsafe": 0.1,
                        "safety_margin": 0.85,
                        "brier_allow": 0.01,
                        "p50_ms": 10.0,
                        "p95_ms": 12.0,
                        "vram_delta_mib": 100,
                        "errors": 0,
                        "by_category": {},
                        "sweep": {
                            k: {"false_allows": 0, "safe_recall_pct": 100.0}
                            for k in ("0.70", "0.80", "0.85", "0.90", "0.95")
                        },
                    },
                }

            cp1252_stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
            argv = [
                "run_bench.py",
                "--manifest",
                str(manifest_path),
                "--cases",
                str(cases_path),
                "--output-dir",
                str(out_dir),
                "--llama-server",
                "fake-llama-server",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(sys, "stdout", cp1252_stdout),
                mock.patch.object(run_bench, "load_dotenv"),
                mock.patch.object(run_bench, "run_model", side_effect=fake_run_model),
            ):
                rc = run_bench.main()
            self.assertEqual(rc, 0)
            self.assertTrue((out_dir / "report.md").is_file())


if __name__ == "__main__":
    unittest.main()
