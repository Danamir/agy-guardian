"""Unit tests for scripts/manage_permissions.py and scripts/manage_policy.py."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import manage_permissions  # noqa: E402
import manage_policy  # noqa: E402


def _run_main(mod, argv: list[str]) -> tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = mod.main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestManagePermissionsScript(unittest.TestCase):
    def test_show_replace_dedupe_and_remove_with_safety_guards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings_path = Path(tmp) / "settings.json"
            initial = {
                "theme": "dark",
                "permissions": {
                    "allow": [
                        "command(git status)",
                        "command(glab issue create --title \"Foo\" --description \"Bar\")",
                    ]
                },
            }
            settings_path.write_text(json.dumps(initial, indent=2), encoding="utf-8")

            # Show last 1
            rc, out, err = _run_main(
                manage_permissions,
                ["show", "--last", "1", "--path", str(settings_path), "--json"],
            )
            self.assertEqual(rc, 0, err)
            payload = json.loads(out)
            self.assertEqual(payload["total"], 2)
            self.assertEqual(len(payload["entries"]), 1)
            self.assertEqual(payload["entries"][0]["index"], 1)

            # Safety guard rejects mismatched --expected
            rc, _, err = _run_main(
                manage_permissions,
                [
                    "replace",
                    "--index",
                    "-1",
                    "--expected",
                    "command(wrong)",
                    "--value",
                    "command(glab issue create *)",
                    "--path",
                    str(settings_path),
                ],
            )
            self.assertEqual(rc, 1)
            self.assertIn("Safety guard failed", err)

            # Replace last entry cleanly and create a .bak backup
            old_rule = 'command(glab issue create --title "Foo" --description "Bar")'
            rc, out, err = _run_main(
                manage_permissions,
                [
                    "replace",
                    "--index",
                    "-1",
                    "--expected",
                    old_rule,
                    "--value",
                    "command(glab issue create *)",
                    "--path",
                    str(settings_path),
                    "--json",
                ],
            )
            self.assertEqual(rc, 0, err)
            rep_data = json.loads(out)
            self.assertEqual(rep_data["action"], "replaced")
            self.assertTrue(Path(rep_data["backup"]).is_file())

            updated = json.loads(settings_path.read_text(encoding="utf-8"))
            self.assertEqual(updated["theme"], "dark")
            self.assertEqual(
                updated["permissions"]["allow"],
                ["command(git status)", "command(glab issue create *)"],
            )

            # Replacing with an already-existing rule deduplicates cleanly
            rc, out, err = _run_main(
                manage_permissions,
                [
                    "replace",
                    "--index",
                    "-1",
                    "--expected",
                    "command(glab issue create *)",
                    "--value",
                    "command(git status)",
                    "--path",
                    str(settings_path),
                    "--no-backup",
                    "--json",
                ],
            )
            self.assertEqual(rc, 0, err)
            self.assertEqual(json.loads(out)["action"], "deduplicated")
            self.assertEqual(
                json.loads(settings_path.read_text(encoding="utf-8"))["permissions"]["allow"],
                ["command(git status)"],
            )

            # Remove entry
            rc, out, err = _run_main(
                manage_permissions,
                [
                    "remove",
                    "--index",
                    "0",
                    "--expected",
                    "command(git status)",
                    "--path",
                    str(settings_path),
                    "--no-backup",
                    "--json",
                ],
            )
            self.assertEqual(rc, 0, err)
            self.assertEqual(json.loads(out)["total"], 0)
            self.assertEqual(
                json.loads(settings_path.read_text(encoding="utf-8"))["permissions"]["allow"],
                [],
            )


class TestManagePolicyScript(unittest.TestCase):
    def test_create_update_validate_and_remove_policy_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pol_path = Path(tmp) / "policies.json"
            ws_root = r"C:\Users\dev\workspace\mesh-project"

            # Create new project entry with URL, program, extra workspace, and note
            rc, out, err = _run_main(
                manage_policy,
                [
                    "update",
                    "--path",
                    str(pol_path),
                    "--project",
                    "mesh-project",
                    "--workspace",
                    ws_root,
                    "--add-url",
                    "http://127.0.0.1:8188/",
                    "--add-program",
                    r"C:\Program Files\Blender Foundation\*\blender.exe",
                    "--add-workspace",
                    r"D:\Assets\Meshes",
                    "--append-note",
                    "ComfyUI and Blender allowed on project meshes.",
                    "--json",
                ],
            )
            self.assertEqual(rc, 0, err)
            created = json.loads(out)["entry"]
            self.assertEqual(created["name"], "mesh-project")
            self.assertEqual(created["allowedUrls"], ["http://127.0.0.1:8188"])
            self.assertEqual(
                created["allowedPrograms"],
                [r"C:\Program Files\Blender Foundation\*\blender.exe"],
            )
            self.assertEqual(created["extraWorkspaces"], [r"D:\Assets\Meshes"])

            # Show by workspace finds the project
            rc, out, err = _run_main(
                manage_policy,
                ["show", "--path", str(pol_path), "--workspace", ws_root + r"\subdir"],
            )
            self.assertEqual(rc, 0, err)
            self.assertEqual(json.loads(out)["project"]["name"], "mesh-project")

            # Invalid URL and unsafe program are rejected
            rc_bad_url, _, err_url = _run_main(
                manage_policy,
                [
                    "update",
                    "--path",
                    str(pol_path),
                    "--project",
                    "mesh-project",
                    "--add-url",
                    "file:///etc/passwd",
                ],
            )
            self.assertEqual(rc_bad_url, 1)
            self.assertIn("Invalid http(s) URL", err_url)

            rc_bad_prog, _, err_prog = _run_main(
                manage_policy,
                [
                    "update",
                    "--path",
                    str(pol_path),
                    "--project",
                    "mesh-project",
                    "--add-program",
                    "blender.exe; calc.exe",
                ],
            )
            self.assertEqual(rc_bad_prog, 1)
            self.assertIn("Invalid program", err_prog)

            # Refuses to write policy file inside a workspace
            in_ws_pol = Path(tmp) / "workspace" / "policies.json"
            rc_ws, _, err_ws = _run_main(
                manage_policy,
                [
                    "update",
                    "--path",
                    str(in_ws_pol),
                    "--project",
                    "bad",
                    "--workspace",
                    str(Path(tmp) / "workspace"),
                ],
            )
            self.assertEqual(rc_ws, 1)
            self.assertIn("Refused", err_ws)

            # Remove URL and program cleanly (and create backup)
            rc, out, err = _run_main(
                manage_policy,
                [
                    "update",
                    "--path",
                    str(pol_path),
                    "--project",
                    "mesh-project",
                    "--remove-url",
                    "http://127.0.0.1:8188",
                    "--remove-program",
                    r"C:\Program Files\Blender Foundation\*\blender.exe",
                    "--json",
                ],
            )
            self.assertEqual(rc, 0, err)
            res = json.loads(out)
            self.assertTrue(Path(res["backup"]).is_file())
            self.assertEqual(res["entry"]["allowedUrls"], [])
            self.assertEqual(res["entry"]["allowedPrograms"], [])


if __name__ == "__main__":
    unittest.main()
