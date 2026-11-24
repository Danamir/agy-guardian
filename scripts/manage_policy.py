#!/usr/bin/env python3
"""Safe, auditable CLI helper for inspecting and updating agy_guardian_policies.json.

Pure Python 3.12+ standard library. Validates URLs, programs, forge CLIs, and workspace
isolation, creates a timestamped .bak backup before overwriting, and writes JSON atomically.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agy_guardian.config import DEFAULT_POLICY_FILE, expand_path, load_config  # noqa: E402
from agy_guardian.policy import (  # noqa: E402
    _VALID_FORGE_CLIS,
    normalize_policy_program,
    normalize_policy_url,
)
from agy_guardian.shell_parser import is_path_within_workspace, normalize_windows_path  # noqa: E402


def _resolve_policy_path(raw: str | None) -> Path:
    if raw:
        return expand_path(raw)
    cfg = load_config()
    if cfg.resolved_policy_path is not None:
        return cfg.resolved_policy_path
    return expand_path(DEFAULT_POLICY_FILE)


def _default_policy_doc() -> dict[str, Any]:
    return {
        "defaults": {
            "extraWorkspaces": [],
            "allowedWritePaths": [],
            "allowedSshReadHosts": [],
            "allowedForgeCliWrites": [],
            "allowedUrls": [],
            "allowedPrograms": [],
            "policyNotes": "",
        },
        "projects": [],
    }


def _load_policy_doc(path: Path, *, allow_missing: bool = False) -> dict[str, Any]:
    if not path.is_file():
        if allow_missing:
            return _default_policy_doc()
        raise FileNotFoundError(f"Policy file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError(f"Malformed policy file (root must be a JSON object): {path}")
    return data


def _backup_file(path: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = path.with_name(f"{path.name}.{stamp}.bak")
    counter = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.name}.{stamp}-{counter}.bak")
        counter += 1
    shutil.copy2(path, candidate)
    return candidate


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(rendered)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _norm_key_path(raw: str) -> str:
    cleaned = raw.strip()
    if cleaned.startswith(("\\\\", "//")):
        cleaned = cleaned.replace("/", "\\").rstrip("\\")
    else:
        cleaned = str(expand_path(cleaned))
    return normalize_windows_path(cleaned)


def _find_project(
    projects: list[Any],
    *,
    name: str | None = None,
    workspace: str | None = None,
) -> dict[str, Any] | None:
    if name:
        target = name.strip().lower()
        for entry in projects:
            if isinstance(entry, dict) and str(entry.get("name") or "").strip().lower() == target:
                return entry
    if workspace:
        ws_expanded = str(expand_path(workspace)) if not workspace.startswith(("\\\\", "//")) else workspace
        for entry in projects:
            if not isinstance(entry, dict):
                continue
            roots = [str(r).strip() for r in (entry.get("matchWorkspaces") or []) if isinstance(r, str) and r.strip()]
            expanded_roots = [
                r.replace("/", "\\").rstrip("\\") if r.startswith(("\\\\", "//")) else str(expand_path(r))
                for r in roots
            ]
            if expanded_roots and is_path_within_workspace(ws_expanded, ws_expanded, expanded_roots):
                return entry
    return None


def _ensure_list(section: dict[str, Any], key: str) -> list[str]:
    val = section.get(key)
    if not isinstance(val, list):
        val = []
    cleaned = [str(x).strip() for x in val if isinstance(x, str) and x.strip()]
    section[key] = cleaned
    return cleaned


def _add_unique(items: list[str], new_items: list[str], key_fn) -> list[str]:
    existing_keys = {key_fn(x) for x in items}
    added: list[str] = []
    for item in new_items:
        k = key_fn(item)
        if k not in existing_keys:
            items.append(item)
            existing_keys.add(k)
            added.append(item)
    return added


def _remove_matching(items: list[str], to_remove: list[str], key_fn) -> list[str]:
    remove_keys = {key_fn(x) for x in to_remove}
    kept: list[str] = []
    removed: list[str] = []
    for item in items:
        if key_fn(item) in remove_keys:
            removed.append(item)
        else:
            kept.append(item)
    items[:] = kept
    return removed


def cmd_show(args: argparse.Namespace) -> int:
    path = _resolve_policy_path(args.path)
    data = _load_policy_doc(path, allow_missing=False)
    if args.project or args.workspace:
        projects = data.get("projects") if isinstance(data.get("projects"), list) else []
        match = _find_project(projects, name=args.project or None, workspace=args.workspace or None)
        out = {"path": str(path), "project": match}
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0
    if args.json:
        print(json.dumps({"path": str(path), "policy": data}, indent=2, ensure_ascii=False))
    else:
        print(f"Policy file: {path}")
        print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    path = _resolve_policy_path(args.path)

    # Validate inputs before touching disk
    add_urls: list[str] = []
    for raw_url in args.add_url:
        norm = normalize_policy_url(raw_url)
        if not norm:
            raise ValueError(f"Invalid http(s) URL for --add-url: {raw_url!r}")
        add_urls.append(norm)

    remove_urls: list[str] = []
    for raw_url in args.remove_url:
        norm = normalize_policy_url(raw_url)
        if not norm:
            raise ValueError(f"Invalid http(s) URL for --remove-url: {raw_url!r}")
        remove_urls.append(norm)

    add_programs: list[str] = []
    for raw_prog in args.add_program:
        norm = normalize_policy_program(raw_prog)
        if not norm:
            raise ValueError(f"Invalid program name/path for --add-program: {raw_prog!r}")
        add_programs.append(norm)

    remove_programs: list[str] = []
    for raw_prog in args.remove_program:
        norm = normalize_policy_program(raw_prog)
        if not norm:
            raise ValueError(f"Invalid program name/path for --remove-program: {raw_prog!r}")
        remove_programs.append(norm)

    add_forge_clis: list[str] = []
    for raw_cli in args.add_forge_cli:
        cleaned = raw_cli.strip().lower()
        if cleaned not in _VALID_FORGE_CLIS:
            raise ValueError(
                f"Unsupported forge CLI {raw_cli!r}; valid values: {sorted(_VALID_FORGE_CLIS)}"
            )
        add_forge_clis.append(cleaned)

    add_ssh_hosts = [h.strip().lower() for h in args.add_ssh_host if h.strip()]
    remove_ssh_hosts = [h.strip().lower() for h in args.remove_ssh_host if h.strip()]
    remove_forge_clis = [c.strip().lower() for c in args.remove_forge_cli if c.strip()]

    # Security boundary: refuse to write a policy file inside any matchWorkspaces root
    check_roots = [r.strip() for r in (args.match_workspace + ([args.workspace] if args.workspace else [])) if r.strip()]
    resolved_policy = str(path.resolve())
    for root in check_roots:
        expanded_root = root.replace("/", "\\").rstrip("\\") if root.startswith(("\\\\", "//")) else str(expand_path(root))
        if is_path_within_workspace(resolved_policy, expanded_root, [expanded_root]):
            raise ValueError(
                f"Refused: policy file {path} is inside writable workspace {expanded_root}"
            )

    if not args.defaults and not args.project and not args.workspace:
        raise ValueError("Specify --defaults, --project <name>, or --workspace <path>")

    existed = path.is_file()
    data = _load_policy_doc(path, allow_missing=True)
    if not isinstance(data.get("defaults"), dict):
        data["defaults"] = _default_policy_doc()["defaults"]
    if not isinstance(data.get("projects"), list):
        data["projects"] = []

    if args.defaults:
        target = data["defaults"]
        target_label = "defaults"
    else:
        projects: list[Any] = data["projects"]
        target = _find_project(projects, name=args.project or None, workspace=args.workspace or None)
        if target is None:
            match_ws = list(args.match_workspace)
            if args.workspace and args.workspace not in match_ws:
                match_ws.append(args.workspace)
            if not match_ws:
                raise ValueError(
                    "Project not found. Provide --match-workspace <path> (or --workspace <path>) to create it."
                )
            proj_name = (args.project or Path(match_ws[0]).name or "project").strip()
            target = {
                "name": proj_name,
                "matchWorkspaces": match_ws,
            }
            projects.append(target)
        target_label = str(target.get("name") or "project")

        if args.match_workspace:
            _add_unique(_ensure_list(target, "matchWorkspaces"), args.match_workspace, _norm_key_path)

    if args.add_workspace:
        _add_unique(_ensure_list(target, "extraWorkspaces"), args.add_workspace, _norm_key_path)
    if args.remove_workspace:
        _remove_matching(_ensure_list(target, "extraWorkspaces"), args.remove_workspace, _norm_key_path)

    if args.add_write_path:
        _add_unique(_ensure_list(target, "allowedWritePaths"), args.add_write_path, _norm_key_path)
    if args.remove_write_path:
        _remove_matching(_ensure_list(target, "allowedWritePaths"), args.remove_write_path, _norm_key_path)

    if add_ssh_hosts:
        _add_unique(_ensure_list(target, "allowedSshReadHosts"), add_ssh_hosts, lambda s: s.lower())
    if remove_ssh_hosts:
        _remove_matching(_ensure_list(target, "allowedSshReadHosts"), remove_ssh_hosts, lambda s: s.lower())

    if add_forge_clis:
        _add_unique(_ensure_list(target, "allowedForgeCliWrites"), add_forge_clis, lambda s: s.lower())
    if remove_forge_clis:
        _remove_matching(_ensure_list(target, "allowedForgeCliWrites"), remove_forge_clis, lambda s: s.lower())

    if add_urls:
        _add_unique(_ensure_list(target, "allowedUrls"), add_urls, lambda s: s)
    if remove_urls:
        _remove_matching(_ensure_list(target, "allowedUrls"), remove_urls, lambda s: s)

    if add_programs:
        _add_unique(_ensure_list(target, "allowedPrograms"), add_programs, lambda s: s.lower())
    if remove_programs:
        _remove_matching(_ensure_list(target, "allowedPrograms"), remove_programs, lambda s: s.lower())

    if args.note is not None:
        target["policyNotes"] = args.note.strip()
    elif args.append_note:
        addition = args.append_note.strip()
        existing = str(target.get("policyNotes") or "").strip()
        if addition and addition not in existing:
            target["policyNotes"] = f"{existing} {addition}".strip() if existing else addition

    backup_path = _backup_file(path) if (existed and not args.no_backup) else None
    _write_json_atomic(path, data)

    if args.json:
        print(
            json.dumps(
                {
                    "path": str(path),
                    "backup": str(backup_path) if backup_path else None,
                    "target": target_label,
                    "entry": target,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        if backup_path:
            print(f"Backup: {backup_path}")
        print(f"Updated '{target_label}' in {path}:")
        print(json.dumps(target, indent=2, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect and safely update agy_guardian_policies.json."
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_show = sub.add_parser("show", help="Show the policy file or a matching project entry.")
    p_show.add_argument("--project", default="", help="Filter by project name")
    p_show.add_argument("--workspace", default="", help="Filter by matching workspace path")
    p_show.add_argument("--path", default="", help="Override policy file path")
    p_show.add_argument("--json", action="store_true", help="Output JSON")
    p_show.set_defaults(func=cmd_show)

    p_upd = sub.add_parser("update", help="Create or update defaults or a project policy entry.")
    p_upd.add_argument("--defaults", action="store_true", help="Update the global 'defaults' section")
    p_upd.add_argument("--project", default="", help="Project name to update or create")
    p_upd.add_argument("--workspace", default="", help="Workspace path used to locate (or create) a project")
    p_upd.add_argument("--match-workspace", action="append", default=[], help="Add to matchWorkspaces")
    p_upd.add_argument("--add-workspace", action="append", default=[], help="Add to extraWorkspaces")
    p_upd.add_argument("--remove-workspace", action="append", default=[], help="Remove from extraWorkspaces")
    p_upd.add_argument("--add-write-path", action="append", default=[], help="Add to allowedWritePaths")
    p_upd.add_argument("--remove-write-path", action="append", default=[], help="Remove from allowedWritePaths")
    p_upd.add_argument("--add-ssh-host", action="append", default=[], help="Add to allowedSshReadHosts")
    p_upd.add_argument("--remove-ssh-host", action="append", default=[], help="Remove from allowedSshReadHosts")
    p_upd.add_argument("--add-forge-cli", action="append", default=[], help="Add to allowedForgeCliWrites (glab/gh)")
    p_upd.add_argument("--remove-forge-cli", action="append", default=[], help="Remove from allowedForgeCliWrites")
    p_upd.add_argument("--add-url", action="append", default=[], help="Add http(s) URL prefix to allowedUrls")
    p_upd.add_argument("--remove-url", action="append", default=[], help="Remove URL from allowedUrls")
    p_upd.add_argument("--add-program", action="append", default=[], help="Add executable/path/glob to allowedPrograms")
    p_upd.add_argument("--remove-program", action="append", default=[], help="Remove program from allowedPrograms")
    p_upd.add_argument("--note", default=None, help="Replace policyNotes with this text")
    p_upd.add_argument("--append-note", default="", help="Append text to policyNotes")
    p_upd.add_argument("--path", default="", help="Override policy file path")
    p_upd.add_argument("--no-backup", action="store_true", help="Skip creating a .bak backup")
    p_upd.add_argument("--json", action="store_true", help="Output JSON")
    p_upd.set_defaults(func=cmd_update)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
