#!/usr/bin/env python3
"""Safe, auditable CLI helper for inspecting and generalizing Antigravity settings.json permissions.

Pure Python 3.12+ standard library. Every mutating subcommand requires --expected to match the
exact current entry at --index, writes a timestamped .bak backup, and saves JSON atomically.
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

DEFAULT_SETTINGS_PATH = Path.home() / ".gemini" / "antigravity-cli" / "settings.json"


def _resolve_path(raw: str | None) -> Path:
    if raw:
        return Path(os.path.expandvars(raw)).expanduser()
    return DEFAULT_SETTINGS_PATH


def _load_settings(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Settings file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError(f"Malformed settings file (root must be a JSON object): {path}")
    return data


def _get_allow_list(data: dict[str, Any]) -> list[str]:
    perms = data.get("permissions")
    if perms is None:
        return []
    if not isinstance(perms, dict):
        raise ValueError("Malformed settings file ('permissions' must be a JSON object)")
    allow = perms.get("allow")
    if allow is None:
        return []
    if not isinstance(allow, list) or not all(isinstance(x, str) for x in allow):
        raise ValueError("Malformed settings file ('permissions.allow' must be a list of strings)")
    return allow


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


def _resolve_index(allow: list[str], index: int) -> int:
    if not allow:
        raise IndexError("permissions.allow is empty")
    resolved = index if index >= 0 else len(allow) + index
    if resolved < 0 or resolved >= len(allow):
        raise IndexError(f"Index {index} out of range for permissions.allow (length {len(allow)})")
    return resolved


def cmd_show(args: argparse.Namespace) -> int:
    path = _resolve_path(args.path)
    data = _load_settings(path)
    allow = _get_allow_list(data)
    total = len(allow)

    if args.all or args.last <= 0:
        start = 0
    else:
        start = max(0, total - args.last)

    entries = [{"index": idx, "value": allow[idx]} for idx in range(start, total)]
    if args.json:
        print(
            json.dumps(
                {"path": str(path), "total": total, "entries": entries},
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    print(f"File: {path} (total permissions.allow entries: {total})")
    if not entries:
        print("  (none)")
        return 0
    for item in entries:
        print(f"  [{item['index']}] {item['value']}")
    return 0


def cmd_replace(args: argparse.Namespace) -> int:
    path = _resolve_path(args.path)
    new_val = args.value.strip()
    if not new_val:
        raise ValueError("--value must not be empty")

    data = _load_settings(path)
    allow = _get_allow_list(data)
    idx = _resolve_index(allow, args.index)
    current = allow[idx]
    if current != args.expected:
        raise ValueError(
            f"Safety guard failed: entry [{idx}] does not match --expected.\n"
            f"  Current : {current!r}\n"
            f"  Expected: {args.expected!r}"
        )

    backup_path = None if args.no_backup else _backup_file(path)
    already_exists = any(i != idx and v == new_val for i, v in enumerate(allow))
    if already_exists:
        del allow[idx]
        action = "deduplicated"
    else:
        allow[idx] = new_val
        action = "replaced"

    data.setdefault("permissions", {})["allow"] = allow
    _write_json_atomic(path, data)

    if args.json:
        print(
            json.dumps(
                {
                    "action": action,
                    "path": str(path),
                    "backup": str(backup_path) if backup_path else None,
                    "index": idx,
                    "old": current,
                    "new": new_val,
                    "total": len(allow),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        if backup_path:
            print(f"Backup: {backup_path}")
        if action == "deduplicated":
            print(f"Removed duplicate entry [{idx}] (rule already present in permissions.allow):")
            print(f"  - {current}")
            print(f"  = {new_val}")
        else:
            print(f"Replaced entry [{idx}]:")
            print(f"  - {current}")
            print(f"  + {new_val}")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    path = _resolve_path(args.path)
    data = _load_settings(path)
    allow = _get_allow_list(data)
    idx = _resolve_index(allow, args.index)
    current = allow[idx]
    if current != args.expected:
        raise ValueError(
            f"Safety guard failed: entry [{idx}] does not match --expected.\n"
            f"  Current : {current!r}\n"
            f"  Expected: {args.expected!r}"
        )

    backup_path = None if args.no_backup else _backup_file(path)
    del allow[idx]
    data.setdefault("permissions", {})["allow"] = allow
    _write_json_atomic(path, data)

    if args.json:
        print(
            json.dumps(
                {
                    "action": "removed",
                    "path": str(path),
                    "backup": str(backup_path) if backup_path else None,
                    "index": idx,
                    "removed": current,
                    "total": len(allow),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        if backup_path:
            print(f"Backup: {backup_path}")
        print(f"Removed entry [{idx}]:")
        print(f"  - {current}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect and safely generalize Antigravity settings.json permissions.allow entries."
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_show = sub.add_parser("show", help="Show recent or all permissions.allow entries.")
    p_show.add_argument("--last", type=int, default=5, help="Show last N entries (default: 5)")
    p_show.add_argument("--all", action="store_true", help="Show all entries")
    p_show.add_argument("--path", default="", help="Override settings.json path")
    p_show.add_argument("--json", action="store_true", help="Output JSON")
    p_show.set_defaults(func=cmd_show)

    p_rep = sub.add_parser("replace", help="Replace a specific permissions.allow entry.")
    p_rep.add_argument("--index", type=int, required=True, help="Entry index (supports negative, e.g. -1)")
    p_rep.add_argument("--expected", required=True, help="Exact current value required to match before replacing")
    p_rep.add_argument("--value", required=True, help="New generalized permission rule")
    p_rep.add_argument("--path", default="", help="Override settings.json path")
    p_rep.add_argument("--no-backup", action="store_true", help="Skip creating a .bak backup")
    p_rep.add_argument("--json", action="store_true", help="Output JSON")
    p_rep.set_defaults(func=cmd_replace)

    p_rem = sub.add_parser("remove", help="Remove a specific permissions.allow entry.")
    p_rem.add_argument("--index", type=int, required=True, help="Entry index (supports negative, e.g. -1)")
    p_rem.add_argument("--expected", required=True, help="Exact current value required to match before removing")
    p_rem.add_argument("--path", default="", help="Override settings.json path")
    p_rem.add_argument("--no-backup", action="store_true", help="Skip creating a .bak backup")
    p_rem.add_argument("--json", action="store_true", help="Output JSON")
    p_rem.set_defaults(func=cmd_remove)

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
