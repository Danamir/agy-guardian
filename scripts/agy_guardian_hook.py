#!/usr/bin/env python3
"""Direct entrypoint for Antigravity PreToolUse hooks (no PYTHONPATH required)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


def _run() -> int:
    try:
        from agy_guardian.cli import main

        return main()
    except Exception as exc:
        sys.stdout.write(
            json.dumps(
                {
                    "decision": "ask",
                    "reason": f"agy-guardian bootstrap error ({type(exc).__name__}) - failing closed to ask",
                },
                ensure_ascii=True,
            )
            + "\n"
        )
        sys.stdout.flush()
        return 0


if __name__ == "__main__":
    raise SystemExit(_run())
