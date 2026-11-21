# AGENTS.md — `agy-guardian`

Workspace instructions for coding agents working in this repository.

## Project Purpose

`agy-guardian` is a local, low-latency `PreToolUse` command approval guardian for Google Antigravity CLI (`agy`), targeting Windows 10 (PowerShell 5.1 / Git Bash) while remaining portable across machines.

3-layer architecture:
1. **Layer 1 — Deterministic Hard-Deny (0 ms):** Block catastrophic/obfuscated/exfiltration commands immediately after stripping command wrappers and decomposing compound chains.
2. **Layer 2 — Deterministic Fast-Allow (0 ms):** Allow trivial, cleanly decomposed read-only workspace commands; never fast-allow opaque constructs (`$(...)`, backticks, `-EncodedCommand`, `iex`, redirections, script blocks, unknown wrappers).
3. **Layer 3 — Local Decision Model Classifier:** Primary backend uses `llama-server`'s native `POST /v1/systemone` endpoint with open-weight System One Decision Models (`Cloudflare_clef-flash-Q5_K_M`, `multi` schema, `output_tokens = 0`). `POST /v1/chat/completions` (1-token GBNF) is retained as an optional fallback (`AGY_GUARDIAN_BACKEND=completion|auto` or `AGY_GUARDIAN_FALLBACK_ENDPOINT`) and benchmark baseline.

## Safety Invariants (Non-Negotiable)

- **Always fail closed to `"ask"`:** Any exception, HTTP timeout, connection error, unexpected JSON schema, sub-threshold probability, or failed audit write (when `AGY_GUARDIAN_AUDIT_FAIL_CLOSED=true` on `"allow"`) MUST return `"ask"` — never `"allow"`.
- **Zero False-Allows is the primary metric:** When tuning rules, schemas, prompts, or thresholds, prioritize `0%` false-allows on `ask`, `deny`, and `adversarial_injection` test cases above safe-command recall.
- **No silent weakening:** Any change to parser logic, Layer 1/2 rules, or Layer 3 schemas/thresholds must be validated against the unit test suite (`python -m unittest discover -s tests -v`) and `bench/cases.json`.

## Engineering Standards

- **Runtime dependencies:** Keep hook and benchmark runtime code on **Python 3.12+ standard library only** (zero third-party runtime dependencies) to keep synchronous `PreToolUse` hook cold-start latency minimal.
- **Python environment (`uv`):** If third-party Python dev tools (e.g., `pytest`, `ruff`) are introduced, use `uv` to initialize and manage a `.venv` virtual environment pinned to Python 3.12 (`uv venv --python 3.12 .venv` / `uv sync`).
- **Antigravity Hook Contract (`PreToolUse`):**
  - Stdin: camelCase JSON (`conversationId`, `workspacePaths`, `cwd`, `lastUserInput`, `hookEventName`, `toolCall.name`, `toolCall.args.CommandLine`, `stepIdx`).
  - Stdout: JSON with `decision` (`"auto_approve"` for allowed commands, `"ask"`, `"force_ask"`, or `"deny"`) and optional `reason`.
- **Windows-first shell awareness:** Account for PowerShell 5.1 (`Remove-Item`, `ri`, `iwr | iex`, backtick obfuscation, `-EncodedCommand`, `;`, `|`, `cmd /c`, `powershell -c`) alongside Git Bash (`&&`, `||`, `rm -rf`, `curl | bash`).

## Repository & Privacy Hygiene

- **Forge-agnostic:** Do not hardcode GitHub- or GitLab-specific URLs, badges, or CI templates unless explicitly requested.
- **Local settings pattern (`.env.example` + `.env`):**
  - Keep all machine-specific settings (`AGY_GUARDIAN_LLAMA_SERVER`, model directories, host/port, thresholds, audit path) in a gitignored `.env` file copied from the tracked `.env.example`.
  - Follow standard precedence: `CLI flags > OS env vars > .env > code defaults`, using pure-stdlib loading (`agy_guardian/config.py`, zero third-party deps).
  - Never commit personal usernames, hostnames, local drive paths, API keys, or raw server/JSONL logs.
  - Keep local notes, custom model manifests, PID/server logs, and raw benchmark artifacts (`*.jsonl`, `*.server.log`) under `.local/` (gitignored).
  - Curated, privacy-clean benchmark reports and sanitized summary JSONs belong in `bench/RESULTS.md` and `bench/results/`.
  - Use placeholder paths (e.g. `C:\Users\dev\workspace\my-app`) in tracked test cases and `${AGY_GUARDIAN_*_DIR}` placeholders in `bench/models.example.json`.
- **Secrets:** Never print, echo, or log environment secrets such as `HF_TOKEN`.

## Repository Layout & Workflow

- `.env.example` — Tracked template for machine-local settings (copy to gitignored `.env`).
- `SETUP-AGENTS.md` — Interactive AI-guided setup & per-project policy configuration runbook (keep separate from `AGENTS.md` to avoid bloating normal coding sessions).
  - **Permissions review / audit / cleanup:** Whenever the user asks for a permissions review, audit, or cleanup of `settings.json`, read `SETUP-AGENTS.md` (**Step 6 — Optional Maintenance: `settings.json` Permissions Cleanup**) first and follow its scan-scope and tiered wildcard workflow.
- `agy_guardian/` — Production stdlib-only 3-layer `PreToolUse` hook package:
  - `config.py` — Pure-stdlib `.env` loader, `${VAR}` expander, and `GuardianConfig`.
  - `policy.py` — Per-project policy loader (`~/.gemini/config/agy_guardian_policies.json`), fail-closed and strictly refusing in-workspace policy files.
  - `shell_parser.py` — PowerShell/Bash lexical splitter, backtick normalizer, wrapper stripper, opaque detector, and Windows/WSL UNC workspace path containment checker.
  - `rules.py` — Layer 1 deterministic hard-deny (including SSH remote commands) and Layer 2 deterministic fast-allow (including policy-scoped read-only SSH) evaluators.
  - `classifiers.py` — Pure-stdlib HTTP clients for `POST /v1/systemone` and `POST /v1/chat/completions`, plus fail-closed `apply_thresholds()`.
  - `pipeline.py` — 3-layer evaluation orchestrator with per-project policy resolution and optional `/v1/chat/completions` fallback.
  - `audit.py` — Fail-closed JSONL audit logger.
  - `cli.py` & `__main__.py` — Antigravity `PreToolUse` stdin/stdout entrypoint and diagnostic CLI (`--check`, `--policy`, `--health`).
- `scripts/` — Operational scripts:
  - `agy_guardian_hook.py` — Direct hook launcher (zero `PYTHONPATH` setup needed under `cmd /c`).
  - `start_llama_server.ps1` & `start_llama_server.sh` — Idempotent `llama-server` startup/status/stop scripts for PowerShell and Git Bash (`--ctx-size 2048 -b 2048 -ub 2048 -np 1`, shared `.local/llama-server.pid`).
  - `install_hooks.ps1` — Safe JSON merger for `%USERPROFILE%\.gemini\config\hooks.json`.
- `config/` — Tracked portable templates (`hooks.example.json`, `policies.example.json`).
- `tests/` — Stdlib `unittest` suite covering parser, all 86 `bench/cases.json` cases, mocked Layer 3/fallbacks, and hook CLI/audit contract.
- `bench/` — Benchmark suite (`cases.json`, `run_bench.py`, `RESULTS.md`, `results/`, and compatibility shims `env.py`/`classifiers.py`).

Run unit tests and benchmarks locally:
```powershell
python -m unittest discover -s tests -v
python bench/run_bench.py
```
