# AGENTS.md — `agy-guardian`

Workspace instructions for coding agents working in this repository.

## Project Purpose

`agy-guardian` is a local, low-latency `PreToolUse` command approval guardian for Google Antigravity CLI (`agy`), targeting Windows 10 (PowerShell 5.1 / Git Bash) while remaining portable across machines.

Target 3-layer architecture:
1. **Layer 1 — Deterministic Hard-Deny (0 ms):** Block catastrophic/obfuscated commands immediately after stripping command wrappers and decomposing compound chains.
2. **Layer 2 — Deterministic Fast-Allow (0 ms):** Allow trivial, cleanly decomposed read-only commands; never fast-allow opaque constructs (`$(...)`, backticks, `-EncodedCommand`, `iex`, unknown wrappers).
3. **Layer 3 — Local Decision Model Classifier:** Primary backend uses `llama-server`'s native `POST /v1/systemone` endpoint with open-weight System One Decision Models (`output_tokens = 0`, calibrated probabilities over typed `choice` + `noul` schemas). `POST /completion` (1-token GBNF) is retained only as a fallback/benchmark control baseline.

## Safety Invariants (Non-Negotiable)

- **Always fail closed to `"ask"`:** Any exception, HTTP timeout, connection error, unexpected JSON schema, or sub-threshold probability MUST return `"ask"` — never `"allow"`.
- **Zero False-Allows is the primary metric:** When tuning rules, schemas, prompts, or thresholds, prioritize `0%` false-allows on `ask`, `deny`, and `adversarial_injection` test cases above safe-command recall.
- **No silent weakening:** Any change to parser logic, Layer 1/2 rules, or Layer 3 schemas/thresholds must be validated against the test/benchmark suite (`bench/cases.json` and unit tests once added).

## Engineering Standards

- **Runtime dependencies:** Keep hook and benchmark runtime code on **Python 3.12+ standard library only** (zero third-party runtime dependencies) to keep synchronous `PreToolUse` hook cold-start latency minimal.
- **Python environment (`uv`):** If third-party Python libraries or dev tools (e.g., `pytest`, `ruff`) are introduced, use `uv` to initialize and manage a `.venv` virtual environment pinned to Python 3.12 (`uv venv --python 3.12 .venv` / `uv sync`).
- **Antigravity Hook Contract (`PreToolUse`):**
  - Stdin: camelCase JSON (`conversationId`, `workspacePaths`, `cwd`, `lastUserInput`, `hookEventName`, `toolCall.name`, `toolCall.args.CommandLine`).
  - Stdout: JSON with `decision` (`"allow"` | `"ask"` | `"force_ask"` | `"deny"`) and optional `reason`.
- **Windows-first shell awareness:** Account for PowerShell 5.1 (`Remove-Item`, `iwr | iex`, `-EncodedCommand`, `;`, `|`, `cmd /c`, `powershell -c`) alongside Git Bash (`&&`, `||`, `rm -rf`, `curl | bash`).

## Repository & Privacy Hygiene

- **Forge-agnostic:** Do not hardcode GitHub- or GitLab-specific URLs, badges, or CI templates unless explicitly requested.
- **Local settings pattern (`.env.example` + `.env`):**
  - Keep all machine-specific settings (`AGY_GUARDIAN_LLAMA_SERVER`, model directories, host/port, thresholds) in a gitignored `.env` file copied from the tracked `.env.example`.
  - Follow standard precedence: `CLI flags > OS env vars > .env > code defaults`, using pure-stdlib loading (`bench/env.py`, zero third-party deps).
  - Never commit personal usernames, hostnames, local drive paths, API keys, or raw server/JSONL logs.
  - Keep local notes, custom model manifests, and raw benchmark artifacts (`*.jsonl`, `*.server.log`) under `.local/` (gitignored).
  - Curated, privacy-clean benchmark reports and sanitized summary JSONs belong in `bench/RESULTS.md` and `bench/results/`.
  - Use placeholder paths (e.g. `C:\Users\dev\workspace\my-app`) in tracked test cases and `${AGY_GUARDIAN_*_DIR}` placeholders in `bench/models.example.json`.
- **Secrets:** Never print, echo, or log environment secrets such as `HF_TOKEN`.

## Current Layout & Workflow

- `.env.example` — Tracked template for machine-local settings (copy to gitignored `.env`).
- `bench/env.py` — Pure-stdlib `.env` loader and `${VAR}` path expander.
- `bench/cases.json` — Labeled CLI safety test cases across `safe_read`, `safe_dev`, `hard_safe`, `ask_risky`, `hard_ask`, `deny_catastrophic`, `hard_deny`, `adversarial_injection`, and `hard_adversarial`.
- `bench/classifiers.py` — Pure-stdlib HTTP clients for `POST /v1/systemone` and `POST /v1/chat/completions`, plus fail-closed `apply_thresholds()`.
- `bench/run_bench.py` — Automated runner launching `llama-server`, measuring VRAM/latency/calibration, and writing raw runs to `.local/benchmark_results/`.
- `bench/models.example.json` — Portable template manifest using `${AGY_GUARDIAN_*_DIR}` placeholders (copy to `.local/models.json`).
- `bench/RESULTS.md` & `bench/results/` — Tracked, privacy-clean benchmark reports and sanitized summary JSONs.

Run benchmarks locally (reading `AGY_GUARDIAN_*` from `.env`):
```powershell
python bench/run_bench.py
```
