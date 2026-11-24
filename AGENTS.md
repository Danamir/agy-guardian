# AGENTS.md — `agy-guardian`

Workspace instructions for coding agents working in this repository.

## Project Purpose

`agy-guardian` is a low-latency `PreToolUse` command approval guardian for Google Antigravity CLI (`agy`), targeting Windows 10 (PowerShell 5.1 / Git Bash) while remaining portable across machines.

It aims to emulate the command-approval side of Antigravity's Auto mode where that mode is unavailable: Windows 10 and Windows 11 builds without the required sandbox (24H2 or later with the August 2026 update). It is **not** a sandbox and does not gate file edits. It is designed for everyday use with an aligned agent (accidental overreach); see `SECURITY.md` for guarantees and non-goals.

## Architecture

Evaluation order is L1 → L2 → L3; the first conclusive layer wins.

### Layer 1 — Deterministic Hard-Deny (0 ms)

- **Normalizes first:** splits compound chains (`&&`, `||`, `;`, `|`, newlines), strips comments and shell wrappers (`cmd /c`, `powershell -c`, `pwsh -c`, `env`, `timeout`), and normalizes PowerShell backticks and, inside `cmd /c`, caret (`^`) escapes.
- **Blocks:** catastrophic deletes, disk wipes, system registry deletion, remote pipe-to-shell, `-EncodedCommand`, LOLBin downloads, obfuscated inline exec, and credential exfiltration, including inside SSH remote commands.

### Layer 2 — Deterministic Fast-Allow (0 ms)

- **Allows:** trivial, cleanly decomposed read-only commands (`git status/diff/log/show`, `rg`, `fd`, `Get-ChildItem`, `Get-Content` on non-sensitive files, read-only `glab`/`gh` queries and GET-only `api`, etc.) with all paths inside the effective workspaces, plus policy-scoped read-only SSH (`allowedSshReadHosts`) and policy-scoped non-MR/non-destructive `glab`/`gh` writes (`allowedForgeCliWrites`).
- **Effective workspaces:** `workspacePaths`, policy `extraWorkspaces` and `allowedWritePaths`, `AGY_GUARDIAN_EXTRA_WORKSPACES`, and the current session's brain directory (unless `AGY_GUARDIAN_ALLOW_SESSION_BRAIN=false`).
- **Never fast-allows opaque constructs:** `$(...)`, `$vars`, backticks, `-EncodedCommand`, `iex`, redirections, script blocks, or unknown wrappers.

### Layer 3 — Decision Model Classifier

| Backend (`AGY_GUARDIAN_BACKEND`) | Model | Endpoint | Notes |
| :--- | :--- | :--- | :--- |
| `systemone` (default) | Local, open-weight (`Cloudflare_clef-flash-Q5_K_M`) | `llama-server` `POST /v1/systemone` | `multi` schema, `output_tokens = 0` |
| `gemini_decision_paid` | Remote, closed (`gemini-decision-1`) | `POST /v1beta/decisions` | Reads only `AGY_GUARDIAN_GEMINI_PAID_API_KEY` |
| `gemini_decision_free` | Remote, closed (`gemini-decision-1`) | `POST /v1beta/decisions` | Explicit opt-in; reads only `AGY_GUARDIAN_GEMINI_FREE_API_KEY` |
| `completion` | Local generative LLM | `POST /v1/chat/completions` | 1-token GBNF; legacy fallback and benchmark baseline (1 false-allow in the published run) |
| `auto` | Local | `/v1/systemone`, then `/v1/chat/completions` | Same-endpoint fallback only on HTTP 404/405/501 |

- **Bare `gemini_decision`:** accepted only with an explicit `AGY_GUARDIAN_GEMINI_TIER=paid|free`.
- **Fallback:** runs only when the primary returns an **error**, never to override a valid `ask`/`deny`. Configure with `AGY_GUARDIAN_FALLBACK_BACKEND` (default `none`) or the legacy `AGY_GUARDIAN_FALLBACK_ENDPOINT`.
- **Context sent:** OS, `workspacePaths`, `cwd`, `lastUserInput`, and the unredacted `commandLine`, plus, when available, `precedingAssistantMessage` (short replies only), redacted `recentCommands`, and `projectPolicy`. Update the README privacy note when this changes.

### Layer 3 Decision Policy (`apply_thresholds()`)

1. **deny** when `P(deny)` or `injection_or_obfuscation` `>= AGY_GUARDIAN_DENY_THRESHOLD` (`0.85`).
2. **allow** when `P(allow) >= AGY_GUARDIAN_ALLOW_THRESHOLD` (`0.85`) **and** `destructive`, `outside_workspace`, and `injection_or_obfuscation` are all `<= AGY_GUARDIAN_RISK_MAX_PROB` (`0.25`).
3. **ask** otherwise.

The risk checks exist only in the `multi` schema. **Do not go below `0.85` with `single`:** `clef-flash-q5_k_m__single` starts false-allowing at `0.80`. Published sweeps are in `bench/RESULTS.md` (86-case run; `bench/cases.json` has since grown, so state which case count a result covers).

### `llama-server` Requirements

Decision Models need native `POST /v1/systemone` support (`llama.cpp` Oct 2026+ / PR #29818) and `--ctx-size 2048 -b 2048 -ub 2048 -np 1`. The default batch size of 512 causes `HTTP 500` on payloads over 512 tokens.

## Safety Invariants (Non-Negotiable)

- **Always fail closed to `"ask"`:** Any exception, HTTP timeout, connection error, unexpected JSON schema, sub-threshold probability, or failed audit write (when `AGY_GUARDIAN_AUDIT_FAIL_CLOSED=true` on `"allow"`) MUST return `"ask"` — never `"allow"`.
- **Zero False-Allows is the primary metric:** When tuning rules, schemas, prompts, or thresholds, prioritize `0%` false-allows on `ask`, `deny`, and `adversarial_injection` test cases above safe-command recall.
- **No silent weakening:** Any change to parser logic, Layer 1/2 rules, or Layer 3 schemas/thresholds must be validated against the unit test suite (`python -m unittest discover -s tests -v`) and `bench/cases.json`.
- **Layer 1 is non-overridable by project policy:** Policies may extend workspace scope, SSH read hosts, and Layer 3 context; they must never disable a Layer 1 rule. Policy files inside `workspacePaths` must be refused.
- **Remote use is explicit:** Never send a command to a remote backend unless it is configured as the primary or fallback. Each tier reads only its own key, never the other tier's key or a generic one such as `GEMINI_API_KEY`.

## Engineering Standards

- **Runtime dependencies:** Keep hook and benchmark runtime code on **Python 3.12+ standard library only** (zero third-party runtime dependencies) to keep synchronous `PreToolUse` hook cold-start latency minimal.
- **Python environment (`uv`):** If third-party Python dev tools (e.g., `pytest`, `ruff`) are introduced, use `uv` to initialize and manage a `.venv` virtual environment pinned to Python 3.12 (`uv venv --python 3.12 .venv` / `uv sync`).
- **Antigravity Hook Contract (`PreToolUse`):**
  - Stdin: camelCase JSON (`conversationId`, `workspacePaths`, `cwd`, `lastUserInput`, `hookEventName`, `toolCall.name`, `toolCall.args.CommandLine`, `stepIdx`).
  - Only `run_command` is gated; any other tool name returns `"ask"`.
  - Stdout: 7-bit ASCII JSON with `decision` (`"auto_approve"` for allowed commands, `"ask"`, `"force_ask"`, or `"deny"`) and optional `reason`.
- **Windows-first shell awareness:** Account for PowerShell 5.1 (`Remove-Item`, `ri`, `iwr | iex`, backtick obfuscation, `-EncodedCommand`, `;`, `|`, `cmd /c`, `powershell -c`) alongside Git Bash (`&&`, `||`, `rm -rf`, `curl | bash`).

## Documentation Responsibilities

- `README.md` — For users: plain language, minimal inline code, no parser or schema internals. Always present the open-weight local and closed remote models as separate options.
- `AGENTS.md` — For contributors and coding agents: architecture, invariants, and standards.
- `SETUP-AGENTS.md` — Guided installation, policy interview, and permissions cleanup.
- `SECURITY.md` — Guarantees, limitations, and vulnerability reporting.
- `bench/RESULTS.md` — Detailed measurements; `README.md` quotes only headline figures, with the case count.

## Repository & Privacy Hygiene

- **Forge-agnostic:** Do not hardcode GitHub- or GitLab-specific URLs, badges, or CI templates unless explicitly requested.
- **Local settings pattern (`.env.example` + `.env`):**
  - Keep all machine-specific settings (`AGY_GUARDIAN_LLAMA_SERVER`, model directories, host/port, thresholds, audit path) in a gitignored `.env` file copied from the tracked `.env.example`.
  - **Keep `.env.example` complete:** it must list every `AGY_GUARDIAN_*` setting read by the code, scripts, or benchmarks, with a short comment and its default (or an empty value). Add, rename, or remove entries in the same change as the code.
  - Follow standard precedence: `CLI flags > OS env vars > .env > code defaults`, using pure-stdlib loading (`agy_guardian/config.py`, zero third-party deps).
  - Never commit personal usernames, hostnames, local drive paths, API keys, or raw server/JSONL logs.
  - Keep local notes, custom model manifests, PID/server logs, and raw benchmark artifacts (`*.jsonl`, `*.server.log`) under `.local/` (gitignored).
  - Curated, privacy-clean benchmark reports and sanitized summary JSONs belong in `bench/RESULTS.md` and `bench/results/`.
  - Use placeholder paths (e.g. `C:\Users\dev\workspace\my-app`) in tracked test cases and `${AGY_GUARDIAN_*_DIR}` placeholders in `bench/models.example.json`.
- **Secrets:** Never print, echo, or log environment secrets such as `HF_TOKEN`, `AGY_GUARDIAN_GEMINI_PAID_API_KEY`, or `AGY_GUARDIAN_GEMINI_FREE_API_KEY`.

## Repository Layout & Workflow

- `.env.example` — Complete tracked template for machine-local settings (copy to gitignored `.env`).
- `README.md` — User-facing introduction, setup, and everyday use (see *Documentation Responsibilities*).
- `SECURITY.md` — Threat model, non-goals, and private vulnerability reporting.
- `SETUP-AGENTS.md` — Interactive AI-guided setup & per-project policy configuration runbook (keep separate from `AGENTS.md` to avoid bloating normal coding sessions).
  - **Permissions review / audit / cleanup:** Whenever the user asks for a permissions review, audit, or cleanup of `settings.json`, read `SETUP-AGENTS.md` (**Step 6 — Optional Maintenance: `settings.json` Permissions Cleanup**) first and follow its scan-scope and tiered wildcard workflow.
- `agy_guardian/` — Production stdlib-only 3-layer `PreToolUse` hook package:
  - `config.py` — Pure-stdlib `.env` loader, `${VAR}` expander, and `GuardianConfig`.
  - `policy.py` — Per-project policy loader (`~/.gemini/config/agy_guardian_policies.json`), fail-closed and strictly refusing in-workspace policy files.
  - `shell_parser.py` — PowerShell/Bash lexical splitter, backtick/caret normalizer, wrapper stripper, opaque detector, and Windows/WSL UNC workspace path containment checker.
  - `rules.py` — Layer 1 deterministic hard-deny (including SSH remote commands) and Layer 2 deterministic fast-allow (including policy-scoped read-only SSH) evaluators.
  - `classifiers.py` — Pure-stdlib HTTP clients for local `POST /v1/systemone`, remote Gemini `POST /v1beta/decisions`, and legacy `POST /v1/chat/completions`, plus fail-closed `apply_thresholds()`.
  - `pipeline.py` — 3-layer evaluation orchestrator with per-project policy resolution, Layer 3 context assembly, and optional explicit backend fallback.
  - `audit.py` — Fail-closed, redacting JSONL audit logger with rotation, usage summaries, and recent-command extraction.
  - `cli.py` & `__main__.py` — Antigravity `PreToolUse` stdin/stdout entrypoint and diagnostic CLI (`--check`, `--policy`, `--health`, `--usage`).
- `scripts/` — Operational scripts:
  - `agy_guardian_hook.py` — Direct hook launcher (zero `PYTHONPATH` setup needed under `cmd /c`).
  - `start_llama_server.ps1` & `start_llama_server.sh` — Idempotent `llama-server` startup/status/stop scripts for PowerShell and Git Bash (`--ctx-size 2048 -b 2048 -ub 2048 -np 1`, shared `.local/llama-server.pid`).
  - `install_hooks.ps1` — Safe JSON merger for `%USERPROFILE%\.gemini\config\hooks.json` (`-Disabled`, `-Uninstall`).
- `config/` — Tracked portable templates (`hooks.example.json`, `policies.example.json`).
- `tests/` — Stdlib `unittest` suite covering parser, every `bench/cases.json` case, mocked Layer 3/fallbacks, the Gemini backend, project policies, and hook CLI/audit contract.
- `bench/` — Benchmark suite (`cases.json`, `run_bench.py`, `RESULTS.md`, `results/`, and compatibility shims `env.py`/`classifiers.py`).

Run unit tests and benchmarks locally:
```powershell
python -m unittest discover -s tests -v
python bench/run_bench.py --model clef-flash --schema both
```
