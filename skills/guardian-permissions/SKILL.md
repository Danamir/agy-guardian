---
name: guardian-permissions
description: Generalize the last Antigravity settings.json permission, audit/clean up permissions.allow, or show/update per-project agy-guardian policies (allowedUrls, allowedPrograms, extraWorkspaces, policyNotes) from any workspace. Activate when the user says "generalize the last permission", "show me the guardian policy", asks to inspect/clean up/audit settings.json permissions, or wants to view or allow a URL, program, workspace, or note in agy-guardian.
---

# Guardian Permissions & Policy Manager

Safely generalize Antigravity `settings.json` permissions and update per-project `agy-guardian` policies from **any** workspace without bypassing `~/.gemini/` protection.

> **Installation note:** Replace `<AGY_GUARDIAN_REPO>` below with the absolute path to your local `agy-guardian` clone (e.g. `C:\Users\dev\workspace\agy-guardian`).

## Core Safety Rules
- **Never bypass `~/.gemini/` protection.** Do not try to silently edit `settings.json` or `agy_guardian_policies.json` directly when protected; use the auditable helper scripts below so the user approves the exact change in one click.
- **Always confirm before mutating.** Present concrete tiered options and apply only what the user explicitly selects.
- **Always pass `--expected`** to `manage_permissions.py replace` and `remove` so the script refuses to edit if the entry at `--index` changed.
- **Keep `agy-guardian` Layer 1 inviolable.** Never suggest overly broad legacy wildcards (e.g. `command(git *)`, `command(curl *)`, `command(python *)`) without warning that they bypass `agy-guardian` prompts for destructive/network commands.

---

## Workflow 1 — "Generalize the last permission" (Fast Path)

When the user just approved a tool call permanently and asks to generalize the last permission:

1. **Inspect the last entry** in `settings.json`:
   ```powershell
   python "<AGY_GUARDIAN_REPO>\scripts\manage_permissions.py" show --last 1
   ```
   *(Use `--last 3` if the user mentions the last few permissions.)*

2. **Analyze the rule & propose tiered options** using `ask_question` (or a concise numbered list), ordered from strictest to broadest, marking the best fit with `(Recommended)`:
   - **Remove & move to `agy-guardian` policy** *(often recommended for complex PowerShell pipelines, `$vars`, inline scripts, external programs like `blender.exe`, or local API URLs like `http://127.0.0.1:8188` where `settings.json` wildcards are fragile)* — removes the verbatim rule from `settings.json` and adds `allowedPrograms` / `allowedUrls` / `extraWorkspaces` / `policyNotes` to `agy_guardian_policies.json`.
   - **Remove & defer to `agy-guardian`** — drops the one-off entry completely so `agy-guardian` Layers 1–3 judge it dynamically.
   - **Narrow subcommand wildcard** — e.g. `command(glab issue create *)` or `command(pytest *)`.
   - **Sub-area wildcard** — e.g. `command(glab issue *)` or `command(git commit *)` (note any mutating subcommands covered).
   - **Broad tool wildcard (High Liberty)** — e.g. `command(glab *)` (explicitly warn about destructive subcommands covered).

3. **Apply the chosen action** in one readable command (the user approves once; a `.bak` backup is created automatically):
   - Replace:
     ```powershell
     python "<AGY_GUARDIAN_REPO>\scripts\manage_permissions.py" replace --index -1 --expected "<EXACT_OLD_VALUE>" --value "<NEW_VALUE>"
     ```
   - Remove:
     ```powershell
     python "<AGY_GUARDIAN_REPO>\scripts\manage_permissions.py" remove --index -1 --expected "<EXACT_OLD_VALUE>"
     ```
   - If moving to `agy-guardian` policy, also run Workflow 3 below.

---

## Workflow 2 — Batch `settings.json` Permissions Cleanup

When the user asks to review, audit, or clean up `settings.json` permissions:

1. **Pick scope** (default to `--last 10` for quick passes; use `--all` for a full audit):
   ```powershell
   python "<AGY_GUARDIAN_REPO>\scripts\manage_permissions.py" show --last 10
   ```
2. **Flag noisy or risky entries:**
   - Verbatim one-offs with specific paths, titles, commit messages, `$vars`, pipes, or `;`.
   - Duplicate/redundant rules.
   - Overly broad legacy regexes (`git .*`, `curl .*`, `iwr .*`, `Get-Content .*`, `Start-Process .*`) that override `agy-guardian`.
3. **Group by tool family**, propose the same tiered options per group, and apply only approved `replace`/`remove` calls (apply from highest index to lowest so indices don't shift, or re-run `show` between batches).

---

## Workflow 3 — Show or Update Per-Project `agy-guardian` Policy

When the user asks to **show/inspect** the guardian policy, or wants to allow a local service URL, external program, companion workspace, read-only SSH host, forge CLI write, or `policyNotes` for the current project:

1. **Check the current project's policy** (read-only):
   ```powershell
   python "<AGY_GUARDIAN_REPO>\scripts\manage_policy.py" show --workspace "<CURRENT_WORKSPACE>"
   ```
   *(Omit `--workspace` to show the full policy file including `defaults` and all projects. If the user only asked to view the policy, summarize the result and stop here.)*
2. **Propose and run a single `update` command** (creates a `.bak` backup, validates URLs/programs, and merges without clobbering other projects):
   ```powershell
   python "<AGY_GUARDIAN_REPO>\scripts\manage_policy.py" update --project "<PROJECT_NAME>" --workspace "<CURRENT_WORKSPACE>" --add-url "http://127.0.0.1:8188" --add-program "C:\Program Files\Blender Foundation\*\blender.exe" --add-workspace "D:\path\to\extra-folder" --append-note "Calling local ComfyUI and running Blender on project meshes is allowed; destructive deletes still ask."
   ```
   - Use `--defaults` instead of `--project`/`--workspace` only when the user wants a global default across all workspaces.
   - Supported flags: `--match-workspace`, `--add-workspace` / `--remove-workspace`, `--add-write-path` / `--remove-write-path`, `--add-ssh-host` / `--remove-ssh-host`, `--add-forge-cli` / `--remove-forge-cli`, `--add-url` / `--remove-url`, `--add-program` / `--remove-program`, `--note` / `--append-note`.
3. **Verify immediately** (policy changes take effect on the next hook call, no restart needed):
   ```powershell
   python "<AGY_GUARDIAN_REPO>\scripts\agy_guardian_hook.py" --cwd "<CURRENT_WORKSPACE>" --user-input "<TYPICAL_REQUEST>" --check "<SAMPLE_COMMAND>" --no-audit
   ```
