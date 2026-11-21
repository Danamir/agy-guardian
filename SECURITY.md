# Security Policy

## Security Model & Guarantees

`agy-guardian` is a defense-in-depth `PreToolUse` command approval filter for Google Antigravity CLI (`agy`). Its primary design invariant is **fail-closed safety with zero false-allows**:

1. **Always fail closed to `"ask"`:** Any parser ambiguity, HTTP timeout, backend outage, malformed response, sub-threshold probability, or failed JSONL audit write (when `AGY_GUARDIAN_AUDIT_FAIL_CLOSED=true` on `"allow"`) degrades to `"ask"` — never `"allow"`.
2. **Layer 1 hard-deny is non-overridable:** Per-project policies (`agy_guardian_policies.json`) cannot disable or bypass Layer 1 deterministic blocks (catastrophic deletes, remote pipe-to-shell, `-EncodedCommand`, credential exfiltration, obfuscated inline execution, etc.).
3. **Out-of-workspace policy trust boundary:** `agy_guardian` actively refuses to load policy files located inside writable `workspacePaths`, preventing a compromised repository or prompt-injected agent from escalating its own permissions.
4. **Tier-isolated remote API keys:** When using the optional remote `gemini-decision-1` backend, `AGY_GUARDIAN_GEMINI_PAID_API_KEY` and `AGY_GUARDIAN_GEMINI_FREE_API_KEY` are strictly isolated and never fall back to each other or to generic `GEMINI_API_KEY`.
5. **Audit log redaction:** Sensitive tokens (API keys, bearer tokens, basic-auth URLs, common secret env assignments) are redacted before writing to the local JSONL audit log.

## Non-Goals & Limitations

- `agy-guardian` is **not an OS sandbox or container**. It evaluates command lines *before* execution; once a command is approved (or manually accepted by the user), execution is governed by the OS user's privileges.
- **Layer 3 is probabilistic.** Although `Clef-Flash Q5_K_M` (`multi` schema) and `gemini-decision-1` achieve `0` false-allows on [`bench/cases.json`](bench/cases.json), novel or heavily crafted commands can still be misclassified. Keep `AGY_GUARDIAN_ALLOW_THRESHOLD >= 0.85` and `AGY_GUARDIAN_RISK_MAX_PROB <= 0.25` (especially if using `single` schema).
- **Project-local code execution:** Commands such as `pytest`, `npm test`, or build scripts execute arbitrary code inside the workspace. If you open an untrusted repository, keep Layer 3 conservative or disable auto-approval until you have reviewed the repo.

## Reporting a Vulnerability or Rule Bypass

If you discover a **Layer 1/2 parser bypass**, a **false-allow regression**, a **policy isolation flaw**, or a **secret-leakage bug**:

1. **Do not open a public issue with a working exploit** before it has been reviewed.
2. Report it privately using the repository host's **Security Advisory / Private Vulnerability Reporting** feature, or open a minimal issue asking for a private contact channel.
3. Please include:
   - The exact command line (and target shell: PowerShell 5.1, `cmd`, or Git Bash)
   - Relevant `workspacePaths` / `cwd` / policy configuration (sanitized)
   - The observed decision (`layer`, `decision`, `reason`) vs. expected decision

Every confirmed bypass will be added as a permanent regression case to `tests/` and/or `bench/cases.json` once patched.
