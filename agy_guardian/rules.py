"""Layer 1 (Deterministic Hard-Deny) and Layer 2 (Deterministic Fast-Allow) rules."""

from __future__ import annotations

import ntpath
import re
from dataclasses import dataclass

from .shell_parser import (
    CommandSegment,
    ParsedCommand,
    Token,
    is_path_within_workspace,
    normalize_windows_path,
    parse_command,
)


@dataclass
class RuleMatch:
    decision: str  # "deny" | "allow"
    rule_id: str
    reason: str


# ---------------------------------------------------------------------------
# Layer 1 — Deterministic Hard-Deny (0 ms)
# ---------------------------------------------------------------------------

_DISK_WIPE_HEADS = {
    "format-volume",
    "clear-disk",
    "initialize-disk",
    "diskpart",
    "bcdedit",
    "mkfs",
    "mkfs.ext4",
    "mkfs.xfs",
    "mkfs.ntfs",
    "mkfs.vfat",
    "fdisk",
    "parted",
    "wipefs",
}

_DELETE_HEADS = {
    "remove-item",
    "ri",
    "rm",
    "del",
    "erase",
    "rd",
    "rmdir",
}

_NETWORK_FETCH_HEADS = {
    "curl",
    "wget",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
}

_SHELL_EXEC_HEADS = {
    "iex",
    "invoke-expression",
    "bash",
    "sh",
    "zsh",
    "powershell",
    "pwsh",
    "cmd",
}

_SAFE_SEARCH_OR_PRINT_HEADS = {
    "rg",
    "grep",
    "select-string",
    "findstr",
    "git",
    "echo",
    "write-output",
    "write-host",
}

_SYSTEM_REG_HIVES = (
    "hklm",
    "hkcr",
    "hku",
    "hkey_local_machine",
    "hkey_classes_root",
    "hkey_users",
)

_SENSITIVE_DELETE_SEGMENTS = (
    "\\windows",
    "\\system32",
    "\\.ssh",
    "\\.aws",
    "\\.gnupg",
    "\\documents",
    "\\desktop",
)

_TEMP_PATH_MARKERS = (
    "\\windows\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\temp\\",
    "/tmp/",
)

_SECRET_EXFIL_RE = re.compile(
    r"(?:"
    r"@\.env\b|"
    r"(?:^|[\\/=\"'\s])\.env(?:\.[a-z0-9_-]+)?(?=$|[\\/\"'\s)&|;])|"
    r"\.ssh(?:[\\/]|$|\s)|"
    r"\.aws[\\/]credentials|"
    r"\bid_rsa\b|"
    r"\benv:"
    r")",
    re.IGNORECASE,
)

_EMBEDDED_NET_RE = re.compile(
    r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl(?:\.exe)?|wget(?:\.exe)?|downloadstring|downloadfile)\b",
    re.IGNORECASE,
)
_EMBEDDED_EXEC_RE = re.compile(
    r"(?:\biex\b|\binvoke-expression\b|\[scriptblock\]::create)",
    re.IGNORECASE,
)
_INLINE_PY_BASE64_RE = re.compile(r"\bb64decode\b", re.IGNORECASE)
_INLINE_PY_EXEC_RE = re.compile(r"\b(?:os\.system|subprocess\.|exec\s*\(|eval\s*\()", re.IGNORECASE)
_INLINE_PY_NET_RE = re.compile(r"\b(?:urlopen|requests\.get|httpx\.get|http\.client)\b", re.IGNORECASE)
_INLINE_NODE_B64_RE = re.compile(r"(?:\batob\s*\(|['\"]base64['\"])", re.IGNORECASE)
_INLINE_NODE_EXEC_RE = re.compile(r"\b(?:execsync|spawn|child_process|eval\s*\()", re.IGNORECASE)


def _norm_segment_text(seg: CommandSegment) -> str:
    """Segment text with PowerShell escape backticks stripped for obfuscation detection."""
    return seg.raw.replace("`", "")


def _is_catastrophic_delete_target(target: str, cwd: str, workspace_paths: list[str]) -> bool:
    cleaned = target.strip().strip('"').strip("'")
    if not cleaned:
        return False
    low = cleaned.replace("/", "\\").lower()

    # Exact roots, wildcards at root, home roots
    if low in ("\\", "\\*", "*", ".", "..", "~", "~\\*", "$home", "%userprofile%", "%systemroot%"):
        if low in (".", ".."):
            # Relative `.` or `..` only catastrophic if outside workspace
            return not is_path_within_workspace(cleaned, cwd, workspace_paths)
        return True
    if re.match(r"^[a-z]:\\?\*?$", low):
        return True
    if re.match(r"^[a-z]:\\users\\[^\\]+\\\*?$", low):
        return True

    # Registry system hives via Remove-Item HKLM:\...
    if any(low.startswith(hive + ":") for hive in _SYSTEM_REG_HIVES):
        return True

    # Sensitive OS / user directories
    for marker in _SENSITIVE_DELETE_SEGMENTS:
        if marker in low:
            # Allow explicit temp subdirs under C:\Windows\Temp\<subdir>
            if "\\windows\\temp\\" in low and not low.rstrip("\\").endswith("\\windows\\temp"):
                return False
            return True

    # Any path outside workspacePaths (except scoped temp subdirs)
    if workspace_paths and not is_path_within_workspace(cleaned, cwd, workspace_paths):
        for tmp_marker in _TEMP_PATH_MARKERS:
            if tmp_marker in low and not low.rstrip("\\").endswith(tmp_marker.rstrip("\\")):
                return False
        return True

    return False


def _check_delete_segment(seg: CommandSegment, cwd: str, workspace_paths: list[str]) -> RuleMatch | None:
    if seg.head not in _DELETE_HEADS:
        return None

    is_recursive = False
    is_forced = False
    targets: list[str] = []
    args = seg.args
    i = 0
    while i < len(args):
        tok = args[i]
        low = tok.normalized

        if low in ("-path", "-literalpath"):
            if i + 1 < len(args):
                targets.append(args[i + 1].text)
                i += 2
                continue
        elif low in ("-r", "-rec", "-recurse", "--recursive", "/s"):
            is_recursive = True
        elif low in ("-f", "-fo", "-for", "-force", "--force", "/q", "/f"):
            is_forced = True
        elif low.startswith("-") and not low.startswith("--") and tok.quoted is None:
            # Combined Unix short flags like -rf, -fr, -rfi
            letters = low[1:]
            if letters.isalpha():
                if "r" in letters:
                    is_recursive = True
                if "f" in letters:
                    is_forced = True
        elif low.startswith("/") and len(low) == 2 and low[1].isalpha():
            if low == "/s":
                is_recursive = True
            elif low in ("/q", "/f"):
                is_forced = True
        else:
            targets.append(tok.text)
        i += 1

    if is_recursive and is_forced:
        for target in targets:
            if _is_catastrophic_delete_target(target, cwd, workspace_paths):
                return RuleMatch(
                    decision="deny",
                    rule_id="L1_CATASTROPHIC_DELETE",
                    reason=f"Layer 1 hard-deny: catastrophic recursive forced deletion targeting '{target}'",
                )
    return None


def _check_segment_layer1(seg: CommandSegment, cwd: str, workspace_paths: list[str]) -> RuleMatch | None:
    head = seg.head
    args_low = [t.normalized for t in seg.args]

    # 1. Disk / partition / boot destruction
    if head in _DISK_WIPE_HEADS:
        return RuleMatch(
            decision="deny",
            rule_id="L1_DISK_WIPE",
            reason=f"Layer 1 hard-deny: destructive disk/system command '{head}'",
        )
    if head == "dd" and any(a.startswith(("of=/dev/", "of=\\\\.\\")) for a in args_low):
        return RuleMatch(
            decision="deny",
            rule_id="L1_DISK_WIPE",
            reason="Layer 1 hard-deny: raw device write via dd",
        )
    if head == "cipher" and any(a.startswith("/w") for a in args_low):
        return RuleMatch(
            decision="deny",
            rule_id="L1_DISK_WIPE",
            reason="Layer 1 hard-deny: disk wipe via cipher /w",
        )

    # 2. PowerShell Base64 EncodedCommand
    if head in ("powershell", "pwsh") and "encoded_command" in seg.opaque_reasons:
        return RuleMatch(
            decision="deny",
            rule_id="L1_ENCODED_COMMAND",
            reason="Layer 1 hard-deny: obfuscated PowerShell -EncodedCommand",
        )

    # 3. System Windows Registry deletion
    if head == "reg" and args_low and args_low[0] == "delete":
        for a in args_low[1:]:
            if any(a.startswith(hive + "\\") or a == hive for hive in _SYSTEM_REG_HIVES):
                return RuleMatch(
                    decision="deny",
                    rule_id="L1_REG_DELETE_SYSTEM",
                    reason=f"Layer 1 hard-deny: system registry deletion '{a}'",
                )

    # 4. Catastrophic recursive forced deletion
    del_match = _check_delete_segment(seg, cwd, workspace_paths)
    if del_match is not None:
        return del_match

    # 5. Remote download-and-execute embedded in a single segment (e.g. iex (iwr ...), scriptblock::Create(irm ...))
    if head not in _SAFE_SEARCH_OR_PRINT_HEADS:
        norm_raw = _norm_segment_text(seg)
        if _EMBEDDED_EXEC_RE.search(norm_raw) and (
            _EMBEDDED_NET_RE.search(norm_raw) or "http://" in norm_raw.lower() or "https://" in norm_raw.lower()
        ):
            return RuleMatch(
                decision="deny",
                rule_id="L1_REMOTE_PIPE_TO_SHELL",
                reason="Layer 1 hard-deny: remote download-and-execute expression",
            )

    # 6. Windows LOLBin remote download/exec
    if head == "certutil" and any(a in ("-urlcache", "/urlcache") for a in args_low):
        return RuleMatch(
            decision="deny",
            rule_id="L1_LOLBIN_DOWNLOAD_EXEC",
            reason="Layer 1 hard-deny: certutil -urlcache remote download",
        )
    if head == "mshta" and any("http://" in a or "https://" in a for a in args_low):
        return RuleMatch(
            decision="deny",
            rule_id="L1_LOLBIN_DOWNLOAD_EXEC",
            reason="Layer 1 hard-deny: mshta remote execution",
        )
    if head == "bitsadmin" and any(a in ("/transfer", "-transfer") for a in args_low):
        return RuleMatch(
            decision="deny",
            rule_id="L1_LOLBIN_DOWNLOAD_EXEC",
            reason="Layer 1 hard-deny: bitsadmin remote transfer",
        )
    if head == "regsvr32" and any("http://" in a or "https://" in a for a in args_low):
        return RuleMatch(
            decision="deny",
            rule_id="L1_LOLBIN_DOWNLOAD_EXEC",
            reason="Layer 1 hard-deny: regsvr32 remote scriptlet execution",
        )

    # 7. Obfuscated or remote-code-executing inline Python / Node
    if head in ("python", "python3", "py"):
        for idx, tok in enumerate(seg.args):
            if tok.normalized == "-c" and idx + 1 < len(seg.args):
                code = seg.args[idx + 1].text
                if _INLINE_PY_BASE64_RE.search(code) and _INLINE_PY_EXEC_RE.search(code):
                    return RuleMatch(
                        decision="deny",
                        rule_id="L1_OBFUSCATED_INLINE_EXEC",
                        reason="Layer 1 hard-deny: Base64-obfuscated inline Python execution",
                    )
                if _INLINE_PY_NET_RE.search(code) and re.search(r"\b(?:exec|eval)\s*\(", code):
                    return RuleMatch(
                        decision="deny",
                        rule_id="L1_OBFUSCATED_INLINE_EXEC",
                        reason="Layer 1 hard-deny: remote code execution via inline Python",
                    )
    if head == "node":
        for idx, tok in enumerate(seg.args):
            if tok.normalized in ("-e", "--eval") and idx + 1 < len(seg.args):
                code = seg.args[idx + 1].text
                if _INLINE_NODE_B64_RE.search(code) and _INLINE_NODE_EXEC_RE.search(code):
                    return RuleMatch(
                        decision="deny",
                        rule_id="L1_OBFUSCATED_INLINE_EXEC",
                        reason="Layer 1 hard-deny: Base64-obfuscated inline Node execution",
                    )

    # 8. Direct secret-file / credential exfiltration via network sender
    if head in _NETWORK_FETCH_HEADS:
        joined_args = " ".join(t.text for t in seg.args)
        if _SECRET_EXFIL_RE.search(joined_args):
            return RuleMatch(
                decision="deny",
                rule_id="L1_CREDENTIAL_EXFIL",
                reason=f"Layer 1 hard-deny: credential/secret exfiltration attempt via '{head}'",
            )

    return None


def _check_pipelines_layer1(parsed: ParsedCommand) -> RuleMatch | None:
    """Inspect connected pipe stages (seg1 | seg2 | ...) for pipe-to-shell and secret exfiltration."""
    # Group leaf segments (excluding outer wrapper shells) by (unwrapped_from, pipeline_group)
    groups: dict[tuple[tuple[str, ...], int], list[CommandSegment]] = {}
    for seg in parsed.all_segments:
        if seg.is_wrapper_shell:
            continue
        key = (seg.unwrapped_from, seg.pipeline_group)
        groups.setdefault(key, []).append(seg)

    for stages in groups.values():
        if len(stages) < 2:
            continue

        # Check remote fetch | shell exec
        saw_remote_fetch = False
        saw_secret_source = False
        for seg in stages:
            head = seg.head
            norm_raw = _norm_segment_text(seg)

            if saw_remote_fetch and (head in _SHELL_EXEC_HEADS or _EMBEDDED_EXEC_RE.search(norm_raw)):
                return RuleMatch(
                    decision="deny",
                    rule_id="L1_REMOTE_PIPE_TO_SHELL",
                    reason=f"Layer 1 hard-deny: remote content piped into '{head or 'shell'}'",
                )

            if saw_secret_source and (
                head in _NETWORK_FETCH_HEADS or _EMBEDDED_NET_RE.search(norm_raw)
            ):
                return RuleMatch(
                    decision="deny",
                    rule_id="L1_CREDENTIAL_EXFIL",
                    reason="Layer 1 hard-deny: secret/environment data piped to outbound network tool",
                )

            if head in _NETWORK_FETCH_HEADS:
                saw_remote_fetch = True

            if head not in _SAFE_SEARCH_OR_PRINT_HEADS and _SECRET_EXFIL_RE.search(norm_raw):
                saw_secret_source = True

    return None


_SSH_SAFE_BOOL_FLAGS = {"-n", "-t", "-q", "-4", "-6", "-v"}
_SSH_SAFE_VALUE_FLAGS = {"-p", "-l"}
_SSH_FORBIDDEN_FLAGS = {
    "-o", "-f", "-n", "-a", "-x", "-y", "-l", "-r", "-d", "-w", "-j", "-s", "-m", "-e", "-i",
}
_SSH_VALUE_FLAGS_FOR_L1 = {
    "-b", "-c", "-d", "-e", "-f", "-i", "-j", "-l", "-m", "-o", "-p", "-q", "-r", "-s", "-w",
}

_REMOTE_READONLY_SIMPLE_HEADS = {
    "ls",
    "ll",
    "pwd",
    "whoami",
    "id",
    "uname",
    "hostname",
    "uptime",
    "date",
    "df",
    "du",
    "free",
    "ps",
    "ss",
    "netstat",
    "lscpu",
    "lsblk",
    "stat",
    "file",
    "readlink",
    "realpath",
}

_REMOTE_FILE_VIEW_HEADS = {"cat", "head", "tail", "wc"}
_REMOTE_SYSTEMCTL_READONLY_SUBS = {
    "status",
    "is-active",
    "is-enabled",
    "is-failed",
    "list-units",
    "list-unit-files",
    "list-timers",
    "show",
    "cat",
}
_REMOTE_JOURNALCTL_FORBIDDEN = {
    "--flush",
    "--rotate",
    "--sync",
    "--relinquish-var",
    "--update-catalog",
}
_REMOTE_DOCKER_SIMPLE_READONLY = {"ps", "images", "logs", "inspect", "info", "version"}
_REMOTE_DOCKER_COMPOSE_READONLY = {"ps", "logs", "config", "images", "version"}

_REMOTE_SENSITIVE_PATH_RE = re.compile(
    r"(?:/etc/shadow|/etc/gshadow|/etc/sudoers|\.ssh(?:/|$)|\.aws(?:/|$)|\.gnupg(?:/|$)|"
    r"(?:^|/)\.env(?:\.[a-z0-9_-]+)?$|(?:^|/)[^/]+\.env$|"
    r"(?:^|/)\.(?:npmrc|git-credentials|netrc|pypirc)$|"
    r"(?:^|/)\.git/config$|"
    r"\bid_rsa\b|\bid_ed25519\b|\.pem$|\.key$|\.kdbx$|credentials|secret|token)",
    re.IGNORECASE,
)


def _extract_ssh_target_and_command(
    args: list[Token],
    *,
    strict_for_l2: bool,
) -> tuple[str | None, str | None]:
    """Extract (host, remote_command) from ssh args. In strict mode, reject risky SSH options."""
    i = 0
    while i < len(args):
        tok = args[i]
        raw = tok.text
        if raw == "--":
            i += 1
            break
        if raw.startswith("-") and len(raw) > 1:
            if strict_for_l2:
                # Allow only explicitly safe non-forwarding, non-ProxyCommand flags
                if raw in ("-n", "-T", "-q", "-4", "-6", "-v"):
                    i += 1
                    continue
                if raw in ("-p", "-l"):
                    if i + 1 >= len(args):
                        return None, None
                    i += 2
                    continue
                return None, None
            else:
                low = raw.lower()
                if len(raw) == 2 and low in _SSH_VALUE_FLAGS_FOR_L1:
                    i += 2
                    continue
                i += 1
                continue
        break

    if i >= len(args):
        return None, None

    target = args[i].text.strip()
    if not target:
        return None, None
    host = target.rsplit("@", 1)[-1].lower()

    rest = args[i + 1 :]
    if not rest:
        return host, None

    remote_cmd = rest[0].text if len(rest) == 1 else " ".join(t.raw for t in rest)
    return host, remote_cmd


def _is_remote_sensitive_arg(arg: str) -> bool:
    return bool(_REMOTE_SENSITIVE_PATH_RE.search(arg.strip().strip('"').strip("'")))


def _check_remote_git_readonly(args: list[Token]) -> bool:
    if not args:
        return False
    idx = 0
    while idx < len(args) and args[idx].text.startswith("-"):
        flag = args[idx].text
        low = flag.lower()
        if flag == "-C":
            if idx + 1 >= len(args):
                return False
            idx += 2
            continue
        if flag == "-c" or any(low == f or low.startswith(f + "=") for f in _GIT_FORBIDDEN_GLOBAL_FLAGS):
            return False
        if low in ("--no-pager", "-p", "--paginate", "--no-optional-locks"):
            idx += 1
            continue
        return False
    if idx >= len(args):
        return False
    sub = args[idx].normalized
    sub_args = args[idx + 1 :]
    for tok in sub_args:
        low = tok.normalized
        if low in ("--output", "--ext-diff", "--textconv") or low.startswith("--output="):
            return False
    if sub in _GIT_READONLY_SUBCOMMANDS:
        return True
    if sub == "branch":
        return all(t.normalized.split("=", 1)[0] in _GIT_BRANCH_READONLY_FLAGS for t in sub_args)
    if sub == "tag":
        if not sub_args:
            return True
        has_list = False
        i = 0
        while i < len(sub_args):
            base = sub_args[i].normalized.split("=", 1)[0]
            if base in ("-l", "--list"):
                has_list = True
                i += 1
                if i < len(sub_args) and not sub_args[i].text.startswith("-"):
                    i += 1
                continue
            if base in _GIT_TAG_READONLY_FLAGS:
                i += 1
                continue
            return False
        return has_list
    return False


def _check_remote_segment_readonly(seg: CommandSegment) -> bool:
    if seg.opaque_reasons or not seg.tokens:
        return False
    head = seg.head
    args = seg.args
    is_piped_in = seg.operator_before == "|"

    if head in _REMOTE_READONLY_SIMPLE_HEADS:
        return not any(_is_remote_sensitive_arg(t.text) for t in args if not t.text.startswith("-"))

    if head in _REMOTE_FILE_VIEW_HEADS:
        paths = [t.text for t in args if not t.text.startswith("-")]
        if not paths:
            return is_piped_in
        return not any(_is_remote_sensitive_arg(p) for p in paths)

    if head in ("grep", "egrep", "fgrep", "rg"):
        for tok in args:
            base = tok.normalized.split("=", 1)[0]
            if base in ("--pre", "--pre-glob", "--files-from", "-f", "--file"):
                return False
            if not tok.text.startswith("-") and _is_remote_sensitive_arg(tok.text):
                return False
        return True

    if head == "fd":
        for tok in args:
            base = tok.normalized.split("=", 1)[0]
            if base in ("-x", "--exec", "-X", "--exec-batch"):
                return False
            if tok.text.startswith("-") and not tok.text.startswith("--"):
                if "x" in tok.text[1:] or "X" in tok.text[1:]:
                    return False
        return True

    if head in ("sort", "uniq", "cut", "tr"):
        return _check_pipeline_filter(head, args, is_piped_in)

    if head == "systemctl":
        pos = [t.normalized for t in args if not t.text.startswith("-")]
        return bool(pos) and pos[0] in _REMOTE_SYSTEMCTL_READONLY_SUBS

    if head == "journalctl":
        for tok in args:
            base = tok.normalized.split("=", 1)[0]
            if base in _REMOTE_JOURNALCTL_FORBIDDEN or base.startswith("--vacuum"):
                return False
        return True

    if head == "docker":
        pos = [t.normalized for t in args if not t.text.startswith("-")]
        if not pos:
            return False
        sub = pos[0]
        if sub in _REMOTE_DOCKER_SIMPLE_READONLY:
            return True
        if sub == "stats":
            return any(t.normalized == "--no-stream" for t in args)
        if sub in ("network", "volume"):
            return len(pos) >= 2 and pos[1] in ("ls", "list", "inspect")
        if sub == "compose":
            return len(pos) >= 2 and pos[1] in _REMOTE_DOCKER_COMPOSE_READONLY
        return False

    if head == "git":
        return _check_remote_git_readonly(args)

    return False


def _check_ssh_readonly_segment(
    seg: CommandSegment,
    allowed_ssh_read_hosts: set[str],
) -> bool:
    if not allowed_ssh_read_hosts or seg.head != "ssh" or seg.opaque_reasons:
        return False
    host, remote_cmd = _extract_ssh_target_and_command(seg.args, strict_for_l2=True)
    if not host or not remote_cmd or host not in allowed_ssh_read_hosts:
        return False

    remote_parsed = parse_command(remote_cmd)
    if remote_parsed.has_opaque or not remote_parsed.leaf_segments:
        return False
    # Never allow anything Layer 1 would deny remotely
    if check_layer1_deny(remote_parsed, "/", []) is not None:
        return False
    return all(_check_remote_segment_readonly(rseg) for rseg in remote_parsed.leaf_segments)


def check_layer1_deny(
    parsed: ParsedCommand,
    cwd: str,
    workspace_paths: list[str],
) -> RuleMatch | None:
    """Evaluate Layer 1 deterministic hard-deny rules across all parsed/unwrapped segments."""
    for seg in parsed.all_segments:
        match = _check_segment_layer1(seg, cwd, workspace_paths)
        if match is not None:
            return match
        if seg.head == "ssh":
            _, remote_cmd = _extract_ssh_target_and_command(seg.args, strict_for_l2=False)
            if remote_cmd:
                remote_parsed = parse_command(remote_cmd)
                remote_match = check_layer1_deny(remote_parsed, "/", [])
                if remote_match is not None:
                    return RuleMatch(
                        decision="deny",
                        rule_id=remote_match.rule_id,
                        reason=f"{remote_match.reason} (via ssh remote command)",
                    )

    return _check_pipelines_layer1(parsed)


# ---------------------------------------------------------------------------
# Layer 2 — Deterministic Fast-Allow (0 ms)
# ---------------------------------------------------------------------------

_GIT_READONLY_SUBCOMMANDS = {
    "status",
    "diff",
    "log",
    "show",
    "rev-parse",
    "ls-files",
    "blame",
    "shortlog",
    "describe",
}

_GIT_FORBIDDEN_GLOBAL_FLAGS = {
    "-c",
    "--config-env",
    "--git-dir",
    "--work-tree",
    "--exec-path",
    "--namespace",
    "--super-prefix",
}

_GIT_BRANCH_READONLY_FLAGS = {
    "--show-current",
    "-a",
    "--all",
    "-r",
    "--remotes",
    "-v",
    "-vv",
    "--verbose",
    "-l",
    "--list",
    "--contains",
    "--no-contains",
    "--merged",
    "--no-merged",
    "--sort",
    "--format",
    "--color",
    "--no-color",
    "--abbrev",
    "--no-abbrev",
}

_GIT_TAG_READONLY_FLAGS = {
    "-l",
    "--list",
    "-n",
    "--sort",
    "--contains",
    "--no-contains",
    "--merged",
    "--no-merged",
    "--format",
    "--color",
    "--no-color",
}

_VERSION_ONLY_HEADS = {
    "python",
    "python3",
    "py",
    "node",
    "npm",
    "npx",
    "uv",
    "git",
    "cargo",
    "rustc",
    "ruff",
    "pytest",
    "mypy",
    "black",
    "go",
    "java",
    "dotnet",
}

_PIPELINE_FILTER_HEADS = {
    "select-object",
    "select",
    "measure-object",
    "measure",
    "sort-object",
    "format-table",
    "ft",
    "format-list",
    "fl",
    "out-string",
    "uniq",
    "cut",
    "tr",
    "sort",
}

_FILE_VIEW_HEADS = {
    "get-content",
    "gc",
    "cat",
    "type",
    "head",
    "tail",
    "wc",
}

_DIR_LIST_HEADS = {
    "get-childitem",
    "gci",
    "ls",
    "dir",
    "test-path",
    "resolve-path",
}

_ZERO_ARG_INFO_HEADS = {
    "pwd",
    "get-location",
    "gl",
}

_SENSITIVE_FILENAME_RE = re.compile(
    r"(?:^\.env(?:\..+)?$|\.env$|\.pem$|\.key$|\.pfx$|\.p12$|\.kdbx$|"
    r"^\.npmrc$|^\.git-credentials$|^\.netrc$|^\.pypirc$|"
    r"^id_rsa|^id_ed25519|^credentials(?:\..+)?$|secret|token)",
    re.IGNORECASE,
)


_TEMPLATE_SUFFIXES = (".example", "-dist")
_GLOB_CHARS = ("*", "?", "[", "]")
_SAFE_SELECT_STRING_GLOB_EXTS = (
    ".py", ".ts", ".tsx", ".js", ".jsx", ".rs", ".go", ".java",
    ".cs", ".c", ".cpp", ".h", ".hpp", ".md", ".rst", ".html", ".css",
)


def _strip_win_trailing_dots_spaces(segment: str) -> str:
    """Windows strips trailing dots and spaces from path components."""
    return segment.rstrip(" .")


def _bash_unescape(text: str) -> str | None:
    """Simulate Git Bash unquoted backslash escaping (\\X -> X). Returns None on trailing lone \\."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            if i + 1 >= n:
                return None
            out.append(text[i + 1])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _has_glob_wildcard(text: str) -> bool:
    return any(ch in text for ch in _GLOB_CHARS)


def _is_safe_select_string_glob(path_str: str) -> bool:
    """Allow only narrow source-extension globs like 'src\\*.py' in Select-String -Path."""
    cleaned = path_str.replace("/", "\\")
    base = ntpath.basename(cleaned)
    parent = ntpath.dirname(cleaned)
    if _has_glob_wildcard(parent):
        return False
    # Must be a simple *.ext with a known safe source extension
    if not base.startswith("*.") or "?" in base or "[" in base or "]" in base or base.count("*") > 1:
        return False
    ext = base[1:].lower()
    return ext in _SAFE_SELECT_STRING_GLOB_EXTS


def _is_sensitive_filename(path_str: str) -> bool:
    replaced = path_str.replace("/", "\\").rstrip("\\")
    if not replaced:
        return False
    parts = [_strip_win_trailing_dots_spaces(p) for p in replaced.split("\\")]
    norm_joined = "\\".join(parts)
    low_full = norm_joined.lower()
    if "\\.ssh\\" in low_full or "\\.aws\\" in low_full or "\\.gnupg\\" in low_full:
        return True
    if low_full.endswith("\\.git\\config") or low_full == ".git\\config" or low_full.endswith("\\.git\\config\\"):
        return True
    base = parts[-1] if parts else ""
    if not base:
        return False
    if base.lower().endswith(_TEMPLATE_SUFFIXES):
        return False
    return bool(_SENSITIVE_FILENAME_RE.search(base))


def _is_safe_workspace_path(
    tok: Token,
    cwd: str,
    workspace_paths: list[str],
    *,
    check_sensitive: bool = True,
    allow_wildcards: bool = False,
    allow_safe_select_string_glob: bool = False,
) -> bool:
    """Validate a path token under both Windows/PowerShell and Git Bash semantics."""
    text = tok.text
    if not text:
        return False

    # PowerShell treats unquoted commas as array separators (e.g. Get-Content README.md,.env)
    if tok.quoted is None and "," in text:
        return False

    # Wildcards can match secret files unless explicitly allowed
    if _has_glob_wildcard(text):
        if allow_safe_select_string_glob and _is_safe_select_string_glob(text):
            pass
        elif not allow_wildcards:
            return False

    if not is_path_within_workspace(text, cwd, workspace_paths):
        return False
    if check_sensitive and _is_sensitive_filename(text):
        return False

    # Dual-shell check: Git Bash interprets unquoted `\` as an escape character
    if tok.quoted is None and "\\" in text:
        bash_path = _bash_unescape(text)
        if bash_path is None:
            return False
        if check_sensitive and _is_sensitive_filename(bash_path):
            return False
        if "/" in bash_path or ".." in bash_path or bash_path.startswith(("~", "/")):
            if not is_path_within_workspace(bash_path, cwd, workspace_paths):
                return False

    return True


def _check_git_readonly(args: list[Token], cwd: str, workspace_paths: list[str]) -> bool:
    if not args:
        return False
    if len(args) == 1 and args[0].normalized in ("--version", "-v"):
        return True

    idx = 0
    # Parse global git options before subcommand
    while idx < len(args) and args[idx].text.startswith("-"):
        flag = args[idx].text
        low = flag.lower()
        if flag == "-C":
            if idx + 1 >= len(args):
                return False
            if not _is_safe_workspace_path(args[idx + 1], cwd, workspace_paths, check_sensitive=False):
                return False
            idx += 2
            continue
        if flag == "-c" or any(low == f or low.startswith(f + "=") for f in _GIT_FORBIDDEN_GLOBAL_FLAGS):
            return False
        if low in ("--no-pager", "-p", "--paginate", "--bare", "--no-optional-locks"):
            idx += 1
            continue
        # Unknown global git flag -> defer to Layer 3
        return False

    if idx >= len(args):
        return False

    sub = args[idx].normalized
    sub_args = args[idx + 1 :]

    # Forbid --output file writing and external diff/textconv execution in diff/log/show
    for tok in sub_args:
        low = tok.normalized
        if low in ("--output", "--ext-diff", "--textconv") or low.startswith("--output="):
            return False

    if sub in _GIT_READONLY_SUBCOMMANDS:
        # Check pathspecs after `--` or path-like arguments stay inside workspace
        after_dd = False
        for tok in sub_args:
            if tok.text == "--":
                after_dd = True
                continue
            if after_dd or "/" in tok.text or "\\" in tok.text or ":" in tok.text:
                # Allow git revision specs like origin/main or HEAD:src/app.py unless Windows drive/escape
                if tok.text.startswith("-"):
                    continue
                if re.match(r"^[A-Za-z]:[\\/]", tok.text) or tok.text.startswith(("..", "/", "\\", "~")):
                    if not is_path_within_workspace(tok.text, cwd, workspace_paths):
                        return False
        return True

    if sub == "branch":
        # Must be strictly read-only listing (no positional branch creation, no -d/-D/-m/-M/-c/-C)
        if not sub_args:
            return True
        for tok in sub_args:
            low = tok.normalized
            base_flag = low.split("=", 1)[0]
            if base_flag not in _GIT_BRANCH_READONLY_FLAGS:
                return False
        return True

    if sub == "tag":
        if not sub_args:
            return True
        has_list = False
        i = 0
        while i < len(sub_args):
            low = sub_args[i].normalized
            base_flag = low.split("=", 1)[0]
            if base_flag in ("-l", "--list"):
                has_list = True
                i += 1
                # Optional glob pattern after -l/--list (e.g. git tag -l "v*")
                if i < len(sub_args) and not sub_args[i].text.startswith("-"):
                    i += 1
                continue
            if base_flag in _GIT_TAG_READONLY_FLAGS:
                i += 1
                continue
            return False
        return has_list

    return False


def _check_rg_or_grep(head: str, args: list[Token], cwd: str, workspace_paths: list[str]) -> bool:
    # Forbid arbitrary command execution flags in ripgrep/grep
    value_flags_rg = {
        "-e", "--regexp", "-f", "--file", "-g", "--glob", "--iglob",
        "-t", "--type", "-T", "--type-not", "-m", "--max-count",
        "-A", "-B", "-C", "--after-context", "--before-context", "--context",
        "--max-depth", "--max-filesize", "--color", "--encoding",
    }
    i = 0
    positionals: list[Token] = []
    has_explicit_pattern = False
    files_only_mode = False
    while i < len(args):
        tok = args[i]
        low = tok.normalized
        base = low.split("=", 1)[0]
        if base in ("--pre", "--pre-glob", "--files-from", "-f", "--file"):
            return False
        if tok.text == "--":
            positionals.extend(args[i + 1 :])
            break
        if tok.text.startswith("-") and len(tok.text) > 1:
            # Block short-flag clusters containing -f (pattern file)
            if not tok.text.startswith("--") and "f" in tok.text[1:]:
                return False
            if base == "--files":
                files_only_mode = True
                i += 1
                continue
            if base in ("-e", "--regexp"):
                has_explicit_pattern = True
                if "=" not in tok.text:
                    i += 2
                else:
                    i += 1
                continue
            if not tok.text.startswith("--") and "e" in tok.text[1:]:
                has_explicit_pattern = True
                # If `e` is the last char in a short-flag cluster (e.g. `-re`), next token is the pattern
                if tok.text.endswith("e"):
                    i += 2
                else:
                    i += 1
                continue
            if tok.text in value_flags_rg and "=" not in tok.text:
                i += 2
                continue
            i += 1
            continue
        positionals.append(tok)
        i += 1

    # When -e/--regexp or --files is given, ALL positionals are paths; otherwise first positional is pattern
    if has_explicit_pattern or files_only_mode:
        path_args = positionals
    else:
        path_args = positionals[1:] if len(positionals) > 1 else []
    for p in path_args:
        if not _is_safe_workspace_path(p, cwd, workspace_paths, check_sensitive=True):
            return False
    return True


def _check_fd(args: list[Token], cwd: str, workspace_paths: list[str]) -> bool:
    value_flags = {
        "-e", "--extension", "-t", "--type", "-d", "--max-depth", "--min-depth",
        "-E", "--exclude", "--base-directory", "--search-path", "-c", "--color",
        "-S", "--size", "--changed-within", "--changed-before", "--max-results",
    }
    i = 0
    positionals: list[Token] = []
    while i < len(args):
        tok = args[i]
        low = tok.normalized
        base = low.split("=", 1)[0]
        # Forbid command execution flags in fd (including grouped short flags like -Hx, -HX)
        if base in ("-x", "--exec", "-X", "--exec-batch"):
            return False
        if tok.text.startswith("-") and not tok.text.startswith("--"):
            if "x" in tok.text[1:] or "X" in tok.text[1:]:
                return False
        if base in ("--base-directory", "--search-path"):
            if "=" in tok.text:
                val_tok = Token(text=tok.text.split("=", 1)[1], raw=tok.raw, quoted=tok.quoted)
                i += 1
            else:
                if i + 1 >= len(args):
                    return False
                val_tok = args[i + 1]
                i += 2
            if not _is_safe_workspace_path(val_tok, cwd, workspace_paths, check_sensitive=True):
                return False
            continue
        if tok.text == "--":
            positionals.extend(args[i + 1 :])
            break
        if tok.text.startswith("-"):
            if tok.text in value_flags and "=" not in tok.text:
                i += 2
                continue
            i += 1
            continue
        positionals.append(tok)
        i += 1

    # In fd, if -e/-t is given with 1 positional, that positional could be path or pattern;
    # validate any positional that looks like a path or any positional beyond the first.
    for idx, p in enumerate(positionals):
        if idx > 0 or "/" in p.text or "\\" in p.text or p.text.startswith((".", "~")) or ":" in p.text:
            if not _is_safe_workspace_path(p, cwd, workspace_paths, check_sensitive=True):
                return False
    return True


def _check_select_string(args: list[Token], cwd: str, workspace_paths: list[str]) -> bool:
    i = 0
    saw_path = False
    while i < len(args):
        tok = args[i]
        low = tok.normalized
        if low in ("-path", "-literalpath"):
            if i + 1 >= len(args):
                return False
            if not _is_safe_workspace_path(
                args[i + 1],
                cwd,
                workspace_paths,
                check_sensitive=True,
                allow_safe_select_string_glob=True,
            ):
                return False
            saw_path = True
            i += 2
            continue
        if low in ("-pattern", "-include", "-exclude", "-context", "-encoding"):
            i += 2
            continue
        if low.startswith("-"):
            i += 1
            continue
        # Positional argument could be pattern or path; if it looks like a path check containment
        if "/" in tok.text or "\\" in tok.text or ":" in tok.text or tok.text.startswith((".", "~")):
            if not _is_safe_workspace_path(
                tok,
                cwd,
                workspace_paths,
                check_sensitive=True,
                allow_safe_select_string_glob=True,
            ):
                return False
            saw_path = True
        i += 1
    return saw_path


def _check_dir_list(args: list[Token], cwd: str, workspace_paths: list[str]) -> bool:
    value_flags = {"-filter", "-include", "-exclude", "-depth", "-attributes"}
    i = 0
    while i < len(args):
        tok = args[i]
        low = tok.normalized
        if low in ("-path", "-literalpath"):
            if i + 1 >= len(args):
                return False
            if not _is_safe_workspace_path(
                args[i + 1], cwd, workspace_paths, check_sensitive=False, allow_wildcards=True
            ):
                return False
            i += 2
            continue
        if low in value_flags:
            i += 2
            continue
        if tok.text.startswith("-"):
            i += 1
            continue
        if not _is_safe_workspace_path(
            tok, cwd, workspace_paths, check_sensitive=False, allow_wildcards=True
        ):
            return False
        i += 1
    return True


def _check_file_view(args: list[Token], cwd: str, workspace_paths: list[str], is_piped_in: bool) -> bool:
    value_flags = {
        "-head", "-totalcount", "-first", "-tail", "-last", "-readcount",
        "-encoding", "-delimiter", "-n", "-c", "--lines", "--bytes",
    }
    paths: list[Token] = []
    i = 0
    while i < len(args):
        tok = args[i]
        low = tok.normalized
        if low in ("-path", "-literalpath"):
            if i + 1 >= len(args):
                return False
            paths.append(args[i + 1])
            i += 2
            continue
        if low in value_flags and "=" not in low:
            i += 2
            continue
        if tok.text.startswith("-"):
            i += 1
            continue
        paths.append(tok)
        i += 1

    if not paths:
        return is_piped_in
    for p_tok in paths:
        if not _is_safe_workspace_path(p_tok, cwd, workspace_paths, check_sensitive=True):
            return False
    return True


def _check_pipeline_filter(head: str, args: list[Token], is_piped_in: bool) -> bool:
    if not is_piped_in:
        return False
    if head == "sort":
        sort_value_flags = {
            "-k", "--key", "-t", "--field-separator", "-S", "--buffer-size",
            "--parallel", "--sort", "--batch-size",
        }
        sort_forbidden_long = {
            "--output", "--compress-program", "--files0-from",
            "--temporary-directory", "--random-source",
        }
        i = 0
        while i < len(args):
            tok = args[i]
            low = tok.normalized
            base = low.split("=", 1)[0]
            if base in sort_forbidden_long:
                return False
            if tok.text == "--":
                # Any positional file after -- is forbidden for pipeline filter
                return i + 1 >= len(args)
            if tok.text.startswith("-") and len(tok.text) > 1:
                if not tok.text.startswith("--"):
                    # Block -o, -oFILE, -uoFILE, -T, -TDIR
                    if "o" in tok.text[1:] or "T" in tok.text[1:]:
                        return False
                if tok.text in sort_value_flags and "=" not in tok.text:
                    i += 2
                    continue
                i += 1
                continue
            # Positional file argument to sort -> defer to Layer 3
            return False
        return True

    if head == "uniq":
        uniq_value_flags = {
            "-f", "--skip-fields", "-s", "--skip-chars", "-w", "--check-chars",
            "--group", "--all-repeated",
        }
        i = 0
        while i < len(args):
            tok = args[i]
            if tok.text == "--":
                return i + 1 >= len(args)
            if tok.text.startswith("-") and len(tok.text) > 1:
                if tok.text in uniq_value_flags and "=" not in tok.text:
                    i += 2
                    continue
                i += 1
                continue
            # Positional INPUT/OUTPUT file arguments to uniq -> defer to Layer 3
            return False
        return True

    if head == "cut":
        cut_value_flags = {
            "-b", "--bytes", "-c", "--characters", "-d", "--delimiter",
            "-f", "--fields", "--output-delimiter",
        }
        i = 0
        while i < len(args):
            tok = args[i]
            if tok.text == "--":
                return i + 1 >= len(args)
            if tok.text.startswith("-") and len(tok.text) > 1:
                if tok.text in cut_value_flags and "=" not in tok.text:
                    i += 2
                    continue
                i += 1
                continue
            # Positional file argument to cut -> defer to Layer 3
            return False
        return True

    # PowerShell pipeline filters and `tr` (reads stdin only, never files)
    # PowerShell scriptblock expressions in Select-Object / Sort-Object are already caught by opaque `{}`
    return True


_GLAB_READONLY_SUBS: dict[str, set[str]] = {
    "issue": {"view", "list", "ls"},
    "mr": {"view", "list", "ls", "diff", "issues"},
    "ci": {"status", "list", "view", "get", "trace", "lint"},
    "job": {"list", "view", "trace"},
    "repo": {"view", "list", "ls", "search", "contributors"},
    "label": {"list", "ls"},
    "milestone": {"list", "ls", "get"},
    "release": {"list", "ls", "view"},
    "snippet": {"list", "ls", "view"},
    "epic": {"list", "ls", "view"},
    "iteration": {"list", "ls"},
    "schedule": {"list", "ls", "view"},
}

_GLAB_ALLOWED_WRITE_SUBS: dict[str, set[str]] = {
    "issue": {"create", "new", "update", "note", "comment", "close", "reopen", "subscribe", "unsubscribe"},
    "mr": {"note", "comment"},
    "label": {"create"},
    "milestone": {"create", "edit"},
}

_GH_READONLY_SUBS: dict[str, set[str]] = {
    "issue": {"view", "list", "ls", "status"},
    "pr": {"view", "list", "ls", "diff", "checks", "status"},
    "run": {"list", "ls", "view", "watch"},
    "workflow": {"list", "ls", "view"},
    "repo": {"view", "list", "ls"},
    "release": {"list", "ls", "view"},
    "label": {"list", "ls"},
    "search": {"issues", "prs", "repos", "commits", "code"},
    "gist": {"list", "ls", "view"},
    "project": {"list", "ls", "view", "item-list", "field-list"},
}

_GH_ALLOWED_WRITE_SUBS: dict[str, set[str]] = {
    "issue": {"create", "edit", "comment", "close", "reopen"},
    "pr": {"comment"},
    "label": {"create", "edit"},
}

_FORGE_READONLY_FORBIDDEN_LONG = {"--web", "--output-file", "--file"}
_FORGE_WRITE_FORBIDDEN_LONG = {
    "--body-file",
    "--description-file",
    "--file",
    "--input",
    "--editor",
    "--web",
    "--template",
    "--recover",
    "--resolve",
    "--unresolve",
}
_FORGE_API_FORBIDDEN_LONG = {"--field", "--raw-field", "--input", "--data", "--header"}


def _check_forge_api_readonly(sub_args: list[Token], is_piped_in: bool) -> bool:
    """Allow strictly GET-only `glab api` / `gh api` calls with no body/field/file flags."""
    if is_piped_in or not sub_args:
        return False
    value_flags = {"--jq", "-q", "--template", "-t", "--hostname", "--cache", "--preview", "-p"}
    positionals: list[Token] = []
    i = 0
    while i < len(sub_args):
        tok = sub_args[i]
        raw = tok.text
        low = tok.normalized
        base = low.split("=", 1)[0]

        if raw == "--":
            positionals.extend(sub_args[i + 1 :])
            break

        if base in _FORGE_API_FORBIDDEN_LONG:
            return False

        if base == "--method":
            if "=" in raw:
                method = raw.split("=", 1)[1].strip().upper()
                i += 1
            else:
                if i + 1 >= len(sub_args):
                    return False
                method = sub_args[i + 1].text.strip().upper()
                i += 2
            if method != "GET":
                return False
            continue

        if raw == "-X":
            if i + 1 >= len(sub_args):
                return False
            if sub_args[i + 1].text.strip().upper() != "GET":
                return False
            i += 2
            continue

        if raw.startswith("-X") and len(raw) > 2:
            if raw[2:].strip().upper() != "GET":
                return False
            i += 1
            continue

        if raw.startswith("-") and not raw.startswith("--") and len(raw) > 1:
            cluster = raw[1:]
            # -f/-F switch api to POST and support @file; -d/-H/-X mutate or send custom headers/methods
            if any(ch in cluster for ch in ("f", "F", "d", "H", "X")):
                return False
            if raw in value_flags:
                if i + 1 >= len(sub_args):
                    return False
                i += 2
                continue
            i += 1
            continue

        if raw.startswith("--"):
            if base in value_flags and "=" not in raw:
                if i + 1 >= len(sub_args):
                    return False
                i += 2
                continue
            i += 1
            continue

        positionals.append(tok)
        i += 1

    if len(positionals) != 1:
        return False
    endpoint = positionals[0].text.strip().lstrip("/").lower()
    if not endpoint or endpoint == "graphql" or endpoint.startswith("graphql/"):
        return False
    return True


def _check_forge_cli(
    head: str,
    args: list[Token],
    is_piped_in: bool,
    allowed_forge_cli_writes: set[str],
) -> str | None:
    """Validate read-only (built-in) and policy-opted-in non-MR write `glab`/`gh` commands.

    Returns 'readonly', 'write', or None (defer to Layer 3).
    """
    if not args:
        return None

    idx = 0
    # Parse leading global flags before subcommand
    while idx < len(args) and args[idx].text.startswith("-"):
        raw = args[idx].text
        low = args[idx].normalized
        base = low.split("=", 1)[0]
        if len(args) == 1 and low in ("--version", "--help", "-h"):
            return "readonly"
        if head == "glab" and len(args) == 1 and raw == "-v":
            return "readonly"
        if head == "glab" and base in ("-r", "--repo"):
            if "=" in raw:
                idx += 1
            else:
                if idx + 1 >= len(args):
                    return None
                idx += 2
            continue
        if head == "glab" and low == "--no-color":
            idx += 1
            continue
        return None

    if idx >= len(args):
        return None

    group = args[idx].normalized
    rest = args[idx + 1 :]

    if group == "version" and not rest:
        return "readonly"
    if head == "gh" and group == "status":
        for tok in rest:
            if tok.normalized.split("=", 1)[0] in _FORGE_READONLY_FORBIDDEN_LONG or tok.text == "-w":
                return None
        return "readonly"

    if group == "api":
        return "readonly" if _check_forge_api_readonly(rest, is_piped_in) else None

    if not rest:
        return None

    # Allow `glab issue board view ...`
    if head == "glab" and group == "issue" and rest[0].normalized == "board":
        if len(rest) >= 2 and rest[1].normalized == "view":
            sub_args = rest[2:]
            for tok in sub_args:
                base = tok.normalized.split("=", 1)[0]
                if base in _FORGE_READONLY_FORBIDDEN_LONG or tok.text == "-w":
                    return None
            return "readonly"
        return None

    action = rest[0].normalized
    sub_args = rest[1:]

    readonly_map = _GLAB_READONLY_SUBS if head == "glab" else _GH_READONLY_SUBS
    if action in readonly_map.get(group, ()):
        for tok in sub_args:
            raw = tok.text
            base = tok.normalized.split("=", 1)[0]
            if base in _FORGE_READONLY_FORBIDDEN_LONG:
                return None
            if raw == "-w" or (head == "glab" and group == "ci" and action == "lint" and raw == "-f"):
                return None
        return "readonly"

    if head in allowed_forge_cli_writes and not is_piped_in:
        write_map = _GLAB_ALLOWED_WRITE_SUBS if head == "glab" else _GH_ALLOWED_WRITE_SUBS
        if action in write_map.get(group, ()):
            for tok in sub_args:
                raw = tok.text
                base = tok.normalized.split("=", 1)[0]
                if base in _FORGE_WRITE_FORBIDDEN_LONG:
                    return None
                if raw.startswith("-") and not raw.startswith("--") and len(raw) > 1:
                    if any(ch in raw[1:] for ch in ("F", "e", "w")):
                        return None
            return "write"

    return None


def _check_segment_layer2(
    seg: CommandSegment,
    cwd: str,
    workspace_paths: list[str],
    allowed_ssh_read_hosts: set[str],
    allowed_forge_cli_writes: set[str],
) -> str | None:
    """Return a match category ('readonly', 'ssh_readonly', 'forge_readonly', 'forge_write') or None."""
    if seg.opaque_reasons or not seg.tokens:
        return None

    head = seg.head
    args = seg.args
    is_piped_in = seg.operator_before == "|"

    if head == "ssh" and allowed_ssh_read_hosts:
        return "ssh_readonly" if _check_ssh_readonly_segment(seg, allowed_ssh_read_hosts) else None

    if head in ("glab", "gh"):
        forge_kind = _check_forge_cli(head, args, is_piped_in, allowed_forge_cli_writes)
        if forge_kind == "readonly":
            return "forge_readonly"
        if forge_kind == "write":
            return "forge_write"
        return None

    if head in _ZERO_ARG_INFO_HEADS and not args:
        return "readonly"

    if head in _VERSION_ONLY_HEADS:
        if len(args) == 1:
            flag = args[0].text
            if flag == "--version":
                return "readonly"
            if flag == "-V" and head in ("python", "python3", "py", "uv", "ruff", "pytest", "rustc", "cargo"):
                return "readonly"
            if flag == "-v" and head in ("node", "npm", "git"):
                return "readonly"
        if head != "git":
            return None

    if head == "git":
        return "readonly" if _check_git_readonly(args, cwd, workspace_paths) else None

    if head in ("rg", "grep"):
        return "readonly" if _check_rg_or_grep(head, args, cwd, workspace_paths) else None

    if head == "fd":
        return "readonly" if _check_fd(args, cwd, workspace_paths) else None

    if head == "select-string":
        return "readonly" if _check_select_string(args, cwd, workspace_paths) else None

    if head in _DIR_LIST_HEADS:
        return "readonly" if _check_dir_list(args, cwd, workspace_paths) else None

    if head in _FILE_VIEW_HEADS:
        return "readonly" if _check_file_view(args, cwd, workspace_paths, is_piped_in) else None

    if head in _PIPELINE_FILTER_HEADS:
        return "readonly" if _check_pipeline_filter(head, args, is_piped_in) else None

    return None


def check_layer2_allow(
    parsed: ParsedCommand,
    cwd: str,
    workspace_paths: list[str],
    allowed_ssh_read_hosts: set[str] | list[str] | None = None,
    allowed_forge_cli_writes: set[str] | list[str] | None = None,
) -> RuleMatch | None:
    """Evaluate Layer 2 deterministic fast-allow rules (zero opaque constructs, all segments allowed)."""
    if parsed.has_opaque or not parsed.leaf_segments:
        return None
    if not workspace_paths or not cwd:
        return None
    if not is_path_within_workspace(cwd, cwd, workspace_paths):
        return None

    ssh_hosts = {h.strip().lower() for h in (allowed_ssh_read_hosts or []) if h and h.strip()}
    forge_writes = {c.strip().lower() for c in (allowed_forge_cli_writes or []) if c and c.strip()}

    kinds: set[str] = set()
    for seg in parsed.leaf_segments:
        kind = _check_segment_layer2(seg, cwd, workspace_paths, ssh_hosts, forge_writes)
        if kind is None:
            return None
        kinds.add(kind)

    heads = ", ".join(seg.head for seg in parsed.leaf_segments)
    if "forge_write" in kinds:
        return RuleMatch(
            decision="allow",
            rule_id="L2_FAST_ALLOW_FORGE_WRITE",
            reason=f"Layer 2 fast-allow: verified policy-allowed forge CLI write ({heads})",
        )
    if "ssh_readonly" in kinds:
        return RuleMatch(
            decision="allow",
            rule_id="L2_FAST_ALLOW_SSH_READONLY",
            reason=f"Layer 2 fast-allow: verified policy-allowed read-only ssh command ({heads})",
        )
    if "forge_readonly" in kinds:
        return RuleMatch(
            decision="allow",
            rule_id="L2_FAST_ALLOW_FORGE_READONLY",
            reason=f"Layer 2 fast-allow: verified read-only forge CLI command ({heads})",
        )
    return RuleMatch(
        decision="allow",
        rule_id="L2_FAST_ALLOW_READONLY",
        reason=f"Layer 2 fast-allow: verified read-only workspace command ({heads})",
    )
