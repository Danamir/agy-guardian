"""Windows PowerShell 5.1 & Git Bash lexical parser, compound splitter, and wrapper stripper."""

from __future__ import annotations

import ntpath
import re
from dataclasses import dataclass, field

MAX_UNWRAP_DEPTH = 4

_PS_PROVIDER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]+:(?![\\/])")
_PS_DRIVE_PROVIDER_RE = re.compile(r"^[A-Za-z]{2,}:")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_WSL_UNC_RE = re.compile(r"^(?:\\\\|//)(?:wsl\.localhost|wsl\$)[\\/][^\\/]+(?:[\\/].*)?$", re.IGNORECASE)
_ENV_PERCENT_RE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%")
_VAR_DOLLAR_RE = re.compile(r"\$(?:[A-Za-z_?*$@]|\{)")
_TIMEOUT_NUM_RE = re.compile(r"^\d+(?:\.\d+)?[smhd]?$", re.IGNORECASE)
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")

_PS_ENCODED_FLAGS = {
    "-e",
    "-ec",
    "-enc",
    "-enco",
    "-encod",
    "-encode",
    "-encoded",
    "-encodedc",
    "-encodedco",
    "-encodedcom",
    "-encodedcomm",
    "-encodedcomma",
    "-encodedcomman",
    "-encodedcommand",
}
_PS_CMD_FLAGS = {"-c", "-co", "-com", "-comm", "-comma", "-comman", "-command"}
_PS_BENIGN_NO_ARG_FLAGS = {
    "-noprofile",
    "-nop",
    "-noninteractive",
    "-noni",
    "-nologo",
    "-nol",
    "-sta",
    "-mta",
}
_PS_SUSPICIOUS_EP_FLAGS = {"-ep", "-exec", "-executionpolicy"}
_PS_SUSPICIOUS_WIN_FLAGS = {"-w", "-win", "-windowstyle"}


@dataclass
class Token:
    text: str
    raw: str
    quoted: str | None = None  # None | "'" | '"'

    @property
    def normalized(self) -> str:
        """Lowercased text with PowerShell escape backticks removed when unquoted."""
        if self.quoted is None:
            return self.text.replace("`", "").lower()
        return self.text.lower()


@dataclass
class CommandSegment:
    raw: str
    tokens: list[Token]
    operator_before: str | None = None
    pipeline_group: int = 0
    unwrapped_from: tuple[str, ...] = ()
    opaque_reasons: list[str] = field(default_factory=list)
    wrapper_tokens: list[Token] = field(default_factory=list)
    is_wrapper_shell: bool = False

    @property
    def head(self) -> str:
        if not self.tokens:
            return ""
        return normalize_command_head(self.tokens[0].normalized)

    @property
    def args(self) -> list[Token]:
        return self.tokens[1:] if len(self.tokens) > 1 else []


@dataclass
class ParsedCommand:
    raw: str
    # All segments including wrapper shells (for Layer 1 inspection)
    all_segments: list[CommandSegment] = field(default_factory=list)
    # Leaf executable segments after transparent wrapper unwrapping (for Layer 2)
    leaf_segments: list[CommandSegment] = field(default_factory=list)
    opaque_reasons: list[str] = field(default_factory=list)
    parse_error: str | None = None

    @property
    def has_opaque(self) -> bool:
        if self.parse_error or self.opaque_reasons:
            return True
        return any(seg.opaque_reasons for seg in self.all_segments)


def normalize_command_head(raw_head: str) -> str:
    """Normalize a command head: strip backticks, path prefix if standard .exe, lowercase."""
    cleaned = raw_head.replace("`", "").strip().lower()
    if not cleaned:
        return ""
    # Strip trailing .exe for matching (e.g., curl.exe -> curl, ls.exe -> ls)
    if cleaned.endswith(".exe") and "/" not in cleaned and "\\" not in cleaned:
        return cleaned[:-4]
    return cleaned


def _split_raw_segments(command: str) -> tuple[list[tuple[str | None, str]], list[str], str | None]:
    """Split a shell command on unquoted &&, ||, ;, |, and newlines, stripping unquoted # comments."""
    segments: list[tuple[str | None, str]] = []
    opaque: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    op_before: str | None = None
    i = 0
    n = len(command)

    def flush(next_op: str | None) -> None:
        nonlocal op_before
        seg_text = "".join(buf).strip()
        buf.clear()
        if seg_text:
            segments.append((op_before, seg_text))
        op_before = next_op

    while i < n:
        ch = command[i]
        nxt = command[i + 1] if i + 1 < n else ""

        if quote is not None:
            buf.append(ch)
            if quote == '"':
                if ch == "\\" and nxt == '"':
                    buf.append(nxt)
                    i += 2
                    continue
                if ch == "`" and nxt in ('"', "`"):
                    if "backtick" not in opaque:
                        opaque.append("backtick")
                    buf.append(nxt)
                    i += 2
                    continue
                if ch == '"':
                    quote = None
            elif quote == "'":
                if ch == "'":
                    quote = None
            i += 1
            continue

        # Unquoted context
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue

        # Unquoted comment starts after whitespace or at start of segment
        if ch == "#" and (not buf or buf[-1].isspace()):
            while i < n and command[i] not in ("\n", "\r"):
                i += 1
            continue

        if ch in ("\r", "\n"):
            if "newline" not in opaque:
                opaque.append("newline")
            if ch == "\r" and nxt == "\n":
                i += 2
            else:
                i += 1
            flush("\n")
            continue

        if ch == "&" and nxt == "&":
            flush("&&")
            i += 2
            continue

        if ch == "|" and nxt == "|":
            flush("||")
            i += 2
            continue

        if ch == ";":
            flush(";")
            i += 1
            continue

        if ch == "|":
            flush("|")
            i += 1
            continue

        buf.append(ch)
        i += 1

    if quote is not None:
        return [], opaque, f"Unclosed {quote} quote"

    flush(None)
    return segments, opaque, None


def _tokenize_segment(segment: str) -> tuple[list[Token], list[str], str | None]:
    """Tokenize a single command segment while tracking quotes and opaque shell constructs."""
    tokens: list[Token] = []
    opaque: list[str] = []
    i = 0
    n = len(segment)

    def add_opaque(reason: str) -> None:
        if reason not in opaque:
            opaque.append(reason)

    while i < n:
        while i < n and segment[i].isspace():
            i += 1
        if i >= n:
            break

        text_parts: list[str] = []
        raw_parts: list[str] = []
        first_quote: str | None = None
        mixed_or_unquoted = False
        had_quotes = False
        start_i = i

        while i < n and not segment[i].isspace():
            ch = segment[i]
            nxt = segment[i + 1] if i + 1 < n else ""

            if ch in ("'", '"'):
                q = ch
                had_quotes = True
                if first_quote is None and i == start_i:
                    first_quote = q
                else:
                    mixed_or_unquoted = True
                raw_parts.append(q)
                i += 1
                inner_start = i
                closed = False
                while i < n:
                    c = segment[i]
                    c_nxt = segment[i + 1] if i + 1 < n else ""
                    if q == '"':
                        if c == "\\" and c_nxt == '"':
                            text_parts.append('"')
                            raw_parts.append('\\"')
                            i += 2
                            continue
                        if c == "`":
                            add_opaque("backtick")
                            if c_nxt in ('"', "`", "$"):
                                text_parts.append(c_nxt)
                                raw_parts.append(c + c_nxt)
                                i += 2
                                continue
                        if c == '"':
                            raw_parts.append('"')
                            i += 1
                            closed = True
                            break
                    else:
                        if c == "'":
                            raw_parts.append("'")
                            i += 1
                            closed = True
                            break
                    text_parts.append(c)
                    raw_parts.append(c)
                    i += 1

                if not closed:
                    return [], opaque, f"Unclosed {q} quote in segment"

                inner_str = segment[inner_start : i - 1]
                if q == '"':
                    _scan_expandable_text(inner_str, add_opaque)
                continue

            # Unquoted character
            mixed_or_unquoted = True
            if ch == "`":
                add_opaque("backtick")
            text_parts.append(ch)
            raw_parts.append(ch)
            i += 1

        tok_text = "".join(text_parts)
        tok_raw = "".join(raw_parts)
        tok_quoted = first_quote if (had_quotes and not mixed_or_unquoted) else None

        # Inspect unquoted token content for opaque constructs
        if tok_quoted is None:
            _scan_unquoted_token(tok_raw, add_opaque)

        tokens.append(Token(text=tok_text, raw=tok_raw, quoted=tok_quoted))

    return tokens, opaque, None


def _scan_expandable_text(text: str, add_opaque) -> None:
    if "$(" in text or "@(" in text or "${" in text:
        add_opaque("subexpression")
    if "`" in text:
        add_opaque("backtick")
    if _VAR_DOLLAR_RE.search(text):
        add_opaque("variable_expansion")
    if _ENV_PERCENT_RE.search(text):
        add_opaque("env_expansion")


def _scan_unquoted_token(raw: str, add_opaque) -> None:
    if raw == "2>&1":
        return
    # Scan only portions outside quotes
    unquoted_chars: list[str] = []
    q: str | None = None
    i = 0
    while i < len(raw):
        ch = raw[i]
        if q is not None:
            if q == '"' and ch == "\\" and i + 1 < len(raw) and raw[i + 1] == '"':
                i += 2
                continue
            if ch == q:
                q = None
            i += 1
            continue
        if ch in ("'", '"'):
            q = ch
            i += 1
            continue
        unquoted_chars.append(ch)
        i += 1

    unquoted = "".join(unquoted_chars)
    if not unquoted:
        return
    _scan_expandable_text(unquoted, add_opaque)
    if ">" in unquoted or "<" in unquoted:
        add_opaque("redirection")
    if "{" in unquoted or "}" in unquoted:
        add_opaque("script_block")
    if "(" in unquoted or ")" in unquoted:
        add_opaque("subshell_or_grouping")
    if "&" in unquoted:
        add_opaque("call_or_background_op")
    if unquoted == ".":
        # Dot-sourcing checked at segment head level, not as path argument `.`
        pass


def _normalize_cmd_caret_escapes(text: str) -> tuple[str, bool]:
    """Strip unquoted cmd.exe `^` escape characters and report whether any were found."""
    if "^" not in text:
        return text, False
    out: list[str] = []
    in_double = False
    found = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            in_double = not in_double
            out.append(ch)
            i += 1
            continue
        if not in_double and ch == "^":
            found = True
            if i + 1 < n:
                out.append(text[i + 1])
                i += 2
            else:
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), found


def _extract_wrapper_inner(
    seg: CommandSegment,
) -> tuple[str | None, str | None, list[str]]:
    """If seg is a shell/execution wrapper, return (wrapper_name, inner_command, extra_opaque)."""
    if not seg.tokens:
        return None, None, []

    head = seg.head
    args = seg.args
    extra_opaque: list[str] = []

    if head == "cmd":
        for idx, tok in enumerate(args):
            low = tok.normalized
            if low in ("/c", "/k"):
                if low == "/k":
                    extra_opaque.append("interactive_cmd_k")
                rest = args[idx + 1 :]
                if not rest:
                    return "cmd", None, extra_opaque + ["empty_wrapper"]
                inner = rest[0].text if len(rest) == 1 else " ".join(t.raw for t in rest)
                inner_norm, had_caret = _normalize_cmd_caret_escapes(inner)
                if had_caret:
                    extra_opaque.append("cmd_caret_escape")
                    inner = inner_norm
                return "cmd", inner, extra_opaque
        return None, None, []

    if head in ("powershell", "pwsh"):
        idx = 0
        while idx < len(args):
            low = args[idx].normalized
            if low in _PS_ENCODED_FLAGS or low.startswith("-enc"):
                extra_opaque.append("encoded_command")
                return head, None, extra_opaque
            if low in _PS_SUSPICIOUS_EP_FLAGS:
                val = args[idx + 1].normalized if idx + 1 < len(args) else ""
                if val in ("bypass", "unrestricted"):
                    extra_opaque.append("execution_policy_bypass")
                else:
                    extra_opaque.append("wrapper_flag")
                idx += 2
                continue
            if low in _PS_SUSPICIOUS_WIN_FLAGS:
                val = args[idx + 1].normalized if idx + 1 < len(args) else ""
                if val in ("hidden", "h", "1"):
                    extra_opaque.append("hidden_window")
                else:
                    extra_opaque.append("wrapper_flag")
                idx += 2
                continue
            if low in _PS_BENIGN_NO_ARG_FLAGS:
                idx += 1
                continue
            if low in _PS_CMD_FLAGS:
                rest = args[idx + 1 :]
                if not rest:
                    return head, None, extra_opaque + ["empty_wrapper"]
                inner = rest[0].text if len(rest) == 1 else " ".join(t.raw for t in rest)
                return head, inner, extra_opaque
            # Unknown powershell flag or script file
            extra_opaque.append("unknown_wrapper_arg")
            return head, None, extra_opaque
        return None, None, []

    if head in ("bash", "sh"):
        idx = 0
        while idx < len(args):
            low = args[idx].normalized
            if low == "-c":
                rest = args[idx + 1 :]
                if not rest:
                    return head, None, extra_opaque + ["empty_wrapper"]
                inner = rest[0].text if len(rest) == 1 else " ".join(t.raw for t in rest)
                return head, inner, extra_opaque
            if low in ("-l", "--login", "-e", "-u"):
                idx += 1
                continue
            extra_opaque.append("unknown_wrapper_arg")
            return head, None, extra_opaque
        return None, None, []

    if head == "env":
        idx = 0
        while idx < len(args):
            raw_arg = args[idx].raw
            if _ENV_ASSIGN_RE.match(args[idx].text) and args[idx].quoted is None:
                idx += 1
                continue
            if raw_arg.startswith("-"):
                extra_opaque.append("env_flag")
                return "env", None, extra_opaque
            break
        rest = args[idx:]
        if not rest:
            return None, None, []
        inner = " ".join(t.raw for t in rest)
        return "env", inner, extra_opaque

    if head == "timeout":
        idx = 0
        while idx < len(args) and args[idx].text.startswith("-"):
            if args[idx].text in ("-k", "--kill-after", "-s", "--signal"):
                idx += 2
            else:
                idx += 1
        if idx < len(args) and _TIMEOUT_NUM_RE.match(args[idx].text):
            rest = args[idx + 1 :]
            if rest:
                inner = " ".join(t.raw for t in rest)
                return "timeout", inner, extra_opaque
        return None, None, []

    return None, None, []


def parse_command(command: str, _depth: int = 0, _unwrapped_from: tuple[str, ...] = ()) -> ParsedCommand:
    """Parse a shell command into decomposed, wrapper-stripped segments."""
    result = ParsedCommand(raw=command)
    if not command or not command.strip():
        result.parse_error = "Empty command"
        return result

    raw_segs, split_opaque, split_err = _split_raw_segments(command)
    result.opaque_reasons.extend(split_opaque)
    if split_err:
        result.parse_error = split_err
        return result

    pipe_group = 0
    for op_before, seg_str in raw_segs:
        if op_before != "|":
            pipe_group += 1

        tokens, tok_opaque, tok_err = _tokenize_segment(seg_str)
        if tok_err:
            result.parse_error = tok_err
            return result
        if not tokens:
            continue

        # Dot-sourcing in PowerShell/Bash (`. script.ps1`) is opaque
        if tokens[0].text == "." and tokens[0].quoted is None:
            tok_opaque.append("dot_sourcing")

        seg = CommandSegment(
            raw=seg_str,
            tokens=tokens,
            operator_before=op_before,
            pipeline_group=pipe_group,
            unwrapped_from=_unwrapped_from,
            opaque_reasons=list(tok_opaque),
        )

        wrapper_name, inner_cmd, wrapper_opaque = _extract_wrapper_inner(seg)
        if wrapper_opaque:
            for r in wrapper_opaque:
                if r not in seg.opaque_reasons:
                    seg.opaque_reasons.append(r)

        if wrapper_name is not None and inner_cmd is not None:
            seg.is_wrapper_shell = True
            result.all_segments.append(seg)
            if _depth >= MAX_UNWRAP_DEPTH:
                seg.opaque_reasons.append("max_unwrap_depth")
                result.leaf_segments.append(seg)
                continue

            sub = parse_command(
                inner_cmd,
                _depth=_depth + 1,
                _unwrapped_from=_unwrapped_from + (wrapper_name,),
            )
            if sub.parse_error:
                result.parse_error = sub.parse_error
                return result
            for r in sub.opaque_reasons:
                if r not in result.opaque_reasons:
                    result.opaque_reasons.append(r)
            # Propagate wrapper's own suspicious opaque reasons down to leaf segments
            for child in sub.all_segments:
                for r in seg.opaque_reasons:
                    if r not in child.opaque_reasons:
                        child.opaque_reasons.append(r)
                result.all_segments.append(child)
            for child in sub.leaf_segments:
                result.leaf_segments.append(child)
        else:
            result.all_segments.append(seg)
            result.leaf_segments.append(seg)

    return result


def is_wsl_unc_path(path_str: str) -> bool:
    """Return True if path_str is a Windows WSL UNC path (\\\\wsl.localhost\\... or \\\\wsl$\\...)."""
    return bool(_WSL_UNC_RE.match(path_str.strip()))


def normalize_windows_path(path_str: str) -> str:
    """Normalize a Windows or WSL UNC path case-insensitively with backslash separators."""
    replaced = path_str.replace("/", "\\")
    return ntpath.normcase(ntpath.normpath(replaced))


def is_path_within_workspace(
    raw_path: str,
    cwd: str,
    workspace_paths: list[str],
) -> bool:
    """Return True iff raw_path resolves strictly inside at least one workspacePaths entry."""
    if not workspace_paths or not raw_path:
        return False

    cleaned = raw_path.strip().strip('"').strip("'")
    if not cleaned:
        return False

    # Reject home shortcuts, env expansions, POSIX root paths, and PS providers (Env:, HKLM:, etc.)
    if cleaned.startswith(("~", "$", "%")):
        return False
    if cleaned.startswith(("\\\\", "//")):
        # Allow UNC paths ONLY for explicit WSL UNC roots; block arbitrary network shares (\\host\share)
        if not is_wsl_unc_path(cleaned):
            return False
        resolved = normalize_windows_path(cleaned)
    elif cleaned.startswith("/"):
        return False
    elif _PS_DRIVE_PROVIDER_RE.match(cleaned) or _PS_PROVIDER_RE.match(cleaned):
        return False
    elif _WINDOWS_DRIVE_RE.match(cleaned):
        resolved = normalize_windows_path(cleaned)
    else:
        if not cwd:
            return False
        resolved = normalize_windows_path(ntpath.join(cwd.replace("/", "\\"), cleaned.replace("/", "\\")))

    for ws in workspace_paths:
        if not ws:
            continue
        ws_clean = ws.strip().strip('"').strip("'")
        if ws_clean.startswith(("\\\\", "//")) and not is_wsl_unc_path(ws_clean):
            continue
        ws_norm = normalize_windows_path(ws_clean)
        if resolved == ws_norm:
            return True
        prefix = ws_norm if ws_norm.endswith("\\") else ws_norm + "\\"
        if resolved.startswith(prefix):
            return True
    return False
