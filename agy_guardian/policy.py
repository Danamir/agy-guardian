"""Per-project policy loader stored outside writable workspaces (fail-closed)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .config import expand_path
from .shell_parser import is_path_within_workspace, normalize_windows_path


@dataclass
class EffectivePolicy:
    """Merged per-project policy active for a single hook invocation."""

    matched_projects: list[str] = field(default_factory=list)
    extra_workspaces: list[str] = field(default_factory=list)
    allowed_write_paths: list[str] = field(default_factory=list)
    allowed_ssh_read_hosts: list[str] = field(default_factory=list)
    allowed_forge_cli_writes: list[str] = field(default_factory=list)
    allowed_urls: list[str] = field(default_factory=list)
    allowed_programs: list[str] = field(default_factory=list)
    policy_notes: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def has_rules(self) -> bool:
        return bool(
            self.extra_workspaces
            or self.allowed_write_paths
            or self.allowed_ssh_read_hosts
            or self.allowed_forge_cli_writes
            or self.allowed_urls
            or self.allowed_programs
            or self.policy_notes
        )

    @property
    def label(self) -> str | None:
        if self.matched_projects:
            return ",".join(self.matched_projects)
        return "defaults" if self.has_rules else None

    def to_layer3_context(self) -> dict[str, Any] | None:
        if not self.has_rules:
            return None
        ctx: dict[str, Any] = {}
        if self.matched_projects:
            ctx["projects"] = list(self.matched_projects)
        if self.extra_workspaces:
            ctx["extraWorkspaces"] = list(self.extra_workspaces)
        if self.allowed_write_paths:
            ctx["allowedWritePaths"] = list(self.allowed_write_paths)
        if self.allowed_ssh_read_hosts:
            ctx["allowedSshReadHosts"] = list(self.allowed_ssh_read_hosts)
        if self.allowed_forge_cli_writes:
            ctx["allowedForgeCliWrites"] = list(self.allowed_forge_cli_writes)
        if self.allowed_urls:
            ctx["allowedUrls"] = list(self.allowed_urls)
        if self.allowed_programs:
            ctx["allowedPrograms"] = list(self.allowed_programs)
        if self.policy_notes:
            ctx["notes"] = " ".join(self.policy_notes)
        return ctx


def _expand_policy_path(raw: str) -> str:
    cleaned = raw.strip()
    if not cleaned:
        return ""
    # Preserve UNC paths without Path.expanduser corrupting leading backslashes
    if cleaned.startswith(("\\\\", "//")):
        return cleaned.replace("/", "\\").rstrip("\\")
    return str(expand_path(cleaned))


def _dedupe_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in paths:
        expanded = _expand_policy_path(raw)
        if not expanded:
            continue
        norm = normalize_windows_path(expanded)
        if norm not in seen:
            seen.add(norm)
            out.append(expanded)
    return out


def _dedupe_hosts(hosts: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for h in hosts:
        cleaned = str(h).strip().lower()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            out.append(cleaned)
    return out


_VALID_FORGE_CLIS = frozenset({"glab", "gh"})
_PROGRAM_UNSAFE_RE = re.compile(r"[;&|`$<>\r\n\"']")


def normalize_policy_url(raw: str) -> str | None:
    """Validate and normalize an http(s) URL prefix for Layer 3 projectPolicy."""
    cleaned = str(raw).strip()
    if not cleaned or any(ch.isspace() for ch in cleaned):
        return None
    try:
        parsed = urlsplit(cleaned)
    except Exception:
        return None
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return None
    if not parsed.hostname or parsed.username or parsed.password:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port is not None else host
    path = (parsed.path or "").rstrip("/")
    return f"{scheme}://{netloc}{path}"


def _dedupe_urls(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in urls:
        norm = normalize_policy_url(raw)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def normalize_policy_program(raw: str) -> str | None:
    """Validate and normalize an executable name or path/glob for Layer 3 projectPolicy."""
    cleaned = str(raw).strip()
    if not cleaned or _PROGRAM_UNSAFE_RE.search(cleaned):
        return None
    # Expand ~ / env vars only when it looks like a path
    if any(sep in cleaned for sep in ("\\", "/")) or cleaned.startswith("~"):
        if cleaned.startswith(("\\\\", "//")):
            expanded = cleaned.replace("/", "\\").rstrip("\\")
        else:
            expanded = str(expand_path(cleaned))
        return expanded
    return cleaned


def _dedupe_programs(programs: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in programs:
        norm = normalize_policy_program(raw)
        if not norm:
            continue
        key = norm.lower()
        if key not in seen:
            seen.add(key)
            out.append(norm)
    return out


def _dedupe_forge_clis(clis: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for c in clis:
        cleaned = str(c).strip().lower()
        if cleaned in _VALID_FORGE_CLIS and cleaned not in seen:
            seen.add(cleaned)
            out.append(cleaned)
    return out


def _str_list(obj: Any) -> list[str]:
    if not isinstance(obj, list):
        return []
    return [str(x).strip() for x in obj if isinstance(x, str) and x.strip()]


def _workspace_matches_any(
    active_paths: list[str],
    match_roots: list[str],
) -> bool:
    expanded_roots = [_expand_policy_path(r) for r in match_roots if r.strip()]
    if not expanded_roots:
        return False
    for active in active_paths:
        if not active:
            continue
        if is_path_within_workspace(active, active, expanded_roots):
            return True
    return False


def _merge_section(
    target_extra: list[str],
    target_writes: list[str],
    target_hosts: list[str],
    target_forge_writes: list[str],
    target_urls: list[str],
    target_programs: list[str],
    target_notes: list[str],
    section: dict[str, Any],
) -> None:
    target_extra.extend(_str_list(section.get("extraWorkspaces")))
    target_writes.extend(_str_list(section.get("allowedWritePaths")))
    target_hosts.extend(_str_list(section.get("allowedSshReadHosts")))
    target_forge_writes.extend(_str_list(section.get("allowedForgeCliWrites")))
    target_urls.extend(_str_list(section.get("allowedUrls")))
    target_programs.extend(_str_list(section.get("allowedPrograms")))
    note = section.get("policyNotes")
    if isinstance(note, str) and note.strip():
        target_notes.append(note.strip())


def load_effective_policy(
    *,
    policy_path: Path | None,
    cwd: str,
    workspace_paths: list[str],
    env_extra_workspaces: list[str] | None = None,
) -> EffectivePolicy:
    """Load and resolve per-project policies safely (fail-closed on any error or workspace tampering)."""
    extra_ws: list[str] = list(env_extra_workspaces or [])
    allowed_writes: list[str] = []
    ssh_hosts: list[str] = []
    forge_writes: list[str] = []
    allowed_urls: list[str] = []
    allowed_programs: list[str] = []
    notes: list[str] = []
    matched: list[str] = []

    if policy_path is None or not policy_path.is_file():
        return EffectivePolicy(extra_workspaces=_dedupe_paths(extra_ws))

    # Security boundary: refuse to load a policy file stored inside a writable workspace
    resolved_policy_str = str(policy_path.resolve())
    if workspace_paths and is_path_within_workspace(resolved_policy_str, cwd, workspace_paths):
        return EffectivePolicy(
            extra_workspaces=_dedupe_paths(extra_ws),
            error="Refused to load policy file inside writable workspacePaths",
        )

    try:
        data = json.loads(policy_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        return EffectivePolicy(
            extra_workspaces=_dedupe_paths(extra_ws),
            error=f"Failed to parse policy file ({type(exc).__name__}: {exc})",
        )

    if not isinstance(data, dict):
        return EffectivePolicy(
            extra_workspaces=_dedupe_paths(extra_ws),
            error="Malformed policy file (root must be a JSON object)",
        )

    defaults = data.get("defaults")
    if isinstance(defaults, dict):
        _merge_section(
            extra_ws,
            allowed_writes,
            ssh_hosts,
            forge_writes,
            allowed_urls,
            allowed_programs,
            notes,
            defaults,
        )

    active_paths = list(workspace_paths) if workspace_paths else ([cwd] if cwd else [])
    projects = data.get("projects")
    if isinstance(projects, list) and active_paths:
        for idx, entry in enumerate(projects):
            if not isinstance(entry, dict):
                continue
            match_roots = _str_list(entry.get("matchWorkspaces"))
            if not match_roots:
                continue
            if _workspace_matches_any(active_paths, match_roots):
                proj_name = str(entry.get("name") or f"project_{idx}").strip()
                matched.append(proj_name)
                _merge_section(
                    extra_ws,
                    allowed_writes,
                    ssh_hosts,
                    forge_writes,
                    allowed_urls,
                    allowed_programs,
                    notes,
                    entry,
                )

    return EffectivePolicy(
        matched_projects=matched,
        extra_workspaces=_dedupe_paths(extra_ws),
        allowed_write_paths=_dedupe_paths(allowed_writes),
        allowed_ssh_read_hosts=_dedupe_hosts(ssh_hosts),
        allowed_forge_cli_writes=_dedupe_forge_clis(forge_writes),
        allowed_urls=_dedupe_urls(allowed_urls),
        allowed_programs=_dedupe_programs(allowed_programs),
        policy_notes=notes,
    )
