"""Filesystem and git-history walker for SecretHawk.

``walk_repo`` walks the working tree, respecting ``.gitignore`` and the
``.git/`` directory, skipping binary files (via a NUL-byte sniff), and feeds
text content into the pure :func:`scan_content` core. When ``scan_history``
is requested and the root is a git repository, it also scans historical blobs
via a READ-ONLY ``git log -p`` subprocess.
"""

from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

from .allowlist import Allowlist
from .models import Finding
from .scanner import scan_content

_NUL = b"\x00"
_MAX_BYTES = 2 * 1024 * 1024  # cap per-file read at 2 MiB for sanity


def _is_binary(data: bytes) -> bool:
    """Heuristically determine whether ``data`` is binary (NUL-byte sniff)."""
    return _NUL in data[:8192]


def _load_gitignore(root: Path) -> list[str]:
    """Return a list of gitignore glob patterns found at ``root``.

    A lightweight parser: supports simple globs and directory ignores. It is
    intentionally conservative (no negation/nested .gitignore semantics) which
    is sufficient for the scanner's "skip obvious noise" needs.
    """
    patterns: list[str] = []
    gi = root / ".gitignore"
    if not gi.exists():
        return patterns
    for raw in gi.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):  # negation unsupported; skip
            continue
        patterns.append(line.rstrip("/"))
    return patterns


def _is_gitignored(rel_path: str, patterns: list[str]) -> bool:
    """Return True if ``rel_path`` matches any gitignore ``patterns``."""
    norm = rel_path.replace("\\", "/")
    parts = norm.split("/")
    for pat in patterns:
        p = pat.replace("\\", "/")
        # Directory or any-depth match.
        if p in parts:
            return True
        if fnmatch.fnmatch(norm, p) or fnmatch.fnmatch(norm, "*/" + p):
            return True
        base = parts[-1]
        if fnmatch.fnmatch(base, p):
            return True
    return False


def _iter_files(root: Path):
    """Yield (absolute_path, relative_posix_path) for files under ``root``."""
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        rel = path.relative_to(root).as_posix()
        yield path, rel


def _is_git_repo(root: Path) -> bool:
    """Return True if ``root`` is (inside) a git working tree."""
    if (root / ".git").exists():
        return True
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    except (FileNotFoundError, OSError):  # pragma: no cover - git absent
        return False


def _scan_history(root: Path, allowlist: Allowlist) -> list[Finding]:
    """Scan historical blobs via a READ-ONLY ``git log -p``."""
    findings: list[Finding] = []
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "log", "-p", "--no-color", "--all"],
            capture_output=True,
            text=True,
            check=False,
        )
    except (FileNotFoundError, OSError):  # pragma: no cover - git absent
        return findings
    if proc.returncode != 0:
        return findings

    current_commit = "HISTORY"
    added_lines: list[str] = []

    def flush(ref: str):
        if not added_lines:
            return
        text = "\n".join(added_lines)
        findings.extend(
            scan_content(text, f"git-history:{ref}", allowlist)
        )
        added_lines.clear()

    for line in proc.stdout.splitlines():
        if line.startswith("commit "):
            flush(current_commit)
            current_commit = line.split()[1][:12]
        elif line.startswith("+") and not line.startswith("+++"):
            # Strip the leading '+' from added diff lines.
            added_lines.append(line[1:])
    flush(current_commit)
    return findings


def walk_repo(
    root: str | Path,
    scan_history: bool = False,
    allowlist: Allowlist | None = None,
) -> list[Finding]:
    """Walk ``root`` and return all findings.

    Args:
        root: Directory to scan (the working tree).
        scan_history: If True and ``root`` is a git repo, also scan history.
        allowlist: Optional :class:`Allowlist`; if None, one is discovered from
            ``<root>/.secrethawk.toml``.
    """
    root_path = Path(root).resolve()
    allow = allowlist if allowlist is not None else Allowlist.discover(root_path)
    gitignore = _load_gitignore(root_path)

    findings: list[Finding] = []

    for abs_path, rel in _iter_files(root_path):
        # Always skip the .git directory.
        if rel == ".git" or rel.startswith(".git/"):
            continue
        if _is_gitignored(rel, gitignore):
            continue
        if allow.is_path_allowlisted(rel):
            continue

        try:
            data = abs_path.read_bytes()
        except (OSError, PermissionError):  # pragma: no cover
            continue
        if _is_binary(data):
            continue
        if len(data) > _MAX_BYTES:
            data = data[:_MAX_BYTES]

        text = data.decode("utf-8", errors="replace")
        findings.extend(scan_content(text, rel, allow))

    if scan_history and _is_git_repo(root_path):
        findings.extend(_scan_history(root_path, allow))

    return findings
