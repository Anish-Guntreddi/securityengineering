"""Allowlist support for SecretHawk.

An :class:`Allowlist` can suppress findings via three mechanisms:

1. Path globs: files whose path matches any glob are skipped entirely.
2. Regex patterns: a finding is suppressed if its surrounding line (or the
   redacted preview) matches any configured regex pattern.
3. Inline ignores: a line containing the marker ``secrethawk:ignore`` or
   ``pragma: allowlist secret`` suppresses findings on that line.

Allowlists load from a ``.secrethawk.toml`` file using stdlib ``tomllib``.
"""

from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

INLINE_MARKERS = ("secrethawk:ignore", "pragma: allowlist secret")


@dataclass
class Allowlist:
    """Suppression configuration for a scan."""

    path_globs: list[str] = field(default_factory=list)
    patterns: list[re.Pattern] = field(default_factory=list)
    inline_markers: tuple[str, ...] = INLINE_MARKERS

    # ----- path globs -------------------------------------------------
    def is_path_allowlisted(self, path: str) -> bool:
        """Return True if ``path`` matches any configured glob."""
        norm = str(path).replace("\\", "/")
        base = norm.rsplit("/", 1)[-1]
        for glob in self.path_globs:
            if fnmatch.fnmatch(norm, glob) or fnmatch.fnmatch(base, glob):
                return True
            # Allow matching against any path suffix segment, e.g. a glob of
            # "secrets/*.pem" should match "a/b/secrets/x.pem".
            if "/" in glob and fnmatch.fnmatch(norm, "*/" + glob):
                return True
        return False

    # ----- inline ignores --------------------------------------------
    def line_has_inline_ignore(self, line: str) -> bool:
        """Return True if ``line`` contains an inline ignore marker."""
        lowered = line.lower()
        return any(marker.lower() in lowered for marker in self.inline_markers)

    # ----- regex pattern suppression ---------------------------------
    def is_suppressed_by_pattern(self, *texts: str) -> bool:
        """Return True if any configured regex matches any provided text."""
        for pattern in self.patterns:
            for text in texts:
                if text and pattern.search(text):
                    return True
        return False

    # ----- loading ----------------------------------------------------
    @classmethod
    def empty(cls) -> "Allowlist":
        """Return an allowlist that suppresses nothing extra."""
        return cls()

    @classmethod
    def from_dict(cls, data: dict) -> "Allowlist":
        """Build an Allowlist from a parsed TOML mapping.

        Recognised structure::

            [allowlist]
            paths = ["**/*.lock", "vendor/**"]
            patterns = ["EXAMPLE", "your-api-key-here"]
            inline_markers = ["secrethawk:ignore"]
        """
        section = data.get("allowlist", data) if isinstance(data, dict) else {}
        if not isinstance(section, dict):
            section = {}

        raw_paths = section.get("paths", []) or []
        raw_patterns = section.get("patterns", []) or []
        raw_markers = section.get("inline_markers")

        path_globs = [str(p) for p in raw_paths]
        compiled = [re.compile(str(p)) for p in raw_patterns]
        markers = (
            tuple(str(m) for m in raw_markers) if raw_markers else INLINE_MARKERS
        )
        return cls(path_globs=path_globs, patterns=compiled, inline_markers=markers)

    @classmethod
    def load(cls, path: str | Path) -> "Allowlist":
        """Load an allowlist from a ``.secrethawk.toml`` file.

        Returns an empty allowlist if the file does not exist.
        """
        p = Path(path)
        if not p.exists():
            return cls.empty()
        with p.open("rb") as fh:
            data = tomllib.load(fh)
        return cls.from_dict(data)

    @classmethod
    def discover(cls, root: str | Path) -> "Allowlist":
        """Load ``<root>/.secrethawk.toml`` if present, else empty."""
        candidate = Path(root) / ".secrethawk.toml"
        return cls.load(candidate)
