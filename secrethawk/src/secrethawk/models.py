"""Data models for SecretHawk findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Detector = Literal["rule", "entropy"]
Severity = Literal["low", "medium", "high", "critical"]


def redact(value: str) -> str:
    """Redact a secret-looking value for safe display.

    Shows only the first 4 and last 2 characters; the middle is masked
    with asterisks. Very short values are fully masked so that nothing
    sensitive leaks into reports or terminals.

    Examples:
        "TOKEN0123456789abcdEF" -> "TOKE***************EF"
        "short"                 -> "*****"
    """
    if value is None:
        return ""
    # Operate on the raw token only (callers pass the matched secret).
    text = value
    n = len(text)
    # If revealing first 4 + last 2 would expose (almost) the whole string,
    # mask everything to avoid leaking short secrets.
    if n <= 6:
        return "*" * n
    head = text[:4]
    tail = text[-2:]
    masked = "*" * (n - 6)
    return f"{head}{masked}{tail}"


@dataclass(frozen=True)
class Finding:
    """A single secret detection result.

    Attributes:
        rule_id: Identifier of the rule or "entropy" detector that fired.
        description: Human-readable description of what was detected.
        severity: One of low | medium | high | critical.
        file_path: Path (or git ref) where the match was found.
        line: 1-based line number.
        column: 1-based column number of the match start.
        match_preview: REDACTED preview of the matched secret.
        detector: Whether the finding came from a "rule" or "entropy" check.
    """

    rule_id: str
    description: str
    severity: Severity
    file_path: str
    line: int
    column: int
    match_preview: str
    detector: Detector = "rule"
    # Optional metadata, never part of equality/hash for determinism of the
    # core fields above.
    metadata: dict = field(default_factory=dict, compare=False, hash=False)

    @classmethod
    def from_match(
        cls,
        *,
        rule_id: str,
        description: str,
        severity: Severity,
        file_path: str,
        line: int,
        column: int,
        raw_match: str,
        detector: Detector = "rule",
    ) -> "Finding":
        """Construct a Finding, redacting ``raw_match`` into a preview."""
        return cls(
            rule_id=rule_id,
            description=description,
            severity=severity,
            file_path=file_path,
            line=line,
            column=column,
            match_preview=redact(raw_match),
            detector=detector,
        )

    def to_dict(self) -> dict:
        """Serialize to a plain JSON-friendly dict (no raw secret)."""
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "match_preview": self.match_preview,
            "detector": self.detector,
        }
