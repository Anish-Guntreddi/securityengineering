"""Pure scanning core for SecretHawk.

``scan_content`` is deterministic and performs no filesystem or git access.
It applies regex rules and then the entropy detector to each line, honours
inline ignores and allowlist patterns, and redacts every preview.
"""

from __future__ import annotations

from .allowlist import Allowlist
from .entropy import extract_candidate_tokens, is_high_entropy
from .models import Finding
from .rules import Rule, get_rules


def scan_content(
    text: str,
    path: str,
    allowlist: Allowlist | None = None,
    *,
    rules: list[Rule] | None = None,
    entropy_min_len: int = 20,
    entropy_threshold: float = 4.0,
) -> list[Finding]:
    """Scan ``text`` and return a deterministic list of findings.

    Args:
        text: The content to scan.
        path: Logical path/identifier reported on findings.
        allowlist: Optional :class:`Allowlist` for suppression. If None, an
            empty allowlist (no extra suppression) is used.
        rules: Override the rule set (defaults to :func:`get_rules`).
        entropy_min_len: Minimum token length for entropy detection.
        entropy_threshold: Minimum entropy (bits/char) for entropy detection.
    """
    allow = allowlist or Allowlist.empty()
    active_rules = rules if rules is not None else get_rules()

    findings: list[Finding] = []

    for lineno, line in enumerate(text.splitlines(), start=1):
        # Inline ignore suppresses every finding on this line.
        if allow.line_has_inline_ignore(line):
            continue

        # Track spans already claimed by a rule so the entropy detector does
        # not double-report the same secret.
        covered_spans: list[tuple[int, int]] = []

        # ---- regex rules ----
        for rule in active_rules:
            for match in rule.finditer(line):
                secret_text, start = _resolve_match(match)
                end = start + len(secret_text)

                if allow.is_suppressed_by_pattern(line, secret_text):
                    covered_spans.append((start, end))
                    continue

                findings.append(
                    Finding.from_match(
                        rule_id=rule.id,
                        description=rule.description,
                        severity=rule.severity,
                        file_path=path,
                        line=lineno,
                        column=start + 1,
                        raw_match=secret_text,
                        detector="rule",
                    )
                )
                covered_spans.append((start, end))

        # ---- entropy detector (only for tokens not covered by a rule) ----
        for token in extract_candidate_tokens(line):
            if not is_high_entropy(
                token, min_len=entropy_min_len, threshold=entropy_threshold
            ):
                continue

            idx = line.find(token)
            if idx < 0:
                continue
            tok_end = idx + len(token)

            # Skip if this token overlaps a span already covered by a rule.
            if any(
                not (tok_end <= cs or idx >= ce) for cs, ce in covered_spans
            ):
                continue

            if allow.is_suppressed_by_pattern(line, token):
                continue

            findings.append(
                Finding.from_match(
                    rule_id="high-entropy-string",
                    description="High-entropy string (possible generic secret)",
                    severity="medium",
                    file_path=path,
                    line=lineno,
                    column=idx + 1,
                    raw_match=token,
                    detector="entropy",
                )
            )
            covered_spans.append((idx, tok_end))

    return findings


def _resolve_match(match) -> tuple[str, int]:
    """Return (secret_text, start_index), preferring a named ``secret`` group."""
    groupdict = match.groupdict()
    if "secret" in groupdict and groupdict["secret"] is not None:
        return match.group("secret"), match.start("secret")
    return match.group(0), match.start()
