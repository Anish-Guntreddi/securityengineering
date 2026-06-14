"""Shannon-entropy based detection of generic high-entropy secrets.

This module flags long, random-looking strings that the precise regex
rules do not already cover. It is intentionally conservative: it only
considers reasonably long tokens drawn from quoted strings and the
right-hand side of assignments, and applies an entropy threshold.
"""

from __future__ import annotations

import math
import re

# Quoted strings: '...' or "..."
_QUOTED = re.compile(r"""(['"])(?P<val>[^'"\n]+)\1""")

# Assignment right-hand-side: key = value / key: value, value may be bare
# or quoted. We capture the value token (stop at whitespace/quote/comment).
_ASSIGN = re.compile(
    r"""(?ix)
    [A-Za-z_][A-Za-z0-9_\-]*       # an identifier-ish key
    \s*[:=]\s*
    ['"]?                          # optional opening quote
    (?P<val>[A-Za-z0-9+/=_\-.]{8,})  # the value token
    """
)

# Tokens that look like common non-secret identifiers we should not flag
# even if they are long. These are checked as full-token matches.
_BENIGN_TOKEN = re.compile(
    r"""(?ix)^(?:
        [0-9a-f]{32}                      # md5 hex
        |[0-9a-f]{40}                      # sha1 hex
        |[0-9a-f]{64}                      # sha256 hex
        |[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}  # UUID
    )$"""
)


def shannon_entropy(s: str) -> float:
    """Return the Shannon entropy (bits per character) of ``s``.

    Returns 0.0 for the empty string.
    """
    if not s:
        return 0.0
    length = len(s)
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_high_entropy(token: str, min_len: int = 20, threshold: float = 4.0) -> bool:
    """Return True if ``token`` is long enough AND high-entropy enough.

    A token must be at least ``min_len`` characters and have Shannon
    entropy strictly greater than ``threshold`` bits/char to qualify.
    Known benign formats (hex digests, UUIDs) are excluded.
    """
    if token is None:
        return False
    if len(token) < min_len:
        return False
    if _BENIGN_TOKEN.match(token):
        return False
    return shannon_entropy(token) > threshold


def extract_candidate_tokens(line: str):
    """Yield candidate secret tokens from a single ``line``.

    Candidates come from:
      * quoted string literals
      * the right-hand side value of an assignment (key = value / key: value)

    Duplicate tokens within the same line are yielded only once, in order
    of first appearance, for determinism.
    """
    seen: set[str] = set()

    for m in _QUOTED.finditer(line):
        val = m.group("val")
        if val and val not in seen:
            seen.add(val)
            yield val

    for m in _ASSIGN.finditer(line):
        val = m.group("val")
        if val and val not in seen:
            seen.add(val)
            yield val
