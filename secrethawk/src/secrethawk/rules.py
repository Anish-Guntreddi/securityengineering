"""Regex-based detection rules for SecretHawk.

Each :class:`Rule` carries an id, description, severity and a compiled
regular expression. The scanner applies every rule to each line of input.

These patterns intentionally favour precision (well-known prefixes and
lengths) to keep false positives low, while the entropy detector catches
the long tail of generic high-entropy secrets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


@dataclass(frozen=True)
class Rule:
    """A single regex detection rule."""

    id: str
    description: str
    severity: str
    regex: Pattern[str]

    def finditer(self, text: str):
        """Yield regex match objects for ``text``."""
        return self.regex.finditer(text)


# A reusable fragment for "assignment or quoted context": the value is
# preceded by an assignment operator (= or :) and/or wrapped in quotes.
# We keep the secret itself in a named group "secret".
_ASSIGN_PREFIX = r"""(?:['"]?\s*[:=]\s*)?['"]?"""

RULES: list[Rule] = [
    Rule(
        id="aws-access-key-id",
        description="AWS Access Key ID",
        severity="high",
        regex=re.compile(r"(?P<secret>AKIA[0-9A-Z]{16})"),
    ),
    Rule(
        id="aws-secret-access-key",
        description="AWS Secret Access Key (40-char base64 in assignment/quoted context)",
        severity="critical",
        # Require an assignment/quoted context and a secret-ish keyword nearby
        # to avoid flagging arbitrary 40-char base64 blobs.
        regex=re.compile(
            r"""(?ix)
            (?:aws.{0,20})?(?:secret|access[_-]?key|key)
            \s*['"]?\s*[:=]\s*['"]?
            (?P<secret>[A-Za-z0-9/+]{40})
            (?![A-Za-z0-9/+=])
            """
        ),
    ),
    Rule(
        id="github-pat",
        description="GitHub Personal Access Token",
        severity="high",
        regex=re.compile(r"(?P<secret>ghp_[A-Za-z0-9]{36})"),
    ),
    Rule(
        id="github-oauth",
        description="GitHub OAuth Access Token",
        severity="high",
        regex=re.compile(r"(?P<secret>gho_[A-Za-z0-9]{36})"),
    ),
    Rule(
        id="github-fine-grained-pat",
        description="GitHub Fine-Grained Personal Access Token",
        severity="high",
        regex=re.compile(r"(?P<secret>github_pat_[0-9A-Za-z_]{82})"),
    ),
    Rule(
        id="slack-token",
        description="Slack Token",
        severity="high",
        regex=re.compile(r"(?P<secret>xox[baprs]-[0-9A-Za-z-]{10,})"),
    ),
    Rule(
        id="google-api-key",
        description="Google API Key",
        severity="high",
        regex=re.compile(r"(?P<secret>AIza[0-9A-Za-z_-]{35})"),
    ),
    Rule(
        id="stripe-secret-key",
        description="Stripe Secret Key (live)",
        severity="critical",
        regex=re.compile(r"(?P<secret>sk_live_[0-9A-Za-z]{24,})"),
    ),
    Rule(
        id="stripe-restricted-key",
        description="Stripe Restricted Key (live)",
        severity="high",
        regex=re.compile(r"(?P<secret>rk_live_[0-9A-Za-z]{24,})"),
    ),
    Rule(
        id="private-key",
        description="Private Key Block",
        severity="critical",
        regex=re.compile(
            r"(?P<secret>-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)"
        ),
    ),
    Rule(
        id="jwt",
        description="JSON Web Token (JWT)",
        severity="medium",
        regex=re.compile(
            r"(?P<secret>eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"
        ),
    ),
    Rule(
        id="twilio-api-key",
        description="Twilio API Key (SID)",
        severity="high",
        regex=re.compile(r"(?P<secret>SK[0-9a-fA-F]{32})"),
    ),
    Rule(
        id="sendgrid-api-key",
        description="SendGrid API Key",
        severity="high",
        regex=re.compile(r"(?P<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})"),
    ),
    Rule(
        id="npm-token",
        description="npm Access Token",
        severity="high",
        regex=re.compile(r"(?P<secret>npm_[A-Za-z0-9]{36})"),
    ),
    Rule(
        id="generic-secret-assignment",
        description="Generic secret keyword assigned to a quoted value",
        severity="medium",
        regex=re.compile(
            r"""(?ix)
            \b(?:password|passwd|secret|api[_-]?key|apikey|token|access[_-]?key)\b
            \s*[:=]\s*
            ['"](?P<secret>[^'"\n]{4,})['"]
            """
        ),
    ),
]


def get_rules() -> list[Rule]:
    """Return the list of detection rules (defensive copy)."""
    return list(RULES)
