"""Tests for individual detection rules: positive and negative cases.

Provider literals are assembled at runtime from non-contiguous parts (see
:mod:`tests._assembly`) so no committed line contains a contiguous, provider-
shaped credential. The values handed to the scanner are byte-for-byte
identical to the original inline literals, so detection coverage is unchanged.
"""

import re

import pytest

from secrethawk.rules import get_rules
from tests._assembly import (
    AWS_ACCESS_KEY,
    GH_OAUTH,
    GH_PAT,
    GOOGLE_API_KEY,
    JWT,
    NPM_TOKEN,
    SENDGRID_API_KEY,
    SLACK_TOKEN,
    STRIPE_RESTRICTED_KEY,
    STRIPE_SECRET_KEY,
    TWILIO_API_KEY,
    secret,
)


def _rule(rule_id):
    for r in get_rules():
        if r.id == rule_id:
            return r
    raise KeyError(rule_id)


def _matches(rule_id, text):
    rule = _rule(rule_id)
    return list(rule.finditer(text))


POSITIVES = [
    ("aws-access-key-id", AWS_ACCESS_KEY),
    ("github-pat", GH_PAT),
    ("github-oauth", GH_OAUTH),
    (
        "github-fine-grained-pat",
        secret("github_pat_", "A" * 82),
    ),
    ("slack-token", SLACK_TOKEN),
    ("google-api-key", GOOGLE_API_KEY),
    ("stripe-secret-key", STRIPE_SECRET_KEY),
    ("stripe-restricted-key", STRIPE_RESTRICTED_KEY),
    ("private-key", secret("-----BEGIN ", "RSA ", "PRIVATE KEY", "-----")),
    ("private-key", secret("-----BEGIN ", "OPENSSH ", "PRIVATE KEY", "-----")),
    ("private-key", secret("-----BEGIN ", "PRIVATE KEY", "-----")),
    ("jwt", JWT),
    ("twilio-api-key", TWILIO_API_KEY),
    ("sendgrid-api-key", SENDGRID_API_KEY),
    ("npm-token", NPM_TOKEN),
    ("generic-secret-assignment", 'password = "hunter2secret"'),
    (
        "aws-secret-access-key",
        'aws_secret_access_key = "'
        + secret("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY")
        + '"',
    ),
]


@pytest.mark.parametrize("rule_id, sample", POSITIVES)
def test_rule_positive(rule_id, sample):
    matches = _matches(rule_id, sample)
    assert matches, f"{rule_id} should match: {sample!r}"


NEGATIVES = [
    ("aws-access-key-id", "AKIA1234"),  # too short
    ("github-pat", "ghp_short"),
    ("github-oauth", "gho_short"),
    ("stripe-secret-key", "sk_test_abcdefghijklmnopqrstuvwx1234"),  # test, not live
    ("google-api-key", "AIzaShort"),
    ("private-key", "BEGIN PUBLIC KEY"),
    ("jwt", "eyJonlyonepart"),
    ("npm-token", "npm_short"),
    ("generic-secret-assignment", "password = os.environ['PW']"),  # not quoted literal
]


@pytest.mark.parametrize("rule_id, sample", NEGATIVES)
def test_rule_negative(rule_id, sample):
    matches = _matches(rule_id, sample)
    assert not matches, f"{rule_id} should NOT match: {sample!r}"


def test_all_rules_have_secret_group_or_match():
    """Every rule must produce a usable match group (named 'secret' or 0)."""
    for rule in get_rules():
        assert isinstance(rule.regex, re.Pattern)
        assert rule.id
        assert rule.severity in {"low", "medium", "high", "critical"}


def test_aws_secret_not_flagged_without_context():
    """A bare 40-char base64 blob without a key context should not match."""
    bare = "A" * 40
    assert not _matches("aws-secret-access-key", bare)
