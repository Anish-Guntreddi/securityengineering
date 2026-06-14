"""Tests for the pure scanning core: detection + redaction.

Provider literals are assembled at runtime from non-contiguous parts (see
:mod:`tests._assembly`) so no committed line contains a contiguous, provider-
shaped credential. The values handed to ``scan_content`` are byte-for-byte
identical to the original inline literals, so detection coverage is unchanged.
"""

from secrethawk.allowlist import Allowlist
from secrethawk.scanner import scan_content
from tests._assembly import (
    AWS_ACCESS_KEY,
    GH_PAT,
    HIGH_ENTROPY_TOKEN,
    STRIPE_SECRET_KEY,
)


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_finds_aws_access_key():
    text = f'AWS_KEY = "{AWS_ACCESS_KEY}"'
    findings = scan_content(text, "x.py")
    assert "aws-access-key-id" in _rule_ids(findings)


def test_finds_multiple_distinct_secrets():
    text = "\n".join(
        [
            f'aws = "{AWS_ACCESS_KEY}"',
            f'gh = "{GH_PAT}"',
            f'stripe = "{STRIPE_SECRET_KEY}"',
        ]
    )
    findings = scan_content(text, "x.py")
    ids = _rule_ids(findings)
    assert {"aws-access-key-id", "github-pat", "stripe-secret-key"} <= ids


def test_preview_is_redacted_first4_last2():
    text = f'AWS_KEY = "{AWS_ACCESS_KEY}"'
    findings = scan_content(text, "x.py")
    aws = next(f for f in findings if f.rule_id == "aws-access-key-id")
    preview = aws.match_preview
    # First 4 visible, last 2 visible, middle masked.
    assert preview.startswith("AKIA")
    assert preview.endswith("LE")
    assert "*" in preview
    # The full raw secret must NOT appear in the preview.
    assert AWS_ACCESS_KEY not in preview


def test_line_and_column_reported():
    text = "\n" + f'   key = "{AWS_ACCESS_KEY}"'
    findings = scan_content(text, "x.py")
    aws = next(f for f in findings if f.rule_id == "aws-access-key-id")
    assert aws.line == 2
    # Column points at the start of the secret (1-based).
    assert aws.column == text.splitlines()[1].index("AKIA") + 1


def test_inline_ignore_suppresses_line():
    text = f'key = "{AWS_ACCESS_KEY}"  # secrethawk:ignore'
    findings = scan_content(text, "x.py")
    assert findings == []


def test_pragma_allowlist_secret_suppresses_line():
    text = f'key = "{AWS_ACCESS_KEY}"  # pragma: allowlist secret'
    findings = scan_content(text, "x.py")
    assert findings == []


def test_high_entropy_generic_token_detected():
    text = f'SESSION = "{HIGH_ENTROPY_TOKEN}"'
    findings = scan_content(text, "x.py")
    assert any(f.detector == "entropy" for f in findings)


def test_entropy_does_not_double_report_rule_match():
    # An AWS key is also long; ensure only the rule fires, not entropy too.
    text = f'AWS_KEY = "{AWS_ACCESS_KEY}"'
    findings = scan_content(text, "x.py")
    detectors = [f.detector for f in findings if f.column]
    # The AWS key is exactly 20 chars; make sure no duplicate entropy
    # finding overlaps the same column as the rule finding.
    aws = next(f for f in findings if f.rule_id == "aws-access-key-id")
    overlapping_entropy = [
        f
        for f in findings
        if f.detector == "entropy" and f.line == aws.line
        and abs(f.column - aws.column) < 5
    ]
    assert overlapping_entropy == []


def test_allowlist_pattern_suppresses():
    allow = Allowlist.from_dict({"allowlist": {"patterns": ["EXAMPLE"]}})
    text = f'key = "{AWS_ACCESS_KEY}"'
    findings = scan_content(text, "x.py", allow)
    assert "aws-access-key-id" not in _rule_ids(findings)


def test_deterministic_output():
    text = "\n".join(
        [
            f'aws = "{AWS_ACCESS_KEY}"',
            f'gh = "{GH_PAT}"',
        ]
    )
    a = scan_content(text, "x.py")
    b = scan_content(text, "x.py")
    assert a == b


def test_no_findings_on_clean_text():
    text = "def add(a, b):\n    return a + b\n"
    assert scan_content(text, "clean.py") == []
