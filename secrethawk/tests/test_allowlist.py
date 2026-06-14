"""Tests for allowlist non-detection controls.

Provider literals are assembled at runtime from non-contiguous parts (see
:mod:`tests._assembly`) so no committed line contains a contiguous, provider-
shaped credential; the values handed to the scanner are identical.
"""

from pathlib import Path

from secrethawk.allowlist import Allowlist
from secrethawk.scanner import scan_content
from tests._assembly import AWS_ACCESS_KEY, GH_PAT_IGNORED


def test_inline_ignore_marker():
    allow = Allowlist.empty()
    assert allow.line_has_inline_ignore("foo  # secrethawk:ignore") is True
    assert allow.line_has_inline_ignore("foo  # pragma: allowlist secret") is True
    assert allow.line_has_inline_ignore("foo  # normal comment") is False


def test_path_glob_skip_basename():
    allow = Allowlist.from_dict({"allowlist": {"paths": ["*.lock"]}})
    assert allow.is_path_allowlisted("package.lock") is True
    assert allow.is_path_allowlisted("a/b/package.lock") is True
    assert allow.is_path_allowlisted("main.py") is False


def test_path_glob_skip_nested_dir():
    allow = Allowlist.from_dict({"allowlist": {"paths": ["vendor/**"]}})
    assert allow.is_path_allowlisted("vendor/lib/x.py") is True
    assert allow.is_path_allowlisted("a/vendor/lib/x.py") is True
    assert allow.is_path_allowlisted("src/main.py") is False


def test_pattern_suppress_in_scan():
    allow = Allowlist.from_dict({"allowlist": {"patterns": ["your-api-key-here"]}})
    text = 'api_key = "your-api-key-here"'
    findings = scan_content(text, "x.py", allow)
    assert findings == []


def test_pattern_suppress_specific_rule():
    allow = Allowlist.from_dict({"allowlist": {"patterns": ["EXAMPLE"]}})
    text = f'key = "{AWS_ACCESS_KEY}"'
    findings = scan_content(text, "x.py", allow)
    assert all(f.rule_id != "aws-access-key-id" for f in findings)


def test_load_from_toml(tmp_path: Path):
    toml = tmp_path / ".secrethawk.toml"
    toml.write_text(
        "\n".join(
            [
                "[allowlist]",
                'paths = ["*.min.js"]',
                'patterns = ["FAKE"]',
            ]
        ),
        encoding="utf-8",
    )
    allow = Allowlist.load(toml)
    assert allow.is_path_allowlisted("bundle.min.js") is True
    assert allow.is_suppressed_by_pattern("this is FAKE") is True


def test_load_missing_returns_empty(tmp_path: Path):
    allow = Allowlist.load(tmp_path / "nope.toml")
    assert allow.path_globs == []
    assert allow.patterns == []


def test_discover_uses_secrethawk_toml(sample_repo: Path):
    # The generated sample repo's .secrethawk.toml allowlists the placeholder.
    allow = Allowlist.discover(sample_repo)
    assert allow.is_suppressed_by_pattern("api_key = your-api-key-here") is True


def test_inline_ignore_in_scan_content():
    text = f'token = "{GH_PAT_IGNORED}"  # secrethawk:ignore'
    assert scan_content(text, "x.py") == []
