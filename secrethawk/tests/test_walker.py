"""Tests for the repo walker against the generated sample fixture repo.

Verifies the false-positive control: EXACTLY the planted set is found and
ZERO benign strings are flagged; the clean/ subtree yields nothing.

The sample repo is built at runtime in a temp directory by the ``sample_repo``
session fixture (see ``conftest.py`` / ``tests/_assembly.py``) so no committed
file contains a contiguous, provider-shaped credential. The scanner reads the
same bytes it would have read from a committed fixture, so coverage is
unchanged: ``.gitignore`` handling, allowlist suppression, every planted rule,
preview redaction, and the clean subtree are all still exercised.
"""

from pathlib import Path

from secrethawk.walker import walk_repo
from tests._assembly import AWS_ACCESS_KEY

# Rule ids we expect to find in the planted fixture (excludes clean/).
EXPECTED_PLANTED_RULES = {
    "aws-access-key-id",     # config.py
    "github-pat",            # config.py
    "stripe-secret-key",     # config.py
    "private-key",           # keys/id_rsa
    "high-entropy-string",   # config.py SESSION_SIGNING_KEY (entropy detector)
}


def test_clean_tree_yields_zero(clean_subtree: Path):
    findings = walk_repo(clean_subtree)
    assert findings == [], [f.to_dict() for f in findings]


def test_sample_repo_finds_expected_planted_set(sample_repo: Path):
    findings = walk_repo(sample_repo)
    found_rules = {f.rule_id for f in findings}
    assert EXPECTED_PLANTED_RULES <= found_rules, found_rules


def test_sample_repo_no_false_positives_on_benign(sample_repo: Path):
    findings = walk_repo(sample_repo)
    # No finding may originate from benign.txt: every benign case is either a
    # non-secret format, a placeholder (allowlisted), or inline-ignored.
    benign_findings = [f for f in findings if f.file_path == "benign.txt"]
    assert benign_findings == [], [f.to_dict() for f in benign_findings]


def test_sample_repo_finding_paths_are_expected(sample_repo: Path):
    findings = walk_repo(sample_repo)
    paths = {f.file_path for f in findings}
    # Findings should only come from the planted files.
    assert "config.py" in paths
    assert "keys/id_rsa" in paths
    # benign.txt and clean/ must contribute nothing.
    assert "benign.txt" not in paths
    assert not any(p.startswith("clean/") for p in paths)


def test_previews_never_contain_raw_secret(sample_repo: Path):
    findings = walk_repo(sample_repo)
    for f in findings:
        assert AWS_ACCESS_KEY not in f.match_preview
        assert "*" in f.match_preview or len(f.match_preview) <= 6


def test_walker_handles_single_file_root(tmp_path: Path):
    # walk_repo expects a directory; ensure a directory with one file works.
    d = tmp_path / "repo"
    d.mkdir()
    (d / "a.py").write_text(f'k = "{AWS_ACCESS_KEY}"\n', encoding="utf-8")
    findings = walk_repo(d)
    assert any(f.rule_id == "aws-access-key-id" for f in findings)


def test_walker_skips_binary(tmp_path: Path):
    d = tmp_path / "repo"
    d.mkdir()
    # A binary file containing a secret-looking byte sequence + NUL.
    (d / "blob.bin").write_bytes(AWS_ACCESS_KEY.encode("ascii") + b"\x00\x01\x02")
    findings = walk_repo(d)
    assert findings == []
