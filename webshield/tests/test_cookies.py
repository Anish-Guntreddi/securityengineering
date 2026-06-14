"""Tests for cookie checks on good AND bad inputs."""

from __future__ import annotations

from webshield.models import Probe
from webshield.checks.cookies import check_cookies


def test_secure_cookie_passes(secure_probe):
    findings = check_cookies(secure_probe)
    assert len(findings) == 1
    assert findings[0].verdict == "pass"
    assert "sid" in findings[0].title


def test_insecure_cookies_fail(insecure_probe):
    findings = check_cookies(insecure_probe)
    # Fixture has two cookies: "sid=abc123" (missing all) and
    # "tracking=xyz; SameSite=None" (None without Secure).
    assert len(findings) == 2
    verdicts = [f.verdict for f in findings]
    assert verdicts == ["fail", "fail"]
    for f in findings:
        assert f.remediation


def test_missing_secure_fails():
    probe = Probe("https://x", set_cookie=["a=1; HttpOnly; SameSite=Lax"])
    f = check_cookies(probe)[0]
    assert f.verdict == "fail"
    assert "Secure" in f.detail


def test_missing_httponly_fails():
    probe = Probe("https://x", set_cookie=["a=1; Secure; SameSite=Lax"])
    f = check_cookies(probe)[0]
    assert f.verdict == "fail"
    assert "HttpOnly" in f.detail


def test_secure_httponly_no_samesite_warns():
    probe = Probe("https://x", set_cookie=["a=1; Secure; HttpOnly"])
    f = check_cookies(probe)[0]
    assert f.verdict == "warn"
    assert "SameSite" in f.detail


def test_full_attributes_pass():
    probe = Probe("https://x", set_cookie=["a=1; Secure; HttpOnly; SameSite=Strict"])
    f = check_cookies(probe)[0]
    assert f.verdict == "pass"


def test_samesite_none_without_secure_fails():
    probe = Probe("https://x", set_cookie=["a=1; HttpOnly; SameSite=None"])
    f = check_cookies(probe)[0]
    assert f.verdict == "fail"
    assert "SameSite=None" in f.detail


def test_samesite_none_with_secure_passes():
    probe = Probe(
        "https://x", set_cookie=["a=1; Secure; HttpOnly; SameSite=None"]
    )
    f = check_cookies(probe)[0]
    assert f.verdict == "pass"


def test_no_cookies_passes():
    probe = Probe("https://x", set_cookie=[])
    findings = check_cookies(probe)
    assert len(findings) == 1
    assert findings[0].verdict == "pass"
    assert findings[0].check_id == "cookies.none"


def test_attribute_case_insensitive():
    probe = Probe("https://x", set_cookie=["a=1; secure; httponly; samesite=lax"])
    f = check_cookies(probe)[0]
    assert f.verdict == "pass"
