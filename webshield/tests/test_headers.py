"""Tests for security-header checks on good AND bad inputs."""

from __future__ import annotations

from webshield.models import Probe
from webshield.checks.headers import (
    check_security_headers,
    check_csp,
    check_hsts,
    check_frame_options,
    check_content_type_options,
    check_referrer_policy,
    check_permissions_policy,
)


def _by_id(findings):
    return {f.check_id: f for f in findings}


def test_secure_probe_all_headers_pass(secure_probe):
    findings = check_security_headers(secure_probe)
    by_id = _by_id(findings)
    for cid in (
        "headers.csp",
        "headers.hsts",
        "headers.frame_options",
        "headers.content_type_options",
        "headers.referrer_policy",
        "headers.permissions_policy",
    ):
        assert by_id[cid].verdict == "pass", (cid, by_id[cid].detail)


def test_insecure_probe_headers_fail(insecure_probe):
    findings = check_security_headers(insecure_probe)
    by_id = _by_id(findings)
    # Absent headers => fail.
    assert by_id["headers.csp"].verdict == "fail"
    assert by_id["headers.hsts"].verdict == "fail"
    assert by_id["headers.content_type_options"].verdict == "fail"
    assert by_id["headers.referrer_policy"].verdict == "fail"
    assert by_id["headers.permissions_policy"].verdict == "fail"
    # X-Frame-Options present but non-standard "ALLOWALL" => warn.
    assert by_id["headers.frame_options"].verdict == "warn"
    # Every non-pass finding must carry remediation.
    for f in findings:
        if f.verdict != "pass":
            assert f.remediation


def test_csp_weak_unsafe_inline_warns():
    probe = Probe(
        url="https://x",
        headers={"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"},
    )
    f = check_csp(probe)
    assert f.verdict == "warn"
    assert "unsafe-inline" in f.detail


def test_csp_wildcard_warns():
    probe = Probe(
        url="https://x",
        headers={"Content-Security-Policy": "default-src *"},
    )
    f = check_csp(probe)
    assert f.verdict == "warn"


def test_hsts_short_max_age_warns():
    probe = Probe(
        url="https://x",
        headers={"Strict-Transport-Security": "max-age=100; includeSubDomains"},
    )
    f = check_hsts(probe)
    assert f.verdict == "warn"
    assert "max-age" in f.detail


def test_hsts_missing_includesubdomains_warns():
    probe = Probe(
        url="https://x",
        headers={"Strict-Transport-Security": "max-age=31536000"},
    )
    f = check_hsts(probe)
    assert f.verdict == "warn"
    assert "includeSubDomains" in f.detail


def test_hsts_no_max_age_warns():
    probe = Probe(
        url="https://x",
        headers={"Strict-Transport-Security": "includeSubDomains"},
    )
    f = check_hsts(probe)
    assert f.verdict == "warn"


def test_frame_ancestors_none_passes_without_xfo():
    probe = Probe(
        url="https://x",
        headers={"Content-Security-Policy": "frame-ancestors 'none'"},
    )
    f = check_frame_options(probe)
    assert f.verdict == "pass"


def test_frame_ancestors_wildcard_warns():
    probe = Probe(
        url="https://x",
        headers={"Content-Security-Policy": "frame-ancestors *"},
    )
    f = check_frame_options(probe)
    assert f.verdict == "warn"


def test_xfo_sameorigin_passes():
    probe = Probe(url="https://x", headers={"X-Frame-Options": "SAMEORIGIN"})
    assert check_frame_options(probe).verdict == "pass"


def test_content_type_options_wrong_value_warns():
    probe = Probe(url="https://x", headers={"X-Content-Type-Options": "sniff"})
    assert check_content_type_options(probe).verdict == "warn"


def test_referrer_policy_unsafe_url_warns():
    probe = Probe(url="https://x", headers={"Referrer-Policy": "unsafe-url"})
    assert check_referrer_policy(probe).verdict == "warn"


def test_referrer_policy_no_referrer_passes():
    probe = Probe(url="https://x", headers={"Referrer-Policy": "no-referrer"})
    assert check_referrer_policy(probe).verdict == "pass"


def test_permissions_policy_present_passes():
    probe = Probe(url="https://x", headers={"Permissions-Policy": "geolocation=()"})
    assert check_permissions_policy(probe).verdict == "pass"


def test_case_insensitive_header_lookup():
    # Header set with unusual casing must still be found.
    probe = Probe(
        url="https://x",
        headers={"content-SECURITY-policy": "default-src 'self'"},
    )
    assert check_csp(probe).verdict == "pass"
