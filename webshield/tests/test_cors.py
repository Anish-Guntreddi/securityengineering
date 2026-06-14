"""Tests for CORS checks on good AND bad inputs."""

from __future__ import annotations

from webshield.models import Probe
from webshield.checks.cors import check_cors


def test_no_cors_header_passes(secure_probe):
    # secure fixture sets no ACAO header.
    findings = check_cors(secure_probe)
    assert len(findings) == 1
    assert findings[0].verdict == "pass"


def test_wildcard_with_credentials_fails(insecure_probe):
    # insecure fixture: ACAO=* + ACAC=true.
    findings = check_cors(insecure_probe)
    assert findings[0].verdict == "fail"
    assert findings[0].severity == "critical"
    assert findings[0].remediation


def test_wildcard_without_credentials_warns():
    probe = Probe("https://x", headers={"Access-Control-Allow-Origin": "*"})
    f = check_cors(probe)[0]
    assert f.verdict == "warn"


def test_reflected_origin_with_credentials_fails():
    probe = Probe(
        "https://x",
        headers={
            "Access-Control-Allow-Origin": "https://evil.example",
            "Access-Control-Allow-Credentials": "true",
            "X-WebShield-Request-Origin": "https://evil.example",
        },
    )
    f = check_cors(probe)[0]
    assert f.verdict == "fail"
    assert f.severity == "critical"
    assert "reflected" in f.detail.lower()


def test_specific_origin_with_credentials_no_reflection_marker_warns():
    probe = Probe(
        "https://x",
        headers={
            "Access-Control-Allow-Origin": "https://trusted.example",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    f = check_cors(probe)[0]
    assert f.verdict == "warn"


def test_specific_origin_without_credentials_passes():
    probe = Probe(
        "https://x",
        headers={"Access-Control-Allow-Origin": "https://trusted.example"},
    )
    f = check_cors(probe)[0]
    assert f.verdict == "pass"


def test_null_origin_with_credentials_fails():
    probe = Probe(
        "https://x",
        headers={
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    f = check_cors(probe)[0]
    assert f.verdict == "fail"


def test_null_origin_without_credentials_warns():
    probe = Probe("https://x", headers={"Access-Control-Allow-Origin": "null"})
    f = check_cors(probe)[0]
    assert f.verdict == "warn"
