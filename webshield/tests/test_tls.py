"""Tests for TLS checks on good AND bad inputs."""

from __future__ import annotations

from webshield.models import Probe
from webshield.checks.tls import (
    check_tls,
    check_https,
    check_http_redirect,
    check_hsts_present,
    check_modern_tls,
)


def _by_id(findings):
    return {f.check_id: f for f in findings}


def test_secure_probe_tls_all_pass(secure_probe):
    by_id = _by_id(check_tls(secure_probe))
    assert by_id["tls.https"].verdict == "pass"
    assert by_id["tls.http_redirect"].verdict == "pass"
    assert by_id["tls.hsts"].verdict == "pass"
    assert by_id["tls.version"].verdict == "pass"


def test_insecure_probe_tls_all_fail(insecure_probe):
    by_id = _by_id(check_tls(insecure_probe))
    assert by_id["tls.https"].verdict == "fail"
    assert by_id["tls.http_redirect"].verdict == "fail"
    assert by_id["tls.hsts"].verdict == "fail"
    assert by_id["tls.version"].verdict == "fail"
    for f in check_tls(insecure_probe):
        if f.verdict != "pass":
            assert f.remediation


def test_https_pass_and_fail():
    assert check_https(Probe("https://x", tls={"https": True})).verdict == "pass"
    assert check_https(Probe("http://x", tls={"https": False})).verdict == "fail"


def test_http_redirect_pass_and_fail():
    assert (
        check_http_redirect(
            Probe("https://x", tls={"redirects_http_to_https": True})
        ).verdict
        == "pass"
    )
    assert (
        check_http_redirect(
            Probe("https://x", tls={"redirects_http_to_https": False})
        ).verdict
        == "fail"
    )


def test_hsts_present_pass_and_fail():
    assert check_hsts_present(Probe("https://x", tls={"hsts": True})).verdict == "pass"
    assert check_hsts_present(Probe("https://x", tls={"hsts": False})).verdict == "fail"


def test_modern_tls_versions():
    assert (
        check_modern_tls(
            Probe("https://x", tls={"https": True, "tls_version": "TLSv1.3"})
        ).verdict
        == "pass"
    )
    assert (
        check_modern_tls(
            Probe("https://x", tls={"https": True, "tls_version": "TLSv1.2"})
        ).verdict
        == "pass"
    )
    assert (
        check_modern_tls(
            Probe("https://x", tls={"https": True, "tls_version": "TLSv1.0"})
        ).verdict
        == "fail"
    )
    assert (
        check_modern_tls(
            Probe("https://x", tls={"https": True, "tls_version": "TLSv1.1"})
        ).verdict
        == "fail"
    )


def test_modern_tls_unknown_version_warns():
    f = check_modern_tls(Probe("https://x", tls={"https": True, "tls_version": None}))
    assert f.verdict == "warn"


def test_modern_tls_no_https_fails():
    f = check_modern_tls(Probe("http://x", tls={"https": False}))
    assert f.verdict == "fail"
