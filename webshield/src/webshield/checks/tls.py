"""TLS / transport-security checks.

Operates purely over ``probe.tls``, which carries best-effort transport posture:
    - ``https``: whether the final URL used HTTPS.
    - ``redirects_http_to_https``: whether plain HTTP redirects to HTTPS.
    - ``tls_version``: negotiated TLS version string (e.g. "TLSv1.3"), or None.
    - ``hsts``: whether an HSTS header was observed.
"""

from __future__ import annotations

import re

from ..models import Probe, Finding


# TLS versions considered modern / acceptable.
MODERN_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}


def check_https(probe: Probe) -> Finding:
    if probe.tls.get("https"):
        return Finding(
            check_id="tls.https",
            title="HTTPS in use",
            severity="info",
            verdict="pass",
            detail="The target is served over HTTPS.",
            remediation="",
        )
    return Finding(
        check_id="tls.https",
        title="HTTPS in use",
        severity="critical",
        verdict="fail",
        detail="The target is not served over HTTPS.",
        remediation="Serve the site exclusively over HTTPS with a valid certificate.",
    )


def check_http_redirect(probe: Probe) -> Finding:
    if probe.tls.get("redirects_http_to_https"):
        return Finding(
            check_id="tls.http_redirect",
            title="HTTP to HTTPS redirect",
            severity="info",
            verdict="pass",
            detail="Plain HTTP requests are redirected to HTTPS.",
            remediation="",
        )
    return Finding(
        check_id="tls.http_redirect",
        title="HTTP to HTTPS redirect",
        severity="medium",
        verdict="fail",
        detail="Plain HTTP requests are not redirected to HTTPS.",
        remediation=(
            "Configure the server to 301-redirect all HTTP traffic to HTTPS so "
            "users never communicate in cleartext."
        ),
    )


def check_hsts_present(probe: Probe) -> Finding:
    if probe.tls.get("hsts"):
        return Finding(
            check_id="tls.hsts",
            title="HSTS enforced for transport",
            severity="info",
            verdict="pass",
            detail="An HSTS header is present, enforcing HTTPS for future visits.",
            remediation="",
        )
    return Finding(
        check_id="tls.hsts",
        title="HSTS enforced for transport",
        severity="medium",
        verdict="fail",
        detail="No HSTS header was observed at the transport layer.",
        remediation=(
            "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
            "to enforce HTTPS on subsequent connections."
        ),
    )


def _tls_version_value(version: str | None) -> float | None:
    """Extract a comparable numeric value from a TLS version string."""
    if not version:
        return None
    match = re.search(r"(\d+)\.(\d+)", version)
    if not match:
        return None
    return float(f"{match.group(1)}.{match.group(2)}")


def check_modern_tls(probe: Probe) -> Finding:
    version = probe.tls.get("tls_version")
    if not probe.tls.get("https"):
        return Finding(
            check_id="tls.version",
            title="Modern TLS version (>= 1.2)",
            severity="high",
            verdict="fail",
            detail="No TLS connection (the target is not HTTPS), so no TLS version was negotiated.",
            remediation="Enable HTTPS using TLS 1.2 or TLS 1.3.",
        )

    numeric = _tls_version_value(version)
    if numeric is None:
        return Finding(
            check_id="tls.version",
            title="Modern TLS version (>= 1.2)",
            severity="low",
            verdict="warn",
            detail="TLS version could not be determined.",
            remediation="Ensure the server negotiates TLS 1.2 or 1.3 and verify with a TLS scanner.",
        )

    if version in MODERN_TLS_VERSIONS or numeric >= 1.2:
        return Finding(
            check_id="tls.version",
            title="Modern TLS version (>= 1.2)",
            severity="info",
            verdict="pass",
            detail=f"Negotiated {version}, which is modern.",
            remediation="",
        )

    return Finding(
        check_id="tls.version",
        title="Modern TLS version (>= 1.2)",
        severity="high",
        verdict="fail",
        detail=f"Negotiated {version}, which is outdated and insecure.",
        remediation="Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2 or 1.3.",
    )


def check_tls(probe: Probe) -> list[Finding]:
    """Run all TLS checks and return their findings."""
    return [
        check_https(probe),
        check_http_redirect(probe),
        check_hsts_present(probe),
        check_modern_tls(probe),
    ]
