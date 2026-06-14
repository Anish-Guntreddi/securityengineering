"""Orchestrate all checks over a Probe and aggregate Findings."""

from __future__ import annotations

from typing import Callable

from .models import Probe, Finding
from .checks.headers import check_security_headers
from .checks.tls import check_tls
from .checks.cookies import check_cookies
from .checks.cors import check_cors
from .checks.reflected import check_reflected_input


def run_all(
    probe: Probe,
    fetcher: Callable[[str], Probe] | None = None,
) -> list[Finding]:
    """Run every check against ``probe`` and return aggregated findings.

    Args:
        probe: the recorded response to analyze. The static checks (headers,
            TLS, cookies, CORS) operate purely on this probe.
        fetcher: optional callable used by the reflected-input check, which must
            issue an additional GET with a benign marker. If omitted, the
            reflected-input check is skipped (it cannot run without a fetcher).

    Returns:
        A flat list of Finding objects.
    """
    findings: list[Finding] = []
    findings.extend(check_security_headers(probe))
    findings.extend(check_tls(probe))
    findings.extend(check_cookies(probe))
    findings.extend(check_cors(probe))

    if fetcher is not None:
        findings.append(check_reflected_input(fetcher, probe.url))

    return findings
