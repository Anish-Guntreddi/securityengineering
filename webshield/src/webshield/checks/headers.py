"""Security-header checks.

Pure functions over a :class:`~webshield.models.Probe`. Each check inspects
response headers and emits a :class:`~webshield.models.Finding` with a verdict:

- ``pass``  : header present and configured sanely.
- ``warn``  : header present but weak / questionable.
- ``fail``  : header absent (or fundamentally broken).

Covered headers:
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS): max-age + includeSubDomains sanity
- X-Frame-Options OR CSP frame-ancestors (clickjacking)
- X-Content-Type-Options: nosniff
- Referrer-Policy
- Permissions-Policy
"""

from __future__ import annotations

import re

from ..models import Probe, Finding


# Minimum HSTS max-age we consider "sane" (~6 months in seconds).
HSTS_MIN_MAX_AGE = 15_552_000

# Referrer-Policy values that meaningfully restrict referrer leakage.
SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}

# Referrer-Policy values that leak the full URL cross-origin (weak).
WEAK_REFERRER_POLICIES = {"unsafe-url", "origin-when-cross-origin", "origin"}


def _csp_directives(csp: str) -> dict[str, str]:
    """Parse a CSP header into a {directive: value} mapping (lowercased names)."""
    directives: dict[str, str] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split(None, 1)
        name = tokens[0].lower()
        value = tokens[1].strip() if len(tokens) > 1 else ""
        directives[name] = value
    return directives


def check_csp(probe: Probe) -> Finding:
    csp = probe.headers.get("content-security-policy")
    if not csp:
        return Finding(
            check_id="headers.csp",
            title="Content-Security-Policy",
            severity="high",
            verdict="fail",
            detail="No Content-Security-Policy header is set.",
            remediation=(
                "Add a Content-Security-Policy header. Start with a restrictive "
                "policy such as \"default-src 'self'; object-src 'none'; "
                "frame-ancestors 'none'; base-uri 'self'\" and tighten from there."
            ),
        )

    directives = _csp_directives(csp)
    weaknesses: list[str] = []

    has_default = "default-src" in directives
    has_script = "script-src" in directives
    if not has_default and not has_script:
        weaknesses.append("no default-src or script-src directive")

    # Inspect the most security-relevant fetch directives for wildcards /
    # unsafe-inline, which substantially weaken the policy.
    for directive in ("default-src", "script-src"):
        value = directives.get(directive, "")
        if not value:
            continue
        if "'unsafe-inline'" in value:
            weaknesses.append(f"{directive} allows 'unsafe-inline'")
        if "'unsafe-eval'" in value:
            weaknesses.append(f"{directive} allows 'unsafe-eval'")
        if re.search(r"(^|\s)\*(\s|$)", value):
            weaknesses.append(f"{directive} uses a wildcard '*' source")

    if weaknesses:
        return Finding(
            check_id="headers.csp",
            title="Content-Security-Policy",
            severity="medium",
            verdict="warn",
            detail="CSP present but weak: " + "; ".join(weaknesses) + ".",
            remediation=(
                "Tighten the CSP: avoid 'unsafe-inline'/'unsafe-eval' and wildcard "
                "sources, and ensure a restrictive default-src (or explicit "
                "script-src) is defined."
            ),
        )

    return Finding(
        check_id="headers.csp",
        title="Content-Security-Policy",
        severity="info",
        verdict="pass",
        detail="CSP present with a sane restrictive policy.",
        remediation="",
    )


def check_hsts(probe: Probe) -> Finding:
    hsts = probe.headers.get("strict-transport-security")
    if not hsts:
        return Finding(
            check_id="headers.hsts",
            title="Strict-Transport-Security (HSTS)",
            severity="high",
            verdict="fail",
            detail="No Strict-Transport-Security header is set.",
            remediation=(
                "Send 'Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains' over HTTPS to force secure connections."
            ),
        )

    lowered = hsts.lower()
    match = re.search(r"max-age\s*=\s*(\d+)", lowered)
    if not match:
        return Finding(
            check_id="headers.hsts",
            title="Strict-Transport-Security (HSTS)",
            severity="medium",
            verdict="warn",
            detail="HSTS header present but missing a valid max-age directive.",
            remediation=(
                "Include a max-age of at least 15552000 seconds (180 days), e.g. "
                "'max-age=31536000; includeSubDomains'."
            ),
        )

    max_age = int(match.group(1))
    includes_subdomains = "includesubdomains" in lowered
    weaknesses: list[str] = []
    if max_age < HSTS_MIN_MAX_AGE:
        weaknesses.append(f"max-age={max_age} is below the recommended {HSTS_MIN_MAX_AGE}")
    if not includes_subdomains:
        weaknesses.append("missing includeSubDomains")

    if weaknesses:
        return Finding(
            check_id="headers.hsts",
            title="Strict-Transport-Security (HSTS)",
            severity="medium",
            verdict="warn",
            detail="HSTS present but weak: " + "; ".join(weaknesses) + ".",
            remediation=(
                "Use 'max-age=31536000; includeSubDomains' (consider 'preload' once "
                "you are confident all subdomains support HTTPS)."
            ),
        )

    return Finding(
        check_id="headers.hsts",
        title="Strict-Transport-Security (HSTS)",
        severity="info",
        verdict="pass",
        detail=f"HSTS present with max-age={max_age} and includeSubDomains.",
        remediation="",
    )


def check_frame_options(probe: Probe) -> Finding:
    xfo = probe.headers.get("x-frame-options")
    csp = probe.headers.get("content-security-policy") or ""
    csp_directives = _csp_directives(csp)
    frame_ancestors = csp_directives.get("frame-ancestors")

    if frame_ancestors is not None:
        # frame-ancestors supersedes X-Frame-Options in modern browsers.
        if frame_ancestors.strip().lower() in ("'none'", "'self'"):
            return Finding(
                check_id="headers.frame_options",
                title="Clickjacking protection (X-Frame-Options / frame-ancestors)",
                severity="info",
                verdict="pass",
                detail=f"CSP frame-ancestors set to {frame_ancestors!r}.",
                remediation="",
            )
        return Finding(
            check_id="headers.frame_options",
            title="Clickjacking protection (X-Frame-Options / frame-ancestors)",
            severity="medium",
            verdict="warn",
            detail=(
                f"CSP frame-ancestors is permissive ({frame_ancestors!r}); framing "
                "may still be possible from unintended origins."
            ),
            remediation=(
                "Set CSP \"frame-ancestors 'none'\" (or 'self') to prevent "
                "clickjacking, unless you explicitly need to be framed."
            ),
        )

    if xfo:
        normalized = xfo.strip().lower()
        if normalized in ("deny", "sameorigin"):
            return Finding(
                check_id="headers.frame_options",
                title="Clickjacking protection (X-Frame-Options / frame-ancestors)",
                severity="info",
                verdict="pass",
                detail=f"X-Frame-Options set to {xfo!r}.",
                remediation="",
            )
        return Finding(
            check_id="headers.frame_options",
            title="Clickjacking protection (X-Frame-Options / frame-ancestors)",
            severity="medium",
            verdict="warn",
            detail=f"X-Frame-Options has a non-standard/weak value {xfo!r}.",
            remediation=(
                "Use 'X-Frame-Options: DENY' or 'SAMEORIGIN' (ALLOW-FROM is "
                "obsolete; prefer CSP frame-ancestors)."
            ),
        )

    return Finding(
        check_id="headers.frame_options",
        title="Clickjacking protection (X-Frame-Options / frame-ancestors)",
        severity="medium",
        verdict="fail",
        detail="Neither X-Frame-Options nor CSP frame-ancestors is set.",
        remediation=(
            "Add 'X-Frame-Options: DENY' or a CSP \"frame-ancestors 'none'\" "
            "directive to prevent clickjacking."
        ),
    )


def check_content_type_options(probe: Probe) -> Finding:
    value = probe.headers.get("x-content-type-options")
    if not value:
        return Finding(
            check_id="headers.content_type_options",
            title="X-Content-Type-Options",
            severity="low",
            verdict="fail",
            detail="No X-Content-Type-Options header is set.",
            remediation="Send 'X-Content-Type-Options: nosniff' to disable MIME sniffing.",
        )
    if value.strip().lower() == "nosniff":
        return Finding(
            check_id="headers.content_type_options",
            title="X-Content-Type-Options",
            severity="info",
            verdict="pass",
            detail="X-Content-Type-Options: nosniff is set.",
            remediation="",
        )
    return Finding(
        check_id="headers.content_type_options",
        title="X-Content-Type-Options",
        severity="low",
        verdict="warn",
        detail=f"X-Content-Type-Options has unexpected value {value!r}.",
        remediation="Set 'X-Content-Type-Options: nosniff'.",
    )


def check_referrer_policy(probe: Probe) -> Finding:
    value = probe.headers.get("referrer-policy")
    if not value:
        return Finding(
            check_id="headers.referrer_policy",
            title="Referrer-Policy",
            severity="low",
            verdict="fail",
            detail="No Referrer-Policy header is set.",
            remediation=(
                "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or "
                "'no-referrer') to limit referrer leakage."
            ),
        )

    # A policy may be a comma-separated list; the last token the browser
    # understands wins. Evaluate the set of tokens.
    tokens = {t.strip().lower() for t in value.split(",") if t.strip()}
    if tokens & SAFE_REFERRER_POLICIES:
        if tokens & WEAK_REFERRER_POLICIES:
            return Finding(
                check_id="headers.referrer_policy",
                title="Referrer-Policy",
                severity="low",
                verdict="warn",
                detail=f"Referrer-Policy {value!r} mixes safe and leaky values.",
                remediation="Use a single restrictive value like 'strict-origin-when-cross-origin'.",
            )
        return Finding(
            check_id="headers.referrer_policy",
            title="Referrer-Policy",
            severity="info",
            verdict="pass",
            detail=f"Referrer-Policy {value!r} restricts referrer leakage.",
            remediation="",
        )

    return Finding(
        check_id="headers.referrer_policy",
        title="Referrer-Policy",
        severity="low",
        verdict="warn",
        detail=f"Referrer-Policy {value!r} is permissive and may leak full URLs.",
        remediation="Use 'strict-origin-when-cross-origin' or 'no-referrer'.",
    )


def check_permissions_policy(probe: Probe) -> Finding:
    value = probe.headers.get("permissions-policy")
    if not value:
        return Finding(
            check_id="headers.permissions_policy",
            title="Permissions-Policy",
            severity="low",
            verdict="fail",
            detail="No Permissions-Policy header is set.",
            remediation=(
                "Send a Permissions-Policy header that disables unused powerful "
                "features, e.g. 'geolocation=(), camera=(), microphone=()'."
            ),
        )
    return Finding(
        check_id="headers.permissions_policy",
        title="Permissions-Policy",
        severity="info",
        verdict="pass",
        detail="Permissions-Policy header is set.",
        remediation="",
    )


def check_security_headers(probe: Probe) -> list[Finding]:
    """Run all security-header checks and return their findings."""
    return [
        check_csp(probe),
        check_hsts(probe),
        check_frame_options(probe),
        check_content_type_options(probe),
        check_referrer_policy(probe),
        check_permissions_policy(probe),
    ]
