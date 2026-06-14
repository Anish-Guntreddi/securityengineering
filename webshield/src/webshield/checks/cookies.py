"""Cookie security checks.

Parses each ``Set-Cookie`` header value and flags missing ``Secure``,
``HttpOnly``, and ``SameSite`` attributes. Verdict per cookie:

- ``fail`` : missing Secure or HttpOnly (the highest-impact attributes), OR
             SameSite=None without Secure (an invalid/insecure combination).
- ``warn`` : has Secure + HttpOnly but no SameSite attribute.
- ``pass`` : Secure, HttpOnly, and an explicit SameSite present.
"""

from __future__ import annotations

from ..models import Probe, Finding


def _parse_cookie(raw: str) -> dict[str, object]:
    """Parse a raw Set-Cookie value into name and attribute flags."""
    parts = [p.strip() for p in raw.split(";")]
    name = ""
    if parts and "=" in parts[0]:
        name = parts[0].split("=", 1)[0].strip()
    elif parts:
        name = parts[0].strip()

    attrs = {p.split("=", 1)[0].strip().lower(): p for p in parts[1:]}
    samesite_value = None
    if "samesite" in attrs:
        raw_attr = attrs["samesite"]
        if "=" in raw_attr:
            samesite_value = raw_attr.split("=", 1)[1].strip()
        else:
            samesite_value = ""

    return {
        "name": name or "(unnamed)",
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": "samesite" in attrs,
        "samesite_value": samesite_value,
    }


def _check_one_cookie(raw: str, index: int) -> Finding:
    parsed = _parse_cookie(raw)
    name = parsed["name"]
    check_id = f"cookies.{index}"

    missing: list[str] = []
    if not parsed["secure"]:
        missing.append("Secure")
    if not parsed["httponly"]:
        missing.append("HttpOnly")

    samesite_value = parsed["samesite_value"]
    samesite_none = (
        isinstance(samesite_value, str) and samesite_value.lower() == "none"
    )

    # SameSite=None requires Secure; without it the cookie is rejected by
    # modern browsers and is effectively insecure.
    if samesite_none and not parsed["secure"]:
        return Finding(
            check_id=check_id,
            title=f"Cookie {name!r} attributes",
            severity="high",
            verdict="fail",
            detail=(
                f"Cookie {name!r} uses SameSite=None without the Secure attribute, "
                "which is invalid and insecure."
            ),
            remediation="Set SameSite=None only together with the Secure attribute.",
        )

    if missing:
        return Finding(
            check_id=check_id,
            title=f"Cookie {name!r} attributes",
            severity="high",
            verdict="fail",
            detail=f"Cookie {name!r} is missing: {', '.join(missing)}.",
            remediation=(
                "Set Secure (HTTPS-only) and HttpOnly (no JS access) on cookies, "
                "and add an explicit SameSite attribute (Lax or Strict)."
            ),
        )

    if not parsed["samesite"]:
        return Finding(
            check_id=check_id,
            title=f"Cookie {name!r} attributes",
            severity="medium",
            verdict="warn",
            detail=(
                f"Cookie {name!r} has Secure and HttpOnly but no explicit SameSite "
                "attribute."
            ),
            remediation="Add 'SameSite=Lax' (or 'Strict') to mitigate CSRF.",
        )

    return Finding(
        check_id=check_id,
        title=f"Cookie {name!r} attributes",
        severity="info",
        verdict="pass",
        detail=(
            f"Cookie {name!r} has Secure, HttpOnly, and "
            f"SameSite={samesite_value or 'set'}."
        ),
        remediation="",
    )


def check_cookies(probe: Probe) -> list[Finding]:
    """Run cookie checks for every Set-Cookie header on the probe."""
    if not probe.set_cookie:
        return [
            Finding(
                check_id="cookies.none",
                title="Cookie security",
                severity="info",
                verdict="pass",
                detail="No cookies were set by the response.",
                remediation="",
            )
        ]
    return [
        _check_one_cookie(raw, index)
        for index, raw in enumerate(probe.set_cookie)
    ]
