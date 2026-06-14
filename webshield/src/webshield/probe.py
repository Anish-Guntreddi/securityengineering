"""Network probe: fetch a URL into a :class:`~webshield.models.Probe`.

READ-ONLY. This module issues a single GET request (following redirects) and
captures the status, headers, Set-Cookie values, body, and best-effort TLS
posture. It never sends payloads, never mutates server state, and never uses
any method other than GET.
"""

from __future__ import annotations

from urllib.parse import urlparse

import requests

from .models import Probe, CaseInsensitiveDict


# Identify ourselves honestly and as a scanner.
USER_AGENT = "WebShield/0.1 (+defensive-readonly-scanner)"

DEFAULT_TIMEOUT = 15


def _detect_http_redirect(url: str, timeout: int) -> bool:
    """Check whether the plain-HTTP form of ``url`` redirects to HTTPS.

    READ-ONLY: a single GET to the http:// origin, without following redirects,
    inspecting the Location header.
    """
    parsed = urlparse(url)
    http_url = parsed._replace(scheme="http").geturl()
    try:
        resp = requests.get(
            http_url,
            allow_redirects=False,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        )
    except requests.RequestException:
        return False

    if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("Location", "")
        return location.lower().startswith("https://")
    return False


def _negotiated_tls_version(response: requests.Response) -> str | None:
    """Best-effort extraction of the negotiated TLS version from a response."""
    try:
        raw = response.raw
        # urllib3 exposes the underlying socket via the connection.
        sock = getattr(raw, "_connection", None)
        if sock is not None:
            sock = getattr(sock, "sock", None)
        if sock is None:
            sock = getattr(getattr(raw, "_fp", None), "fp", None)
        if sock is not None and hasattr(sock, "version"):
            return sock.version()
    except Exception:
        return None
    return None


def fetch(url: str, timeout: int = DEFAULT_TIMEOUT) -> Probe:
    """Fetch ``url`` (GET only) and return a populated Probe.

    Args:
        url: target URL (http or https).
        timeout: per-request timeout in seconds.

    Returns:
        A Probe describing the response. On a request failure, a Probe with
        ``status_code == 0`` and best-effort metadata is returned.
    """
    headers = {"User-Agent": USER_AGENT}
    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers=headers,
            allow_redirects=True,
        )
    except requests.RequestException as exc:  # pragma: no cover - network path
        parsed = urlparse(url)
        return Probe(
            url=url,
            status_code=0,
            headers=CaseInsensitiveDict(),
            set_cookie=[],
            tls={
                "https": parsed.scheme == "https",
                "redirects_http_to_https": False,
                "tls_version": None,
                "hsts": False,
            },
            body=f"<request failed: {exc}>",
        )

    final_url = response.url
    parsed_final = urlparse(final_url)
    is_https = parsed_final.scheme == "https"

    # Collect Set-Cookie headers. requests merges duplicate headers, so use the
    # raw urllib3 headers to recover individual Set-Cookie lines when possible.
    set_cookie: list[str] = []
    try:
        raw_headers = response.raw.headers
        if hasattr(raw_headers, "get_all"):
            got = raw_headers.get_all("Set-Cookie")
            if got:
                set_cookie = list(got)
    except Exception:
        set_cookie = []
    if not set_cookie:
        single = response.headers.get("Set-Cookie")
        if single:
            set_cookie = [single]

    hsts_present = "strict-transport-security" in CaseInsensitiveDict(
        dict(response.headers)
    )

    redirects_http_to_https = False
    if is_https:
        redirects_http_to_https = _detect_http_redirect(final_url, timeout)

    tls = {
        "https": is_https,
        "redirects_http_to_https": redirects_http_to_https,
        "tls_version": _negotiated_tls_version(response) if is_https else None,
        "hsts": bool(hsts_present),
    }

    return Probe(
        url=final_url,
        status_code=response.status_code,
        headers=CaseInsensitiveDict(dict(response.headers)),
        set_cookie=set_cookie,
        tls=tls,
        body=response.text or "",
    )
