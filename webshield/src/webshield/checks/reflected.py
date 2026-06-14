"""Reflected-input (potential reflected-XSS) detection.

This is a DETECTION-ONLY check. It NEVER sends weaponized payloads. Instead it
sends a single benign, unique marker as a query parameter and inspects whether
the marker is echoed back into the HTML response *unescaped*.

Detection logic:
    1. Build a unique marker that contains characters which MUST be HTML-escaped
       when reflected safely (``<`` and ``>``).
    2. Send it via an injectable ``fetcher(url) -> Probe`` (so tests can target
       a local app with no real network).
    3. If the raw marker appears verbatim in the body -> ``fail`` (the input is
       reflected without escaping, a reflected-XSS indicator).
    4. If only the HTML-escaped form of the marker appears -> ``pass``
       (the application correctly escapes user input).
    5. If the marker does not appear at all -> ``pass`` (not reflected).
"""

from __future__ import annotations

import html
import uuid
from typing import Callable
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

from ..models import Probe, Finding


# The parameter name we inject the marker under.
MARKER_PARAM = "q"


def _build_marker() -> str:
    """A benign, unique marker containing characters that require escaping."""
    token = uuid.uuid4().hex
    # Angle brackets are inert here (no script/handler) but force the question
    # of whether the app escapes HTML metacharacters.
    return f"<wsx_{token}>"


def _with_query_param(url: str, param: str, value: str) -> str:
    """Return ``url`` with ``param=value`` added/overridden in the query."""
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = value
    new_query = urlencode(query)
    return urlunparse(parsed._replace(query=new_query))


def check_reflected_input(
    fetcher: Callable[[str], Probe],
    url: str,
    param: str = MARKER_PARAM,
) -> Finding:
    """Detect whether a benign marker is reflected unescaped into the HTML.

    Args:
        fetcher: callable that fetches a URL and returns a Probe (injectable so
            tests can point at a local app).
        url: the base URL to probe.
        param: the query parameter name to inject the marker under.
    """
    marker = _build_marker()
    target = _with_query_param(url, param, marker)
    probe = fetcher(target)
    body = probe.body or ""

    escaped_marker = html.escape(marker)  # "<" -> "&lt;", ">" -> "&gt;"

    raw_present = marker in body
    escaped_present = escaped_marker in body

    if raw_present:
        return Finding(
            check_id="reflected.input",
            title="Reflected input (unescaped)",
            severity="high",
            verdict="fail",
            detail=(
                f"The benign marker was reflected UNESCAPED in the response body "
                f"(parameter {param!r}). Untrusted input echoed without HTML "
                "encoding is a reflected-XSS indicator."
            ),
            remediation=(
                "HTML-escape all user-controlled output (e.g. encode <, >, &, \" "
                "and '), and prefer context-aware templating/auto-escaping. "
                "Add a strong Content-Security-Policy as defense in depth."
            ),
        )

    if escaped_present:
        return Finding(
            check_id="reflected.input",
            title="Reflected input (escaped)",
            severity="info",
            verdict="pass",
            detail=(
                f"The marker was reflected but correctly HTML-escaped "
                f"(parameter {param!r})."
            ),
            remediation="",
        )

    return Finding(
        check_id="reflected.input",
        title="Reflected input",
        severity="info",
        verdict="pass",
        detail=(
            f"The injected marker was not reflected in the response "
            f"(parameter {param!r})."
        ),
        remediation="",
    )
