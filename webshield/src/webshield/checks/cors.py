"""CORS configuration checks.

Detects over-permissive Cross-Origin Resource Sharing configurations that can
expose authenticated data to arbitrary origins. The classic dangerous patterns:

- ``Access-Control-Allow-Origin: *`` together with
  ``Access-Control-Allow-Credentials: true``.
  (Browsers reject the literal combination, but servers that emit it usually
  also reflect the Origin, which IS exploitable -- so we flag it.)
- A reflected, arbitrary ``Origin`` echoed back in
  ``Access-Control-Allow-Origin`` together with credentials enabled. This is
  the genuinely exploitable misconfiguration.

The probe may record the request Origin it sent under ``tls`` is not relevant
here; instead we rely on ``headers`` plus an optional ``probe`` convention:
if the response ACAO equals a non-"*"/non-"null" specific origin AND
credentials are enabled, that is treated as a reflected-origin risk when it
matches the probe's recorded request origin (probe.headers may carry an
"x-webshield-request-origin" marker set by the fetcher). When no marker is
present we conservatively flag specific-origin + credentials as a warning.
"""

from __future__ import annotations

from ..models import Probe, Finding


def check_cors(probe: Probe) -> list[Finding]:
    acao = probe.headers.get("access-control-allow-origin")
    acac = probe.headers.get("access-control-allow-credentials")

    if acao is None:
        return [
            Finding(
                check_id="cors.policy",
                title="CORS policy",
                severity="info",
                verdict="pass",
                detail="No Access-Control-Allow-Origin header; CORS is not enabled.",
                remediation="",
            )
        ]

    acao_value = acao.strip()
    credentials_enabled = bool(acac) and acac.strip().lower() == "true"

    # The fetcher may record the Origin it sent so we can detect reflection.
    request_origin = probe.headers.get("x-webshield-request-origin")

    if acao_value == "*":
        if credentials_enabled:
            return [
                Finding(
                    check_id="cors.policy",
                    title="CORS policy",
                    severity="critical",
                    verdict="fail",
                    detail=(
                        "Access-Control-Allow-Origin is '*' while "
                        "Access-Control-Allow-Credentials is 'true'. This is an "
                        "invalid yet dangerous configuration that typically signals "
                        "an origin-reflecting backend exposing credentialed data."
                    ),
                    remediation=(
                        "Never combine a wildcard ACAO with credentials. Use an "
                        "explicit allow-list of trusted origins and only enable "
                        "credentials for those."
                    ),
                )
            ]
        return [
            Finding(
                check_id="cors.policy",
                title="CORS policy",
                severity="low",
                verdict="warn",
                detail=(
                    "Access-Control-Allow-Origin is '*'. This is acceptable for "
                    "public, non-credentialed resources but exposes responses to "
                    "any origin."
                ),
                remediation=(
                    "Restrict ACAO to specific trusted origins unless the resource "
                    "is intentionally public and carries no sensitive data."
                ),
            )
        ]

    if acao_value.lower() == "null":
        if credentials_enabled:
            return [
                Finding(
                    check_id="cors.policy",
                    title="CORS policy",
                    severity="high",
                    verdict="fail",
                    detail=(
                        "Access-Control-Allow-Origin is 'null' with credentials "
                        "enabled; sandboxed/opaque origins can exploit this."
                    ),
                    remediation="Never allow the 'null' origin with credentials.",
                )
            ]
        return [
            Finding(
                check_id="cors.policy",
                title="CORS policy",
                severity="low",
                verdict="warn",
                detail="Access-Control-Allow-Origin is 'null', which is risky.",
                remediation="Avoid returning ACAO 'null'; use explicit trusted origins.",
            )
        ]

    # Specific origin echoed back.
    reflected = request_origin is not None and acao_value == request_origin.strip()

    if credentials_enabled:
        if reflected:
            return [
                Finding(
                    check_id="cors.policy",
                    title="CORS policy",
                    severity="critical",
                    verdict="fail",
                    detail=(
                        f"The server reflected an arbitrary request Origin "
                        f"({acao_value!r}) into Access-Control-Allow-Origin while "
                        "allowing credentials. Any origin can read credentialed "
                        "responses."
                    ),
                    remediation=(
                        "Do not reflect the Origin header. Validate the Origin "
                        "against a strict allow-list before echoing it, and only "
                        "enable credentials for trusted origins."
                    ),
                )
            ]
        return [
            Finding(
                check_id="cors.policy",
                title="CORS policy",
                severity="medium",
                verdict="warn",
                detail=(
                    f"Access-Control-Allow-Origin is a specific origin "
                    f"({acao_value!r}) with credentials enabled. Verify the value "
                    "comes from a strict allow-list and is not reflected."
                ),
                remediation=(
                    "Ensure the allowed origin is from a fixed allow-list and not "
                    "dynamically reflected from the request."
                ),
            )
        ]

    return [
        Finding(
            check_id="cors.policy",
            title="CORS policy",
            severity="info",
            verdict="pass",
            detail=(
                f"Access-Control-Allow-Origin is a specific origin ({acao_value!r}) "
                "without credentials, which is a reasonable CORS configuration."
            ),
            remediation="",
        )
    ]
