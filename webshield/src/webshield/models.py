"""Core data models for WebShield.

These dataclasses are the pure, network-free inputs and outputs that every
check operates over. A ``Probe`` is a recorded snapshot of a single HTTP
response (plus best-effort TLS metadata); checks consume a ``Probe`` and emit
``Finding`` objects. Because checks are pure functions over a ``Probe``, they
can be unit tested against recorded fixtures with no network access.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Mapping


# Allowed verdict values for a Finding.
VALID_VERDICTS = ("pass", "warn", "fail")

# Allowed severity values for a Finding.
VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")


class CaseInsensitiveDict(dict):
    """A dict subclass that performs case-insensitive key lookups.

    HTTP header names are case-insensitive (RFC 7230), so this wrapper lets
    checks look up ``headers["content-security-policy"]`` regardless of how the
    server cased the header. Original key casing is preserved for display.
    """

    def __init__(self, data: Mapping[str, Any] | None = None) -> None:
        super().__init__()
        self._lower_map: dict[str, str] = {}
        if data:
            for key, value in data.items():
                self[key] = value

    def __setitem__(self, key: str, value: Any) -> None:
        lowered = key.lower()
        # Remove any previously-stored key that differs only in case.
        existing = self._lower_map.get(lowered)
        if existing is not None and existing != key:
            super().__delitem__(existing)
        self._lower_map[lowered] = key
        super().__setitem__(key, value)

    def __getitem__(self, key: str) -> Any:
        real_key = self._lower_map[key.lower()]
        return super().__getitem__(real_key)

    def __delitem__(self, key: str) -> None:
        lowered = key.lower()
        real_key = self._lower_map.pop(lowered)
        super().__delitem__(real_key)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return super().__contains__(key)
        return key.lower() in self._lower_map

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


@dataclass
class Probe:
    """A recorded snapshot of a single HTTP response.

    Attributes:
        url: The final URL that was fetched.
        status_code: HTTP status code of the response.
        headers: Response headers (case-insensitive lookups).
        set_cookie: Raw ``Set-Cookie`` header values (one entry per cookie).
        tls: Best-effort TLS posture, with keys:
            ``https`` (bool), ``redirects_http_to_https`` (bool),
            ``tls_version`` (str|None, e.g. "TLSv1.3"), ``hsts`` (bool).
        body: The response body as text.
    """

    url: str
    status_code: int = 0
    headers: CaseInsensitiveDict = field(default_factory=CaseInsensitiveDict)
    set_cookie: list[str] = field(default_factory=list)
    tls: dict[str, Any] = field(default_factory=dict)
    body: str = ""

    def __post_init__(self) -> None:
        # Allow callers / fixtures to pass a plain dict for headers.
        if not isinstance(self.headers, CaseInsensitiveDict):
            self.headers = CaseInsensitiveDict(self.headers or {})

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Probe":
        """Build a Probe from a plain dict (e.g. a loaded JSON fixture)."""
        return cls(
            url=data["url"],
            status_code=int(data.get("status_code", 0)),
            headers=CaseInsensitiveDict(data.get("headers") or {}),
            set_cookie=list(data.get("set_cookie") or []),
            tls=dict(data.get("tls") or {}),
            body=str(data.get("body") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict suitable for JSON."""
        return {
            "url": self.url,
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "set_cookie": list(self.set_cookie),
            "tls": dict(self.tls),
            "body": self.body,
        }


@dataclass
class Finding:
    """The result of a single security check.

    Attributes:
        check_id: Stable machine identifier (e.g. "headers.csp").
        title: Human-readable title.
        severity: One of VALID_SEVERITIES.
        verdict: One of VALID_VERDICTS ("pass", "warn", "fail").
        detail: Explanation of what was observed.
        remediation: Concrete guidance on how to fix the issue.
    """

    check_id: str
    title: str
    severity: str
    verdict: str
    detail: str
    remediation: str = ""

    def __post_init__(self) -> None:
        if self.verdict not in VALID_VERDICTS:
            raise ValueError(
                f"invalid verdict {self.verdict!r}; expected one of {VALID_VERDICTS}"
            )
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"invalid severity {self.severity!r}; expected one of {VALID_SEVERITIES}"
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
