"""WebShield: a defensive, read-only web security-configuration scanner.

WebShield performs non-destructive, GET-only inspection of a web target's
security configuration (headers, TLS posture, cookies, CORS, and reflected
input). It NEVER sends weaponized payloads and refuses to run without an
explicit authorized-target confirmation.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
