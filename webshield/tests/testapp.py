"""A small Flask app used ONLY by the test suite.

It deliberately exposes:
  - /echo?q=...   : VULNERABLE -- reflects q UNESCAPED into the HTML body.
  - /safe?q=...   : SAFE       -- reflects q HTML-escaped into the HTML body.
  - /secure       : a response with strong security headers + secure cookie.
  - /insecure     : a response missing security headers + insecure cookie.

This app is never shipped or run by the scanner itself; it is a local target so
tests can validate detections against a real (controlled) server.
"""

from __future__ import annotations

from markupsafe import escape
from flask import Flask, request, Response


# A generic page template with a single slot. Filling it is a plain string
# operation; whether the inserted content is safe depends entirely on the
# CALLER pre-escaping it. The vulnerable endpoint passes raw input; the safe
# endpoint passes an HTML-escaped value.
_PAGE_TEMPLATE = "<html><body><h1>{heading}</h1><div>{slot}</div></body></html>"


def _render_page(heading: str, slot_content: str) -> str:
    """Insert ``slot_content`` verbatim into the page template.

    This helper does NOT escape ``slot_content`` -- escaping (or not) is the
    caller's responsibility, which is exactly what lets us model both a
    vulnerable and a safe endpoint with one renderer.
    """
    return _PAGE_TEMPLATE.format(heading=heading, slot=slot_content)


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/echo")
    def echo() -> Response:
        # VULNERABLE BY DESIGN (test fixture only): the raw, user-supplied value
        # is inserted into the page with NO escaping. This deliberately-
        # vulnerable endpoint exists solely so the reflected-input DETECTOR can
        # be proven to fire against a real local target. It is never shipped or
        # run by the scanner.
        raw_input = request.args.get("q", "")
        return Response(_render_page("Echo", raw_input), mimetype="text/html")

    @app.route("/safe")
    def safe() -> Response:
        # SAFE: the value is HTML-escaped BEFORE being handed to the renderer, so
        # angle brackets become entities and nothing is reflected unescaped.
        escaped_input = str(escape(request.args.get("q", "")))
        return Response(_render_page("Safe", escaped_input), mimetype="text/html")

    @app.route("/secure")
    def secure() -> Response:
        resp = Response(
            "<html><body>secure</body></html>", mimetype="text/html"
        )
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'self'"
        )
        resp.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        resp.headers["Set-Cookie"] = "sid=abc; Secure; HttpOnly; SameSite=Lax"
        return resp

    @app.route("/insecure")
    def insecure() -> Response:
        resp = Response(
            "<html><body>insecure</body></html>", mimetype="text/html"
        )
        # No security headers at all; an insecure cookie.
        resp.headers["Set-Cookie"] = "sid=abc"
        return resp

    return app


if __name__ == "__main__":  # pragma: no cover - manual debugging only
    create_app().run(port=5000)
