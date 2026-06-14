"""Tests for the reflected-input detector against a real local Flask app.

The Flask app is started on an ephemeral port in a background thread. The
detector must FAIL on the vulnerable /echo endpoint (unescaped reflection) and
PASS on the safe /safe endpoint (HTML-escaped reflection).
"""

from __future__ import annotations

import socket
import threading
from wsgiref.simple_server import make_server, WSGIServer
from wsgiref.simple_server import WSGIRequestHandler

import pytest

from webshield.checks.reflected import check_reflected_input
from webshield.probe import fetch
from testapp import create_app


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *args, **kwargs):  # silence request logging
        pass


@pytest.fixture(scope="module")
def live_server():
    """Start the Flask test app on an ephemeral port in a background thread."""
    app = create_app()

    # Bind to an ephemeral port chosen by the OS.
    httpd: WSGIServer = make_server("127.0.0.1", 0, app, handler_class=_QuietHandler)
    host, port = httpd.server_address
    base_url = f"http://127.0.0.1:{port}"

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    # Wait until the server accepts connections.
    _wait_for_port("127.0.0.1", port)

    try:
        yield base_url
    finally:
        httpd.shutdown()
        thread.join(timeout=5)


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> None:
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"server at {host}:{port} did not start in time")


def test_reflected_check_fails_on_vulnerable_echo(live_server):
    finding = check_reflected_input(fetch, f"{live_server}/echo")
    assert finding.verdict == "fail", finding.detail
    assert finding.check_id == "reflected.input"
    assert finding.remediation


def test_reflected_check_passes_on_safe_endpoint(live_server):
    finding = check_reflected_input(fetch, f"{live_server}/safe")
    assert finding.verdict == "pass", finding.detail


def test_reflected_check_passes_when_not_reflected(live_server):
    # /secure does not echo the query parameter at all.
    finding = check_reflected_input(fetch, f"{live_server}/secure")
    assert finding.verdict == "pass", finding.detail
