"""CLI tests using click's CliRunner.

Verifies:
  - The CLI refuses to run without --i-am-authorized (exit code 2).
  - With --i-am-authorized and an injected fetcher, it produces a graded report.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from webshield.cli import cli
from webshield.models import Probe


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_probe(name: str) -> Probe:
    data = json.loads((FIXTURES_DIR / f"{name}.json").read_text(encoding="utf-8"))
    return Probe.from_dict(data)


def _injected_fetcher(name: str):
    probe = _load_probe(name)

    def fetcher(url: str) -> Probe:
        # Return the recorded probe regardless of URL (and ignore the marker
        # query the reflected check appends -- the fixture body has no marker).
        return probe

    return fetcher


def _combined_output(result) -> str:
    """Return stdout+stderr regardless of click version stream handling."""
    text = result.output or ""
    try:
        text += result.stderr or ""
    except ValueError:
        # Older click with mixed streams raises if stderr wasn't separate.
        pass
    return text


def test_refuses_without_authorization():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "https://example.com"])
    assert result.exit_code == 2
    assert "Refusing to run" in _combined_output(result)


def test_refuses_without_authorization_message_mentions_flag():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "https://example.com"])
    assert result.exit_code == 2
    assert "--i-am-authorized" in _combined_output(result)


def test_scan_with_authorization_text(secure_fixture_name="secure"):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "https://secure.example.com", "--i-am-authorized"],
        obj={"fetcher": _injected_fetcher("secure")},
    )
    assert result.exit_code == 0, result.output
    assert "Overall grade:" in result.output
    assert "Content-Security-Policy" in result.output


def test_scan_with_authorization_json():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "https://insecure.example.com",
            "--i-am-authorized",
            "--format",
            "json",
        ],
        obj={"fetcher": _injected_fetcher("insecure")},
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["overall_grade"] == "F"
    assert payload["summary"]["fail"] > 0


def test_scan_writes_output_file(tmp_path):
    runner = CliRunner()
    out = tmp_path / "report.txt"
    result = runner.invoke(
        cli,
        [
            "scan",
            "https://secure.example.com",
            "--i-am-authorized",
            "--output",
            str(out),
        ],
        obj={"fetcher": _injected_fetcher("secure")},
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "Overall grade:" in content


def test_help_mentions_authorized_use():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "AUTHORIZED USE" in result.output
    assert "--i-am-authorized" in result.output
