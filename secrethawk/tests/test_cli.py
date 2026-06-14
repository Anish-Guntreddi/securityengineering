"""Tests for the click CLI using CliRunner.

The scanned sample repo is built at runtime by the ``sample_repo`` session
fixture (see ``conftest.py`` / ``tests/_assembly.py``) so no committed file
contains a contiguous, provider-shaped credential. CLI behaviour over the
generated tree is identical to scanning a committed fixture.
"""

import json
from pathlib import Path

from click.testing import CliRunner

from secrethawk.cli import cli
from secrethawk.reporters import is_valid_sarif
from tests._assembly import AWS_ACCESS_KEY


def test_scan_planted_tree_nonzero_exit(sample_repo: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(sample_repo)])
    assert result.exit_code == 1, result.output
    assert "potential secret" in result.output


def test_scan_clean_tree_zero_exit(clean_subtree: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(clean_subtree)])
    assert result.exit_code == 0, result.output
    assert "no secrets detected" in result.output


def test_no_fail_on_findings_exits_zero(sample_repo: Path):
    runner = CliRunner()
    result = runner.invoke(
        cli, ["scan", str(sample_repo), "--no-fail-on-findings"]
    )
    assert result.exit_code == 0, result.output


def test_json_format_output(sample_repo: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(sample_repo), "--format", "json"])
    assert result.exit_code == 1
    doc = json.loads(result.output)
    assert doc["tool"] == "SecretHawk"
    assert doc["finding_count"] >= 1


def test_sarif_format_output_validates(sample_repo: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(sample_repo), "--format", "sarif"])
    assert result.exit_code == 1
    doc = json.loads(result.output)
    assert is_valid_sarif(doc) is True


def test_output_to_file(sample_repo: Path, tmp_path: Path):
    out = tmp_path / "results.sarif"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(sample_repo), "--format", "sarif", "--output", str(out)],
    )
    assert result.exit_code == 1
    assert out.exists()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert is_valid_sarif(doc) is True


def test_version_flag():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "secrethawk" in result.output.lower()


def test_help_has_authorized_use_note():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "AUTHORIZED USE" in result.output


def test_scan_single_file(tmp_path: Path):
    f = tmp_path / "secrets.py"
    f.write_text(f'k = "{AWS_ACCESS_KEY}"\n', encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(f)])
    assert result.exit_code == 1
    assert "potential secret" in result.output


def test_config_option(tmp_path: Path):
    # A custom config that allowlists the AWS example pattern.
    cfg = tmp_path / "custom.toml"
    cfg.write_text(
        '[allowlist]\npatterns = ["EXAMPLE"]\n', encoding="utf-8"
    )
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text(
        f'k = "{AWS_ACCESS_KEY}"\n', encoding="utf-8"
    )
    runner = CliRunner()
    result = runner.invoke(
        cli, ["scan", str(src), "--config", str(cfg)]
    )
    # The only planted secret is allowlisted, so clean exit.
    assert result.exit_code == 0, result.output
