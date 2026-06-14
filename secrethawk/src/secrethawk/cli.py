"""Command-line interface for SecretHawk.

Usage::

    secrethawk scan PATH [--history] [--format text|json|sarif]
                         [--output FILE] [--config PATH]
                         [--fail-on-findings/--no-fail-on-findings]

AUTHORIZED USE ONLY: only scan repositories that you own or are explicitly
authorized to assess.
"""

from __future__ import annotations

import json
import sys

import click

from . import __version__
from .allowlist import Allowlist
from .models import Finding
from .reporters import to_json, to_sarif
from .walker import walk_repo

_EPILOG = (
    "AUTHORIZED USE ONLY: SecretHawk is defensive tooling. Only scan "
    "repositories that you own or are explicitly authorized to assess."
)


def _render_text(findings: list[Finding]) -> str:
    """Render a redacted, human-readable summary of ``findings``."""
    if not findings:
        return "SecretHawk: no secrets detected. ✓"
    lines = [f"SecretHawk: {len(findings)} potential secret(s) detected.", ""]
    for f in findings:
        lines.append(
            f"  [{f.severity.upper():8}] {f.rule_id} ({f.detector})\n"
            f"      {f.file_path}:{f.line}:{f.column}\n"
            f"      preview: {f.match_preview}"
        )
    lines.append("")
    lines.append(
        "Remember: review each finding and rotate any real credentials."
    )
    return "\n".join(lines)


@click.group(epilog=_EPILOG)
@click.version_option(__version__, prog_name="secrethawk")
def cli() -> None:
    """SecretHawk: a defensive Git secret-scanning CLI.

    Scan repositories you own for accidentally committed credentials.
    """


@cli.command(epilog=_EPILOG)
@click.argument("path", type=click.Path(exists=True, file_okay=True, dir_okay=True))
@click.option("--history", is_flag=True, help="Also scan git history (read-only).")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["sarif", "json", "text"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write output to FILE instead of stdout.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to a .secrethawk.toml allowlist config.",
)
@click.option(
    "--fail-on-findings/--no-fail-on-findings",
    default=True,
    show_default=True,
    help="Exit non-zero when findings are present.",
)
def scan(
    path: str,
    history: bool,
    output_format: str,
    output_file: str | None,
    config_path: str | None,
    fail_on_findings: bool,
) -> None:
    """Scan PATH (a file or directory) for secrets."""
    import os

    if config_path:
        allowlist = Allowlist.load(config_path)
    else:
        # Discover from the scan root when PATH is a directory.
        root = path if os.path.isdir(path) else os.path.dirname(path) or "."
        allowlist = Allowlist.discover(root)

    if os.path.isdir(path):
        findings = walk_repo(path, scan_history=history, allowlist=allowlist)
    else:
        from .scanner import scan_content

        with open(path, "rb") as fh:
            data = fh.read()
        text = data.decode("utf-8", errors="replace")
        rel = os.path.basename(path)
        findings = scan_content(text, rel, allowlist)

    fmt = output_format.lower()
    if fmt == "json":
        rendered = json.dumps(to_json(findings), indent=2, sort_keys=True)
    elif fmt == "sarif":
        rendered = json.dumps(
            to_sarif(findings, __version__), indent=2, sort_keys=True
        )
    else:
        rendered = _render_text(findings)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(rendered + "\n")
        click.echo(f"Wrote {fmt} output to {output_file}")
    else:
        click.echo(rendered)

    if findings and fail_on_findings:
        sys.exit(1)
    sys.exit(0)


def main() -> None:
    """Console-script entry point."""
    cli(prog_name="secrethawk")


if __name__ == "__main__":  # pragma: no cover
    main()
