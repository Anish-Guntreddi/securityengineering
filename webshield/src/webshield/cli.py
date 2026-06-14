"""WebShield command-line interface.

Provides a single ``scan`` command. The CLI is a defensive, read-only tool and
REFUSES to run without an explicit ``--i-am-authorized`` confirmation flag.
"""

from __future__ import annotations

import sys
from typing import Callable

import click

from . import __version__
from .models import Probe
from .runner import run_all
from .report import to_text, to_json


AUTHORIZED_USE_EPILOG = (
    "AUTHORIZED USE ONLY:\n"
    "  WebShield is a defensive, READ-ONLY scanner. It performs GET-only,\n"
    "  non-destructive requests and never sends weaponized payloads.\n"
    "  Only scan sites you own or are explicitly authorized to test.\n"
    "  You must pass --i-am-authorized to confirm authorization."
)

# Exit code returned when the authorization gate is not satisfied.
EXIT_NOT_AUTHORIZED = 2


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    epilog=AUTHORIZED_USE_EPILOG,
)
@click.version_option(version=__version__, prog_name="webshield")
def cli() -> None:
    """WebShield: a defensive, read-only web security-configuration scanner."""


@cli.command(epilog=AUTHORIZED_USE_EPILOG)
@click.argument("url")
@click.option(
    "--i-am-authorized",
    "authorized",
    is_flag=True,
    default=False,
    help="REQUIRED. Confirm you own or are authorized to test the target.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Report output format.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write the report to FILE instead of stdout.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    url: str,
    authorized: bool,
    output_format: str,
    output_file: str | None,
) -> None:
    """Scan URL for security-configuration issues (READ-ONLY)."""
    if not authorized:
        click.echo(
            "Refusing to run: WebShield will not scan a target without explicit "
            "authorization.\n"
            "Re-run with --i-am-authorized to confirm you own or are authorized "
            "to test this target.\n"
            "WebShield is read-only and non-destructive, but you are responsible "
            "for having permission.",
            err=True,
        )
        ctx.exit(EXIT_NOT_AUTHORIZED)

    fetcher: Callable[[str], Probe] = ctx.obj.get("fetcher") if ctx.obj else None
    if fetcher is None:
        # Import lazily so unit tests that inject a fetcher do not require the
        # network stack to import.
        from .probe import fetch as fetcher  # type: ignore[assignment]

    probe = fetcher(url)
    findings = run_all(probe, fetcher=fetcher)

    report = to_json(findings) if output_format == "json" else to_text(findings)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as handle:
            handle.write(report)
        click.echo(f"Report written to {output_file}")
    else:
        click.echo(report)


def main(argv: list[str] | None = None) -> int:
    """Console-script entry point. Returns a process exit code."""
    try:
        # standalone_mode=False lets us capture the exit code without click
        # calling sys.exit directly, which is friendlier for embedding/tests.
        # With standalone_mode=False, click catches ctx.exit() and RETURNS the
        # code, so we must use the return value as our process exit code.
        result = cli.main(
            args=argv if argv is not None else sys.argv[1:],
            prog_name="webshield",
            standalone_mode=False,
            obj={},
        )
        return int(result) if isinstance(result, int) else 0
    except SystemExit as exc:  # pragma: no cover - defensive
        return int(exc.code) if isinstance(exc.code, int) else 0
    except click.ClickException as exc:
        exc.show()
        return exc.exit_code
    except click.exceptions.Abort:  # pragma: no cover - defensive
        click.echo("Aborted.", err=True)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
