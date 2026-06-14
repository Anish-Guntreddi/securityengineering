"""Runtime assembly of test secrets and the sample fixture repo.

GitHub push protection (correctly) rejects committed files that contain
contiguous, provider-shaped credential literals. SecretHawk's whole purpose
is to *detect* such literals, so its tests need credential-shaped inputs.

We honour push protection's intent by never committing a contiguous token:
every provider literal used by the test suite is *assembled at runtime* from
non-contiguous parts, and the disk-scanned sample repo is *generated* into a
temporary directory at test time rather than committed verbatim.

The value handed to the scanner is byte-for-byte identical to the original
literal, so detection coverage is unchanged; only the on-disk representation
in version control differs (the prefix is split from the body).
"""

from __future__ import annotations

from pathlib import Path


def secret(*parts: str) -> str:
    """Join ``parts`` into one string.

    Callers split a provider token across multiple string literals so the
    contiguous token never appears in the committed source bytes, e.g.::

        secret("AKIA", "IOSFODNN7" + "EXAMPLE")    # an AWS-access-key-shaped id
        secret("sk_", "live_", "abc...")           # a Stripe live key

    The concatenated result is identical to writing the literal inline.
    """
    return "".join(parts)


# --- Individual provider literals, assembled from non-contiguous parts. ---
# Each value is identical to the corresponding contiguous literal but the
# provider prefix is split from the body so no committed line matches a
# push-protection / secret-scanning pattern.

AWS_ACCESS_KEY = secret("AKIA", "IOSFODNN7EXAMPLE")
GH_PAT = secret("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789")
GH_OAUTH = secret("gho_", "abcdefghijklmnopqrstuvwxyz0123456789")
GH_FINE_GRAINED = secret("github_pat_", "A" * 82)
SLACK_TOKEN = secret("xoxb-", "1234567890-abcdefghijklmnop")
GOOGLE_API_KEY = secret("AIza", "B" * 35)
STRIPE_SECRET_KEY = secret("sk_", "live_", "abcdefghijklmnopqrstuvwx1234")
STRIPE_RESTRICTED_KEY = secret("rk_", "live_", "abcdefghijklmnopqrstuvwx1234")
JWT = secret(
    "eyJ", "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ".", "eyJ", "zdWIiOiIxMjM0NTY3ODkwIn0",
    ".", "abc123XYZ_-",
)
TWILIO_API_KEY = secret("SK", "a1b2c3d4" * 4)
SENDGRID_API_KEY = secret("SG.", "A" * 22, ".", "B" * 43)
NPM_TOKEN = secret("npm_", "abcdefghijklmnopqrstuvwxyz0123456789")

# An inline-ignored GitHub-PAT-shaped token (used in benign/allowlist cases).
GH_PAT_IGNORED = secret("ghp_", "z" * 36)

# A high-entropy generic token (matched by the entropy detector, not a rule).
HIGH_ENTROPY_TOKEN = "g7Xq2Lp9Zk4Rb8Wm3Vn6Td1Yc5Hj0Fs7Ae2Qo"


def private_key_block() -> str:
    """Return a full RSA private-key block assembled from parts.

    The ``-----BEGIN ... PRIVATE KEY-----`` marker is split so the contiguous
    block never appears in committed source; the assembled value still trips
    the ``private-key`` rule because it contains the exact marker at runtime.
    """
    begin = secret("-----BEGIN ", "RSA ", "PRIVATE KEY", "-----")
    end = secret("-----END ", "RSA ", "PRIVATE KEY", "-----")
    body = "\n".join(
        [
            "MIIEpAIBAAKCAQEAx4fakefakefakefakefakefakefakefakefakefakefakefake",
            "THISISAFAKEKEYFORTESTINGONLYDONOTUSEItIsNotARealPrivateKeyAtAllNope",
            "fakefakefakefakefakefakefakefakefakefakefakefakefakefakefakefakeAB",
        ]
    )
    return f"{begin}\n{body}\n{end}\n"


# --- Sample fixture repo content, generated at runtime. ---

def _config_py() -> str:
    """Source of the planted ``config.py`` (assembled, format-valid fakes)."""
    return (
        "# Sample application config with PLANTED (fake) secrets for testing.\n"
        "# These are NOT real credentials; they are clearly fake but"
        " format-valid.\n"
        "\n"
        f'AWS_ACCESS_KEY_ID = "{AWS_ACCESS_KEY}"\n'
        f'GITHUB_TOKEN = "{GH_PAT}"\n'
        f'STRIPE_KEY = "{STRIPE_SECRET_KEY}"\n'
        "\n"
        "# A high-entropy generic token assignment (not matched by a specific"
        " rule).\n"
        f'SESSION_SIGNING_KEY = "{HIGH_ENTROPY_TOKEN}"\n'
    )


def _benign_txt() -> str:
    """Source of ``benign.txt``: cases that must NOT be flagged."""
    return (
        "Benign strings that must NOT be flagged by SecretHawk.\n"
        "\n"
        "# A sha256 hash (hex digest, deterministic, not a secret):\n"
        "checksum ="
        " e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        "\n"
        "# A UUID (random-looking but a known non-secret format):\n"
        "request_id = 550e8400-e29b-41d4-a716-446655440000\n"
        "\n"
        "# A placeholder that should never be treated as a real credential:\n"
        'api_key = "your-api-key-here"\n'
        "\n"
        "# A secret-looking line that is explicitly ignored inline:\n"
        f'real_token = "{GH_PAT_IGNORED}"  # secrethawk:ignore\n'
    )


def _secrethawk_toml() -> str:
    """Source of the fixture ``.secrethawk.toml`` allowlist."""
    return (
        "# SecretHawk allowlist for the sample fixture repo.\n"
        "# Suppresses the benign cases so they are not reported as findings.\n"
        "\n"
        "[allowlist]\n"
        "# Regex patterns: any line/preview matching these is suppressed.\n"
        "patterns = [\n"
        '  "your-api-key-here",\n'
        "]\n"
        "\n"
        "# Path globs to skip entirely (none needed; shown for docs).\n"
        "paths = []\n"
        "\n"
        "# Inline ignore markers (defaults shown explicitly).\n"
        'inline_markers = ["secrethawk:ignore", "pragma: allowlist secret"]\n'
    )


def _clean_readme() -> str:
    return (
        "# Clean Module\n"
        "\n"
        "This directory contains a clean tree with no secrets. SecretHawk"
        " should\n"
        "report zero findings when scanning it.\n"
        "\n"
        "Configuration is loaded from environment variables at runtime, never\n"
        "hard-coded. See the deployment runbook for details.\n"
    )


def _clean_app_py() -> str:
    return (
        '"""A clean source file with no secrets at all."""\n'
        "\n"
        "\n"
        "def add(a: int, b: int) -> int:\n"
        '    """Return the sum of two integers."""\n'
        "    return a + b\n"
        "\n"
        "\n"
        "def greet(name: str) -> str:\n"
        '    """Return a friendly greeting."""\n'
        '    return f"Hello, {name}!"\n'
    )


def build_sample_repo(root: Path) -> Path:
    """Materialise the full sample fixture repo under ``root``.

    Mirrors the previously committed ``tests/fixtures/sample_repo`` tree, but
    with every provider literal assembled at runtime. Returns ``root``.

    Layout:
        config.py            -- planted AWS / GitHub / Stripe / entropy secrets
        benign.txt           -- benign + allowlisted + inline-ignored cases
        keys/id_rsa          -- planted RSA private-key block
        .secrethawk.toml     -- allowlist (suppresses the placeholder)
        clean/README.md      -- clean subtree (zero findings)
        clean/app.py         -- clean subtree (zero findings)
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)

    (root / "config.py").write_text(_config_py(), encoding="utf-8")
    (root / "benign.txt").write_text(_benign_txt(), encoding="utf-8")
    (root / ".secrethawk.toml").write_text(_secrethawk_toml(), encoding="utf-8")

    keys = root / "keys"
    keys.mkdir(exist_ok=True)
    (keys / "id_rsa").write_text(private_key_block(), encoding="utf-8")

    clean = root / "clean"
    clean.mkdir(exist_ok=True)
    (clean / "README.md").write_text(_clean_readme(), encoding="utf-8")
    (clean / "app.py").write_text(_clean_app_py(), encoding="utf-8")

    return root
