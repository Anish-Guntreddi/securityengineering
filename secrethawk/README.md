# SecretHawk

SecretHawk is a **defensive** Git secret-scanning CLI written in Python. It
scans a repository's working tree (and, optionally, its git history) for
accidentally committed credentials — AWS keys, GitHub tokens, Stripe keys,
private key blocks, JWTs, and generic high-entropy secrets — and reports them
as human-readable text, JSON, or **SARIF 2.1.0** for GitHub code scanning.

> ## ⚠️ AUTHORIZED USE ONLY
> SecretHawk is **defensive tooling**. Only scan repositories that **you own**
> or are **explicitly authorized to assess**. Do not use it against systems or
> codebases without permission. All detected previews are **redacted**; rotate
> any real credential that is discovered.

---

## Why

Secrets leak into git history constantly: a `.env` committed by accident, a
hard-coded API key in a config file, a private key checked into a `keys/`
directory. SecretHawk gives you a fast, dependency-light, CI-friendly way to
catch these before they reach production — and to fail a pull request when they
do.

## Install

SecretHawk uses a `src/` layout and a project-local virtual environment.

```bash
cd secrethawk
python3 -m venv .venv
.venv/bin/python -m pip install -U pip
.venv/bin/python -m pip install -e ".[dev]"
```

This installs the `secrethawk` console-script entry point.

## Usage

```bash
# Scan the current directory, human-readable text output (default).
secrethawk scan .

# Emit JSON.
secrethawk scan . --format json

# Emit SARIF 2.1.0 to a file (for GitHub code scanning).
secrethawk scan . --format sarif --output results.sarif

# Also scan git history (READ-ONLY `git log -p`).
secrethawk scan . --history

# Use an explicit allowlist config.
secrethawk scan . --config .secrethawk.toml

# Do not fail the process on findings (report only).
secrethawk scan . --no-fail-on-findings
```

By default `scan` exits **non-zero** when any finding is present, which makes it
a natural CI gate. Pass `--no-fail-on-findings` to report without failing.

You can also run it as a module: `python -m secrethawk scan .`.

## Detection types

SecretHawk combines **precise regex rules** with a **Shannon-entropy** detector
for the long tail of generic secrets.

| Detector | Examples |
| --- | --- |
| `aws-access-key-id` | `AKIA…` (16 chars) |
| `aws-secret-access-key` | 40-char base64 in a key assignment context |
| `github-pat` / `github-oauth` / `github-fine-grained-pat` | `ghp_…`, `gho_…`, `github_pat_…` |
| `slack-token` | `xoxb-…`, `xoxp-…`, etc. |
| `google-api-key` | `AIza…` |
| `stripe-secret-key` / `stripe-restricted-key` | `sk_live_…`, `rk_live_…` |
| `private-key` | `-----BEGIN [RSA/EC/OPENSSH/DSA/PGP] PRIVATE KEY-----` |
| `jwt` | `eyJ….eyJ….…` |
| `twilio-api-key` | `SK` + 32 hex |
| `sendgrid-api-key` | `SG.…` |
| `npm-token` | `npm_…` |
| `generic-secret-assignment` | `password = "…"`, `api_key = "…"`, `token = "…"`, … |
| `high-entropy-string` | long, random-looking tokens not covered by a rule |

The entropy detector only considers quoted strings and assignment right-hand
sides, requires a minimum length (default 20), and uses an entropy threshold
(default 4.0 bits/char). Known non-secret formats (hex digests, UUIDs) are
excluded to keep false positives low.

## Allowlisting

Findings can be suppressed three ways:

1. **Inline ignore** — add a comment marker on the offending line:

   ```python
   token = "ghp_…"  # secrethawk:ignore
   # or:
   token = "ghp_…"  # pragma: allowlist secret
   ```

2. **Path globs** — skip whole files/directories.

3. **Regex patterns** — suppress findings whose line or preview matches.

Configure 2 and 3 in a `.secrethawk.toml` at your repo root:

```toml
[allowlist]
paths = ["**/*.min.js", "vendor/**"]
patterns = ["your-api-key-here", "EXAMPLE"]
inline_markers = ["secrethawk:ignore", "pragma: allowlist secret"]
```

The file is loaded with the standard-library `tomllib`. When `--config` is not
given, SecretHawk auto-discovers `<scan-root>/.secrethawk.toml`.

## SARIF + GitHub code scanning

`--format sarif` produces a SARIF 2.1.0 document
(`$schema = https://json.schemastore.org/sarif-2.1.0.json`, `version = "2.1.0"`)
with `runs[0].tool.driver.name = "SecretHawk"`, a `rules` table, and `results`
that carry `ruleId`, `level`, `message.text`, and
`locations[].physicalLocation.artifactLocation.uri` + `region.startLine`.

SecretHawk ships a **vendored** JSON Schema at
`src/secrethawk/schemas/sarif-2.1.0.json` and exposes `validate_sarif(doc)`,
which validates the structure with `jsonschema` and **rejects** malformed
documents (wrong `version`, missing `runs`, missing `tool.driver.name`, results
missing `message`, etc.).

Upload the SARIF to GitHub to see findings in the **Security → Code scanning**
tab:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## GitHub Action

A composite action is provided in [`action.yml`](./action.yml). It sets up
Python, installs SecretHawk, runs
`secrethawk scan . --format sarif --output results.sarif`, and uploads the SARIF
to code scanning. See [`.github/workflows/example-usage.yml`](./.github/workflows/example-usage.yml)
for a complete example workflow. The workflow needs `security-events: write`
permission to upload SARIF.

```yaml
- uses: your-org/secrethawk@v0.1.0
  with:
    path: "."
    output: "results.sarif"
    fail-on-findings: "true"
```

## Verification gates

SecretHawk is built and validated against three hard gates, all exercised by
the test suite (`pytest`):

1. **Detection + false-positive control** — every planted secret in the fixture
   repo is found, and every allowlisted/benign string (sha256 hash, UUID,
   placeholder, inline-ignored line) is **not** flagged. The `clean/` subtree
   yields zero findings.
2. **SARIF validity** — SARIF output validates against the vendored schema, and
   deliberately malformed SARIF is rejected.
3. **CLI exit semantics** — the CLI exits **non-zero** on a planted tree and
   **zero** on a clean tree.

Run the suite:

```bash
.venv/bin/python -m pytest -q
```

## Development

```bash
cd secrethawk
python3 -m venv .venv
.venv/bin/python -m pip install -U pip
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest -q
```

The scanning core (`scanner.scan_content`) is **pure**: deterministic, with no
filesystem or git access, which keeps it easy to test and reason about. The
walker layer adds filesystem traversal, `.gitignore` handling, binary-file
skipping, and optional read-only git-history scanning.

## License

MIT.
