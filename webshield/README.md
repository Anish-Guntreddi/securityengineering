# WebShield

WebShield is a **defensive, read-only web security-configuration scanner** CLI.
It inspects a single web target's security posture — HTTP security headers, TLS
configuration, cookie flags, CORS policy, and reflected input — and produces a
graded report with concrete remediation guidance.

WebShield is **non-destructive by design**: it issues only `GET` requests, never
sends weaponized payloads, and refuses to run without an explicit
authorized-target confirmation.

## Purpose

WebShield helps you verify that a site you own (or are authorized to test) has
sane, defense-in-depth security configuration. It is meant for:

- Engineers hardening their own services.
- CI checks that catch security-header regressions.
- Security reviewers performing a quick, safe configuration audit.

It is **not** an exploitation tool. The reflected-input check, for example, only
sends a single benign marker and reports whether it was echoed unescaped — it
never attempts to execute anything.

## Install

WebShield uses a `src/` layout and a project-local virtual environment.

```bash
cd webshield
python3 -m venv .venv
.venv/bin/python -m pip install -U pip
.venv/bin/python -m pip install -e ".[dev]"
```

This installs the `webshield` console script into the venv.

## Usage

```bash
# Refuses to run without explicit authorization (exit code 2):
.venv/bin/webshield scan https://example.com

# Run a scan you are authorized to perform:
.venv/bin/webshield scan https://example.com --i-am-authorized

# JSON output:
.venv/bin/webshield scan https://example.com --i-am-authorized --format json

# Write the report to a file:
.venv/bin/webshield scan https://example.com --i-am-authorized --output report.txt
```

You can also run it as a module: `python -m webshield scan ... --i-am-authorized`.

### Options

- `--i-am-authorized` (**required**): confirms you own or are authorized to test
  the target. Without it WebShield refuses to run and exits with code `2`.
- `--format [text|json]`: report format (default `text`).
- `--output FILE`: write the report to a file instead of stdout.

## The checks

| Area     | What it checks |
|----------|----------------|
| Headers  | `Content-Security-Policy` (presence + weak directives), `Strict-Transport-Security` (max-age + `includeSubDomains` sanity), clickjacking protection (`X-Frame-Options` **or** CSP `frame-ancestors`), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`. |
| TLS      | HTTPS in use, HTTP→HTTPS redirect, HSTS present, modern TLS (≥ 1.2). |
| Cookies  | Per `Set-Cookie`: `Secure`, `HttpOnly`, `SameSite` (including the invalid `SameSite=None` without `Secure`). |
| CORS     | Over-permissive policies: wildcard `Access-Control-Allow-Origin` with credentials, reflected arbitrary `Origin` with credentials, risky `null` origin. |
| Reflected input | Sends one benign unique marker as a query param and reports if it is reflected **unescaped** in the HTML (a reflected-XSS indicator). Detection only — no payloads. |

Each check yields a verdict of **pass** / **warn** / **fail**, and every
non-passing finding carries remediation guidance. The report rolls these up into
an overall letter grade **A–F**.

## Remediation philosophy

Every finding that is not a pass includes actionable, specific remediation: the
exact header to add, the recommended value, or the configuration change to make.
Guidance favors safe, modern defaults (e.g. restrictive CSP, `SameSite=Lax`,
TLS 1.2+) and defense in depth rather than one-off fixes.

## Authorized-use & safety design

WebShield is built to be safe to point at production:

- **Read-only / non-destructive**: only `GET` requests are issued. No forms are
  submitted, no state is changed, and no method other than `GET` is used.
- **No weaponized payloads**: the reflected-input check sends a single inert,
  unique marker and merely observes whether it is echoed unescaped.
- **Authorization gate**: the CLI **refuses to run** without
  `--i-am-authorized`, exiting with code `2` and a clear message. This is a
  deliberate speed bump so you affirm you own or are authorized to test the
  target.

**Only scan sites you own or are explicitly authorized to test.** Scanning
systems without permission may be illegal even with a read-only tool.

## Architecture

Every check is a **pure function over a `Probe`** dataclass (a recorded snapshot
of one HTTP response). This makes checks deterministic and unit-testable against
recorded fixtures with **no network access**.

```
src/webshield/
  models.py            Probe, Finding, case-insensitive headers
  probe.py             fetch(url) -> Probe  (READ-ONLY, GET only)
  runner.py            run_all(probe, fetcher=None)
  report.py            to_text / to_json + A–F grading
  cli.py               `webshield scan URL` with the authorization gate
  checks/
    headers.py  tls.py  cookies.py  cors.py  reflected.py
```

The reflected-input check takes an injectable `fetcher(url) -> Probe` so tests
can target a local app instead of the network.

## Verification gates

The test suite enforces three gates:

1. **Checks** produce correct pass/warn/fail on recorded **good and bad**
   fixtures (both detections and non-detections).
2. **Reflected-input** is validated against a deliberately-vulnerable local
   Flask app (`/echo`, must **fail**) and a safe app (`/safe`, must **pass**),
   started on an ephemeral port in a threaded pytest fixture.
3. **The CLI refuses to run** without the `--i-am-authorized` flag (exit `2`).

Run everything:

```bash
.venv/bin/python -m pytest -q
```
