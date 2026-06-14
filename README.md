# Security Engineering — Defensive Tooling Portfolio

> Three production-grade, **defensive & educational** security tools — built end-to-end,
> tested against concrete verification gates, and shipped with an explicit authorized-use posture.

**🔗 Live showcase → https://anish-guntreddi.github.io/securityengineering/**

`3 tools` · `205 tests passing` · `100% gates green` · `defensive only`

---

## ⚠️ Authorized use only

Everything here protects, audits, or teaches about code and infrastructure **you own or are
explicitly authorized to test**. There is no offensive tooling: no auto-revocation, no live key
abuse, no weaponized payloads, no fuzzing, no detection evasion. See [SECURITY.md](SECURITY.md).

---

## The toolkit

| # | Tool | Role | Stack | Tests | What it does |
|---|------|------|-------|-------|--------------|
| 01 | **[SecretHawk](secrethawk/)** | Detection | Python CLI | **90** | Scans your own Git repos for leaked keys/tokens/credentials — 15 rules + Shannon-entropy, allowlists, SARIF + JSON, and a GitHub Action. |
| 02 | **[WebShield](webshield/)** | Auditing | Python CLI | **59** | Read-only audit of a site you own — 13 checks across headers, TLS, cookies, CORS, and reflected-input, graded A–F, behind a hard authorization gate. |
| 03 | **[AuthLab](authlab/)** | Education | Next.js + Prisma | **56** | A playground contrasting secure vs. insecure OAuth & session patterns — Authorization Code + PKCE, refresh rotation, and labeled, sandboxed anti-pattern demos. |

---

## Why this exists

Most portfolios skip security. This one leans in — detection, configuration auditing, and
secure-design education, the work backend, platform, and AppSec teams actually value. Every tool
follows the same discipline:

- **A pure, testable core** wrapped in a thin I/O shell. SecretHawk's `scan_content(text) → findings`,
  WebShield's `check(probe) → findings`, and AuthLab's `pkce`/`session` modules are pure functions
  over plain data — trivially unit-testable with no filesystem, network, or browser.
- **Tests that prove detections *and* non-detections.** A scanner is only trustworthy if it stays
  quiet on benign input. Each suite asserts what the tool catches *and* what it deliberately ignores.
- **A green gate is the definition of done.** Each project defines concrete verification gates — a
  passing test, a valid SARIF doc, a refusal-without-authorization, an end-to-end PKCE exchange —
  and "done" means those gates are green, not that the code looks plausible.

---

## Quickstart

### SecretHawk — scan a repo you own
```bash
cd secrethawk
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/secrethawk scan /path/to/your/repo            # text report
.venv/bin/secrethawk scan . --format sarif -o results.sarif
.venv/bin/pytest -q                                      # 90 tests
```

### WebShield — audit a site you own
```bash
cd webshield
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/webshield scan https://your-site.example --i-am-authorized
.venv/bin/pytest -q                                      # 59 tests
```

### AuthLab — explore secure vs. insecure auth
```bash
cd authlab
npm install
npm run db:push      # SQLite, zero config
npm run dev          # http://localhost:3000
npm test             # 56 tests
```

---

## Verification gates (the definition of "done")

| Tool | Gate |
|------|------|
| **SecretHawk** | Every planted secret found; every allowlisted/benign string suppressed · SARIF validates against the vendored schema, malformed SARIF rejected · non-zero exit on a planted tree, zero on a clean tree. |
| **WebShield** | Correct pass/warn/fail on recorded good & bad fixtures · reflected-input check fails on a vulnerable app and passes on a safe one · refuses to run without the authorized-target flag. |
| **AuthLab** | End-to-end secure flow (PKCE verifier/challenge, state validation, session issuance) · insecure demos labeled & isolated, cookie flags verified · production build & lint succeed. |

All gates pass. CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs all three suites on every push.

---

## Repository layout

```
securityengineering/
├── secrethawk/     # 01 · Git secret scanner (Python, src/ layout, pytest)
├── webshield/      # 02 · Web security-config auditor (Python, pure checks over a Probe)
├── authlab/        # 03 · OAuth/session playground (Next.js App Router, Prisma, Vitest)
├── docs/           # GitHub Pages showcase site (hand-written, dependency-free)
├── .github/        # unified CI
├── SECURITY.md     # authorized-use policy
└── LICENSE         # MIT
```

## Tech

`Python` · `TypeScript` · `Next.js` · `Prisma` · `Flask` · regex + Shannon entropy ·
OAuth2 / PKCE / sessions · SARIF · `pytest` · `vitest` · GitHub Actions

## License

[MIT](LICENSE) © Anish Guntreddi
