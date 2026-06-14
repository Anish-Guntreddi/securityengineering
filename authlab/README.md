# AuthLab

An **educational, fully sandboxed** playground that compares the **secure** way
to implement OAuth 2.0 + sessions with common **insecure** anti-patterns, side
by side.

> ⚠️ **No real credentials are involved anywhere in AuthLab.** The "OAuth
> provider" is a self-contained mock Authorization Server that runs inside this
> app (`/api/mock-oauth/*`), uses no external network, and issues opaque random
> tokens for a single fixed pseudo-user (`sandbox-user-001`). Nothing here can
> authenticate against a real identity provider, and the insecure demos are
> loudly labeled and isolated from the real flow.

Built with **Next.js (App Router, TypeScript)**, **Prisma ORM** on **SQLite**
(zero-config), and **Vitest**.

---

## The secure flow

AuthLab implements the OAuth 2.0 **Authorization Code flow with PKCE**, entirely
server-side, plus refresh-token rotation and hardened session cookies.

```
Browser            /api/auth/login        Mock provider           /api/auth/callback
   │  GET /login        │                       │                        │
   ├───────────────────▶│  gen verifier+challenge(S256)+state            │
   │                    │  store AuthRequest, set HttpOnly cookies        │
   │  302 → /authorize?code_challenge=…&state=…                          │
   ├────────────────────────────────────────────▶│ validate client/redirect/state/challenge
   │                                              │ issue single-use code bound to challenge
   │  302 → /callback?code=…&state=…              │                        │
   ├──────────────────────────────────────────────────────────────────▶ │ validate state (constant-time)
   │                                              │  POST /token (server, back-channel)
   │                                              │◀────── code + code_verifier ───────────┤
   │                                              │ verify sha256(verifier)==challenge      │
   │                                              │────── access + refresh tokens ─────────▶│
   │  200 + Set-Cookie: session (HttpOnly; Secure; SameSite=Lax)                            │
   │◀───────────────────────────────────────────────────────────────────────────────────── │
```

### 1. PKCE (RFC 7636)

- `lib/pkce.ts` generates a random `code_verifier` (≥256-bit) and derives the
  S256 `code_challenge = base64url(sha256(verifier))`.
- The **verifier never travels on the front channel** — only the challenge does.
  It is held server-side in a short-lived `HttpOnly` cookie.
- The mock `/token` endpoint rejects any exchange whose verifier does not hash to
  the stored challenge. Only **S256** is supported (`plain` is intentionally not
  implemented).

### 2. Anti-CSRF `state`

- A high-entropy `state` is generated, stored (cookie + `AuthRequest` row), and
  verified on callback with a **constant-time** comparison (`constantTimeEqual`).
- Mismatched, missing, or cookie-less state is rejected (`403` / `400`), fail-closed.

### 3. Server-side token exchange

- `lib/oauth.ts#exchangeCodeForToken` performs the code→token exchange on the
  **server**. Tokens never reach client-side JavaScript, so XSS cannot read them
  from the page.

### 4. Hardened session cookies

- `lib/session.ts` stores sessions in the database; the cookie only carries a
  256-bit random id. The `Set-Cookie` is:
  `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=…`.
  - **HttpOnly** → invisible to `document.cookie` / scripts (XSS defense).
  - **Secure** → HTTPS only.
  - **SameSite=Lax** → blocks most CSRF while still allowing the top-level OAuth
    return redirect. (`SameSite=Strict` is also supported via
    `buildSessionCookie(id, { sameSite: "Strict" })` for cookies that never need
    to survive a cross-site navigation.)
- On a **privilege change**, `rotateSession` issues a **new** session id and
  revokes the old one (session-fixation defense).

### 5. Refresh-token rotation with reuse detection

- `lib/tokens.ts` keeps refresh tokens in a rotation **family**. Each rotation
  issues a new token and marks the old one `rotatedAt`.
- Presenting an **already-rotated** token is **reuse** → the whole family is
  revoked (a strong theft signal). `/api/auth/refresh` rotates both the refresh
  token and the session id.

---

## The insecure demos (and their fixes)

Each lives at `app/insecure/<name>/page.tsx`, is **loudly labeled
"INSECURE — FOR EDUCATION ONLY"**, demonstrates the anti-pattern, explains the
risk, and shows the secure fix **side by side**. These pages are **sandboxed**:
they do **not** import the real session/provider modules (asserted by
`tests/insecure-isolation.test.ts`).

| Demo | Anti-pattern | Risk | Secure fix |
| --- | --- | --- | --- |
| `token-in-localstorage` | Store tokens in `localStorage` | Any XSS can read and exfiltrate them | Keep the credential out of JS — `HttpOnly` cookie |
| `missing-state` | Omit the `state` parameter | Login CSRF / code injection | Generate, bind, and constant-time verify `state` |
| `missing-pkce` | Skip PKCE | A leaked authorization code can be redeemed by an attacker | Bind the code to a secret verifier (S256) |

---

## Project layout

```
authlab/
├─ app/
│  ├─ page.tsx                       landing (explains the playground, links)
│  ├─ secure/page.tsx                secure login demo + inline security notes
│  ├─ insecure/page.tsx              index of anti-patterns
│  ├─ insecure/<name>/page.tsx       each loudly-labeled, side-by-side demo
│  ├─ api/mock-oauth/authorize       mock provider: /authorize (PKCE, state)
│  ├─ api/mock-oauth/token           mock provider: /token (verifier check)
│  ├─ api/auth/login                 secure flow: begin (verifier+challenge+state)
│  ├─ api/auth/callback              secure flow: validate state, exchange, session
│  ├─ api/auth/refresh               secure flow: rotate refresh + session
│  └─ api/auth/logout                secure flow: revoke session
├─ lib/
│  ├─ crypto.ts        base64url, randomBytes, sha256, constant-time compare
│  ├─ pkce.ts          verifier/challenge (S256), state, verify
│  ├─ oauth.ts         buildAuthorizeUrl, exchangeCodeForToken, validateState
│  ├─ session.ts       create/get/rotate/destroy + secure cookie builders
│  ├─ tokens.ts        refresh-token rotation + reuse detection
│  ├─ authCookies.ts   in-flight (verifier/state) cookie helpers + parser
│  └─ db.ts            Prisma client singleton (better-sqlite3 adapter)
├─ prisma/schema.prisma  Session, RefreshToken, AuthRequest, AuthCode
├─ tests/                Vitest suites (see below)
└─ vitest.config.ts      points Prisma at a test DB + runs db push before tests
```

---

## How to run

```bash
npm install
npm run prisma:generate   # generate the Prisma client (-> app/generated/prisma)
npm run db:push           # create/sync the local SQLite schema (prisma/dev.db)
npm run dev               # http://localhost:3000
```

Open <http://localhost:3000>, then try the **Secure login demo** and the
**Insecure anti-patterns** index.

## How to test

```bash
npm test
```

The Vitest setup (`tests/global-setup.ts` + `tests/setup-env.ts`) provisions an
**isolated** test SQLite database (`prisma/test.db`), runs `prisma generate` and
`prisma db push` against it, and then runs all suites serially:

| Suite | Covers |
| --- | --- |
| `pkce.test.ts` | S256 correctness (incl. RFC 7636 vector), challenge ≠ verifier, `constantTimeEqual`, base64url round-trip |
| `state.test.ts` | state generation + validation; tampered/missing/length-mismatch rejected |
| `oauth-flow.test.ts` | **Integration** via route handlers: authorize→code→token (correct verifier succeeds, wrong verifier / missing & tampered state rejected, single-use code), full login→callback issues a session |
| `session.test.ts` | cookie has `HttpOnly`+`Secure`+`SameSite`; rotation issues a new id and invalidates the old |
| `tokens.test.ts` | refresh rotation invalidates the old token; **reuse detected** + family revoked |
| `insecure-isolation.test.ts` | each insecure demo is loudly labeled and imports none of the real session/provider modules |

Also verified: `npm run lint` (clean) and `npm run build` (production build
succeeds).

---

## Switching SQLite → PostgreSQL

It is a **one-line datasource change** plus the matching driver adapter:

1. In `prisma/schema.prisma`, change the datasource provider:
   ```prisma
   datasource db {
     provider = "postgresql"   // was "sqlite"
   }
   ```
2. Point `DATABASE_URL` at your Postgres instance (used by `prisma.config.ts`
   and `lib/db.ts`):
   ```bash
   export DATABASE_URL="postgresql://user:pass@host:5432/authlab"
   ```
3. Swap the driver adapter in `lib/db.ts` (`PrismaBetterSqlite3` →
   `PrismaPg` from `@prisma/adapter-pg`) and `npm i @prisma/adapter-pg pg`.
4. `npm run prisma:generate && npm run db:push`.

No model changes are required — the schema is portable.

---

## Inline-security-notes philosophy

Security knowledge is most useful **at the point of decision**. AuthLab embeds
short, specific notes right next to the code/UI they explain:

- The **secure** page annotates each control (PKCE, state, server-side exchange,
  cookie flags, rotation) with *what it is* and *why it matters*.
- Every **insecure** demo shows the broken pattern, the concrete attack it
  enables, and the secure fix **immediately beside it** — so the contrast, not
  just the rule, is what sticks.

The goal is for a reader to leave understanding the *threat model*, not merely a
checklist.

---

## Reminder

This is a teaching sandbox. **No real users, credentials, secrets, or external
identity providers are involved.** Do not copy the insecure demos into
production; do borrow the patterns in `lib/` and the secure routes.
