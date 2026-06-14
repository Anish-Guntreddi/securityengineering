import Link from "next/link";

export const metadata = {
  title: "AuthLab — Secure Login Demo",
};

export default function SecurePage() {
  return (
    <main>
      <p>
        <Link href="/">← Back to AuthLab</Link>
      </p>
      <h1>Secure login demo</h1>
      <div className="banner-secure">
        SECURE PATTERN — Authorization Code + PKCE with server-side token
        exchange, rotation, and hardened cookies. Sandbox only; no real
        credentials.
      </div>

      <p className="muted">
        Click the button to start the flow. Your browser will hit{" "}
        <code>/api/auth/login</code>, which redirects to the mock provider and
        comes back through <code>/api/auth/callback</code>. Because the mock
        provider auto-approves a fixed pseudo-user, no login form is shown.
      </p>

      <p>
        <a href="/api/auth/login">→ Start secure login</a>
      </p>

      <h2>What makes this secure?</h2>

      <div className="card">
        <h3>1. PKCE (Proof Key for Code Exchange)</h3>
        <p className="note">
          A random <code>code_verifier</code> is generated and never leaves the
          server-side cookie jar. Only its SHA-256 hash (the{" "}
          <code>code_challenge</code>) travels on the front channel. An attacker
          who intercepts the authorization code cannot exchange it without the
          verifier.
        </p>
        <pre>
          <code>{`verifier  = base64url(randomBytes(32))      // secret
challenge = base64url(sha256(verifier))     // public (S256)`}</code>
        </pre>
      </div>

      <div className="card">
        <h3>2. Anti-CSRF state</h3>
        <p className="note">
          A high-entropy <code>state</code> is bound to the request and verified
          on callback with a <strong>constant-time</strong> comparison. A
          mismatched or missing state is rejected (HTTP 403), defeating
          login-CSRF / code-injection.
        </p>
      </div>

      <div className="card">
        <h3>3. Server-side token exchange</h3>
        <p className="note">
          The authorization code and verifier are exchanged for tokens on the
          server (<code>/api/auth/callback</code> →{" "}
          <code>/api/mock-oauth/token</code>). Tokens never reach client-side
          JavaScript, so XSS cannot steal them from the page.
        </p>
      </div>

      <div className="card">
        <h3>4. Hardened session cookie</h3>
        <p className="note">
          The session id is a 256-bit random value stored server-side and
          delivered as{" "}
          <code>HttpOnly; Secure; SameSite=Lax; Path=/</code>. HttpOnly blocks
          JS access (XSS), Secure forces HTTPS, and SameSite=Lax blocks most
          CSRF while still allowing the OAuth return redirect.
        </p>
      </div>

      <div className="card">
        <h3>5. Refresh-token rotation with reuse detection</h3>
        <p className="note">
          <code>/api/auth/refresh</code> issues a new refresh token, invalidates
          the old one, and rotates the session id. If a previously-rotated token
          is replayed, the entire token family is revoked — a strong signal of
          theft.
        </p>
      </div>
    </main>
  );
}
