import Link from "next/link";

export default function HomePage() {
  return (
    <main>
      <h1>AuthLab</h1>
      <p className="muted">
        An educational, fully sandboxed playground for OAuth 2.0 and session
        security. Compare the <strong>secure</strong> way of doing things with
        common <strong>insecure</strong> anti-patterns, side by side.
      </p>

      <div className="banner-secure">
        SANDBOX ONLY — No real users, credentials, or identity providers are
        involved. The &quot;OAuth provider&quot; is a self-contained mock that
        runs entirely inside this app with no external network calls.
      </div>

      <div className="card">
        <h2 style={{ marginTop: 0 }}>What is this?</h2>
        <p>
          AuthLab implements the OAuth 2.0 <strong>Authorization Code flow
          with PKCE</strong>, server-side token exchange, refresh-token
          rotation with reuse detection, and hardened session cookies. It then
          demonstrates what goes wrong when you skip those protections.
        </p>
        <p className="muted">
          Everything is local: a mock Authorization Server lives at{" "}
          <code>/api/mock-oauth/*</code> and issues opaque random tokens for a
          fixed pseudo-user. Nothing here can authenticate against a real
          service.
        </p>
      </div>

      <h2>Explore</h2>
      <ul className="links">
        <li>
          <Link href="/secure">→ Secure login demo</Link> — Authorization Code
          + PKCE, state validation, rotation, and secure cookies with inline
          security notes.
        </li>
        <li>
          <Link href="/insecure">→ Insecure anti-patterns</Link> — loudly
          labeled demos of what NOT to do, each with the secure fix shown
          alongside.
        </li>
      </ul>

      <h2>The secure flow at a glance</h2>
      <div className="card">
        <ol>
          <li>
            <code>/api/auth/login</code> generates a PKCE{" "}
            <code>code_verifier</code> + <code>code_challenge</code> (S256) and
            an anti-CSRF <code>state</code>, stores them, and redirects to the
            mock provider.
          </li>
          <li>
            The mock provider validates the request and returns a single-use
            authorization code bound to the challenge.
          </li>
          <li>
            <code>/api/auth/callback</code> validates <code>state</code>{" "}
            (constant-time) and exchanges the code + verifier{" "}
            <strong>server-side</strong> for tokens.
          </li>
          <li>
            A server-side session is created and delivered in an{" "}
            <code>HttpOnly; Secure; SameSite=Lax</code> cookie.
          </li>
          <li>
            <code>/api/auth/refresh</code> rotates the refresh token (reuse is
            detected and revokes the family) and rotates the session id.
          </li>
        </ol>
      </div>

      <p className="muted">
        No real credentials are involved anywhere in AuthLab. Read the{" "}
        <code>README.md</code> for the full walkthrough and how to run the
        tests.
      </p>
    </main>
  );
}
