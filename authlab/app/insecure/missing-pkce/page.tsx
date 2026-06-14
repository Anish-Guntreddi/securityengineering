import Link from "next/link";

export const metadata = {
  title: "AuthLab — INSECURE: Missing PKCE",
};

// Self-contained illustration. Does NOT import the real session / provider
// modules. No real credentials.

export default function MissingPkcePage() {
  return (
    <main>
      <p>
        <Link href="/insecure">← Back to anti-patterns</Link>
      </p>
      <h1>Skipping PKCE</h1>

      <div className="banner-insecure">
        ⚠ INSECURE — FOR EDUCATION ONLY ⚠ This page demonstrates an
        Authorization Code flow with NO PKCE. Sandboxed; no real credentials.
      </div>

      <div className="grid">
        <div className="card col col-insecure">
          <h3>❌ Insecure</h3>
          <p>The code is exchanged with no <code>code_verifier</code>:</p>
          <pre>
            <code>{`// Anti-pattern: no code_challenge sent,
// no code_verifier on exchange
GET /authorize?response_type=code
  &client_id=app&redirect_uri=/cb

POST /token
  grant_type=authorization_code
  code=<authorization_code>
  // <-- nothing proves we started the flow`}</code>
          </pre>
          <p className="muted">
            <strong>Risk:</strong> If the authorization code leaks (referrer
            header, open redirect, a malicious app on the same custom URI scheme,
            proxy logs), an attacker can redeem it directly because nothing binds
            the code to the original requester. This is the classic{" "}
            <strong>authorization code interception</strong> attack, especially
            dangerous for public/native clients.
          </p>
        </div>

        <div className="card col col-secure">
          <h3>✅ Secure fix</h3>
          <p>Bind the code to a secret verifier (S256):</p>
          <pre>
            <code>{`// Before redirect
verifier  = base64url(randomBytes(32))   // secret
challenge = base64url(sha256(verifier))  // S256

GET /authorize?...&code_challenge=<challenge>
  &code_challenge_method=S256

// On exchange (server-side)
POST /token ... &code_verifier=<verifier>
// provider checks sha256(verifier) == challenge`}</code>
          </pre>
          <p className="muted">
            <strong>Why it helps:</strong> Only the party that generated the
            verifier can complete the exchange, so a stolen code is useless. The
            verifier never travels on the front channel.{" "}
            <Link href="/secure">The secure flow</Link> stores the verifier in
            an HttpOnly cookie and the mock provider rejects any token request
            whose verifier does not hash to the stored challenge.
          </p>
        </div>
      </div>
    </main>
  );
}
