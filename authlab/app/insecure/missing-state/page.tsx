import Link from "next/link";

export const metadata = {
  title: "AuthLab — INSECURE: Missing state",
};

// Self-contained illustration. Does NOT import the real session / provider
// modules. No real credentials.

export default function MissingStatePage() {
  return (
    <main>
      <p>
        <Link href="/insecure">← Back to anti-patterns</Link>
      </p>
      <h1>Omitting the state parameter</h1>

      <div className="banner-insecure">
        ⚠ INSECURE — FOR EDUCATION ONLY ⚠ This page demonstrates an OAuth flow
        with NO anti-CSRF <code>state</code>. Sandboxed; no real credentials.
      </div>

      <div className="grid">
        <div className="card col col-insecure">
          <h3>❌ Insecure</h3>
          <p>The authorize URL has no <code>state</code>, and the callback never checks one:</p>
          <pre>
            <code>{`// Anti-pattern: no state at all
const url =
  "/authorize?response_type=code" +
  "&client_id=app" +
  "&redirect_uri=/cb";
// callback blindly trusts whatever code arrives:
function callback(req) {
  const code = req.query.code;
  exchange(code); // no state validation!
}`}</code>
          </pre>
          <p className="muted">
            <strong>Risk:</strong> Without <code>state</code> the callback
            cannot tell whether the response corresponds to a request{" "}
            <em>this</em> user/browser actually started. An attacker can perform
            <strong> login CSRF</strong> — tricking a victim&apos;s browser into
            completing a flow the attacker initiated, attaching the victim to
            the attacker&apos;s account (or injecting a stolen authorization
            code).
          </p>
        </div>

        <div className="card col col-secure">
          <h3>✅ Secure fix</h3>
          <p>Generate, bind, and verify <code>state</code> on return:</p>
          <pre>
            <code>{`// Before redirect
const state = randomBytes(32) // high entropy
storeForSession(state)        // cookie + server

// On callback
if (!constantTimeEqual(
      cookieState, req.query.state)) {
  return reject(403); // CSRF
}`}</code>
          </pre>
          <p className="muted">
            <strong>Why it helps:</strong> The unguessable <code>state</code>{" "}
            ties the callback to the original request. A constant-time compare
            avoids leaking it via timing.{" "}
            <Link href="/secure">The secure flow</Link> checks state against
            both an HttpOnly cookie and a stored AuthRequest, and rejects
            mismatches with 403.
          </p>
        </div>
      </div>
    </main>
  );
}
