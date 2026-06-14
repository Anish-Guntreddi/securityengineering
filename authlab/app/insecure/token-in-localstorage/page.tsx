import Link from "next/link";

export const metadata = {
  title: "AuthLab — INSECURE: Token in localStorage",
};

// NOTE: This page is intentionally self-contained. It does NOT import
// the real session, tokens, oauth, db, or mock provider modules. The "token"
// shown here is a hardcoded fake string for illustration only.

export default function TokenInLocalStoragePage() {
  return (
    <main>
      <p>
        <Link href="/insecure">← Back to anti-patterns</Link>
      </p>
      <h1>Tokens in localStorage</h1>

      <div className="banner-insecure">
        ⚠ INSECURE — FOR EDUCATION ONLY ⚠ Do not store access/refresh tokens or
        session ids in localStorage or sessionStorage. Sandboxed demo with a
        FAKE token; no real credentials.
      </div>

      <div className="grid">
        <div className="card col col-insecure">
          <h3>❌ Insecure</h3>
          <p>The token lives in JavaScript-readable storage:</p>
          <pre>
            <code>{`// Anti-pattern
localStorage.setItem(
  "access_token",
  "FAKE.demo.token"
);
// ...later
fetch("/api/data", {
  headers: {
    Authorization:
      "Bearer " + localStorage.getItem("access_token"),
  },
});`}</code>
          </pre>
          <p className="muted">
            <strong>Risk:</strong> Any successful XSS (a malicious dependency, a
            reflected script, a compromised CDN) can run{" "}
            <code>localStorage.getItem(&quot;access_token&quot;)</code> and
            exfiltrate the token. There is no browser barrier — storage is fully
            scriptable. The token can then be replayed from anywhere.
          </p>
        </div>

        <div className="card col col-secure">
          <h3>✅ Secure fix</h3>
          <p>Keep the credential out of JS entirely — use an HttpOnly cookie:</p>
          <pre>
            <code>{`// Server sets the session cookie
Set-Cookie: authlab_session=<id>;
  HttpOnly; Secure; SameSite=Lax; Path=/

// Client JS literally cannot read it:
document.cookie // -> does NOT include authlab_session`}</code>
          </pre>
          <p className="muted">
            <strong>Why it helps:</strong> <code>HttpOnly</code> makes the
            cookie invisible to <code>document.cookie</code> and any script, so
            XSS cannot steal it. <code>Secure</code> keeps it on HTTPS and{" "}
            <code>SameSite</code> limits cross-site sending. This is exactly what{" "}
            <Link href="/secure">the secure flow</Link> does.
          </p>
        </div>
      </div>
    </main>
  );
}
