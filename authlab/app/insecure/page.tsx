import Link from "next/link";

export const metadata = {
  title: "AuthLab — Insecure Anti-Patterns",
};

export default function InsecureIndexPage() {
  return (
    <main>
      <p>
        <Link href="/">← Back to AuthLab</Link>
      </p>
      <h1>Insecure anti-patterns</h1>

      <div className="banner-insecure">
        ⚠ INSECURE — FOR EDUCATION ONLY ⚠ These pages intentionally demonstrate
        BROKEN patterns. They are isolated from the real secure flow, use no
        real credentials, and must NEVER be copied into production.
      </div>

      <p className="muted">
        Each page below shows one common mistake, explains the concrete risk,
        and presents the secure fix side by side. None of these pages import the
        real session or OAuth provider modules — they are fully sandboxed
        illustrations.
      </p>

      <ul className="links">
        <li>
          <Link href="/insecure/token-in-localstorage">
            → Storing tokens in localStorage
          </Link>{" "}
          — readable by any XSS payload.
        </li>
        <li>
          <Link href="/insecure/missing-state">
            → Omitting the state parameter
          </Link>{" "}
          — opens the door to login CSRF / code injection.
        </li>
        <li>
          <Link href="/insecure/missing-pkce">→ Skipping PKCE</Link> —
          intercepted authorization codes can be redeemed by an attacker.
        </li>
      </ul>
    </main>
  );
}
