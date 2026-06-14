/**
 * Cookie helpers for the in-flight OAuth dance (PKCE verifier + state).
 *
 * These are short-lived, HttpOnly, Secure, SameSite=Lax cookies. SameSite=Lax
 * (not Strict) is required so the cookies survive the top-level redirect from
 * the provider back to /api/auth/callback.
 */

export const PKCE_VERIFIER_COOKIE = "authlab_pkce_verifier";
export const STATE_COOKIE = "authlab_oauth_state";

/** Short lifetime for the in-flight dance: 10 minutes. */
const FLOW_TTL_SECONDS = 10 * 60;

export function buildFlowCookie(name: string, value: string): string {
  return [
    `${name}=${value}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${FLOW_TTL_SECONDS}`,
  ].join("; ");
}

export function buildClearedFlowCookie(name: string): string {
  return [
    `${name}=`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/",
    "Max-Age=0",
  ].join("; ");
}

/** Parse a Cookie header into a simple map. */
export function parseCookies(header: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(val);
  }
  return out;
}
