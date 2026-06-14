import {
  base64urlEncode,
  constantTimeEqual as ctEqual,
  randomBytes,
  sha256Base64url,
} from "./crypto";

/**
 * PKCE (Proof Key for Code Exchange, RFC 7636) helpers + the anti-CSRF
 * `state` parameter. Pure functions, no I/O, fully unit-testable.
 */

/**
 * Generate a PKCE code verifier: a high-entropy cryptographically random
 * string. RFC 7636 requires 43-128 characters from the unreserved set; 32
 * random bytes base64url-encoded yields 43 chars of ~256-bit entropy.
 */
export function generateCodeVerifier(byteLength = 32): string {
  if (byteLength < 32) {
    // 32 bytes -> 43 chars, the spec minimum. Refuse weaker verifiers.
    throw new Error("PKCE code verifier must be >= 32 bytes of entropy");
  }
  return base64urlEncode(randomBytes(byteLength));
}

/**
 * Derive the S256 code challenge from a verifier:
 *   challenge = BASE64URL( SHA256( ASCII(verifier) ) )
 * The challenge is deterministically derived but NOT reversible, so it can be
 * sent over the front channel while the verifier stays secret.
 */
export function codeChallengeS256(verifier: string): string {
  if (!verifier) {
    throw new Error("code verifier is required");
  }
  return sha256Base64url(verifier);
}

/** Generate a high-entropy anti-CSRF state value. */
export function generateState(byteLength = 32): string {
  return base64urlEncode(randomBytes(byteLength));
}

/**
 * Constant-time equality. Re-exported through pkce so callers comparing
 * verifiers/challenges/states use a timing-safe comparison by default.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  return ctEqual(a, b);
}

/**
 * Verify a presented code verifier against a stored S256 challenge using a
 * constant-time comparison. Only S256 is supported (the `plain` method is
 * intentionally NOT implemented because it provides no protection).
 */
export function verifyCodeChallenge(
  verifier: string,
  storedChallenge: string,
  method = "S256",
): boolean {
  if (method !== "S256") {
    return false;
  }
  const derived = codeChallengeS256(verifier);
  return constantTimeEqual(derived, storedChallenge);
}
