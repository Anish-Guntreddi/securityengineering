import {
  createHash,
  randomBytes as nodeRandomBytes,
  timingSafeEqual,
} from "node:crypto";

/**
 * Low-level crypto helpers built on node:crypto.
 *
 * These are deliberately small and pure so they can be unit-tested in
 * isolation and reused by lib/pkce.ts, lib/session.ts and lib/tokens.ts.
 */

/**
 * base64url-encode a Buffer or string (RFC 4648 §5): standard base64 with
 * `+`/`/` replaced by `-`/`_` and `=` padding stripped. This is the encoding
 * required by the PKCE spec (RFC 7636) for code challenges.
 */
export function base64urlEncode(input: Buffer | string): string {
  const buf = typeof input === "string" ? Buffer.from(input, "utf8") : input;
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

/**
 * Decode a base64url string back to a Buffer. Restores padding and the
 * standard base64 alphabet before decoding.
 */
export function base64urlDecode(input: string): Buffer {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + "=".repeat(padLength);
  return Buffer.from(padded, "base64");
}

/**
 * Cryptographically-strong random bytes. Thin wrapper so call sites read
 * clearly and we have a single place to audit randomness.
 */
export function randomBytes(length: number): Buffer {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error("randomBytes length must be a positive integer");
  }
  return nodeRandomBytes(length);
}

/**
 * Generate a high-entropy random token as a base64url string. `byteLength`
 * defaults to 32 bytes (256 bits) which is well above the entropy needed for
 * session ids and tokens.
 */
export function randomToken(byteLength = 32): string {
  return base64urlEncode(randomBytes(byteLength));
}

/** SHA-256 digest as a raw Buffer. */
export function sha256(input: Buffer | string): Buffer {
  const buf = typeof input === "string" ? Buffer.from(input, "utf8") : input;
  return createHash("sha256").update(buf).digest();
}

/** SHA-256 digest encoded as base64url (used for PKCE S256 + token hashing). */
export function sha256Base64url(input: Buffer | string): string {
  return base64urlEncode(sha256(input));
}

/**
 * Constant-time string comparison. Returns false for length mismatch without
 * leaking via early return on content. Wraps node's timingSafeEqual.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}
