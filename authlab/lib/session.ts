import { randomToken } from "./crypto";
import { prisma } from "./db";

/**
 * Server-side session management. Sessions live in the database; the cookie
 * only carries a high-entropy random id. We expose helpers to build the
 * Set-Cookie header with secure attributes (HttpOnly + Secure + SameSite).
 *
 * Privilege change -> rotateSession issues a brand-new id and invalidates the
 * old one (defends against session fixation).
 */

export const SESSION_COOKIE_NAME = "authlab_session";

/** Default session lifetime: 1 hour. */
const SESSION_TTL_MS = 60 * 60 * 1000;

export interface SessionRecord {
  id: string;
  userRef: string;
  role: string;
  createdAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
}

export interface CreateSessionInput {
  userRef: string;
  role?: string;
  ttlMs?: number;
}

/** Create a new session row and return it. The `id` is the cookie value. */
export async function createSession(
  input: CreateSessionInput,
): Promise<SessionRecord> {
  const id = randomToken(32); // 256-bit random session id
  const now = Date.now();
  const session = await prisma.session.create({
    data: {
      id,
      userRef: input.userRef,
      role: input.role ?? "user",
      expiresAt: new Date(now + (input.ttlMs ?? SESSION_TTL_MS)),
    },
  });
  return session;
}

/**
 * Look up an active session by id. Returns null if missing, revoked, or
 * expired. Never returns a session that should not authenticate a request.
 */
export async function getSession(
  id: string | undefined | null,
): Promise<SessionRecord | null> {
  if (!id) return null;
  const session = await prisma.session.findUnique({ where: { id } });
  if (!session) return null;
  if (session.revokedAt) return null;
  if (session.expiresAt.getTime() <= Date.now()) return null;
  return session;
}

/**
 * Rotate a session on a privilege change (e.g. role elevation). Issues a NEW
 * session id, copies forward the user ref, applies the (possibly new) role,
 * and revokes the old session so the previous cookie can no longer be used.
 */
export async function rotateSession(
  oldId: string,
  opts: { role?: string; ttlMs?: number } = {},
): Promise<SessionRecord> {
  const existing = await getSession(oldId);
  if (!existing) {
    throw new Error("cannot rotate a missing or invalid session");
  }
  const newId = randomToken(32);
  const now = Date.now();

  // Create the replacement and revoke the old one atomically.
  const [, replacement] = await prisma.$transaction([
    prisma.session.update({
      where: { id: oldId },
      data: { revokedAt: new Date(now) },
    }),
    prisma.session.create({
      data: {
        id: newId,
        userRef: existing.userRef,
        role: opts.role ?? existing.role,
        expiresAt: new Date(now + (opts.ttlMs ?? SESSION_TTL_MS)),
      },
    }),
  ]);
  return replacement;
}

/** Destroy (revoke) a session so its cookie can no longer authenticate. */
export async function destroySession(id: string): Promise<void> {
  await prisma.session.updateMany({
    where: { id, revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

/**
 * Build a Set-Cookie header value for the session cookie.
 *
 * Security attributes:
 *  - HttpOnly: JS cannot read the cookie (mitigates XSS token theft).
 *  - Secure: only sent over HTTPS.
 *  - SameSite=Lax: blocks most CSRF while allowing top-level OAuth redirects
 *    back to the app. (Use Strict for cookies never needed on cross-site
 *    navigations; Lax is correct for a session that must survive the
 *    provider -> callback redirect.)
 *  - Path=/ and an explicit Max-Age.
 */
export function buildSessionCookie(
  sessionId: string,
  opts: { maxAgeSeconds?: number; sameSite?: "Lax" | "Strict" } = {},
): string {
  const maxAge = opts.maxAgeSeconds ?? Math.floor(SESSION_TTL_MS / 1000);
  const sameSite = opts.sameSite ?? "Lax";
  return [
    `${SESSION_COOKIE_NAME}=${sessionId}`,
    "HttpOnly",
    "Secure",
    `SameSite=${sameSite}`,
    "Path=/",
    `Max-Age=${maxAge}`,
  ].join("; ");
}

/** Build a Set-Cookie header that immediately clears the session cookie. */
export function buildClearedSessionCookie(): string {
  return [
    `${SESSION_COOKIE_NAME}=`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/",
    "Max-Age=0",
  ].join("; ");
}
