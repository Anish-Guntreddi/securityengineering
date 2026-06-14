import { randomToken } from "./crypto";
import { prisma } from "./db";

/**
 * Refresh-token rotation with reuse detection (RFC 6819 / OAuth security BCP).
 *
 * Each refresh token belongs to a rotation *family*. Exchanging a token issues
 * a new token in the same family and marks the old one `rotatedAt`. If a token
 * that has ALREADY been rotated is presented again, that is a strong signal of
 * theft: we revoke the entire family so neither the attacker nor the victim's
 * stale token can be used.
 */

/** Default refresh-token lifetime: 30 days. */
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export interface RefreshTokenRecord {
  id: string;
  familyId: string;
  sessionId: string;
  createdAt: Date;
  expiresAt: Date;
  rotatedAt: Date | null;
  revokedAt: Date | null;
}

export interface IssueResult {
  token: RefreshTokenRecord;
  /** The raw token value to hand to the client (equals token.id). */
  value: string;
}

/** Issue the first refresh token for a session (starts a new family). */
export async function issueRefreshToken(
  sessionId: string,
  opts: { ttlMs?: number } = {},
): Promise<IssueResult> {
  const id = randomToken(32);
  const familyId = randomToken(16);
  const token = await prisma.refreshToken.create({
    data: {
      id,
      familyId,
      sessionId,
      expiresAt: new Date(Date.now() + (opts.ttlMs ?? REFRESH_TTL_MS)),
    },
  });
  return { token, value: id };
}

export class RefreshReuseError extends Error {
  constructor(message = "refresh token reuse detected") {
    super(message);
    this.name = "RefreshReuseError";
  }
}

export class RefreshInvalidError extends Error {
  constructor(message = "refresh token invalid or expired") {
    super(message);
    this.name = "RefreshInvalidError";
  }
}

/** Revoke every token in a family (called on reuse detection). */
export async function revokeFamily(familyId: string): Promise<void> {
  await prisma.refreshToken.updateMany({
    where: { familyId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

/**
 * Rotate a refresh token. On success the presented token is marked rotated and
 * a fresh token in the same family is returned.
 *
 * Failure modes:
 *  - token unknown / expired / revoked  -> RefreshInvalidError
 *  - token already rotated (REUSE)      -> revoke whole family + RefreshReuseError
 */
export async function rotateRefreshToken(
  presentedTokenValue: string,
  opts: { ttlMs?: number } = {},
): Promise<IssueResult> {
  const existing = await prisma.refreshToken.findUnique({
    where: { id: presentedTokenValue },
  });

  if (!existing) {
    throw new RefreshInvalidError("unknown refresh token");
  }

  // Family already revoked (e.g. earlier reuse) -> reject.
  if (existing.revokedAt) {
    throw new RefreshInvalidError("refresh token has been revoked");
  }

  // REUSE: a token that was already exchanged is being presented again.
  if (existing.rotatedAt) {
    await revokeFamily(existing.familyId);
    throw new RefreshReuseError();
  }

  if (existing.expiresAt.getTime() <= Date.now()) {
    throw new RefreshInvalidError("refresh token expired");
  }

  const newId = randomToken(32);
  const now = Date.now();

  // Atomically mark the old token rotated and create its successor.
  const [, replacement] = await prisma.$transaction([
    prisma.refreshToken.update({
      where: { id: existing.id },
      data: { rotatedAt: new Date(now) },
    }),
    prisma.refreshToken.create({
      data: {
        id: newId,
        familyId: existing.familyId,
        sessionId: existing.sessionId,
        expiresAt: new Date(now + (opts.ttlMs ?? REFRESH_TTL_MS)),
      },
    }),
  ]);

  return { token: replacement, value: newId };
}
