import { beforeEach, describe, expect, it } from "vitest";
import { prisma } from "@/lib/db";
import { createSession } from "@/lib/session";
import {
  issueRefreshToken,
  RefreshInvalidError,
  RefreshReuseError,
  rotateRefreshToken,
} from "@/lib/tokens";

async function freshSessionId(): Promise<string> {
  const s = await createSession({ userRef: "sandbox-user-001" });
  return s.id;
}

describe("refresh-token rotation", () => {
  beforeEach(async () => {
    await prisma.refreshToken.deleteMany();
    await prisma.session.deleteMany();
  });

  it("issues an initial refresh token bound to a session and family", async () => {
    const sessionId = await freshSessionId();
    const { token, value } = await issueRefreshToken(sessionId);
    expect(value).toBe(token.id);
    expect(token.sessionId).toBe(sessionId);
    expect(token.familyId).toBeTruthy();
    expect(token.rotatedAt).toBeNull();
    expect(token.revokedAt).toBeNull();
  });

  it("rotation issues a NEW token and invalidates the OLD one", async () => {
    const sessionId = await freshSessionId();
    const first = await issueRefreshToken(sessionId);

    const second = await rotateRefreshToken(first.value);

    // New token differs and stays in the same family.
    expect(second.value).not.toBe(first.value);
    expect(second.token.familyId).toBe(first.token.familyId);

    // Old token is now marked rotated in the DB.
    const oldRow = await prisma.refreshToken.findUnique({
      where: { id: first.value },
    });
    expect(oldRow?.rotatedAt).not.toBeNull();
  });

  it("DETECTS reuse of an already-rotated token and revokes the family", async () => {
    const sessionId = await freshSessionId();
    const first = await issueRefreshToken(sessionId);
    const second = await rotateRefreshToken(first.value);

    // Replaying the original (already-rotated) token is reuse.
    await expect(rotateRefreshToken(first.value)).rejects.toBeInstanceOf(
      RefreshReuseError,
    );

    // The whole family is revoked: even the legitimately-current token
    // can no longer be rotated.
    await expect(rotateRefreshToken(second.value)).rejects.toBeInstanceOf(
      RefreshInvalidError,
    );

    const familyRows = await prisma.refreshToken.findMany({
      where: { familyId: first.token.familyId },
    });
    expect(familyRows.length).toBeGreaterThanOrEqual(2);
    for (const row of familyRows) {
      expect(row.revokedAt).not.toBeNull();
    }
  });

  it("rejects an unknown refresh token", async () => {
    await expect(rotateRefreshToken("not-a-real-token")).rejects.toBeInstanceOf(
      RefreshInvalidError,
    );
  });

  it("rejects an expired refresh token", async () => {
    const sessionId = await freshSessionId();
    const { value } = await issueRefreshToken(sessionId, { ttlMs: -1000 });
    await expect(rotateRefreshToken(value)).rejects.toBeInstanceOf(
      RefreshInvalidError,
    );
  });

  it("supports several sequential rotations in a family", async () => {
    const sessionId = await freshSessionId();
    let current = await issueRefreshToken(sessionId);
    const familyId = current.token.familyId;
    for (let i = 0; i < 3; i++) {
      current = await rotateRefreshToken(current.value);
      expect(current.token.familyId).toBe(familyId);
    }
    // Final token still valid; reusing the very first is still caught.
    expect(current.token.rotatedAt).toBeNull();
  });
});
