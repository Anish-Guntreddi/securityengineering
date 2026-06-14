import { beforeEach, describe, expect, it } from "vitest";
import { prisma } from "@/lib/db";
import {
  buildClearedSessionCookie,
  buildSessionCookie,
  createSession,
  destroySession,
  getSession,
  rotateSession,
  SESSION_COOKIE_NAME,
} from "@/lib/session";

describe("session cookie flags", () => {
  it("sets HttpOnly + Secure + SameSite=Lax + Path on the session cookie", () => {
    const cookie = buildSessionCookie("abc123");
    expect(cookie.startsWith(`${SESSION_COOKIE_NAME}=abc123`)).toBe(true);
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/Secure/);
    expect(cookie).toMatch(/SameSite=Lax/);
    expect(cookie).toMatch(/Path=\//);
    expect(cookie).toMatch(/Max-Age=\d+/);
  });

  it("supports SameSite=Strict where appropriate", () => {
    const cookie = buildSessionCookie("abc123", { sameSite: "Strict" });
    expect(cookie).toMatch(/SameSite=Strict/);
  });

  it("cleared cookie has Max-Age=0 and keeps secure attributes", () => {
    const cleared = buildClearedSessionCookie();
    expect(cleared).toMatch(/Max-Age=0/);
    expect(cleared).toMatch(/HttpOnly/);
    expect(cleared).toMatch(/Secure/);
    expect(cleared).toMatch(/SameSite=Lax/);
  });
});

describe("session lifecycle", () => {
  beforeEach(async () => {
    await prisma.refreshToken.deleteMany();
    await prisma.session.deleteMany();
  });

  it("creates a session with a high-entropy id and a default role", async () => {
    const session = await createSession({ userRef: "sandbox-user-001" });
    expect(session.id.length).toBeGreaterThanOrEqual(43); // ~256-bit base64url
    expect(session.role).toBe("user");
    expect(await getSession(session.id)).not.toBeNull();
  });

  it("getSession returns null for missing, revoked, or expired sessions", async () => {
    expect(await getSession("does-not-exist")).toBeNull();
    expect(await getSession(undefined)).toBeNull();

    const revoked = await createSession({ userRef: "u" });
    await destroySession(revoked.id);
    expect(await getSession(revoked.id)).toBeNull();

    const expired = await createSession({ userRef: "u", ttlMs: -1000 });
    expect(await getSession(expired.id)).toBeNull();
  });

  it("rotateSession issues a NEW id and invalidates the old one (privilege change)", async () => {
    const original = await createSession({ userRef: "u", role: "user" });

    const rotated = await rotateSession(original.id, { role: "admin" });

    // New id, different from the old.
    expect(rotated.id).not.toBe(original.id);
    expect(rotated.role).toBe("admin");
    expect(rotated.userRef).toBe("u");

    // Old session is no longer valid.
    expect(await getSession(original.id)).toBeNull();
    // New session is valid.
    expect(await getSession(rotated.id)).not.toBeNull();

    // The old row is explicitly revoked in the DB.
    const oldRow = await prisma.session.findUnique({ where: { id: original.id } });
    expect(oldRow?.revokedAt).not.toBeNull();
  });

  it("rotateSession throws when the source session is invalid", async () => {
    await expect(rotateSession("nonexistent")).rejects.toThrow();
  });

  it("destroySession revokes the session so its cookie cannot authenticate", async () => {
    const s = await createSession({ userRef: "u" });
    await destroySession(s.id);
    expect(await getSession(s.id)).toBeNull();
  });
});
