import { NextResponse } from "next/server";
import { parseCookies } from "@/lib/authCookies";
import {
  buildClearedSessionCookie,
  destroySession,
  SESSION_COOKIE_NAME,
} from "@/lib/session";

/**
 * SECURE FLOW — /api/auth/logout.
 *
 * Revokes the server-side session and clears the cookie. Idempotent: a
 * missing/invalid session still returns OK and a cleared cookie.
 */
export async function POST(req: Request) {
  const cookies = parseCookies(req.headers.get("cookie"));
  const sessionId = cookies[SESSION_COOKIE_NAME];

  if (sessionId) {
    await destroySession(sessionId);
  }

  const res = NextResponse.json({ ok: true, loggedOut: true }, { status: 200 });
  res.headers.append("Set-Cookie", buildClearedSessionCookie());
  return res;
}
