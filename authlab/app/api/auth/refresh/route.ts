import { NextResponse } from "next/server";
import { parseCookies } from "@/lib/authCookies";
import {
  buildSessionCookie,
  getSession,
  rotateSession,
  SESSION_COOKIE_NAME,
} from "@/lib/session";
import {
  RefreshInvalidError,
  RefreshReuseError,
  rotateRefreshToken,
} from "@/lib/tokens";

/**
 * SECURE FLOW — /api/auth/refresh.
 *
 * Rotates BOTH the refresh token and the session id:
 *   - rotateRefreshToken issues a new refresh token and invalidates the old
 *     one; presenting an already-rotated token is detected as reuse and
 *     revokes the whole family (token-theft response).
 *   - rotateSession issues a fresh session id and revokes the old one, so a
 *     leaked session cookie cannot be replayed after a refresh.
 *
 * The refresh token is provided in the JSON body (the secure app keeps it in
 * an HttpOnly cookie or server store in a real deployment; here it is passed
 * explicitly to keep the demo self-contained).
 */

function fail(error: string, description: string, status: number) {
  return NextResponse.json({ error, error_description: description }, { status });
}

export async function POST(req: Request) {
  const cookies = parseCookies(req.headers.get("cookie"));
  const sessionId = cookies[SESSION_COOKIE_NAME];

  const session = await getSession(sessionId);
  if (!session) {
    return fail("invalid_session", "no active session", 401);
  }

  let body: { refresh_token?: string } = {};
  try {
    body = (await req.json()) as { refresh_token?: string };
  } catch {
    return fail("invalid_request", "missing JSON body", 400);
  }
  const presented = body.refresh_token;
  if (!presented) {
    return fail("invalid_request", "missing refresh_token", 400);
  }

  let rotated;
  try {
    rotated = await rotateRefreshToken(presented);
  } catch (err) {
    if (err instanceof RefreshReuseError) {
      return fail("token_reuse_detected", "refresh token reuse detected; family revoked", 401);
    }
    if (err instanceof RefreshInvalidError) {
      return fail("invalid_grant", err.message, 401);
    }
    throw err;
  }

  // Rotate the session id too (new id, old one revoked).
  const newSession = await rotateSession(session.id, { role: session.role });

  const res = NextResponse.json(
    { ok: true, refresh_token: rotated.value, rotated: true },
    { status: 200 },
  );
  res.headers.append("Set-Cookie", buildSessionCookie(newSession.id));
  return res;
}
