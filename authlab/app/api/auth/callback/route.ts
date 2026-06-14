import { NextResponse } from "next/server";
import {
  buildClearedFlowCookie,
  parseCookies,
  PKCE_VERIFIER_COOKIE,
  STATE_COOKIE,
} from "@/lib/authCookies";
import { prisma } from "@/lib/db";
import { exchangeCodeForToken, OAUTH_CONFIG, validateState } from "@/lib/oauth";
import { createSession, buildSessionCookie } from "@/lib/session";
import { issueRefreshToken } from "@/lib/tokens";

/**
 * SECURE FLOW — /api/auth/callback.
 *
 * Completes Authorization Code + PKCE:
 *   1. Read `code` + `state` from the query.
 *   2. Validate state against BOTH the cookie and the stored AuthRequest
 *      (constant-time) -> CSRF defence; reject + fail closed on mismatch.
 *   3. Exchange code + the cookie-stored verifier for tokens SERVER-SIDE.
 *   4. Issue a server-side session (HttpOnly/Secure/SameSite cookie) and an
 *      initial refresh token, then clear the in-flight cookies.
 */

function fail(description: string, status = 400) {
  return NextResponse.json({ error: "invalid_request", error_description: description }, { status });
}

export async function GET(req: Request) {
  const url = new URL(req.url);
  const origin = url.origin;
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");

  const cookies = parseCookies(req.headers.get("cookie"));
  const cookieState = cookies[STATE_COOKIE];
  const codeVerifier = cookies[PKCE_VERIFIER_COOKIE];

  if (!code) return fail("missing code");
  if (!returnedState) return fail("missing state");

  // State must match the cookie value (constant-time).
  if (!validateState(cookieState, returnedState)) {
    return fail("state mismatch (possible CSRF)", 403);
  }

  // State must also correspond to a live, unconsumed AuthRequest.
  const authRequest = await prisma.authRequest.findUnique({
    where: { state: returnedState },
  });
  if (!authRequest || authRequest.consumedAt || authRequest.expiresAt.getTime() <= Date.now()) {
    return fail("unknown or expired auth request", 403);
  }

  if (!codeVerifier) {
    return fail("missing PKCE verifier cookie", 400);
  }

  // Consume the AuthRequest (single-use) before the exchange.
  const consumed = await prisma.authRequest.updateMany({
    where: { state: returnedState, consumedAt: null },
    data: { consumedAt: new Date() },
  });
  if (consumed.count !== 1) {
    return fail("auth request already consumed", 403);
  }

  // Server-side back-channel token exchange.
  let tokens;
  try {
    tokens = await exchangeCodeForToken({
      baseUrl: origin,
      code,
      codeVerifier,
      clientId: OAUTH_CONFIG.clientId,
      redirectUri: OAUTH_CONFIG.redirectUri,
    });
  } catch (err) {
    return fail(`token exchange failed: ${(err as Error).message}`, 502);
  }

  // Issue a server-side session + initial refresh token.
  const session = await createSession({
    userRef: tokens.userRef ?? "sandbox-user-001",
    role: "user",
  });
  await issueRefreshToken(session.id);

  const res = NextResponse.json(
    { ok: true, sessionEstablished: true, userRef: session.userRef },
    { status: 200 },
  );
  res.headers.append("Set-Cookie", buildSessionCookie(session.id));
  // Clear the now-spent in-flight cookies.
  res.headers.append("Set-Cookie", buildClearedFlowCookie(PKCE_VERIFIER_COOKIE));
  res.headers.append("Set-Cookie", buildClearedFlowCookie(STATE_COOKIE));
  return res;
}
