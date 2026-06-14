import { NextResponse } from "next/server";
import {
  buildFlowCookie,
  PKCE_VERIFIER_COOKIE,
  STATE_COOKIE,
} from "@/lib/authCookies";
import { prisma } from "@/lib/db";
import { buildAuthorizeUrl, OAUTH_CONFIG } from "@/lib/oauth";
import {
  codeChallengeS256,
  generateCodeVerifier,
  generateState,
} from "@/lib/pkce";
import { randomToken } from "@/lib/crypto";

/**
 * SECURE FLOW — /api/auth/login.
 *
 * Begins Authorization Code + PKCE entirely server-side:
 *   1. Generate a PKCE code_verifier (secret) and its S256 code_challenge.
 *   2. Generate an anti-CSRF state.
 *   3. Persist the AuthRequest (state + challenge) and set short-lived
 *      HttpOnly cookies for the verifier + state.
 *   4. Redirect the browser to the mock provider's /authorize with the
 *      code_challenge (verifier never leaves the server / cookie jar).
 */

const AUTH_REQUEST_TTL_MS = 10 * 60 * 1000;

export async function GET(req: Request) {
  const origin = new URL(req.url).origin;

  const codeVerifier = generateCodeVerifier();
  const codeChallenge = codeChallengeS256(codeVerifier);
  const state = generateState();

  await prisma.authRequest.create({
    data: {
      id: randomToken(16),
      state,
      codeChallenge,
      challengeMethod: "S256",
      redirectUri: OAUTH_CONFIG.redirectUri,
      clientId: OAUTH_CONFIG.clientId,
      expiresAt: new Date(Date.now() + AUTH_REQUEST_TTL_MS),
    },
  });

  const authorizeUrl = buildAuthorizeUrl({
    baseUrl: origin,
    clientId: OAUTH_CONFIG.clientId,
    redirectUri: OAUTH_CONFIG.redirectUri,
    state,
    codeChallenge,
    codeChallengeMethod: "S256",
    scope: OAUTH_CONFIG.scope,
  });

  const res = NextResponse.json(
    { authorizeUrl, state },
    { status: 302, headers: { Location: authorizeUrl } },
  );
  res.headers.append("Set-Cookie", buildFlowCookie(PKCE_VERIFIER_COOKIE, codeVerifier));
  res.headers.append("Set-Cookie", buildFlowCookie(STATE_COOKIE, state));
  return res;
}
