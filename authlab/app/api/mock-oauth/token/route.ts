import { NextResponse } from "next/server";
import { randomToken } from "@/lib/crypto";
import { prisma } from "@/lib/db";
import { verifyCodeChallenge } from "@/lib/pkce";

/**
 * MOCK OAuth2 Authorization Server — /token (SANDBOX, TEST PROVIDER).
 *
 * Back-channel half of Authorization Code + PKCE. Given an authorization code
 * and a PKCE code_verifier it:
 *   - looks up the single-use code (rejecting unknown/expired/consumed)
 *   - verifies client_id + redirect_uri match what the code was issued for
 *   - verifies the code_verifier against the stored S256 challenge
 *   - consumes the code (single-use) and returns access + refresh tokens
 *
 * These tokens are opaque random strings with no real privileges.
 */

function tokenError(error: string, description: string, status = 400) {
  return NextResponse.json(
    { error, error_description: description },
    { status },
  );
}

export async function POST(req: Request) {
  let params: URLSearchParams;
  const contentType = req.headers.get("content-type") ?? "";
  try {
    if (contentType.includes("application/json")) {
      const json = await req.json();
      params = new URLSearchParams(json as Record<string, string>);
    } else {
      params = new URLSearchParams(await req.text());
    }
  } catch {
    return tokenError("invalid_request", "could not parse request body");
  }

  const grantType = params.get("grant_type");
  const code = params.get("code");
  const codeVerifier = params.get("code_verifier");
  const clientId = params.get("client_id");
  const redirectUri = params.get("redirect_uri");

  if (grantType !== "authorization_code") {
    return tokenError("unsupported_grant_type", "only authorization_code");
  }
  if (!code) {
    return tokenError("invalid_request", "missing code");
  }
  if (!codeVerifier) {
    return tokenError("invalid_request", "missing PKCE code_verifier");
  }

  const authCode = await prisma.authCode.findUnique({ where: { id: code } });
  if (!authCode) {
    return tokenError("invalid_grant", "unknown authorization code");
  }
  if (authCode.consumedAt) {
    return tokenError("invalid_grant", "authorization code already used");
  }
  if (authCode.expiresAt.getTime() <= Date.now()) {
    return tokenError("invalid_grant", "authorization code expired");
  }
  if (clientId && clientId !== authCode.clientId) {
    return tokenError("invalid_grant", "client_id mismatch");
  }
  if (redirectUri && redirectUri !== authCode.redirectUri) {
    return tokenError("invalid_grant", "redirect_uri mismatch");
  }

  // The crux of PKCE: verify the verifier against the stored challenge.
  const ok = verifyCodeChallenge(
    codeVerifier,
    authCode.codeChallenge,
    authCode.challengeMethod,
  );
  if (!ok) {
    return tokenError("invalid_grant", "PKCE verification failed");
  }

  // Consume the code (single-use). updateMany with consumedAt:null guards
  // against a race where two requests redeem the same code.
  const consumed = await prisma.authCode.updateMany({
    where: { id: code, consumedAt: null },
    data: { consumedAt: new Date() },
  });
  if (consumed.count !== 1) {
    return tokenError("invalid_grant", "authorization code already used");
  }

  const accessToken = randomToken(32);
  const refreshToken = randomToken(32);

  return NextResponse.json({
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: "openid profile",
    userRef: authCode.userRef,
  });
}
