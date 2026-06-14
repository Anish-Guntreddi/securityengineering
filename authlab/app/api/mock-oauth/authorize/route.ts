import { NextResponse } from "next/server";
import { randomToken } from "@/lib/crypto";
import { prisma } from "@/lib/db";
import { OAUTH_CONFIG } from "@/lib/oauth";

/**
 * MOCK OAuth2 Authorization Server — /authorize (SANDBOX, TEST PROVIDER).
 *
 * This is a self-contained fake provider. It uses NO real accounts and never
 * talks to the network. It implements the front-channel half of Authorization
 * Code + PKCE:
 *   - validates client_id, redirect_uri, response_type, state, code_challenge
 *   - "authenticates" a fixed sandbox pseudo-user (no credentials collected)
 *   - issues a single-use authorization code BOUND to the code_challenge
 *   - redirects back to redirect_uri with ?code=...&state=...
 *
 * Allowed-list of clients/redirects keeps the sandbox closed.
 */

const ALLOWED_CLIENTS: Record<string, { redirectUris: string[] }> = {
  [OAUTH_CONFIG.clientId]: {
    redirectUris: [OAUTH_CONFIG.redirectUri],
  },
};

// Fixed sandbox identity. NOT a real user — purely a label for the demo.
const SANDBOX_USER_REF = "sandbox-user-001";

const AUTH_CODE_TTL_MS = 5 * 60 * 1000;

function errorResponse(error: string, description: string, status = 400) {
  return NextResponse.json({ error, error_description: description }, { status });
}

export async function GET(req: Request) {
  const url = new URL(req.url);
  const p = url.searchParams;

  const responseType = p.get("response_type");
  const clientId = p.get("client_id");
  const redirectUri = p.get("redirect_uri");
  const state = p.get("state");
  const codeChallenge = p.get("code_challenge");
  const codeChallengeMethod = p.get("code_challenge_method") ?? "S256";

  if (responseType !== "code") {
    return errorResponse("unsupported_response_type", "only 'code' is supported");
  }
  if (!clientId || !ALLOWED_CLIENTS[clientId]) {
    return errorResponse("invalid_client", "unknown client_id");
  }
  if (!redirectUri || !ALLOWED_CLIENTS[clientId].redirectUris.includes(redirectUri)) {
    // Per spec we must NOT redirect to an unregistered URI.
    return errorResponse("invalid_request", "redirect_uri not registered");
  }
  if (!state) {
    return errorResponse("invalid_request", "missing state (anti-CSRF)");
  }
  if (!codeChallenge) {
    return errorResponse("invalid_request", "missing PKCE code_challenge");
  }
  if (codeChallengeMethod !== "S256") {
    return errorResponse(
      "invalid_request",
      "only S256 code_challenge_method is supported",
    );
  }

  // Issue a single-use auth code bound to the PKCE challenge.
  const code = randomToken(32);
  await prisma.authCode.create({
    data: {
      id: code,
      clientId,
      redirectUri,
      codeChallenge,
      challengeMethod: codeChallengeMethod,
      userRef: SANDBOX_USER_REF,
      expiresAt: new Date(Date.now() + AUTH_CODE_TTL_MS),
    },
  });

  // Redirect back to the client with code + state.
  const redirect = new URL(redirectUri);
  redirect.searchParams.set("code", code);
  redirect.searchParams.set("state", state);

  return NextResponse.json(
    { redirect: redirect.toString(), code, state },
    {
      status: 302,
      headers: { Location: redirect.toString() },
    },
  );
}
