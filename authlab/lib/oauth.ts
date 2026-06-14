import { constantTimeEqual } from "./pkce";

/**
 * Server-side OAuth helpers for the Authorization Code + PKCE flow.
 *
 * The token exchange happens ONLY on the server (the code + verifier never
 * touch client-side JS). `exchangeCodeForToken` performs a back-channel POST
 * to the (mock) token endpoint.
 */

export const OAUTH_CONFIG = {
  clientId: "authlab-demo-client",
  // The redirect URI the mock provider is allowed to call back. In the
  // sandbox this is the app's own callback route.
  redirectUri: "http://localhost:3000/api/auth/callback",
  authorizeEndpoint: "/api/mock-oauth/authorize",
  tokenEndpoint: "/api/mock-oauth/token",
  scope: "openid profile",
} as const;

export interface AuthorizeParams {
  baseUrl?: string;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod?: string;
  scope?: string;
  responseType?: string;
}

/**
 * Build the front-channel /authorize URL. Includes the PKCE code_challenge
 * (S256) and the anti-CSRF state. The verifier is intentionally NOT included.
 */
export function buildAuthorizeUrl(params: AuthorizeParams): string {
  const base = params.baseUrl ?? "";
  const qs = new URLSearchParams({
    response_type: params.responseType ?? "code",
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
    state: params.state,
    code_challenge: params.codeChallenge,
    code_challenge_method: params.codeChallengeMethod ?? "S256",
    scope: params.scope ?? OAUTH_CONFIG.scope,
  });
  return `${base}${OAUTH_CONFIG.authorizeEndpoint}?${qs.toString()}`;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
  userRef?: string;
}

export interface ExchangeParams {
  /** Absolute base URL of the token endpoint host (e.g. http://localhost:3000). */
  baseUrl: string;
  code: string;
  codeVerifier: string;
  clientId: string;
  redirectUri: string;
  /** Injectable fetch for tests (defaults to global fetch). */
  fetchImpl?: typeof fetch;
}

/**
 * Exchange an authorization code + PKCE verifier for tokens at the token
 * endpoint (back-channel POST, server-side only). Throws on a non-OK
 * response so callers fail closed.
 */
export async function exchangeCodeForToken(
  params: ExchangeParams,
): Promise<TokenResponse> {
  const doFetch = params.fetchImpl ?? fetch;
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    code_verifier: params.codeVerifier,
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
  });

  const res = await doFetch(`${params.baseUrl}${OAUTH_CONFIG.tokenEndpoint}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!res.ok) {
    let detail = "";
    try {
      detail = JSON.stringify(await res.json());
    } catch {
      // ignore body parse errors
    }
    throw new Error(`token exchange failed (${res.status}): ${detail}`);
  }

  return (await res.json()) as TokenResponse;
}

/**
 * Validate the `state` returned from the provider against the value we stored
 * before the redirect. Uses a constant-time comparison. Returns false on any
 * mismatch or missing value (fail closed) -> defends against CSRF.
 */
export function validateState(
  expected: string | undefined | null,
  received: string | undefined | null,
): boolean {
  if (!expected || !received) return false;
  return constantTimeEqual(expected, received);
}
