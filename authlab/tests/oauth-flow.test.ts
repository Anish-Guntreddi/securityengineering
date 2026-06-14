import { beforeEach, describe, expect, it, vi } from "vitest";
import { prisma } from "@/lib/db";
import {
  codeChallengeS256,
  generateCodeVerifier,
  generateState,
} from "@/lib/pkce";
import { OAUTH_CONFIG } from "@/lib/oauth";
import { GET as authorizeHandler } from "@/app/api/mock-oauth/authorize/route";
import { POST as tokenHandler } from "@/app/api/mock-oauth/token/route";
import { GET as loginHandler } from "@/app/api/auth/login/route";
import { GET as callbackHandler } from "@/app/api/auth/callback/route";
import {
  parseCookies,
  PKCE_VERIFIER_COOKIE,
  STATE_COOKIE,
} from "@/lib/authCookies";
import { SESSION_COOKIE_NAME } from "@/lib/session";

const ORIGIN = "http://localhost:3000";

function authorizeUrl(params: Record<string, string>): string {
  const qs = new URLSearchParams(params);
  return `${ORIGIN}/api/mock-oauth/authorize?${qs.toString()}`;
}

async function callAuthorize(params: Record<string, string>) {
  return authorizeHandler(new Request(authorizeUrl(params)));
}

async function callToken(body: Record<string, string>) {
  return tokenHandler(
    new Request(`${ORIGIN}/api/mock-oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString(),
    }),
  );
}

/** Collect all Set-Cookie header values from a Response into one Cookie string. */
function cookieHeaderFromResponse(res: Response): string {
  const setCookies = res.headers.getSetCookie?.() ?? [];
  const pairs: string[] = [];
  for (const sc of setCookies) {
    const first = sc.split(";")[0];
    if (first) pairs.push(first.trim());
  }
  return pairs.join("; ");
}

describe("mock provider: authorize -> code", () => {
  beforeEach(async () => {
    await prisma.authCode.deleteMany();
  });

  it("issues an auth code bound to the PKCE challenge for a valid request", async () => {
    const verifier = generateCodeVerifier();
    const challenge = codeChallengeS256(verifier);
    const state = generateState();

    const res = await callAuthorize({
      response_type: "code",
      client_id: OAUTH_CONFIG.clientId,
      redirect_uri: OAUTH_CONFIG.redirectUri,
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });

    expect(res.status).toBe(302);
    const body = (await res.json()) as { code: string; state: string };
    expect(body.code).toBeTruthy();
    expect(body.state).toBe(state);

    const stored = await prisma.authCode.findUnique({ where: { id: body.code } });
    expect(stored?.codeChallenge).toBe(challenge);
    expect(stored?.consumedAt).toBeNull();
  });

  it("rejects an unknown client_id", async () => {
    const res = await callAuthorize({
      response_type: "code",
      client_id: "evil-client",
      redirect_uri: OAUTH_CONFIG.redirectUri,
      state: generateState(),
      code_challenge: codeChallengeS256(generateCodeVerifier()),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_client");
  });

  it("rejects an unregistered redirect_uri", async () => {
    const res = await callAuthorize({
      response_type: "code",
      client_id: OAUTH_CONFIG.clientId,
      redirect_uri: "http://evil.example/steal",
      state: generateState(),
      code_challenge: codeChallengeS256(generateCodeVerifier()),
    });
    expect(res.status).toBe(400);
  });

  it("rejects a missing state", async () => {
    const res = await callAuthorize({
      response_type: "code",
      client_id: OAUTH_CONFIG.clientId,
      redirect_uri: OAUTH_CONFIG.redirectUri,
      code_challenge: codeChallengeS256(generateCodeVerifier()),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error_description: string };
    expect(body.error_description).toMatch(/state/i);
  });

  it("rejects a missing code_challenge", async () => {
    const res = await callAuthorize({
      response_type: "code",
      client_id: OAUTH_CONFIG.clientId,
      redirect_uri: OAUTH_CONFIG.redirectUri,
      state: generateState(),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error_description: string };
    expect(body.error_description).toMatch(/code_challenge/i);
  });
});

describe("mock provider: token exchange (PKCE)", () => {
  async function getCode(challenge: string) {
    const res = await callAuthorize({
      response_type: "code",
      client_id: OAUTH_CONFIG.clientId,
      redirect_uri: OAUTH_CONFIG.redirectUri,
      state: generateState(),
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const body = (await res.json()) as { code: string };
    return body.code;
  }

  it("SUCCEEDS with the correct verifier and returns tokens", async () => {
    const verifier = generateCodeVerifier();
    const code = await getCode(codeChallengeS256(verifier));

    const res = await callToken({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: OAUTH_CONFIG.clientId,
      redirect_uri: OAUTH_CONFIG.redirectUri,
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      access_token: string;
      refresh_token: string;
      token_type: string;
    };
    expect(body.access_token).toBeTruthy();
    expect(body.refresh_token).toBeTruthy();
    expect(body.token_type).toBe("Bearer");
  });

  it("REJECTS the wrong verifier", async () => {
    const verifier = generateCodeVerifier();
    const code = await getCode(codeChallengeS256(verifier));

    const res = await callToken({
      grant_type: "authorization_code",
      code,
      code_verifier: generateCodeVerifier(), // wrong
      client_id: OAUTH_CONFIG.clientId,
      redirect_uri: OAUTH_CONFIG.redirectUri,
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { error_description: string };
    expect(body.error_description).toMatch(/PKCE/i);
  });

  it("REJECTS reuse of a single-use authorization code", async () => {
    const verifier = generateCodeVerifier();
    const code = await getCode(codeChallengeS256(verifier));

    const first = await callToken({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: OAUTH_CONFIG.clientId,
      redirect_uri: OAUTH_CONFIG.redirectUri,
    });
    expect(first.status).toBe(200);

    const second = await callToken({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: OAUTH_CONFIG.clientId,
      redirect_uri: OAUTH_CONFIG.redirectUri,
    });
    expect(second.status).toBe(400);
  });

  it("REJECTS a missing code_verifier", async () => {
    const verifier = generateCodeVerifier();
    const code = await getCode(codeChallengeS256(verifier));
    const res = await callToken({
      grant_type: "authorization_code",
      code,
      client_id: OAUTH_CONFIG.clientId,
      redirect_uri: OAUTH_CONFIG.redirectUri,
    });
    expect(res.status).toBe(400);
  });
});

describe("end-to-end secure flow via route handlers", () => {
  beforeEach(async () => {
    await prisma.refreshToken.deleteMany();
    await prisma.session.deleteMany();
    await prisma.authRequest.deleteMany();
    await prisma.authCode.deleteMany();
    vi.restoreAllMocks();
  });

  /**
   * Stub global fetch so the callback's back-channel POST to the token
   * endpoint is served directly by the mock token route handler (no network).
   */
  function stubTokenEndpoint() {
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      const urlStr = typeof input === "string" ? input : input.toString();
      if (urlStr.endsWith(OAUTH_CONFIG.tokenEndpoint)) {
        return tokenHandler(
          new Request(urlStr, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: init?.body as string,
          }),
        );
      }
      throw new Error(`unexpected fetch in test: ${urlStr}`);
    });
  }

  async function runLogin() {
    const res = await loginHandler(new Request(`${ORIGIN}/api/auth/login`));
    const cookies = cookieHeaderFromResponse(res);
    const parsed = parseCookies(cookies);
    const location = res.headers.get("Location")!;
    return { res, cookies, parsed, location };
  }

  it("completes login -> authorize -> callback and issues a session", async () => {
    stubTokenEndpoint();
    const { parsed, location } = await runLogin();

    // login must set the in-flight cookies and redirect to /authorize
    expect(parsed[PKCE_VERIFIER_COOKIE]).toBeTruthy();
    expect(parsed[STATE_COOKIE]).toBeTruthy();
    expect(location).toContain("/api/mock-oauth/authorize");
    expect(location).toContain("code_challenge=");
    expect(location).not.toContain("code_verifier"); // verifier never on front channel

    // The challenge sent matches sha256(verifier-from-cookie)
    const verifier = parsed[PKCE_VERIFIER_COOKIE];
    const sentChallenge = new URL(location).searchParams.get("code_challenge");
    expect(sentChallenge).toBe(codeChallengeS256(verifier));

    // Follow the authorize redirect to obtain the code.
    const authorizeRes = await authorizeHandler(new Request(location));
    const authorizeBody = (await authorizeRes.json()) as {
      code: string;
      state: string;
    };

    // Callback with the code + state, carrying the in-flight cookies.
    const callbackUrl = `${ORIGIN}/api/auth/callback?code=${authorizeBody.code}&state=${authorizeBody.state}`;
    const callbackRes = await callbackHandler(
      new Request(callbackUrl, {
        headers: {
          cookie: `${PKCE_VERIFIER_COOKIE}=${verifier}; ${STATE_COOKIE}=${parsed[STATE_COOKIE]}`,
        },
      }),
    );

    expect(callbackRes.status).toBe(200);
    const callbackBody = (await callbackRes.json()) as {
      sessionEstablished: boolean;
    };
    expect(callbackBody.sessionEstablished).toBe(true);

    // A session cookie (HttpOnly/Secure/SameSite) must be set.
    const setCookies = callbackRes.headers.getSetCookie();
    const sessionCookie = setCookies.find((c) =>
      c.startsWith(`${SESSION_COOKIE_NAME}=`),
    );
    expect(sessionCookie).toBeTruthy();
    expect(sessionCookie).toMatch(/HttpOnly/i);
    expect(sessionCookie).toMatch(/Secure/i);
    expect(sessionCookie).toMatch(/SameSite=Lax/i);

    // A session + refresh token now exist in the DB.
    const sessionId = parseCookies(
      sessionCookie!.split(";")[0],
    )[SESSION_COOKIE_NAME];
    const session = await prisma.session.findUnique({ where: { id: sessionId } });
    expect(session).not.toBeNull();
    const refresh = await prisma.refreshToken.findFirst({
      where: { sessionId },
    });
    expect(refresh).not.toBeNull();
  });

  it("REJECTS a callback with a mismatched (tampered) state", async () => {
    stubTokenEndpoint();
    const { parsed, location } = await runLogin();
    const verifier = parsed[PKCE_VERIFIER_COOKIE];

    const authorizeRes = await authorizeHandler(new Request(location));
    const authorizeBody = (await authorizeRes.json()) as { code: string };

    // Cookie state and query state disagree -> CSRF rejection.
    const tamperedState = "tampered-" + parsed[STATE_COOKIE];
    const callbackRes = await callbackHandler(
      new Request(
        `${ORIGIN}/api/auth/callback?code=${authorizeBody.code}&state=${tamperedState}`,
        {
          headers: {
            cookie: `${PKCE_VERIFIER_COOKIE}=${verifier}; ${STATE_COOKIE}=${parsed[STATE_COOKIE]}`,
          },
        },
      ),
    );
    expect(callbackRes.status).toBe(403);
  });

  it("REJECTS a callback with a missing state", async () => {
    stubTokenEndpoint();
    const { parsed, location } = await runLogin();
    const verifier = parsed[PKCE_VERIFIER_COOKIE];
    const authorizeRes = await authorizeHandler(new Request(location));
    const authorizeBody = (await authorizeRes.json()) as { code: string };

    const callbackRes = await callbackHandler(
      new Request(`${ORIGIN}/api/auth/callback?code=${authorizeBody.code}`, {
        headers: {
          cookie: `${PKCE_VERIFIER_COOKIE}=${verifier}; ${STATE_COOKIE}=${parsed[STATE_COOKIE]}`,
        },
      }),
    );
    expect(callbackRes.status).toBe(400);
  });

  it("REJECTS a callback when the state cookie is absent (no CSRF anchor)", async () => {
    stubTokenEndpoint();
    const { parsed, location } = await runLogin();
    const verifier = parsed[PKCE_VERIFIER_COOKIE];
    const authorizeRes = await authorizeHandler(new Request(location));
    const authorizeBody = (await authorizeRes.json()) as {
      code: string;
      state: string;
    };

    // No STATE_COOKIE in the request -> validateState fails closed.
    const callbackRes = await callbackHandler(
      new Request(
        `${ORIGIN}/api/auth/callback?code=${authorizeBody.code}&state=${authorizeBody.state}`,
        { headers: { cookie: `${PKCE_VERIFIER_COOKIE}=${verifier}` } },
      ),
    );
    expect(callbackRes.status).toBe(403);
  });
});
