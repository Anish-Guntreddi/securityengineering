import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  base64urlDecode,
  base64urlEncode,
  sha256Base64url,
} from "@/lib/crypto";
import {
  codeChallengeS256,
  constantTimeEqual,
  generateCodeVerifier,
  generateState,
  verifyCodeChallenge,
} from "@/lib/pkce";

describe("base64url", () => {
  it("round-trips arbitrary bytes", () => {
    const data = Buffer.from([0, 1, 2, 250, 251, 255, 62, 63]);
    const encoded = base64urlEncode(data);
    expect(encoded).not.toMatch(/[+/=]/); // url-safe, no padding
    expect(base64urlDecode(encoded).equals(data)).toBe(true);
  });

  it("produces the url-safe alphabet for bytes that map to + and /", () => {
    // 0xFB,0xFF,0xBF -> base64 "+/+/"-ish; ensure no +,/ survive
    const encoded = base64urlEncode(Buffer.from([0xfb, 0xff, 0xbf]));
    expect(encoded.includes("+")).toBe(false);
    expect(encoded.includes("/")).toBe(false);
  });
});

describe("PKCE S256", () => {
  it("derives the challenge as base64url(sha256(verifier))", () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const expected = createHash("sha256")
      .update(verifier)
      .digest("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
    expect(codeChallengeS256(verifier)).toBe(expected);
    expect(sha256Base64url(verifier)).toBe(expected);
  });

  it("matches the RFC 7636 Appendix B test vector", () => {
    // RFC 7636 example verifier/challenge pair.
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    expect(codeChallengeS256(verifier)).toBe(challenge);
  });

  it("challenge is never equal to the verifier", () => {
    for (let i = 0; i < 20; i++) {
      const verifier = generateCodeVerifier();
      const challenge = codeChallengeS256(verifier);
      expect(challenge).not.toBe(verifier);
    }
  });

  it("generates verifiers of sufficient length/entropy and uniqueness", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const v = generateCodeVerifier();
      expect(v.length).toBeGreaterThanOrEqual(43); // RFC minimum
      expect(v).toMatch(/^[A-Za-z0-9\-_]+$/);
      seen.add(v);
    }
    expect(seen.size).toBe(50);
  });

  it("rejects verifiers with too little entropy", () => {
    expect(() => generateCodeVerifier(16)).toThrow();
  });

  it("verifyCodeChallenge accepts the correct verifier and rejects wrong ones", () => {
    const verifier = generateCodeVerifier();
    const challenge = codeChallengeS256(verifier);
    expect(verifyCodeChallenge(verifier, challenge)).toBe(true);
    expect(verifyCodeChallenge(generateCodeVerifier(), challenge)).toBe(false);
    // plain method is intentionally unsupported even if the value "matches"
    expect(verifyCodeChallenge(verifier, challenge, "plain")).toBe(false);
  });
});

describe("constantTimeEqual", () => {
  it("returns true for identical strings", () => {
    expect(constantTimeEqual("abc123", "abc123")).toBe(true);
  });

  it("returns false for different strings of equal length", () => {
    expect(constantTimeEqual("abc123", "abc124")).toBe(false);
  });

  it("returns false for different-length strings without throwing", () => {
    expect(constantTimeEqual("short", "longer-string")).toBe(false);
  });

  it("returns false comparing empty vs non-empty", () => {
    expect(constantTimeEqual("", "x")).toBe(false);
  });
});

describe("generateState", () => {
  it("produces unique high-entropy url-safe values", () => {
    const a = generateState();
    const b = generateState();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9\-_]+$/);
    expect(a.length).toBeGreaterThanOrEqual(43);
  });
});
