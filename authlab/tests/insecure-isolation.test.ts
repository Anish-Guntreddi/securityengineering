import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Each insecure demo page must (1) be loudly labeled and (2) stay isolated
// from the real secure machinery. We assert both by static inspection of the
// page source.

const INSECURE_DIR = resolve(__dirname, "..", "app", "insecure");

const INSECURE_PAGES = [
  "token-in-localstorage/page.tsx",
  "missing-state/page.tsx",
  "missing-pkce/page.tsx",
];

// Modules that implement the REAL secure flow. Insecure demos must not import
// any of these (they are sandboxed illustrations only).
const FORBIDDEN_IMPORTS = [
  "@/lib/session",
  "@/lib/tokens",
  "@/lib/oauth",
  "@/lib/db",
  "@/lib/authCookies",
  "@/app/api/auth",
  "@/app/api/mock-oauth",
  "../../api/auth",
  "../../api/mock-oauth",
  "generated/prisma",
];

function readPage(rel: string): string {
  return readFileSync(resolve(INSECURE_DIR, rel), "utf8");
}

describe("insecure demos are loudly labeled", () => {
  it.each(INSECURE_PAGES)("%s contains the INSECURE - FOR EDUCATION ONLY label", (rel) => {
    const src = readPage(rel);
    expect(src.toUpperCase()).toContain("INSECURE");
    expect(src.toUpperCase()).toContain("FOR EDUCATION ONLY");
  });

  it("the insecure index page is also loudly labeled", () => {
    const src = readFileSync(resolve(INSECURE_DIR, "page.tsx"), "utf8");
    expect(src.toUpperCase()).toContain("INSECURE");
    expect(src.toUpperCase()).toContain("FOR EDUCATION ONLY");
  });
});

describe("insecure demos do NOT import the real session/provider modules", () => {
  it.each(INSECURE_PAGES)("%s imports none of the real modules", (rel) => {
    const src = readPage(rel);
    // Look only at import statements to avoid matching prose/code samples.
    const importLines = src
      .split("\n")
      .filter((line) => /^\s*import\b/.test(line) || /\brequire\(/.test(line));
    const importBlock = importLines.join("\n");
    for (const forbidden of FORBIDDEN_IMPORTS) {
      expect(importBlock).not.toContain(forbidden);
    }
  });

  it.each(INSECURE_PAGES)("%s shows the secure fix side by side", (rel) => {
    const src = readPage(rel);
    // Each demo links back to the secure flow and labels both columns.
    expect(src).toContain("/secure");
    expect(src.toLowerCase()).toContain("secure fix");
  });
});
