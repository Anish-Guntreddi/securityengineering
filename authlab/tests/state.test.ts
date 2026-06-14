import { describe, expect, it } from "vitest";
import { generateState } from "@/lib/pkce";
import { validateState } from "@/lib/oauth";

describe("state generation + validation", () => {
  it("validates a matching state", () => {
    const state = generateState();
    expect(validateState(state, state)).toBe(true);
  });

  it("rejects a tampered state", () => {
    const state = generateState();
    const tampered = state.slice(0, -1) + (state.endsWith("A") ? "B" : "A");
    expect(validateState(state, tampered)).toBe(false);
  });

  it("rejects a completely different state", () => {
    expect(validateState(generateState(), generateState())).toBe(false);
  });

  it("rejects when expected is missing", () => {
    expect(validateState(undefined, "anything")).toBe(false);
    expect(validateState(null, "anything")).toBe(false);
    expect(validateState("", "anything")).toBe(false);
  });

  it("rejects when received is missing", () => {
    const state = generateState();
    expect(validateState(state, undefined)).toBe(false);
    expect(validateState(state, null)).toBe(false);
    expect(validateState(state, "")).toBe(false);
  });

  it("rejects length-mismatched states", () => {
    const state = generateState();
    expect(validateState(state, state + "extra")).toBe(false);
  });
});
