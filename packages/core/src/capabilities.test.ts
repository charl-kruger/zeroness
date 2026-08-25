import { describe, it, expect } from "vitest";
import { parseCap, isCap, mintOpaqueToken } from "./capabilities";

describe("capability handles", () => {
  it("parses a bare handle", () => {
    expect(parseCap("cap:reports")).toEqual({ handle: "cap:reports", name: "reports", path: "" });
  });
  it("parses a handle with a path", () => {
    expect(parseCap("cap:reports://2026/q3.csv")).toEqual({ handle: "cap:reports", name: "reports", path: "2026/q3.csv" });
  });
  it("rejects non-cap URIs", () => {
    expect(parseCap("https://example.com")).toBeNull();
    expect(parseCap("/etc/passwd")).toBeNull();
    expect(isCap("cap:x")).toBe(true);
    expect(isCap("file:x")).toBe(false);
  });
  it("mints opaque, unguessable, unique tokens", () => {
    const a = mintOpaqueToken(), b = mintOpaqueToken();
    expect(a).toMatch(/^zn_[0-9a-f]{48}$/);
    expect(a).not.toEqual(b);
  });
});
