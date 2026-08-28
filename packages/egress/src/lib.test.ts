import { describe, it, expect } from "vitest";
import { sessionToken, intendedTarget, capName, snapshotRef } from "./lib";

const mk = (url: string, headers: Record<string, string> = {}, method = "GET") => new Request(url, { method, headers });

describe("egress request parsing", () => {
  it("extracts the session token from a header", () => {
    expect(sessionToken(mk("https://e.workers.dev", { "x-zeroness-session-token": "zn_abc" }))).toBe("zn_abc");
  });
  it("extracts the session token from proxy basic auth", () => {
    const basic = "Basic " + btoa("zeroness:zn_xyz");
    expect(sessionToken(mk("https://e.workers.dev", { "proxy-authorization": basic }))).toBe("zn_xyz");
  });
  it("returns null when no token", () => {
    expect(sessionToken(mk("https://e.workers.dev"))).toBeNull();
  });
  it("resolves an absolute forward-proxy target", () => {
    expect(intendedTarget(mk("https://api.github.com/repos/a/b"))?.hostname).toBe("api.github.com");
  });
  it("ignores the worker's own host as a target", () => {
    expect(intendedTarget(mk("https://edge.workers.dev/anything"))).toBeNull();
  });
  it("prefers the explicit intercept target header", () => {
    expect(intendedTarget(mk("https://edge.workers.dev", { "x-zeroness-target": "https://pypi.org/simple" }))?.hostname).toBe("pypi.org");
  });
  it("recognizes capability paths and decodes the name", () => {
    expect(capName(mk("https://edge.workers.dev/__zeroness/cap/reports?path=x"))).toBe("reports");
    expect(capName(mk("https://edge.workers.dev/anything"))).toBeNull();
  });
  it("recognizes a snapshot download path and validates the ref", () => {
    expect(snapshotRef(mk("https://edge.workers.dev/__zeroness/snapshot/snap_abc123"))).toBe("snap_abc123");
    expect(snapshotRef(mk("https://edge.workers.dev/__zeroness/snapshot/upload"))).toBeNull();
    expect(snapshotRef(mk("https://edge.workers.dev/__zeroness/snapshot/../evil"))).toBeNull();
  });
});
