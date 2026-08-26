import { describe, it, expect, beforeEach } from "vitest";
import { ZeronessBroker } from "./index";

// ---- in-process fakes for the DO storage + R2 (mimic structured-clone semantics) ----
class MemStorage {
  m = new Map<string, unknown>();
  async get<T>(k: string): Promise<T | undefined> { const v = this.m.get(k); return v === undefined ? undefined : (JSON.parse(JSON.stringify(v)) as T); }
  async put(k: string, v: unknown): Promise<void> { this.m.set(k, JSON.parse(JSON.stringify(v))); }
  async delete(k: string): Promise<void> { this.m.delete(k); }
}
class MemR2 {
  m = new Map<string, string>();
  async put(k: string, v: string | Uint8Array) { this.m.set(k, typeof v === "string" ? v : Buffer.from(v).toString("binary")); }
  async get(k: string) { const v = this.m.get(k); return v === undefined ? null : { async text() { return v; }, body: v }; }
}

const TOK = "zn_session_token";
function makeBroker() {
  const state = { storage: new MemStorage() } as unknown as DurableObjectState;
  const env = { SNAPSHOTS: new MemR2() as unknown as R2Bucket, SECRETS: { STRIPE_RO: "sk_test_abc" } };
  return new ZeronessBroker(state, env);
}
const req = (path: string, init: RequestInit = {}) => new Request(`https://zeroness.broker${path}`, init);
const j = (path: string, method: string, body?: unknown, headers: Record<string, string> = {}) =>
  req(path, { method, headers: { "content-type": "application/json", ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });

describe("broker integration", () => {
  let b: ZeronessBroker;
  beforeEach(async () => {
    b = makeBroker();
    const res = await b.fetch(j("/session", "POST", {
      sessionId: "sid1", sessionToken: TOK, pubKey: "x",
      policy: {
        default: "deny",
        allow: [
          { host: "api.github.com", methods: ["GET"], path: "/repos/**" },
          { host: "api.stripe.com", verdict: "ask", identity: "cap:stripe" },
        ],
      },
      resources: { stripe: { accessToken: "STRIPE_RO" }, reports: { r2: "reports", mode: "rw", prefix: "u/" } },
    }));
    expect(res.status).toBe(200);
  });

  it("allows an allow-listed request", async () => {
    const d = await (await b.fetch(j("/authorize", "POST", { token: TOK, url: "https://api.github.com/repos/a/b", method: "GET" }))).json();
    expect(d.verdict).toBe("allow");
  });

  it("denies by default", async () => {
    const d = await (await b.fetch(j("/authorize", "POST", { token: TOK, url: "https://evil.com/", method: "GET" }))).json();
    expect(d.verdict).toBe("deny");
  });

  it("rejects an unknown/forged session token", async () => {
    const res = await b.fetch(j("/authorize", "POST", { token: "wrong", url: "https://api.github.com/repos/a/b", method: "GET" }));
    expect(res.status).toBe(401);
  });

  it("gates a risky route, then allows it after human approval + injects brokered identity", async () => {
    const ask = await (await b.fetch(j("/authorize", "POST", { token: TOK, url: "https://api.stripe.com/v1/charges", method: "POST" }))).json();
    expect(ask.verdict).toBe("ask");
    expect(ask.approvalId).toBeTruthy();

    // still ask before approval
    const ask2 = await (await b.fetch(j("/authorize", "POST", { token: TOK, url: "https://api.stripe.com/v1/charges", method: "POST" }))).json();
    expect(ask2.verdict).toBe("ask");

    // human approves
    const ap = await b.fetch(j(`/approval/${ask.approvalId}/approve`, "POST"));
    expect(ap.status).toBe(200);

    // retry now allowed, with the Stripe secret injected (never seen by the sandbox)
    const allow = await (await b.fetch(j("/authorize", "POST", { token: TOK, url: "https://api.stripe.com/v1/charges", method: "POST" }))).json();
    expect(allow.verdict).toBe("allow");
    expect(allow.injectHeaders.authorization).toBe("Bearer sk_test_abc");
  });

  it("writes then reads a capability by handle (path via query on GET)", async () => {
    const w = await b.fetch(j("/cap/reports", "POST", { path: "q3.csv", data: "hello" }, { "x-zeroness-token": TOK }));
    expect((await w.json()).ok).toBe(true);
    const r = await b.fetch(req("/cap/reports?path=q3.csv", { method: "GET", headers: { "x-zeroness-token": TOK } }));
    expect((await r.json()).content).toBe("hello");
  });

  it("rejects a capability op from a mismatched token", async () => {
    const res = await b.fetch(j("/cap/reports", "POST", { path: "x", data: "y" }, { "x-zeroness-token": "wrong" }));
    expect(res.status).toBe(403);
  });

  it("stores a content-addressed snapshot and serves it back", async () => {
    const up = await b.fetch(req("/snapshot/upload", { method: "POST", headers: { "x-zeroness-token": TOK }, body: "SNAPSHOT-BYTES" }));
    const { ref } = await up.json();
    expect(ref).toMatch(/^snap_[0-9a-f]{64}$/);
    const get = await b.fetch(req(`/snapshot/${ref}`, { method: "GET" }));
    expect(get.status).toBe(200);
  });

  it("records an audit trail of decisions", async () => {
    await b.fetch(j("/authorize", "POST", { token: TOK, url: "https://api.github.com/repos/a/b", method: "GET" }));
    await b.fetch(j("/authorize", "POST", { token: TOK, url: "https://evil.com/", method: "GET" }));
    const audit = await (await b.fetch(req("/audit", { method: "GET" }))).json();
    const events = audit.map((a: { event: string }) => a.event);
    expect(events).toContain("egress:allow");
    expect(events).toContain("egress:deny");
  });
});
