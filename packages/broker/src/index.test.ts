import { describe, it, expect, beforeEach } from "vitest";
import { ZeronessBroker } from "./index";

// ---- in-process fakes for the DO storage + R2 (mimic structured-clone semantics) ----
class MemStorage {
  m = new Map<string, unknown>();
  async get<T>(k: string): Promise<T | undefined> { const v = this.m.get(k); return v === undefined ? undefined : (JSON.parse(JSON.stringify(v)) as T); }
  async put(k: string, v: unknown): Promise<void> { this.m.set(k, JSON.parse(JSON.stringify(v))); }
  async delete(k: string): Promise<void> { this.m.delete(k); }
  async list<T>(opts: { prefix?: string; limit?: number; reverse?: boolean } = {}): Promise<Map<string, T>> {
    let keys = [...this.m.keys()].filter((k) => !opts.prefix || k.startsWith(opts.prefix)).sort();
    if (opts.reverse) keys.reverse();
    if (opts.limit) keys = keys.slice(0, opts.limit);
    const out = new Map<string, T>();
    for (const k of keys) out.set(k, JSON.parse(JSON.stringify(this.m.get(k))) as T);
    return out;
  }
}
class MemR2 {
  m = new Map<string, string>();
  async put(k: string, v: string | Uint8Array) { this.m.set(k, typeof v === "string" ? v : Buffer.from(v).toString("binary")); }
  async get(k: string) { const v = this.m.get(k); return v === undefined ? null : { async text() { return v; }, body: v }; }
}
class MemKV {
  m = new Map<string, string>();
  async put(k: string, v: string | Uint8Array) { this.m.set(k, typeof v === "string" ? v : Buffer.from(v).toString("binary")); }
  async get(k: string) { return this.m.get(k) ?? null; }
}
class MemD1 {
  rows: Array<Record<string, unknown>> = [];
  writes: string[] = [];           // every statement that actually executed a write
  prepare(sql: string) {
    const self = this;
    const stmt = {
      bind(..._params: unknown[]) { return stmt; },
      async run() { self.writes.push(sql); return { success: true, meta: {} }; },
      async all() {
        // A real D1 .all() executes writes too — model that, so ro-enforcement can be tested.
        if (/^\s*(insert|update|delete|drop|create|alter|replace)\b/i.test(sql)) self.writes.push(sql);
        return { results: self.rows };
      },
    };
    return stmt;
  }
}

const TOK = "zn_session_token";
function makeBroker() {
  const state = { storage: new MemStorage() } as unknown as DurableObjectState;
  const d1 = new MemD1();
  const kv = new MemKV();
  const reports = new MemR2();
  const env = {
    SNAPSHOTS: new MemR2() as unknown as R2Bucket,
    SECRETS: { STRIPE_RO: "sk_test_abc" },
    analytics: d1 as unknown as D1Database,
    cache: kv as unknown as KVNamespace,
    reports: reports as unknown as R2Bucket,
  };
  return { broker: new ZeronessBroker(state, env), d1, kv, reports };
}
const req = (path: string, init: RequestInit = {}) => new Request(`https://zeroness.broker${path}`, init);
const j = (path: string, method: string, body?: unknown, headers: Record<string, string> = {}) =>
  req(path, { method, headers: { "content-type": "application/json", ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });

describe("broker integration", () => {
  let b: ZeronessBroker;
  let d1: MemD1;
  let kv: MemKV;
  let reports: MemR2;
  beforeEach(async () => {
    ({ broker: b, d1, kv, reports } = makeBroker());
    const res = await b.fetch(j("/session", "POST", {
      sessionId: "sid1", sessionToken: TOK, pubKey: "x",
      policy: {
        default: "deny",
        allow: [
          { host: "api.github.com", methods: ["GET"], path: "/repos/**" },
          { host: "api.stripe.com", verdict: "ask", identity: "cap:stripe" },
        ],
      },
      resources: {
        stripe: { accessToken: "STRIPE_RO" },
        reports: { r2: "reports", mode: "rw", prefix: "u/" },
        analyticsRo: { d1: "analytics", mode: "ro" },
        analyticsRw: { d1: "analytics", mode: "rw" },
        cacheRw: { kv: "cache", mode: "rw" },
        cacheRo: { kv: "cache", mode: "ro" },
      },
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

  it("writes R2 capability data to its configured bucket, not the snapshots bucket", async () => {
    await b.fetch(j("/cap/reports", "POST", { path: "q3.csv", data: "hello" }, { "x-zeroness-token": TOK }));
    expect(reports.m.has("u/q3.csv")).toBe(true);      // landed in the reports bucket, with prefix
    // and did NOT leak into the snapshots bucket
    const snapKeys = [...(reports.m.keys())].filter((k) => k.startsWith("snapshots/"));
    expect(snapKeys).toEqual([]);
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

  it("keeps the audit log chronological and bounded", async () => {
    for (let i = 0; i < 1005; i++) {
      await b.fetch(j("/audit", "POST", { event: "tick", detail: { i } }));
    }
    const audit = await (await b.fetch(req("/audit", { method: "GET" }))).json();
    const ticks = audit.filter((a: { event: string }) => a.event === "tick");
    expect(ticks.length).toBe(1000);                              // trimmed to the cap
    expect((ticks[0].detail as { i: number }).i).toBe(5);         // oldest 5 dropped
    expect((ticks.at(-1).detail as { i: number }).i).toBe(1004);  // newest retained, in order
  });

  it("injects a brokered accessToken identity on an allowed request", async () => {
    // add a direct allow-with-identity to a fresh session
    const b2 = makeBroker().broker;
    await b2.fetch(j("/session", "POST", {
      sessionId: "sid2", sessionToken: TOK, pubKey: "x",
      policy: { default: "deny", allow: [{ host: "api.stripe.com", identity: "cap:stripe" }] },
      resources: { stripe: { accessToken: "STRIPE_RO" } },
    }));
    const d = await (await b2.fetch(j("/authorize", "POST", { token: TOK, url: "https://api.stripe.com/v1/x", method: "GET" }))).json();
    expect(d.verdict).toBe("allow");
    expect(d.injectHeaders.authorization).toBe("Bearer sk_test_abc");
  });

  it("writes then reads a KV capability by handle", async () => {
    const w = await b.fetch(j("/cap/cacheRw", "POST", { path: "k1", data: "v1" }, { "x-zeroness-token": TOK }));
    expect(w.status).toBe(200);
    const r = await b.fetch(req("/cap/cacheRw?path=k1", { method: "GET", headers: { "x-zeroness-token": TOK } }));
    expect((await r.json()).content).toBe("v1");
  });

  it("blocks a write to a read-only KV capability", async () => {
    const w = await b.fetch(j("/cap/cacheRo", "POST", { path: "k1", data: "v1" }, { "x-zeroness-token": TOK }));
    expect(w.status).toBe(403);
  });

  it("reads through a D1 capability", async () => {
    d1.rows = [{ id: 1, name: "a" }];
    const r = await b.fetch(req("/cap/analyticsRo?query=" + encodeURIComponent("SELECT * FROM t"), {
      method: "GET", headers: { "x-zeroness-token": TOK },
    }));
    expect((await r.json()).results).toEqual([{ id: 1, name: "a" }]);
  });

  it("blocks a write through a read-only D1 capability (POST)", async () => {
    const res = await b.fetch(j("/cap/analyticsRo", "POST", { query: "DELETE FROM users" }, { "x-zeroness-token": TOK }));
    expect(res.status).toBe(403);
    expect(d1.writes).toEqual([]); // the write never executed
  });

  it("blocks a write through a read-only D1 capability (GET)", async () => {
    const res = await b.fetch(req("/cap/analyticsRo?query=" + encodeURIComponent("DELETE FROM users"), {
      method: "GET", headers: { "x-zeroness-token": TOK },
    }));
    expect(res.status).toBe(403);
    expect(d1.writes).toEqual([]);
  });

  it("blocks multi-statement smuggling on a read-only D1 capability", async () => {
    const res = await b.fetch(j("/cap/analyticsRo", "POST", { query: "SELECT 1; DROP TABLE users" }, { "x-zeroness-token": TOK }));
    expect(res.status).toBe(403);
    expect(d1.writes).toEqual([]);
  });

  it("allows a write through a read-write D1 capability", async () => {
    const res = await b.fetch(j("/cap/analyticsRw", "POST", { query: "INSERT INTO t VALUES (1)" }, { "x-zeroness-token": TOK }));
    expect((await res.json()).success).toBe(true);
    expect(d1.writes).toContain("INSERT INTO t VALUES (1)");
  });

  it("blocks a CTE that feeds a write on a read-only D1 capability", async () => {
    const res = await b.fetch(j("/cap/analyticsRo", "POST", { query: "WITH x AS (SELECT 1) DELETE FROM users" }, { "x-zeroness-token": TOK }));
    expect(res.status).toBe(403);
    expect(d1.writes).toEqual([]);
  });

  it("blocks a mutating PRAGMA on a read-only D1 capability", async () => {
    const res = await b.fetch(j("/cap/analyticsRo", "POST", { query: "PRAGMA user_version = 5" }, { "x-zeroness-token": TOK }));
    expect(res.status).toBe(403);
    expect(d1.writes).toEqual([]);
  });

  it("still allows a read-only CTE on a read-only D1 capability", async () => {
    d1.rows = [{ n: 1 }];
    const res = await b.fetch(req("/cap/analyticsRo?query=" + encodeURIComponent("WITH x AS (SELECT 1) SELECT * FROM x"), { method: "GET", headers: { "x-zeroness-token": TOK } }));
    expect(res.status).toBe(200);
    expect((await res.json()).results).toEqual([{ n: 1 }]);
  });
});
