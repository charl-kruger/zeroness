# Plan 001: Lock correct capability behavior with tests and add reusable D1/KV fakes

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 8ac83e3..HEAD -- packages/broker/src`
> If `packages/broker/src/index.ts` or `packages/broker/src/index.test.ts`
> changed since this plan was written, compare the "Current state" excerpts
> against the live code before proceeding; on a mismatch, treat it as a STOP
> condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: LOW
- **Depends on**: none
- **Category**: tests
- **Planned at**: commit `8ac83e3`, 2026-08-28

## Why this matters

The Broker (`@zeroness/broker`) is the trust root: it resolves capabilities to
real bindings and mints identity. Its integration test currently covers only
the accessToken-injection path and a single R2 read/write roundtrip. The D1 and
KV capability paths, and the `mode:"ro"` enforcement contract, have **zero
tests**. Two follow-up plans (002 fixes a D1 read-only bypass, 003 fixes an R2
bucket-resolution bug) will change this code; without a safety net that pins the
*correct* behaviors first, those fixes could silently regress KV writes,
identity injection, or D1 reads. This plan adds that net and introduces
in-process `MemD1`/`MemKV` fakes that plans 002 reuse.

This plan **only adds tests and test fakes**. It changes no production code and
must not assert any of the buggy behaviors that plans 002/003 will fix.

## Current state

- `packages/broker/src/index.ts` — the `ZeronessBroker` Durable Object. The
  capability handler `capIO(method, name, body)` (lines 188–236) dispatches on
  binding type. The KV branch (lines 221–233) enforces read-only correctly:
  a `POST` to a `mode:"ro"` KV cap returns `403`. The D1 branch (lines 208–219)
  resolves the database by name via `this.env[binding.d1]`.
- `packages/broker/src/index.test.ts` — the in-process integration test. It
  already defines `MemStorage` and `MemR2` fakes, a `makeBroker()` helper, and
  `req`/`j` request builders. Excerpt of the current harness:

```ts
// packages/broker/src/index.test.ts:11-25
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
```

- The `beforeEach` (lines 29–43) registers a session whose `resources` are
  `{ stripe: { accessToken: "STRIPE_RO" }, reports: { r2: "reports", mode: "rw", prefix: "u/" } }`.
- How the broker reads KV/D1 bindings, for reference (do **not** change this
  file in this plan):

```ts
// packages/broker/src/index.ts:208-233 (abridged)
if ("d1" in binding) {
  const db = this.env[binding.d1] as D1Database | undefined;               // resolves by name
  ...
  const r = await db.prepare(body.query ?? "SELECT 1").bind(...(body.params ?? [])).all();
  return json({ results: r.results });
}
if ("kv" in binding) {
  const ns = this.env[binding.kv] as KVNamespace | undefined;             // resolves by name
  ...
  if (method === "POST") { if (binding.mode === "ro") return json({ error: "read-only capability" }, 403); await ns.put(key, ...); ... }
  await ns.get(key); ...
}
```

- Test conventions: Vitest, `describe/it/expect`, in-process fakes typed via
  `as unknown as <CfType>`, one behavior per `it`. Follow the existing file's
  style exactly.

## Commands you will need

| Purpose        | Command                                   | Expected on success        |
|----------------|-------------------------------------------|----------------------------|
| Install        | `pnpm install`                            | exit 0                     |
| Test (broker)  | `pnpm --filter @zeroness/broker test`     | all pass, incl. new tests  |
| Typecheck      | `pnpm --filter @zeroness/broker typecheck`| exit 0, no errors          |

## Scope

**In scope** (the only file you may modify):
- `packages/broker/src/index.test.ts`

**Out of scope** (do NOT touch):
- `packages/broker/src/index.ts` — no production change in this plan. If a test
  you add fails because the production code is wrong, that is expected for the
  D1 read-only case **only if you were about to test it — you are not** (see
  Steps; the D1 write-bypass assertion belongs to plan 002). Do not "fix" prod
  code here.
- Any other package.

## Git workflow

- Branch: `advisor/001-capability-characterization-tests`
- Commit message style — conventional commits, matching `git log` (e.g.
  `test: cover KV/D1 capability paths + identity injection in broker`).
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Add `MemKV` and `MemD1` fakes

In `packages/broker/src/index.test.ts`, directly below the `MemR2` class
(after line 15), add two fakes. `MemD1` records executed writes so later plans
can assert on them:

```ts
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
```

**Verify**: `pnpm --filter @zeroness/broker typecheck` → exit 0.

### Step 2: Bind the new fakes and declare D1/KV capabilities

Update `makeBroker()` to expose the fakes, and return them so tests can inspect
`writes`. Replace the `makeBroker` function (current lines 18–22) with:

```ts
function makeBroker() {
  const state = { storage: new MemStorage() } as unknown as DurableObjectState;
  const d1 = new MemD1();
  const kv = new MemKV();
  const env = {
    SNAPSHOTS: new MemR2() as unknown as R2Bucket,
    SECRETS: { STRIPE_RO: "sk_test_abc" },
    analytics: d1 as unknown as D1Database,
    cache: kv as unknown as KVNamespace,
  };
  return { broker: new ZeronessBroker(state, env), d1, kv };
}
```

Every current test does `b = makeBroker()`. Update the `beforeEach` so `b` is
the broker and the fakes are reachable. Change the top of the `describe` block
(current lines 28–43) so the shared state includes the fakes:

```ts
describe("broker integration", () => {
  let b: ZeronessBroker;
  let d1: MemD1;
  let kv: MemKV;
  beforeEach(async () => {
    ({ broker: b, d1, kv } = makeBroker());
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
        cacheRw: { kv: "cache", mode: "rw" },
        cacheRo: { kv: "cache", mode: "ro" },
      },
    }));
    expect(res.status).toBe(200);
  });
```

> Note: the `reports` R2 cap still resolves to `SNAPSHOTS` in the current code
> (that is the bug plan 003 fixes). Leave the existing R2 test as-is; do not add
> new R2 assertions in this plan.

**Verify**: `pnpm --filter @zeroness/broker test` → all existing tests still
pass (the harness refactor didn't break them).

### Step 3: Add tests for the correct, currently-working capability paths

Add these `it` blocks inside the `describe`. They pin behavior that plans
002/003 must not regress. Do **not** assert any read-only *bypass* here.

```ts
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
```

**Verify**: `pnpm --filter @zeroness/broker test` → all pass, including the 4
new tests.

## Test plan

- New tests (all in `packages/broker/src/index.test.ts`): accessToken identity
  injection on an allowed request; KV write→read roundtrip; KV read-only write
  blocked (403); D1 read returns rows.
- Structural pattern: model each after the existing
  `"writes then reads a capability by handle"` test (lines 79–84).
- Verification: `pnpm --filter @zeroness/broker test` → all pass, 4 new tests
  added.

## Done criteria

ALL must hold:

- [ ] `pnpm --filter @zeroness/broker typecheck` exits 0
- [ ] `pnpm --filter @zeroness/broker test` exits 0; the 4 new tests exist and pass
- [ ] All pre-existing broker tests still pass
- [ ] `git status --porcelain` shows only `packages/broker/src/index.test.ts` modified
- [ ] `plans/README.md` status row for 001 updated to DONE

## STOP conditions

Stop and report back (do not improvise) if:

- The `capIO`, `makeBroker`, or `beforeEach` code in "Current state" doesn't
  match the live file (drift since this plan was written).
- Any pre-existing test fails after the harness refactor in Step 2 and the cause
  is not obviously your edit.
- The "reads through a D1 capability" test fails — that would mean the D1 read
  path itself is broken, which is unexpected; report it rather than editing
  production code.

## Maintenance notes

- Plan 002 (D1 read-only enforcement) reuses `MemD1` and the `analyticsRo`
  binding added here, and asserts on `d1.writes`. Keep the `MemD1.writes`
  behavior (writes recorded from both `run()` and a write-shaped `all()`).
- Reviewer: confirm no production file changed and that the read-only KV test
  genuinely exercises the 403 path.
