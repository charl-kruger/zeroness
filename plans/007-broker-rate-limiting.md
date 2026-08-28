# Plan 007: Per-session rate limiting at the Broker

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report — do not improvise.
> When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: this plan stacks on plan 004. If executing against
> the `advisor/004-o1-audit-append` branch, run
> `git diff --stat <that branch's base>..HEAD -- packages/broker/src packages/egress/src`
> and compare the "Current state" excerpts to the live code; on a mismatch, STOP.
> The `authorize`/`capIO`/egress excerpts below are unchanged by plans 001–004.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/004 (stacks on the broker chain; shares `broker/index.ts`). Can also be built on `main` if 004 is merged first.
- **Category**: security
- **Planned at**: commit `8ac83e3`, 2026-08-28

## Why this matters

`SECURITY.md` names this as the outstanding production gap: "A sandbox can spam
egress/cap ops; add rate limits at the Broker/Egress for production." Today a
hostile (or runaway) sandbox can hammer the `authorize` hot path and capability
I/O without bound — a denial-of-service and a cost amplifier (each authorize is
a DO round-trip; each cap op touches R2/D1/KV). There is no ceiling. This plan
adds a per-session token-bucket limiter at the Broker (the natural place: the
Broker DO is already one instance per session token), returning `429` when a
session exceeds its budget, and maps that to a clean `429` at the Egress Worker.
Limits are env-configurable with generous defaults and can be disabled.

## Current state

- `packages/broker/src/index.ts` — the two sandbox-driven hot paths.
  `authorize` (the egress decision):

```ts
// ---- the hot path: authorize one egress request ----
private async authorize(body: { token: string; url: string; method: string }): Promise<Response> {
  const s = await this.session();
  if (!s || s.sessionToken !== body.token) return json({ error: "unknown session" }, 401);
  const u = new URL(body.url);
  const decision = evaluate(s.policy, { host: u.hostname, method: body.method, path: u.pathname });
  // …deny / ask / allow…
}
```

  and `capIO` (R2/D1/KV):

```ts
private async capIO(method: string, name: string, body: { … }): Promise<Response> {
  const s = await this.session();
  const binding = s?.resources[name] as ResourceBinding | undefined;
  if (!s || !binding) return json({ error: "unknown capability" }, 404);
  // …r2 / d1 / kv…
}
```

- `Env` (broker) has an index signature `[binding: string]: unknown`, so
  `this.env.RATE_LIMIT_RPS` / `RATE_LIMIT_BURST` are already accessible without a
  type change.
- `this.append({ ts, event, detail })` is the audit helper.
- `packages/egress/src/index.ts` — how the egress maps broker authorize status:

```ts
const authRes = await broker.fetch("https://zeroness.broker/authorize", { … });
if (authRes.status === 401) return deny("unknown or revoked session", 403);
const decision = (await authRes.json()) as AuthorizeResult;   // ⚠ parses JSON unconditionally after the 401 check
if (decision.verdict === "deny") return deny(decision.reason, 403);
```

  Note: a `429` from the broker would currently fall through to `.json()` and be
  mis-parsed as an allow (verdict `undefined`). The egress must special-case
  `429` **before** that parse. (The capability path already returns the broker's
  response verbatim — `new Response(res.body, { status: res.status })` — so a
  `429` there propagates without an egress change.)
- Convention for pure, serializable, unit-tested logic: see
  `packages/gatekeeper/src/index.ts` (`ApprovalStore` — a pure class over a
  serializable state, tested in isolation). Model the limiter on it.
- `packages/core/src/index.ts` re-exports public symbols; add the new limiter
  there next to the others.

## Commands you will need

| Purpose        | Command                                    | Expected on success |
|----------------|--------------------------------------------|---------------------|
| Install        | `pnpm install`                             | exit 0              |
| Test (core)    | `pnpm --filter @zeroness/core test`        | all pass            |
| Test (broker)  | `pnpm --filter @zeroness/broker test`      | all pass            |
| Test (egress)  | `pnpm --filter @zeroness/egress test`      | all pass            |
| Typecheck core | `pnpm --filter @zeroness/core typecheck`   | exit 0              |
| Build all      | `pnpm -r build`                            | exit 0              |

## Scope

**In scope**:
- `packages/core/src/rate-limit.ts` (create — the pure `TokenBucket`)
- `packages/core/src/rate-limit.test.ts` (create)
- `packages/core/src/index.ts` (export `TokenBucket`)
- `packages/broker/src/index.ts` (consume a token in `authorize` + `capIO`)
- `packages/broker/src/index.test.ts` (rate-limit regression test)
- `packages/egress/src/index.ts` (map broker `429` → `429`)

**Out of scope** (do NOT touch):
- The `/audit`, `/session`, `/approval`, `/snapshot`, `/command` routes — do NOT
  rate-limit them (they are not the sandbox-driven abuse surface, and `/audit`
  is exercised in bulk by an existing test).
- Persisting the bucket to storage — keep it in-memory (see Maintenance notes).
- The policy engine.

## Git workflow

- Branch: `advisor/007-broker-rate-limiting`
- Commit per package is fine; conventional-commit messages (e.g.
  `feat(core): add TokenBucket`, `feat(broker): rate-limit authorize + cap ops`).
- Do NOT push or open a PR.

## Steps

### Step 1: Create the pure `TokenBucket`

`packages/core/src/rate-limit.ts`:

```ts
/**
 * A pure token-bucket rate limiter. Time is injectable (`now`) so it is fully
 * deterministic under test. Not persisted — the caller owns lifetime.
 */
export interface TokenBucketState {
  tokens: number;
  lastRefillMs: number;
}

export class TokenBucket {
  constructor(
    private readonly capacity: number,
    private readonly refillPerSec: number,
    private state: TokenBucketState = { tokens: capacity, lastRefillMs: Date.now() },
  ) {}

  /** Attempt to spend one token. Returns true if allowed, false if exhausted. */
  tryConsume(now = Date.now()): boolean {
    const elapsedSec = Math.max(0, (now - this.state.lastRefillMs) / 1000);
    this.state.tokens = Math.min(this.capacity, this.state.tokens + elapsedSec * this.refillPerSec);
    this.state.lastRefillMs = now;
    if (this.state.tokens >= 1) {
      this.state.tokens -= 1;
      return true;
    }
    return false;
  }
}
```

Export it from `packages/core/src/index.ts` (add alongside the other exports):

```ts
export { TokenBucket } from "./rate-limit";
export type { TokenBucketState } from "./rate-limit";
```

**Verify**: `pnpm --filter @zeroness/core typecheck` → exit 0.

### Step 2: Unit-test the bucket

`packages/core/src/rate-limit.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { TokenBucket } from "./rate-limit";

describe("TokenBucket", () => {
  it("allows up to the burst capacity, then blocks", () => {
    const b = new TokenBucket(3, 1, { tokens: 3, lastRefillMs: 0 });
    expect(b.tryConsume(0)).toBe(true);
    expect(b.tryConsume(0)).toBe(true);
    expect(b.tryConsume(0)).toBe(true);
    expect(b.tryConsume(0)).toBe(false); // exhausted
  });

  it("refills over time at refillPerSec", () => {
    const b = new TokenBucket(3, 2, { tokens: 0, lastRefillMs: 0 });
    expect(b.tryConsume(0)).toBe(false);      // empty
    expect(b.tryConsume(1000)).toBe(true);    // +2 tokens after 1s, spend 1
    expect(b.tryConsume(1000)).toBe(true);    // spend the 2nd
    expect(b.tryConsume(1000)).toBe(false);   // empty again
  });

  it("never exceeds capacity on refill", () => {
    const b = new TokenBucket(3, 100, { tokens: 3, lastRefillMs: 0 });
    // 10s later, refill would be 1000 tokens but capacity caps at 3
    expect(b.tryConsume(10_000)).toBe(true);
    expect(b.tryConsume(10_000)).toBe(true);
    expect(b.tryConsume(10_000)).toBe(true);
    expect(b.tryConsume(10_000)).toBe(false);
  });
});
```

**Verify**: `pnpm --filter @zeroness/core test` → all pass, incl. these 3.

### Step 3: Consume a token in the Broker hot paths

In `packages/broker/src/index.ts`, import `TokenBucket` and add a lazily-built
per-instance limiter plus a helper. Add the import to the existing
`@zeroness/core` import line, add a field next to `sessionId`, and add the
helper near the other private helpers:

```ts
// import: add TokenBucket to the existing "@zeroness/core" import
import { evaluate, /* …existing… */ mintOpaqueToken, emitAuditLog, TokenBucket } from "@zeroness/core";

// field on the class (next to `private sessionId?: string;`)
private limiter?: TokenBucket;

// helper (near the other private helpers, e.g. below `session()`)
/** Per-session token bucket. Defaults: burst 100, 50/s. Disabled when either is <= 0. */
private rateLimitAllowed(): boolean {
  const rps = Number(this.env.RATE_LIMIT_RPS ?? 50);
  const burst = Number(this.env.RATE_LIMIT_BURST ?? 100);
  if (!(rps > 0) || !(burst > 0)) return true; // explicitly disabled
  if (!this.limiter) this.limiter = new TokenBucket(burst, rps);
  return this.limiter.tryConsume();
}
```

Then gate the two hot paths. In `authorize`, immediately after the session
check:

```ts
private async authorize(body: { token: string; url: string; method: string }): Promise<Response> {
  const s = await this.session();
  if (!s || s.sessionToken !== body.token) return json({ error: "unknown session" }, 401);
  if (!this.rateLimitAllowed()) {
    await this.append({ ts: Date.now(), event: "ratelimit:block", detail: { path: "authorize" } });
    return json({ error: "rate_limited" }, 429);
  }
  // …unchanged…
```

In `capIO`, immediately after the `if (!s || !binding)` guard:

```ts
private async capIO(method: string, name: string, body: { … }): Promise<Response> {
  const s = await this.session();
  const binding = s?.resources[name] as ResourceBinding | undefined;
  if (!s || !binding) return json({ error: "unknown capability" }, 404);
  if (!this.rateLimitAllowed()) {
    await this.append({ ts: Date.now(), event: "ratelimit:block", detail: { path: "cap", name } });
    return json({ error: "rate_limited" }, 429);
  }
  // …unchanged…
```

**Verify**: `pnpm --filter @zeroness/broker typecheck` → exit 0.

### Step 4: Map the broker `429` at the Egress Worker

In `packages/egress/src/index.ts`, add a `429` check right after the existing
`401` check and BEFORE `await authRes.json()`:

```ts
if (authRes.status === 401) return deny("unknown or revoked session", 403);
if (authRes.status === 429) return deny("rate limited", 429);   // ← add
const decision = (await authRes.json()) as AuthorizeResult;
```

(The capability path already returns the broker status verbatim, so no change is
needed there.)

**Verify**: `pnpm --filter @zeroness/egress typecheck` → exit 0.

### Step 5: Broker regression test

In `packages/broker/src/index.test.ts`, add a test that builds a broker with a
tiny burst so blocking is deterministic (do NOT change the shared `makeBroker`
defaults). Construct a dedicated broker inline:

```ts
it("rate-limits authorize once the per-session burst is exhausted", async () => {
  const state = { storage: new MemStorage() } as unknown as DurableObjectState;
  const env = { SNAPSHOTS: new MemR2() as unknown as R2Bucket, SECRETS: {}, RATE_LIMIT_BURST: "2", RATE_LIMIT_RPS: "0.0001" };
  const rb = new ZeronessBroker(state, env);
  await rb.fetch(j("/session", "POST", {
    sessionId: "rl", sessionToken: TOK, pubKey: "x",
    policy: { default: "deny", allow: [{ host: "api.github.com" }] },
    resources: {},
  }));
  const call = () => rb.fetch(j("/authorize", "POST", { token: TOK, url: "https://api.github.com/x", method: "GET" }));
  expect((await call()).status).toBe(200);   // 1st — within burst
  expect((await call()).status).toBe(200);   // 2nd — within burst
  expect((await call()).status).toBe(429);   // 3rd — burst exhausted, refill negligible
});
```

**Verify**: `pnpm --filter @zeroness/broker test` → all pass, incl. this test,
and confirm no pre-existing broker test regressed (the shared `makeBroker` has no
`RATE_LIMIT_*` set, so its default burst of 100 is never hit by the existing
low-volume tests).

### Step 6: Full build + test

**Verify**:
- `pnpm -r build` → exit 0
- `pnpm -r test` → all pass

## Test plan

- `TokenBucket`: burst-then-block, timed refill, capacity cap (3 tests).
- Broker: authorize returns `429` after the burst is spent (1 test).
- Rely on the existing egress tests for the `429` mapping compile path; the
  status special-case is a one-liner verified by typecheck + build.
- Structural patterns: `ApprovalStore` tests for the pure class; the existing
  broker integration tests for the broker test.

## Done criteria

ALL must hold:

- [ ] `pnpm -r build` exits 0
- [ ] `pnpm -r test` exits 0; the 3 `TokenBucket` tests and the broker rate-limit test pass
- [ ] `authorize` and `capIO` each return `429` (JSON `{ error: "rate_limited" }`) once the bucket is empty, and audit a `ratelimit:block` event
- [ ] The egress maps a broker `429` to a `429` before parsing JSON
- [ ] Existing broker/egress/core tests all still pass (no default-limit regressions)
- [ ] `git status --porcelain` shows only the in-scope files (uncommitted `pnpm-lock.yaml` is fine, do NOT commit it)
- [ ] `plans/README.md` status row for 007 updated

## STOP conditions

Stop and report if:

- Any "Current state" excerpt doesn't match the live code (drift).
- Adding the limiter makes an existing broker or egress test fail (the defaults
  should be generous enough that low-volume tests never hit them — if one fails,
  the limit is too tight or applied to the wrong route; report before loosening).
- You find the limiter needs to touch `/audit`, `/command`, or `/session` to
  work — it must not; report instead.

## Maintenance notes

- The bucket is **in-memory per DO instance**. On DO eviction it resets to full
  (fail-open on eviction) — acceptable for a coarse abuse/cost ceiling, and it
  deliberately avoids a per-request storage write (see plan 004's O(1) lesson).
  If a stricter guarantee is needed, back the `TokenBucketState` with
  `state.storage` and a DO alarm for refill — but measure the added storage cost
  first.
- Defaults (burst 100, 50/s per session) are generous; tune via `RATE_LIMIT_RPS`
  / `RATE_LIMIT_BURST` on the Broker Worker, or set either to `0` to disable.
  Document these in `DEPLOY.md` when this lands.
- Reviewer: confirm only `authorize` + `capIO` are gated, the egress `429`
  special-case precedes the `.json()` parse, and the shared `makeBroker` defaults
  were not changed.
