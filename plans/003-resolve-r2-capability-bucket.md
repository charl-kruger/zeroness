# Plan 003: Resolve R2 capabilities to their configured bucket

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report — do not improvise.
> When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 8ac83e3..HEAD -- packages/broker/src`
> If `packages/broker/src/index.ts` changed since this plan was written, compare
> the "Current state" excerpt against the live code; on a mismatch, STOP.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/001-capability-characterization-tests.md (shares the broker test harness); run after plans/002 to avoid conflicts in `index.ts`
- **Category**: security
- **Planned at**: commit `8ac83e3`, 2026-08-28

## Why this matters

An R2 capability is documented as binding to a named bucket:
`{ r2: "reports-bucket", mode: "rw", prefix: "u42/" }` (see `AGENTS.md` §7). The
Broker ignores the bucket name entirely: the R2 branch of `capIO` hardcodes
`const bucket = this.env.SNAPSHOTS`. Consequences:

1. **No bucket isolation between capabilities.** Two different R2 caps
   (`cap:reports` → bucket A, `cap:tenantB` → bucket B) both read/write the same
   physical bucket. Only `prefix` separates them, and a cap with no prefix sees
   everything.
2. **Capability data co-mingles with FS snapshots.** `snapshotUpload` writes to
   `SNAPSHOTS` under `snapshots/…`; cap data lands in the same bucket. A cap with
   a broad or empty prefix can read snapshot objects and vice versa.
3. **Code contradicts the documented contract** — an operator who binds a
   dedicated bucket per tenant does not get it.

The D1 and KV branches already resolve their binding by name via
`this.env[binding.x]`. This plan makes R2 do the same.

## Current state

- `packages/broker/src/index.ts` — the R2 branch of `capIO` (lines 193–206):

```ts
// packages/broker/src/index.ts:193-206
if ("r2" in binding) {
  const bucket = this.env.SNAPSHOTS; // demo maps R2 caps to the snapshots bucket; production binds per-name
  if (!bucket) return json({ error: "r2 binding unavailable" }, 501);
  const key = `${binding.prefix ?? ""}${body.path ?? ""}`;
  if (method === "POST") {
    if (binding.mode === "ro") return json({ error: "read-only capability" }, 403);
    await bucket.put(key, typeof body.data === "string" ? body.data : new Uint8Array(body.data ?? []));
    await this.append({ ts: Date.now(), event: "cap:write", detail: { name, key } });
    return json({ ok: true, key });
  }
  const obj = await bucket.get(key);
  await this.append({ ts: Date.now(), event: "cap:read", detail: { name, key, found: !!obj } });
  return json({ content: obj ? await obj.text() : null });
}
```

- For comparison, the D1/KV branches resolve by name:
  `this.env[binding.d1]` (line 209), `this.env[binding.kv]` (line 222).
- `snapshotUpload` (lines 250–259) uses `this.env.SNAPSHOTS` directly and must
  keep doing so — snapshots are not a capability.
- Plan 001 refactored `makeBroker()` to return `{ broker, d1, kv }` and bind
  `analytics`/`cache`. This plan adds a named R2 fake to that harness.
- The existing R2 test (lines 79–84) uses the `reports` cap with
  `{ r2: "reports", ... }`; after this fix, the test env must bind a `reports`
  R2 bucket or that test will 501.

## Commands you will need

| Purpose        | Command                                    | Expected on success       |
|----------------|--------------------------------------------|---------------------------|
| Install        | `pnpm install`                             | exit 0                    |
| Test (broker)  | `pnpm --filter @zeroness/broker test`      | all pass                  |
| Typecheck      | `pnpm --filter @zeroness/broker typecheck` | exit 0                    |
| Build (broker) | `pnpm --filter @zeroness/broker build`     | exit 0                    |

## Scope

**In scope**:
- `packages/broker/src/index.ts` (the R2 branch of `capIO` only)
- `packages/broker/src/index.test.ts` (bind a named R2 fake; add an isolation test)

**Out of scope** (do NOT touch):
- `snapshotUpload` / `snapshotGet` — they correctly use `this.env.SNAPSHOTS`.
- The D1/KV branches.
- `AGENTS.md` — the doc already describes the correct behavior; this plan makes
  the code match it, no doc change needed.

## Git workflow

- Branch: `advisor/003-resolve-r2-capability-bucket`
- Commit message style — conventional commits (e.g.
  `fix(broker): resolve R2 capabilities to their configured bucket`).
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Resolve the bucket by binding name

Replace the first two lines of the R2 branch (the `const bucket = …` and its
guard) with a by-name resolution that mirrors D1/KV:

```ts
if ("r2" in binding) {
  const bucket = this.env[binding.r2] as R2Bucket | undefined;
  if (!bucket) return json({ error: `R2 binding '${binding.r2}' not found` }, 501);
  const key = `${binding.prefix ?? ""}${body.path ?? ""}`;
  // …rest of the branch unchanged…
```

Leave the rest of the branch (key construction, `mode:"ro"` POST guard, put/get,
audit) exactly as-is.

**Verify**: `pnpm --filter @zeroness/broker typecheck` → exit 0.

### Step 2: Bind a named R2 fake in the test harness

In `packages/broker/src/index.test.ts`, update `makeBroker()` (as refactored by
plan 001) to add a `reports` R2 bucket and return it:

```ts
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
```

Update the `describe`-level destructure and `beforeEach` to also capture
`reports` (mirroring how `d1`/`kv` are captured):

```ts
  let reports: MemR2;
  beforeEach(async () => {
    ({ broker: b, d1, kv, reports } = makeBroker());
    // …session registration unchanged…
```

**Verify**: `pnpm --filter @zeroness/broker test` → the existing
`"writes then reads a capability by handle"` R2 test passes again (it now hits
the `reports` bucket, not `SNAPSHOTS`).

### Step 3: Add an isolation regression test

Add a test proving R2 cap data lands in the configured bucket and is isolated
from snapshots. Register a second session with a second R2 cap pointing at a
different bucket, and assert writes don't cross. Simplest form — assert the
`reports` cap writes to the `reports` fake and **not** to `SNAPSHOTS`:

```ts
it("writes R2 capability data to its configured bucket, not the snapshots bucket", async () => {
  await b.fetch(j("/cap/reports", "POST", { path: "q3.csv", data: "hello" }, { "x-zeroness-token": TOK }));
  expect(reports.m.has("u/q3.csv")).toBe(true);      // landed in the reports bucket, with prefix
  // and did NOT leak into the snapshots bucket
  const snapKeys = [...(reports.m.keys())].filter((k) => k.startsWith("snapshots/"));
  expect(snapKeys).toEqual([]);
});
```

**Verify**: `pnpm --filter @zeroness/broker test` → all pass, including the new
test.

### Step 4: Full build + test

**Verify**:
- `pnpm --filter @zeroness/broker build` → exit 0
- `pnpm --filter @zeroness/broker test` → all pass

## Test plan

- New test: R2 cap write lands in the configured (`reports`) bucket under its
  prefix, and not in the snapshots bucket.
- Adjusted harness: the existing R2 roundtrip test now exercises a real named
  bucket resolution instead of the SNAPSHOTS fallback.
- Structural pattern: existing `"writes then reads a capability by handle"`
  test.
- Verification: `pnpm --filter @zeroness/broker test` → all pass.

## Done criteria

ALL must hold:

- [ ] `pnpm --filter @zeroness/broker typecheck` exits 0
- [ ] `pnpm --filter @zeroness/broker build` exits 0
- [ ] `pnpm --filter @zeroness/broker test` exits 0; the new isolation test passes
- [ ] `grep -n "this.env.SNAPSHOTS" packages/broker/src/index.ts` shows matches
      only inside `snapshotUpload`/`snapshotGet`, not in the R2 capability branch
- [ ] `git status --porcelain` shows only the two in-scope files modified
- [ ] `plans/README.md` status row for 003 updated

## STOP conditions

Stop and report if:

- The R2 branch in "Current state" doesn't match the live code (drift), or plan
  002 hasn't landed (this plan expects the plan-001/002 test harness shape).
- The existing R2 roundtrip test fails in a way the named-bucket binding doesn't
  explain.
- You discover another code path (outside `snapshotUpload`) that intentionally
  relies on all R2 caps sharing `SNAPSHOTS` — report before changing behavior.

## Maintenance notes

- After this change, every R2 capability requires its named bucket to be bound
  on the Broker Worker's `env` (wrangler `[[r2_buckets]]`). Ensure `DEPLOY.md`
  reflects that operators bind one R2 binding per R2 cap name; flag in review if
  deployment docs imply the old single-bucket behavior.
- The same by-name resolution pattern now holds for R2/D1/KV — keep them
  consistent if a new resource type is added.
- Reviewer: confirm snapshots still use `SNAPSHOTS` and that prefix scoping is
  unchanged.
