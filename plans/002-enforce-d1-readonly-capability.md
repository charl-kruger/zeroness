# Plan 002: Enforce `mode:"ro"` on D1 capabilities (block writes)

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
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/001-capability-characterization-tests.md (reuses `MemD1` + `analyticsRo` binding)
- **Category**: security
- **Planned at**: commit `8ac83e3`, 2026-08-28

## Why this matters

A D1 capability granted `mode:"ro"` is meant to be read-only — the operator's
mental model is "this untrusted sandbox can query, but not modify, the
database." It is not enforced. In the Broker's `capIO` D1 branch, a write is
only rejected on the `POST` + `.run()` path; a `mode:"ro"` request skips that
guard and falls through to `.all(body.query)`, and D1's `.all()` **executes any
statement**, including `INSERT`/`UPDATE`/`DELETE`/`DROP`. The `GET` path runs
`?query=` through the same `.all()`. So untrusted code holding a "read-only" D1
handle has full write and DDL. This is a capability-scope violation on the
component whose entire job is scoping capabilities.

The fix: for a `mode:"ro"` D1 capability, allow only read-shaped statements and
reject everything else, on every method — before the query reaches D1.

## Current state

- `packages/broker/src/index.ts` — the D1 branch of `capIO` (lines 208–219):

```ts
// packages/broker/src/index.ts:208-219
if ("d1" in binding) {
  const db = this.env[binding.d1] as D1Database | undefined;
  if (!db) return json({ error: `D1 binding '${binding.d1}' not found` }, 501);
  if (method === "POST" && binding.mode !== "ro" && body.query) {
    const r = await db.prepare(body.query).bind(...(body.params ?? [])).run();
    await this.append({ ts: Date.now(), event: "cap:d1:write", detail: { name } });
    return json({ success: r.success, meta: r.meta });
  }
  const r = await db.prepare(body.query ?? "SELECT 1").bind(...(body.params ?? [])).all();
  await this.append({ ts: Date.now(), event: "cap:d1:read", detail: { name } });
  return json({ results: r.results });
}
```

- The bug: when `binding.mode === "ro"`, a `POST` (or `GET`) with a write query
  bypasses the first `if` and executes via `.all()`, which performs the write.
- `body.query` is attacker-controlled (it comes from the sandbox). The `d1`
  capability is *designed* to accept raw SQL — that is the capability. The only
  thing `mode:"ro"` must add is a read/write gate.
- Conventions: pure branch logic, `json(v, status)` helper (defined at line
  314), audit via `this.append(...)`. Match them.
- Plan 001 added a `MemD1` fake (with a `writes: string[]` recorder) and an
  `analyticsRo: { d1: "analytics", mode: "ro" }` capability to the broker test.
  This plan builds on both.

## Commands you will need

| Purpose        | Command                                    | Expected on success       |
|----------------|--------------------------------------------|---------------------------|
| Install        | `pnpm install`                             | exit 0                    |
| Test (broker)  | `pnpm --filter @zeroness/broker test`      | all pass, incl. new tests |
| Typecheck      | `pnpm --filter @zeroness/broker typecheck` | exit 0                    |
| Build (broker) | `pnpm --filter @zeroness/broker build`     | exit 0                    |

## Scope

**In scope**:
- `packages/broker/src/index.ts` (the D1 branch of `capIO` only)
- `packages/broker/src/index.test.ts` (add regression tests)

**Out of scope** (do NOT touch):
- The R2 branch (that is plan 003).
- The KV branch (already enforces read-only correctly).
- `@zeroness/policy` or `@zeroness/core` — the SQL read/write gate lives at the
  enforcement point (the Broker), not in policy authoring.
- Do not attempt a full SQL parser. A conservative allowlist of read-shaped
  statements is the intended approach (see Step 1).

## Git workflow

- Branch: `advisor/002-enforce-d1-readonly-capability`
- Commit message style — conventional commits (e.g.
  `fix(broker): enforce mode:"ro" on D1 capabilities`).
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Add a read-only SQL guard to the D1 branch

Introduce a small helper and use it to reject writes on read-only D1 caps.
A statement is read-shaped only if, after trimming, it begins with `SELECT`,
`WITH` (CTE that ends in a select), `EXPLAIN`, or `PRAGMA` — and contains no
statement separator that could smuggle a second statement.

Add this module-level helper near the other helpers at the bottom of
`packages/broker/src/index.ts` (next to `reorigin`/`applyPath`):

```ts
/** Conservative read-only check for a D1 statement on a mode:"ro" capability. */
function isReadOnlySql(sql: string): boolean {
  const s = sql.trim().replace(/;+\s*$/, ""); // allow a single trailing semicolon
  if (s.includes(";")) return false;           // no multi-statement smuggling
  if (!/^(select|with|explain)\b/i.test(s)) return false; // must be read-shaped (PRAGMA excluded — it can mutate)
  // Belt-and-suspenders: reject any data-mutating keyword anywhere in the statement.
  // Covers WITH-CTE-feeding-a-write (SQLite allows `WITH x AS (...) DELETE ...`) and
  // EXPLAIN <write>. Word-boundaried so identifiers like "order_updates"/"created_at"
  // do NOT false-positive.
  if (/\b(insert|update|delete|replace|drop|alter|create|attach|detach|reindex|vacuum|pragma)\b/i.test(s)) return false;
  return true;
}
```

> Why not just the prefix allowlist: SQLite/D1 permits data-modifying statements
> behind a `WITH` CTE, and `PRAGMA` can mutate (`PRAGMA user_version = 5`). The
> prefix check alone lets both through, so the keyword denylist is required.

Then replace the D1 branch (lines 208–219) with a version that gates writes for
`mode:"ro"` on every method:

```ts
if ("d1" in binding) {
  const db = this.env[binding.d1] as D1Database | undefined;
  if (!db) return json({ error: `D1 binding '${binding.d1}' not found` }, 501);
  const readOnly = binding.mode === "ro";
  if (readOnly) {
    if (body.query && !isReadOnlySql(body.query)) {
      await this.append({ ts: Date.now(), event: "cap:d1:blocked", detail: { name } });
      return json({ error: "read-only capability: only read statements are allowed" }, 403);
    }
    const r = await db.prepare(body.query ?? "SELECT 1").bind(...(body.params ?? [])).all();
    await this.append({ ts: Date.now(), event: "cap:d1:read", detail: { name } });
    return json({ results: r.results });
  }
  if (method === "POST" && body.query) {
    const r = await db.prepare(body.query).bind(...(body.params ?? [])).run();
    await this.append({ ts: Date.now(), event: "cap:d1:write", detail: { name } });
    return json({ success: r.success, meta: r.meta });
  }
  const r = await db.prepare(body.query ?? "SELECT 1").bind(...(body.params ?? [])).all();
  await this.append({ ts: Date.now(), event: "cap:d1:read", detail: { name } });
  return json({ results: r.results });
}
```

**Verify**: `pnpm --filter @zeroness/broker typecheck` → exit 0.

### Step 2: Add regression tests

In `packages/broker/src/index.test.ts`, add tests that exercise the read-only
gate. These rely on the `analyticsRo` cap and `MemD1` (`d1.writes`) added by
plan 001. Also add a read-write D1 cap to prove writes still work when allowed —
add `analyticsRw: { d1: "analytics", mode: "rw" }` to the `beforeEach` session
`resources` (alongside `analyticsRo`).

```ts
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
```

**Verify**: `pnpm --filter @zeroness/broker test` → all pass, including the 4
new tests and the plan-001 D1 read test (still green).

### Step 3: Full build + test

**Verify**:
- `pnpm --filter @zeroness/broker build` → exit 0
- `pnpm --filter @zeroness/broker test` → all pass

## Test plan

- New tests: ro D1 write blocked via POST; via GET; multi-statement smuggling
  blocked; rw D1 write still succeeds. All assert on `d1.writes` so a bypass is
  caught even if the HTTP status is wrong.
- Structural pattern: model after plan 001's D1 read test and the existing
  `"rejects a capability op from a mismatched token"` test.
- Verification: `pnpm --filter @zeroness/broker test` → all pass, 4 new tests.

## Done criteria

ALL must hold:

- [ ] `pnpm --filter @zeroness/broker typecheck` exits 0
- [ ] `pnpm --filter @zeroness/broker build` exits 0
- [ ] `pnpm --filter @zeroness/broker test` exits 0; the 4 new tests pass
- [ ] A `mode:"ro"` D1 cap returns 403 for any non-SELECT/WITH/EXPLAIN/PRAGMA
      statement and never records a write in `d1.writes`
- [ ] `git status --porcelain` shows only the two in-scope files modified
- [ ] `plans/README.md` status row for 002 updated

## STOP conditions

Stop and report if:

- The D1 branch in "Current state" doesn't match the live code (drift).
- Plan 001 has not landed (`MemD1`/`analyticsRo` absent from the test file) —
  this plan depends on it.
- Making the read-only path work requires touching any file outside the
  in-scope list.
- You find an existing caller that legitimately sends non-SELECT queries to a
  `mode:"ro"` D1 cap (there should be none) — report before loosening the guard.

## Maintenance notes

- `isReadOnlySql` is deliberately conservative (rejects anything it can't prove
  is a read). It is a prefix allowlist (`SELECT`/`WITH`/`EXPLAIN`) **plus** a
  word-boundaried mutating-keyword denylist — the denylist is required because
  SQLite allows writes behind a `WITH` CTE and `PRAGMA` can mutate. Known edge:
  a legitimate read whose text contains a write keyword as a standalone token —
  e.g. `SELECT * FROM t WHERE status = 'delete'` (string literal) — is
  fail-closed rejected. That is acceptable for read-only enforcement (a rare
  legit read is denied, never a write allowed). If a future feature needs those,
  parameterize the literal or add an explicit narrow allowance — never relax the
  denylist wholesale.
- The gate is defense at the enforcement point; document in review that policy
  authoring (`@zeroness/policy`) is not where this belongs.
- Reviewer: confirm the `GET` path is gated too, not just `POST`.
