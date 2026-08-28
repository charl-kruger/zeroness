# Plan 004: Make audit append O(1) instead of O(n) per crossing

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report — do not improvise.
> When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 8ac83e3..HEAD -- packages/broker/src`
> If `packages/broker/src/index.ts` changed since this plan was written, compare
> the "Current state" excerpt against the live code; on a mismatch, STOP.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/001-capability-characterization-tests.md (audit test as safety net); run after plans/003 to avoid conflicts in `index.ts`
- **Category**: perf
- **Planned at**: commit `8ac83e3`, 2026-08-28

## Why this matters

Every governed crossing — each egress authorize, each capability op, each
command, each approval — calls `this.append(...)`, which reads the **entire**
audit array out of Durable Object storage, pushes one entry, and writes the
whole array back (`slice(-1000)`). That is an O(n) read + O(n) serialize +
O(n) write on the single hottest path in the system, where n grows to 1000.
Under load, a busy session pays a full 1000-entry structured-clone read and
write on every request it makes. This turns a constant-time audit into a cost
that scales with how much has already happened in the session.

The fix: store each audit entry under its own key and keep a tiny counter, so
append is a constant number of small writes regardless of log size. The
`/audit` read API keeps returning the same chronological array.

## Current state

- `packages/broker/src/index.ts` — audit append and read:

```ts
// packages/broker/src/index.ts:185 (read)
private async getAudit(): Promise<AuditEntry[]> { return (await this.state.storage.get<AuditEntry[]>("audit")) ?? []; }

// packages/broker/src/index.ts:274-282 (append — the hot path)
private async append(e: AuditEntry): Promise<void> {
  const log = (await this.state.storage.get<AuditEntry[]>("audit")) ?? [];
  log.push(e); await this.state.storage.put("audit", log.slice(-1000));
  // Also emit a compact structured line so Cloudflare Workers Logs captures it …
  if (this.sessionId === undefined) this.sessionId = (await this.session())?.sessionId;
  emitAuditLog({ event: e.event, ts: e.ts, sessionId: this.sessionId, detail: e.detail });
}
```

- `AuditEntry` is `{ ts: number; event: string; detail: unknown }` (line 33).
- `emitAuditLog` (from `@zeroness/core`) must stay exactly as-is — it is the
  Workers Logs / Logpush integration.
- The `/audit` GET returns `getAudit()` as a JSON array (line 51), and the
  existing test `"records an audit trail of decisions"` (test file lines 99–106)
  asserts the returned array's `event` values. That contract must not change.
- The test's `MemStorage` fake (test file lines 5–10) implements only
  `get`/`put`/`delete`. This plan adds a `list` method to it, matching the DO
  storage `list({ prefix })` API.

## Commands you will need

| Purpose        | Command                                    | Expected on success       |
|----------------|--------------------------------------------|---------------------------|
| Install        | `pnpm install`                             | exit 0                    |
| Test (broker)  | `pnpm --filter @zeroness/broker test`      | all pass                  |
| Typecheck      | `pnpm --filter @zeroness/broker typecheck` | exit 0                    |
| Build (broker) | `pnpm --filter @zeroness/broker build`     | exit 0                    |

## Scope

**In scope**:
- `packages/broker/src/index.ts` (`append`, `getAudit`, and a small helper)
- `packages/broker/src/index.test.ts` (extend `MemStorage` with `list`; add a
  bounded-log test)

**Out of scope** (do NOT touch):
- `emitAuditLog` / `packages/core/src/audit-log.ts` — unchanged.
- The `/audit` GET/POST route handlers' external contract (still an array).
- Migration of pre-existing `"audit"` arrays in already-deployed sessions — see
  Maintenance notes; do not attempt a data migration in this plan.

## Git workflow

- Branch: `advisor/004-o1-audit-append`
- Commit message style — conventional commits (e.g.
  `perf(broker): store audit entries per-key for O(1) append`).
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Switch storage layout to per-entry keys with a counter

Entries live under keys `audit:<zero-padded-seq>` (lexicographically sortable =
chronological). A separate `auditMeta` key (note: **no colon**, so it is not
caught by the `audit:` prefix) holds `{ next, oldest }`. Add a constant and
rewrite `append` and `getAudit`:

```ts
const AUDIT_MAX = 1000;
const auditKey = (seq: number) => `audit:${String(seq).padStart(12, "0")}`;
```

```ts
private async getAudit(): Promise<AuditEntry[]> {
  const map = await this.state.storage.list<AuditEntry>({ prefix: "audit:" });
  return [...map.values()];
}

private async append(e: AuditEntry): Promise<void> {
  const meta = (await this.state.storage.get<{ next: number; oldest: number }>("auditMeta")) ?? { next: 0, oldest: 0 };
  await this.state.storage.put(auditKey(meta.next), e);
  meta.next++;
  // Trim the oldest entry once we exceed the cap — keeps the working set bounded.
  if (meta.next - meta.oldest > AUDIT_MAX) {
    await this.state.storage.delete(auditKey(meta.oldest));
    meta.oldest++;
  }
  await this.state.storage.put("auditMeta", meta);
  if (this.sessionId === undefined) this.sessionId = (await this.session())?.sessionId;
  emitAuditLog({ event: e.event, ts: e.ts, sessionId: this.sessionId, detail: e.detail });
}
```

Place `AUDIT_MAX`/`auditKey` near the other module-level helpers at the bottom
of the file (with `reorigin`/`applyPath`), or as `private static` members — match
the file's existing style (free functions at module scope).

**Verify**: `pnpm --filter @zeroness/broker typecheck` → exit 0.

### Step 2: Add `list` to the test `MemStorage` fake

The DO `storage.list({ prefix })` returns a `Map<string, T>` sorted by key
ascending. Add this method to `MemStorage` in `packages/broker/src/index.test.ts`
(after its `delete` method):

```ts
async list<T>(opts: { prefix?: string; limit?: number; reverse?: boolean } = {}): Promise<Map<string, T>> {
  let keys = [...this.m.keys()].filter((k) => !opts.prefix || k.startsWith(opts.prefix)).sort();
  if (opts.reverse) keys.reverse();
  if (opts.limit) keys = keys.slice(0, opts.limit);
  const out = new Map<string, T>();
  for (const k of keys) out.set(k, JSON.parse(JSON.stringify(this.m.get(k))) as T);
  return out;
}
```

**Verify**: `pnpm --filter @zeroness/broker test` → the existing
`"records an audit trail of decisions"` test still passes (order + contents
unchanged).

### Step 3: Add a bounded-log regression test

Prove the log stays chronological and bounded at `AUDIT_MAX`. Use the public
`POST /audit` endpoint (no network, in-memory fakes, fast):

```ts
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
```

(Note: the `beforeEach` session-create adds one `session:create` audit entry, so
filter to `event === "tick"` to isolate this test's appends.)

**Verify**: `pnpm --filter @zeroness/broker test` → all pass, including the new
test.

### Step 4: Full build + test

**Verify**:
- `pnpm --filter @zeroness/broker build` → exit 0
- `pnpm --filter @zeroness/broker test` → all pass

## Test plan

- New test: 1005 appends → exactly 1000 retained, oldest-5 dropped, order
  preserved, newest present.
- Unchanged: the existing audit-trail test still passes (proves the `/audit`
  read contract is intact).
- Structural pattern: existing `"records an audit trail of decisions"` test.
- Verification: `pnpm --filter @zeroness/broker test` → all pass.

## Done criteria

ALL must hold:

- [ ] `pnpm --filter @zeroness/broker typecheck` exits 0
- [ ] `pnpm --filter @zeroness/broker build` exits 0
- [ ] `pnpm --filter @zeroness/broker test` exits 0; the bounded-log test passes
- [ ] `append` performs a constant number of storage ops (no full-array
      read/write) — confirm by reading the final `append` body
- [ ] `grep -n '"audit"' packages/broker/src/index.ts` returns no matches (the
      old single-array key is gone)
- [ ] `git status --porcelain` shows only the two in-scope files modified
- [ ] `plans/README.md` status row for 004 updated

## STOP conditions

Stop and report if:

- The `append`/`getAudit` code in "Current state" doesn't match the live file
  (drift).
- The existing audit-trail test fails after Step 1/2 for a reason other than an
  obvious typo in your edit.
- You find another reader of the `"audit"` storage key elsewhere in the codebase
  (`grep -rn '"audit"' packages/`) that this plan doesn't account for.

## Maintenance notes

- Already-deployed sessions have their history in the old `"audit"` array key;
  after this change it is simply ignored (not shown by `/audit`). For a pre-1.0
  library that is acceptable — note it in the PR. If backward visibility is
  wanted, a one-time `getAudit` fallback that also reads the legacy `"audit"`
  array can be added, but that is deliberately out of scope here.
- DO `list()` cost is O(returned keys); `getAudit` is a cold path (explicit
  `audit()` reads), so its O(n) is fine — the point is that `append` (the hot
  path) is now O(1).
- Reviewer: confirm the `auditMeta` key has no colon (so it isn't returned by
  the `audit:` prefix list) and that the trim keeps exactly `AUDIT_MAX` entries.
