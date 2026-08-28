# Plan 008: Wire the queue capability (send-only producer)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report — do not improvise.
> When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: this plan stacks on the broker chain (tip: plan
> 007). Compare the "Current state" excerpts to the live code before editing; on
> a mismatch, STOP. The queue placeholder and `capIO` signature below are
> unchanged by plans 001–007.

## Status

- **Priority**: P3
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/007 (stacks on the broker chain; shares `broker/index.ts`)
- **Category**: direction
- **Planned at**: commit `8ac83e3`, 2026-08-28

## Why this matters

`ResourceBinding` declares a `{ queue: string }` variant (`capabilities.ts:15`),
and `AGENTS.md` lists `{queue}` among the resource types — but the Broker's
`capIO` returns `501 "capability type not yet wired (queue)"`. The type
over-promises: an operator can declare a queue capability that silently 501s at
use. Every other resource type (R2/D1/KV) resolves its binding by name and
performs I/O. This plan finishes the queue variant as a **send-only producer**
(Cloudflare Queues producer bindings expose `send()`; there is no read side — a
consumer is a separate Worker), so the declared surface becomes real.

## Current state

- `packages/broker/src/index.ts` — `capIO` dispatches on binding type; the queue
  case is the final unhandled fallthrough:

```ts
private async capIO(method: string, name: string, body: { path?: string; data?: number[] | string; query?: string; params?: unknown[] }): Promise<Response> {
  const s = await this.session();
  const binding = s?.resources[name] as ResourceBinding | undefined;
  if (!s || !binding) return json({ error: "unknown capability" }, 404);
  // …(rate-limit gate from plan 007)…
  // …r2 branch… d1 branch… kv branch…
  return json({ error: "capability type not yet wired (queue)" }, 501);   // ← this line
}
```

  For reference, the KV branch (the closest shape) resolves by name and writes:

```ts
if ("kv" in binding) {
  const ns = this.env[binding.kv] as KVNamespace | undefined;
  if (!ns) return json({ error: `KV binding '${binding.kv}' not found` }, 501);
  const key = `${binding.prefix ?? ""}${body.path ?? ""}`;
  if (method === "POST") { …await ns.put(key, …)… }
  …await ns.get(key)…
}
```

- `binding.queue` is a string (the Queue binding name on the Broker `env`).
- The sandbox reaches a cap via `writeFile("cap:<name>://", data)` → `POST /cap/<name>` with `{ path, data }` (see `zeroness.ts` `capIO`); `data` is `string | number[]`. For a queue, `data` is the message body.
- `Env` has `[binding: string]: unknown`, so `this.env[binding.queue]` resolves
  without a type change. Cloudflare's `Queue` type comes from
  `@cloudflare/workers-types` (already a dev dependency).
- Audit via `this.append({ ts, event, detail })`.
- Test conventions: in-process fakes typed `as unknown as <CfType>`, added to
  `makeBroker()`; one behavior per `it`. See the KV/D1/R2 tests added by plans
  001–003.

## Commands you will need

| Purpose        | Command                                    | Expected on success |
|----------------|--------------------------------------------|---------------------|
| Install        | `pnpm install`                             | exit 0              |
| Test (broker)  | `pnpm --filter @zeroness/broker test`      | all pass            |
| Typecheck      | `pnpm --filter @zeroness/broker typecheck` | exit 0              |
| Build (broker) | `pnpm --filter @zeroness/broker build`     | exit 0              |

## Scope

**In scope**:
- `packages/broker/src/index.ts` (replace the queue fallthrough with a real branch)
- `packages/broker/src/index.test.ts` (bind a `MemQueue` fake; add tests)

**Out of scope** (do NOT touch):
- `packages/core/src/capabilities.ts` — the `{ queue: string }` type is already
  correct; no change.
- The R2/D1/KV branches.
- Consumer-side queue handling — out of scope; this is the producer (send) side
  only.
- `AGENTS.md` — already lists `{queue}`; no doc change needed.

## Git workflow

- Branch: `advisor/008-wire-queue-capability`
- Commit message style — conventional commits (e.g.
  `feat(broker): wire the queue capability (send-only)`).
- Do NOT push or open a PR.

## Steps

### Step 1: Implement the queue branch

In `packages/broker/src/index.ts`, replace the final fallthrough line
(`return json({ error: "capability type not yet wired (queue)" }, 501);`) with a
real branch. A queue capability is send-only: `POST` sends the message body;
any other method is rejected.

```ts
if ("queue" in binding) {
  const q = this.env[binding.queue] as Queue | undefined;
  if (!q) return json({ error: `Queue binding '${binding.queue}' not found` }, 501);
  if (method !== "POST") return json({ error: "queue capability is send-only (use POST)" }, 405);
  await q.send(body.data ?? null);
  await this.append({ ts: Date.now(), event: "cap:queue:send", detail: { name } });
  return json({ ok: true });
}

return json({ error: "unknown capability type" }, 501);
```

(Keep a final `return` for any future unhandled binding type, as shown.)

**Verify**: `pnpm --filter @zeroness/broker typecheck` → exit 0.

### Step 2: Bind a `MemQueue` fake and declare a queue capability

In `packages/broker/src/index.test.ts`, add a `MemQueue` fake next to the other
`Mem*` fakes:

```ts
class MemQueue {
  sent: unknown[] = [];
  async send(m: unknown) { this.sent.push(m); }
}
```

Wire it into `makeBroker()` and return it (mirror how `d1`/`kv`/`reports` are
bound and returned by the earlier plans):

```ts
const events = new MemQueue();
const env = {
  // …existing bindings…
  events: events as unknown as Queue,
};
return { broker: new ZeronessBroker(state, env), d1, kv, reports, events };
```

Capture `events` in the `describe`-level destructure and `beforeEach` (mirror
`reports`), and add a queue capability to the session `resources`:

```ts
resources: {
  // …existing…
  eventsCap: { queue: "events" },
},
```

**Verify**: `pnpm --filter @zeroness/broker test` → existing tests still pass.

### Step 3: Add tests

```ts
it("sends a message through a queue capability", async () => {
  const res = await b.fetch(j("/cap/eventsCap", "POST", { data: "hello-queue" }, { "x-zeroness-token": TOK }));
  expect((await res.json()).ok).toBe(true);
  expect(events.sent).toEqual(["hello-queue"]);
});

it("rejects a non-POST on a queue capability (send-only)", async () => {
  const res = await b.fetch(req("/cap/eventsCap?path=x", { method: "GET", headers: { "x-zeroness-token": TOK } }));
  expect(res.status).toBe(405);
  expect(events.sent).toEqual([]);
});
```

**Verify**: `pnpm --filter @zeroness/broker test` → all pass, incl. these 2.

### Step 4: Full build + test

**Verify**:
- `pnpm --filter @zeroness/broker build` → exit 0
- `pnpm --filter @zeroness/broker test` → all pass

## Test plan

- Queue send: `POST` puts the message on the queue fake (`events.sent`).
- Send-only: a non-POST returns `405` and sends nothing.
- Structural pattern: the KV/R2 capability tests from plans 001/003.
- Verification: `pnpm --filter @zeroness/broker test` → all pass, 2 new tests.

## Done criteria

ALL must hold:

- [ ] `pnpm --filter @zeroness/broker typecheck` exits 0
- [ ] `pnpm --filter @zeroness/broker build` exits 0
- [ ] `pnpm --filter @zeroness/broker test` exits 0; the 2 new tests pass
- [ ] `grep -n "not yet wired" packages/broker/src/index.ts` returns no matches
- [ ] A queue cap `POST` sends the message and audits `cap:queue:send`; a non-POST returns `405`
- [ ] `git status --porcelain` shows only the two in-scope files (uncommitted `pnpm-lock.yaml` is fine, do NOT commit it)
- [ ] `plans/README.md` status row for 008 updated

## STOP conditions

Stop and report if:

- The queue placeholder or `capIO` signature in "Current state" doesn't match the
  live code (drift).
- `Queue` is not resolvable as a type (it should come from
  `@cloudflare/workers-types`); if typecheck complains it's undefined, report
  rather than inventing a local type.

## Maintenance notes

- This wires the **producer** (send) side only; consuming messages is a separate
  Worker's job and intentionally out of scope. If a batch-send or delay option is
  later wanted, extend the branch to pass `q.send(body.data, { … })` options.
- `body.data` is sent as-is (string or byte array). If structured JSON messages
  become the norm, consider parsing/validating here.
- Reviewer: confirm the queue cap is send-only (non-POST → 405) and that the
  `501` placeholder is gone.
