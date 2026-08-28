# Plan 005: Make `Zeroness.resume()` functional (wire snapshot restore end-to-end)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If
> anything in "STOP conditions" occurs, stop and report — do not improvise.
> When done, update the status row for this plan in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat 8ac83e3..HEAD -- packages/core/src/zeroness.ts packages/agent/src packages/egress/src`
> If any of these changed since this plan was written, compare the "Current
> state" excerpts against the live code; on a mismatch, STOP.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: none (independent of the broker plans; can run in parallel)
- **Category**: bug
- **Planned at**: commit `8ac83e3`, 2026-08-28

## Why this matters

`Zeroness.resume(snapshotRef)` is documented as "resume/branch a sandbox from a
snapshot ref," but it does not work. It runs `box.exec("zeronessd restore
<ref>")` — a shell command — yet the agent (`zeronessd`) implements **no
`restore` subcommand**: its entrypoint only starts an HTTP server, so
`zeronessd restore …` just starts a second server and ignores the argument. The
call silently does nothing. Worse, it uses the raw `exec` path rather than the
signed command channel every other privileged op uses.

This plan wires restore correctly: a signed `restore` command → the agent
downloads the content-addressed snapshot (via the Egress Worker → Broker) and
untars it into the rootfs — mirroring how `snapshot()` already works in reverse.
It also makes the failure mode honest: `restore()` throws a clear error if the
agent isn't configured, instead of no-oping.

## Current state

- `packages/core/src/zeroness.ts` — the broken `resume`:

```ts
// packages/core/src/zeroness.ts:127-131
async resume(snapshotRef: string, id = crypto.randomUUID()): Promise<ZeronessSandbox> {
  const box = await this.sandbox(id, {});
  await box.exec(`zeronessd restore ${shq(snapshotRef)}`); // agent pulls checkpoint from R2 via broker
  return box;
}
```

- `ZeronessSandbox` already has a `snapshot()` that requires `agentUrl` and
  dispatches a signed command (lines 200–206), and a private `dispatch()`
  (lines 226–242) that signs, records to the Broker, and (when `agentUrl` is
  set) POSTs `{envelope, signature, body}` to `<agentUrl>/command`. Model
  `restore()` on `snapshot()`.
- `packages/agent/src/zeronessd.mjs` — `defaultRunners` (lines 44–75) holds
  `exec`/`writeFile`/`readFile`/`snapshot`. The `snapshot` runner uploads via
  `fetch(`${ctx.egressUrl}/__zeroness/snapshot/upload`, …)`. The command handler
  `handleCommand(ctx, msg)` (lines 78–89) verifies the signature then calls
  `ctx.runners[msg.envelope.procedure]`. `ctx` carries `egressUrl`,
  `sessionToken`, `runners`, `seq`.
- `packages/egress/src/index.ts` — routes control paths to the Broker. It
  handles `POST /__zeroness/snapshot/upload` (lines 52–59) but has **no GET**
  route to download a snapshot. The Broker already serves snapshots at
  `GET /snapshot/<ref>` (`snapshotGet`, broker `index.ts:260-265`, ref shape
  `snap_[0-9a-f]+`).
- `packages/egress/src/lib.ts` — pure request-parsing helpers (`sessionToken`,
  `intendedTarget`, `capName`), each unit-tested in `lib.test.ts`. Add a
  `snapshotRef` helper here and test it the same way.
- Conventions: agent is `.mjs` (plain JS, injectable `runners` for tests, see
  `handler.test.mjs`); egress helpers are pure + unit-tested in `lib.test.ts`;
  core signs via `dispatch`. Match each.

## Commands you will need

| Purpose        | Command                                    | Expected on success |
|----------------|--------------------------------------------|---------------------|
| Install        | `pnpm install`                             | exit 0              |
| Test (agent)   | `pnpm --filter @zeroness/agent test`       | all pass            |
| Test (egress)  | `pnpm --filter @zeroness/egress test`      | all pass            |
| Test (core)    | `pnpm --filter @zeroness/core test`        | all pass            |
| Typecheck core | `pnpm --filter @zeroness/core typecheck`   | exit 0              |
| Typecheck egr. | `pnpm --filter @zeroness/egress typecheck` | exit 0              |
| Build all      | `pnpm -r build`                            | exit 0              |

## Scope

**In scope**:
- `packages/core/src/zeroness.ts` (add `ZeronessSandbox.restore`, rewrite `resume`)
- `packages/core/src/zeroness.test.ts` (create)
- `packages/agent/src/zeronessd.mjs` (add a `restore` runner)
- `packages/agent/src/handler.test.mjs` (add a restore dispatch test)
- `packages/egress/src/lib.ts` (add `snapshotRef` helper)
- `packages/egress/src/lib.test.ts` (test it)
- `packages/egress/src/index.ts` (add the GET snapshot-download route)

**Out of scope** (do NOT touch):
- The Broker (`snapshotGet` already exists and is correct).
- The `snapshot()` upload path — unchanged.
- Actual container tar/restore semantics on live infra — not unit-testable here;
  see Maintenance notes. Do not add integration/e2e infra in this plan.

## Git workflow

- Branch: `advisor/005-wire-snapshot-resume`
- Commit per package is fine; conventional-commit messages (e.g.
  `fix(core): make resume() dispatch a signed restore command`,
  `feat(agent): add restore runner`, `feat(egress): snapshot download route`).
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Egress — add a `snapshotRef` parser + GET download route

In `packages/egress/src/lib.ts`, add (near `capName`):

```ts
const SNAP_PREFIX = "/__zeroness/snapshot/";

/** If this GET request is a snapshot download, return the ref; else null. */
export function snapshotRef(req: Request): string | null {
  try {
    const p = new URL(req.url).pathname;
    if (!p.startsWith(SNAP_PREFIX)) return null;
    const ref = p.slice(SNAP_PREFIX.length);
    return /^snap_[0-9a-f]+$/.test(ref) ? ref : null;   // upload/ and junk excluded
  } catch { return null; }
}
```

In `packages/egress/src/index.ts`, add a GET handler **before** the existing
`POST … /snapshot/upload` block (import `snapshotRef` from `./lib`). It forwards
to the Broker's `GET /snapshot/<ref>` with the session token:

```ts
// ---- snapshot download: stream a content-addressed snapshot from the Broker ----
if (req.method === "GET") {
  const ref = snapshotRef(req);
  if (ref) {
    const res = await broker.fetch(`https://zeroness.broker/snapshot/${ref}`, {
      method: "GET",
      headers: { "x-zeroness-token": token },
    });
    return new Response(res.body, { status: res.status });
  }
}
```

Add tests to `packages/egress/src/lib.test.ts` (import `snapshotRef`):

```ts
it("recognizes a snapshot download path and validates the ref", () => {
  expect(snapshotRef(mk("https://edge.workers.dev/__zeroness/snapshot/snap_abc123"))).toBe("snap_abc123");
  expect(snapshotRef(mk("https://edge.workers.dev/__zeroness/snapshot/upload"))).toBeNull();
  expect(snapshotRef(mk("https://edge.workers.dev/__zeroness/snapshot/../evil"))).toBeNull();
});
```

**Verify**:
- `pnpm --filter @zeroness/egress typecheck` → exit 0
- `pnpm --filter @zeroness/egress test` → all pass, incl. the new test

### Step 2: Agent — add a `restore` runner

In `packages/agent/src/zeronessd.mjs`, add to `defaultRunners` (after
`snapshot`):

```ts
async restore({ ref }, ctx) {
  if (!ctx.egressUrl) throw new Error("restore requires ZERONESS_EGRESS_URL");
  if (!/^snap_[0-9a-f]+$/.test(String(ref ?? ""))) throw new Error("invalid snapshot ref");
  const res = await fetch(`${ctx.egressUrl}/__zeroness/snapshot/${ref}`, {
    headers: { "x-zeroness-session-token": ctx.sessionToken ?? "" },
  });
  if (!res.ok) throw new Error(`restore download failed: ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  await new Promise((resolve, reject) => {
    const tar = spawn("tar", ["xzf", "-", "-C", "/"]);
    tar.on("error", reject);
    tar.on("close", (code) => (code === 0 ? resolve(undefined) : reject(new Error(`tar exit ${code}`))));
    tar.stdin.write(buf);
    tar.stdin.end();
  });
  return { restored: ref };
},
```

Add a handler test to `packages/agent/src/handler.test.mjs` proving a signed
`restore` command dispatches to the runner (inject a fake runner, exactly like
the existing `exec` test uses `ctx.runners`):

```ts
it("dispatches a validly-signed restore command", async () => {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const c = { pub: kp.publicKey, seq: { last: 0 }, runners: { restore: async ({ ref }) => ({ restored: ref }) } };
  const msg = await signed(kp.privateKey, "restore", { ref: "snap_abc" });
  const out = await handleCommand(c, msg);
  expect(out.status).toBe(200);
  expect(out.body.restored).toBe("snap_abc");
});
```

**Verify**: `pnpm --filter @zeroness/agent test` → all pass, incl. the new test.

### Step 3: Core — add `restore()` and rewrite `resume()`

In `packages/core/src/zeroness.ts`, add a `restore` method to `ZeronessSandbox`
(model on `snapshot()`), right after `snapshot()`:

```ts
/**
 * Restore the sandbox FS from a content-addressed snapshot ref. Requires the
 * agent: zeronessd downloads the snapshot via the Egress Worker and untars it.
 */
async restore(ref: string): Promise<unknown> {
  if (!this.config.agentUrl) throw new Error("restore() requires the zeronessd agent — set `agentUrl` in the sandbox config");
  const viaAgent = await this.dispatch("restore", { ref });
  if (!viaAgent) throw new Error("agent restore failed");
  await this.audit("restore", { ref, agent: true });
  return viaAgent;
}
```

Rewrite `Zeroness.resume` (lines 127–131) to accept a config and use the signed
channel instead of a shelled CLI:

```ts
/** Resume/branch a sandbox from a snapshot ref returned by ZeronessSandbox.snapshot(). */
async resume(snapshotRef: string, id = crypto.randomUUID(), config: ZeronessConfig = {}): Promise<ZeronessSandbox> {
  const box = await this.sandbox(id, config);
  await box.restore(snapshotRef);
  return box;
}
```

(`shq` is still used elsewhere in the file — do not remove it.)

**Verify**: `pnpm --filter @zeroness/core typecheck` → exit 0.

### Step 4: Core — test the honest-failure guard and the signed dispatch

Create `packages/core/src/zeroness.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { ZeronessSandbox, type CfSandbox } from "./zeroness";
import { generateSessionKey } from "./signing";

const fakeCf = {} as unknown as CfSandbox;

describe("ZeronessSandbox.restore", () => {
  it("throws a clear error when no agent is configured (no silent no-op)", async () => {
    const box = new ZeronessSandbox("sid", fakeCf, {} as CryptoKey, {}, async () => undefined);
    await expect(box.restore("snap_abc")).rejects.toThrow(/agentUrl/);
  });

  it("dispatches a signed restore command to the agent", async () => {
    const keys = await generateSessionKey();
    const calls: Array<[string, string]> = [];
    const broker = async (m: string, p: string) => { calls.push([m, p]); return undefined; };
    const box = new ZeronessSandbox("sid", fakeCf, keys.privateKey, { agentUrl: "https://agent.example" }, broker);
    const orig = globalThis.fetch;
    globalThis.fetch = (async () => new Response(JSON.stringify({ restored: "snap_abc" }), { status: 200 })) as typeof fetch;
    try {
      const r = await box.restore("snap_abc");
      expect(r).toEqual({ restored: "snap_abc" });
      expect(calls.some(([m, p]) => m === "POST" && p === "/command")).toBe(true); // signed + recorded
    } finally {
      globalThis.fetch = orig;
    }
  });
});
```

**Verify**: `pnpm --filter @zeroness/core test` → all pass, incl. the 2 new tests.

### Step 5: Full build + test

**Verify**:
- `pnpm -r build` → exit 0
- `pnpm -r test` → all pass

## Test plan

- Egress: `snapshotRef` recognizes a valid ref, rejects `upload` and traversal.
- Agent: a signed `restore` command dispatches to the runner (200 + payload).
- Core: `restore()` throws without `agentUrl`; with `agentUrl` it records a
  signed `/command` and returns the agent result.
- Structural patterns: `lib.test.ts` (egress), the `exec` test in
  `handler.test.mjs` (agent), and a new small suite for core.
- Verification: `pnpm -r test` → all pass.

## Done criteria

ALL must hold:

- [ ] `pnpm -r build` exits 0
- [ ] `pnpm -r test` exits 0; the new egress/agent/core tests pass
- [ ] `grep -n "zeronessd restore" packages/core/src/zeroness.ts` returns no
      matches (the shelled non-command is gone)
- [ ] `grep -n "restore" packages/agent/src/zeronessd.mjs` shows the runner
- [ ] `git status --porcelain` shows only the in-scope files modified
- [ ] `plans/README.md` status row for 005 updated

## STOP conditions

Stop and report if:

- Any "Current state" excerpt doesn't match the live code (drift).
- `pnpm -r build` fails in a package you didn't intend to change.
- The egress index has been refactored such that adding the GET route conflicts
  with existing control-path handling — report the shape rather than guessing.
- You conclude the download route needs a Broker change (it should not —
  `snapshotGet` already exists); if it seems to, stop and report.

## Maintenance notes

- The actual tar extraction runs only inside a live Cloudflare Sandbox and is
  **not** unit-tested (same status as the existing `snapshot()` upload). Before
  advertising resume as production-ready, validate it on live infra with
  `scripts/validate.mjs`-style checks and note it in `LIVE-VALIDATION.md`. This
  plan makes the wiring correct and the failure honest; it does not prove the
  container-level restore.
- `restore` extracts to `/`, trusting the snapshot bytes; snapshots are
  content-addressed and produced by the same session's `snapshot()`. If snapshot
  provenance ever widens (e.g. cross-session branch), revisit the trust on the
  tarball before extracting.
- Reviewer: confirm `resume()` now requires `agentUrl` (callers must pass a
  config with it) and that no code path still shells `zeronessd restore`.
