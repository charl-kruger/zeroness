# Plan 009: zeroness × celld integration (spike + phased design)

> Design/spike plan. Spike 0 has been **executed** (results below). Phases 1–3
> are the build-out, scoped from what Spike 0 established.

## Status

- **Priority**: P2 (strategic direction)
- **Effort**: Phase 1 S–M · Phase 2 M (spike) · Phase 3 L (upstream)
- **Risk**: Phase 1 LOW (scoped, spike-validated) · Phase 2/3 HIGH (depends on celld internals / upstream)
- **Depends on**: none (independent of 001–008; builds on the shipped 0.4.0 tree)
- **Category**: direction
- **Planned at**: commit `6eb3aa9` (v0.4.0), 2026-09-01

## Context — what celld is

[`denoland/celld`](https://github.com/denoland/celld) is a **self-hosted,
distributed Cloudflare Workers + Durable Objects runtime** (Rust daemon,
embedded V8; a "cell" = a named SQLite-backed DO). It runs Wrangler bundles in
V8 isolates. It has **no containers, no Python/non-JS workloads**, and **no
documented outbound-fetch interception** (per `docs/cloudflare-compat.md`,
`docs/limitations.md`). Cloudflare-compat is "Partial" across DO storage / R2 /
KV / D1 / Queues / service bindings / outbound fetch / WebCrypto.

zeroness has two halves with opposite celld-fit:

| Half | celld fit |
|---|---|
| Control plane: `@zeroness/broker` (DO) + `@zeroness/egress` (Worker) | ✅ celld's native workload — **portable** |
| Governed workload: `createGovernedSandbox` over `@cloudflare/sandbox` **containers** | ❌ celld has no containers / no egress hook — **not portable** |

So "zeroness on celld" means **self-hosting the control plane** (Mode A), not
running the container network-jail (Mode B, blocked — see Phase 2/3).

## Spike 0 — RESULTS (executed 2026-09-01, celld 0.4.0 via Docker `node:22-bookworm`)

Ran three probes on `celld dev` (probe app: `Probe` SQLite DO + a Worker;
sources archived in the advisor scratchpad). Verbatim outcomes:

| Probe | Result | Meaning for zeroness |
|---|---|---|
| DO per-key write + `storage.list({prefix})` | ✅ `count:5, ordered:true, excludesMeta:true` | **Plan-004 audit storage ports as-is** |
| Cross-isolate DO `stub.fetch()` via `idFromName` | ✅ `crossIsolateFetch:true` | **Egress→Broker binding ports as-is** |
| `crypto.subtle` SHA-256 digest / `getRandomValues` / `randomUUID` | ✅ all true | `sha256Hex`, `mintOpaqueToken`, session ids work |
| `crypto.subtle` **Ed25519** generate/sign/**verify** | ❌ `unsupported verify algorithm: ED25519` | **zeroness's WebCrypto Ed25519 path fails on celld** |
| `node:crypto` Ed25519 (with `nodejs_compat`) generate/sign/verify/tamper-reject/JWK round-trip | ✅ all true | **Confirmed fallback** |

### What Spike 0 concludes

1. **Mode A is viable.** The plumbing (DO storage incl. prefix-list, cross-isolate
   DO fetch, digest, randomness) all works on celld unmodified.
2. **The Ed25519 gap is narrow.** In the Broker, `crypto.subtle` Ed25519 is used
   in exactly **one place** — `mintOidc()` (the `oidc:` capability-identity
   feature, which mints signed JWTs). Everything else — session, authorize
   (allow/deny/ask), capability I/O (R2/D1/KV/queue), approvals, audit, snapshot
   content-addressing — uses **no Ed25519**. So:
   - The Broker + Egress run on celld **today, unmodified**, for every policy that
     does **not** use an `oidc:` identity (`accessToken`/`secret` identities inject
     a Bearer with no crypto).
   - `oidc:` identities need the `node:crypto` fallback.
3. `@zeroness/core` `signing.ts` (command sign/verify) is for the **container
   agent** channel; celld has no agent, so it is out of scope for a celld
   control-plane deployment.

## Phase 1 — Broker + Egress on celld (the deliverable)

**Goal:** `@zeroness/broker` + `@zeroness/egress` run on a self-hosted celld
fleet, so the zeroness control plane needs no Cloudflare account.

### Step 1 — Scope the Ed25519 fallback to `mintOidc`

In `packages/broker/src/index.ts`, `mintOidc()` uses `crypto.subtle`
(`generateKey`/`importKey`/`sign` Ed25519, `exportKey` jwk). Add a crypto
abstraction that prefers `crypto.subtle` and falls back to `node:crypto` when
subtle Ed25519 is unavailable. Recommended shape: a `@zeroness/core` export
`edSign(privateJwk, data)` / `edGenerate()` that:
- tries `crypto.subtle` (works on Cloudflare), and
- falls back to `node:crypto` (`generateKeyPairSync("ed25519")`,
  `sign(null, data, key)`, JWK import/export) when subtle throws/`verify`
  is unsupported.
Detect once and cache. This isolates the only celld-incompatible line to one
module and keeps Cloudflare behavior identical.

**Verify:** unit test the abstraction under both paths; existing broker tests
stay green.

### Step 2 — celld deploy variant

- Add `"compatibility_flags": ["nodejs_compat"]` to the Broker's wrangler config
  (required for the `node:crypto` fallback). Confirmed necessary in Spike 0.
- Provide a `celld deploy`-compatible config (celld reads Wrangler bundles;
  `celld deploy` needs `esbuild` on PATH). Bind R2/KV/D1/Queue by name via celld
  config exactly as on Cloudflare (plan 003 already made R2 resolve by binding
  name — celld-portable).
- Write `docs/DEPLOY-celld.md`: `celld dev` for local, `celld deploy . --bucket
  s3://…` + `celld --bucket …` for a fleet; note the DO-namespace binding for
  Egress→Broker.

### Step 3 — celld compat proof + CI lane

- Stand up the **real** `@zeroness/broker` on `celld dev` (bundle the workspace
  deps) and drive `session → authorize(allow/deny/ask) → cap(R2/KV/D1/queue) →
  approval → audit`, plus one `oidc:` identity to exercise the fallback.
- Add a CI job (or a documented script) that runs the broker integration flow
  against a `celld dev` node, so celld compatibility can't silently drift.

**Done when:** the broker integration flow passes on celld, including an `oidc:`
identity via the fallback, with `nodejs_compat` set.

## Phase 2 — investigate governing celld workloads (Mode B, the hard part)

celld's untrusted workload is a **V8 isolate**, not a container, and there is
**no egress-interception hook**. Two walls:

- **Isolation strength:** `SECURITY.md` assumes the substrate isolates one
  tenant; a self-hosted celld isolate is a weaker boundary than a microVM for
  hostile code. Document this explicitly; do not claim container-grade isolation.
- **Egress enforcement:** the Cloudflare jail (`createGovernedSandbox`:
  `enableInternet=false` + `interceptHttps=true` + static `outbound`) has **no
  celld equivalent**. The strong-enforcement options:
  - **(b2, investigate first)** Can celld run an isolate with **no ambient
    `fetch`**, exposing only zeroness `cap:` bindings? If so, deny-by-default is
    enforced at the binding layer (cleaner than proxy interception). **Spike:
    determine whether celld lets you control an isolate's globals/bindings.**
  - **(b3, fallback, weak)** A cooperative `fetch` shim — bypassable by untrusted
    code, i.e. a convenience, not a jail (same caveat as `HTTP_PROXY` today). Not
    acceptable for untrusted code.

**Deliverable:** a spike answering b2. If yes → design the fetch-less cap-only
isolate model. If no → Phase 3.

## Phase 3 — upstream egress hook in celld (only if Phase 2 fails)

If celld cannot strip an isolate's `fetch`, strong egress governance requires an
**outbound/fetch-intercept hook in celld itself** (Rust + V8; the runtime already
mediates `fetch`). Scope this as an RFC to the celld/Deno maintainers — an
upstream contribution, not an in-repo change.

## Honest framing (for docs/marketing when Phase 1 ships)

- ✅ "zeroness's control plane runs self-hosted on celld" — deliverable after
  Phase 1.
- ❌ "zeroness jails untrusted code on celld like it does on Cloudflare Sandbox" —
  **not** true until Phase 2 (b2) or Phase 3 (b1) lands. Don't claim it.

## Open verification items (lower-risk, confirm during Phase 1)

- DO storage `list` cursor limits at scale (Spike 0 used 5 keys; the audit cap is
  1000 — verify a 1000-key prefix list on celld).
- R2/KV/D1/Queue "Partial" limits vs zeroness's usage (all within caps for the
  current code paths, but re-check when snapshots/large objects are involved).
- Cross-isolate DO `.fetch()` under concurrency (Spike 0 was single-shot).
