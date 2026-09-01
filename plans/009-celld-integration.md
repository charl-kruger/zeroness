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

## Phase 1 — Broker + Egress on celld (the deliverable) — ✅ DONE (branch `feat/celld-support`)

**Result:** the real `@zeroness/broker` DO runs on `celld dev` and serves the full
`session → authorize(allow/deny) → oidc-identity → audit` flow. `/edbackend`
reports `node` (fallback selected); the `oidc:` identity mints a valid EdDSA JWT
via `node:crypto`; audit uses the plan-004 list storage and celld's `cell_console`
captures every line. Steps below reflect what shipped.

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

## Phase 2 — investigate governing celld workloads (Mode B) — ✅ INVESTIGATED: b2 blocked

**Empirical finding (celld 0.4.0):** an untrusted celld isolate's global `fetch`
reaches the internet freely (`/egress` probe → `reachedInternet:true, status:200,
hasFetch:true`). celld exposes **no egress-restriction mechanism** — the only
network-related controls are `CELLD_MAX_CELL_REQUESTS` (concurrency) and
`CELLD_FETCH_TIMEOUT_S` (timeout). There is no allowlist, no interception, and no
way to disable or redirect an isolate's `fetch` via configuration.

**Conclusion:** the **b2** hypothesis (strip/redirect the isolate's ambient
`fetch` via celld config) is **not achievable on celld as-is**, and **b3** (a
cooperative in-bundle `fetch` shim) is bypassable — a convenience, not a jail. But
b2/b3 were both looking at the **wrong layer**. See Phase 3.

## Phase 3 — govern egress at the network boundary (the Vercel model, no upstream celld change) — ✅ BUILT + PROVEN

**Result:** shipped `@zeroness/egress-proxy` (the authorizing jail proxy) and
`examples/celld-jail` (a fail-closed firewall + proxy reference). Proven in Docker:
allowed host via proxy → 200; denied host → proxy deny; **code ignoring `HTTP_PROXY`
and connecting directly → firewall DROP (http=000)** — the jail holds; internal
metadata → floor 403. No upstream celld change was needed. Design below.

**Key insight from the Vercel Sandbox reconstruction** (`~/dev/vercel-comp/
vercel-sandbox-reconstruction/`): Vercel does **not** intercept `fetch` inside the
guest runtime either. Their egress firewall is **host-side, outside the compute
unit** — the guest gets a `100.64.0.0/16` tap with **no direct route**, and all
egress "leaves through a firewall that SNI-peeks and re-resolves." The per-sandbox
**MITM CA private key stays host-side**; the guest only trusts the cert. And the
**tenant boundary is the microVM, not the container/isolate** — they don't trust
the inner isolation for hostile code.

Applied to celld, this **dissolves the "need an upstream celld hook" conclusion**.
You don't make celld intercept `fetch`; you jail celld's network from **outside
the process**. celld isolates use the host process's network stack, so a host-side
jail captures every isolate's egress with **zero celld changes**. The design:

1. **Boundary = one microVM (or a locked container in its own netns) per untrusted
   tenant — never a shared V8 isolate.** Mirror Vercel: the isolate is not a
   strong enough wall for hostile code; the VM/netns is. `SECURITY.md` already
   says "one tenant per sandbox"; make it "one tenant per jailed celld unit."
2. **Host-side network jail:** the untrusted celld unit runs default-deny egress,
   all outbound forced through the zeroness **Egress Worker** via a transparent
   proxy — Linux netns + `iptables`/`nftables` REDIRECT/TPROXY to a local proxy
   that speaks to the Egress, or the process's `HTTP(S)_PROXY` honored **plus** a
   firewall that fail-closes any non-proxied packet. This is exactly
   `createGovernedSandbox`'s `enableInternet=false` + intercept, rebuilt with OS
   networking instead of a Cloudflare primitive.
3. **Host-side MITM CA for brokered identity:** reuse `@zeroness/tls` — a
   per-tenant CA whose **private key never enters the jail**, cert trusted inside
   it. The Egress injects brokered identity and re-originates; the isolate never
   holds a secret. Same shape as Vercel's `Vercel Network Proxy CA`.
4. **Apply the matcher-hardening from plan 010 at the proxy**, plus the two
   proxy-layer items 010 defers: **`authority == SNI` binding** (Vercel's own
   fronting fix — don't inject a brokered credential unless the inner `:authority`
   equals the SNI-authorized host) and **DNS resolve-and-pin** (re-resolve the
   allowed name and connect to that IP, refusing internal results — defeats
   DNS-rebind, which plan 010's literal floor cannot).

**Deliverable:** a reference "governed celld node" — a container/VM image running
celld with the netns egress jail + a zeroness transparent proxy → Egress + MITM
CA, one tenant per unit. Document it as a "governing untrusted workloads on celld"
section in `docs/DEPLOY-celld.md`. An in-celld `globalOutbound` hook (an upstream
RFC to denoland/celld) remains a *nice-to-have* that would let a single celld node
host multiple governed tenants without per-tenant VMs — but it is **no longer on
the critical path**.

**Security lessons baked in (from breaking Vercel's firewall):** canonicalization
parity (plan 010 #1), the internal-address floor (010 #2) plus resolve-and-pin at
the proxy, `authority == SNI` binding, per-domain credential scoping, and
`redirect: "manual"` (already in the Egress). See `plans/010-egress-matcher-hardening.md`.

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
