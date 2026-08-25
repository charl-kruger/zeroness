# zeroness — a capability & identity mesh for Cloudflare Sandboxes

> **zeroness** — the governed edge between untrusted code inside a sandbox and
> the trusted world outside. Published as `@zeroness/*` (Apache-2.0).

**Thesis.** Cloudflare already has the two halves of the best possible sandbox
platform — a code-execution layer (**Cloudflare Sandbox**) and a capability
governance layer (**Cloudflare OS / Gatekeepers**) — but they live in different
worlds and don't talk. Zeroness is the open-source library that fuses them: it
gives any Cloudflare Sandbox a **programmable egress firewall**, **brokered
short-lived identity (no secrets in the sandbox)**, and **capability-token
resource access**, governed by the same Gatekeeper/human-in-the-loop model. These
are precisely the mechanisms that make Vercel Sandbox differentiated — rebuilt
Cloudflare-native, generalized, and made public.

Zeroness transfers **architecture lessons** (design patterns: capability tokens,
egress mediation, audience-bound token brokering, signed control channels) — not
any code, exploit, or proprietary material. All of these are established,
industry-standard security patterns; the value is assembling them into one
coherent, batteries-included library for Cloudflare.

---

## 1. Landscape (grounded)

### Cloudflare Sandbox — `@cloudflare/sandbox`
- **Runs on** Workers (Paid) + Cloudflare Containers, state in Durable Objects.
- **Compute API**: `getSandbox(env.Sandbox, id)`, `exec(cmd)` (streaming),
  `createCodeContext({language})` + `runCode(code)` (Py/JS interpreter, rich
  output), `writeFile/readFile/mkdir`, `watch(path)`, `terminal(req, dims)`
  (WebSocket), `wsConnect(req, port)`, **preview URLs** for in-sandbox HTTP.
- **Storage**: mount R2/S3/GCS as local FS; DO-backed persistence.
- **Networking**: can "block, allow, and **intercept outbound HTTP**, inject
  headers for credentials." ← a real primitive, but shallow (no policy engine,
  no identity brokering, no per-destination rewriting/audit surfaced in docs).
- **Isolation**: documented only as "isolated container, full Linux." The
  underlying boundary (gVisor? microVM? shared kernel?) is **not stated**.

**Gaps vs. a governed sandbox:** no declarative network policy, no brokered
identity (secrets end up inside the sandbox), no capability-scoped resource
handles, no signed command channel, no human-in-the-loop for risky actions, no
first-class snapshot/fork story.

### Cloudflare OS — `github.com/cloudflare/cloudflare-os` (Apache-2.0)
- An **agent workspace OS**: Kernel = `workshop-backend`, Shell =
  `workshop-frontend`, Processes = **Gadgets** (private apps in **Dynamic Worker
  Facets**), Device Drivers = **Gatekeepers**.
- **Gatekeepers** = capability-based access control: agents/gadgets start at
  **zero permissions**; users introduce resources explicitly; Gatekeepers
  mediate external SaaS (GitHub, Google, Slack, Notion, Supabase, …), do authz +
  logging + **human-in-the-loop** approvals that *simulate asynchronously* rather
  than block.
- Built on Workers/DO/Dynamic Workers/Facets; runs on `workerd`. External
  contributions not currently sought.

**Gaps vs. a code sandbox:** governance is at the **OAuth/SaaS** layer, not the
**network/syscall/code** layer. Gadgets are Worker-runtime code, not arbitrary
untrusted Linux processes. There is no bridge from "an agent typed `curl`/`pip
install`/opened a socket in a real Linux sandbox" to the Gatekeeper capability
model.

### What we learned from reverse-engineering Vercel Sandbox
The six mechanisms that make it differentiated (see `vercel-sandbox-reconstruction/`):
1. **microVM is the boundary; the container is thin** — honest, unambiguous isolation.
2. **Drives = opaque capability tokens** — resources addressed by unguessable,
   control-plane-minted handles never exposed to the guest; isolation by
   capability opacity, not just an ownership check.
3. **Programmable egress firewall** — per-sandbox MITM proxy, SNI/host/path
   policy, transform/forwardURL request rewriting, per-sandbox CA.
4. **OIDC-brokered identity** — audience-bound, short-lived tokens injected on
   egress so the sandbox calls authed upstreams **without ever holding a secret**.
5. **Signed command channel** — ed25519-signed control→agent commands; private
   key never enters the container.
6. **Snapshot/resume** — content-addressed drives to object storage.

---

## 2. The revolutionary idea

> **Turn "isolate the code" into "govern the code's identity, network, and
> resources by capability" — and unify it with Cloudflare OS's Gatekeepers.**

Today a Cloudflare Sandbox is a black box that either can or can't reach the
internet, and whose secrets you smuggle in as env vars. Zeroness makes the
sandbox a **zero-trust process**: it starts with **zero network + zero
credentials**, and every outbound call is mediated by a policy engine and an
identity broker that are the *same* capability substrate Cloudflare OS uses for
agents. The result: you can hand an AI agent a real Linux box, let it run
arbitrary code, and still know — and control, and audit, and get a human to
approve — exactly which hosts it reached and which of *your* credentials (never
exposed to it) were used.

Nobody ships this as an open library. Vercel has it but closed and platform-
locked. Cloudflare has both halves but unconnected. Zeroness is the missing seam.

---

## 3. Vercel insight → Cloudflare-native mechanism (the mapping)

| Vercel mechanism | Zeroness on Cloudflare | Built from |
|---|---|---|
| Per-sandbox MITM egress firewall (SNI/host/path policy, transforms) | **Egress Worker** in front of the sandbox: all outbound HTTP is already interceptable; Zeroness adds a declarative **NetworkPolicy** engine (allow/deny by host+path+method, rewrite, forwardURL). Optional TLS interception via a per-sandbox CA injected into the container trust store. | Workers, the existing "intercept outbound HTTP" hook, `fetch()` |
| OIDC-brokered, audience-bound identity (no secrets in sandbox) | **Identity Broker**: sandbox references an upstream by a **capability handle**; the broker mints/attaches a short-lived, `aud`-bound token at egress time. Backed by Cloudflare **Access service tokens / mTLS / Workers OIDC**, and unified with **Gatekeeper** OAuth for SaaS. | Cloudflare Access, `SignJWT`, Gatekeepers |
| Drives = opaque capability tokens | **Resource capabilities**: R2/D1/KV/Queues/secrets exposed to the sandbox as **opaque handles** (`cap_...`); the real binding/credential lives in the broker DO. The sandbox reads/writes via a local proxy FS/endpoint keyed by the handle — never sees keys. | Durable Objects, R2/D1 bindings, a FUSE/HTTP shim in-container |
| Signed control channel (ed25519) | **Signed command envelope**: the controlling Worker signs each `exec`/`runCode` with a per-session key; an in-sandbox **agent** verifies before running. Detects a compromised control path and enables offline audit. | WebCrypto Ed25519, the sandbox agent |
| microVM-is-the-boundary honesty | **Isolation posture doc + defense-in-depth**: since CF Sandbox's substrate is container-based, Zeroness leans the governance layer harder (egress + identity are the real perimeter) and ships an **attestation/heartbeat** so the control plane can detect a wedged/compromised sandbox. Optionally target stronger substrates as they appear. | policy + attestation |
| Snapshot/resume to object storage | **fork()/snapshot()** helpers: checkpoint sandbox FS state to R2, content-addressed, resume/branch — a clean lifecycle API over the DO-backed sandbox. | R2, DO |
| — (new) Gatekeeper bridge | **Human-in-the-loop egress**: a policy verdict can be `ask` → routes to a Gatekeeper-style async approval (simulate-then-apply), so risky calls from untrusted code get a human gate. | Cloudflare OS Gatekeeper model |

---

## 4. Architecture

```
        ┌──────────────────────────────────────────────────────────────┐
        │  Your Worker (control plane)                                   │
        │    zeroness.sandbox(id, policy)  →  session key (Ed25519)       │
        └───────────────┬──────────────────────────────────────────────┘
                        │ signed commands (exec/runCode/writeFile)
                        ▼
   ┌───────────────────────────────────┐        ┌──────────────────────────┐
   │  Zeroness Broker  (Durable Object)  │◄──────►│  Gatekeepers (CF OS)     │
   │  - NetworkPolicy engine            │  authz │  OAuth · human-in-loop   │
   │  - Identity broker (mint tokens)   │        └──────────────────────────┘
   │  - Capability registry (cap_… → binding)                              │
   │  - Audit log (every egress + resource op)                             │
   └───────────────┬───────────────────────────────────────┬─────────────┘
      capability handles │                    egress verdicts │ + injected identity
                        ▼                                     ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │  Cloudflare Sandbox (Container, full Linux)                            │
   │   ┌──────────────┐   all outbound HTTP ─► Zeroness Egress Worker ───►   │
   │   │ zeronessd      │   (policy check, TLS-MITM opt, token inject, audit)│
   │   │ (in-sandbox   │   resource I/O ─► capability proxy (R2/D1/KV/secret)│
   │   │  agent)       │   verifies signed commands · reports heartbeat     │
   │   └──────────────┘   preview URLs · terminal · watch (pass-through)    │
   └──────────────────────────────────────────────────────────────────────┘
```

**Components (all in the monorepo):**
- `@zeroness/core` — the `ZeronessSandbox` wrapper over `@cloudflare/sandbox`,
  policy types, capability registry, session keys.
- `@zeroness/broker` — the Durable Object: policy engine, identity broker, audit.
- `@zeroness/egress` — the egress Worker (default-deny HTTP proxy, token
  injection, optional per-sandbox CA MITM, forwardURL rewriting).
- `@zeroness/agent` (`zeronessd`) — tiny in-sandbox binary/script: verifies signed
  commands, exposes the capability proxy FS/endpoint, emits heartbeats.
- `@zeroness/gatekeeper` — adapter that maps Zeroness `ask` verdicts and identity
  requests onto Cloudflare OS Gatekeepers.
- `@zeroness/policy` — declarative policy authoring + a local simulator/linter.

---

## 5. The library API (developer surface)

```ts
import { Zeroness } from "@zeroness/core";

const zeroness = new Zeroness(env.SANDBOX, env.AIRLOCK_BROKER);

// zero network, zero credentials by default
const box = await zeroness.sandbox("user-42", {
  network: {
    default: "deny",
    allow: [
      { host: "api.github.com", methods: ["GET"], path: "/repos/**" },
      { host: "pypi.org" }, { host: "*.pythonhosted.org" },  // let pip work
      { host: "api.stripe.com", identity: "cap:stripe-readonly", verdict: "ask" },
    ],
    transform: [
      // rewrite an internal call onto a signed forwardURL, add brokered identity
      { match: { host: "internal.acme" }, forwardURL: "https://gw.acme.com",
        identity: "cap:acme-oidc" },
    ],
  },
  resources: {
    "cap:reports":   { r2: "reports-bucket", mode: "rw", prefix: "u42/" },
    "cap:analytics": { d1: "analytics-db", mode: "ro" },
    "cap:stripe-readonly": { accessToken: "stripe-ro" }, // lives in broker, never in box
  },
  snapshotOn: "shutdown",
});

// identical ergonomics to @cloudflare/sandbox, but signed + governed
await box.exec("pip install pandas && python analyze.py");
const ctx = await box.createCodeContext({ language: "python" });
const out = await box.runCode(ctx, "import requests; requests.get('https://api.github.com/repos/cloudflare/workerd')");

// resources by capability handle — code never sees credentials
await box.writeFile("cap:reports://2026/q3.csv", csv);

// lifecycle
const snap = await box.snapshot();          // → content-addressed R2 ref
const fork = await zeroness.resume(snap);     // branch a new box from it

// audit + control
const trail = await box.audit();             // every egress + resource op, with verdicts
box.on("policy:ask", approveViaGatekeeper);  // human-in-the-loop
```

Design rules: **drop-in** (same shape as `@cloudflare/sandbox`), **secure by
default** (deny network, zero creds), **declarative** (policy is data, lintable &
simulatable offline), **auditable** (every boundary crossing is a logged event).

---

## 6. Security model

- **Default-deny egress.** The container has no route to the internet except
  through the Egress Worker; policy is allow-listed.
- **No secrets in the sandbox.** Credentials live only in the Broker DO; the
  Egress Worker injects short-lived, `aud`-bound tokens at the moment of egress.
  A leaked sandbox FS leaks nothing reusable.
- **Capability opacity.** Resources are `cap:` handles; the sandbox cannot
  enumerate or forge bindings (registry lives in the broker; handles are random
  and per-session).
- **Signed control channel.** Commands are Ed25519-signed per session; `zeronessd`
  refuses unsigned/stale commands (freshness nonce — improving on the Vercel gap
  where the timestamp wasn't freshness-checked).
- **Human-in-the-loop for risky verdicts** via Gatekeepers (async simulate-then-
  apply), so untrusted code can't quietly exfiltrate or spend.
- **Full audit trail** of every egress and resource op, exportable.
- **Honest about the substrate.** We document that CF Sandbox isolation is
  container-based and that Zeroness's perimeter is the *governance* layer; we add
  heartbeat/attestation so a wedged sandbox is detectable, and we recommend one
  tenant per sandbox (Vercel's lesson).

---

## 7. Roadmap (phased, shippable increments)

**Phase 0 — spike (2–3 wks).** `@zeroness/core` wrapper + `@zeroness/egress`
default-deny HTTP proxy with a basic allow-list. Prove: a sandbox with no
network can `pip install` only from an allow-listed host. Public repo + demo.

**Phase 1 — identity broker (3–4 wks).** Capability handles for secrets/tokens;
egress-time injection; `aud`-bound JWTs; Cloudflare Access service-token backend.
Demo: sandbox calls Stripe with zero secrets in the box.

**Phase 2 — resource capabilities (3–4 wks).** `cap:` handles for R2/D1/KV via
the in-sandbox capability proxy; opaque, prefix-scoped. Demo: agent reads/writes
R2 by handle, never sees keys.

**Phase 3 — signed channel + attestation (2–3 wks).** `zeronessd` verifies signed
commands with freshness nonces; heartbeat + audit stream.

**Phase 4 — Gatekeeper bridge + human-in-the-loop (3–4 wks).** `ask` verdicts →
CF OS Gatekeepers; async approve/deny; simulate-then-apply.

**Phase 5 — snapshot/fork + policy simulator (3–4 wks).** `snapshot()/resume()`
to R2; offline policy linter/simulator; TLS-MITM option with per-sandbox CA.

**Phase 6 — hardening & 1.0.** Fuzz the egress parser, threat-model doc, red-team
the capability registry, docs site, `create-zeroness` starter.

---

## 8. Why it's revolutionary / positioning

- **vs. raw Cloudflare Sandbox:** turns a bare execution box into a zero-trust,
  governed, auditable process — the difference between "run this code" and "run
  this code *on behalf of a user, with these exact powers, and prove it.*"
- **vs. Vercel Sandbox:** open-source, portable, and *more* — Zeroness unifies
  network governance with an app-level capability/human-in-the-loop model (via
  Gatekeepers) that Vercel doesn't expose, and closes the signing-freshness gap
  we found in Vercel's own channel.
- **vs. E2B / Modal / Fly:** those isolate; none ship a declarative egress +
  brokered-identity + capability-resource mesh as a library.
- **For the AI-agent era:** this is the safety layer everyone building "let the
  agent run code" needs and nobody has open-sourced. It makes *untrusted* code
  safe to give *trusted* powers — the core unsolved problem.

---

## 9. OSS packaging

- **Monorepo** (`pnpm` workspaces, mirrors CF OS conventions): `packages/core`,
  `broker`, `egress`, `agent`, `gatekeeper`, `policy`, plus `examples/` and
  `create-zeroness`.
- **License:** Apache-2.0 (matches cloudflare-os; friendly to Cloudflare
  upstreaming).
- **Distribution:** npm `@zeroness/*`; one-command `wrangler`-deployable demo;
  docs site; a `wrangler`-native template.
- **Community:** clear threat model + security policy up front; typed policy
  schema; a public policy gallery (github/openai/stripe/internal presets).
- **Upstream path:** designed so Cloudflare could adopt it as the governance
  layer for Sandbox, or wire it into Cloudflare OS as the "code execution device
  driver." Build it so it's *acquirable/upstreamable*, not adversarial.

---

## 10. Honest caveats & open questions

- **CF Sandbox internals are undocumented.** We must verify the exact
  outbound-interception hook and whether we can install a per-sandbox CA / route
  all egress through a Worker. Phase 0 is partly a feasibility probe.
- **TLS-MITM is opt-in and noisy.** Prefer policy-at-L7 via a forward proxy the
  container is configured to use (HTTP_PROXY) over full CA interception where we
  can — less fragile, fewer trust-store games.
- **Gatekeeper coupling.** CF OS isn't seeking external contributions; we
  integrate via its public surface / adapter, we don't fork it.
- **Perf.** Every egress hop adds latency; batch/keep-alive, and make the proxy
  optional per-route.
- **This transfers design patterns, not code.** Nothing here derives from
  Vercel's proprietary implementation — only from the public architectural shape
  and from standard zero-trust patterns.
