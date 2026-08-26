# Operating zeroness

Precise, imperative guidance for an AI agent writing code **with** zeroness (and
for working **in** this repo). Read this top to bottom before generating code
that governs a sandbox. Human docs: [`README.md`](./README.md),
[`docs/`](./docs/). Every claim here matches the shipped API (v0.1.x).

---

## 1. What zeroness is (and the one rule)

zeroness wraps a **Cloudflare Sandbox** so untrusted code runs with **zero
network and zero credentials by default**. You then *grant* exactly what the code
needs: specific hosts (network policy), specific resources (capability handles),
and specific identities (brokered, injected at egress). Every boundary crossing
is audited.

**The one rule you must preserve:** never hand a secret to the sandbox. Give it a
`cap:` handle or an `identity` on a policy rule instead. If you find yourself
putting an API key in `exec`, an env var, or a file the code reads, stop; use a
capability.

## 2. When to use it

Use zeroness when running **untrusted or AI-generated code** that must reach a
*specific* external API or resource. If the code is fully trusted and needs the
open internet, you don't need zeroness. If it needs *some* network or *some*
credential but not all, that is exactly the case zeroness exists for.

## 3. The model (know these five nouns)

- **Session**: one governed sandbox. Created by `zeroness.sandbox(id, config)`.
  Carries a per-session Ed25519 signing key and an opaque session token.
- **Policy**: declarative `NetworkPolicy` deciding egress: `allow` / `deny` /
  `ask` per host + path + method.
- **Capability**: an opaque handle (`cap:reports`) the code uses to touch a
  resource (R2/D1/KV/secret/OIDC). The real binding + credential live only in the
  Broker.
- **Brokered identity**: a short-lived, audience-bound token the Egress Worker
  injects into an outbound request at the moment it leaves. The code never sees
  it.
- **Approval**: an `ask` verdict creates a pending approval; a human/system
  approves; the retry then passes (grant is scoped to that method+URL for a TTL).

Data plane: your Worker → **Broker** (Durable Object, trust root, holds secrets)
→ **Egress Worker** (enforces + injects) → internet. Inside the sandbox,
**`zeronessd`** verifies signed commands and proxies capability I/O.

## 4. Setup you must ensure exists

Three deployables. If the two Workers below are not deployed, nothing is
governed.

1. **Broker** (`@zeroness/broker`), the `ZeronessBroker` Durable Object.
2. **Egress Worker** (`@zeroness/egress`), bound to the Broker DO.
3. **Your Worker**: uses `@zeroness/core` + `@cloudflare/sandbox`.

Deploy steps: [`DEPLOY.md`](./DEPLOY.md). Do not tell a user the network policy
protects them until the Egress Worker is deployed and the sandbox egress is
actually routed through it.

## 5. The API you call

```ts
import { getSandbox } from "@cloudflare/sandbox";
import { Zeroness } from "@zeroness/core";

const zeroness = new Zeroness({
  sandboxBinding: env.Sandbox,     // @cloudflare/sandbox DO binding
  broker: env.ZERONESS_BROKER,     // ZeronessBroker DO binding
  egressUrl: env.EGRESS_URL,       // public URL of the Egress Worker
  getSandbox,                       // pass the SDK function (no hard dep in core)
});

const box = await zeroness.sandbox(userId, config); // ZeronessSandbox
```

**`ZeronessSandbox` methods** (all signed + audited):

| Method | Semantics |
|--------|-----------|
| `exec(command, opts?)` | run a shell command → `{ stdout, stderr?, exitCode, success }` |
| `createCodeContext({ language })` | make a Py/JS code context (SDK passthrough) |
| `runCode(ctxOrCode, codeOrOpts?)` | run code in the SDK interpreter |
| `writeFile(path, data, opts?)` | write a file. `cap:name://p` routes to the capability proxy |
| `readFile(path, opts?)` | read a file. `cap:name://p` routes to the capability proxy |
| `snapshot()` | checkpoint FS → R2, returns a content-addressed ref (**requires `agentUrl`**) |
| `audit()` | returns the full audit trail (array of `{ ts, event, detail }`) |
| `destroy()` | revoke the session (tokens stop working); snapshots first if `snapshotOn:"shutdown"` |

Always `await box.destroy()` in a `finally`. It revokes the session at the edge.

## 6. Authoring a NetworkPolicy (exact semantics)

```ts
network: {
  default: "deny",                 // ALWAYS start here for untrusted code
  deny?:  Rule[],                  // hard denials, evaluated FIRST, always win
  allow?: Rule[],                  // first match wins; carries verdict/identity/forwardURL
  transform?: Rule[],              // layered onto an allowed request (add identity/rewrite)
}
```

`Rule` = `{ host, methods?, path?, verdict?, identity?, forwardURL?, rewrite? }`.

**Matching rules (do not get these wrong):**
- `host`: exact (`api.github.com`), wildcard (`*.pythonhosted.org` = one-or-more
  subdomain labels, does **not** match the apex), or `*` (any host, avoid).
- `path`: glob. `*` matches within one segment; `**` spans segments.
  `"/repos/**"` matches `/repos/a/b`; it does **not** match `/users/x`.
- `methods`: array; omit = all methods.
- Evaluation order: **deny → first allow → default**. Transforms apply only to an
  already-allowed/ask request and never loosen the verdict.

**`verdict`:** `"allow"` (default in `allow[]`), `"deny"`, or `"ask"` (human gate).
**`identity`:** a `cap:` handle whose brokered token is injected on egress.
**`forwardURL`:** re-origin the request to a trusted gateway.
**`rewrite`:** `{ headers?: Record<string,string|null>, path? }`, a `null` header
value deletes it.

Author policies with the tools before shipping:

```ts
import { lint, simulate, formatSimulation } from "@zeroness/policy";
lint(policy);                                   // Finding[], fix warns/errors
formatSimulation(simulate(policy, requests));   // dry-run a batch of requests
```

## 7. Capabilities, give access without secrets

Declare resources; reference them as `cap:` handles.

```ts
resources: {
  "cap:reports":   { r2: "reports-bucket", mode: "rw", prefix: "u42/" },
  "cap:analytics": { d1: "analytics-db", mode: "ro" },
  "cap:cache":     { kv: "cache-ns", mode: "rw" },
  "cap:stripe":    { accessToken: "STRIPE_RO" },              // secret name in the Broker
  "cap:internal":  { oidc: { audience: "https://gw.acme", ttlSeconds: 300 } },
}
```

`ResourceBinding` variants: `{r2,mode?,prefix?}` · `{d1,mode?}` · `{kv,mode?,prefix?}`
· `{queue}` · `{secret}` · `{accessToken}` · `{oidc:{audience,subject?,ttlSeconds?}}`.
`mode:"ro"` blocks writes. `prefix` scopes R2/KV keys.

**Data resources** (r2/d1/kv) are used via file paths in the sandbox:
`box.writeFile("cap:reports://q3.csv", data)` / `box.readFile("cap:reports://q3.csv")`.

**Identity resources** (accessToken/secret/oidc) are used by naming them as a
rule's `identity`, the Broker mints the header at egress. Never read them as
data.

## 8. Human-in-the-loop (`ask`)

Set `verdict: "ask"` on a risky route. Flow:
1. The code's request returns `451` with an `approvalId` (or, server-side, the
   `/authorize` decision is `ask`).
2. A human approves via the Broker: `POST /approval/<id>/approve` (or deny).
3. The code **retries**; the grant lets it through (scoped to that method+URL,
   TTL-bounded) with identity injected.

Wire notifications with a `GatekeeperAdapter` (`WebhookGatekeeper`,
`CloudflareOSGatekeeper`), set `GATEKEEPER_URL` on the Broker.

## 9. Recipes (copy these shapes)

**Let an agent `pip install` but nothing else:**
```ts
network: { default: "deny", allow: [{ host: "pypi.org" }, { host: "*.pythonhosted.org" }] }
```

**Call an authed API with no secret in the box:**
```ts
network: { default: "deny", allow: [{ host: "api.stripe.com", identity: "cap:stripe" }] },
resources: { "cap:stripe": { accessToken: "STRIPE_RO" } }
```

**Read/write a scoped R2 prefix:**
```ts
resources: { "cap:out": { r2: "bucket", mode: "rw", prefix: `${userId}/` } }
// in-sandbox: box.writeFile("cap:out://result.json", json)
```

**Gate spend behind a human:**
```ts
allow: [{ host: "api.stripe.com", path: "/v1/charges", methods: ["POST"], verdict: "ask", identity: "cap:stripe" }]
```

## 10. Invariants & guardrails (never violate)

- **Default-deny for untrusted code.** Never set `default: "allow"` for code you
  don't trust. `lint()` warns on this.
- **No secret enters the sandbox.** No API keys in `exec`, env, files, or
  `runCode`. Use `identity`/`cap:` only.
- **One tenant per sandbox.** Do not multiplex tenants in one session; the
  microVM/container is the isolation unit.
- **Scope capabilities.** Use `mode:"ro"` and `prefix` to the minimum. Prefer a
  path-scoped rule over `host:"*"`.
- **Always `destroy()`** the session when done.
- **Do not claim network protection without a deployed Egress Worker** and
  verified egress steering (see §12).

## 11. Common mistakes

- Putting a token in `exec("curl -H 'Authorization: Bearer …'")` → use `identity`.
- `*.example.com` and expecting it to match `example.com` (it doesn't, add both).
- `path: "/repos/*"` when you meant `/repos/**` (single-segment vs any-depth).
- Forgetting `snapshot()` needs `agentUrl` set (the in-sandbox agent).
- Calling `runCode` and expecting the agent to run it, `runCode` executes on the
  SDK's code runtime; only `exec`/file ops route to `zeronessd`.

## 12. The open caveat you must surface

zeroness routes egress by setting `HTTP(S)_PROXY` and relying on Cloudflare
Sandbox's outbound-intercept. **Whether *all* traffic is captured is not yet
proven on live infra** (see [`SECURITY.md`](./SECURITY.md) → Residual risks). If
a user asks "is my network policy airtight?", answer honestly: HTTP(S) via the
proxy is governed; validate with `scripts/validate.mjs` before trusting it for
raw sockets/other protocols.

## 13. Working in this repo

- Monorepo: `pnpm install`, `pnpm -r build`, `pnpm -r test` (44 tests).
- Packages: `core` (wrapper/policy/signing/caps), `broker` (trust-root DO),
  `egress` (enforcement Worker), `agent` (`zeronessd`), `policy` (lint/simulate),
  `gatekeeper` (approvals), `tls` (opt-in MITM CA), `create-zeroness` (scaffolder).
- Keep pure logic in `core`/`policy`/`gatekeeper` and **unit-tested**. The Broker
  has an in-process integration test (mock DO storage + R2), extend it when you
  change broker behavior.
- Do not add third-party attributions; keep the repo attribution-neutral.
