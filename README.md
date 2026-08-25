<h1 align="center">zeroness</h1>
<p align="center"><strong>A capability & identity mesh for Cloudflare Sandboxes.</strong><br>
Give untrusted code a real Linux box — and still control, broker, and audit every
credential it uses and every host it reaches.</p>

<p align="center">
  <code>default-deny network</code> · <code>zero secrets in the sandbox</code> ·
  <code>capability-scoped resources</code> · <code>signed commands</code> ·
  <code>full audit</code>
</p>

---

## Why

Running AI-generated / untrusted code is the defining workload of the moment, and
the hard part isn't *isolating* it — Cloudflare Sandbox, E2B, Modal and Fly all
do that. The hard part is **giving isolated code trusted powers safely**: letting
an agent call your Stripe API, read one R2 prefix, or reach `api.github.com` —
*without* handing it your keys or the open internet.

Cloudflare already ships both halves of the answer and hasn't connected them:

- **Cloudflare Sandbox** — real Linux code execution, and a raw hook to
  "intercept outbound HTTP."
- **Cloudflare OS / Gatekeepers** — capability-based, zero-permission,
  human-in-the-loop governance — but only at the OAuth/SaaS layer.

**zeroness is the missing seam.** It pushes Gatekeeper-style governance down onto
the code-execution layer, using proven zero-trust network-and-identity techniques —
built Cloudflare-native, generalized, and open.

## What you get

```ts
import { getSandbox } from "@cloudflare/sandbox";
import { Zeroness } from "@zeroness/core";

const zeroness = new Zeroness({
  sandboxBinding: env.Sandbox,
  broker: env.ZERONESS_BROKER,
  egressUrl: env.EGRESS_URL,
  getSandbox,
});

const box = await zeroness.sandbox("user-42", {
  network: {
    default: "deny",                                   // no internet unless allowed
    allow: [
      { host: "pypi.org" }, { host: "*.pythonhosted.org" },     // let pip work
      { host: "api.github.com", methods: ["GET"], path: "/repos/**" },
      { host: "api.stripe.com", verdict: "ask", identity: "cap:stripe-ro" }, // gated + brokered
    ],
  },
  resources: {
    "cap:stripe-ro": { accessToken: "STRIPE_RO" },     // lives in the Broker, never in the box
    "cap:reports":   { r2: "reports", mode: "rw", prefix: "user-42/" },
  },
});

await box.exec("pip install pandas && python analyze.py"); // signed + governed
await box.writeFile("cap:reports://q3.csv", csv);          // code never sees keys
const trail = await box.audit();                           // every crossing, logged
```

- **Default-deny egress.** The sandbox reaches only the hosts/paths/methods you
  allow. `pip install` works because you allow-listed PyPI — nothing else does.
- **No secrets in the sandbox.** Credentials live only in the Broker; the Egress
  Worker injects short-lived, audience-bound identity **at the moment of egress**.
  Dump the sandbox filesystem and you get nothing reusable.
- **Capability-scoped resources.** R2/D1/KV/secrets are opaque `cap:` handles;
  the code can't enumerate or forge bindings.
- **Human-in-the-loop.** A rule can be `ask` → routed to a Gatekeeper approval.
- **Signed command channel.** Every command is Ed25519-signed with body-hash +
  freshness + replay protection (closing gaps we found in the pattern's originator).
- **Drop-in.** Same shape as `@cloudflare/sandbox`.

## Architecture

```
 your Worker ──signed cmds──►  Zeroness  ──►  Cloudflare Sandbox (Linux)
                                  │                     │ all egress
                            ┌─────▼──────┐              ▼
                            │  Broker DO │◄──authorize──  Egress Worker ──► internet
                            │ policy +   │   (per-request identity)
                            │ identity + │
                            │ caps +     │◄──► Gatekeepers (human-in-loop)
                            │ audit      │
                            └────────────┘
```

- `@zeroness/core` — the `Zeroness` wrapper, policy engine, capability handles, signing.
- `@zeroness/egress` — default-deny outbound proxy Worker (enforces Broker decisions).
- `@zeroness/broker` — the trust-root Durable Object (the only component with secrets).
- `@zeroness/agent` — `zeronessd`, the in-sandbox agent (verify signed commands, cap I/O, heartbeat).
- `@zeroness/policy` — author, **lint**, and **simulate** policies offline.

## Quickstart

```bash
pnpm install
pnpm build
pnpm -C packages/core test          # the policy engine is unit-tested

# deploy the two Workers
pnpm -C packages/broker deploy
pnpm -C packages/egress deploy
pnpm -C examples/governed-sandbox deploy
```

Author policy with confidence — it's just data:

```ts
import { lint, simulate, formatSimulation } from "@zeroness/policy";
lint(myPolicy);                                  // catch foot-guns in CI
console.log(formatSimulation(simulate(myPolicy, [
  { host: "api.github.com", path: "/repos/a/b", method: "GET" },
  { host: "evil.com", path: "/", method: "GET" },
])));
// ✓ GET api.github.com/repos/a/b → allow
// ✗ GET evil.com/ → deny  (no allow rule; policy default=deny)
```

## Security model

| Control | Protects | Fails if… |
|---|---|---|
| default-deny egress | the sandbox's reach | a route bypasses the Egress Worker |
| Broker-held secrets + per-request injection | credential exposure | the Broker DO is compromised |
| `cap:` capability handles | resource isolation | a handle is guessable *(they're random, per-session)* |
| Ed25519 signed commands | the control channel | the session private key leaks *(never enters the box)* |
| `ask` + Gatekeepers | silent exfiltration/spend | approvals are auto-granted |
| audit log | blind spots | the Broker log is tampered |

See [`PLAN.md`](./PLAN.md) for the full design, roadmap, and the mapping from each
design pattern to its Cloudflare-native mechanism.

## Status

Early. The **policy engine, signing, capability handles, Egress Worker, and Broker
are implemented**; the in-sandbox agent, snapshot/restore, TLS-MITM option, and
the Gatekeeper bridge are scaffolded with clear seams. **Cloudflare Sandbox's
outbound-intercept internals are undocumented** — Phase 0 verifies the exact hook.

## A note on provenance

zeroness transfers **architecture patterns** — capability tokens, egress
mediation, audience-bound token brokering, signed control channels — all
established zero-trust practice. It contains no code, exploit, or proprietary
material from any third party. Designed to be **upstreamable** into Cloudflare,
not adversarial.

## License

Apache-2.0.
