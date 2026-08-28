<h1 align="center">zeroness</h1>
<p align="center"><strong>Run untrusted code on Cloudflare, with zero network and zero secrets by default.</strong></p>
<p align="center">
  <a href="https://www.npmjs.com/package/@zeroness/core"><img alt="npm" src="https://img.shields.io/npm/v/@zeroness/core?color=%23111"></a>
  <img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-blue">
  <img alt="tests" src="https://img.shields.io/badge/tests-44%20passing-brightgreen">
</p>

<p align="center">
  <code>default-deny egress</code> · <code>no secrets in the sandbox</code> ·
  <code>capability-scoped resources</code> · <code>signed commands</code> ·
  <code>human-in-the-loop</code> · <code>full audit</code>
</p>

---

zeroness wraps a [Cloudflare Sandbox](https://developers.cloudflare.com/sandbox/)
so that untrusted or AI-generated code starts with **no internet and no
credentials**, and you grant exactly what it needs (specific hosts, specific resources, specific
identities), while every boundary crossing is brokered and logged. It's the safety layer for "let the agent run code."

## Install

```bash
pnpm add @zeroness/core @zeroness/broker @cloudflare/sandbox
# deploy the two Workers (Broker + Egress) once, see DEPLOY.md
```

Or scaffold a project:

```bash
pnpm create zeroness my-app
```

## 60-second example

```ts
import { getSandbox } from "@cloudflare/sandbox";
import { Zeroness } from "@zeroness/core";
export { ZeronessBroker } from "@zeroness/broker";

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const zeroness = new Zeroness({
      sandboxBinding: env.Sandbox,
      broker: env.ZERONESS_BROKER,
      egressUrl: env.EGRESS_URL,
      getSandbox,
    });

    const box = await zeroness.sandbox("user-42", {
      network: {
        default: "deny",                                            // no internet…
        allow: [
          { host: "pypi.org" }, { host: "*.pythonhosted.org" },     // …except pip
          { host: "api.github.com", methods: ["GET"], path: "/repos/**" },
          { host: "api.stripe.com", identity: "cap:stripe" },       // authed, no key in the box
        ],
      },
      resources: {
        "cap:stripe":  { accessToken: "STRIPE_RO" },                // lives in the Broker only
        "cap:reports": { r2: "reports", mode: "rw", prefix: "user-42/" },
      },
    });

    try {
      await box.exec("pip install requests && python analyze.py");  // signed + governed
      await box.writeFile("cap:reports://out.json", "{}");          // code never sees keys
      return Response.json({ audit: await box.audit() });           // every crossing, logged
    } finally {
      await box.destroy();                                          // revoke the session
    }
  },
};
```

- **Default-deny egress**: the sandbox reaches only the hosts/paths/methods you allow.
- **No secrets in the sandbox**: the Broker injects short-lived, audience-bound identity at the moment of egress. Dump the filesystem and you get nothing reusable.
- **Capability-scoped resources**: R2/D1/KV/queue/secrets are opaque `cap:` handles; the code can't enumerate or forge bindings, and `mode:"ro"` is enforced (D1 read-only rejects writes, CTE-fed writes, and mutating PRAGMAs).
- **Human-in-the-loop**: a rule can be `ask`, routed to an approval before the call proceeds.
- **Rate-limited**: a per-session token bucket caps egress + capability ops at the Broker (configurable), returning `429` on abuse.
- **Signed command channel**: every command is Ed25519-signed (body-hash + freshness + replay protection) and verified by the in-sandbox agent.
- **Drop-in**: the same surface as `@cloudflare/sandbox`.

## Enforced network jail

The example above is the control plane. To make the default-deny boundary
enforceable against *untrusted* in-container code (so a raw `curl` cannot bypass
it, not just cooperative SDK fetches), define your container Durable Object with
`createGovernedSandbox`:

```ts
import { Sandbox as BaseSandbox, getSandbox } from "@cloudflare/sandbox";
import { createGovernedSandbox, registerGovernedSession } from "@zeroness/core";
export { ContainerProxy } from "@cloudflare/containers";
export { ZeronessBroker } from "@zeroness/broker";

// No direct internet + intercept ALL outbound HTTPS -> the Broker mediates every
// request. Export this as your container class.
export const Sandbox = createGovernedSandbox(BaseSandbox);

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    await registerGovernedSession(env.ZERONESS_BROKER, "user-42", {
      policy: { default: "deny", allow: [{ host: "api.github.com", methods: ["GET"] }] },
      resources: { gh: { accessToken: env.GH_TOKEN } }, // stays in the Broker
    });
    const box = getSandbox(env.Sandbox, "user-42");
    return Response.json(await box.exec("curl -s https://api.github.com/repos/cloudflare/workers-sdk"));
  },
};
```

wrangler needs `enable_ctx_exports` in `compatibility_flags` and the
`ContainerProxy` export above. Interception MITMs TLS with the Cloudflare
containers CA; the standard `cloudflare/sandbox` base image already trusts it, so
plain in-container HTTPS works cleanly and is still governed (a denied host is
blocked at the handler regardless). Full recipe and the live proof:
[`docs/recipes.md`](./docs/recipes.md), [`LIVE-VALIDATION.md`](./LIVE-VALIDATION.md).

## How it works

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

Your Worker drives the sandbox with **signed commands**. All egress is routed
through the **Egress Worker**, which asks the **Broker** (a Durable Object, the
only component that holds secrets) to authorize each request and mint identity.
Inside the sandbox, **`zeronessd`** verifies commands and proxies capability I/O.

## Packages

| Package | What it is |
|---------|-----------|
| [`@zeroness/core`](./packages/core) | The `Zeroness` wrapper, network-policy engine, capability handles, Ed25519 signing |
| [`@zeroness/broker`](./packages/broker) | The trust-root Durable Object (policy eval, per-request identity, capabilities, audit) |
| [`@zeroness/egress`](./packages/egress) | Default-deny outbound Worker that enforces Broker decisions |
| [`@zeroness/agent`](./packages/agent) | `zeronessd`, verifies signed commands, proxies caps, heartbeats |
| [`@zeroness/policy`](./packages/policy) | Author, **lint**, and **simulate** policies offline |
| [`@zeroness/gatekeeper`](./packages/gatekeeper) | Human-in-the-loop approval state machine + adapters |
| [`@zeroness/tls`](./packages/tls) | Opt-in per-session MITM certificate authority |
| [`create-zeroness`](./packages/create-zeroness) | `pnpm create zeroness my-app` scaffolder |

## Documentation

- **[AGENTS.md](./AGENTS.md)**: deep, imperative guide for an AI agent using zeroness (and working in this repo).
- **[docs/concepts.md](./docs/concepts.md)**: the mental model.
- **[docs/use-cases.md](./docs/use-cases.md)**: what to build, and how it fits Cloudflare OS.
- **[docs/api-reference.md](./docs/api-reference.md)**: full API surface for every package.
- **[docs/recipes.md](./docs/recipes.md)**: task-oriented examples.
- **[docs/logging.md](./docs/logging.md)**: audit via Workers Logs (7-day) and Logpush.
- **[DEPLOY.md](./DEPLOY.md)**: deploy the Workers + validate on live Cloudflare.
- **[SECURITY.md](./SECURITY.md)**: threat model, assumptions, residual risks.

## Status

Pre-1.0. Everything is implemented and unit-tested, and the whole system is
**validated live on real Cloudflare infrastructure** (Workers + Durable Objects +
R2 + Containers). See [`LIVE-VALIDATION.md`](./LIVE-VALIDATION.md) for the proof.

Proven live:

- The governance control plane: default-deny, allow by host, method + path
  enforcement, brokered identity injection, human-in-the-loop approvals, audit.
- A **network jail over untrusted in-container code**: with `createGovernedSandbox`
  (`enableInternet=false` + `interceptHttps=true` + a Broker-backed `outbound`
  handler), every outbound request (a raw in-container `curl` included, not just
  the SDK's own fetch) is intercepted at the container network layer and mediated
  by the Broker. Allowed hosts get brokered identity; everything else is denied
  and audited.

The injected `HTTP(S)_PROXY` env vars are a convenience for cooperative HTTP
clients, not the jail: use `createGovernedSandbox` for the enforced boundary.

## Contributing & releases

`pnpm install && pnpm -r build && pnpm -r test`. See [RELEASING.md](./RELEASING.md).

## License

Apache-2.0.
