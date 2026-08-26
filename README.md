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
- **Capability-scoped resources**: R2/D1/KV/secrets are opaque `cap:` handles; the code can't enumerate or forge bindings.
- **Human-in-the-loop**: a rule can be `ask`, routed to an approval before the call proceeds.
- **Signed command channel**: every command is Ed25519-signed (body-hash + freshness + replay protection) and verified by the in-sandbox agent.
- **Drop-in**: the same surface as `@cloudflare/sandbox`.

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
- **[docs/api-reference.md](./docs/api-reference.md)**: full API surface for every package.
- **[docs/recipes.md](./docs/recipes.md)**: task-oriented examples.
- **[DEPLOY.md](./DEPLOY.md)**: deploy the Workers + validate on live Cloudflare.
- **[SECURITY.md](./SECURITY.md)**: threat model, assumptions, residual risks.

## Status

Pre-1.0. Everything is implemented and unit-tested (44 tests, incl. an in-process
Broker integration suite). The one open item is **live validation against a real
Cloudflare Sandbox**: zeroness routes egress via `HTTP(S)_PROXY` + Cloudflare's
outbound-intercept, and whether *all* traffic is captured must be proven on live
infra (`scripts/validate.mjs` + [`DEPLOY.md`](./DEPLOY.md) make it one command).
Treat the network guarantee as "HTTP(S) via the proxy" until you've validated it.

## Contributing & releases

`pnpm install && pnpm -r build && pnpm -r test`. See [RELEASING.md](./RELEASING.md).

## License

Apache-2.0.
