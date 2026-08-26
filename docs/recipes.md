# Recipes

Task-oriented patterns. Most assume you've created a `zeroness` client and are
inside a request handler; copy the `config` shape into `zeroness.sandbox(id, config)`.
The first recipe below is different: it is the enforced network jail, wired at the
container class.

## Enforce the network boundary over untrusted code (the jail)

The policy recipes below describe what egress you *intend*. To make that boundary
*enforceable* against untrusted in-container code (so a raw `curl` cannot bypass
it, not just cooperative SDK fetches), define your container Durable Object with
`createGovernedSandbox`. This is the configuration proven live in
[`../LIVE-VALIDATION.md`](../LIVE-VALIDATION.md).

```ts
// src/index.ts (your Worker entrypoint)
import { Sandbox as BaseSandbox, getSandbox, proxyToSandbox } from "@cloudflare/sandbox";
import { createGovernedSandbox, registerGovernedSession } from "@zeroness/core";
export { ContainerProxy } from "@cloudflare/containers";
export { ZeronessBroker } from "@zeroness/broker";

// enableInternet=false + interceptHttps=true + a Broker-backed catch-all outbound
// handler. Export this as your container class.
export const Sandbox = createGovernedSandbox(BaseSandbox);

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const proxied = await proxyToSandbox(req, env);
    if (proxied) return proxied;

    const id = "user-42";
    await registerGovernedSession(env.ZERONESS_BROKER, env.Sandbox, id, {
      policy: {
        default: "deny",
        allow: [
          { host: "httpbingo.org", identity: "cap:echo" },  // authed, no key in the box
          { host: "api.github.com", methods: ["GET"], path: "/repos/**" },
        ],
      },
      resources: { echo: { accessToken: env.ECHO_TOKEN } }, // resolved by the Broker only
    });

    const box = getSandbox(env.Sandbox, id);
    // A raw curl inside the container is intercepted and governed:
    return Response.json(await box.exec("curl -s https://httpbingo.org/headers"));
  },
};
```

wrangler config needs the interception plumbing:

```jsonc
{
  "compatibility_flags": ["nodejs_compat", "enable_ctx_exports"],
  "containers": [{ "class_name": "Sandbox", "image": "./Dockerfile", "instance_type": "standard" }],
  "durable_objects": { "bindings": [
    { "name": "Sandbox", "class_name": "Sandbox" },
    { "name": "ZERONESS_BROKER", "class_name": "ZeronessBroker", "script_name": "zeroness-broker" }
  ]},
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["Sandbox"] }]
}
```

Interception MITMs TLS with the Cloudflare containers CA. The standard
`cloudflare/sandbox` base image **already trusts** it (verified: a plain
`curl https://<allowed-host>` returns 200 and is governed), so a minimal
Dockerfile is enough:

```dockerfile
FROM docker.io/cloudflare/sandbox:0.12.8
EXPOSE 3000
```

Only if you build on a base image that does not ship that CA do clients need to
point at it (the cert is at `/etc/cloudflare/certs/cloudflare-containers-ca.crt`
at runtime), e.g. `CURL_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS`, or by adding it to
the trust store. A client that trusts nothing fails its handshake (fail-closed);
enforcement of denied hosts does not depend on the CA either way.

Result (proven live): allowed hosts return 200 with brokered identity injected,
every other host returns `403 zeroness: blocked by policy`, and every crossing is
audited. An `ask` rule returns `451` until approved.

## Let an agent install packages, nothing else

## Let an agent install packages, nothing else

```ts
network: {
  default: "deny",
  allow: [
    { host: "pypi.org" }, { host: "*.pythonhosted.org" },     // pip
    { host: "registry.npmjs.org" },                            // npm
  ],
}
// box.exec("pip install pandas")  ✓     box.exec("curl http://evil.com")  ✗ blocked
```

## Call an authenticated API with no secret in the sandbox

```ts
network: { default: "deny", allow: [{ host: "api.stripe.com", identity: "cap:stripe" }] },
resources: { "cap:stripe": { accessToken: "STRIPE_RO" } },   // secret lives in the Broker
// the code just calls https://api.stripe.com/... ; the Broker injects Authorization: Bearer …
```

## Call an internal service with a short-lived OIDC token

```ts
network: {
  default: "deny",
  allow: [{ host: "gateway.acme.internal", identity: "cap:acme" }],
  transform: [{ host: "gateway.acme.internal", forwardURL: "https://gw.acme.com" }],
},
resources: { "cap:acme": { oidc: { audience: "https://gw.acme.com", ttlSeconds: 300 } } },
```

## Read/write a scoped R2 prefix (code never sees keys)

```ts
resources: { "cap:out": { r2: "results-bucket", mode: "rw", prefix: `${userId}/` } },
// in-sandbox:
await box.writeFile("cap:out://run-1/result.json", JSON.stringify(result));
const back = await box.readFile("cap:out://run-1/result.json");
```

## Query a read-only D1 database by handle

```ts
resources: { "cap:db": { d1: "analytics", mode: "ro" } },
// the in-sandbox capability proxy exposes it; writes are rejected (ro).
```

## Gate a risky action behind a human

```ts
network: {
  default: "deny",
  allow: [{ host: "api.stripe.com", path: "/v1/charges", methods: ["POST"],
            verdict: "ask", identity: "cap:stripe" }],
},
resources: { "cap:stripe": { accessToken: "STRIPE_RW" } },
```
The charge request is blocked (`451` + `approvalId`) until a human approves via
`POST /approval/<id>/approve` on the Broker; the retry then succeeds. Wire
notifications by setting `GATEKEEPER_URL` on the Broker (a `WebhookGatekeeper`).

## Rewrite/normalize outbound requests

```ts
network: {
  default: "deny",
  allow: [{ host: "api.github.com", methods: ["GET"], path: "/repos/**" }],
  transform: [{ host: "api.github.com", rewrite: {
    headers: { "user-agent": "my-app", "x-internal": null },   // set UA, delete a header
  } }],
}
```

## Snapshot and resume

```ts
const box = await zeroness.sandbox("u1", { agentUrl, snapshotOn: "shutdown", /* … */ });
// … work …
const ref = await box.snapshot();          // "snap_<sha256>", stored in R2
const fork = await zeroness.resume(ref);   // branch a fresh sandbox from it
```
`snapshot()` requires `agentUrl` (the in-sandbox `zeronessd`).

## Test a policy before shipping it

```ts
import { lint, simulate, formatSimulation } from "@zeroness/policy";

const findings = lint(policy);             // fix any "error"/"warn"
console.log(formatSimulation(simulate(policy, [
  { host: "api.github.com", path: "/repos/a/b", method: "GET" },
  { host: "evil.com", path: "/", method: "GET" },
  { host: "api.stripe.com", path: "/v1/charges", method: "POST" },
])));
// ✓ GET api.github.com/repos/a/b → allow
// ✗ GET evil.com/ → deny  (no allow rule; policy default=deny)
// ? POST api.stripe.com/v1/charges → ask [cap:stripe]
```

## Inspect what the code actually did

```ts
const trail = await box.audit();
// [{ ts, event: "egress:allow", detail: { url, identity } },
//  { ts, event: "egress:deny",  detail: { url, reason } },
//  { ts, event: "cap:write",    detail: { name, key } }, … ]
```
