# Recipes

Task-oriented patterns. Each assumes you've created a `zeroness` client and are
inside a request handler. Copy the `config` shape into `zeroness.sandbox(id, config)`.

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
