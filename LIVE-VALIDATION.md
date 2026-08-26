# Live validation results (Cloudflare)

Deployed and tested on a real Cloudflare account (Workers + Durable Objects + R2
+ Containers). Everything below was verified end-to-end on live infrastructure.

## Deployed

- Broker: `zeroness-broker` (Durable Object, R2, secret)
- Egress Worker: `zeroness-egress`
- Control harness: `zeroness-livetest`
- Real container sandbox: `zeroness-sandbox-example` (`@cloudflare/sandbox@0.12.8`)

## Governance control plane, proven working live ✅

The entire zeroness governance layer, verified against the deployed Egress Worker
via the control harness:

- **Default-deny** egress policy; **allow** by host; **method + path** enforcement.
- **Brokered identity**: an upstream received `Authorization: Bearer <secret>`
  injected by the Broker at egress; the secret never existed in the request and
  the sandbox never holds it.
- **Human-in-the-loop**: `ask -> 451 -> approve -> retry -> 200`, grant scoped to
  the request.
- **Full audit trail** streamed from the Broker DO.

## Network jail over untrusted in-container code, proven working live ✅

A real Cloudflare Sandbox container (`@cloudflare/sandbox@0.12.8`) builds,
deploys, runs (`exec` works), and is fully governed. The jail configuration:

```ts
export class Sandbox extends BaseSandbox {
  enableInternet = false;  // container has NO direct network
  interceptHttps = true;   // ALL outbound HTTPS is MITM'd at the network layer
}
(Sandbox as any).outbound = async (request, env, ctx) => {
  // runs in the Worker; asks the Broker to authorize + inject identity
};
```

With this, **every** request from arbitrary in-container code (raw `curl`, any
process, not just the SDK's own fetch) is intercepted at the container network
layer and routed through the Worker `outbound` handler -> zeroness Broker. Live
result, pristine container instance:

| In-container command | Policy | Result |
|----------------------|--------|--------|
| `curl https://httpbingo.org/get` | allow (identity `cap:echo`) | **200**, Broker injected `Authorization: Bearer sk_live_...` |
| `curl https://httpbingo.org/headers` | allow | **200**, upstream saw the injected bearer (client is raw curl) |
| `curl https://example.com/` | default-deny | **403** `zeroness: blocked by policy` |
| `curl https://api.github.com/` | default-deny | **403** `zeroness: blocked by policy` |

Audit trail for the run (every crossing seen and recorded by the handler):

```
outbound:hit + egress:allow   https://httpbingo.org/get
outbound:hit + egress:deny    https://example.com
outbound:hit + egress:deny    https://api.github.com
outbound:hit + egress:allow   https://httpbingo.org/headers
```

## How the interception works (and the one operational caveat)

The mechanism lives in `@cloudflare/containers`. `interceptHttps = true` combined
with a catch-all `outbound` handler promotes the container to intercept-all and
calls `interceptOutboundHttps('*')`, so all outbound HTTPS is terminated by a
per-container MITM (the Cloudflare containers CA) and handed to the Worker
handler. `enableInternet = false` means there is no direct route out, so nothing
escapes the handler.

Operational note (verified): interception MITMs TLS with the Cloudflare
containers CA, present at runtime at
`/etc/cloudflare/certs/cloudflare-containers-ca.crt`. On the standard
`cloudflare/sandbox` base image that CA is **already in the trust store**, so a
plain in-container `curl https://<allowed-host>` (no `-k`) returns 200 and is
governed — cooperative code needs no special handling. Verified live:
`curl` with no flags to an allowed host returned 200, as did `curl --cacert
/etc/cloudflare/certs/cloudflare-containers-ca.crt`.

Enforcement does not depend on the CA: a denied host returns `403 blocked by
policy` at the handler whether or not the client trusts the CA. The CA only
affects whether an *allowed* host's TLS verifies cleanly. For a custom base image
that does not ship the CA, point clients at that cert path (or add it to the
trust store); a client that trusts nothing simply fails its handshake
(fail-closed). The `-k` in the table above was only to isolate "is it intercepted
and governed" from CA trust during debugging.

### Earlier finding, now resolved

An earlier pass left `interceptHttps` at its default of `false`. In that mode only
the SDK's own fetch path is intercepted; `allowedHosts` / `deniedHosts` / the
`outbound` handler did not govern raw `curl`, which went direct (example.com
returned 200). Setting `interceptHttps = true` (this section) closes that gap on
Cloudflare itself. There is no need for a separate microVM substrate to get a
per-host network jail over untrusted in-container code.

## What this means for zeroness

- **Identity broker, capability handles, policy engine, human-in-the-loop
  approvals, audit**: proven live as a governed control plane.
- **Per-host network jail over untrusted in-container code**: proven live on
  Cloudflare Sandbox with `enableInternet = false` + `interceptHttps = true` +
  catch-all `outbound`. Allowed hosts get brokered identity; everything else is
  denied and audited.

## Repro

`examples/governed-sandbox` (real 0.12.8 container) drives the checks in this
doc; the control-plane matrix runs against `zeroness-livetest` +
`zeroness-egress`. The container needs Docker locally to build; the Workers do
not.
