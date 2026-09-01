# celld-jail — a fail-closed egress cage for untrusted workloads

Governs the egress of an untrusted workload on a substrate with **no built-in
egress hook** (e.g. a self-hosted [celld](https://github.com/denoland/celld)
node). The model is Vercel Sandbox's: **enforce at the network boundary around
the compute unit, not inside the runtime.**

```
 untrusted workload (uid 2000)          zeroness egress proxy (root)        internet
   │  HTTP(S)_PROXY → proxy                 │ authorize each connection        ▲
   │  (or any direct socket)                │ via the Broker (policy +         │
   ▼                                        │ brokered identity + audit)       │
 ┌───────────────────────────┐    only     ▼                                  │
 │ iptables OUTPUT (owner):   │  127.0.0.1  allow → forward / inject id ───────┘
 │  uid 2000 → 127.0.0.1 OK   │─────────►   deny  → 403
 │  uid 2000 → *      DROP     │
 └───────────────────────────┘
```

Two things make this a **jail**, not a convenience:

1. **Fail-closed firewall.** `iptables` drops every packet the workload uid emits
   except to the proxy. Code that ignores `HTTP_PROXY` and opens a raw socket
   reaches nothing — there is no direct route out (exactly Vercel's routeless
   guest tap).
2. **Authorizing proxy.** Every connection is checked by
   [`@zeroness/egress-proxy`](../../packages/egress-proxy) against the zeroness
   Broker: default-deny policy, the internal-address floor, audit, and (with TLS
   interception) brokered identity injection.

## Run the demo

Requires Docker with `NET_ADMIN`. From the **built** monorepo root (so
`@zeroness/*` resolve):

```bash
pnpm install && pnpm -r build
docker run --rm --cap-add=NET_ADMIN \
  -v "$PWD/examples/celld-jail:/app:ro" \
  -v "$PWD/node_modules:/app/node_modules:ro" \
  node:22-bookworm bash /app/run-jail.sh
```

Expected:

```
A) via proxy to ALLOWED host        → http=200        (reached)
B) via proxy to DENIED host         → egress:deny, http=000
C) UNCOOPERATIVE direct connect     → http=000 (timeout — firewall DROP)   ← the jail
D) via proxy to internal metadata   → internal address blocked, http=403
```

## Production wiring

- Point the proxy at the real Broker: set `ZERONESS_BROKER_URL` +
  `ZERONESS_SESSION`, and `demo-proxy.mjs` uses `brokerAuthorizer(...)` instead of
  the demo policy. The Broker can itself run on celld (see
  [`docs/DEPLOY-celld.md`](../../docs/DEPLOY-celld.md)).
- **One tenant per jailed unit** (VM or locked netns) — never a shared isolate;
  the isolate is not a strong enough boundary for hostile code (Vercel uses a
  microVM for the same reason).
- **HTTPS identity injection / path policy** needs TLS interception: add a
  per-tenant MITM CA ([`@zeroness/tls`](../../packages/tls)) whose private key
  stays in the proxy, trusted inside the jail. Without it, the proxy governs on
  the CONNECT host+port (SNI-level), which is enough for default-deny by host.
- **DNS:** the workload never resolves names (it hands the proxy a hostname via
  `CONNECT`); the proxy resolves. Block the workload's DNS in the firewall too
  (already covered by the default DROP) to prevent DNS-tunnel exfiltration.

## Limits

- The literal internal-address floor blocks IP-literal targets; a public name
  that *resolves* to an internal IP (DNS-rebind) needs resolve-and-pin at the
  proxy's connect step — a hardening to add for hostile multi-tenant use.
- `iptables owner` match governs locally-generated traffic by uid. If the
  workload can gain a different uid (root), the owner rule must be paired with a
  netns/user-namespace boundary. Prefer one-tenant-per-VM for hostile code.
