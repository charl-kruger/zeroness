# Live validation results (Cloudflare)

Deployed and tested on a real Cloudflare account (Workers + Durable Objects + R2
+ Containers). This records what is proven, and the one hard finding.

## Deployed

- Broker: `zeroness-broker` (Durable Object, R2, secret)
- Egress Worker: `zeroness-egress`
- Control harness: `zeroness-livetest`
- Real container sandbox: `zeroness-sandbox-example` (`@cloudflare/sandbox@0.12.8`)

## Proven working live ✅

The entire zeroness governance layer, verified end-to-end on deployed
infrastructure via the control harness:

- **Default-deny** egress policy; **allow** by host; **method + path** enforcement.
- **Brokered identity** — an upstream received `Authorization: Bearer <secret>`
  that was injected by the Broker at egress and never existed in the request; the
  sandbox never holds the secret.
- **Human-in-the-loop** — `ask → 451 → approve → retry → 200`, grant scoped to the
  request.
- **Full audit trail** streamed from the Broker DO.
- A real **Cloudflare Sandbox container** builds, deploys, and runs (`exec` works).
- **`enableInternet = false`** on the Sandbox class gives a genuine default-deny:
  the container gets **no internet at all** (verified: every outbound `curl`
  returns connection-failed).

## The hard finding ⚠️ (network enforcement over untrusted processes)

Cloudflare Sandbox exposes two *different* egress mechanisms, and only one
governs arbitrary in-container code:

| Mechanism | Layer | Governs raw `curl`/sockets? |
|-----------|-------|------------------------------|
| `enableInternet = false` | container **network** (no route) | **Yes** (blocks everything) |
| `allowedHosts` / `deniedHosts` / `outbound` handler | SDK **fetch** interception | **No** |

Evidence: with `deniedHosts = ["example.com"]`, an in-container
`curl https://example.com` still returned **200** (not blocked); with
`enableInternet = false`, the same `curl` returned connection-failed. So the
selective controls (host allow/deny lists and the `outbound` handler) intercept
requests made through the SDK's own fetch path, **not** the network of arbitrary
processes the untrusted code spawns.

**Implication.** On Cloudflare Sandbox today, network control over *untrusted*
in-container processes is effectively **all-or-nothing** (`enableInternet`).
Selective, per-host, identity-injecting egress governance — zeroness's network
story — is enforceable at the SDK-fetch layer (useful for cooperative code that
fetches through the SDK) but not for raw processes. Confirming whether a
supported configuration routes *all* container egress through the `outbound`
handler is an open question for Cloudflare.

## What this means for zeroness

- **Works today, fully:** the identity broker, capability handles, policy engine,
  human-in-the-loop approvals, and audit — as a governed control plane. This is
  the differentiated, hard part, and it is proven live.
- **Network jail for untrusted code on Cloudflare Sandbox:** limited to
  `enableInternet` all-or-nothing until the `outbound`-handler path is confirmed
  to capture raw-process egress. For a strict per-host network jail over
  untrusted code, a substrate where the guest network namespace is controllable
  (a Firecracker/microVM platform) enforces it at the network layer.

## Repro

`examples/governed-sandbox` (real 0.12.8 container) + `scripts/validate.mjs`
against the harness. The container needs Docker locally to build; the Workers do
not.
