# zeroness, threat model & security posture

zeroness governs what untrusted code running in a Cloudflare Sandbox can reach
and which credentials it can use. This document states what it defends, what it
assumes, and where the sharp edges are. Security reports: see the bottom.

## Assets

1. **Operator credentials**: API tokens, OIDC identities, R2/D1/KV bindings the
   sandboxed code acts *with* but must never *hold*.
2. **Other tenants / other sessions**: one sandbox must not reach another's
   resources or network scope.
3. **The control plane**: the ability to issue commands to a sandbox.
4. **The audit record**: an accurate log of every boundary crossing.

## Trust boundaries

```
 UNTRUSTED                     │ TRUSTED
 the code in the sandbox       │ your Worker, the Broker DO, the Egress Worker
 (assume fully compromised)    │ (Cloudflare-run, your account)
```

Everything inside the sandbox is assumed **hostile**: the code may be
adversarial, may read its own filesystem and environment, and may probe
localhost. zeroness is designed so that this buys the attacker nothing reusable.

## What zeroness defends (and how)

| Threat | Mitigation |
|---|---|
| Code exfiltrates a long-lived secret | Secrets live only in the **Broker DO**; the Egress Worker injects short-lived, `aud`-bound identity **per request**. The sandbox never receives a credential. A dumped FS/env yields nothing reusable. |
| Code reaches an unapproved host | **Default-deny egress**: all outbound traffic is routed through the Egress Worker; only allow-listed host+path+method pass. |
| Code guesses/forges a resource binding | Resources are **opaque `cap:` handles** backed by random, per-session tokens; the binding + credential are resolved only in the Broker. The Broker rejects a cap op whose token doesn't own the session. |
| Someone injects a command to the sandbox | Every command carries an **Ed25519 signature** over `procedure + timestamp + body-hash`; `zeronessd` verifies signature **and** freshness **and** a monotonic sequence before executing, blocking tamper and replay. |
| Code silently spends/exfiltrates via an allowed-but-risky call | `ask` verdicts route to **human-in-the-loop** approval; the call is blocked until a human approves, and the grant is scoped to that exact method+URL for a TTL. |
| Blind spots | Every crossing (egress verdict, cap op, command, approval) is **audited** in the Broker. |
| Cross-session reach | The Broker is one DO **per session token**; a session can only address its own DO, and cap ops re-check token ownership. |

## Assumptions (things zeroness relies on)

- **The Broker DO and Egress Worker are trusted** (they run in your Cloudflare
  account). Compromise of the Broker exposes that session's secrets.
- **All sandbox egress actually transits the Egress Worker.** This is enforced
  by routing (proxy env + Cloudflare Sandbox's outbound-intercept). If a code
  path can open a socket that bypasses the Worker, the network policy is void for
  that path, see Residual risks.
- **The sandbox substrate isolates one tenant per sandbox.** zeroness governs the
  network/identity layer; it does not itself provide kernel/VM isolation, that
  is Cloudflare Sandbox's job. Run one tenant per sandbox.
- **The session private key never enters the sandbox.** Only the public key does.

## Residual risks / sharp edges

- **Egress-bypass is the crux.** Cloudflare Sandbox's outbound-intercept internals
  are undocumented; if raw sockets or a non-HTTP protocol can escape the proxy,
  policy is bypassed for that traffic. **This must be validated** on the live
  platform (the Phase-0 gap). Until then, treat the network guarantee as
  "HTTP(S) via the configured proxy," not "all traffic."
- **TLS-MITM is off by default.** Without interception, policy matches on SNI/host
  + the request line the client exposes to the proxy; a client that lies about
  its `Host` after CONNECT could evade host rules. Prefer the L7 proxy path and
  enable MITM only where the threat warrants.
- **Broker compromise = session secret compromise.** Secrets are per-session and
  short-lived at the edge, but the Broker itself holds the resolvable bindings.
- **`ask` fatigue.** Auto-approving to reduce friction defeats the control; keep
  `ask` scoped to genuinely risky routes.
- **Denial of service.** A sandbox can spam egress/cap ops. The Broker applies a
  per-session token-bucket rate limit to the `authorize` and capability paths
  (default burst 100, 50/s; tune with `RATE_LIMIT_BURST` / `RATE_LIMIT_RPS`, or
  set either to `0` to disable), returning `429` when a session exceeds its
  budget. The bucket is per-DO-instance and in-memory (it resets on eviction), so
  it is a coarse abuse/cost ceiling, not a hard quota; pair it with account-level
  limits for stricter guarantees.

## Non-goals

- Kernel/VM/container isolation (delegated to Cloudflare Sandbox).
- Protecting against a compromised Cloudflare account or Broker.
- Data-loss prevention on *allowed* destinations (policy controls *where*, not
  *what*, pair with content controls if needed).

## Reporting

Please report vulnerabilities privately to the maintainers (see repo contact)
before public disclosure. This is pre-1.0 software; the egress-bypass validation
above is the single most important open question.
