# Concepts

The mental model behind zeroness. If you understand these, the API is obvious.

## The problem

Running untrusted code is easy to *isolate* (a container, a microVM) but hard to
make *useful safely*. Real workloads need to reach an API, read a bucket, call an
internal service — which usually means handing the code a credential and opening
the network. That's the leak: a prompt-injected agent, a malicious dependency, or
a bug now has your keys and the open internet.

zeroness inverts the default. The sandbox starts with **nothing**, and you grant
capabilities the code can *use* without ever *holding*.

## Session

A **session** is one governed sandbox, created by `zeroness.sandbox(id, config)`.
On creation zeroness:

1. mints a per-session **Ed25519 keypair** (private key stays in your Worker) and
   an opaque **session token**;
2. registers the policy + resource bindings with the **Broker** (keyed by the
   token), which mints an opaque handle token per capability;
3. steers the sandbox's egress through the **Egress Worker** (sets `HTTP(S)_PROXY`
   and the session token) and injects the agent's boot env.

`box.destroy()` revokes the session; its tokens stop working at the edge
immediately.

## Network policy

A **policy** is data: a `default` stance plus `deny` / `allow` / `transform`
rules. Each outbound request is evaluated to a **decision** — `allow`, `deny`, or
`ask` — possibly carrying an identity to inject and a rewrite/forwardURL to apply.
Evaluation is `deny → first allow → default`. Because it's pure data, you can
`lint()` and `simulate()` it offline before it ever governs anything.

The policy is enforced at the **Egress Worker**, not inside the sandbox — so
compromised in-sandbox code cannot change it.

## Capability handles

A **capability** is an opaque handle (`cap:reports`) that stands in for a real
resource binding (an R2 bucket, a D1 database, a secret, an OIDC identity). The
binding and any credential live only in the Broker. The sandbox receives a random
per-session token for the handle — it cannot enumerate other resources or forge a
binding.

This is *capability security*: the ability to use a resource is the unforgeable
token, not an ambient credential. It's why cross-tenant access isn't gated by a
guessable id.

## Brokered identity

When a policy rule has an `identity: "cap:…"`, the Egress Worker asks the Broker
to **mint the credential for that one request** — a `Bearer` token from a stored
secret/access token, or a freshly-signed, audience-bound **OIDC JWT**. It's
attached as the request leaves and never exists inside the sandbox. A dumped
sandbox filesystem yields nothing reusable.

## Signed commands

Every command your Worker sends (`exec`, `writeFile`, `snapshot`, …) is wrapped in
an **Ed25519-signed envelope** over `procedure + timestamp + sha256(body)`. The
in-sandbox agent **`zeronessd`** verifies the signature, a freshness window, and a
monotonic sequence number before executing — so a tampered body or a replayed
command is rejected. The private key never enters the sandbox.

(`runCode` is signed and audited but executes on the SDK's code runtime, not via
the agent.)

## Approvals (human-in-the-loop)

A rule with `verdict: "ask"` turns a request into a **pending approval**. The call
is blocked; a human or system approves it via the Broker; the code's retry then
passes. The grant is scoped to that exact method + URL for a TTL. This is how you
let untrusted code do something risky (spend money, hit a sensitive endpoint)
without letting it do so silently.

## Audit

Every crossing — egress verdict, capability op, command, approval, heartbeat — is
appended to the Broker's audit log, retrievable via `box.audit()`. It's the record
of *what the code actually did*.

## Trust boundaries

```
 UNTRUSTED  │  TRUSTED (your Cloudflare account)
 the code   │  your Worker · Broker DO · Egress Worker
```

Assume the code is hostile: it can read its own filesystem and environment and
probe localhost. zeroness is designed so that buys nothing reusable. What it does
**not** replace is the isolation substrate — the microVM/container that keeps one
tenant off another is Cloudflare Sandbox's job. Run one tenant per sandbox. See
[SECURITY.md](../SECURITY.md).
