# Running zeroness on celld (self-hosted)

[celld](https://github.com/denoland/celld) is a self-hosted, distributed
Cloudflare Workers + Durable Objects runtime (Rust + embedded V8; a "cell" is a
SQLite-backed DO). zeroness's **control plane** — the Broker (a DO) and the
Egress Worker — are ordinary Workers-runtime code, so they run on a self-hosted
celld fleet with **no Cloudflare account**.

This is validated: the real `@zeroness/broker` runs on `celld dev` and serves the
full `session → authorize → capability → audit` flow, including OIDC identity
minting. See [`../plans/009-celld-integration.md`](../plans/009-celld-integration.md)
for the spike + validation record.

## Scope — read this first

celld runs **V8 isolates, not containers**. That means:

- ✅ **Supported:** the zeroness **control plane** (Broker + Egress) — policy
  enforcement, brokered identity, capabilities (R2/D1/KV/queue), approvals,
  audit — governing traffic that transits the Egress Worker.
- ⚠️ **Different mechanism for the network jail.** celld has no containers and no
  outbound-fetch hook, so the Cloudflare `createGovernedSandbox` primitive does
  not apply. Instead, jail egress **at the network boundary around the celld
  unit** (the Vercel Sandbox model): a fail-closed firewall + the
  [`@zeroness/egress-proxy`](../packages/egress-proxy) authorizing every
  connection through the Broker. Untrusted code that ignores `HTTP_PROXY` still
  cannot egress — there is no direct route. See
  [`examples/celld-jail`](../examples/celld-jail) for a proven reference.

**Honest boundary:** on celld you get default-deny egress + brokered identity +
audit via the network jail, and **one tenant per jailed unit** (VM or locked
netns) — never a shared isolate, since a V8 isolate is not a strong enough wall
for hostile code (Vercel uses a microVM for the same reason). HTTPS identity
injection / path-scoped policy needs a per-tenant MITM CA (`@zeroness/tls`);
without it the jail governs on CONNECT host+port, which still enforces
default-deny by host.

## Requirements

- celld installed: `curl -fsSL https://celld.dev/install.sh | sh`
- `esbuild` on PATH (celld bundles Wrangler projects with it).
- The Broker's `wrangler.jsonc` already sets `"compatibility_flags":
  ["nodejs_compat"]` — **required**, because on celld `crypto.subtle` lacks
  Ed25519, so zeroness signs OIDC JWTs via `node:crypto` (see below).

## Ed25519 note (handled automatically)

celld's `crypto.subtle` does not implement Ed25519 verify. zeroness's
`@zeroness/core` detects this once at runtime and falls back to `node:crypto`
(under `nodejs_compat`) for OIDC JWT minting; on Cloudflare it uses
`crypto.subtle` unchanged. No configuration needed beyond the `nodejs_compat`
flag. The persisted OIDC key is a standard OKP JWK, interchangeable between
runtimes.

## Local development

From a project whose entrypoint exports the `ZeronessBroker` DO and an
Egress-style Worker (the Egress routes to the Broker DO by session token):

```bash
celld dev            # http://127.0.0.1:9876, state under .celld/dev
```

Drive it exactly as on Cloudflare: `POST /session`, `POST /authorize`,
`GET|POST /cap/<name>`, `GET /audit`.

## Fleet deployment

```bash
# one-time: deploy the bundle to a shared bucket
celld deploy . --bucket s3://my-cells-bucket

# run a node (repeat on each machine; they discover peers via the bucket)
celld \
  --bucket s3://my-cells-bucket \
  --listen 0.0.0.0:8080 \
  --internal-listen 10.0.0.12:8081 \
  --advertise 10.0.0.12:8081
```

Bind resources by name in the Wrangler config exactly as on Cloudflare — a
`{ r2: "reports" }` capability resolves to a celld R2 binding named `reports`,
`{ d1: "analytics" }` to a D1 binding, `{ queue: "events" }` to a queue, etc.
(zeroness resolves every binding by its configured name.) The Egress→Broker link
is a Durable-Object namespace binding; celld supports the DO `stub.fetch()`
crossing.

## Known celld limits to keep in mind

celld's Cloudflare compatibility is "Partial" (see celld
`docs/cloudflare-compat.md`): R2 has no `ssecKey` and multipart constraints, KV
is single-writer/1 MiB, D1 caps results at 100k rows / 32 MiB, Queues are
single-writer with 4-day retention. All are within zeroness's current usage, but
re-check if you push large snapshots or high-volume capability I/O.
