# Deploying zeroness

zeroness runs as two Workers (Broker + Egress) plus your app Worker that uses
`@cloudflare/sandbox`. This is the exact sequence to stand it up and validate it
end-to-end on a real Cloudflare account.

## Prerequisites

- A Cloudflare account on the **Workers Paid** plan (Cloudflare Sandbox requires it).
- `wrangler` authenticated: `npx wrangler login`.
- Node 20+ and `pnpm`.

## 1. Build

```bash
pnpm install
pnpm build
pnpm -r test        # 36 tests should pass locally before you deploy
```

## 2. Create the R2 bucket (snapshots + R2 capabilities)

```bash
npx wrangler r2 bucket create zeroness-snapshots     # matches wrangler.jsonc bindings
```

## 3. Deploy the Broker (the trust root)

```bash
pnpm -C packages/broker deploy
# note the deployed name: zeroness-broker
# add any secrets your policies reference, e.g.:
npx wrangler secret put STRIPE_RO --name zeroness-broker
```

## 4. Deploy the Egress Worker (enforcement)

It binds the Broker DO by `script_name` — deploy the Broker first.

```bash
pnpm -C packages/egress deploy
# note its URL, e.g. https://zeroness-egress.<acct>.workers.dev
```

## 5. Deploy the example app

```bash
# set EGRESS_URL in examples/governed-sandbox/wrangler.jsonc to the URL from step 4
pnpm -C examples/governed-sandbox deploy
# note its URL, e.g. https://zeroness-example.<acct>.workers.dev
```

## 6. Validate (Phase 0 — the load-bearing proof)

```bash
node scripts/validate.mjs https://zeroness-example.<acct>.workers.dev
```

Expected:

```
✓ allow-listed host reachable (github → 200)
✓ default-deny blocks example.com
✓ audit recorded an allow
✓ audit recorded a deny
✓ no long-lived secret surfaced to the sandbox
5/5 guarantees held.
```

If **default-deny does NOT block example.com**, the sandbox has a network path
that bypasses the Egress Worker — that is the single most important thing to
learn, and it tells you the egress steering (proxy env / outbound-intercept)
isn't capturing all traffic yet. Fix the steering before trusting the network
policy. (See `SECURITY.md` → Residual risks.)

## Notes

- **Egress steering.** zeroness sets `HTTP(S)_PROXY` in the sandbox and relies on
  Cloudflare Sandbox's outbound-intercept. Confirm your image's clients honor the
  proxy; for stubborn clients, route via the intercept hook.
- **TLS interception (optional).** Set `tlsIntercept: true` in the sandbox config
  to mint a per-session CA (`@zeroness/tls`), trust it in the box, and hand it to
  the Broker. Terminating TLS at the interception point is the remaining wiring;
  prefer the L7 proxy path unless you need deep inspection.
