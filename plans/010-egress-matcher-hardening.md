# Plan 010: Harden the egress policy matcher (canonicalization parity, dest-IP floor, host normalization)

> Grounded in a live red-team of a production sandbox egress firewall (Vercel
> Sandbox). Each item below is a differential we **proved** breaks a real-world
> egress control. These fixes apply to zeroness on Cloudflare *and* self-hosted
> (celld) — they harden the pure policy engine, so every deployment benefits.

## Status

- **Priority**: P1 (security)
- **Effort**: M
- **Risk**: MED (changes matching semantics; must not loosen existing allow/deny)
- **Depends on**: none (touches `@zeroness/core` policy + `@zeroness/broker`)
- **Category**: security
- **Planned at**: commit `085a7ac` (branch `feat/celld-support`), 2026-09-01

## Why this matters — the three proven differentials

A red-team of Vercel Sandbox's egress firewall found (and confirmed live) three
matcher/enforcement gaps. zeroness's engine has the same shapes:

1. **Path canonicalization differential.** The firewall normalized `../` but did
   **not** percent-decode before matching, while the upstream did both. So
   `%73ecret` (→ `/secret`) **evades** a path-scoped rule the origin honors, and
   `%2f..%2f` makes a rule **fire** while a normalizing origin routes the request
   out of scope (attaching a brokered secret to an unintended endpoint).
   zeroness matches the **raw** `u.pathname` — `new URL()` resolves dot-segments
   but does **not** percent-decode — so `path` rules mismatch what the origin
   decodes. Same bug class.
2. **No internal-address floor.** An allowed *name* that resolves to an internal
   IP (`169.254.169.254` metadata, RFC1918, loopback, link-local) reached
   internal services. zeroness does `fetch(decision.target)` with **no
   destination filtering** — and on self-hosted celld a Worker's `fetch` *can*
   reach `localhost`/RFC1918, so this is worse there than on Cloudflare.
3. **Host normalization gaps** (trailing dot / IDN / wildcard-to-regex). A
   trailing-dot FQDN (`evil.com.`) can slip an exact matcher. zeroness lowercases
   the host but does not strip a trailing dot (audit finding #9).

(Two Vercel controls zeroness already gets right: it uses `redirect: "manual"`
at egress — so brokered creds are not carried across redirects — and it matches
on the full target-URL host, not SNI alone. Keep both.)

## Current state

- `packages/core/src/policy.ts` — the pure matcher. `ruleMatches` (verbatim):

```ts
function ruleMatches(rule: Rule, req: RequestInfo): boolean {
  if (!hostToRegExp(rule.host).test(req.host.toLowerCase())) return false;
  if (rule.methods && !rule.methods.map((m) => m.toUpperCase()).includes(req.method.toUpperCase())) return false;
  if (rule.path && !pathToRegExp(rule.path).test(req.path)) return false;   // req.path is RAW (encoded)
  return true;
}
```

  `hostToRegExp` lowercases the pattern but neither side strips a trailing dot.
  `pathToRegExp` builds a glob regex; it is tested against the raw `req.path`.

- `packages/broker/src/index.ts` `authorize` builds the RequestInfo:

```ts
const u = new URL(body.url);
const decision = evaluate(s.policy, { host: u.hostname, method: body.method, path: u.pathname });
```

  `u.pathname` keeps `%73` encoded; `u.hostname` is punycoded + lowercased by URL
  but may retain a trailing dot. The governed-sandbox `outbound` handler
  (`packages/core/src/governed-sandbox.ts`) and `@zeroness/policy` `simulate()`
  also call `evaluate` — so fixing it inside `evaluate` covers every caller.

- `packages/egress/src/index.ts` upstream fetch (already good on redirects):

```ts
const res = await fetch(new Request(decision.target, { method: req.method, headers, body: req.body, redirect: "manual" }));
```

- Conventions: `policy.ts` is pure + dependency-free + unit-tested
  (`policy.test.ts`); the broker has an in-process integration test. Match both.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Install | `pnpm install` | exit 0 |
| Build | `pnpm --filter @zeroness/core build` | exit 0 |
| Test core | `pnpm --filter @zeroness/core test` | all pass |
| Test broker | `pnpm --filter @zeroness/broker test` | all pass |
| Typecheck | `pnpm --filter @zeroness/core typecheck` | exit 0 |

## Scope

**In scope**:
- `packages/core/src/policy.ts` (canonicalize inside `evaluate`; export a dest-IP predicate)
- `packages/core/src/policy.test.ts` (matcher differential tests)
- `packages/core/src/index.ts` (export the new predicate if placed in a new file)
- `packages/broker/src/index.ts` (`authorize`: apply the internal-address floor)
- `packages/broker/src/index.test.ts` (internal-address deny test)

**Out of scope**:
- The MITM/transparent-proxy `authority == SNI` binding and DNS-rebind
  resolve-and-pin — those belong to the celld network-jail path; see
  `plans/009-celld-integration.md` (Phase 2/3). This plan is the pure matcher +
  literal-target floor.
- Changing the glob semantics (`*` vs `**`) or the allow/deny order.

## Steps

### Step 1: Canonicalize host + path inside `evaluate`

Normalize the RequestInfo once, at the top of `evaluate`, so all callers get
identical, upstream-faithful matching. Add helpers to `policy.ts`:

```ts
/** Percent-decode to a fixed point, then resolve ./.. dot-segments. Matches what
 *  a fully-decoding origin sees, closing the encode/normalize differential. */
function canonicalPath(path: string): string {
  let p = path;
  for (let i = 0; i < 5; i++) {                 // bounded: catch double-encoding (%2573 -> %73 -> s)
    let decoded: string;
    try { decoded = decodeURIComponent(p); } catch { break; }
    if (decoded === p) break;
    p = decoded;
  }
  // resolve dot-segments (RFC 3986 §5.2.4)
  const out: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "..") out.pop();
    else if (seg !== ".") out.push(seg);
  }
  return out.join("/") || "/";
}

/** Lowercase and strip a single trailing dot (root-anchored FQDN). */
function canonicalHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}
```

Apply them at the start of `evaluate`:

```ts
export function evaluate(policy: NetworkPolicy, req: RequestInfo): Decision {
  const r: RequestInfo = { host: canonicalHost(req.host), method: req.method, path: canonicalPath(req.path) };
  // …use `r` everywhere below instead of `req`…
```

Replace the remaining `req` uses in `evaluate` (the deny/allow/transform loops
pass `req` to `ruleMatches`) with `r`. `ruleMatches` already lowercases the host;
that is now redundant but harmless — leave it.

**Verify:** `pnpm --filter @zeroness/core typecheck` → exit 0.

### Step 2: Destination-address floor

Add a predicate that flags targets which must never be reachable regardless of
policy, and export it. Place in `policy.ts` (or a small `egress-guard.ts`):

```ts
/** True if `host` is a literal internal/metadata address that must never be an
 *  egress target (defense against SSRF / DNS-rebind to internal services). */
export function isForbiddenEgressHost(host: string): boolean {
  const h = canonicalHost(host);
  if (h === "localhost" || h === "metadata.google.internal") return true;
  // IPv6 literals (URL host keeps brackets off in hostname): loopback, ULA, link-local
  if (h === "::1" || h === "::" ) return true;
  if (/^(fc|fd)[0-9a-f]{2}:/i.test(h)) return true;               // fc00::/7 ULA
  if (/^fe[89ab][0-9a-f]:/i.test(h)) return true;                 // fe80::/10 link-local
  // IPv4 literals
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 10 || a === 127 || a === 0) return true;             // 10/8, loopback, 0/8
    if (a === 169 && b === 254) return true;                       // 169.254/16 link-local + metadata
    if (a === 172 && b >= 16 && b <= 31) return true;              // 172.16/12
    if (a === 192 && b === 168) return true;                       // 192.168/16
    if (a === 100 && b >= 64 && b <= 127) return true;             // 100.64/10 CGNAT (sandbox fabric)
  }
  return false;
}
```

Export it from `packages/core/src/index.ts`. Apply it in the Broker `authorize`
as a hard deny, **before** policy evaluation (so it covers both the egress-worker
and governed-sandbox paths, which both call `authorize`):

```ts
const u = new URL(body.url);
if (isForbiddenEgressHost(u.hostname)) {
  await this.append({ ts: Date.now(), event: "egress:deny", detail: { url: body.url, reason: "internal address blocked" } });
  return json({ verdict: "deny", reason: "internal address blocked", target: body.url });
}
const decision = evaluate(s.policy, { host: u.hostname, method: body.method, path: u.pathname });
```

> Note the limit: this blocks **literal** internal targets. A public hostname
> that *resolves* to an internal IP (DNS-rebind) needs resolve-and-pin at the
> connection layer — out of scope here, covered by the transparent-proxy in
> plan 009's celld path. State this in the maintenance note.

**Verify:** `pnpm --filter @zeroness/broker typecheck` → exit 0.

### Step 3: Tests

`policy.test.ts` — add:

```ts
it("matches a path rule against the decoded path (percent-encoding cannot evade)", () => {
  const p: NetworkPolicy = { default: "deny", allow: [{ host: "api.x.com", path: "/secret" }] };
  expect(evaluate(p, { host: "api.x.com", method: "GET", path: "/%73ecret" }).verdict).toBe("allow");
});

it("normalizes encoded dot-segments so a rule cannot fire out of scope", () => {
  const p: NetworkPolicy = { default: "deny", allow: [{ host: "api.x.com", path: "/pub/**" }] };
  // decodes+normalizes to /admin — must NOT match /pub/**
  expect(evaluate(p, { host: "api.x.com", method: "GET", path: "/pub/%2e%2e/admin" }).verdict).toBe("deny");
});

it("treats a trailing-dot FQDN as the same host", () => {
  const p: NetworkPolicy = { default: "deny", deny: [{ host: "evil.com" }], allow: [{ host: "*" }] };
  expect(evaluate(p, { host: "evil.com.", method: "GET", path: "/" }).verdict).toBe("deny");
});
```

`policy.test.ts` — also unit-test `isForbiddenEgressHost`:

```ts
it("flags internal + metadata targets", () => {
  for (const h of ["169.254.169.254", "127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.0.1", "localhost", "::1", "metadata.google.internal", "100.64.0.5"])
    expect(isForbiddenEgressHost(h)).toBe(true);
  for (const h of ["api.github.com", "8.8.8.8", "203.0.113.5"])
    expect(isForbiddenEgressHost(h)).toBe(false);
});
```

`broker/index.test.ts` — add an integration deny:

```ts
it("hard-denies an egress request to an internal address", async () => {
  const d = await (await b.fetch(j("/authorize", "POST", { token: TOK, url: "http://169.254.169.254/latest/meta-data", method: "GET" }))).json();
  expect(d.verdict).toBe("deny");
  expect(d.reason).toMatch(/internal address/);
});
```

**Verify:** `pnpm --filter @zeroness/core test` and `pnpm --filter @zeroness/broker test` → all pass, including the new cases.

### Step 4: Full build + test

- `pnpm -r build` → exit 0
- `pnpm -r test` → all pass

## Done criteria

- [ ] `pnpm -r build` exits 0; `pnpm -r typecheck` exits 0
- [ ] `pnpm -r test` exits 0; new matcher + floor tests pass
- [ ] A `path` rule matches the **decoded** path; encoded dot-segments cannot make a rule fire out of scope; a trailing-dot host is treated as the bare host
- [ ] `authorize` hard-denies literal internal/metadata targets and audits it
- [ ] Existing policy/broker tests all still pass (no allow/deny regressions)
- [ ] `git status` shows only the in-scope files
- [ ] `plans/README.md` status row for 010 updated

## STOP conditions

- Any "Current state" excerpt doesn't match the live code (drift).
- Canonicalization changes an **existing** passing allow/deny test in a way that
  isn't obviously the intended security tightening — report before adjusting the
  test.
- `decodeURIComponent` on a legitimately-encoded path throws for a real request
  shape you did not anticipate (the helper already `break`s on throw — but report
  if you see it).

## Maintenance notes

- `canonicalPath` decodes `%2f` to `/` — i.e. it matches an origin that treats
  encoded slashes as separators. That is the conservative stance (deny/scope by
  the most-decoded form). If a specific upstream is known **not** to decode
  `%2f`, that is a per-integration exception, not a matcher default.
- The dest-IP floor is **literal-only**. DNS-rebind (public name → private IP)
  requires resolve-and-pin at connect time; that lives in the celld
  transparent-proxy (plan 009 Phase 2). Cross-reference it.
- Reviewer: confirm the floor is applied **before** `evaluate` (so it cannot be
  overridden by an `allow` rule) and that `evaluate` canonicalizes once at the
  top so every caller (broker, governed-sandbox, `simulate`) is covered.
```
