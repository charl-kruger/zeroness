# API Reference

Full surface for every package (v0.1.x). Types are TypeScript.

## `@zeroness/core`

### `class Zeroness`

```ts
new Zeroness(options: ZeronessOptions)

interface ZeronessOptions {
  sandboxBinding: unknown;          // env.Sandbox (the @cloudflare/sandbox binding)
  broker: DurableObjectNamespace;   // env.ZERONESS_BROKER (the ZeronessBroker DO)
  egressUrl: string;                // public URL of the Egress Worker
  getSandbox: (binding, id) => CfSandbox | Promise<CfSandbox>; // from "@cloudflare/sandbox"
}

zeroness.sandbox(id: string, config?: ZeronessConfig): Promise<ZeronessSandbox>
zeroness.resume(snapshotRef: string, id?: string): Promise<ZeronessSandbox>
```

### `interface ZeronessConfig`

```ts
{
  network?:   NetworkPolicy;                 // default: { default: "deny" }
  resources?: ResourceMap;
  snapshotOn?: "shutdown" | "never";         // checkpoint FS to R2 on destroy()
  tlsIntercept?: boolean;                    // opt-in per-session MITM CA (see @zeroness/tls)
  agentUrl?: string;                         // URL of zeronessd; enables agent-verified exec + snapshot
}
```

### `class ZeronessSandbox`

```ts
readonly sessionId: string;

exec(command: string, opts?): Promise<{ stdout: string; stderr?: string; exitCode: number; success: boolean }>
createCodeContext(opts: { language: string }): Promise<unknown>
runCode(ctxOrCode: unknown, codeOrOpts?): Promise<unknown>
writeFile(path: string, data: string | Uint8Array, opts?): Promise<unknown>   // "cap:name://p" → capability proxy
readFile(path: string, opts?): Promise<{ content: string } | string | unknown>
snapshot(): Promise<string>                 // requires config.agentUrl; returns "snap_<sha256>"
audit(): Promise<Array<{ ts: number; event: string; detail: unknown }>>
destroy(): Promise<void>                     // revoke session; snapshot first if snapshotOn:"shutdown"
```

### Policy types

```ts
type Verdict = "allow" | "deny" | "ask";

interface NetworkPolicy {
  default: "deny" | "allow";
  allow?: Rule[];        // first match wins
  deny?:  Rule[];        // evaluated first; always wins
  transform?: Rule[];    // layered onto an allowed request
}

interface Rule {
  host: string;          // "api.github.com" | "*.pythonhosted.org" | "*"
  methods?: string[];    // omit = all
  path?: string;         // glob: "*" within a segment, "**" across segments
  verdict?: Verdict;     // default "allow" in allow[], "deny" in deny[]
  identity?: string;     // "cap:<name>", brokered token injected on egress
  forwardURL?: string;   // re-origin to a trusted gateway
  rewrite?: { headers?: Record<string, string | null>; path?: string }; // null header = delete
}

// pure evaluator (used by the Broker and the simulator)
evaluate(policy: NetworkPolicy, req: { host; method; path }): Decision
interface Decision { verdict: Verdict; identity?: string; forwardURL?: string; rewrite?; reason: string }
```

### Capability types

```ts
type ResourceBinding =
  | { r2: string; mode?: "ro" | "rw"; prefix?: string }
  | { d1: string; mode?: "ro" | "rw" }
  | { kv: string; mode?: "ro" | "rw"; prefix?: string }
  | { queue: string }
  | { secret: string }        // secret name resolved in the Broker
  | { accessToken: string }   // access-token/OIDC identity name
  | { oidc: { audience: string; subject?: string; ttlSeconds?: number } };

type ResourceMap = Record<string, ResourceBinding>;   // "cap:<key>" is the handle

parseCap(uri): { handle; name; path } | null          // "cap:reports://a.csv"
isCap(uri): boolean
mintOpaqueToken(): string                              // "zn_<48 hex>"
```

### Governed sandbox (enforced network jail)

The enforced network boundary over untrusted in-container code. Proven live
(`LIVE-VALIDATION.md`). See [recipes.md](./recipes.md) for the full walkthrough.

```ts
// Wrap the @cloudflare/sandbox (or @cloudflare/containers) base class into a
// governed container DO: enableInternet=false + interceptHttps=true + a
// Broker-backed catch-all `outbound` handler. `base` is passed in so core keeps
// no hard dependency on the SDK package.
createGovernedSandbox(base, options?: GovernedSandboxOptions): typeof base

interface GovernedSandboxOptions {
  brokerBinding?: string;                 // env key for the Broker DO; default "ZERONESS_BROKER"
  tokenFor?: (ctx: { sandboxId?: string }) => string; // default: `sandbox:<sandboxId>`
}

// Register a policy + resources for a sandbox id, under the same token the
// governed `outbound` handler derives. Call before the sandbox makes a request.
registerGovernedSession(
  broker: DurableObjectNamespace,
  sandboxId: string,
  init: { policy: NetworkPolicy; resources?: ResourceMap; pubKey?: string },
): Promise<{ handleTokens: Record<string, string> }>

governedSessionToken(sandboxId: string): string  // "sandbox:<id>"
makeOutboundHandler(options?): (req, env, ctx) => Promise<Response> // the handler alone
```

Requirements in wrangler config: `compatibility_flags` includes
`enable_ctx_exports`, and the entrypoint does
`export { ContainerProxy } from "@cloudflare/containers"`. Interception MITMs TLS
with the Cloudflare containers CA (present at runtime at
`/etc/cloudflare/certs/cloudflare-containers-ca.crt`); the standard
`cloudflare/sandbox` base image already trusts it, so plain in-container HTTPS is
clean and still governed. Enforcement does not depend on the CA: a denied host
is blocked at the handler regardless. On a custom base image that lacks the CA,
point clients at that cert path or a client that trusts nothing fails closed.

### Signing

```ts
generateSessionKey(): Promise<CryptoKeyPair>           // Ed25519
signCommand(priv, env, body): Promise<{ envelope; signature }>
verifyCommand(pub, envelope, signature, body, opts?): Promise<{ ok: true } | { ok: false; reason }>
exportPublicKeyRaw / importPublicKeyRaw / sha256Hex / randomNonce
```

## `@zeroness/policy`

```ts
lint(policy: NetworkPolicy): Finding[]                 // { level: "error"|"warn"|"info"; message }
simulate(policy, requests: RequestInfo[]): Array<{ req; decision }>
formatSimulation(rows): string                         // "✓/?/✗ METHOD host/path → verdict …"
```

## `@zeroness/gatekeeper`

```ts
class ApprovalStore {
  constructor(state?: ApprovalState);
  create(req): Approval;                 // pending
  approve(id, by?, ttlMs?, now?): Approval | undefined;   // grants method+url for ttl
  deny(id, by?, now?): Approval | undefined;
  isGranted(method, url, now?): boolean; // a live grant covers this request?
  sweep(now?): void;                     // drop expired grants
  state: ApprovalState;                  // serializable, persisted by the Broker DO
}
approvalKey(method, url): string
emptyApprovalState(): ApprovalState

interface GatekeeperAdapter { onApprovalRequested(req: ApprovalRequest): Promise<void>; }
class ManualGatekeeper implements GatekeeperAdapter          // no-op; resolve via Broker API
class WebhookGatekeeper implements GatekeeperAdapter         // POST pending approvals to a URL
class CloudflareOSGatekeeper implements GatekeeperAdapter    // bridge to a Cloudflare OS Gatekeeper
```

## `@zeroness/tls`  (opt-in TLS interception)

```ts
generateSessionCA(opts?: { commonName?; days? }): Promise<SessionCA>   // ECDSA P-256
issueLeaf(ca: SessionCA, host: string, opts?: { minutes? }): Promise<{ certPem; keyPem }>
installCACommand(certPem: string): string   // shell to trust the CA in a Debian/Ubuntu sandbox
```

## `@zeroness/broker` (Durable Object)

`class ZeronessBroker`, deployed as a Worker; addressed by binding, keyed per
session token. HTTP surface (called by core and the Egress Worker):

| Method + path | Purpose |
|---------------|---------|
| `POST /session` | register session (policy, resources, pubKey) → `{ handleTokens }` |
| `DELETE /session` | revoke |
| `POST /authorize` | `{ token, url, method }` → `{ verdict, target, injectHeaders?, dropHeaders?, approvalId? }` |
| `POST /command` | record a signed command (audit + seq) |
| `GET /audit` · `POST /audit` | read / append the audit log |
| `GET /approvals` | list pending approvals |
| `GET/POST /approval/:id[/approve\|/deny]` | read / resolve an approval |
| `POST /cap/:name` · `GET /cap/:name?path=` | capability write / read (token-checked) |
| `POST /snapshot/upload` · `GET /snapshot/:ref` | content-addressed snapshot store / fetch |
| `POST /tls-ca` | store the per-session MITM CA |

`Env`: `SNAPSHOTS?: R2Bucket`, `SECRETS?: Record<string,string>`, `GATEKEEPER_URL?`,
plus dynamic D1/KV bindings resolved by name.

## `@zeroness/egress` (Worker)

Default-export fetch handler. Routes:
- **egress** (default): identify session by token → Broker `/authorize` → enforce
  (deny 403 / ask 451 / allow: inject identity + rewrite → forward, `redirect:"manual"`).
- `POST /__zeroness/snapshot/upload` → Broker `/snapshot/upload`.
- `GET/POST /__zeroness/cap/<name>` → Broker `/cap/<name>` (token-checked).
- `POST /__zeroness/heartbeat` → Broker audit.

`Env`: `ZERONESS_BROKER: DurableObjectNamespace`.

## `@zeroness/agent`, `zeronessd`

In-sandbox HTTP agent (default `127.0.0.1:9787`). Boot env (injected by core):
`ZERONESS_PUBKEY`, `ZERONESS_SESSION`, `ZERONESS_EGRESS_URL`, `ZERONESS_CAPS`,
`ZERONESS_AGENT_PORT?`. Endpoints: `POST /command` (verify → dispatch
exec/writeFile/readFile/snapshot), `GET /health`, `GET/POST /cap/<name>` (forwards
to the Egress cap route). Heartbeats to the Broker via the Egress Worker.

## Injected sandbox environment

When `Zeroness.sandbox()` creates a session, core sets in the sandbox:
`HTTP_PROXY`/`HTTPS_PROXY` (→ Egress Worker, session token as basic-auth
password), `ZERONESS_SESSION`, `ZERONESS_PUBKEY`, `ZERONESS_EGRESS_URL`,
`ZERONESS_CAPS`.

Note: the `HTTP(S)_PROXY` vars only steer clients that honor them; a process can
ignore them and reach the network directly. They are a convenience for
cooperative HTTP clients and the capability routes, **not** the enforced network
jail. For an enforced boundary over untrusted code (raw `curl` included), use
`createGovernedSandbox` (above), which mediates egress at the container network
layer.
