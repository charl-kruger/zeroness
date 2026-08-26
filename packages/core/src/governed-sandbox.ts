/**
 * Governed sandbox — the network jail for untrusted in-container code.
 *
 * This is the mechanism proven live in /LIVE-VALIDATION.md. It turns a Cloudflare
 * Sandbox container into one whose entire outbound network is mediated by the
 * zeroness Broker:
 *
 *   - `enableInternet = false` — the container has NO direct route to the network.
 *   - `interceptHttps = true`  — ALL outbound HTTPS is terminated by a per-container
 *     MITM and handed to the Worker, so even a raw in-container `curl` (any process,
 *     not just the SDK's own fetch) is intercepted at the network layer.
 *   - a catch-all `outbound` handler runs in the Worker (which has normal internet)
 *     and asks the Broker to authorize each request, inject brokered identity for
 *     allowed hosts, and audit every crossing.
 *
 * Untrusted code cannot bypass this: without a direct route, its only path out is
 * the handler, and a client that does not trust the interception CA simply fails
 * its TLS handshake (fail-closed).
 *
 * Usage in your Worker entrypoint:
 *
 *   import { Sandbox as BaseSandbox } from "@cloudflare/sandbox";
 *   import { createGovernedSandbox } from "@zeroness/core";
 *   export { ContainerProxy } from "@cloudflare/containers";
 *
 *   export const Sandbox = createGovernedSandbox(BaseSandbox);
 *
 * Requirements in wrangler config:
 *   - compatibility_flags include "enable_ctx_exports"
 *   - `export { ContainerProxy } from "@cloudflare/containers"` in the entrypoint
 *
 * And register a policy for each sandbox id before it makes requests:
 *
 *   await registerGovernedSession(env.ZERONESS_BROKER, id, {
 *     policy: { default: "deny", allow: [{ host: "api.github.com", methods: ["GET"] }] },
 *     resources: { gh: { accessToken: env.GH_TOKEN } },
 *   });
 */

import type { NetworkPolicy } from "./policy";
import type { ResourceMap } from "./capabilities";

/** The env available to the static `outbound` handler. It must expose the Broker DO. */
export interface GovernedEnv {
  [key: string]: unknown;
}

/**
 * The `ctx` the container runtime passes to the static `outbound` handler.
 * `containerId` is the container Durable Object's id (`this.ctx.id.toString()`),
 * i.e. the stable value `registerGovernedSession` keys the session under. Note
 * there is no sandbox *name* here — the DO id is one-way, so both the handler and
 * the registration side key on the id.
 */
export interface OutboundCtx {
  containerId?: string;
  className?: string;
}

export interface GovernedSandboxOptions {
  /**
   * Name of the Broker Durable Object binding on `env`. Default "ZERONESS_BROKER".
   */
  brokerBinding?: string;
  /**
   * Derive the Broker session token from the outbound ctx. Must match the token a
   * session was registered under (see `registerGovernedSession`). Default:
   * `sandbox:<containerId>`.
   */
  tokenFor?: (ctx: OutboundCtx) => string;
}

const DEFAULT_BROKER_BINDING = "ZERONESS_BROKER";
const defaultTokenFor = (ctx: OutboundCtx): string => `sandbox:${ctx?.containerId ?? "unknown"}`;

interface AuthorizeResult {
  verdict: "allow" | "deny" | "ask";
  reason?: string;
  target?: string;
  injectHeaders?: Record<string, string>;
  dropHeaders?: string[];
  approvalId?: string;
}

/** The token a governed session is keyed under, from the container DO id. */
export function governedSessionToken(containerId: string): string {
  return `sandbox:${containerId}`;
}

/**
 * The container Durable Object id for a sandbox name, as a string — the value the
 * outbound handler sees as `ctx.containerId` and the key a session is registered
 * under. `getSandbox(ns, name)` resolves to `ns.idFromName(name)`, so this matches.
 * (Use a DNS-safe name: lowercase, no leading/trailing hyphen.)
 */
export function sandboxContainerId(sandboxNs: DurableObjectNamespace, name: string): string {
  return sandboxNs.idFromName(name).toString();
}

/**
 * Build the catch-all outbound handler that mediates every intercepted request
 * through the Broker. Exposed on its own so a subclass can compose it, but most
 * callers should use `createGovernedSandbox`.
 */
export function makeOutboundHandler(options: GovernedSandboxOptions = {}) {
  const brokerBinding = options.brokerBinding ?? DEFAULT_BROKER_BINDING;
  const tokenFor = options.tokenFor ?? defaultTokenFor;

  return async function outbound(request: Request, env: GovernedEnv, ctx: OutboundCtx): Promise<Response> {
    const ns = env[brokerBinding] as DurableObjectNamespace | undefined;
    if (!ns) return new Response(`zeroness: broker binding '${brokerBinding}' not found`, { status: 500 });

    const token = tokenFor(ctx);
    const broker = ns.get(ns.idFromName(`token:${token}`));

    // Audit the crossing attempt (fire-and-forget).
    void broker
      .fetch("https://zeroness.broker/audit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ event: "outbound:hit", detail: { url: request.url, containerId: ctx?.containerId ?? null } }),
      })
      .catch(() => {});

    const res = await broker.fetch("https://zeroness.broker/authorize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, url: request.url, method: request.method }),
    });
    if (res.status === 401) return new Response("zeroness: unknown or revoked session", { status: 403 });

    const decision = (await res.json()) as AuthorizeResult;
    if (decision.verdict === "deny") return new Response(`zeroness: blocked by policy${decision.reason ? " (" + decision.reason + ")" : ""}`, { status: 403 });
    if (decision.verdict === "ask") {
      return new Response(
        JSON.stringify({ error: "approval_required", approvalId: decision.approvalId, reason: decision.reason }),
        { status: 451, headers: { "content-type": "application/json", "x-zeroness-approval": decision.approvalId ?? "" } },
      );
    }

    const fwd = new Request(decision.target ?? request.url, request);
    for (const h of decision.dropHeaders ?? []) fwd.headers.delete(h);
    for (const [k, v] of Object.entries(decision.injectHeaders ?? {})) fwd.headers.set(k, v);
    return fetch(fwd);
  };
}

/**
 * Wrap a Cloudflare Sandbox (or Container) base class into a governed one: no
 * direct internet, all outbound HTTPS intercepted, every request mediated by the
 * Broker. `base` is passed in so @zeroness/core keeps no hard dependency on the
 * @cloudflare/sandbox package.
 *
 * Returns a subclass you export as your container Durable Object.
 */
export function createGovernedSandbox<T extends abstract new (...args: any[]) => object>(
  base: T,
  options: GovernedSandboxOptions = {},
): T {
  const Base = base as unknown as new (...args: any[]) => object;

  class GovernedSandbox extends Base {
    // No direct network route out of the container.
    enableInternet = false;
    // Intercept ALL outbound HTTPS at the container network layer, so raw
    // processes (not just SDK fetch) are routed through `outbound`.
    interceptHttps = true;
  }

  // The container runtime reads the static `outbound` as the catch-all handler.
  (GovernedSandbox as unknown as { outbound: unknown }).outbound = makeOutboundHandler(options);

  return GovernedSandbox as unknown as T;
}

export interface RegisterGovernedSessionInit {
  policy: NetworkPolicy;
  resources?: ResourceMap;
  /** Optional agent public key (raw hex) if you also verify signed commands. */
  pubKey?: string;
}

/**
 * Register a policy + resources for a sandbox with the Broker, under the same
 * token the governed `outbound` handler derives (`sandbox:<containerId>`). Pass
 * the Sandbox binding and the same `name` you give `getSandbox(env.Sandbox, name)`
 * — the container DO id is computed from it so both sides agree. Call this before
 * the sandbox makes any request. Returns the Broker's session registration (cap
 * handle tokens).
 */
export async function registerGovernedSession(
  broker: DurableObjectNamespace,
  sandboxNs: DurableObjectNamespace,
  name: string,
  init: RegisterGovernedSessionInit,
): Promise<{ handleTokens: Record<string, string> }> {
  const containerId = sandboxContainerId(sandboxNs, name);
  const token = governedSessionToken(containerId);
  const stub = broker.get(broker.idFromName(`token:${token}`));
  const res = await stub.fetch("https://zeroness.broker/session", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      sessionId: name,
      sessionToken: token,
      pubKey: init.pubKey ?? "x",
      policy: init.policy,
      resources: init.resources ?? {},
    }),
  });
  if (!res.ok) throw new Error(`broker /session -> ${res.status}: ${await res.text()}`);
  return (await res.json()) as { handleTokens: Record<string, string> };
}
