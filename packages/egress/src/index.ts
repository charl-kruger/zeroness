/**
 * edgelock — Egress Worker (the enforcement data plane).
 *
 * Every outbound request from a governed sandbox arrives here (via Cloudflare
 * Sandbox's outbound-intercept, or as an HTTP forward-proxy). This Worker:
 *   1. identifies the session from its token,
 *   2. asks the Broker for a Decision (policy eval + brokered identity),
 *   3. enforces it: deny → 403, ask → approval gate, allow → inject identity,
 *      apply rewrite/forwardURL, forward upstream, stream the response back,
 *   4. every crossing is audited by the Broker.
 *
 * The Egress Worker holds NO secrets: the Broker mints and returns the exact
 * headers to inject, per request. A compromised egress node cannot leak
 * long-lived credentials.
 */

export interface Env {
  EDGELOCK_BROKER: DurableObjectNamespace;
}

interface AuthorizeResult {
  verdict: "allow" | "deny" | "ask";
  reason: string;
  target: string;                    // final upstream URL (after forwardURL/rewrite)
  injectHeaders?: Record<string, string>; // brokered identity, minted per-request
  dropHeaders?: string[];
  approvalId?: string;               // present when verdict === "ask"
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    // ---- 1. identify the session ----
    const token = sessionToken(req);
    if (!token) return deny("missing session token", 407);

    // ---- 2. determine the intended target ----
    const target = intendedTarget(req);
    if (!target) return deny("no target", 400);

    // ---- 3. ask the Broker for a decision (it evaluates policy + mints identity) ----
    const broker = env.EDGELOCK_BROKER.get(env.EDGELOCK_BROKER.idFromName(`token:${token}`));
    const authRes = await broker.fetch("https://edgelock.broker/authorize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, url: target.toString(), method: req.method }),
    });
    if (authRes.status === 401) return deny("unknown or revoked session", 403);
    const decision = (await authRes.json()) as AuthorizeResult;

    // ---- 4. enforce ----
    if (decision.verdict === "deny") return deny(decision.reason, 403);

    if (decision.verdict === "ask") {
      // Phase 4: human-in-the-loop via Gatekeeper. Until approved, block the call.
      return new Response(
        JSON.stringify({ error: "approval_required", approvalId: decision.approvalId, reason: decision.reason }),
        { status: 451, headers: { "content-type": "application/json", "x-edgelock-approval": decision.approvalId ?? "" } },
      );
    }

    // allow → build the upstream request with brokered identity + rewrites
    const upstreamUrl = decision.target;
    const headers = new Headers(req.headers);
    headers.delete("proxy-authorization");
    headers.delete("x-edgelock-session-token");
    headers.delete("x-edgelock-target");
    for (const h of decision.dropHeaders ?? []) headers.delete(h);
    for (const [k, v] of Object.entries(decision.injectHeaders ?? {})) headers.set(k, v);

    const upstream = new Request(upstreamUrl, {
      method: req.method,
      headers,
      body: req.body,
      redirect: "manual", // never auto-follow a redirect out of policy scope
    });

    const res = await fetch(upstream);
    // strip hop-by-hop; pass the rest through
    const outHeaders = new Headers(res.headers);
    outHeaders.set("x-edgelock", "allowed");
    return new Response(res.body, { status: res.status, headers: outHeaders });
  },
};

/** Token from Proxy-Authorization basic (password), Authorization basic, or a header. */
function sessionToken(req: Request): string | null {
  const h = req.headers.get("x-edgelock-session-token");
  if (h) return h;
  const proxyAuth = req.headers.get("proxy-authorization") ?? req.headers.get("authorization");
  if (proxyAuth?.toLowerCase().startsWith("basic ")) {
    try {
      const [, pass] = atob(proxyAuth.slice(6)).split(":");
      if (pass) return pass;
    } catch { /* ignore */ }
  }
  return null;
}

/** Absolute proxy URL, or the original target carried by the intercept header. */
function intendedTarget(req: Request): URL | null {
  const explicit = req.headers.get("x-edgelock-target");
  if (explicit) { try { return new URL(explicit); } catch { return null; } }
  try {
    const u = new URL(req.url);
    // In forward-proxy mode the request line carries the absolute target.
    if (u.hostname && !u.hostname.endsWith(".workers.dev")) return u;
  } catch { /* ignore */ }
  return null;
}

function deny(reason: string, status: number): Response {
  return new Response(JSON.stringify({ error: "blocked_by_edgelock", reason }), {
    status,
    headers: { "content-type": "application/json", "x-edgelock": "denied" },
  });
}
