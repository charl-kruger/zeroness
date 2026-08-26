/**
 * zeroness — Egress Worker (the enforcement data plane).
 *
 * Every outbound request from a governed sandbox arrives here (via Cloudflare
 * Sandbox's outbound-intercept, or as an HTTP forward-proxy). This Worker:
 *   1. identifies the session from its token,
 *   2. asks the Broker for a Decision (policy eval + brokered identity),
 *   3. enforces it: deny → 403, ask → approval gate, allow → inject identity,
 *      apply rewrite/forwardURL, forward upstream, stream the response back,
 *   4. every crossing is audited by the Broker.
 *
 * It also exposes a capability endpoint (`/__zeroness/cap/<name>`) so in-sandbox
 * code can read/write R2/D1/KV by opaque handle. The Egress Worker holds NO
 * secrets: the Broker mints identity and resolves capabilities, per request.
 */

import { sessionToken, intendedTarget, capName, deny } from "./lib";

export interface Env {
  ZERONESS_BROKER: DurableObjectNamespace;
}

interface AuthorizeResult {
  verdict: "allow" | "deny" | "ask";
  reason: string;
  target: string;
  injectHeaders?: Record<string, string>;
  dropHeaders?: string[];
  approvalId?: string;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const token = sessionToken(req);
    if (!token) return deny("missing session token", 407);
    const broker = env.ZERONESS_BROKER.get(env.ZERONESS_BROKER.idFromName(`token:${token}`));

    // ---- capability op: forward to the Broker's cap resolver ----
    const cap = capName(req);
    if (cap) {
      const body = req.method === "POST" ? await req.text() : JSON.stringify(queryToCapArgs(req));
      // The Broker checks the session token owns this capability before touching any binding.
      const res = await broker.fetch(`https://zeroness.broker/cap/${encodeURIComponent(cap)}`, {
        method: req.method === "POST" ? "POST" : "GET",
        headers: { "content-type": "application/json", "x-zeroness-token": token },
        body: req.method === "POST" ? body : undefined,
      });
      return new Response(res.body, { status: res.status, headers: { "content-type": "application/json" } });
    }

    // ---- egress op ----
    const target = intendedTarget(req);
    if (!target) return deny("no target", 400);

    const authRes = await broker.fetch("https://zeroness.broker/authorize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, url: target.toString(), method: req.method }),
    });
    if (authRes.status === 401) return deny("unknown or revoked session", 403);
    const decision = (await authRes.json()) as AuthorizeResult;

    if (decision.verdict === "deny") return deny(decision.reason, 403);

    if (decision.verdict === "ask") {
      return new Response(
        JSON.stringify({ error: "approval_required", approvalId: decision.approvalId, reason: decision.reason }),
        { status: 451, headers: { "content-type": "application/json", "x-zeroness-approval": decision.approvalId ?? "" } },
      );
    }

    const headers = new Headers(req.headers);
    for (const h of ["proxy-authorization", "x-zeroness-session-token", "x-zeroness-target"]) headers.delete(h);
    for (const h of decision.dropHeaders ?? []) headers.delete(h);
    for (const [k, v] of Object.entries(decision.injectHeaders ?? {})) headers.set(k, v);

    const res = await fetch(new Request(decision.target, { method: req.method, headers, body: req.body, redirect: "manual" }));
    const outHeaders = new Headers(res.headers);
    outHeaders.set("x-zeroness", "allowed");
    return new Response(res.body, { status: res.status, headers: outHeaders });
  },
};

/** GET cap args come from the query string: ?path=…&query=… */
function queryToCapArgs(req: Request): Record<string, string> {
  const q = new URL(req.url).searchParams;
  const args: Record<string, string> = {};
  for (const k of ["path", "query"]) { const v = q.get(k); if (v !== null) args[k] = v; }
  return args;
}
