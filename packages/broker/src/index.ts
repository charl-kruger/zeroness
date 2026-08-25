/**
 * edgelock — Broker (Durable Object): the trust root.
 *
 * One DO instance per session (keyed by the session token). It holds the policy,
 * the resource bindings + their real credentials, the agent public key, and the
 * audit log. It is the ONLY component that touches secrets: the Egress Worker
 * asks it to authorize each request, and it returns the exact headers to inject,
 * minted fresh per call. Nothing long-lived ever leaves this DO.
 */

import { evaluate, type NetworkPolicy, type ResourceMap, type ResourceBinding, mintOpaqueToken } from "@edgelock/core";

export interface Env {
  /** R2 bucket for FS snapshots (optional in dev). */
  SNAPSHOTS?: R2Bucket;
  /** Secret values referenced by name in resource bindings. Wire real bindings/Secrets Store here. */
  SECRETS?: Record<string, string>;
}

interface SessionState {
  sessionId: string;
  sessionToken: string;
  policy: NetworkPolicy;
  resources: ResourceMap;
  handleTokens: Record<string, string>;
  pubKey: string;
  lastSeq: number;
}

interface AuditEntry { ts: number; event: string; detail: unknown }

export class EdgelockBroker {
  constructor(private state: DurableObjectState, private env: Env) {}

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    try {
      if (req.method === "POST" && path === "/session") return await this.createSession(await req.json());
      if (req.method === "POST" && path === "/authorize") return await this.authorize(await req.json());
      if (req.method === "POST" && path === "/command") return await this.recordCommand(await req.json());
      if (req.method === "POST" && path === "/audit") return await this.appendAudit(await req.json());
      if (req.method === "GET" && path === "/audit") return json(await this.getAudit());
      if (req.method === "POST" && path === "/snapshot") return await this.snapshot();
      if (req.method === "DELETE" && path === "/session") return await this.revoke();
      if ((req.method === "POST" || req.method === "GET") && path.startsWith("/cap/")) {
        return await this.capIO(req.method, path.slice(5), req.method === "POST" ? await req.json() : {});
      }
      return new Response("not found", { status: 404 });
    } catch (e) {
      return json({ error: String(e instanceof Error ? e.message : e) }, 500);
    }
  }

  // ---- lifecycle ----
  private async createSession(body: {
    sessionId: string; sessionToken: string; policy: NetworkPolicy; resources: ResourceMap; pubKey: string;
  }): Promise<Response> {
    const handleTokens: Record<string, string> = {};
    for (const name of Object.keys(body.resources ?? {})) handleTokens[name] = mintOpaqueToken();
    const s: SessionState = {
      sessionId: body.sessionId,
      sessionToken: body.sessionToken,
      policy: body.policy ?? { default: "deny" },
      resources: body.resources ?? {},
      handleTokens,
      pubKey: body.pubKey,
      lastSeq: 0,
    };
    await this.state.storage.put("session", s);
    await this.append({ ts: Date.now(), event: "session:create", detail: { sessionId: s.sessionId } });
    return json({ handleTokens });
  }

  private async revoke(): Promise<Response> {
    await this.append({ ts: Date.now(), event: "session:revoke", detail: {} });
    await this.state.storage.delete("session");
    return new Response(null, { status: 204 });
  }

  // ---- the hot path: authorize one egress request ----
  private async authorize(body: { token: string; url: string; method: string }): Promise<Response> {
    const s = await this.session();
    if (!s || s.sessionToken !== body.token) return json({ error: "unknown session" }, 401);

    const u = new URL(body.url);
    const decision = evaluate(s.policy, { host: u.hostname, method: body.method, path: u.pathname });

    if (decision.verdict === "deny") {
      await this.append({ ts: Date.now(), event: "egress:deny", detail: { url: body.url, reason: decision.reason } });
      return json({ verdict: "deny", reason: decision.reason, target: body.url });
    }

    if (decision.verdict === "ask") {
      const approvalId = mintOpaqueToken();
      await this.state.storage.put(`approval:${approvalId}`, { url: body.url, method: body.method, ts: Date.now() });
      await this.append({ ts: Date.now(), event: "egress:ask", detail: { url: body.url, approvalId, identity: decision.identity } });
      // Phase 4: forward to a Gatekeeper for async human approval.
      return json({ verdict: "ask", reason: decision.reason, target: body.url, approvalId });
    }

    // allow → mint brokered identity for the matched capability, per request
    const injectHeaders = decision.identity ? await this.mintIdentity(s, decision.identity, u) : {};
    const target = decision.forwardURL ? reorigin(decision.forwardURL, u, decision.rewrite?.path) : applyPath(u, decision.rewrite?.path);
    const dropHeaders = decision.rewrite?.headers
      ? Object.entries(decision.rewrite.headers).filter(([, v]) => v === null).map(([k]) => k)
      : [];
    if (decision.rewrite?.headers) {
      for (const [k, v] of Object.entries(decision.rewrite.headers)) if (v !== null) injectHeaders[k] = v;
    }
    await this.append({ ts: Date.now(), event: "egress:allow", detail: { url: body.url, target, identity: decision.identity ?? null } });
    return json({ verdict: "allow", reason: decision.reason, target, injectHeaders, dropHeaders });
  }

  /** Turn a capability handle into request headers — the sandbox never sees the secret. */
  private async mintIdentity(s: SessionState, cap: string, _target: URL): Promise<Record<string, string>> {
    const name = cap.replace(/^cap:/, "");
    const binding = s.resources[name] as ResourceBinding | undefined;
    if (!binding) return {};
    if ("accessToken" in binding) {
      const secret = this.secret(binding.accessToken);
      return secret ? { authorization: `Bearer ${secret}` } : {};
    }
    if ("secret" in binding) {
      const secret = this.secret(binding.secret);
      return secret ? { authorization: `Bearer ${secret}` } : {};
    }
    if ("oidc" in binding) {
      const jwt = await this.mintOidc(binding.oidc.audience, binding.oidc.subject ?? s.sessionId, binding.oidc.ttlSeconds ?? 300);
      return { authorization: `Bearer ${jwt}` };
    }
    return {};
  }

  // ---- signed command channel + audit ----
  private async recordCommand(body: { envelope: { seq: number; procedure: string }; signature: string }): Promise<Response> {
    const s = await this.session();
    if (!s) return json({ error: "no session" }, 401);
    // (Full agent-side verification lives in edgelockd; the broker tracks seq for audit + replay visibility.)
    if (body.envelope.seq > s.lastSeq) { s.lastSeq = body.envelope.seq; await this.state.storage.put("session", s); }
    await this.append({ ts: Date.now(), event: "command", detail: { procedure: body.envelope.procedure, seq: body.envelope.seq } });
    return new Response(null, { status: 204 });
  }

  private async appendAudit(body: { event: string; detail: unknown; ts?: number }): Promise<Response> {
    await this.append({ ts: body.ts ?? Date.now(), event: body.event, detail: body.detail });
    return new Response(null, { status: 204 });
  }

  private async getAudit(): Promise<AuditEntry[]> {
    return (await this.state.storage.get<AuditEntry[]>("audit")) ?? [];
  }

  // ---- capability I/O (R2 for now; D1/KV are analogous) ----
  private async capIO(method: string, name: string, body: { path?: string; data?: number[] | string }): Promise<Response> {
    const s = await this.session();
    const binding = s?.resources[name] as ResourceBinding | undefined;
    if (!s || !binding) return json({ error: "unknown capability" }, 404);
    if ("r2" in binding && this.env.SNAPSHOTS) {
      const key = `${binding.prefix ?? ""}${body.path ?? ""}`;
      if (method === "POST") {
        if (binding.mode === "ro") return json({ error: "read-only capability" }, 403);
        const data = typeof body.data === "string" ? body.data : new Uint8Array(body.data ?? []);
        await this.env.SNAPSHOTS.put(key, data);
        await this.append({ ts: Date.now(), event: "cap:write", detail: { name, key } });
        return json({ ok: true, key });
      } else {
        const obj = await this.env.SNAPSHOTS.get(key);
        await this.append({ ts: Date.now(), event: "cap:read", detail: { name, key, found: !!obj } });
        return json({ content: obj ? await obj.text() : null });
      }
    }
    return json({ error: "capability type not yet wired (D1/KV/queue)" }, 501);
  }

  private async snapshot(): Promise<Response> {
    // Real impl: signal edgelockd to tar the FS and stream it to R2, content-addressed.
    const ref = `snap_${mintOpaqueToken().slice(4)}`;
    await this.append({ ts: Date.now(), event: "snapshot", detail: { ref } });
    return json({ ref });
  }

  // ---- helpers ----
  private async session(): Promise<SessionState | undefined> {
    return this.state.storage.get<SessionState>("session");
  }
  private async append(e: AuditEntry): Promise<void> {
    const log = (await this.state.storage.get<AuditEntry[]>("audit")) ?? [];
    log.push(e);
    await this.state.storage.put("audit", log.slice(-1000));
  }
  private secret(name: string): string | undefined {
    return this.env.SECRETS?.[name] ?? (this.env as unknown as Record<string, string>)[name];
  }
  private async mintOidc(audience: string, subject: string, ttl: number): Promise<string> {
    let jwk = await this.state.storage.get<JsonWebKey>("oidc-key");
    let priv: CryptoKey;
    if (!jwk) {
      const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
      jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
      await this.state.storage.put("oidc-key", jwk);
      priv = pair.privateKey;
    } else {
      priv = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]);
    }
    const now = Math.floor(Date.now() / 1000);
    const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT" }));
    const payload = b64url(JSON.stringify({ iss: "edgelock", sub: subject, aud: audience, iat: now, exp: now + ttl, jti: mintOpaqueToken() }));
    const sig = await crypto.subtle.sign({ name: "Ed25519" }, priv, new TextEncoder().encode(`${header}.${payload}`));
    return `${header}.${payload}.${b64urlBytes(new Uint8Array(sig))}`;
  }
}

// The DO is reached via binding; a bare fetch handler keeps wrangler happy.
export default { fetch: () => new Response("edgelock broker (durable object)", { status: 200 }) };

function reorigin(base: string, orig: URL, pathOverride?: string): string {
  const b = new URL(base);
  b.pathname = pathOverride ?? orig.pathname;
  b.search = orig.search;
  return b.toString();
}
function applyPath(orig: URL, pathOverride?: string): string {
  if (!pathOverride) return orig.toString();
  const u = new URL(orig.toString());
  u.pathname = pathOverride;
  return u.toString();
}
function json(v: unknown, status = 200): Response {
  return new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
}
function b64url(s: string): string { return b64urlBytes(new TextEncoder().encode(s)); }
function b64urlBytes(u: Uint8Array): string {
  let s = ""; for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
