/**
 * zeroness — Broker (Durable Object): the trust root.
 *
 * One DO instance per session (keyed by the session token). It holds the policy,
 * the resource bindings + their real credentials, the agent public key, the
 * approval state, and the audit log. It is the ONLY component that touches
 * secrets: the Egress Worker asks it to authorize each request, and it returns
 * the exact headers to inject, minted fresh per call.
 */

import { evaluate, type NetworkPolicy, type ResourceMap, type ResourceBinding, mintOpaqueToken } from "@zeroness/core";
import { ApprovalStore, emptyApprovalState, type ApprovalState, ManualGatekeeper, WebhookGatekeeper, type GatekeeperAdapter } from "@zeroness/gatekeeper";

export interface Env {
  SNAPSHOTS?: R2Bucket;
  SECRETS?: Record<string, string>;
  /** Optional webhook that receives pending approvals. */
  GATEKEEPER_URL?: string;
  /** Dynamic D1/KV/etc. bindings are resolved by name from env. */
  [binding: string]: unknown;
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

export class ZeronessBroker {
  private gatekeeper: GatekeeperAdapter;
  constructor(private state: DurableObjectState, private env: Env) {
    this.gatekeeper = env.GATEKEEPER_URL ? new WebhookGatekeeper(env.GATEKEEPER_URL) : new ManualGatekeeper();
  }

  async fetch(req: Request): Promise<Response> {
    const { pathname: path } = new URL(req.url);
    try {
      if (req.method === "POST" && path === "/session") return await this.createSession(await req.json());
      if (req.method === "DELETE" && path === "/session") return await this.revoke();
      if (req.method === "POST" && path === "/authorize") return await this.authorize(await req.json());
      if (req.method === "POST" && path === "/command") return await this.recordCommand(await req.json());
      if (req.method === "POST" && path === "/audit") return await this.appendAudit(await req.json());
      if (req.method === "GET" && path === "/audit") return json(await this.getAudit());
      if (req.method === "GET" && path === "/approvals") return json(await this.listApprovals());
      const ap = path.match(/^\/approval\/([^/]+)(\/approve|\/deny)?$/);
      if (ap) return await this.approval(req.method, ap[1]!, ap[2], req);
      if (req.method === "POST" && path === "/tls-ca") return await this.storeTlsCa(await req.json());
      if (req.method === "POST" && path === "/snapshot/upload") return await this.snapshotUpload(req);
      const sn = path.match(/^\/snapshot\/(snap_[0-9a-f]+)$/);
      if (req.method === "GET" && sn) return await this.snapshotGet(sn[1]!);
      if (req.method === "POST" && path === "/snapshot") return await this.snapshotInstruct();
      if ((req.method === "POST" || req.method === "GET") && path.startsWith("/cap/")) {
        // Defense-in-depth: if the caller presents a token (egress path), it must own this session.
        const tok = req.headers.get("x-zeroness-token");
        if (tok) { const s = await this.session(); if (!s || s.sessionToken !== tok) return json({ error: "token mismatch" }, 403); }
        let args: { path?: string; data?: string | number[]; query?: string; params?: unknown[] };
        if (req.method === "POST") {
          args = (await req.json()) as typeof args;
        } else {
          const q: Record<string, string> = {};
          new URL(req.url).searchParams.forEach((v, k) => { q[k] = v; });
          args = q;
        }
        return await this.capIO(req.method, decodeURIComponent(path.slice(5)), args);
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
      sessionId: body.sessionId, sessionToken: body.sessionToken,
      policy: body.policy ?? { default: "deny" }, resources: body.resources ?? {},
      handleTokens, pubKey: body.pubKey, lastSeq: 0,
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
      const store = await this.approvals();
      // A prior human approval (within TTL) lets the retry through.
      if (store.isGranted(body.method, body.url)) {
        await this.saveApprovals(store);
        await this.append({ ts: Date.now(), event: "egress:allow-granted", detail: { url: body.url } });
        return this.allowResponse(s, decision, u, "approved by human");
      }
      const approvalId = mintOpaqueToken();
      const reqInfo = { id: approvalId, sessionId: s.sessionId, method: body.method, url: body.url, identity: decision.identity, reason: decision.reason, createdAt: Date.now() };
      store.create(reqInfo);
      await this.saveApprovals(store);
      await this.gatekeeper.onApprovalRequested(reqInfo).catch(() => {});
      await this.append({ ts: Date.now(), event: "egress:ask", detail: { url: body.url, approvalId } });
      return json({ verdict: "ask", reason: decision.reason, target: body.url, approvalId });
    }

    await this.append({ ts: Date.now(), event: "egress:allow", detail: { url: body.url, identity: decision.identity ?? null } });
    return this.allowResponse(s, decision, u, decision.reason);
  }

  private async allowResponse(s: SessionState, decision: ReturnType<typeof evaluate>, u: URL, reason: string): Promise<Response> {
    const injectHeaders = decision.identity ? await this.mintIdentity(s, decision.identity) : {};
    const target = decision.forwardURL ? reorigin(decision.forwardURL, u, decision.rewrite?.path) : applyPath(u, decision.rewrite?.path);
    const dropHeaders = decision.rewrite?.headers ? Object.entries(decision.rewrite.headers).filter(([, v]) => v === null).map(([k]) => k) : [];
    if (decision.rewrite?.headers) for (const [k, v] of Object.entries(decision.rewrite.headers)) if (v !== null) injectHeaders[k] = v;
    return json({ verdict: "allow", reason, target, injectHeaders, dropHeaders });
  }

  /** Turn a capability handle into request headers — the sandbox never sees the secret. */
  private async mintIdentity(s: SessionState, cap: string): Promise<Record<string, string>> {
    const binding = s.resources[cap.replace(/^cap:/, "")] as ResourceBinding | undefined;
    if (!binding) return {};
    if ("accessToken" in binding) { const t = this.secret(binding.accessToken); return t ? { authorization: `Bearer ${t}` } : {}; }
    if ("secret" in binding) { const t = this.secret(binding.secret); return t ? { authorization: `Bearer ${t}` } : {}; }
    if ("oidc" in binding) {
      const jwt = await this.mintOidc(binding.oidc.audience, binding.oidc.subject ?? s.sessionId, binding.oidc.ttlSeconds ?? 300);
      return { authorization: `Bearer ${jwt}` };
    }
    return {};
  }

  // ---- approvals (human-in-the-loop) ----
  private async approval(method: string, id: string, action: string | undefined, _req: Request): Promise<Response> {
    const store = await this.approvals();
    if (method === "GET" && !action) { const a = store.get(id); return a ? json(a) : new Response("not found", { status: 404 }); }
    if (method === "POST" && action === "/approve") { const a = store.approve(id); await this.saveApprovals(store); await this.append({ ts: Date.now(), event: "approval:approve", detail: { id } }); return a ? json(a) : new Response("not found", { status: 404 }); }
    if (method === "POST" && action === "/deny") { const a = store.deny(id); await this.saveApprovals(store); await this.append({ ts: Date.now(), event: "approval:deny", detail: { id } }); return a ? json(a) : new Response("not found", { status: 404 }); }
    return new Response("method not allowed", { status: 405 });
  }

  private async listApprovals(): Promise<unknown> {
    const store = await this.approvals();
    return Object.values(store.state.approvals).filter((a) => a.status === "pending");
  }

  // ---- signed command channel + audit ----
  private async recordCommand(body: { envelope: { seq: number; procedure: string }; signature: string }): Promise<Response> {
    const s = await this.session();
    if (!s) return json({ error: "no session" }, 401);
    if (body.envelope.seq > s.lastSeq) { s.lastSeq = body.envelope.seq; await this.state.storage.put("session", s); }
    await this.append({ ts: Date.now(), event: "command", detail: { procedure: body.envelope.procedure, seq: body.envelope.seq } });
    return new Response(null, { status: 204 });
  }

  private async appendAudit(body: { event: string; detail: unknown; ts?: number }): Promise<Response> {
    await this.append({ ts: body.ts ?? Date.now(), event: body.event, detail: body.detail });
    return new Response(null, { status: 204 });
  }
  private async getAudit(): Promise<AuditEntry[]> { return (await this.state.storage.get<AuditEntry[]>("audit")) ?? []; }

  // ---- capability I/O: R2 · D1 · KV ----
  private async capIO(method: string, name: string, body: { path?: string; data?: number[] | string; query?: string; params?: unknown[] }): Promise<Response> {
    const s = await this.session();
    const binding = s?.resources[name] as ResourceBinding | undefined;
    if (!s || !binding) return json({ error: "unknown capability" }, 404);

    if ("r2" in binding) {
      const bucket = this.env.SNAPSHOTS; // demo maps R2 caps to the snapshots bucket; production binds per-name
      if (!bucket) return json({ error: "r2 binding unavailable" }, 501);
      const key = `${binding.prefix ?? ""}${body.path ?? ""}`;
      if (method === "POST") {
        if (binding.mode === "ro") return json({ error: "read-only capability" }, 403);
        await bucket.put(key, typeof body.data === "string" ? body.data : new Uint8Array(body.data ?? []));
        await this.append({ ts: Date.now(), event: "cap:write", detail: { name, key } });
        return json({ ok: true, key });
      }
      const obj = await bucket.get(key);
      await this.append({ ts: Date.now(), event: "cap:read", detail: { name, key, found: !!obj } });
      return json({ content: obj ? await obj.text() : null });
    }

    if ("d1" in binding) {
      const db = this.env[binding.d1] as D1Database | undefined;
      if (!db) return json({ error: `D1 binding '${binding.d1}' not found` }, 501);
      if (method === "POST" && binding.mode !== "ro" && body.query) {
        const r = await db.prepare(body.query).bind(...(body.params ?? [])).run();
        await this.append({ ts: Date.now(), event: "cap:d1:write", detail: { name } });
        return json({ success: r.success, meta: r.meta });
      }
      const r = await db.prepare(body.query ?? "SELECT 1").bind(...(body.params ?? [])).all();
      await this.append({ ts: Date.now(), event: "cap:d1:read", detail: { name } });
      return json({ results: r.results });
    }

    if ("kv" in binding) {
      const ns = this.env[binding.kv] as KVNamespace | undefined;
      if (!ns) return json({ error: `KV binding '${binding.kv}' not found` }, 501);
      const key = `${binding.prefix ?? ""}${body.path ?? ""}`;
      if (method === "POST") {
        if (binding.mode === "ro") return json({ error: "read-only capability" }, 403);
        await ns.put(key, typeof body.data === "string" ? body.data : new Uint8Array(body.data ?? []));
        await this.append({ ts: Date.now(), event: "cap:kv:write", detail: { name, key } });
        return json({ ok: true });
      }
      await this.append({ ts: Date.now(), event: "cap:kv:read", detail: { name, key } });
      return json({ content: await ns.get(key) });
    }

    return json({ error: "capability type not yet wired (queue)" }, 501);
  }

  // ---- opt-in TLS interception CA (cert is public; key gates leaf issuance) ----
  private async storeTlsCa(body: { certPem: string; keyPkcs8: number[] }): Promise<Response> {
    await this.state.storage.put("tls-ca", body);
    await this.append({ ts: Date.now(), event: "tls:ca-provisioned", detail: { certBytes: body.certPem.length } });
    return new Response(null, { status: 204 });
  }

  // ---- snapshots: content-addressed to R2 ----
  private async snapshotInstruct(): Promise<Response> {
    // The agent (zeronessd) tars the writable FS and POSTs the bytes to /snapshot/upload.
    return json({ upload: "/snapshot/upload", method: "POST" });
  }
  private async snapshotUpload(req: Request): Promise<Response> {
    if (!this.env.SNAPSHOTS) return json({ error: "no snapshot bucket" }, 501);
    const tok = req.headers.get("x-zeroness-token");
    if (tok) { const s = await this.session(); if (!s || s.sessionToken !== tok) return json({ error: "token mismatch" }, 403); }
    const bytes = new Uint8Array(await req.arrayBuffer());
    const ref = `snap_${await sha256Hex(bytes)}`;
    await this.env.SNAPSHOTS.put(`snapshots/${ref}`, bytes);
    await this.append({ ts: Date.now(), event: "snapshot:upload", detail: { ref, size: bytes.byteLength } });
    return json({ ref, size: bytes.byteLength });
  }
  private async snapshotGet(ref: string): Promise<Response> {
    if (!this.env.SNAPSHOTS) return json({ error: "no snapshot bucket" }, 501);
    const obj = await this.env.SNAPSHOTS.get(`snapshots/${ref}`);
    if (!obj) return new Response("not found", { status: 404 });
    return new Response(obj.body, { headers: { "content-type": "application/octet-stream" } });
  }

  // ---- helpers ----
  private async session(): Promise<SessionState | undefined> { return this.state.storage.get<SessionState>("session"); }
  private async approvals(): Promise<ApprovalStore> {
    const st = (await this.state.storage.get<ApprovalState>("approvals")) ?? emptyApprovalState();
    return new ApprovalStore(st);
  }
  private async saveApprovals(store: ApprovalStore): Promise<void> { store.sweep(); await this.state.storage.put("approvals", store.state); }
  private async append(e: AuditEntry): Promise<void> {
    const log = (await this.state.storage.get<AuditEntry[]>("audit")) ?? [];
    log.push(e); await this.state.storage.put("audit", log.slice(-1000));
  }
  private secret(name: string): string | undefined { return this.env.SECRETS?.[name] ?? (this.env[name] as string | undefined); }
  private async mintOidc(audience: string, subject: string, ttl: number): Promise<string> {
    let jwk = await this.state.storage.get<JsonWebKey>("oidc-key");
    let priv: CryptoKey;
    if (!jwk) {
      const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
      jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
      await this.state.storage.put("oidc-key", jwk); priv = pair.privateKey;
    } else priv = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]);
    const now = Math.floor(Date.now() / 1000);
    const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT" }));
    const payload = b64url(JSON.stringify({ iss: "zeroness", sub: subject, aud: audience, iat: now, exp: now + ttl, jti: mintOpaqueToken() }));
    const sig = await crypto.subtle.sign({ name: "Ed25519" }, priv, new TextEncoder().encode(`${header}.${payload}`));
    return `${header}.${payload}.${b64urlBytes(new Uint8Array(sig))}`;
  }
}

export default { fetch: () => new Response("zeroness broker (durable object)", { status: 200 }) };

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes.byteLength); copy.set(bytes);
  const d = await crypto.subtle.digest("SHA-256", copy);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function reorigin(base: string, orig: URL, pathOverride?: string): string {
  const b = new URL(base); b.pathname = pathOverride ?? orig.pathname; b.search = orig.search; return b.toString();
}
function applyPath(orig: URL, pathOverride?: string): string {
  if (!pathOverride) return orig.toString();
  const u = new URL(orig.toString()); u.pathname = pathOverride; return u.toString();
}
function json(v: unknown, status = 200): Response {
  return new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
}
function b64url(s: string): string { return b64urlBytes(new TextEncoder().encode(s)); }
function b64urlBytes(u: Uint8Array): string {
  let s = ""; for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
