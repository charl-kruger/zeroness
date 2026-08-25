/**
 * edgelock — signed command channel (Ed25519 via WebCrypto).
 *
 * Every control-plane command to the sandbox agent is wrapped in a signed
 * envelope. The agent (edgelockd) verifies signature + freshness before
 * executing. Improves on the Vercel scheme we studied: the payload hash and a
 * per-session monotonic sequence + nonce are signed, and the agent enforces
 * freshness — closing the replay/body-tamper gaps.
 */

export interface Envelope {
  sid: string;      // session id
  seq: number;      // monotonic per session (replay guard)
  ts: number;       // epoch ms (freshness)
  nonce: string;    // random per command
  procedure: string; // e.g. "exec" | "runCode" | "writeFile"
  bodyHash: string; // sha-256 hex of the canonical body → body IS authenticated
}

const enc = new TextEncoder();

/** Copy into a fresh ArrayBuffer-backed view (WebCrypto rejects SharedArrayBuffer-backed views). */
function buf(u: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(u.byteLength);
  out.set(u);
  return out;
}

export async function generateSessionKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
}

export async function exportPublicKeyRaw(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return b64(new Uint8Array(raw));
}

export async function importPublicKeyRaw(b64raw: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", buf(unb64(b64raw)), { name: "Ed25519" }, true, ["verify"]);
}

export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === "string" ? enc.encode(data) : data;
  const digest = await crypto.subtle.digest("SHA-256", buf(bytes));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Canonical bytes for an envelope — stable key order so signer and verifier agree. */
function canonical(e: Envelope): Uint8Array {
  return enc.encode(
    JSON.stringify({ sid: e.sid, seq: e.seq, ts: e.ts, nonce: e.nonce, procedure: e.procedure, bodyHash: e.bodyHash }),
  );
}

export async function signCommand(
  priv: CryptoKey,
  env: Omit<Envelope, "bodyHash">,
  body: string,
): Promise<{ envelope: Envelope; signature: string }> {
  const envelope: Envelope = { ...env, bodyHash: await sha256Hex(body) };
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, priv, buf(canonical(envelope)));
  return { envelope, signature: b64(new Uint8Array(sig)) };
}

export interface VerifyOpts {
  maxSkewMs?: number;   // reject stale/early commands (default 30s)
  lastSeq?: number;     // reject seq <= lastSeq (replay)
}

export async function verifyCommand(
  pub: CryptoKey,
  envelope: Envelope,
  signature: string,
  body: string,
  opts: VerifyOpts = {},
): Promise<{ ok: true } | { ok: false; reason: string }> {
  const maxSkew = opts.maxSkewMs ?? 30_000;
  if (Math.abs(Date.now() - envelope.ts) > maxSkew) return { ok: false, reason: "stale timestamp" };
  if (opts.lastSeq !== undefined && envelope.seq <= opts.lastSeq) return { ok: false, reason: "replayed seq" };
  if ((await sha256Hex(body)) !== envelope.bodyHash) return { ok: false, reason: "body hash mismatch" };
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, pub, buf(unb64(signature)), buf(canonical(envelope)));
  return ok ? { ok: true } : { ok: false, reason: "bad signature" };
}

export function randomNonce(): string {
  return b64(crypto.getRandomValues(new Uint8Array(16)));
}

function b64(u: Uint8Array): string {
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64(s: string): Uint8Array {
  const p = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(p + "=".repeat((4 - (p.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
