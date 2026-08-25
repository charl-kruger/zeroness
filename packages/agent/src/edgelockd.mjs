#!/usr/bin/env node
/**
 * edgelockd — in-sandbox agent (Phase 3 scaffold).
 *
 * Verifies Ed25519-signed command envelopes before execution, closing the
 * body-tamper and replay gaps. Freshness + monotonic seq are enforced here,
 * where the sandbox can't roll the clock back on the control plane.
 *
 * Boot contract (env): EDGELOCK_PUBKEY (base64 raw Ed25519), EDGELOCK_SESSION,
 * EDGELOCK_CAPS, EDGELOCK_BROKER_URL.
 */
import { webcrypto as crypto } from "node:crypto";

let lastSeq = 0;

async function importPub(b64raw) {
  const raw = Uint8Array.from(atob(b64raw.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, true, ["verify"]);
}

async function sha256Hex(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Returns {ok} or {ok:false, reason}. Mirrors @edgelock/core verifyCommand. */
export async function verify(pub, envelope, signatureB64, body, { maxSkewMs = 30_000 } = {}) {
  if (Math.abs(Date.now() - envelope.ts) > maxSkewMs) return { ok: false, reason: "stale" };
  if (envelope.seq <= lastSeq) return { ok: false, reason: "replay" };
  if ((await sha256Hex(body)) !== envelope.bodyHash) return { ok: false, reason: "body mismatch" };
  const canon = new TextEncoder().encode(
    JSON.stringify({ sid: envelope.sid, seq: envelope.seq, ts: envelope.ts, nonce: envelope.nonce, procedure: envelope.procedure, bodyHash: envelope.bodyHash }),
  );
  const sig = Uint8Array.from(atob(signatureB64.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, pub, sig, canon);
  if (!ok) return { ok: false, reason: "bad signature" };
  lastSeq = envelope.seq;
  return { ok: true };
}

// TODO(phase3): open the control transport, loop: read {envelope, signature, body},
// verify(), then dispatch to exec/runCode/writeFile/snapshot; start heartbeat.
if (import.meta.url === `file://${process.argv[1]}`) {
  console.error("edgelockd: scaffold — wire the control transport + heartbeat (see README).");
}
