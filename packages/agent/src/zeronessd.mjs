#!/usr/bin/env node
/**
 * zeronessd — in-sandbox agent.
 *
 * Runs inside the Cloudflare Sandbox on a localhost port (default 9787), exposed
 * to the control plane via a preview URL. It is the ONLY thing that executes
 * privileged operations, and it verifies the Ed25519 signature + freshness +
 * monotonic sequence of every command before running it — closing the
 * body-tamper and replay gaps.
 *
 * Boot contract (env): ZERONESS_PUBKEY (base64 raw Ed25519), ZERONESS_SESSION,
 * ZERONESS_BROKER_URL (for snapshots + heartbeat), ZERONESS_CAPS, ZERONESS_AGENT_PORT.
 */
import http from "node:http";
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

const b64uToBytes = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

async function importPub(b64raw) {
  return crypto.subtle.importKey("raw", b64uToBytes(b64raw), { name: "Ed25519" }, true, ["verify"]);
}
async function sha256Hex(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Verify an envelope against `body`. Returns {ok} or {ok:false,reason}. */
export async function verify(pub, envelope, signatureB64, body, seqRef, { maxSkewMs = 30_000 } = {}) {
  if (Math.abs(Date.now() - envelope.ts) > maxSkewMs) return { ok: false, reason: "stale" };
  if (envelope.seq <= (seqRef.last ?? 0)) return { ok: false, reason: "replay" };
  if ((await sha256Hex(body)) !== envelope.bodyHash) return { ok: false, reason: "body mismatch" };
  const canon = new TextEncoder().encode(
    JSON.stringify({ sid: envelope.sid, seq: envelope.seq, ts: envelope.ts, nonce: envelope.nonce, procedure: envelope.procedure, bodyHash: envelope.bodyHash }),
  );
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, pub, b64uToBytes(signatureB64), canon);
  if (!ok) return { ok: false, reason: "bad signature" };
  seqRef.last = envelope.seq;
  return { ok: true };
}

/** Default privileged runners (real fs/process). Overridable for tests. */
export const defaultRunners = {
  async exec({ command }) {
    return new Promise((resolve) => {
      const p = spawn("/bin/sh", ["-c", command]);
      let stdout = "", stderr = "";
      p.stdout.on("data", (d) => (stdout += d));
      p.stderr.on("data", (d) => (stderr += d));
      p.on("close", (code) => resolve({ stdout, stderr, exitCode: code ?? 0, success: code === 0 }));
    });
  },
  async writeFile({ path, data }) {
    writeFileSync(path, Array.isArray(data) ? Buffer.from(data) : String(data));
    return { ok: true };
  },
  async readFile({ path }) {
    return { content: readFileSync(path, "utf8") };
  },
  async snapshot(_args, ctx) {
    // tar the writable rootfs and upload to the Broker (content-addressed to R2).
    const tar = spawn("tar", ["czf", "-", "-C", "/", "--exclude=./proc", "--exclude=./sys", "."]);
    const chunks = [];
    tar.stdout.on("data", (d) => chunks.push(d));
    await new Promise((r) => tar.on("close", r));
    const body = Buffer.concat(chunks);
    const res = await fetch(`${ctx.brokerUrl}/snapshot/upload`, { method: "POST", body });
    return res.json();
  },
};

/** Verify then dispatch a command. Pure w.r.t. injected `runners` — unit-testable. */
export async function handleCommand(ctx, msg) {
  const v = await verify(ctx.pub, msg.envelope, msg.signature, msg.body, ctx.seq);
  if (!v.ok) return { status: 403, body: { error: "rejected", reason: v.reason } };
  const args = JSON.parse(msg.body);
  const runner = ctx.runners[msg.envelope.procedure];
  if (!runner) return { status: 400, body: { error: `unknown procedure ${msg.envelope.procedure}` } };
  try {
    return { status: 200, body: await runner(args, ctx) };
  } catch (e) {
    return { status: 500, body: { error: String(e?.message ?? e) } };
  }
}

async function main() {
  const port = Number(process.env.ZERONESS_AGENT_PORT ?? 9787);
  const ctx = {
    pub: await importPub(process.env.ZERONESS_PUBKEY),
    brokerUrl: process.env.ZERONESS_BROKER_URL,
    runners: defaultRunners,
    seq: { last: 0 },
  };

  const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/command") {
      let buf = "";
      req.on("data", (d) => (buf += d));
      req.on("end", async () => {
        const out = await handleCommand(ctx, JSON.parse(buf));
        res.writeHead(out.status, { "content-type": "application/json" });
        res.end(JSON.stringify(out.body));
      });
      return;
    }
    if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, seq: ctx.seq.last }));
      return;
    }
    // transparent capability proxy: in-sandbox code hits 127.0.0.1:PORT/cap/<name>,
    // we forward to the Egress Worker with the session token — code never holds secrets.
    if (req.url?.startsWith("/cap/") && process.env.ZERONESS_EGRESS_URL) {
      let buf = "";
      req.on("data", (d) => (buf += d));
      req.on("end", async () => {
        const r = await fetch(`${process.env.ZERONESS_EGRESS_URL}/__zeroness${req.url}`, {
          method: req.method,
          headers: { "content-type": "application/json", "x-zeroness-session-token": process.env.ZERONESS_SESSION ?? "" },
          body: req.method === "POST" ? buf : undefined,
        });
        res.writeHead(r.status, { "content-type": "application/json" });
        res.end(await r.text());
      });
      return;
    }
    res.writeHead(404); res.end();
  });
  server.listen(port, "127.0.0.1", () => console.error(`zeronessd listening on 127.0.0.1:${port}`));

  // heartbeat / attestation
  if (ctx.brokerUrl) {
    setInterval(() => {
      fetch(`${ctx.brokerUrl}/audit`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ event: "heartbeat", detail: { seq: ctx.seq.last, pid: process.pid } }),
      }).catch(() => {});
    }, 15_000);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
