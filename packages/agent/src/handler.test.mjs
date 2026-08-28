import { describe, it, expect } from "vitest";
import { webcrypto as crypto } from "node:crypto";
import { handleCommand } from "./zeronessd.mjs";

const enc = new TextEncoder();
const b64u = (u) => btoa(String.fromCharCode(...u)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const sha256Hex = async (s) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)))].map((b) => b.toString(16).padStart(2, "0")).join("");

async function signed(priv, procedure, args, seq = 1, ts = Date.now()) {
  const body = JSON.stringify(args);
  const envelope = { sid: "s1", seq, ts, nonce: "n", procedure, bodyHash: await sha256Hex(body) };
  const canon = enc.encode(JSON.stringify({ sid: envelope.sid, seq: envelope.seq, ts: envelope.ts, nonce: envelope.nonce, procedure: envelope.procedure, bodyHash: envelope.bodyHash }));
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, priv, canon);
  return { envelope, signature: b64u(new Uint8Array(sig)), body };
}

const ctx = (pub) => ({
  pub,
  runners: { exec: async ({ command }) => ({ stdout: `ran:${command}`, exitCode: 0, success: true }) },
  seq: { last: 0 },
});

describe("zeronessd command handler", () => {
  it("runs a validly-signed command", async () => {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const msg = await signed(kp.privateKey, "exec", { command: "echo hi" });
    const out = await handleCommand(ctx(kp.publicKey), msg);
    expect(out.status).toBe(200);
    expect(out.body.stdout).toBe("ran:echo hi");
  });

  it("rejects a tampered body", async () => {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const msg = await signed(kp.privateKey, "exec", { command: "echo hi" });
    msg.body = JSON.stringify({ command: "rm -rf /" }); // swap payload, keep signature
    const out = await handleCommand(ctx(kp.publicKey), msg);
    expect(out.status).toBe(403);
    expect(out.body.reason).toBe("body mismatch");
  });

  it("rejects a replayed sequence", async () => {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const c = ctx(kp.publicKey); c.seq.last = 5;
    const msg = await signed(kp.privateKey, "exec", { command: "echo hi" }, 5);
    const out = await handleCommand(c, msg);
    expect(out.status).toBe(403);
    expect(out.body.reason).toBe("replay");
  });

  it("rejects an unknown procedure", async () => {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const msg = await signed(kp.privateKey, "destroyEverything", {});
    const out = await handleCommand(ctx(kp.publicKey), msg);
    expect(out.status).toBe(400);
  });

  it("dispatches a validly-signed restore command", async () => {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const c = { pub: kp.publicKey, seq: { last: 0 }, runners: { restore: async ({ ref }) => ({ restored: ref }) } };
    const msg = await signed(kp.privateKey, "restore", { ref: "snap_abc" });
    const out = await handleCommand(c, msg);
    expect(out.status).toBe(200);
    expect(out.body.restored).toBe("snap_abc");
  });
});
