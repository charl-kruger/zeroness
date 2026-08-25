import { describe, it, expect } from "vitest";
import { generateSessionKey, exportPublicKeyRaw, importPublicKeyRaw, signCommand, verifyCommand, randomNonce } from "./signing";

const env = (seq: number, ts = Date.now()) => ({ sid: "s1", seq, ts, nonce: randomNonce(), procedure: "exec" });

describe("signed command channel", () => {
  it("round-trips a valid command", async () => {
    const kp = await generateSessionKey();
    const pub = await importPublicKeyRaw(await exportPublicKeyRaw(kp.publicKey));
    const { envelope, signature } = await signCommand(kp.privateKey, env(1), "ls -la");
    expect(await verifyCommand(pub, envelope, signature, "ls -la")).toEqual({ ok: true });
  });

  it("rejects a tampered body (body IS authenticated)", async () => {
    const kp = await generateSessionKey();
    const pub = await importPublicKeyRaw(await exportPublicKeyRaw(kp.publicKey));
    const { envelope, signature } = await signCommand(kp.privateKey, env(1), "ls");
    const r = await verifyCommand(pub, envelope, signature, "rm -rf /");
    expect(r).toEqual({ ok: false, reason: "body hash mismatch" });
  });

  it("rejects a bad signature", async () => {
    const kp = await generateSessionKey();
    const other = await generateSessionKey();
    const pub = await importPublicKeyRaw(await exportPublicKeyRaw(other.publicKey));
    const { envelope, signature } = await signCommand(kp.privateKey, env(1), "ls");
    expect((await verifyCommand(pub, envelope, signature, "ls")).ok).toBe(false);
  });

  it("rejects stale timestamps", async () => {
    const kp = await generateSessionKey();
    const pub = await importPublicKeyRaw(await exportPublicKeyRaw(kp.publicKey));
    const { envelope, signature } = await signCommand(kp.privateKey, env(1, Date.now() - 120_000), "ls");
    expect(await verifyCommand(pub, envelope, signature, "ls")).toEqual({ ok: false, reason: "stale timestamp" });
  });

  it("rejects replayed sequence numbers", async () => {
    const kp = await generateSessionKey();
    const pub = await importPublicKeyRaw(await exportPublicKeyRaw(kp.publicKey));
    const { envelope, signature } = await signCommand(kp.privateKey, env(5), "ls");
    expect(await verifyCommand(pub, envelope, signature, "ls", { lastSeq: 5 })).toEqual({ ok: false, reason: "replayed seq" });
    expect((await verifyCommand(pub, envelope, signature, "ls", { lastSeq: 4 })).ok).toBe(true);
  });
});
