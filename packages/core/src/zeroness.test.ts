import { describe, it, expect } from "vitest";
import { ZeronessSandbox, type CfSandbox } from "./zeroness";
import { generateSessionKey } from "./signing";

const fakeCf = {} as unknown as CfSandbox;

describe("ZeronessSandbox.restore", () => {
  it("throws a clear error when no agent is configured (no silent no-op)", async () => {
    const box = new ZeronessSandbox("sid", fakeCf, {} as CryptoKey, {}, async () => undefined);
    await expect(box.restore("snap_abc")).rejects.toThrow(/agentUrl/);
  });

  it("dispatches a signed restore command to the agent", async () => {
    const keys = await generateSessionKey();
    const calls: Array<[string, string]> = [];
    const broker = async (m: string, p: string) => { calls.push([m, p]); return undefined; };
    const box = new ZeronessSandbox("sid", fakeCf, keys.privateKey, { agentUrl: "https://agent.example" }, broker);
    const orig = globalThis.fetch;
    globalThis.fetch = (async () => new Response(JSON.stringify({ restored: "snap_abc" }), { status: 200 })) as typeof fetch;
    try {
      const r = await box.restore("snap_abc");
      expect(r).toEqual({ restored: "snap_abc" });
      expect(calls.some(([m, p]) => m === "POST" && p === "/command")).toBe(true); // signed + recorded
    } finally {
      globalThis.fetch = orig;
    }
  });
});
