import { describe, it, expect, beforeEach } from "vitest";
import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { edGenerateJwk, edSignJwk, detectEdBackend, _resetEdBackend } from "./ed25519";

const enc = new TextEncoder();

/** Independently verify an Ed25519 signature via node:crypto, from a private JWK's public half. */
function verifySig(privJwk: JsonWebKey, data: Uint8Array, sig: Uint8Array): boolean {
  const pub = createPublicKey({ key: { kty: privJwk.kty, crv: privJwk.crv, x: privJwk.x } as JsonWebKey, format: "jwk" });
  return nodeVerify(null, Buffer.from(data), pub, Buffer.from(sig));
}

/** Simulate celld: subtle Ed25519 verify is unsupported. Returns a restore fn. */
function breakSubtleEd25519(): () => void {
  const orig = crypto.subtle.verify.bind(crypto.subtle);
  (crypto.subtle as unknown as { verify: unknown }).verify = async () => {
    throw new Error("unsupported verify algorithm: ED25519");
  };
  return () => {
    (crypto.subtle as unknown as { verify: unknown }).verify = orig;
  };
}

describe("portable Ed25519", () => {
  beforeEach(() => _resetEdBackend());

  it("selects the subtle backend where Ed25519 is fully supported", async () => {
    expect(await detectEdBackend()).toBe("subtle"); // the Node vitest env supports it
  });

  it("generates a JWK and signs a verifiable signature (subtle backend)", async () => {
    const jwk = await edGenerateJwk();
    expect(jwk.crv).toBe("Ed25519");
    const data = enc.encode("hello");
    const sig = await edSignJwk(jwk, data);
    expect(sig.byteLength).toBe(64);
    expect(verifySig(jwk, data, sig)).toBe(true);
  });

  it("falls back to node:crypto when subtle Ed25519 verify is unsupported (celld)", async () => {
    const restore = breakSubtleEd25519();
    try {
      expect(await detectEdBackend()).toBe("node");
      const jwk = await edGenerateJwk();
      const data = enc.encode("hello-celld");
      const sig = await edSignJwk(jwk, data);
      expect(sig.byteLength).toBe(64);
      expect(verifySig(jwk, data, sig)).toBe(true);
    } finally {
      restore();
    }
  });

  it("keys are interchangeable across backends (subtle-minted JWK signed via node path)", async () => {
    const jwk = await edGenerateJwk(); // subtle backend
    _resetEdBackend();
    const restore = breakSubtleEd25519();
    try {
      const data = enc.encode("interop");
      const sig = await edSignJwk(jwk, data); // node backend
      expect(verifySig(jwk, data, sig)).toBe(true);
    } finally {
      restore();
    }
  });
});
