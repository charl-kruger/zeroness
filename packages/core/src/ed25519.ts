/**
 * Ed25519 signing with a portable backend.
 *
 * Cloudflare Workers provide full Ed25519 via `crypto.subtle`. Some self-hosted
 * Workers runtimes (e.g. celld) embed a V8 whose WebCrypto does NOT implement
 * Ed25519 verify — `crypto.subtle` sign/verify throws "unsupported ... ED25519".
 * There, `node:crypto` (available under the `nodejs_compat` flag) provides a
 * complete Ed25519 implementation.
 *
 * This module detects, once, whether `crypto.subtle` Ed25519 is fully usable
 * (by doing a sign+verify round-trip) and otherwise falls back to `node:crypto`.
 * The persisted key is a standard OKP JWK (`{kty:"OKP",crv:"Ed25519",x,d}`),
 * which both backends import and export identically, so a key minted on one
 * runtime is usable on the other.
 *
 * Only JWK-in / signature-out is exposed — enough for the Broker's OIDC JWT
 * minting. Verification of Ed25519 (the signed-command channel) runs in the
 * in-sandbox agent on `node:crypto` already, so it is not needed here.
 */

export type EdBackend = "subtle" | "node";

let cached: EdBackend | null = null;

/** Reset the cached backend detection. Test-only. */
export function _resetEdBackend(): void {
  cached = null;
}

/** Detect (once) whether crypto.subtle Ed25519 is fully usable, else "node". */
export async function detectEdBackend(): Promise<EdBackend> {
  if (cached) return cached;
  try {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const data = new TextEncoder().encode("zeroness-ed25519-probe");
    const sig = await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, data);
    const ok = await crypto.subtle.verify({ name: "Ed25519" }, kp.publicKey, sig, data);
    cached = ok ? "subtle" : "node";
  } catch {
    cached = "node";
  }
  return cached;
}

// node:crypto is present only on node-compatible runtimes (nodejs_compat). It is
// imported lazily and only when the node backend is selected, so Cloudflare
// (which uses the subtle backend) never evaluates it.
async function nodeCrypto(): Promise<{
  generateKeyPairSync: (type: "ed25519") => { privateKey: NodePrivateKey };
  createPrivateKey: (opts: { key: JsonWebKey; format: "jwk" }) => NodePrivateKey;
  sign: (algorithm: null, data: Uint8Array, key: NodePrivateKey) => Uint8Array;
}> {
  // @ts-ignore - node:crypto has no @cloudflare/workers-types declaration
  return (await import("node:crypto")) as unknown as Awaited<ReturnType<typeof nodeCrypto>>;
}

interface NodePrivateKey {
  export(opts: { format: "jwk" }): JsonWebKey;
}

/** Generate an Ed25519 private key and return it as a JWK for persistence. */
export async function edGenerateJwk(): Promise<JsonWebKey> {
  if ((await detectEdBackend()) === "subtle") {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    return crypto.subtle.exportKey("jwk", kp.privateKey);
  }
  const nc = await nodeCrypto();
  return nc.generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
}

/** Sign `data` with an Ed25519 private key given as a JWK. Returns 64 raw bytes. */
export async function edSignJwk(privJwk: JsonWebKey, data: Uint8Array): Promise<Uint8Array> {
  if ((await detectEdBackend()) === "subtle") {
    const key = await crypto.subtle.importKey("jwk", privJwk, { name: "Ed25519" }, false, ["sign"]);
    // Copy into a fresh ArrayBuffer-backed view (WebCrypto rejects shared-buffer views).
    const buf = new Uint8Array(data.byteLength);
    buf.set(data);
    const sig = await crypto.subtle.sign({ name: "Ed25519" }, key, buf);
    return new Uint8Array(sig);
  }
  const nc = await nodeCrypto();
  const key = nc.createPrivateKey({ key: privJwk, format: "jwk" });
  return new Uint8Array(nc.sign(null, data, key));
}
