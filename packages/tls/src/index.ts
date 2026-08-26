/**
 * @zeroness/tls — per-session MITM certificate authority.
 *
 * TLS interception is OFF by default (the L7 proxy path is preferred). When a
 * policy domain needs deep inspection, zeroness provisions a **per-session CA**:
 * the sandbox trusts it, and the interception point issues short-lived leaf
 * certificates for the intercepted hosts. This module is the cryptographic core
 * — CA generation and leaf issuance — kept isolated so nothing else depends on
 * X.509 unless interception is enabled.
 *
 * The CA private key lives only in the Broker; the sandbox trusts the CA cert
 * (public) exactly like the operator-installed roots.
 */
import * as x509 from "@peculiar/x509";

const ALG = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;

/** Use the ambient WebCrypto (Workers global, or Node's webcrypto). */
function provider(): Crypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) throw new Error("WebCrypto unavailable");
  x509.cryptoProvider.set(c);
  return c;
}

export interface SessionCA {
  certPem: string;        // trust this in the sandbox
  keyPkcs8: ArrayBuffer;  // CA private key — Broker only
  cert: x509.X509Certificate;
  keys: CryptoKeyPair;
}

export interface Leaf {
  certPem: string;
  keyPem: string;
}

/** Generate a short-lived per-session CA. */
export async function generateSessionCA(opts: { commonName?: string; days?: number } = {}): Promise<SessionCA> {
  const crypto = provider();
  const keys = (await crypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as CryptoKeyPair;
  const now = new Date();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomSerial(),
    name: `CN=${opts.commonName ?? "zeroness Session CA"}, O=zeroness`,
    notBefore: now,
    notAfter: new Date(now.getTime() + (opts.days ?? 1) * 86_400_000),
    keys,
    signingAlgorithm: ALG,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  return { certPem: cert.toString("pem"), keyPkcs8: await crypto.subtle.exportKey("pkcs8", keys.privateKey), cert, keys };
}

/** Issue a leaf certificate for `host`, signed by the session CA. */
export async function issueLeaf(ca: SessionCA, host: string, opts: { minutes?: number } = {}): Promise<Leaf> {
  const crypto = provider();
  const leafKeys = (await crypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as CryptoKeyPair;
  const now = new Date();
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerial(),
    subject: `CN=${host}`,
    issuer: ca.cert.subject,
    notBefore: now,
    notAfter: new Date(now.getTime() + (opts.minutes ?? 60) * 60_000),
    signingKey: ca.keys.privateKey,
    publicKey: leafKeys.publicKey,
    signingAlgorithm: ALG,
    extensions: [
      new x509.BasicConstraintsExtension(false),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment, true),
      new x509.SubjectAlternativeNameExtension([{ type: "dns", value: host }]),
    ],
  });
  return { certPem: cert.toString("pem"), keyPem: toPem(await crypto.subtle.exportKey("pkcs8", leafKeys.privateKey), "PRIVATE KEY") };
}

/** Shell to install the CA into a Debian/Ubuntu sandbox trust store. */
export function installCACommand(certPem: string): string {
  const b64 = btoa(certPem);
  return `echo ${b64} | base64 -d | sudo tee /usr/local/share/ca-certificates/zeroness-session-ca.crt >/dev/null && sudo update-ca-certificates >/dev/null 2>&1`;
}

function randomSerial(): string {
  const u = crypto.getRandomValues(new Uint8Array(8));
  return [...u].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function toPem(der: ArrayBuffer, label: string): string {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(der)));
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}
