import { describe, it, expect } from "vitest";
import * as x509 from "@peculiar/x509";
import { generateSessionCA, issueLeaf, installCACommand } from "./index";

describe("per-session MITM CA", () => {
  it("generates a CA cert that is a CA", async () => {
    const ca = await generateSessionCA({ commonName: "test-ca" });
    expect(ca.certPem).toContain("BEGIN CERTIFICATE");
    const bc = ca.cert.getExtension(x509.BasicConstraintsExtension);
    expect(bc?.ca).toBe(true);
  });

  it("issues a leaf signed by the CA, with the host in the SAN", async () => {
    const ca = await generateSessionCA();
    const leaf = await issueLeaf(ca, "api.example.com");
    expect(leaf.certPem).toContain("BEGIN CERTIFICATE");
    expect(leaf.keyPem).toContain("BEGIN PRIVATE KEY");
    const cert = new x509.X509Certificate(leaf.certPem);
    expect(cert.issuer).toBe(ca.cert.subject);
    const ok = await cert.verify({ publicKey: ca.keys.publicKey, signatureOnly: true });
    expect(ok).toBe(true);
    const san = cert.getExtension(x509.SubjectAlternativeNameExtension);
    expect(san?.toString()).toContain("api.example.com");
  });

  it("emits a trust-store install command", () => {
    expect(installCACommand("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"))
      .toContain("update-ca-certificates");
  });
});
