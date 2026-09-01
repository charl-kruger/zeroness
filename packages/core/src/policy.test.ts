import { describe, it, expect } from "vitest";
import { evaluate, isForbiddenEgressHost, type NetworkPolicy } from "./policy";

const req = (host: string, path = "/", method = "GET") => ({ host, path, method });

describe("network policy engine", () => {
  const policy: NetworkPolicy = {
    default: "deny",
    deny: [{ host: "*.internal.acme" }],
    allow: [
      { host: "api.github.com", methods: ["GET"], path: "/repos/**" },
      { host: "*.pythonhosted.org" },
      { host: "api.stripe.com", verdict: "ask", identity: "cap:stripe-ro" },
    ],
    transform: [{ host: "api.github.com", rewrite: { headers: { "user-agent": "zeroness" } } }],
  };

  it("denies by default", () => {
    expect(evaluate(policy, req("evil.example.com")).verdict).toBe("deny");
  });

  it("allows an explicit allow-rule with path glob", () => {
    expect(evaluate(policy, req("api.github.com", "/repos/cloudflare/workerd")).verdict).toBe("allow");
    expect(evaluate(policy, req("api.github.com", "/users/x")).verdict).toBe("deny"); // path not matched
  });

  it("honors method restrictions", () => {
    expect(evaluate(policy, req("api.github.com", "/repos/a/b", "DELETE")).verdict).toBe("deny");
  });

  it("matches wildcard subdomains", () => {
    expect(evaluate(policy, req("files.pythonhosted.org")).verdict).toBe("allow");
    expect(evaluate(policy, req("pythonhosted.org")).verdict).toBe("deny"); // apex not covered by *.
  });

  it("explicit deny beats allow", () => {
    const p: NetworkPolicy = { default: "allow", deny: [{ host: "*.internal.acme" }], allow: [{ host: "*" }] };
    expect(evaluate(p, req("db.internal.acme")).verdict).toBe("deny");
  });

  it("returns ask + identity for human-in-the-loop routes", () => {
    const d = evaluate(policy, req("api.stripe.com", "/v1/charges"));
    expect(d.verdict).toBe("ask");
    expect(d.identity).toBe("cap:stripe-ro");
  });

  it("layers transforms onto an allowed request", () => {
    const d = evaluate(policy, req("api.github.com", "/repos/a/b"));
    expect(d.rewrite?.headers?.["user-agent"]).toBe("zeroness");
  });

  it("matches a path rule against the decoded path (percent-encoding cannot evade)", () => {
    const p: NetworkPolicy = { default: "deny", allow: [{ host: "api.x.com", path: "/secret" }] };
    expect(evaluate(p, { host: "api.x.com", method: "GET", path: "/%73ecret" }).verdict).toBe("allow");
  });

  it("normalizes encoded dot-segments so a rule cannot fire out of scope", () => {
    const p: NetworkPolicy = { default: "deny", allow: [{ host: "api.x.com", path: "/pub/**" }] };
    expect(evaluate(p, { host: "api.x.com", method: "GET", path: "/pub/%2e%2e/admin" }).verdict).toBe("deny");
  });

  it("treats a trailing-dot FQDN as the same host", () => {
    const p: NetworkPolicy = { default: "deny", deny: [{ host: "evil.com" }], allow: [{ host: "*" }] };
    expect(evaluate(p, { host: "evil.com.", method: "GET", path: "/" }).verdict).toBe("deny");
  });

  it("root-escaping dot-segments cannot bypass a path deny", () => {
    const p: NetworkPolicy = { default: "deny", deny: [{ host: "api.x.com", path: "/admin/**" }], allow: [{ host: "api.x.com" }] };
    expect(evaluate(p, { host: "api.x.com", method: "GET", path: "/../admin/x" }).verdict).toBe("deny");
  });

  it("flags internal + metadata targets", () => {
    for (const h of ["169.254.169.254", "127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.0.1", "localhost", "::1", "metadata.google.internal", "100.64.0.5"])
      expect(isForbiddenEgressHost(h)).toBe(true);
    for (const h of ["api.github.com", "8.8.8.8", "203.0.113.5"])
      expect(isForbiddenEgressHost(h)).toBe(false);
  });
});
