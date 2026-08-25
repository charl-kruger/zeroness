import { describe, it, expect } from "vitest";
import { evaluate, type NetworkPolicy } from "./policy";

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
});
