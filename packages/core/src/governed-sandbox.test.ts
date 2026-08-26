import { describe, it, expect, vi } from "vitest";
import {
  createGovernedSandbox,
  makeOutboundHandler,
  registerGovernedSession,
  governedSessionToken,
} from "./governed-sandbox";

/** A minimal in-memory Broker DO stub that records the requests it receives. */
function mockBroker(handler: (path: string, init: RequestInit) => Response) {
  const calls: Array<{ path: string; body: unknown }> = [];
  const stub = {
    fetch: async (url: string, init: RequestInit = {}) => {
      const path = new URL(url).pathname;
      calls.push({ path, body: init.body ? JSON.parse(init.body as string) : undefined });
      return handler(path, init);
    },
  };
  const ns = {
    idFromName: (name: string) => ({ name, toString: () => `id(${name})` }),
    get: () => stub,
  } as unknown as DurableObjectNamespace;
  return { ns, calls };
}

/** A namespace whose idFromName(name).toString() is deterministic, for id derivation. */
function mockSandboxNs() {
  return {
    idFromName: (name: string) => ({ name, toString: () => `id(${name})` }),
    get: () => ({ fetch: async () => new Response(null) }),
  } as unknown as DurableObjectNamespace;
}

class FakeBase {
  enableInternet = true;
  interceptHttps = false;
  greet() {
    return "hi";
  }
}

describe("createGovernedSandbox", () => {
  it("sets the jail fields and preserves the base class", () => {
    const Governed = createGovernedSandbox(FakeBase as unknown as new () => object) as unknown as new () => FakeBase;
    const inst = new Governed();
    expect(inst.enableInternet).toBe(false);
    expect(inst.interceptHttps).toBe(true);
    expect(inst.greet()).toBe("hi");
  });

  it("attaches a static outbound handler", () => {
    const Governed = createGovernedSandbox(FakeBase as unknown as new () => object);
    expect(typeof (Governed as unknown as { outbound: unknown }).outbound).toBe("function");
  });
});

describe("governedSessionToken", () => {
  it("derives sandbox:<containerId>", () => {
    expect(governedSessionToken("abc")).toBe("sandbox:abc");
  });
});

describe("outbound handler", () => {
  it("allows and injects brokered identity for an allowed host", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok", { status: 200 }));
    const { ns, calls } = mockBroker((path) => {
      if (path === "/authorize")
        return Response.json({ verdict: "allow", target: "https://api.github.com/x", injectHeaders: { Authorization: "Bearer secret" } });
      return new Response(null, { status: 204 });
    });
    const outbound = makeOutboundHandler({ brokerBinding: "ZERONESS_BROKER" });
    const res = await outbound(new Request("https://api.github.com/x"), { ZERONESS_BROKER: ns }, { containerId: "cid1" });
    expect(res.status).toBe(200);
    // audit hit + authorize both keyed to the derived token
    expect(calls.some((c) => c.path === "/authorize" && (c.body as any).token === "sandbox:cid1")).toBe(true);
    // upstream fetch carried the injected identity
    const fwd = fetchSpy.mock.calls[0][0] as Request;
    expect(fwd.headers.get("Authorization")).toBe("Bearer secret");
    fetchSpy.mockRestore();
  });

  it("blocks a denied host with 403", async () => {
    const { ns } = mockBroker((path) => (path === "/authorize" ? Response.json({ verdict: "deny", reason: "no rule" }) : new Response(null, { status: 204 })));
    const outbound = makeOutboundHandler();
    const res = await outbound(new Request("https://example.com/"), { ZERONESS_BROKER: ns }, { containerId: "cid1" });
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("blocked by policy");
  });

  it("returns 451 for an ask verdict", async () => {
    const { ns } = mockBroker((path) => (path === "/authorize" ? Response.json({ verdict: "ask", approvalId: "ap_1", reason: "needs approval" }) : new Response(null, { status: 204 })));
    const outbound = makeOutboundHandler();
    const res = await outbound(new Request("https://postman-echo.com/"), { ZERONESS_BROKER: ns }, { containerId: "cid1" });
    expect(res.status).toBe(451);
    expect(res.headers.get("x-zeroness-approval")).toBe("ap_1");
  });

  it("500s when the broker binding is missing", async () => {
    const outbound = makeOutboundHandler({ brokerBinding: "MISSING" });
    const res = await outbound(new Request("https://x/"), {}, { containerId: "cid1" });
    expect(res.status).toBe(500);
  });
});

describe("registerGovernedSession", () => {
  it("registers under sandbox:<containerId> derived from the sandbox ns + name", async () => {
    const { ns, calls } = mockBroker((path) =>
      path === "/session" ? Response.json({ handleTokens: { gh: "zn_tok" } }) : new Response(null, { status: 204 }),
    );
    const sandboxNs = mockSandboxNs();
    const reg = await registerGovernedSession(ns, sandboxNs, "user-42", {
      policy: { default: "deny", allow: [{ host: "api.github.com" }] },
      resources: { gh: { accessToken: "T" } },
    });
    expect(reg.handleTokens.gh).toBe("zn_tok");
    const sessionCall = calls.find((c) => c.path === "/session");
    // sandbox:id(user-42) — the container DO id string for that name
    expect((sessionCall!.body as any).sessionToken).toBe("sandbox:id(user-42)");
  });
});
