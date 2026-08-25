import { describe, it, expect } from "vitest";
import { ApprovalStore, approvalKey } from "./index";

const req = (id: string) => ({ id, sessionId: "s1", method: "POST", url: "https://api.stripe.com/v1/charges", reason: "ask", createdAt: 0 });

describe("approval state machine", () => {
  it("creates pending approvals", () => {
    const s = new ApprovalStore();
    expect(s.create(req("a1")).status).toBe("pending");
    expect(s.get("a1")?.status).toBe("pending");
  });

  it("approve grants a reusable pass; retry within TTL is allowed", () => {
    const s = new ApprovalStore();
    s.create(req("a1"));
    expect(s.isGranted("POST", "https://api.stripe.com/v1/charges", 0)).toBe(false); // before approval
    s.approve("a1", "alice", 300_000, 0);
    expect(s.get("a1")?.status).toBe("approved");
    expect(s.isGranted("POST", "https://api.stripe.com/v1/charges", 1000)).toBe(true);   // retry passes
    expect(s.isGranted("POST", "https://api.stripe.com/v1/charges", 400_000)).toBe(false); // TTL expired
  });

  it("deny leaves no grant", () => {
    const s = new ApprovalStore();
    s.create(req("a1"));
    s.deny("a1", "bob", 0);
    expect(s.get("a1")?.status).toBe("denied");
    expect(s.isGranted("POST", "https://api.stripe.com/v1/charges", 1)).toBe(false);
  });

  it("grants are scoped to the exact method+url", () => {
    const s = new ApprovalStore();
    s.create(req("a1"));
    s.approve("a1", "alice", 300_000, 0);
    expect(s.isGranted("GET", "https://api.stripe.com/v1/charges", 1)).toBe(false); // different method
    expect(s.isGranted("POST", "https://api.stripe.com/v1/refunds", 1)).toBe(false); // different url
  });

  it("state is serializable (survives JSON round-trip in DO storage)", () => {
    const s = new ApprovalStore();
    s.create(req("a1")); s.approve("a1", "alice", 300_000, 0);
    const revived = new ApprovalStore(JSON.parse(JSON.stringify(s.state)));
    expect(revived.isGranted("POST", "https://api.stripe.com/v1/charges", 1)).toBe(true);
  });

  it("approvalKey is stable and case-normalized on method", () => {
    expect(approvalKey("post", "https://x")).toBe("POST https://x");
  });
});
