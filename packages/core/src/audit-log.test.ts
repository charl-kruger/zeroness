import { describe, it, expect } from "vitest";
import { formatAuditLine, emitAuditLog, ZN_AUDIT } from "./audit-log";

describe("formatAuditLine", () => {
  it("emits a compact filterable envelope", () => {
    const line = formatAuditLine({ event: "egress:allow", ts: 1000, sessionId: "s1", detail: { host: "api.github.com" } });
    const parsed = JSON.parse(line);
    expect(parsed).toEqual({ zn: "audit", v: 1, ts: 1000, event: "egress:allow", sid: "s1", detail: { host: "api.github.com" } });
    expect(parsed.zn).toBe(ZN_AUDIT);
  });

  it("omits sid and detail when absent", () => {
    const parsed = JSON.parse(formatAuditLine({ event: "session:create", ts: 5 }));
    expect(parsed).toEqual({ zn: "audit", v: 1, ts: 5, event: "session:create" });
    expect("sid" in parsed).toBe(false);
    expect("detail" in parsed).toBe(false);
  });

  it("drops an oversized detail rather than emit a line that would be truncated", () => {
    const big = "x".repeat(20 * 1024);
    const parsed = JSON.parse(formatAuditLine({ event: "cap:write", detail: { blob: big } }));
    expect(parsed.detail).toEqual({ truncated: true });
    expect(JSON.stringify(parsed).length).toBeLessThan(16 * 1024);
  });
});

describe("emitAuditLog", () => {
  it("writes one JSON line via the injected logger", () => {
    const lines: string[] = [];
    emitAuditLog({ event: "egress:deny", ts: 2, detail: { reason: "no rule" } }, (m) => lines.push(m));
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]).event).toBe("egress:deny");
  });

  it("defaults ts to now", () => {
    const lines: string[] = [];
    const before = Date.now();
    emitAuditLog({ event: "heartbeat" }, (m) => lines.push(m));
    expect(JSON.parse(lines[0]).ts).toBeGreaterThanOrEqual(before);
  });
});
