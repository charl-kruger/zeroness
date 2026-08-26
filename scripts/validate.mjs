#!/usr/bin/env node
/**
 * Live validation harness (Phase 0).
 *
 * Point this at a deployed example worker and it asserts the governance
 * guarantees actually hold on a real Cloudflare Sandbox:
 *   - an allow-listed host is reachable,
 *   - a non-allow-listed host is blocked (default-deny),
 *   - the audit trail recorded both decisions.
 *
 *   node scripts/validate.mjs https://zeroness-example.<acct>.workers.dev
 *
 * Exit code 0 = all guarantees held; non-zero = a guarantee was violated.
 */
const base = process.argv[2];
if (!base) { console.error("usage: validate.mjs <example-worker-url>"); process.exit(2); }

const checks = [];
const check = (name, ok, detail = "") => { checks.push({ name, ok }); console.log(`${ok ? "✓" : "✗"} ${name}${detail ? "  — " + detail : ""}`); };

const res = await fetch(base).catch((e) => { console.error("request failed:", e.message); process.exit(2); });
if (!res.ok) { console.error(`example worker returned ${res.status}`); process.exit(2); }
const body = await res.json();

// The example allow-lists api.github.com and denies everything else.
check("allow-listed host reachable (github → 200)", body.github === "200", `got ${body.github}`);
check("default-deny blocks example.com", body.example_com === "BLOCKED" || body.example_com === "403", `got ${body.example_com}`);

const audit = Array.isArray(body.audit) ? body.audit : [];
check("audit recorded an allow", audit.some((a) => a.event === "egress:allow"), `${audit.length} entries`);
check("audit recorded a deny", audit.some((a) => a.event === "egress:deny"));
check("no long-lived secret surfaced to the sandbox", !JSON.stringify(body).match(/sk_live|AKIA|-----BEGIN/), "scanned response");

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} guarantees held.`);
process.exit(failed.length ? 1 : 0);
