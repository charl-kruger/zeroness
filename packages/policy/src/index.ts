/**
 * @zeroness/policy — author, lint, and simulate network policies offline.
 *
 * Policy is data, so you can test it without deploying: run a batch of requests
 * through `simulate()` and lint for foot-guns before it ever governs a sandbox.
 */
import { evaluate, type NetworkPolicy, type Decision, type RequestInfo } from "@zeroness/core";

export interface Finding {
  level: "error" | "warn" | "info";
  message: string;
}

/** Static analysis of a policy: catch the classic mistakes before they ship. */
export function lint(policy: NetworkPolicy): Finding[] {
  const out: Finding[] = [];
  if (policy.default === "allow") {
    out.push({ level: "warn", message: "default:allow — the sandbox can reach the entire internet. Prefer default:deny." });
  }
  for (const r of policy.allow ?? []) {
    if (r.host === "*") out.push({ level: "warn", message: "allow rule host:'*' matches every host — scope it down." });
    if (r.verdict === "ask" && !r.identity) {
      out.push({ level: "info", message: `ask rule for '${r.host}' has no identity — approval will carry no brokered credential.` });
    }
    if (r.forwardURL) {
      try { new URL(r.forwardURL); } catch { out.push({ level: "error", message: `invalid forwardURL on '${r.host}': ${r.forwardURL}` }); }
    }
  }
  if (!(policy.allow?.length) && policy.default === "deny") {
    out.push({ level: "info", message: "no allow rules with default:deny — the sandbox has no network at all." });
  }
  return out;
}

/** Run requests through the policy and return the decision for each. */
export function simulate(policy: NetworkPolicy, requests: RequestInfo[]): Array<{ req: RequestInfo; decision: Decision }> {
  return requests.map((req) => ({ req, decision: evaluate(policy, req) }));
}

/** Pretty one-line summary of a simulation, for CLIs/CI. */
export function formatSimulation(rows: Array<{ req: RequestInfo; decision: Decision }>): string {
  return rows
    .map(({ req, decision }) => {
      const mark = decision.verdict === "allow" ? "✓" : decision.verdict === "ask" ? "?" : "✗";
      const id = decision.identity ? ` [${decision.identity}]` : "";
      return `${mark} ${req.method} ${req.host}${req.path} → ${decision.verdict}${id}  (${decision.reason})`;
    })
    .join("\n");
}
