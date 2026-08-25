/**
 * edgelock — network policy engine.
 *
 * A NetworkPolicy is *data*: a default stance plus allow / deny / transform
 * rules. `evaluate()` turns an outbound request into a Decision the egress
 * Worker enforces. Pure, dependency-free, and unit-testable offline.
 */

export type Verdict = "allow" | "deny" | "ask";

export interface Rule {
  /** Host pattern: exact ("api.github.com"), wildcard ("*.pythonhosted.org"), or "*". Case-insensitive. */
  host: string;
  /** HTTP methods this rule covers. Omit = all methods. */
  methods?: string[];
  /** Path glob: "*" = one segment, "**" = any depth. Omit = any path. */
  path?: string;
  /** Verdict when this rule matches. Default "allow" for allow-rules, "deny" for deny-rules. */
  verdict?: Verdict;
  /** Capability handle whose brokered identity is injected on egress (e.g. "cap:stripe-ro"). */
  identity?: string;
  /** Re-origin the request to this base URL (Vercel "forwardURL" pattern). */
  forwardURL?: string;
  /** Header/path rewrites applied before forwarding. A null header value deletes it. */
  rewrite?: { headers?: Record<string, string | null>; path?: string };
}

export interface NetworkPolicy {
  /** Stance when no allow-rule matches. Secure default: "deny". */
  default: "deny" | "allow";
  /** Evaluated in order; first match wins. */
  allow?: Rule[];
  /** Hard denials, evaluated BEFORE allow — an explicit deny always wins. */
  deny?: Rule[];
  /** Rewriting rules layered onto an allowed request (identity/forwardURL/rewrite). */
  transform?: Rule[];
}

export interface RequestInfo {
  host: string;
  method: string;
  path: string; // pathname only, e.g. "/repos/cloudflare/workerd"
}

export interface Decision {
  verdict: Verdict;
  identity?: string;
  forwardURL?: string;
  rewrite?: Rule["rewrite"];
  /** Human-readable reason, surfaced in the audit log. */
  reason: string;
}

/** host pattern → RegExp. "*" = any host; "*.d.com" = any subdomain of d.com. */
function hostToRegExp(pattern: string): RegExp {
  if (pattern === "*") return /^.*$/;
  const p = pattern.toLowerCase();
  if (p.startsWith("*.")) {
    const base = escapeRe(p.slice(2));
    // one or more DNS labels, then the base domain
    return new RegExp(`^(?:[a-z0-9-]+\\.)+${base}$`);
  }
  return new RegExp(`^${escapeRe(p)}$`);
}

/** path glob → RegExp. "**" spans slashes; "*" stays within a segment. */
function pathToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") { re += ".*"; i++; }
      else re += "[^/]*";
    } else {
      re += escapeRe(c);
    }
  }
  return new RegExp(`^${re}$`);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function ruleMatches(rule: Rule, req: RequestInfo): boolean {
  if (!hostToRegExp(rule.host).test(req.host.toLowerCase())) return false;
  if (rule.methods && !rule.methods.map((m) => m.toUpperCase()).includes(req.method.toUpperCase())) return false;
  if (rule.path && !pathToRegExp(rule.path).test(req.path)) return false;
  return true;
}

/**
 * Evaluate a request against a policy.
 * Order: explicit deny → first matching allow (carries verdict/identity/forward)
 * → layered transforms → policy default.
 */
export function evaluate(policy: NetworkPolicy, req: RequestInfo): Decision {
  for (const rule of policy.deny ?? []) {
    if (ruleMatches(rule, req)) {
      return { verdict: "deny", reason: `deny rule matched host=${rule.host}` };
    }
  }

  let decision: Decision | null = null;
  for (const rule of policy.allow ?? []) {
    if (ruleMatches(rule, req)) {
      decision = {
        verdict: rule.verdict ?? "allow",
        identity: rule.identity,
        forwardURL: rule.forwardURL,
        rewrite: rule.rewrite,
        reason: `allow rule matched host=${rule.host}${rule.verdict === "ask" ? " (ask)" : ""}`,
      };
      break;
    }
  }

  if (!decision) {
    return {
      verdict: policy.default === "allow" ? "allow" : "deny",
      reason: `no allow rule; policy default=${policy.default}`,
    };
  }

  // Layer transforms onto an allowed/ask request (they add identity/rewrite, never loosen verdict).
  for (const t of policy.transform ?? []) {
    if (ruleMatches(t, req)) {
      decision.identity = decision.identity ?? t.identity;
      decision.forwardURL = decision.forwardURL ?? t.forwardURL;
      decision.rewrite = mergeRewrite(decision.rewrite, t.rewrite);
      decision.reason += `; transform host=${t.host}`;
    }
  }
  return decision;
}

function mergeRewrite(a: Rule["rewrite"], b: Rule["rewrite"]): Rule["rewrite"] {
  if (!a) return b;
  if (!b) return a;
  return {
    path: b.path ?? a.path,
    headers: { ...(a.headers ?? {}), ...(b.headers ?? {}) },
  };
}
