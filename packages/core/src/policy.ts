/**
 * zeroness — network policy engine.
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
  /** Re-origin the request to this base URL (re-origin an internal call onto a trusted gateway). */
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

/** Percent-decode to a fixed point, then resolve ./.. dot-segments. */
function canonicalPath(path: string): string {
  let p = path;
  for (let i = 0; i < 5; i++) {
    let decoded: string;
    try { decoded = decodeURIComponent(p); } catch { break; }
    if (decoded === p) break;
    p = decoded;
  }
  const out: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "..") { if (out.length > 1) out.pop(); }   // never pop past the root ""
    else if (seg !== ".") out.push(seg);
  }
  return out.join("/") || "/";
}

/** Lowercase and strip a single trailing dot. */
function canonicalHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}

/** True if `host` is a literal internal/metadata address that must never be an egress target. */
export function isForbiddenEgressHost(host: string): boolean {
  const h = canonicalHost(host).replace(/^\[|\]$/g, "");   // unwrap IPv6 URL brackets
  if (h === "localhost" || h === "metadata.google.internal") return true;
  if (h === "::1" || h === "::") return true;
  if (/^(fc|fd)[0-9a-f]{2}:/i.test(h)) return true;      // fc00::/7 ULA
  if (/^fe[89ab][0-9a-f]:/i.test(h)) return true;        // fe80::/10 link-local
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = Number(m[1]), b = Number(m[2]);
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  return false;
}

/**
 * Evaluate a request against a policy.
 * Order: explicit deny → first matching allow (carries verdict/identity/forward)
 * → layered transforms → policy default.
 */
export function evaluate(policy: NetworkPolicy, req: RequestInfo): Decision {
  const r: RequestInfo = { host: canonicalHost(req.host), method: req.method, path: canonicalPath(req.path) };
  for (const rule of policy.deny ?? []) {
    if (ruleMatches(rule, r)) {
      return { verdict: "deny", reason: `deny rule matched host=${rule.host}` };
    }
  }

  let decision: Decision | null = null;
  for (const rule of policy.allow ?? []) {
    if (ruleMatches(rule, r)) {
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
    if (ruleMatches(t, r)) {
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
