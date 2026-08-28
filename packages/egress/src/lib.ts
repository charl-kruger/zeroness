/** Pure request-parsing helpers for the Egress Worker (unit-testable). */

/** Token from a header, or Proxy-Authorization / Authorization basic (password field). */
export function sessionToken(req: Request): string | null {
  const h = req.headers.get("x-zeroness-session-token");
  if (h) return h;
  const auth = req.headers.get("proxy-authorization") ?? req.headers.get("authorization");
  if (auth?.toLowerCase().startsWith("basic ")) {
    try {
      const [, pass] = atob(auth.slice(6)).split(":");
      if (pass) return pass;
    } catch { /* ignore */ }
  }
  return null;
}

/** The intended upstream: an absolute proxy URL, or the intercept target header. */
export function intendedTarget(req: Request): URL | null {
  const explicit = req.headers.get("x-zeroness-target");
  if (explicit) { try { return new URL(explicit); } catch { return null; } }
  try {
    const u = new URL(req.url);
    if (u.hostname && !u.hostname.endsWith(".workers.dev")) return u; // forward-proxy: absolute target
  } catch { /* ignore */ }
  return null;
}

const CAP_PREFIX = "/__zeroness/cap/";

/** If this request is a capability op, return the capability name; else null. */
export function capName(req: Request): string | null {
  try {
    const p = new URL(req.url).pathname;
    return p.startsWith(CAP_PREFIX) ? decodeURIComponent(p.slice(CAP_PREFIX.length)) : null;
  } catch {
    return null;
  }
}

const SNAP_PREFIX = "/__zeroness/snapshot/";

/** If this GET request is a snapshot download, return the ref; else null. */
export function snapshotRef(req: Request): string | null {
  try {
    const p = new URL(req.url).pathname;
    if (!p.startsWith(SNAP_PREFIX)) return null;
    const ref = p.slice(SNAP_PREFIX.length);
    return /^snap_[0-9a-f]+$/.test(ref) ? ref : null;   // upload/ and junk excluded
  } catch { return null; }
}

export function jsonResponse(v: unknown, status = 200): Response {
  return new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
}

export function deny(reason: string, status: number): Response {
  return new Response(JSON.stringify({ error: "blocked_by_zeroness", reason }), {
    status,
    headers: { "content-type": "application/json", "x-zeroness": "denied" },
  });
}
