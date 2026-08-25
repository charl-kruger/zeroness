/**
 * zeroness — capability handles.
 *
 * Resources (R2/D1/KV/secrets/upstream identities) are handed to the sandbox as
 * OPAQUE handles ("cap:reports"). The real binding + any credential live only in
 * the broker; the sandbox never sees keys and cannot enumerate or forge
 * bindings. This is the capability-token pattern — opaque, unforgeable resource
 * handles — applied to Cloudflare resources.
 */

export type ResourceBinding =
  | { r2: string; mode?: "ro" | "rw"; prefix?: string }
  | { d1: string; mode?: "ro" | "rw" }
  | { kv: string; mode?: "ro" | "rw"; prefix?: string }
  | { queue: string }
  | { secret: string }        // a named secret, injected only at egress-time
  | { accessToken: string }   // a Cloudflare Access service token / OIDC identity
  | { oidc: { audience: string; subject?: string; ttlSeconds?: number } };

/** Author-facing map: friendly name → binding. Names become "cap:<name>". */
export type ResourceMap = Record<string, ResourceBinding>;

const CAP_RE = /^cap:([a-z0-9][a-z0-9_-]{0,63})(?::\/\/(.*))?$/i;

export interface ParsedCap {
  handle: string; // "cap:reports"
  name: string;   // "reports"
  path: string;   // "" or "2026/q3.csv"
}

/** Parse "cap:reports" or "cap:reports://2026/q3.csv". Returns null if not a cap URI. */
export function parseCap(uri: string): ParsedCap | null {
  const m = CAP_RE.exec(uri);
  if (!m) return null;
  return { handle: `cap:${m[1]}`, name: m[1]!.toLowerCase(), path: m[2] ?? "" };
}

export function isCap(uri: string): boolean {
  return CAP_RE.test(uri);
}

/** A per-session, unguessable token minted for a handle (never derivable by the sandbox). */
export function mintOpaqueToken(): string {
  const u = crypto.getRandomValues(new Uint8Array(24));
  let s = "";
  for (const b of u) s += b.toString(16).padStart(2, "0");
  return `zn_${s}`;
}
