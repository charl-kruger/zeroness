/**
 * zeroness — self-hosted egress proxy (the network-cage enforcement point).
 *
 * On a substrate without a built-in egress hook (e.g. a self-hosted celld node),
 * you jail the untrusted workload's network from OUTSIDE: a fail-closed firewall
 * drops all direct egress, and every outbound connection is forced through this
 * proxy. The proxy authorizes each connection against the zeroness Broker (policy
 * + brokered identity + audit), mirroring the Cloudflare Egress Worker.
 *
 * This is a Node process (uses node:net/node:http), distinct from the
 * Cloudflare-Worker Egress. It handles:
 *   - CONNECT (HTTPS tunnels): host+port policy on the CONNECT authority.
 *   - plain HTTP (absolute-form proxy requests): host+port+path policy.
 *
 * Path-scoped rules and identity injection over HTTPS require TLS interception
 * (a per-tenant MITM CA — see @zeroness/tls); this module is the L4/CONNECT jail
 * that makes egress default-deny. The internal-address floor from @zeroness/core
 * is enforced here too, as defense-in-depth.
 */

import net from "node:net";
import http from "node:http";
import { isForbiddenEgressHost } from "@zeroness/core";

export interface EgressDecision {
  allow: boolean;
  reason?: string;
}

/** Decides whether one outbound connection may proceed. Back this with the Broker. */
export type Authorizer = (req: {
  host: string;
  port: number;
  method: string;
  url?: string;
}) => Promise<EgressDecision>;

export interface EgressProxyOptions {
  authorize: Authorizer;
  /** Emit an audit line per decision. */
  onAudit?: (event: string, detail: unknown) => void;
  /** Enforce the internal/metadata-address floor (default true). Disable only in tests. */
  enforceInternalFloor?: boolean;
}

async function decide(
  opts: EgressProxyOptions,
  host: string,
  port: number,
  method: string,
  url?: string,
): Promise<EgressDecision> {
  if (opts.enforceInternalFloor !== false && isForbiddenEgressHost(host)) {
    return { allow: false, reason: "internal address blocked" };
  }
  try {
    return await opts.authorize({ host, port, method, url });
  } catch {
    return { allow: false, reason: "authorize error" }; // fail closed
  }
}

/** Build (but do not start) the egress proxy server. Call `.listen(port, host)`. */
export function createEgressProxy(opts: EgressProxyOptions): http.Server {
  const audit = opts.onAudit ?? (() => {});
  const server = http.createServer((req, res) => void handleHttp(req, res, opts, audit));
  server.on("connect", (req, socket, head) => void handleConnect(req, socket as net.Socket, head, opts, audit));
  return server;
}

async function handleConnect(
  req: http.IncomingMessage,
  clientSocket: net.Socket,
  head: Buffer,
  opts: EgressProxyOptions,
  audit: (e: string, d: unknown) => void,
): Promise<void> {
  const [host, portStr] = (req.url ?? "").split(":");
  const port = Number(portStr) || 443;
  const d = await decide(opts, host ?? "", port, "CONNECT", req.url);
  if (!d.allow) {
    audit("egress:deny", { host, port, reason: d.reason });
    clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
    clientSocket.end();
    return;
  }
  audit("egress:allow", { host, port });
  const upstream = net.connect(port, host ?? "", () => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head?.length) upstream.write(head);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  });
  upstream.on("error", () => clientSocket.destroy());
  clientSocket.on("error", () => upstream.destroy());
}

async function handleHttp(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  opts: EgressProxyOptions,
  audit: (e: string, d: unknown) => void,
): Promise<void> {
  let host = "";
  let port = 80;
  let path = "/";
  try {
    const u = new URL(req.url ?? "");
    host = u.hostname;
    port = Number(u.port) || 80;
    path = u.pathname + u.search;
  } catch {
    res.writeHead(400);
    res.end("egress proxy: absolute-form request required");
    return;
  }
  const d = await decide(opts, host, port, req.method ?? "GET", req.url);
  if (!d.allow) {
    audit("egress:deny", { host, port, reason: d.reason });
    res.writeHead(403, { "x-zeroness": "denied" });
    res.end(d.reason ?? "blocked by zeroness");
    return;
  }
  audit("egress:allow", { host, port });
  const upstream = http.request({ host, port, method: req.method, path, headers: req.headers }, (up) => {
    res.writeHead(up.statusCode ?? 502, up.headers);
    up.pipe(res);
  });
  upstream.on("error", () => {
    if (!res.headersSent) res.writeHead(502);
    res.end("upstream error");
  });
  req.pipe(upstream);
}

/** Authorizer backed by the zeroness Broker's /authorize endpoint. */
export function brokerAuthorizer(brokerUrl: string, sessionToken: string): Authorizer {
  const base = brokerUrl.replace(/\/$/, "");
  return async ({ host, port, method, url }) => {
    const target = url && /^https?:\/\//.test(url) ? url : `https://${host}:${port}/`;
    const res = await fetch(`${base}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: sessionToken, url: target, method: method === "CONNECT" ? "GET" : method }),
    });
    if (!res.ok) return { allow: false, reason: `broker ${res.status}` };
    const decision = (await res.json()) as { verdict: string; reason?: string };
    return { allow: decision.verdict === "allow", reason: decision.reason };
  };
}
