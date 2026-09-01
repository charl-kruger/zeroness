import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { createEgressProxy, type Authorizer } from "./proxy";

function listen(server: http.Server): Promise<number> {
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r((server.address() as AddressInfo).port)));
}

/** Make an HTTP request THROUGH the proxy (absolute-form, as a real HTTP proxy client does). */
function viaProxy(proxyPort: number, targetUrl: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const req = http.request(
      { host: "127.0.0.1", port: proxyPort, method: "GET", path: targetUrl, headers: { host: u.host } },
      (res) => {
        let b = "";
        res.on("data", (c) => (b += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe("egress proxy", () => {
  const servers: http.Server[] = [];
  afterEach(() => {
    for (const s of servers.splice(0)) s.close();
  });

  it("forwards an allowed request and blocks a denied one", async () => {
    const upstream = http.createServer((_q, s) => {
      s.writeHead(200);
      s.end("UPSTREAM-OK");
    });
    servers.push(upstream);
    const upPort = await listen(upstream);

    const authorize: Authorizer = async ({ host, port }) => ({ allow: host === "127.0.0.1" && port === upPort });
    const proxy = createEgressProxy({ authorize, enforceInternalFloor: false }); // floor off to use a loopback upstream
    servers.push(proxy);
    const pPort = await listen(proxy);

    const ok = await viaProxy(pPort, `http://127.0.0.1:${upPort}/`);
    expect(ok.status).toBe(200);
    expect(ok.body).toBe("UPSTREAM-OK");

    const denied = await viaProxy(pPort, `http://127.0.0.1:${upPort + 1}/`); // authorizer denies (port mismatch)
    expect(denied.status).toBe(403);
  });

  it("hard-blocks an internal target even when the authorizer is lenient", async () => {
    const authorize: Authorizer = async () => ({ allow: true }); // would allow everything
    const proxy = createEgressProxy({ authorize }); // floor ON (default)
    servers.push(proxy);
    const pPort = await listen(proxy);

    const res = await viaProxy(pPort, "http://169.254.169.254/latest/meta-data");
    expect(res.status).toBe(403);
    expect(res.body).toMatch(/internal address/);
  });
});
