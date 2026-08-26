/**
 * Live governance test harness.
 *
 * Stands up a session on the deployed Broker and returns its token, so we can
 * exercise the deployed Egress Worker exactly as a sandbox would — proving the
 * policy engine, identity brokering, and audit work on real Cloudflare infra
 * (without needing the container/sandbox).
 */
import { mintOpaqueToken } from "@zeroness/core";

export interface Env {
  ZERONESS_BROKER: DurableObjectNamespace; // bound to the deployed zeroness-broker DO
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/new-session") {
      const sessionToken = mintOpaqueToken();
      const stub = env.ZERONESS_BROKER.get(env.ZERONESS_BROKER.idFromName(`token:${sessionToken}`));
      const res = await stub.fetch("https://zeroness.broker/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sessionId: "live-test",
          sessionToken,
          pubKey: "x",
          policy: {
            default: "deny",
            allow: [
              { host: "api.github.com", methods: ["GET"], path: "/repos/**" },
              { host: "httpbingo.org", identity: "cap:echo" },
              { host: "postman-echo.com", verdict: "ask", identity: "cap:echo" }, // human-in-the-loop
            ],
          },
          resources: { echo: { accessToken: "TEST_SECRET" } }, // resolved by the Broker only
        }),
      });
      const reg = await res.json();
      return Response.json({ sessionToken, reg });
    }

    if (url.pathname === "/approve") {
      const token = url.searchParams.get("token"); const id = url.searchParams.get("id");
      const stub = env.ZERONESS_BROKER.get(env.ZERONESS_BROKER.idFromName(`token:${token}`));
      const res = await stub.fetch(`https://zeroness.broker/approval/${id}/approve`, { method: "POST" });
      return new Response(res.body, { headers: { "content-type": "application/json" } });
    }

    // convenience: read a session's audit trail
    if (url.pathname === "/audit") {
      const token = url.searchParams.get("token")!;
      const stub = env.ZERONESS_BROKER.get(env.ZERONESS_BROKER.idFromName(`token:${token}`));
      const res = await stub.fetch("https://zeroness.broker/audit");
      return new Response(res.body, { headers: { "content-type": "application/json" } });
    }

    return new Response("zeroness live-test control worker\n/new-session · /audit?token=");
  },
};
