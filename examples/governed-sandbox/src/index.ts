/**
 * Governed Cloudflare Sandbox — full network jail via HTTPS interception.
 *
 * KEY: `interceptHttps = true` promotes the container to intercept ALL outbound
 * HTTPS (`interceptOutboundHttps('*')`) at the container network layer, so even a
 * raw in-container `curl https://...` is routed through the Worker `outbound`
 * handler — not just requests made through the SDK's own fetch path. The handler
 * asks the zeroness Broker to authorize each request and inject brokered
 * identity. Untrusted in-container code cannot bypass it.
 *
 * (Earlier finding, /LIVE-VALIDATION.md: with `interceptHttps` left at its default
 * of false, only SDK-fetch egress was intercepted and raw curl went direct. This
 * flag closes that gap on Cloudflare itself.)
 */
import { getSandbox, proxyToSandbox, Sandbox as BaseSandbox } from "@cloudflare/sandbox";
export { ContainerProxy } from "@cloudflare/containers";

export interface Env {
  Sandbox: DurableObjectNamespace;
  ZERONESS_BROKER: DurableObjectNamespace;
}

// The jail: the container gets NO direct internet, and ALL outbound HTTPS is
// intercepted at the network layer and routed through `outbound`. The handler
// runs in the Worker (which has normal internet) and does the real fetch only for
// policy-allowed hosts. Untrusted in-container code cannot reach the network
// except through this handler.
export class Sandbox extends (BaseSandbox as unknown as { new (...a: unknown[]): object }) {
  enableInternet = false;
  interceptHttps = true;
}

// Static catch-all outbound handler. Runs in the Worker with Broker access.
// Every intercepted request (SDK fetch OR raw curl) lands here.
(Sandbox as unknown as { outbound: unknown }).outbound = async (
  request: Request,
  env: Env,
  ctx: { sandboxId?: string },
): Promise<Response> => {
  const token = `sandbox:jail-clean-1`;
  const broker = env.ZERONESS_BROKER.get(env.ZERONESS_BROKER.idFromName(`token:${token}`));
  await broker
    .fetch("https://zeroness.broker/audit", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ event: "outbound:hit", detail: { url: request.url, sandboxId: ctx?.sandboxId ?? null } }),
    })
    .catch(() => {});
  const res = await broker.fetch("https://zeroness.broker/authorize", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, url: request.url, method: request.method }),
  });
  if (res.status === 401) return new Response(`zeroness: unknown session`, { status: 403 });
  const d = (await res.json()) as { verdict: string; target?: string; injectHeaders?: Record<string, string> };
  if (d.verdict === "deny") return new Response("zeroness: blocked by policy", { status: 403 });
  if (d.verdict === "ask") return new Response("zeroness: approval required", { status: 451 });
  const fwd = new Request(d.target ?? request.url, request);
  for (const [k, v] of Object.entries(d.injectHeaders ?? {})) fwd.headers.set(k, v);
  return fetch(fwd);
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const proxied = await proxyToSandbox(request, env);
    if (proxied) return proxied;
    if (new URL(request.url).pathname !== "/test") return new Response("GET /test to run the governed egress check");

    const sandboxId = "jail-clean-1";
    const token = `sandbox:${sandboxId}`;
    const broker = env.ZERONESS_BROKER.get(env.ZERONESS_BROKER.idFromName(`token:${token}`));

    // register the policy for this sandbox (the outbound handler reads it by the same key)
    await broker.fetch("https://zeroness.broker/session", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: sandboxId,
        sessionToken: token,
        pubKey: "x",
        policy: { default: "deny", allow: [{ host: "httpbingo.org", identity: "cap:echo" }] },
        resources: { echo: { accessToken: "TEST_SECRET" } },
      }),
    });

    const box = getSandbox(env.Sandbox, sandboxId) as unknown as { exec(c: string): Promise<{ stdout: string }> };

    const before = ((await (await broker.fetch("https://zeroness.broker/audit")).json()) as unknown[]).length;

    // -k: skip cert validation so we isolate WHETHER interception happens from CA trust.
    const allowed = await box.exec(`curl -k -s -m 20 -o /dev/null -w '%{http_code}' https://httpbingo.org/get || echo fail`);
    const blocked = await box.exec(`curl -k -s -m 20 -w ' [%{http_code}]' https://example.com/ || echo fail`);
    const blocked2 = await box.exec(`curl -k -s -m 20 -w ' [%{http_code}]' https://api.github.com/ || echo fail`);
    const injected = await box.exec(`curl -k -s -m 20 https://httpbingo.org/headers || echo fail`);

    const audit = (await (await broker.fetch("https://zeroness.broker/audit")).json()) as Array<{
      event: string;
      detail?: { url?: string; reason?: string };
    }>;
    return Response.json({
      allowed_httpbingo: allowed.stdout, // expect 200 (allowed, identity injected)
      blocked_example_com: blocked.stdout, // not in allow-list
      blocked_github: blocked2.stdout, // not in allow-list
      injected_headers: injected.stdout, // expect Authorization: Bearer ... injected by broker
      audit_this_run: audit.slice(before).map((a) => `${a.event} ${a.detail?.url ?? a.detail?.reason ?? ""}`.trim()),
    });
  },
};
