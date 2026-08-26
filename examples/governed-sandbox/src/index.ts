/**
 * Governed Cloudflare Sandbox — diagnostic of the SDK's native egress controls.
 *
 * This example probes how far Cloudflare Sandbox's selective egress controls
 * reach. FINDING (see /LIVE-VALIDATION.md): `allowedHosts` / `deniedHosts` and the
 * static `outbound` handler intercept only requests made through the SDK's own
 * fetch path. They do NOT govern raw in-container processes: with the allow-list
 * set to httpbingo.org only, an in-container `curl https://example.com` still
 * returns 200 and the `outbound` handler never fires. The only control that
 * governs arbitrary processes is `enableInternet = false` (all-or-nothing).
 *
 * zeroness's per-host, identity-injecting governance is therefore enforced at the
 * Egress Worker (the data plane in packages/egress), which every request reaches
 * by session token — proven live end-to-end in /LIVE-VALIDATION.md.
 */
import { getSandbox, proxyToSandbox, Sandbox as BaseSandbox } from "@cloudflare/sandbox";
export { ContainerProxy } from "@cloudflare/containers";

export interface Env {
  Sandbox: DurableObjectNamespace;
  ZERONESS_BROKER: DurableObjectNamespace;
}

// Minimal SDK egress test: internet on, deny one host. Does deniedHosts work at all?
export class Sandbox extends (BaseSandbox as unknown as { new (...a: unknown[]): object }) {
  deniedHosts = ["example.com"];
}

// Static outbound handler (per the Sandbox SDK). Runs in the Worker with Broker access.
(Sandbox as unknown as { outbound: unknown }).outbound = async (request: Request, env: Env, ctx: { sandboxId?: string }): Promise<Response> => {
  const token = `sandbox:live-sandbox`; // hardcoded for the test to remove sandboxId-mismatch as a variable
  const broker = env.ZERONESS_BROKER.get(env.ZERONESS_BROKER.idFromName(`token:${token}`));
  await broker.fetch("https://zeroness.broker/audit", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ event: "outbound:hit", detail: { url: request.url, sandboxId: ctx?.sandboxId ?? null } }),
  }).catch(() => {});
  const res = await broker.fetch("https://zeroness.broker/authorize", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, url: request.url, method: request.method }),
  });
  if (res.status === 401) return new Response(`zeroness: unknown session (sandboxId=${ctx?.sandboxId})`, { status: 403 });
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

    const sandboxId = "live-sandbox";
    const token = `sandbox:${sandboxId}`;
    const broker = env.ZERONESS_BROKER.get(env.ZERONESS_BROKER.idFromName(`token:${token}`));

    // register the policy for this sandbox (the outbound handler reads it by the same key)
    await broker.fetch("https://zeroness.broker/session", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: sandboxId, sessionToken: token, pubKey: "x",
        policy: { default: "deny", allow: [{ host: "httpbingo.org", identity: "cap:echo" }] },
        resources: { echo: { accessToken: "TEST_SECRET" } },
      }),
    });

    const box = getSandbox(env.Sandbox, sandboxId) as unknown as {
      exec(c: string): Promise<{ stdout: string }>;
      setAllowedHosts?(hosts: string[]): Promise<unknown>;
      setOutboundByHost?(host: string, handler: string): Promise<unknown>;
    };

    // Drive the SDK's native egress control at runtime from our policy.
    const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(box)).filter((m) => /outbound|allow|deny|host|internet/i.test(m));
    let setResult = "not-called";
    try {
      if (box.setAllowedHosts) { await box.setAllowedHosts(["httpbingo.org"]); setResult = "setAllowedHosts ok"; }
      else setResult = "setAllowedHosts missing";
    } catch (e) { setResult = "setAllowedHosts error: " + String(e instanceof Error ? e.message : e); }

    const allowed = await box.exec(`curl -s -m 15 -o /dev/null -w '%{http_code}' https://httpbingo.org/get || echo fail`);
    const blocked = await box.exec(`curl -s -m 15 -o /dev/null -w '%{http_code}' https://example.com/ || echo fail`);

    const audit = (await (await broker.fetch("https://zeroness.broker/audit")).json()) as Array<{ event: string }>;
    return Response.json({
      egress_methods_on_box: methods,       // which SDK egress methods exist
      set_allowed_hosts: setResult,
      allowed_host_status: allowed.stdout,  // httpbingo — expect 200 if allow-list works
      blocked_host_status: blocked.stdout,  // example.com — expect blocked
      audit_events: audit.map((a) => a.event),
    });
  },
};
