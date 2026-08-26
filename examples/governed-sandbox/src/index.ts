/**
 * Governed Cloudflare Sandbox — the network jail, straight from @zeroness/core.
 *
 * `createGovernedSandbox` gives the container NO direct internet and intercepts
 * ALL outbound HTTPS (`enableInternet=false` + `interceptHttps=true`), routing
 * every request — a raw in-container `curl` included, not just SDK fetch —
 * through a Broker-backed `outbound` handler. Allowed hosts get brokered identity
 * injected; everything else is denied and audited. Proven live in
 * /LIVE-VALIDATION.md.
 *
 * wrangler requirements: compatibility_flags include "enable_ctx_exports", and
 * ContainerProxy must be exported from the entrypoint (below).
 */
import { getSandbox, proxyToSandbox, Sandbox as BaseSandbox } from "@cloudflare/sandbox";
import { createGovernedSandbox, registerGovernedSession, sandboxContainerId } from "@zeroness/core";
export { ContainerProxy } from "@cloudflare/containers";

export interface Env {
  Sandbox: DurableObjectNamespace;
  ZERONESS_BROKER: DurableObjectNamespace;
}

// The governed container DO. Everything is wired by the SDK.
export const Sandbox = createGovernedSandbox(BaseSandbox as unknown as abstract new (...a: unknown[]) => object);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const proxied = await proxyToSandbox(request, env);
    if (proxied) return proxied;
    if (new URL(request.url).pathname !== "/test") return new Response("GET /test to run the governed egress check");

    const sandboxId = "jail-sdk-1";

    // Register this sandbox's policy with the Broker (default-deny; allow one host
    // with a brokered identity). The outbound handler reads it by the same token,
    // keyed on the container DO id derived from env.Sandbox + the same name.
    await registerGovernedSession(env.ZERONESS_BROKER, env.Sandbox, sandboxId, {
      policy: { default: "deny", allow: [{ host: "httpbingo.org", identity: "cap:echo" }] },
      resources: { echo: { accessToken: "TEST_SECRET" } },
    });

    const box = getSandbox(env.Sandbox, sandboxId) as unknown as { exec(c: string): Promise<{ stdout: string }> };
    const token = `sandbox:${sandboxContainerId(env.Sandbox, sandboxId)}`;
    const brokerStub = env.ZERONESS_BROKER.get(env.ZERONESS_BROKER.idFromName(`token:${token}`));
    const before = ((await (await brokerStub.fetch("https://zeroness.broker/audit")).json()) as unknown[]).length;

    // -k: skip cert validation so the test isolates "is it intercepted+governed"
    // from "does the client trust the interception CA" (see docs/recipes.md).
    const allowed = await box.exec(`curl -k -s -m 20 -o /dev/null -w '%{http_code}' https://httpbingo.org/get || echo fail`);
    const blocked = await box.exec(`curl -k -s -m 20 -w ' [%{http_code}]' https://example.com/ || echo fail`);
    const blocked2 = await box.exec(`curl -k -s -m 20 -w ' [%{http_code}]' https://api.github.com/ || echo fail`);
    const injected = await box.exec(`curl -k -s -m 20 https://httpbingo.org/headers || echo fail`);
    // CA-trust path: is the interception CA present at runtime, and does an
    // allowed host verify cleanly WITHOUT -k when we point curl at that CA?
    const caPresent = await box.exec(`ls -1 /etc/cloudflare/certs/ 2>&1 || echo none`);
    const cleanTls = await box.exec(`curl -s -m 20 -o /dev/null -w '%{http_code}' --cacert /etc/cloudflare/certs/cloudflare-containers-ca.crt https://httpbingo.org/get 2>&1 || echo fail`);
    const noTrust = await box.exec(`curl -s -m 20 -o /dev/null -w '%{http_code}' https://httpbingo.org/get 2>&1 || echo fail`);

    const audit = (await (await brokerStub.fetch("https://zeroness.broker/audit")).json()) as Array<{
      event: string;
      detail?: { url?: string; reason?: string };
    }>;
    return Response.json({
      allowed_httpbingo: allowed.stdout, // expect 200 (allowed, identity injected)
      blocked_example_com: blocked.stdout, // expect 403 zeroness: blocked by policy
      blocked_github: blocked2.stdout, // expect 403 zeroness: blocked by policy
      injected_headers: injected.stdout, // expect Authorization: Bearer ... injected by broker
      ca_present: caPresent.stdout, // is the interception CA on disk at runtime?
      clean_tls_with_cacert: cleanTls.stdout, // 200 => allowed host verifies cleanly via the CA (no -k)
      no_trust_result: noTrust.stdout, // what an untrusted client gets (fail-closed?)
      audit_this_run: audit.slice(before).map((a) => `${a.event} ${a.detail?.url ?? a.detail?.reason ?? ""}`.trim()),
    });
  },
};
