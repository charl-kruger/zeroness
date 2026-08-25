/**
 * Example: a governed Cloudflare Sandbox with zeroness.
 *
 * The sandbox starts with default-deny network and zero credentials. It can pip
 * install (only from allow-listed hosts), read a public GitHub repo, and call
 * Stripe — but Stripe is gated (ask) and its credential is injected by the
 * Broker at egress-time, never placed in the sandbox.
 */
import { getSandbox } from "@cloudflare/sandbox";
import { Zeroness } from "@zeroness/core";

// Re-export the Broker DO so this Worker (or a sibling) can host it.
export { ZeronessBroker } from "@zeroness/broker";

export interface Env {
  Sandbox: DurableObjectNamespace;         // @cloudflare/sandbox binding
  ZERONESS_BROKER: DurableObjectNamespace;  // ZeronessBroker
  EGRESS_URL: string;                       // https://zeroness-egress.<acct>.workers.dev
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const zeroness = new Zeroness({
      sandboxBinding: env.Sandbox,
      broker: env.ZERONESS_BROKER,
      egressUrl: env.EGRESS_URL,
      getSandbox,
    });

    const box = await zeroness.sandbox("demo-user", {
      network: {
        default: "deny",
        allow: [
          { host: "pypi.org" },
          { host: "*.pythonhosted.org" },
          { host: "api.github.com", methods: ["GET"], path: "/repos/**" },
          { host: "api.stripe.com", verdict: "ask", identity: "cap:stripe-ro" },
        ],
        transform: [
          { host: "api.github.com", rewrite: { headers: { "user-agent": "zeroness-demo" } } },
        ],
      },
      resources: {
        "cap:stripe-ro": { accessToken: "STRIPE_RO" }, // resolved by the Broker only
        "cap:reports": { r2: "reports", mode: "rw", prefix: "demo-user/" },
      },
      snapshotOn: "shutdown",
    });

    try {
      await box.exec("pip install --quiet requests");
      const ghw = await box.exec(
        `python -c "import requests;print(requests.get('https://api.github.com/repos/cloudflare/workerd').status_code)"`,
      );
      const blocked = await box.exec(
        `python -c "import requests;print(requests.get('https://example.com').status_code)" || echo BLOCKED`,
      );
      await box.writeFile("cap:reports://run.txt", `github=${ghw.stdout.trim()} blocked=${blocked.stdout.trim()}`);

      const audit = await box.audit();
      return Response.json({ github: ghw.stdout.trim(), example_com: blocked.stdout.trim(), audit });
    } finally {
      await box.destroy();
    }
  },
};
