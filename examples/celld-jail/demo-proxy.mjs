// The enforcement backend for the jail demo: the zeroness egress proxy.
//
// For a self-contained demo it authorizes with @zeroness/core `evaluate()` and a
// fixed policy. In production, swap `authorize` for `brokerAuthorizer(brokerUrl,
// token)` (also exported from @zeroness/egress-proxy) so policy, brokered
// identity, and audit come from the real zeroness Broker — which can itself run
// on celld (see docs/DEPLOY-celld.md).
import { createEgressProxy, brokerAuthorizer } from "@zeroness/egress-proxy";
import { evaluate } from "@zeroness/core";

const BROKER = process.env.ZERONESS_BROKER_URL;
const TOKEN = process.env.ZERONESS_SESSION ?? "";

const demoPolicy = {
  default: "deny",
  allow: [{ host: "example.com" }, { host: "*.example.com" }],
};

const authorize = BROKER
  ? brokerAuthorizer(BROKER, TOKEN)
  : async ({ host, method }) => {
      const d = evaluate(demoPolicy, { host, method: method === "CONNECT" ? "GET" : method, path: "/" });
      return { allow: d.verdict === "allow", reason: d.reason };
    };

const server = createEgressProxy({
  authorize,
  onAudit: (event, detail) => console.error(JSON.stringify({ zn: "proxy", event, detail })),
});
server.listen(8888, "127.0.0.1", () =>
  console.error(`[proxy] on 127.0.0.1:8888 (${BROKER ? "broker: " + BROKER : "demo policy: allow example.com"})`),
);
