#!/usr/bin/env node
/**
 * zeroness-egress-proxy — run the egress jail proxy against a zeroness Broker.
 *
 *   zeroness-egress-proxy --broker https://broker.example --token <session> [--port 8888] [--host 127.0.0.1]
 *
 * Point the jailed workload's HTTP(S)_PROXY at host:port, and firewall all other
 * egress (fail-closed) so nothing bypasses it.
 */
import { createEgressProxy, brokerAuthorizer } from "./proxy";

function arg(name: string, def?: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : def;
}

const broker = arg("--broker", process.env.ZERONESS_BROKER_URL);
const token = arg("--token", process.env.ZERONESS_SESSION) ?? "";
const port = Number(arg("--port", "8888"));
const host = arg("--host", "127.0.0.1")!;

if (!broker) {
  console.error("usage: zeroness-egress-proxy --broker <url> --token <session> [--port 8888] [--host 127.0.0.1]");
  process.exit(2);
}

const server = createEgressProxy({
  authorize: brokerAuthorizer(broker, token),
  onAudit: (event, detail) => console.error(JSON.stringify({ zn: "egress-proxy", event, detail })),
});
server.listen(port, host, () => console.error(`zeroness egress proxy listening on ${host}:${port} -> broker ${broker}`));
