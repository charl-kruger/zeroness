#!/usr/bin/env node
/**
 * create-zeroness, scaffold a governed Cloudflare Sandbox in one command.
 *
 *   npm create zeroness@latest my-app
 *   pnpm create zeroness my-app
 *
 * The generated project is the enforced network jail: a container with no direct
 * internet whose every outbound request is mediated by the zeroness Broker
 * (default-deny, brokered identity, audit). The Broker runs in the same Worker,
 * so the starter is self-contained.
 */
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const name = process.argv[2] ?? "my-zeroness-app";
const dir = join(process.cwd(), name);
if (existsSync(dir)) { console.error(`✗ ${name} already exists`); process.exit(1); }

const SANDBOX_IMAGE = "docker.io/cloudflare/sandbox:0.12.8";

const files = {
  "package.json": JSON.stringify({
    name, version: "0.0.0", private: true, type: "module",
    scripts: { dev: "wrangler dev", deploy: "wrangler deploy" },
    dependencies: {
      "@zeroness/core": "^0.2.0",
      "@zeroness/broker": "^0.2.0",
      "@cloudflare/sandbox": "^0.12.8",
      "@cloudflare/containers": "^0.3.5",
    },
    devDependencies: { wrangler: "^4.40.0", "@cloudflare/workers-types": "^4.20240909.0" },
  }, null, 2),

  "wrangler.jsonc": `{
  "name": ${JSON.stringify(name)},
  "main": "src/index.ts",
  "compatibility_date": "2025-11-01",
  // enable_ctx_exports is required for outbound HTTPS interception (the jail).
  "compatibility_flags": ["nodejs_compat", "enable_ctx_exports"],
  "containers": [
    { "class_name": "Sandbox", "image": "./Dockerfile", "max_instances": 1, "instance_type": "standard" }
  ],
  "durable_objects": {
    "bindings": [
      { "name": "Sandbox", "class_name": "Sandbox" },
      { "name": "ZERONESS_BROKER", "class_name": "ZeronessBroker" }
    ]
  },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["Sandbox", "ZeronessBroker"] }],
  "r2_buckets": [{ "binding": "SNAPSHOTS", "bucket_name": "${name}-snapshots" }]
}
`,

  "Dockerfile": `FROM ${SANDBOX_IMAGE}
# Outbound HTTPS is intercepted (MITM'd) with the Cloudflare containers CA. This
# base image already trusts that CA, so plain in-container HTTPS works cleanly and
# is still governed. If you switch to a base image that does not ship the CA,
# point clients at it at runtime (it is injected at
# /etc/cloudflare/certs/cloudflare-containers-ca.crt), e.g.
#   export CURL_CA_BUNDLE=/etc/cloudflare/certs/cloudflare-containers-ca.crt
#   export NODE_EXTRA_CA_CERTS=/etc/cloudflare/certs/cloudflare-containers-ca.crt
EXPOSE 3000
`,

  "src/index.ts": `import { getSandbox, proxyToSandbox, Sandbox as BaseSandbox } from "@cloudflare/sandbox";
import { createGovernedSandbox, registerGovernedSession } from "@zeroness/core";
export { ContainerProxy } from "@cloudflare/containers";
export { ZeronessBroker } from "@zeroness/broker";

export interface Env {
  Sandbox: DurableObjectNamespace;
  ZERONESS_BROKER: DurableObjectNamespace;
}

// The jail: no direct internet + all outbound HTTPS intercepted and mediated by
// the Broker. Export this as your container class.
export const Sandbox = createGovernedSandbox(BaseSandbox);

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const proxied = await proxyToSandbox(req, env);
    if (proxied) return proxied;

    const id = "user-1";
    // Default-deny network, zero credentials in the box. Allow only what you list;
    // secrets live in the Broker and are injected at egress via cap: handles.
    await registerGovernedSession(env.ZERONESS_BROKER, env.Sandbox, id, {
      policy: {
        default: "deny",
        allow: [{ host: "api.github.com", methods: ["GET"], path: "/repos/**" }],
      },
      // resources: { gh: { accessToken: "GH_READONLY" } }, // -> identity: "cap:gh"
    });

    const box = getSandbox(env.Sandbox, id);
    // A raw request inside the container is intercepted and governed:
    return Response.json(await box.exec("curl -s https://api.github.com/repos/cloudflare/workers-sdk"));
  },
};
`,

  ".gitignore": "node_modules/\n.wrangler/\n.dev.vars\n",
  "README.md": `# ${name}\n\nA governed Cloudflare Sandbox powered by [zeroness](https://github.com/charl-kruger/zeroness).\n\nThe container has **no direct internet**; every outbound request is intercepted\nand mediated by the zeroness Broker (default-deny, brokered identity, full audit).\nThis is the enforced jail, not just a proxy hint: a raw \`curl\` inside the\ncontainer cannot bypass it.\n\n## Setup\n\n1. \`pnpm install\`\n2. \`pnpm deploy\` (builds the container image; Docker must be running)\n\nEdit the policy in \`src/index.ts\` to allow exactly what your code needs. See the\n[recipes](https://github.com/charl-kruger/zeroness/blob/main/docs/recipes.md) for\nbrokered identity, human-in-the-loop approvals, and scoped resources.\n\n## TLS note\n\nInterception MITMs TLS with the Cloudflare containers CA at\n\`/etc/cloudflare/certs/cloudflare-containers-ca.crt\`. This base image already\ntrusts it, so plain in-container HTTPS works cleanly and is still governed. See\nthe \`Dockerfile\` if you switch base images.\n`,
};

mkdirSync(join(dir, "src"), { recursive: true });
for (const [rel, content] of Object.entries(files)) {
  const p = join(dir, rel);
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, content);
}

console.log(`✓ created ${name}\n\nNext:\n  cd ${name}\n  pnpm install\n  # start Docker, then:\n  pnpm deploy\n`);
