#!/usr/bin/env node
/**
 * create-zeroness — scaffold a governed Cloudflare Sandbox in one command.
 *
 *   npm create zeroness@latest my-app
 *   pnpm create zeroness my-app
 */
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const name = process.argv[2] ?? "my-zeroness-app";
const dir = join(process.cwd(), name);
if (existsSync(dir)) { console.error(`✗ ${name} already exists`); process.exit(1); }

const files = {
  "package.json": JSON.stringify({
    name, version: "0.0.0", private: true, type: "module",
    scripts: { dev: "wrangler dev", deploy: "wrangler deploy" },
    dependencies: { "@zeroness/core": "^0.1.0", "@zeroness/broker": "^0.1.0", "@cloudflare/sandbox": "^0.1.0" },
    devDependencies: { wrangler: "^3.80.0", "@cloudflare/workers-types": "^4.20240909.0" },
  }, null, 2),

  "wrangler.jsonc": `{
  "name": ${JSON.stringify(name)},
  "main": "src/index.ts",
  "compatibility_date": "2025-08-01",
  "compatibility_flags": ["nodejs_compat"],
  "vars": { "EGRESS_URL": "https://REPLACE-egress.workers.dev" },
  "durable_objects": {
    "bindings": [
      { "name": "Sandbox", "class_name": "Sandbox" },
      { "name": "ZERONESS_BROKER", "class_name": "ZeronessBroker" }
    ]
  },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["ZeronessBroker"] }],
  "r2_buckets": [{ "binding": "SNAPSHOTS", "bucket_name": "${name}-snapshots" }]
}
`,

  "src/index.ts": `import { getSandbox } from "@cloudflare/sandbox";
import { Zeroness } from "@zeroness/core";
export { ZeronessBroker } from "@zeroness/broker";

export interface Env {
  Sandbox: DurableObjectNamespace;
  ZERONESS_BROKER: DurableObjectNamespace;
  EGRESS_URL: string;
}

export default {
  async fetch(_req: Request, env: Env): Promise<Response> {
    const zeroness = new Zeroness({
      sandboxBinding: env.Sandbox,
      broker: env.ZERONESS_BROKER,
      egressUrl: env.EGRESS_URL,
      getSandbox,
    });

    // zero network, zero credentials by default — allow only what you list
    const box = await zeroness.sandbox("user-1", {
      network: {
        default: "deny",
        allow: [{ host: "api.github.com", methods: ["GET"], path: "/repos/**" }],
      },
    });

    const r = await box.exec("echo hello from a governed sandbox");
    const audit = await box.audit();
    await box.destroy();
    return Response.json({ stdout: r.stdout, audit });
  },
};
`,

  ".gitignore": "node_modules/\n.wrangler/\n.dev.vars\n",
  "README.md": `# ${name}\n\nA governed Cloudflare Sandbox powered by [zeroness](https://github.com/zeroness).\n\n## Setup\n\n1. Deploy the zeroness Broker + Egress Workers (see the zeroness repo).\n2. Set \`EGRESS_URL\` in \`wrangler.jsonc\`.\n3. \`pnpm install && pnpm deploy\`\n\nThe sandbox starts with **default-deny network** and **zero credentials**. Edit\nthe policy in \`src/index.ts\` to allow exactly what your code needs.\n`,
};

mkdirSync(join(dir, "src"), { recursive: true });
for (const [rel, content] of Object.entries(files)) {
  const p = join(dir, rel);
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, content);
}

console.log(`✓ created ${name}\n\nNext:\n  cd ${name}\n  pnpm install\n  # set EGRESS_URL in wrangler.jsonc, then:\n  pnpm deploy\n`);
