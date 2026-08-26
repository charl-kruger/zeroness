/**
 * zeroness — the developer-facing wrapper.
 *
 * `Zeroness` turns a bare Cloudflare Sandbox into a zero-trust, governed process:
 *   - starts with default-deny network + zero credentials,
 *   - routes all egress through the zeroness Egress Worker (policy + identity),
 *   - hands resources to the code as opaque `cap:` handles,
 *   - signs every command to the in-sandbox agent,
 *   - keeps a full audit trail in the Broker.
 *
 * It intentionally mirrors the @cloudflare/sandbox surface (exec / runCode /
 * writeFile …) so adoption is drop-in.
 */

import type { NetworkPolicy } from "./policy";
import type { ResourceMap } from "./capabilities";
import { parseCap, mintOpaqueToken } from "./capabilities";
import { generateSessionKey, exportPublicKeyRaw, signCommand, randomNonce, type Envelope } from "./signing";

/** Minimal shape of a @cloudflare/sandbox instance (getSandbox(env.Sandbox, id)). */
export interface CfSandbox {
  exec(command: string, opts?: unknown): Promise<{ stdout: string; stderr?: string; exitCode: number; success: boolean }>;
  createCodeContext(opts: { language: string }): Promise<unknown>;
  runCode(ctxOrCode: unknown, codeOrOpts?: unknown): Promise<unknown>;
  writeFile(path: string, data: string | Uint8Array, opts?: unknown): Promise<unknown>;
  readFile(path: string, opts?: unknown): Promise<{ content: string } | string>;
  setEnvVars?(vars: Record<string, string>): Promise<unknown>;
}

/** Injected so core has no hard dependency on the SDK package. Pass `getSandbox` from @cloudflare/sandbox. */
export type GetSandbox = (binding: unknown, id: string) => CfSandbox | Promise<CfSandbox>;

export interface ZeronessConfig {
  network?: NetworkPolicy;
  resources?: ResourceMap;
  /** Checkpoint the FS to R2 on "shutdown", or never (default). */
  snapshotOn?: "shutdown" | "never";
  /** Optional: enable per-sandbox CA TLS interception (default false — prefer L7 proxy). */
  tlsIntercept?: boolean;
  /**
   * URL of the in-sandbox agent (zeronessd) — typically the sandbox preview URL
   * for the agent port. When set, exec/writeFile/readFile/snapshot are executed
   * by the agent, which verifies the Ed25519 signature before running. When
   * unset, commands fall back to the raw SDK (still signed + audited).
   */
  agentUrl?: string;
}

export interface ZeronessOptions {
  sandboxBinding: unknown;         // env.Sandbox (the @cloudflare/sandbox binding)
  broker: DurableObjectNamespace;  // env.ZERONESS_BROKER
  egressUrl: string;               // public URL of the egress Worker, e.g. https://egress.example.workers.dev
  getSandbox: GetSandbox;          // from "@cloudflare/sandbox"
}

interface SessionRegistration {
  handleTokens: Record<string, string>; // cap name → opaque token
}

export class Zeroness {
  constructor(private readonly opts: ZeronessOptions) {}

  /** Create (or attach to) a governed sandbox for `id` with `config`. */
  async sandbox(id: string, config: ZeronessConfig = {}): Promise<ZeronessSandbox> {
    const sessionId = `${id}:${crypto.randomUUID()}`;
    // Mint the session token client-side so the Broker DO can be keyed by it —
    // the Egress Worker (which only knows the token) then reaches the same DO.
    const sessionToken = mintOpaqueToken();
    const brokerKey = `token:${sessionToken}`;
    const keys = await generateSessionKey();
    const pubKey = await exportPublicKeyRaw(keys.publicKey);

    // 1. Register the session with the Broker: it stores policy + resource
    //    bindings, mints opaque cap tokens, and remembers the agent public key.
    const reg = await this.broker(brokerKey, "POST", "/session", {
      sessionId,
      sessionToken,
      policy: config.network ?? { default: "deny" },
      resources: config.resources ?? {},
      pubKey,
    }) as SessionRegistration;

    // 2. Attach to the underlying Cloudflare Sandbox.
    const cf = await this.opts.getSandbox(this.opts.sandboxBinding, id);

    // 3. Steer ALL egress through the Egress Worker, authenticated as this
    //    session. Cloudflare Sandbox's outbound-intercept forwards to this URL;
    //    the proxy env vars are the portable fallback for HTTP clients.
    const proxy = new URL(this.opts.egressUrl);
    proxy.username = "zeroness";
    proxy.password = sessionToken;
    const env: Record<string, string> = {
      HTTP_PROXY: proxy.toString(),
      HTTPS_PROXY: proxy.toString(),
      http_proxy: proxy.toString(),
      https_proxy: proxy.toString(),
      // the agent (zeronessd) reads these at boot to verify signed commands + resolve caps
      ZERONESS_SESSION: sessionToken,
      ZERONESS_PUBKEY: pubKey,
      ZERONESS_EGRESS_URL: this.opts.egressUrl.replace(/\/$/, ""),
      ZERONESS_CAPS: Object.entries(reg.handleTokens).map(([n, t]) => `${n}=${t}`).join(","),
    };
    if (cf.setEnvVars) await cf.setEnvVars(env);
    else await cf.exec(`printf '%s\\n' ${Object.entries(env).map(([k, v]) => `'export ${k}=${shq(v)}'`).join(" ")} >> /etc/profile.d/zeroness.sh`);

    return new ZeronessSandbox(sessionId, cf, keys.privateKey, config, (m, p, b) => this.broker(brokerKey, m, p, b));
  }

  /** Resume/branch a sandbox from a snapshot ref returned by ZeronessSandbox.snapshot(). */
  async resume(snapshotRef: string, id = crypto.randomUUID()): Promise<ZeronessSandbox> {
    const box = await this.sandbox(id, {});
    await box.exec(`zeronessd restore ${shq(snapshotRef)}`); // agent pulls checkpoint from R2 via broker
    return box;
  }

  private async broker(key: string, method: string, path: string, body?: unknown): Promise<unknown> {
    const stub = this.opts.broker.get(this.opts.broker.idFromName(key));
    const res = await stub.fetch(`https://zeroness.broker${path}`, {
      method,
      headers: { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`broker ${method} ${path} → ${res.status}: ${await res.text()}`);
    return res.status === 204 ? undefined : await res.json();
  }
}

type BrokerCall = (method: string, path: string, body?: unknown) => Promise<unknown>;

export class ZeronessSandbox {
  private seq = 0;
  constructor(
    public readonly sessionId: string,
    private readonly cf: CfSandbox,
    private readonly signKey: CryptoKey,
    private readonly config: ZeronessConfig,
    private readonly broker: BrokerCall,
  ) {}

  /** Run a shell command — signed, audited, and (when an agent is configured) verified + executed by zeronessd. */
  async exec(command: string, opts?: unknown) {
    const viaAgent = await this.dispatch("exec", { command, opts });
    if (viaAgent) { await this.audit("exec", { command, exitCode: viaAgent.exitCode, agent: true }); return viaAgent; }
    const r = await this.cf.exec(command, opts);
    await this.audit("exec", { command, exitCode: r.exitCode });
    return r;
  }

  createCodeContext(opts: { language: string }) {
    return this.cf.createCodeContext(opts);
  }

  async runCode(ctxOrCode: unknown, codeOrOpts?: unknown) {
    const body = typeof ctxOrCode === "string" ? ctxOrCode : JSON.stringify(codeOrOpts ?? "");
    await this.dispatch("runCode", { body }); // signed + audited; execution stays on the SDK's code runtime
    const r = await this.cf.runCode(ctxOrCode, codeOrOpts);
    await this.audit("runCode", { bytes: body.length });
    return r;
  }

  /** Write a file. `cap:name://path` routes through the capability proxy (opaque). */
  async writeFile(path: string, data: string | Uint8Array, opts?: unknown) {
    const cap = parseCap(path);
    if (cap) return this.capIO("PUT", cap, data);
    const payload = data instanceof Uint8Array ? [...data] : data;
    const viaAgent = await this.dispatch("writeFile", { path, data: payload });
    if (viaAgent) return viaAgent;
    return this.cf.writeFile(path, data, opts);
  }

  async readFile(path: string, opts?: unknown) {
    const cap = parseCap(path);
    if (cap) return this.capIO("GET", cap);
    const viaAgent = await this.dispatch("readFile", { path });
    if (viaAgent) return viaAgent;
    return this.cf.readFile(path, opts);
  }

  /** Checkpoint FS state to R2 (content-addressed). The agent tars the FS and uploads it; returns a snapshot ref. */
  async snapshot(): Promise<string> {
    const viaAgent = await this.dispatch("snapshot", {});
    if (viaAgent?.ref) { await this.audit("snapshot", { ref: viaAgent.ref, agent: true }); return viaAgent.ref; }
    const { ref } = (await this.broker("POST", "/snapshot", { sessionId: this.sessionId })) as { ref: string };
    await this.audit("snapshot", { ref });
    return ref;
  }

  /** Full audit trail: every egress verdict + resource op + command. */
  async audit(event?: string, detail?: unknown): Promise<unknown> {
    if (event) return this.broker("POST", "/audit", { event, detail, ts: Date.now() });
    return this.broker("GET", "/audit");
  }

  /** Revoke the session: tokens stop working immediately at the egress Worker. */
  async destroy(): Promise<void> {
    if (this.config.snapshotOn === "shutdown") await this.snapshot().catch(() => {});
    await this.broker("DELETE", "/session");
  }

  /**
   * Sign a command, record it for audit, and — if an agent endpoint is
   * configured — send it to zeronessd (which verifies the Ed25519 signature
   * before executing) and return the agent's result. Returns null when no agent
   * is wired, so callers fall back to the raw SDK.
   */
  private async dispatch(procedure: Envelope["procedure"], args: unknown): Promise<any | null> {
    const body = JSON.stringify(args ?? {});
    const { envelope, signature } = await signCommand(
      this.signKey,
      { sid: this.sessionId, seq: ++this.seq, ts: Date.now(), nonce: randomNonce(), procedure },
      body,
    );
    await this.broker("POST", "/command", { envelope, signature });
    if (!this.config.agentUrl) return null;
    const res = await fetch(`${this.config.agentUrl.replace(/\/$/, "")}/command`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envelope, signature, body }),
    });
    if (!res.ok) throw new Error(`agent ${procedure} → ${res.status}: ${await res.text()}`);
    return res.json();
  }

  private async capIO(method: "GET" | "PUT", cap: ReturnType<typeof parseCap>, data?: string | Uint8Array) {
    return this.broker(method === "PUT" ? "POST" : "GET", `/cap/${cap!.name}`, {
      path: cap!.path,
      data: data instanceof Uint8Array ? [...data] : data,
    });
  }
}

/** Single-quote a value for safe embedding in a shell command. */
function shq(v: string): string {
  return `'${v.replace(/'/g, `'\\''`)}'`;
}
