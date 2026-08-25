/**
 * @zeroness/gatekeeper — human-in-the-loop for `ask` verdicts.
 *
 * When policy returns `ask`, the Broker creates a pending Approval and notifies a
 * GatekeeperAdapter (a human queue, a webhook, or a Cloudflare OS Gatekeeper).
 * A decision resolves the approval; the sandbox's retry then passes (or is
 * denied). The state machine here is pure and serializable so the Broker DO can
 * persist it; the adapters are the only side-effecting part.
 */

export type ApprovalStatus = "pending" | "approved" | "denied";

export interface ApprovalRequest {
  id: string;
  sessionId: string;
  method: string;
  url: string;
  identity?: string;
  reason: string;
  createdAt: number;
}

export interface Approval extends ApprovalRequest {
  status: ApprovalStatus;
  resolvedAt?: number;
  resolvedBy?: string;
}

/** Serializable store state — the Broker persists exactly this. */
export interface ApprovalState {
  approvals: Record<string, Approval>;
  /** approved (method+url) → expiry, so a retry within the window is allowed. */
  grants: Record<string, { expiresAt: number }>;
}

export function emptyApprovalState(): ApprovalState {
  return { approvals: {}, grants: {} };
}

/** Canonical key used to match a retry against a granted approval. */
export function approvalKey(method: string, url: string): string {
  return `${method.toUpperCase()} ${url}`;
}

/**
 * Pure operations over ApprovalState. Every method mutates `state` in place and
 * returns the relevant value, so the Broker can `store = new ApprovalStore(state)`
 * then persist `store.state` after the call.
 */
export class ApprovalStore {
  constructor(public state: ApprovalState = emptyApprovalState()) {}

  create(req: ApprovalRequest): Approval {
    const approval: Approval = { ...req, status: "pending" };
    this.state.approvals[req.id] = approval;
    return approval;
  }

  get(id: string): Approval | undefined {
    return this.state.approvals[id];
  }

  /** Approve a pending request; grants a reusable pass for `ttlMs`. */
  approve(id: string, resolvedBy = "human", ttlMs = 300_000, now = Date.now()): Approval | undefined {
    const a = this.state.approvals[id];
    if (!a || a.status !== "pending") return a;
    a.status = "approved";
    a.resolvedAt = now;
    a.resolvedBy = resolvedBy;
    this.state.grants[approvalKey(a.method, a.url)] = { expiresAt: now + ttlMs };
    return a;
  }

  deny(id: string, resolvedBy = "human", now = Date.now()): Approval | undefined {
    const a = this.state.approvals[id];
    if (!a || a.status !== "pending") return a;
    a.status = "denied";
    a.resolvedAt = now;
    a.resolvedBy = resolvedBy;
    return a;
  }

  /** True if a live grant covers this request (a prior approval, still within TTL). */
  isGranted(method: string, url: string, now = Date.now()): boolean {
    const g = this.state.grants[approvalKey(method, url)];
    if (!g) return false;
    if (g.expiresAt <= now) { delete this.state.grants[approvalKey(method, url)]; return false; }
    return true;
  }

  /** Drop expired grants (housekeeping). */
  sweep(now = Date.now()): void {
    for (const [k, g] of Object.entries(this.state.grants)) if (g.expiresAt <= now) delete this.state.grants[k];
  }
}

// ---- adapters: how a human/system is notified of a pending approval ----

export interface GatekeeperAdapter {
  onApprovalRequested(req: ApprovalRequest): Promise<void>;
}

/** Default: no notification — approvals are resolved out-of-band via the Broker API. */
export class ManualGatekeeper implements GatekeeperAdapter {
  async onApprovalRequested(): Promise<void> { /* no-op */ }
}

/** POST the pending approval to a webhook (Slack relay, ops console, etc.). */
export class WebhookGatekeeper implements GatekeeperAdapter {
  constructor(private url: string, private secret?: string) {}
  async onApprovalRequested(req: ApprovalRequest): Promise<void> {
    await fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/json", ...(this.secret ? { "x-zeroness-signature": this.secret } : {}) },
      body: JSON.stringify(req),
    });
  }
}

/**
 * Bridge to a Cloudflare OS Gatekeeper: routes the approval into the OS's
 * human-in-the-loop queue (simulate-then-apply). Endpoint/shape are wired to the
 * target OS instance; this adapter just forwards the request.
 */
export class CloudflareOSGatekeeper implements GatekeeperAdapter {
  constructor(private gatekeeperUrl: string, private token?: string) {}
  async onApprovalRequested(req: ApprovalRequest): Promise<void> {
    await fetch(`${this.gatekeeperUrl}/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(this.token ? { authorization: `Bearer ${this.token}` } : {}) },
      body: JSON.stringify({ kind: "egress", ...req }),
    });
  }
}
