/**
 * Structured audit logging for Cloudflare's log pipeline.
 *
 * zeroness records every governed crossing in the Broker's Durable Object, queryable
 * via the /audit API. It ALSO emits each event as a single compact structured
 * console.log line, so Cloudflare Workers Logs captures it automatically (7-day
 * retention on paid plans, filterable by field in the dashboard) and Workers Trace
 * Events Logpush can ship it to R2, S3, Splunk, Datadog, or an HTTP endpoint for
 * durable retention and SIEM ingest, with no code changes.
 *
 * The envelope is intentionally small: the Logpush Logs+Exceptions field truncates
 * at 16 KB combined per invocation. Filter your logs or Logpush job to zeroness
 * events by the marker field `zn = "audit"`.
 */

/** Marker value on every zeroness audit line. Filter with `zn = "audit"`. */
export const ZN_AUDIT = "audit" as const;

export interface AuditLogEvent {
  /** e.g. "egress:allow", "egress:deny", "egress:ask", "approval:approve", "cap:read". */
  event: string;
  /** Epoch milliseconds. Defaults to Date.now(). */
  ts?: number;
  /** The governed session this event belongs to, when known. */
  sessionId?: string;
  /** Small, event-specific fields. Kept compact for the Logpush size cap. */
  detail?: unknown;
}

/** The shape of the JSON line emitted to Workers Logs. */
export interface AuditLogLine {
  zn: typeof ZN_AUDIT;
  v: 1;
  ts: number;
  event: string;
  sid?: string;
  detail?: unknown;
}

/** Keep a comfortable margin under the 16 KB Logpush Logs+Exceptions cap. */
const MAX_LINE_BYTES = 12 * 1024;

/** Serialize an audit event to a single compact JSON line for the log pipeline. */
export function formatAuditLine(e: AuditLogEvent): string {
  const line: AuditLogLine = {
    zn: ZN_AUDIT,
    v: 1,
    ts: e.ts ?? Date.now(),
    event: e.event,
    ...(e.sessionId ? { sid: e.sessionId } : {}),
    ...(e.detail !== undefined ? { detail: e.detail } : {}),
  };
  let s = JSON.stringify(line);
  if (s.length > MAX_LINE_BYTES) {
    // If a detail payload is oversized, drop it rather than risk truncation
    // splitting the JSON and breaking downstream parsers.
    s = JSON.stringify({ zn: ZN_AUDIT, v: 1, ts: line.ts, event: line.event, sid: line.sid, detail: { truncated: true } });
  }
  return s;
}

/**
 * Emit an audit event as a structured console.log line. `log` is injectable for
 * tests; in a Worker or Durable Object the default (console.log) is what Workers
 * Logs and Logpush capture.
 */
export function emitAuditLog(e: AuditLogEvent, log: (msg: string) => void = console.log): void {
  log(formatAuditLine(e));
}
