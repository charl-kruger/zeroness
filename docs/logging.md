# Audit logging and Logpush

zeroness records every governed crossing in two complementary places:

1. The Broker's Durable Object keeps a rolling audit log you can query at
   `GET /audit` (the last 1000 events per session). This is the interactive,
   per-session view.
2. Every event is also emitted as a compact structured `console.log` line, so it
   rides Cloudflare's own log pipeline: **Workers Logs** for retention and search,
   and **Workers Trace Events Logpush** for durable, off-platform delivery.

You do not write any logging code. Enable observability on the Broker Worker and
the events are there.

## The audit line

Each event is one JSON line with a stable, filterable envelope:

```json
{ "zn": "audit", "v": 1, "ts": 1787747927248, "event": "egress:deny", "sid": "user-1", "detail": { "reason": "no allow rule; policy default=deny" } }
```

- `zn` is always `"audit"`. Filter your logs and Logpush jobs on this field to
  select exactly the zeroness events.
- `event` is the verb: `session:create`, `egress:allow`, `egress:deny`,
  `egress:ask`, `approval:approve`, `approval:deny`, `cap:read`, `cap:write`,
  `command`, `heartbeat`, and so on.
- `sid` is the session id, when known.
- `detail` is kept small on purpose. Workers Trace Events Logpush truncates the
  combined logs and exceptions field at 16 KB per invocation, so zeroness drops an
  oversized `detail` rather than emit a line that would be split.

The helper is exported from `@zeroness/core` if you want to emit your own lines in
the same shape:

```ts
import { emitAuditLog } from "@zeroness/core";
emitAuditLog({ event: "egress:allow", sessionId: "user-1", detail: { host: "api.github.com" } });
```

## Workers Logs (7-day retention, queryable)

Turn on observability for the Broker Worker in its `wrangler.jsonc`:

```jsonc
{
  "observability": { "enabled": true, "head_sampling_rate": 1 }
}
```

Cloudflare then captures every audit line automatically. Retention is 7 days on
paid plans (3 days on free). In the dashboard (Workers and Pages, your Broker,
Observability) you can filter structured fields directly, for example
`zn = "audit"` and `event = "egress:deny"` to see every blocked request, or
`sid = "user-1"` to scope to one session.

`head_sampling_rate` is the fraction of invocations logged. Keep it at `1` for a
complete audit trail. Set `"invocation_logs": false` under `observability.logs`
if you want only the zeroness lines and not Cloudflare's per-request invocation
metadata.

## Logpush to your own sink

Workers Logs holds 7 days. For durable retention, SIEM ingest, or your data lake,
use **Workers Trace Events Logpush** to push the same lines to a destination you
control: R2, S3, GCS, Azure, Splunk, Datadog, Sumo Logic, or an HTTPS endpoint.

1. Add `"logpush": true` to the Broker's `wrangler.jsonc` (top level) and deploy.
2. Create a Logpush job on the `workers_trace_events` dataset pointing at your
   destination. For example, to R2 with the API:

   ```bash
   curl -X POST \
     "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/logpush/jobs" \
     -H "Authorization: Bearer $CF_API_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "zeroness-audit",
       "dataset": "workers_trace_events",
       "destination_conf": "r2://zeroness-audit/logs?account-id='"$ACCOUNT_ID"'&access-key-id='"$R2_KEY"'&secret-access-key='"$R2_SECRET"'",
       "output_options": {
         "field_names": ["ScriptName", "EventTimestampMs", "Outcome", "Logs", "Exceptions"],
         "timestamp_format": "rfc3339"
       },
       "filter": "{\"where\":{\"key\":\"ScriptName\",\"operator\":\"eq\",\"value\":\"zeroness-broker\"}}"
     }'
   ```

The `workers_trace_events` dataset carries `console.log` output in its `Logs`
field, so each zeroness audit line arrives intact. Parse the JSON in `Logs`
downstream and key on `zn = "audit"`.

Requirements: Logpush is available on the Workers Paid plan, and the API token
needs Logpush edit permission. See the Cloudflare docs for the full list of
destinations and the exact `destination_conf` for each.

## What this gives you

- A live, per-session trail from the Broker (`GET /audit`) for interactive use.
- A platform-captured, queryable trail for 7 days with no extra infrastructure.
- A durable, exportable trail wherever your team already keeps security logs,
  turned on with one config flag and one Logpush job.
