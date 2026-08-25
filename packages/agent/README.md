# @edgelock/agent — `edgelockd`

The tiny in-sandbox agent. It is the counterpart to the signed command channel
and the capability proxy. Ships as a single static binary/script baked into the
sandbox image (or `writeFile`-injected on first boot).

Responsibilities:
- **Verify signed commands.** Holds the session public key (delivered at boot);
  refuses any `exec`/`runCode`/`writeFile`/`snapshot` whose Ed25519 envelope is
  invalid, stale (freshness window), or replayed (monotonic `seq`).
- **Serve capability I/O.** Exposes a localhost endpoint (`$EDGELOCK_CAPS`) that
  the SDK/CLI uses for `cap:` reads/writes, forwarding to the Broker so the code
  never holds real credentials.
- **Heartbeat + attestation.** Periodically reports liveness and a measurement of
  its own config to the Broker, so a wedged or tampered sandbox is detectable
  (the defense-in-depth we recommend given the container-based substrate).
- **Snapshot/restore.** On command, tars the writable FS and streams it to R2
  (content-addressed) via the Broker; `restore` pulls one back.

Status: **Phase 3 scaffold.** `edgelockd.mjs` sketches the verify loop; the
transport (how signed envelopes reach the agent — a localhost control socket vs.
riding on the exec channel) is the main open wiring decision.
