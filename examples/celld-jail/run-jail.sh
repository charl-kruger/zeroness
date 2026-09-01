#!/bin/bash
# Fail-closed egress jail demo (run in a Linux container with NET_ADMIN).
#
#   docker run --rm --cap-add=NET_ADMIN -v "$PWD:/app:ro" node:22-bookworm bash /app/run-jail.sh
#
# Runs the zeroness egress proxy as root, then firewalls a "workload" uid so it
# can reach ONLY the proxy — proving code that ignores HTTP_PROXY still cannot
# egress directly. This is the Vercel-style model: enforce at the network
# boundary around the compute unit, not inside the runtime.
set -u
apt-get update -qq >/tmp/apt.log 2>&1 && apt-get install -y -qq iptables curl >/tmp/apt.log 2>&1 || { echo "apt fail"; tail -5 /tmp/apt.log; exit 1; }
npm i -g esbuild >/tmp/esb.log 2>&1

rm -rf /work && cp -r /app /work && cd /work
# bundle the proxy (workspace deps inlined; node:* external). Requires the repo's
# node_modules to be present, or run `pnpm -w build` + copy dist first.
esbuild demo-proxy.mjs --bundle --format=esm --platform=node '--external:node:*' --outfile=proxy.mjs 2>/tmp/b.log \
  || { echo "BUNDLE_FAIL (need @zeroness/* resolvable — run from the built monorepo)"; cat /tmp/b.log; exit 1; }

node proxy.mjs &
PROXY=$!
sleep 1

WUID=2000
useradd -M -u "$WUID" workload || { echo "useradd failed"; exit 1; }

# ---- fail-closed firewall: workload uid may reach ONLY loopback (the proxy) ----
iptables -A OUTPUT -m owner --uid-owner "$WUID" -o lo -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner "$WUID" -d 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner "$WUID" -j DROP
echo "=== firewall installed (workload uid $WUID: only 127.0.0.1 reachable) ==="

run() { echo; echo "### $1"; shift; runuser -u workload -- "$@"; echo " (exit $?)"; }

run "A) via proxy to ALLOWED host (expect 200)" \
  curl -s -o /dev/null -w "http=%{http_code}" --max-time 15 -x http://127.0.0.1:8888 https://example.com/
run "B) via proxy to DENIED host (expect proxy deny, curl fail)" \
  curl -s -o /dev/null -w "http=%{http_code}" --max-time 15 -x http://127.0.0.1:8888 https://denied.invalid/
run "C) UNCOOPERATIVE direct connect ignoring proxy (expect firewall DROP)" \
  curl -s -o /dev/null -w "http=%{http_code}" --max-time 8 --noproxy '*' https://93.184.216.34/
run "D) via proxy to internal metadata (expect floor 403)" \
  curl -s -w " http=%{http_code}" --max-time 15 -x http://127.0.0.1:8888 http://169.254.169.254/latest/meta-data

kill "$PROXY" 2>/dev/null || true
