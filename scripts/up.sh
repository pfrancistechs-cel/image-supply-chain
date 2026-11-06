#!/usr/bin/env bash
# Starts the registry and the console, makes the signing keys, and waits until everything answers.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
mkdir -p "$RESULTS_DIR"; chmod 755 "$RESULTS_DIR"
command -v cosign >/dev/null && command -v syft >/dev/null || die "cosign or syft is missing. Run ./scripts/setup.sh first."

log "Starting the registry and the console (first start pulls registry:2 and builds one small image, 1-2 minutes)"
$DC up -d --build

log "Waiting for every part to answer"
wait_until 60 registry_up && ok "the registry answers on $REGISTRY" || die "Run: $DOCKER logs --tail 30 sc-registry"
wait_http "the console" "$CONSOLE_URL/healthz" 60 || die "Run: $DOCKER logs --tail 30 sc-console"

key_gen release  && ok "the release signing key exists (keys/release.key, keys/release.pub)"
key_gen attacker && ok "an 'attacker' key exists for the demo (keys/attacker.key)"

IP="$(public_ip)"
cat <<EOF

Ready. Open this in your browser (from the laptop allowed by the security group):
  Supply-chain console : http://${IP}:8081/    <- keep it open
  The deployed app     : http://${IP}:8080/    <- appears after the gate lets an image through

Next: ./scripts/smoke.sh   then   ./scripts/demo.sh gameday
By hand: ./scripts/supply.sh release 1.0.0   then   ./scripts/supply.sh gate 1.0.0
EOF
