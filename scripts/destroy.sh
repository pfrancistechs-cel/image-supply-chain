#!/usr/bin/env bash
# Removes everything this project created on the instance: the containers (including the deployed app), the registry
# volume (all images and signatures), the demo image and the demo keys.   Usage: ./scripts/destroy.sh [--keep-env]
set -uo pipefail
. "$(dirname "$0")/lib.sh"

log "Stopping the stack and deleting the registry volume (this deletes every image and signature)"
$DOCKER rm -f sc-app >/dev/null 2>&1 || true
$DC down -v --remove-orphans

log "Removing the demo image and the images built for the demo"
$DOCKER rmi -f supplychain-demo:local >/dev/null 2>&1 || true
for img in $($DOCKER images --format '{{.Repository}}:{{.Tag}}' | grep "^$REGISTRY/$REPO:" || true); do $DOCKER rmi -f "$img" >/dev/null 2>&1 || true; done
$DOCKER image prune -f >/dev/null 2>&1 || true

rm -f "$ROOT"/results/*.json "$ROOT"/results/*.tmp "$KEYS_DIR"/*.key "$KEYS_DIR"/*.pub
if [ "${1:-}" != "--keep-env" ]; then rm -f "$ROOT/.env"; fi

echo
echo "Cleanup done. (cosign and syft stay installed; the registry and python images stay cached: sudo docker image prune -af)"
echo "IMPORTANT: terminate the EC2 instance in the AWS console (EC2 > Instances >"
echo "Instance state > Terminate) so it stops costing money. Then delete the security group."
