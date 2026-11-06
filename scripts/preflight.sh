#!/usr/bin/env bash
# Run this BEFORE the demo. It starts the stack, runs the smoke test, builds and signs a real image, lets it through the
# gate, makes sure an unsigned one is refused, and runs the unit tests, so any failure shows up now and not in front of an audience.
# Everything is left running; stop it with ./scripts/destroy.sh only AFTER the demo.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

FAILS=0
check() { # LABEL COMMAND...
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$label"; else fail "$label"; FAILS=$((FAILS + 1)); fi
}
pull_with_retry() { # IMAGE
  local i
  for i in 1 2 3; do
    $DOCKER pull "$1" >/dev/null 2>&1 && return 0
    sleep 3
  done
  return 1
}
# Docker Hub's /v2/ endpoint answers HTTP 401 (login required) when it is reachable.
# So 200 and 401 both mean "reachable". Do not add curl -f here.
hub_reachable() {
  local code
  code="$(curl -s -o /dev/null -m 10 -w '%{http_code}' https://registry-1.docker.io/v2/ || true)"
  [ "$code" = "200" ] || [ "$code" = "401" ]
}
disk_ok()   { [ "$(df -BG --output=avail / | tail -n1 | tr -dc '0-9')" -ge 5 ]; }
mem_ok()    { [ "$(free -m | awk '/^Mem:/{print $2}')" -ge 2000 ]; }
port_free() { ! python3 -c 'import socket, sys; s = socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)' "$1"; }
stack_up()  { "$ROOT/scripts/up.sh"; }
good_image_passes() { local d; d="$(release_image preflight good)" && [ -n "$d" ] && gate preflight; }
unsigned_refused()  { local d; d="$(build_push preflight-unsigned good)" && [ -n "$d" ] && ! gate preflight-unsigned; }
all_tests() { PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests; }

log "System checks"
check "Docker daemon reachable"                  $DOCKER info
check "Docker Compose v2 installed"              $DC version
check "python3 is installed"                     python3 --version
check "cosign is installed"                      cosign version
check "syft is installed"                        syft version
check "At least 5 GB free disk"                  disk_ok
check "At least 2 GB RAM"                        mem_ok
if [ "$($DC ps -q | wc -l | tr -d ' ')" -gt 0 ]; then
  ok "Stack already running (port checks skipped)"
else
  for port in 5000 8080 8081; do
    check "Port $port is free"                   port_free "$port"
  done
fi
check "Docker Hub reachable (HTTP 200 or 401)"   hub_reachable

log "Pulling images (up to 3 tries each)"
check "Pull ${PYTHON_IMAGE:-python:3.12-slim}"   pull_with_retry "${PYTHON_IMAGE:-python:3.12-slim}"
check "Pull ${REGISTRY_IMAGE:-registry:2}"       pull_with_retry "${REGISTRY_IMAGE:-registry:2}"

log "Starting everything"
check "up.sh: registry and console start and answer" stack_up
check "smoke.sh: all 13 checks pass"             "$ROOT/scripts/smoke.sh"
log "A real image through the gate (about 1-2 minutes)"
check "build, push, SBOM, sign, attest, gate, run a good image" good_image_passes
check "an unsigned image is refused by the gate" unsigned_refused

log "Tests"
check "Unit tests and repo tests"                all_tests

echo
if [ "$FAILS" -eq 0 ]; then
  echo "Preflight passed. Signed images with a clean SBOM run; everything else is refused. Next: ./scripts/demo.sh gameday"
  exit 0
fi
echo "Preflight found $FAILS problem(s). See the troubleshooting table in STEPS.md." >&2
echo "Pull failed? Run 'sudo docker login' with a free Docker Hub account." >&2
exit 1
