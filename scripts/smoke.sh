#!/usr/bin/env bash
# Health check of the running demo (run ./scripts/up.sh first). Ends with "All 13 checks passed."
set -uo pipefail
. "$(dirname "$0")/lib.sh"

TOTAL=0; BAD=0
check() { # LABEL COMMAND...
  local label="$1"; shift
  TOTAL=$((TOTAL + 1))
  if "$@" >/dev/null 2>&1; then ok "$label"; else fail "$label"; BAD=$((BAD + 1)); fi
}
code_is() { [ "$(http_code "$1")" = "$2" ]; }
two_running() { [ "$($DC ps --status running -q | wc -l | tr -d ' ')" = "$EXPECTED_CONTAINERS" ]; }
catalog_ok() { curl -fsS -m 5 "http://$REGISTRY/v2/_catalog" >/dev/null; }
console_sees_registry() { [[ "$(curl -s -m 6 "$CONSOLE_URL/api/state")" == *'"registry_up": true'* ]]; }
key_pair() { [ -s "$KEYS_DIR/release.key" ] && [ -s "$KEYS_DIR/release.pub" ]; }
policy_valid() { python3 -c 'import json,sys; d = json.load(open(sys.argv[1])); assert d["deny"] and d["min_packages"] >= 1' "$POLICY_FILE"; }
sbom_checker_works() { # a made-up SBOM with a bad package must be refused, a clean one accepted
  local t; t="$(mktemp)"
  echo '{"packages":[{"name":"urllib3","versionInfo":"1.0.0"}]}' >"$t"; python3 "$ROOT/scripts/sbom_check.py" --sbom "$t" --policy "$POLICY_FILE" >/dev/null; [ $? -eq 1 ] || return 1
  echo '{"packages":[{"name":"urllib3","versionInfo":"2.2.3"}]}' >"$t"; python3 "$ROOT/scripts/sbom_check.py" --sbom "$t" --policy "$POLICY_FILE" >/dev/null; local rc=$?
  rm -f "$t"; [ "$rc" -eq 0 ]
}
results_dir() { test -d "$RESULTS_DIR"; }
dockerfile_ok() { grep -q '^FROM python:3' "$ROOT/app/Dockerfile"; }

check "Docker daemon reachable"                          $DOCKER info
check "both containers are running (registry, console)"  two_running
check "the registry answers on $REGISTRY"                code_is "http://$REGISTRY/v2/" 200
check "the registry catalog can be read"                 catalog_ok
check "the console is up"                                code_is "$CONSOLE_URL/healthz" 200
check "the console can see the registry"                 console_sees_registry
check "cosign is installed"                              cosign version
check "syft is installed"                                syft version
check "the release key pair exists"                      key_pair
check "the SBOM policy file is valid"                    policy_valid
check "the SBOM checker refuses a bad package and accepts a clean one" sbom_checker_works
check "the results folder exists"                        results_dir
check "the app Dockerfile is present"                    dockerfile_ok

echo
if [ "$BAD" -eq 0 ]; then echo "All $TOTAL checks passed."; exit 0; fi
echo "$BAD of $TOTAL checks failed." >&2
exit 1
