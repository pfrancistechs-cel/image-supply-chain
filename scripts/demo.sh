#!/usr/bin/env bash
# Scripted supply-chain tour. Usage: ./scripts/demo.sh [release|unsigned|tamper|badsbom|wrongkey|gameday]
# Keep the console (http://<EC2-PUBLIC-IP>:8081/) open while it runs.
#   release   build, SBOM, sign, attest, then the gate lets the image through and the app starts
#   unsigned  someone pushes an image without a signature: the gate refuses, the old app keeps running
#   tamper    an attacker overwrites a signed tag with different content: the tag now points elsewhere, the gate refuses
#   badsbom   a properly signed image that contains a vulnerable library: the signature is fine, the SBOM policy refuses
#   wrongkey  an image signed with someone else's key: refused
set -uo pipefail
. "$(dirname "$0")/lib.sh"

FAILURES=0
assert() { # LABEL COMMAND...
  local label="$1"; shift
  if "$@"; then ok "$label"; else fail "$label"; FAILURES=$((FAILURES + 1)); fi
}
finish() {
  if [ "$FAILURES" -eq 0 ]; then printf '\n\033[1;32mPASS\033[0m  %s\n\n' "$1"; else printf '\n\033[1;31mFAIL\033[0m  %s\n\n' "$1"; exit 1; fi
}
eq() { [ "$1" = "$2" ]; }
ne() { [ "$1" != "$2" ]; }
refused() { ! "$@"; }          # the command must fail (its output stays visible)
app_version_is() { [ "$(curl -s -m 3 "$APP_URL/info" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])' 2>/dev/null)" = "$1" ]; }
verdict_is() { [ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[-1]["verdict"])' "$RESULTS_DIR/decisions.json")" = "$1" ]; }
sbom_lists() { python3 - "$1" "$2" "$3" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if any(p["name"] == sys.argv[2] and p["versionInfo"] == sys.argv[3] for p in d["packages"]) else 1)
PY
}

need_stack() {
  registry_up || die "The stack is not running. Run ./scripts/up.sh first."
  mkdir -p "$RESULTS_DIR"
  key_gen release && key_gen attacker || die "Could not make the signing keys (is cosign installed? ./scripts/setup.sh)"
}

# Every scenario first makes sure a known-good version is deployed, so "the old app keeps running" can be checked.
ensure_baseline() {
  local d
  d="$(tag_digest base)"
  if [ -z "$d" ] || ! verify_sig "$d"; then d="$(release_image base good)" || die "could not build the baseline image"; fi
  gate base >/dev/null || die "the baseline image was refused by the gate"
  BASE_DIGEST="$d"
}

scenario_release() {
  log "SCENARIO release: build, SBOM, sign, attest, gate, run"
  local d sbom
  d="$(build_push 1.0.0 good)"; assert "the image is in the registry" ne "$d" ""
  say "digest $d"
  sbom="$(sbom_make "$d")"; assert "the SBOM was made from the image in the registry" test -s "$sbom"
  assert "the SBOM lists urllib3 2.2.3 (the app's one dependency)" sbom_lists "$sbom" urllib3 2.2.3
  assert "signing succeeds"                     sign_image "$d" release
  assert "the SBOM is attested (signed and bound to this digest)" attest_sbom "$d" release "$sbom"
  assert "the signature verifies with the public key" verify_sig "$d"
  assert "the signature does NOT verify with another key" refused verify_sig "$d" attacker
  say "gate:"
  assert "the gate lets it through"             gate 1.0.0
  assert "the application answers and reports version 1.0.0" app_version_is 1.0.0
  assert "it is running exactly this digest"    app_runs_digest "$d"
  assert "the decision was recorded as ALLOW"   verdict_is ALLOW
  finish release
}

scenario_unsigned() {
  log "SCENARIO unsigned: an image nobody signed"
  ensure_baseline
  local d
  d="$(build_push 1.1.0-unsigned good)"; assert "the unsigned image is in the registry" ne "$d" ""
  say "gate:"
  assert "the gate refuses it"                  refused gate 1.1.0-unsigned
  assert "the decision was recorded as DENY"    verdict_is DENY
  assert "the previous application is still running" app_runs_digest "$BASE_DIGEST"
  finish unsigned
}

scenario_tamper() {
  log "SCENARIO tamper: someone overwrites a signed tag"
  ensure_baseline
  local good evil
  good="$(release_image 2.0.0 good)"; assert "2.0.0 is released and signed" ne "$good" ""
  say "digest of 2.0.0 today: $(short "$good")"
  say "ATTACKER pushes different content under the same tag 2.0.0 ..."
  evil="$(build_push 2.0.0 good evil-2.0.0)"
  say "digest of 2.0.0 now:   $(short "$evil")"
  assert "the tag points to a different digest now" ne "$good" "$evil"
  say "gate on the tag:"
  assert "the gate refuses the moved tag"       refused gate 2.0.0
  assert "the tampered image has no valid signature" refused verify_sig "$evil"
  say "gate on the original digest (what a pinned deployment uses):"
  assert "the original, signed digest is still accepted" gate "$good"
  assert "it is the original code that runs, not the attacker's" app_version_is 2.0.0
  finish tamper
}

scenario_badsbom() {
  log "SCENARIO badsbom: signed correctly, but contains a vulnerable library"
  ensure_baseline
  local d
  d="$(release_image 3.0.0 bad)"; assert "3.0.0 (urllib3 1.26.4) is built, signed and its SBOM attested" ne "$d" ""
  assert "its signature is valid"               verify_sig "$d"
  say "gate:"
  assert "the gate refuses it anyway"           refused gate 3.0.0
  assert "the reason is in the console's decision list" verdict_is DENY
  assert "the previous application is still running" app_runs_digest "$BASE_DIGEST"
  say "the fix: rebuild with the patched library and release again"
  d="$(release_image 3.0.1 good)"
  assert "3.0.1 is accepted"                    gate 3.0.1
  finish badsbom
}

scenario_wrongkey() {
  log "SCENARIO wrongkey: an image signed with a key we do not trust"
  ensure_baseline
  local d
  d="$(release_image 4.0.0 good attacker)"; assert "4.0.0 is built and signed by the attacker key" ne "$d" ""
  assert "it verifies with the attacker's own key" verify_sig "$d" attacker
  say "gate:"
  assert "the gate refuses it"                  refused gate 4.0.0
  assert "the previous application is still running" app_runs_digest "$BASE_DIGEST"
  finish wrongkey
}

need_stack
case "${1:-gameday}" in
  release)  scenario_release ;;
  unsigned) scenario_unsigned ;;
  tamper)   scenario_tamper ;;
  badsbom)  scenario_badsbom ;;
  wrongkey) scenario_wrongkey ;;
  gameday)  scenario_release; scenario_unsigned; scenario_tamper; scenario_badsbom; scenario_wrongkey
            printf '\033[1;32mALL SCENARIOS PASSED\033[0m\n' ;;
  *) echo "Usage: $0 [release|unsigned|tamper|badsbom|wrongkey|gameday]" >&2; exit 2 ;;
esac
