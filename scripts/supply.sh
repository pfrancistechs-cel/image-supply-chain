#!/usr/bin/env bash
# The supply-chain tool. Everything the demo does, one command at a time.
#   release TAG [good|bad] [KEY]   build, push, make the SBOM, sign, attest        (KEY defaults to release)
#   build   TAG [good|bad]         build and push only: an UNSIGNED image
#   sbom    TAG                    make the SBOM of what the registry holds under TAG
#   verify  TAG                    check signature and SBOM attestation, change nothing
#   gate    TAG                    verify, check the SBOM policy, and only then start the application
#   list                           tags in the registry, with signature and SBOM status
#   keygen  NAME                   make a key pair in keys/
set -uo pipefail
. "$(dirname "$0")/lib.sh"

cmd="${1:-}"; shift || true
case "$cmd" in
  keygen)  [ $# -ge 1 ] || die "Usage: supply.sh keygen NAME"; key_gen "$1" && echo "keys/$1.key and keys/$1.pub" ;;
  build)   [ $# -ge 1 ] || die "Usage: supply.sh build TAG [good|bad]"
           d="$(build_push "$1" "${2:-good}")" && echo "$1 -> $d (unsigned)" ;;
  release) [ $# -ge 1 ] || die "Usage: supply.sh release TAG [good|bad] [KEY]"
           d="$(release_image "$1" "${2:-good}" "${3:-release}")" && echo "$1 -> $d (signed by ${3:-release}, SBOM attested)" || die "release failed" ;;
  sbom)    d="$(tag_digest "${1:?TAG}")"; [ -n "$d" ] || die "no such tag"
           f="$(sbom_make "$d")" && echo "$f" ;;
  verify)  d="$(tag_digest "${1:?TAG}")"; [ -n "$d" ] || die "no such tag"
           verify_sig "$d" && ok "signature" || fail "signature"
           verify_att "$d" "$RESULTS_DIR/attestation.tmp" && ok "SBOM attestation" || fail "SBOM attestation"
           rm -f "$RESULTS_DIR/attestation.tmp" ;;
  gate)    gate "${1:?TAG}" ;;
  list)    for t in $(curl -s "http://$REGISTRY/v2/$REPO/tags/list" | python3 -c 'import json,sys; print(" ".join(t for t in json.load(sys.stdin).get("tags") or [] if not t.endswith((".sig", ".att"))))'); do
             d="$(tag_digest "$t")"
             printf '%-16s %s  signed=%s sbom=%s\n' "$t" "$(short "$d")" "$(sig_tag_exists "$d" sig && echo yes || echo no)" "$(sig_tag_exists "$d" att && echo yes || echo no)"
           done ;;
  *) sed -n '2,10p' "$0"; exit 2 ;;
esac
