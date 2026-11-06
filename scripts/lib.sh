#!/usr/bin/env bash
# Shared helpers. Sourced by the other scripts, not run directly.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

# Use plain docker if the current user may talk to the daemon, otherwise sudo.
if docker info >/dev/null 2>&1; then DOCKER="docker"; else DOCKER="sudo docker"; fi
DC="$DOCKER compose"

REGISTRY="${REGISTRY:-localhost:5000}"            # docker treats localhost registries as safe over plain http
REPO="${REPO:-shop/app}"
CONSOLE_URL="${CONSOLE_URL:-http://127.0.0.1:8081}"
APP_URL="${APP_URL:-http://127.0.0.1:8080}"
APP_PORT="${APP_PORT:-8080}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT/results}"
KEYS_DIR="${KEYS_DIR:-$ROOT/keys}"
POLICY_FILE="${POLICY_FILE:-$ROOT/policy/deny.json}"
EXPECTED_CONTAINERS=2
export REGISTRY REPO CONSOLE_URL APP_URL RESULTS_DIR KEYS_DIR
export COSIGN_PASSWORD="${COSIGN_PASSWORD-}"     # the demo keys have an empty password; never do that for real keys
export SYFT_REGISTRY_INSECURE_USE_HTTP=true       # our registry speaks http on localhost

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '  \033[1;32mok\033[0m   %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
say()  { printf '    %s\n' "$*"; }
no()   { printf '  \033[1;33mno\033[0m   %s\n' "$*"; }       # a check of the gate that said no (expected in the demo)

ensure_env() { # create .env on first run
  [ -f "$ROOT/.env" ] || cp "$ROOT/.env.example" "$ROOT/.env"
  set -a; . "$ROOT/.env"; set +a
}
ensure_env

public_ip() { # EC2 metadata (IMDSv2), then a public what-is-my-ip fallback
  local tok ip=""
  tok="$(curl -fsS -m 2 -X PUT http://169.254.169.254/latest/api/token \
         -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null || true)"
  if [ -n "$tok" ]; then
    ip="$(curl -fsS -m 2 -H "X-aws-ec2-metadata-token: $tok" \
          http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true)"
  fi
  if [ -z "$ip" ]; then
    ip="$(curl -fsS -m 4 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]' || true)"
  fi
  echo "${ip:-<EC2-PUBLIC-IP>}"
}

http_code() { curl -s -o /dev/null -m 5 -w '%{http_code}' "$@" 2>/dev/null || true; }   # 000 = no connection

wait_http() { # LABEL URL [SECONDS]  (any 2xx)
  local label="$1" url="$2" secs="${3:-60}" i
  for ((i = 0; i < secs; i++)); do
    if curl -fsS -o /dev/null --max-time 2 "$url" 2>/dev/null; then ok "$label is up"; return 0; fi
    sleep 1
  done
  fail "$label did not answer at $url within ${secs}s"
  return 1
}

wait_until() { # SECONDS COMMAND...   (retries every second)
  local secs="$1" i; shift
  for ((i = 0; i < secs; i++)); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# ---------------------------------------------------------------- registry
MANIFEST_ACCEPT='application/vnd.oci.image.manifest.v1+json,application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.docker.distribution.manifest.list.v2+json'

registry_up() { [ "$(http_code "http://$REGISTRY/v2/")" = "200" ]; }

tag_digest() { # TAG -> sha256:... (empty when the tag does not exist)
  curl -s -I -m 10 -H "Accept: $MANIFEST_ACCEPT" "http://$REGISTRY/v2/$REPO/manifests/$1" |
    tr -d '\r' | awk 'tolower($1) == "docker-content-digest:" {print $2}'
}
ref_of() { echo "$REGISTRY/$REPO@$1"; }            # DIGEST -> image reference pinned to that digest
short() { echo "${1#sha256:}" | cut -c1-12; }

# ---------------------------------------------------------------- keys
key_gen() { # NAME   (keys/NAME.key and keys/NAME.pub; the .key stays private)
  mkdir -p "$KEYS_DIR"
  [ -f "$KEYS_DIR/$1.key" ] && return 0
  local tmp; tmp="$(mktemp -d)"
  ( cd "$tmp" && cosign generate-key-pair >/dev/null 2>&1 ) || { rm -rf "$tmp"; return 1; }
  mv "$tmp/cosign.key" "$KEYS_DIR/$1.key"; mv "$tmp/cosign.pub" "$KEYS_DIR/$1.pub"
  rm -rf "$tmp"; chmod 600 "$KEYS_DIR/$1.key"
}

# ---------------------------------------------------------------- build, sbom, sign, attest
build_push() { # TAG KIND(good|bad) [VERSION]   -> prints the digest of what the registry now holds under TAG
  local tag="$1" kind="$2" version="${3:-$1}" reqs=requirements.txt
  [ "$kind" = "bad" ] && reqs=requirements-bad.txt
  $DOCKER build -q -t "$REGISTRY/$REPO:$tag" --build-arg "APP_VERSION=$version" --build-arg "REQS=$reqs" \
    -f "$ROOT/app/Dockerfile" "$ROOT/app" >/dev/null || return 1
  $DOCKER push -q "$REGISTRY/$REPO:$tag" >/dev/null || return 1
  tag_digest "$tag"
}

sbom_make() { # DIGEST -> prints the path of the SBOM file (SPDX json made by syft from the image in the registry)
  local out="$RESULTS_DIR/sbom-$(short "$1").spdx.json"
  mkdir -p "$RESULTS_DIR"
  syft "registry:$(ref_of "$1")" -q -o "spdx-json=$out" >/dev/null 2>&1 || return 1
  echo "$out"
}

sign_image() { # DIGEST KEYNAME
  cosign sign --key "$KEYS_DIR/$2.key" --tlog-upload=false --allow-insecure-registry -y "$(ref_of "$1")" >/dev/null 2>&1
}
attest_sbom() { # DIGEST KEYNAME SBOMFILE
  cosign attest --key "$KEYS_DIR/$2.key" --tlog-upload=false --allow-insecure-registry -y --type spdxjson \
    --predicate "$3" "$(ref_of "$1")" >/dev/null 2>&1
}
verify_sig() { # DIGEST [KEYNAME=release]
  cosign verify --key "$KEYS_DIR/${2:-release}.pub" --insecure-ignore-tlog=true --allow-insecure-registry \
    "$(ref_of "$1")" >/dev/null 2>&1
}
verify_att() { # DIGEST OUTFILE [KEYNAME=release]   -> OUTFILE holds the verified attestation
  cosign verify-attestation --key "$KEYS_DIR/${3:-release}.pub" --type spdxjson --insecure-ignore-tlog=true \
    --allow-insecure-registry "$(ref_of "$1")" >"$2" 2>/dev/null
}
sig_tag_exists() { # DIGEST SUFFIX(sig|att)
  local tags; tags="$(curl -s -m 5 "http://$REGISTRY/v2/$REPO/tags/list")"
  [[ "$tags" == *"\"sha256-${1#sha256:}.$2\""* ]]
}

release_image() { # TAG KIND [KEYNAME=release]: build, push, SBOM, sign, attest. Prints the digest.
  local tag="$1" kind="$2" key="${3:-release}" digest sbom
  key_gen "$key" || return 1
  digest="$(build_push "$tag" "$kind")" && [ -n "$digest" ] || return 1
  sbom="$(sbom_make "$digest")" || return 1
  sign_image "$digest" "$key" || return 1
  attest_sbom "$digest" "$key" "$sbom" || return 1
  echo "$digest"
}

# ---------------------------------------------------------------- the gate
record_decision() { # TAG DIGEST VERDICT REASON...
  python3 - "$RESULTS_DIR" "$@" <<'PY'
import json, os, sys, time
results, tag, digest, verdict, *reasons = sys.argv[1:]
path = os.path.join(results, "decisions.json")
try:
    with open(path, encoding="utf-8") as fh:
        items = json.load(fh)
except (OSError, ValueError):
    items = []
items.append({"time": time.strftime("%H:%M:%S"), "tag": tag, "digest": digest, "verdict": verdict, "reasons": reasons})
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(items[-30:], fh)
os.replace(tmp, path)
PY
}

app_runs_digest() { [ "$(curl -s -m 3 "$APP_URL/info" | python3 -c 'import json,sys; print(json.load(sys.stdin)["image"])' 2>/dev/null)" = "$(ref_of "$1")" ]; }

# gate TAG_OR_DIGEST: the only way the application gets started.
#   1. resolve the tag to a digest (a tag can be moved by anyone who can push; a digest cannot change)
#   2. the signature on that digest must verify with the release public key
#   3. the SBOM attestation on that digest must verify with the same key
#   4. the attested SBOM must pass the deny policy
#   5. only then: docker run <image>@<digest>
# Prints one line per check. Exit 0 = deployed, 1 = refused.
gate() {
  local what="$1" digest tag reasons=() att="$RESULTS_DIR/attestation.tmp"
  mkdir -p "$RESULTS_DIR"
  case "$what" in sha256:*) digest="$what"; tag="(digest)" ;; *) tag="$what"; digest="$(tag_digest "$what")" ;; esac
  if [ -z "$digest" ]; then
    no "tag '$what' does not exist in the registry"; record_decision "$tag" "-" DENY "no such image"; return 1
  fi
  say "tag $tag resolves to digest $(short "$digest")"
  if verify_sig "$digest"; then ok "signature verifies with the release key"
  elif sig_tag_exists "$digest" sig; then no "signature is NOT valid for the release key (signed by someone else?)"; reasons+=("signature not made by the release key")
  else no "no signature on this image"; reasons+=("unsigned image"); fi
  if [ ${#reasons[@]} -eq 0 ]; then
    if verify_att "$digest" "$att"; then ok "SBOM attestation verifies with the release key"
    else no "no valid SBOM attestation"; reasons+=("no valid SBOM attestation"); fi
  fi
  if [ ${#reasons[@]} -eq 0 ]; then
    local out rc=0
    out="$(python3 "$ROOT/scripts/sbom_check.py" --attestation "$att" --policy "$POLICY_FILE" --out "$RESULTS_DIR/last-sbom.json")" || rc=$?
    if [ "$rc" -eq 0 ]; then ok "SBOM passes the policy"
    else
      while IFS= read -r line; do [ -n "$line" ] && { no "SBOM: $line"; reasons+=("$line"); }; done <<<"$out"
    fi
  fi
  rm -f "$att"
  if [ ${#reasons[@]} -gt 0 ]; then
    record_decision "$tag" "$digest" DENY "${reasons[@]}"
    printf '    \033[1;31mDENIED\033[0m: %s was not started\n' "$tag"
    return 1
  fi
  local ref; ref="$(ref_of "$digest")"
  $DOCKER rm -f sc-app >/dev/null 2>&1 || true
  $DOCKER run -d --name sc-app --restart unless-stopped -p "$APP_PORT:8080" -e "IMAGE_REF=$ref" "$ref" >/dev/null || { fail "docker run failed"; return 1; }
  wait_http "the application" "$APP_URL/healthz" 40 || return 1
  record_decision "$tag" "$digest" ALLOW "signature and SBOM verified"
  printf '{"tag": "%s", "digest": "%s", "ref": "%s", "time": "%s"}\n' "$tag" "$digest" "$ref" "$(date +%H:%M:%S)" >"$RESULTS_DIR/app.json"
  printf '    \033[1;32mALLOWED\033[0m: %s is running (image %s)\n' "$tag" "$(short "$digest")"
}
