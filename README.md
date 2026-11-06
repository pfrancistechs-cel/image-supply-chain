# Project 18: Image Supply Chain (registry, SBOM, Cosign)

How do you know the container you are about to run is the one your team built, and that nothing vulnerable is inside it? This demo builds a small image, publishes it to a private registry, writes its **SBOM** (software bill of materials), **signs** it with **Cosign**, and lets a **gate** start it only if the signature and the SBOM both check out. Then it attacks its own pipeline five ways.

Everything runs on one EC2 instance. No AWS service and no IAM role: the registry is the official `registry:2` container, and the signing key is a local key pair (no keyless signing, no transparency log, because those need internet identity services).

## The ideas

| Word | Meaning here |
|---|---|
| **Digest** | `sha256:...`, the fingerprint of an image's exact content. It cannot change. |
| **Tag** (`1.0.0`) | A movable label. Anyone who can push to the registry can point a tag at different content. |
| **SBOM** | The list of packages inside the image. Made by **syft** from the image in the registry (SPDX json). |
| **Signature** | **cosign** signs a digest with a private key. Anyone with the public key can verify it. |
| **Attestation** | The SBOM, signed and bound to one digest, stored in the registry next to the image. |
| **Gate** | `scripts/supply.sh gate TAG`. The only thing that starts the app. |

## What the gate checks (in this order)

1. Resolve the tag to a digest, and from here on use only the digest.
2. The signature on that digest verifies with the release public key.
3. The SBOM attestation on that digest verifies with the same key.
4. The **attested** SBOM (not a fresh scan the attacker could influence) passes `policy/deny.json`.
5. Only then: `docker run image@sha256:...`.

## Scenarios (`./scripts/demo.sh <name>`)

| Scenario | What happens | Result |
|---|---|---|
| `release` | Build, push, SBOM, sign, attest. Gate. | App starts on :8080, running exactly that digest |
| `unsigned` | Someone pushes an image without a signature | Refused. The old app keeps running |
| `tamper` | Attacker overwrites the signed tag `2.0.0` with other content | The tag now has a different digest with no signature: refused. The original digest is still accepted: pinning to digests is safe |
| `badsbom` | A correctly signed image whose SBOM lists `urllib3 1.26.4` (known CVEs) | Signature fine, **policy refuses**. Rebuild with `2.2.3` (3.0.1) and it passes. A signature proves who, not whether it is safe |
| `wrongkey` | Signed with a key that is not the release key | Refused |
| `gameday` | All of the above | `ALL SCENARIOS PASSED` |

## Run it

See `STEPS.md` (full guide, with the AWS console steps) and `DEMO.md` (the 5-minute script).

```bash
chmod +x scripts/*.sh scripts/*.py
./scripts/setup.sh        # once: apt update/upgrade, Docker, cosign 2.4.1, syft 1.14.0
./scripts/preflight.sh    # pulls images, runs a real image through the gate, runs the tests
./scripts/up.sh
./scripts/smoke.sh        # All 13 checks passed.
./scripts/demo.sh gameday
./scripts/destroy.sh
```

Security group: inbound 22, 8080 (the deployed app) and 8081 (console), all from My IP. The registry is bound to `127.0.0.1:5000`: it needs no inbound rule and is not exposed.

By hand: `./scripts/supply.sh release 1.0.0`, `./scripts/supply.sh list`, `./scripts/supply.sh gate 1.0.0`. Edit `policy/deny.json` to change what the gate refuses.

## Limits (say them in the demo)

- Keys are plain files with an empty password. Real keys live in a KMS or HSM, or you use keyless signing (OIDC identity), which needs public Sigstore services. Not possible on an account with no extra services.
- No transparency log (`--tlog-upload=false`): signatures are checked against our own public key only.
- The SBOM policy is a version deny-list, not a vulnerability database. Scanners (Trivy, Grype) add live CVE data; project 9 covers scanning. Here the point is the chain of trust.
- The gate is a script. In Kubernetes the same checks run in an admission controller (see project 16 on policy).
- The registry has no login. It is reachable from the instance only.

## Tests

`python3 -m unittest discover -s tests -v`. The SBOM checker and repo tests always run. The pipeline tests need `cosign`, `syft`, `registry` and `crane` in PATH and run the real scripts with the real tools, using a stub for `docker`; they are skipped on the demo instance.
