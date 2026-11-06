# Demo: Image Supply Chain (about 5 minutes)

Open `http://<EC2-PUBLIC-IP>:8081/` and keep it visible: registry images, signatures, gate decisions, SBOM.

**1. The question (20 s).** "How do we know the image we run is the one we built, with nothing vulnerable inside?" Three answers: a **signature** (who), an **SBOM** (what is inside), a **gate** (nothing runs without both).

**2. Good path (60 s).**
```bash
./scripts/demo.sh release
```
Build, SBOM, sign, attest. The gate verifies both and starts the app at `http://<EC2-PUBLIC-IP>:8080/`. It runs by **digest**, not by tag.

**3. Attacks (3 min).** Each one ends in a red DENIED and a green PASS (the demo passes when the attack fails).
```bash
./scripts/demo.sh unsigned    # no signature: refused
./scripts/demo.sh tamper      # tag overwritten: new digest, no signature, refused
./scripts/demo.sh badsbom     # signed, but urllib3 1.26.4 inside: the SBOM policy refuses
./scripts/demo.sh wrongkey    # someone else's key: refused
```
Point out in `tamper`: the old digest is still accepted. **Tags move, digests do not.**
Point out in `badsbom`: **a signature says who built it, not that it is safe.** The SBOM catches that.

**4. Close (30 s).** "Limits: local keys (production: KMS or keyless), version deny-list instead of a CVE database, script gate instead of an admission controller."

Everything at once: `./scripts/demo.sh gameday`. Then `./scripts/destroy.sh` and terminate the instance.
