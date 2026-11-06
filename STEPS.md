# STEPS: Image Supply Chain (registry, SBOM, Cosign)

## Prerequisites (set these up BEFORE step 1)

| Need | Details |
|---|---|
| **AWS account** | Any account that can launch EC2. No IAM role, no other AWS service. One region for everything. |
| **Instance type** | `m7i-flex.large` (2 vCPU, 8 GiB). This project needs under 1.5 GiB. |
| **OS image (AMI)** | Ubuntu Server 24.04 LTS (64-bit x86). 22.04 also works. |
| **Disk** | 20 GiB gp3. |
| **Key pair** | An RSA `.pem` key pair created in EC2 (step 0a). |
| **Security group** | Created in step 0b. **Inbound: exactly three rules, all with source My IP: SSH TCP 22; Custom TCP 8080 (the deployed app); Custom TCP 8081 (supply-chain console).** **Outbound: leave the default (All traffic, 0.0.0.0/0)**, for Docker Hub, Docker's apt repo, GitHub (cosign and syft downloads) and PyPI (the app image build). The registry (5000) is bound to localhost and needs no rule. |
| **Code on the instance** | Option A: private GitHub repo plus a fine-grained token (Contents: Read) as the `git clone` password. Option B: copy the zip with `scp` (step 2). |
| **Accounts / tokens** | None. |
| **On your laptop** | A terminal with `ssh`/`scp` and a web browser. **No SSH tunnel is needed:** open `http://<PUBLIC-IP>:8081/` directly. |

**Time:** about 10 minutes of setup (preflight pulls two images, builds a real image and runs it through the gate), about 5 minutes for the full tour. **Cost:** about $0.10/hour at your quoted rate, plus pennies for the disk. Do step 11 when finished.

---

## Step 0: Create the key pair, security group and instance (AWS console)

**0a. Key pair.** EC2 > Network & Security > Key pairs > **Create key pair**. Name `sc-lab-key`, type **RSA**, format **.pem**. The file downloads once; keep it safe. Lock down its permissions:

```bash
# Linux / macOS
chmod 400 ~/Downloads/sc-lab-key.pem
```
```powershell
# Windows PowerShell (OpenSSH)
icacls "$HOME\Downloads\sc-lab-key.pem" /inheritance:r /grant:r "$($env:USERNAME):(R)"
```

**0b. Security group.** EC2 > Network & Security > Security Groups > **Create security group**.
- Name: `sc-lab-sg`, Description: `SSH and demo pages from my IP`, VPC: the default VPC.
- **Inbound rules > Add rule** (three times; Type `SSH` first, then `Custom TCP`; Protocol `TCP`; **Source `My IP`** every time):
  1. Port range `22` (SSH)
  2. Port range `8080` (the deployed app)
  3. Port range `8081` (supply-chain console)
- **Outbound rules:** leave the default rule (`All traffic`, `0.0.0.0/0`).
- Click **Create security group**.

> Showing someone on another network? "My IP" blocks them. Share your screen, or add their public IP followed by `/32` to the 8081 and 8080 rules. Never use `0.0.0.0/0`.

**0c. Launch the instance.** EC2 > Instances > **Launch instances**.
- Name: `sc-lab-box`
- OS Image: **Ubuntu Server 24.04 LTS**, **64-bit (x86)**
- Instance type: `m7i-flex.large`
- Key pair: `sc-lab-key`
- Network settings > **Edit**: Auto-assign public IP **Enable**; **Select existing security group** > `sc-lab-sg`
- Storage: **20 GiB**, `gp3`
- Advanced details > IAM instance profile: **No IAM role**
- **Launch instance**, wait for `Running` and `2/2 passed`, copy the **Public IPv4 address** (`<PUBLIC-IP>` below).

> If your network changes, SSH and the pages time out: edit **all three** inbound rules and set Source to My IP again. Stop/start also changes the public IP.

## Step 1: Connect (from your laptop)

```bash
ssh -i ~/Downloads/sc-lab-key.pem ubuntu@<PUBLIC-IP>
```
Type `yes` at the fingerprint prompt. Everything below runs **on the instance**.

## Step 2: Update packages and get the code

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git unzip
```

**Option A (private GitHub repo):**
```bash
git clone https://github.com/<you>/image-supply-chain.git
cd image-supply-chain
```
Username = your GitHub username, password = the fine-grained token.

**Option B (no GitHub). From your laptop, in the folder holding the zip:**
```bash
scp -i ~/Downloads/sc-lab-key.pem image-supply-chain.zip ubuntu@<PUBLIC-IP>:~
```
Then on the instance:
```bash
unzip image-supply-chain.zip
cd image-supply-chain
```

## Step 3: Make the scripts executable (do not skip)

Zipped or uploaded files often lose the executable flag, which gives `Permission denied`.

```bash
chmod +x scripts/*.sh scripts/*.py
ls -l scripts/        # every .sh line should start with -rwxr-xr-x
```

## Step 4: Install Docker, cosign and syft

```bash
./scripts/setup.sh
```
Runs `apt update`/`upgrade`, installs base tools, installs Docker Engine and Compose v2 from Docker's repo (fallback: Ubuntu's `docker.io`), then downloads **cosign 2.4.1** and **syft 1.14.0** from their GitHub releases into `/usr/local/bin` and prints the versions. Takes 3-5 minutes and ends with `Setup complete.` If it says to log out and in for the docker group, either do that or keep going (the scripts use `sudo` by themselves).

## Step 5: Preflight (run well before the demo)

```bash
./scripts/preflight.sh
```
Checks Docker, cosign, syft, disk, memory, ports 5000/8080/8081 and Docker Hub; pulls `python:3.12-slim` and `registry:2`; starts the stack; runs `smoke.sh`; builds a real image, makes its SBOM, signs it, lets it through the gate and checks that it runs; checks that an unsigned image is refused; then runs the unit tests. Every line says `ok` and the last line is `Preflight passed. Signed images with a clean SBOM run; everything else is refused.` First run: 6-9 minutes.

## Step 6: Start the stack

```bash
./scripts/up.sh
```
Starts the registry and the console, makes two key pairs in `keys/` (`release` is the real one, `attacker` is for the demo), and prints:

```
Supply-chain console : http://<PUBLIC-IP>:8081/
The deployed app     : http://<PUBLIC-IP>:8080/
```
(The app address works after the first image passes the gate.)

## Step 7: Health check

```bash
./scripts/smoke.sh
```
Every line says `ok` and it ends with **`All 13 checks passed.`**

## Step 8: Open the console (on your laptop)

`http://<PUBLIC-IP>:8081/`: four panels. **Registry** lists tags with their digest, whether each is signed and whether it has an SBOM attached. **Running application** shows what the gate started. **Gate decisions** shows every ALLOW and DENY with the reason. **SBOM** lists the packages of the last image the gate checked, vulnerable ones in red. **Keep this tab open.**

## Step 9: Run the supply-chain tour (on the instance)

```bash
./scripts/demo.sh gameday          # all five scenarios: about 5 minutes
```
Or one at a time:
```bash
./scripts/demo.sh release          # build, SBOM, sign, attest, gate, app starts on :8080
./scripts/demo.sh unsigned         # an unsigned image is refused
./scripts/demo.sh tamper           # a signed tag is overwritten: refused; the original digest is still accepted
./scripts/demo.sh badsbom          # signed, but urllib3 1.26.4 inside: the SBOM policy refuses; the rebuilt 3.0.1 passes
./scripts/demo.sh wrongkey         # signed with a key we do not trust: refused
```
Each ends with a green `PASS` (the demo passes when the attack is stopped). Use it yourself:
```bash
./scripts/supply.sh release 5.0.0          # build, push, SBOM, sign, attest
./scripts/supply.sh list                   # tags with signed/sbom status
./scripts/supply.sh verify 5.0.0           # check signature and attestation only
./scripts/supply.sh gate 5.0.0             # the gate: only this starts the app
cat policy/deny.json                       # the SBOM policy; edit it, then run the gate again
```
Open `http://<PUBLIC-IP>:8080/` to see the running app (its version and the exact image digest).

## Step 10: Unit tests (optional)

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```
Ends with `OK`. On the instance the SBOM-checker and repo tests run; the pipeline tests are skipped because they also need the `registry` and `crane` programs, which this guide does not install.

## Step 11: Clean up, then terminate the instance

```bash
./scripts/destroy.sh
```
Removes the containers (including the deployed app), the registry volume (every image and signature), the demo image and the demo keys. In the AWS console: EC2 > Instances > `sc-lab-box` > **Instance state > Terminate instance**. Optionally delete `sc-lab-sg` and `sc-lab-key`.

---

## What you should see

| Step | Result |
|---|---|
| 4 | Docker, cosign `v2.4.1`, syft `1.14.0` versions, then `Setup complete.` |
| 5 | All `ok`, then `Preflight passed.` |
| 6 | Two URLs containing your public IP |
| 7 | `All 13 checks passed.` |
| 8 | Registry up; after a demo, rows with `yes` in the signed and SBOM columns |
| 9 | Five `PASS` lines, then `ALL SCENARIOS PASSED`. Yellow `no` lines are the gate saying no to the attacks. Expected |
| 10 | `OK` |

## Risky dependencies and fallbacks

| Dependency | Risk | Fallback |
|---|---|---|
| Docker Hub (`registry:2`, `python:3.12-slim`) | Rate limit or slow pull | `sudo docker login` with a free account; set `REGISTRY_IMAGE` / `PYTHON_IMAGE` in `.env` and re-run preflight |
| GitHub releases (cosign, syft) | Download blocked or slow | Outbound rule must be All traffic; re-run `./scripts/setup.sh` (it skips what is installed) |
| PyPI (`pip install urllib3` during the image build) | Blocked or slow | Re-run; check the outbound rule |
| cosign version | cosign 3.x changed signing defaults | Keep the pinned 2.4.1; `setup.sh` installs it |
| Docker pushing to `localhost:5000` | Docker allows plain http for localhost only | Keep the registry on `127.0.0.1:5000`; do not change `REGISTRY` to the public IP |
| Do not run `destroy.sh` before the demo | It deletes images, signatures and keys | Re-run preflight afterwards |
| MinIO, LocalStack, S3 | **Not used** | none needed |

## If something goes wrong

| Symptom | Fix |
|---|---|
| SSH: `Connection timed out` | Your IP changed. Edit `sc-lab-sg`, inbound rule 22, Source My IP. Check the instance is Running with a public IP. |
| Console or app never loads | (1) Use `http://` with port 8081 or 8080. (2) Each port needs its own inbound rule with Source My IP. (3) Check the current public IP. (4) On the instance `curl -i http://localhost:8081/healthz` should return `200`; if so, it is the security group. (5) The app on :8080 only exists after an image passed the gate. |
| Testing the public IP from the instance hangs | Expected. Use `localhost` on the instance. |
| SSH: `Permission denied (publickey)` | User `ubuntu`, the right `.pem`, `chmod 400`. |
| `./scripts/x.sh: Permission denied` | `chmod +x scripts/*.sh scripts/*.py` (step 3), or `bash scripts/x.sh`. |
| `bad interpreter: /usr/bin/env bash^M` | `sed -i 's/\r$//' scripts/*.sh scripts/*.py` |
| `cosign: command not found` or `syft: command not found` | Run `./scripts/setup.sh` (step 4). |
| Preflight: `Docker Hub reachable` or a pull fails | Outbound rule must be All traffic; `sudo docker login`; retry. |
| Preflight: `Port NNNN is free` fails | `sudo ss -ltnp \| grep ':5000 '`; stop what uses it, or `./scripts/destroy.sh` if it is an old run. |
| `up.sh`: registry never answers | `sudo docker logs --tail 30 sc-registry`. |
| `docker push` says `http: server gave HTTP response to HTTPS client` | The registry reference must start with `localhost:5000`. Do not set `REGISTRY` to an IP or hostname. |
| `release`/`build` fails in `pip install` | The build needs PyPI: check the outbound rule and retry. `sudo docker build -f app/Dockerfile app` shows the error. |
| Gate says `no signature` for an image you just released | You are checking a tag that someone re-pushed (that is the `tamper` demo), or the release failed half way: run `./scripts/supply.sh list`, then release again. |
| Gate says `no valid SBOM attestation` | The release stopped before attesting. Run `./scripts/supply.sh release TAG` again. |
| Gate says `signature is NOT valid for the release key` | The image was signed with another key (the `wrongkey` demo) or `keys/release.*` was regenerated after signing. Re-release the image. |
| `demo.sh`: `The stack is not running` | `./scripts/up.sh` |
| `smoke.sh`: `both containers are running` fails | `sudo docker compose ps -a`, then `sudo docker compose up -d`. |
| Port 8080 already in use when the gate starts the app | Something else holds 8080. The gate replaces its own `sc-app` container, but not other programs: stop the other one. |
| Disk full | `sudo docker system prune -af` (images are pulled again by preflight) |
