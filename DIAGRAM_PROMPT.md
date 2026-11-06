# Diagram prompt (paste into an AI image model)

Create a clean, wide infrastructure and flow diagram, white background, flat icons, thin labelled arrows, a legend at the bottom. Title: "Image supply chain on one EC2 instance: build, SBOM, sign, gate".

Outer box: "EC2 instance m7i-flex.large (Docker)". Inside, a left-to-right pipeline of five numbered stages:

1. "Build": a Dockerfile icon and "docker build" producing "shop/app:TAG".
2. "Registry (registry:2, 127.0.0.1:5000)": a cylinder labelled "images, SBOMs and signatures". An arrow from stage 1 labelled "docker push".
3. "SBOM (syft)": reads the image from the registry, produces "SPDX json: packages inside the image".
4. "Sign (cosign)": a padlock icon with a key labelled "release.key (private)". Two arrows back into the registry: "signature (.sig)" and "SBOM attestation (.att, bound to the digest)".
5. "Gate (supply.sh gate)": a shield. Four small checks inside, in order: "tag to digest", "signature verifies with release.pub", "attestation verifies", "SBOM passes policy/deny.json". Green arrow "ALLOW" to a container "sc-app, :8080, run by digest". Red arrow "DENY" to a stop sign with "old app keeps running".

Below the registry draw three red attacker icons with arrows into the registry: "unsigned image", "overwrite a signed tag", "signed with the attacker key", and one orange: "signed, but urllib3 1.26.4 inside (policy refuses)".

On the right, "console :8081" (browser window showing a table of images with signed/SBOM columns, a gate decision list and an SBOM table) fed by dotted arrows from the registry and from a "results/" folder. Outside the box: "Your laptop (My IP only)" with arrows to ":8081" and ":8080".

Security group note: "Inbound: 22, 8080, 8081 from My IP only. Registry port 5000 is localhost only". Small note: "No S3, no IAM role, no keyless signing: local keys (limit)".
