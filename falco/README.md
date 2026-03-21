# Runtime Security — Falco

This directory adds a runtime security layer to the lab using [Falco](https://falco.org/), a CNCF graduated project for syscall-level threat detection.

The hardening controls in this project work at three layers:

| Layer | Tool | When |
|---|---|---|
| Build time | OPA / Conftest | Dockerfile committed |
| Deploy time | Kyverno | Pod admission to cluster |
| **Runtime** | **Falco** | **Process running inside container** |

Falco is the last line of defence: if an attacker bypasses the first two layers and achieves code execution inside a container, Falco detects the suspicious syscall patterns.

---

## What the rules detect

Five rules in `rules/container-hardening-lab.yaml`, each targeting a step in the post-exploitation kill chain:

| Rule | Trigger | MITRE ATT&CK |
|---|---|---|
| **Shell Spawned** | `sh`, `bash`, `ash` started inside a lab container | T1059 |
| **Package Manager** | `apt`, `pip`, `npm`, `apk` executed | T1105 |
| **Sensitive File Read** | `/etc/shadow`, SSH keys, sudoers opened | T1552.001 |
| **Unexpected Outbound** | Container initiates TCP to external address | T1071 |
| **Filesystem Write** | Write syscall to a non-temp path | T1564 |

The rules are scoped to the lab container images (`hardened-*` and `ghcr.io/r055le/container-hardening-lab-*`) so they don't fire against unrelated containers on the host.

---

## Requirements

- Linux host or WSL2 with kernel ≥ 5.8 (for modern eBPF)
- Docker with access to `/proc`, `/boot`, and kernel interfaces
- `docker compose` (v2)

Check your kernel version: `uname -r`

---

## Running the demo

**1. Start Falco and the target container**

```bash
cd falco/
docker compose up -d
```

Falco takes 10–15 seconds to load the eBPF probe and compile rules. Check it's ready:

```bash
docker logs falco --tail 20
# Look for: "Starting internal webserver" or "Falco initialized"
```

**2. Follow Falco's output in a separate terminal**

```bash
docker logs -f falco
```

Leave this running. Falco alerts will appear here as you trigger the rules below.

---

## Triggering each rule

### Rule 1 — Shell spawned

Exec a shell into the target container:

```bash
docker exec -it lab-target /bin/bash
```

Expected Falco output:
```
Warning Shell Spawned in Lab Container (user=root uid=0 container=lab-target image=python shell=bash parent=runc cmdline=bash)
```

Exit the shell (`exit`) before moving to the next trigger.

---

### Rule 2 — Package manager executed

Run apt-get inside the target container:

```bash
docker exec lab-target apt-get update
```

Expected Falco output:
```
Error Package Manager Executed in Lab Container (user=root uid=0 container=lab-target image=python cmd=apt-get cmdline=apt-get update)
```

---

### Rule 3 — Sensitive file read

Attempt to read `/etc/shadow`:

```bash
docker exec lab-target cat /etc/shadow
```

Expected Falco output:
```
Error Sensitive File Read in Lab Container (user=root uid=0 container=lab-target image=python file=/etc/shadow proc=cat)
```

---

### Rule 4 — Unexpected outbound connection

Initiate an outbound connection to an external address. The target image doesn't include curl or wget, but Python's standard library works:

```bash
docker exec lab-target python3 -c "import urllib.request; urllib.request.urlopen('http://example.com')"
```

Expected Falco output:
```
Warning Unexpected Outbound Connection from Lab Container (user=root uid=0 container=lab-target image=python proc=python3 rip=93.184.216.34 rport=80)
```

---

### Rule 5 — Filesystem write

Attempt to write to a non-temp path:

```bash
docker exec lab-target sh -c "echo test > /usr/local/bin/backdoor"
```

Expected Falco output:
```
Warning Filesystem Write in Lab Container (user=root uid=0 container=lab-target image=python file=/usr/local/bin/backdoor proc=sh)
```

---

## Testing against the hardened images

The target service uses `python:3.12-slim` by default (unhardened) to make the demo commands work without restriction. To test Falco against the actual hardened Python image:

```bash
# Build the hardened image first
cd ..
make build IMAGE=python

# Edit falco/docker-compose.yml — change target image to hardened-python:latest
# Then restart the target:
cd falco/
docker compose up -d --force-recreate target
```

Note: the hardened image runs as UID 10001 (non-root) and has `readOnlyRootFilesystem: true` when deployed via Kubernetes. Running it with plain `docker run` or `docker compose` does not enforce those Kyverno-set securityContext fields — they must be set in the compose service definition or a Kubernetes Pod spec.

---

## Stopping the demo

```bash
docker compose down
```

---

## Next steps

- **Forward alerts to a SIEM**: Falco outputs to stdout by default. Use [falcosidekick](https://github.com/falcosecurity/falcosidekick) to forward alerts to Slack, PagerDuty, Splunk, Elasticsearch, or any webhook.
- **Kubernetes DaemonSet**: Deploy Falco to a cluster as a DaemonSet to monitor all nodes. The [Falco Helm chart](https://github.com/falcosecurity/charts) is the standard approach.
- **Custom rule tuning**: The outbound connection rule will produce false positives in environments with external service dependencies. Add an `allowed_outbound_destinations` list to suppress expected traffic.
