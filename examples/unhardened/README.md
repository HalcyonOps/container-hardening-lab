# Unhardened Dockerfile — Failure Demo

This Dockerfile is **intentionally insecure**. It exists to prove that the OPA/Conftest policies and Trivy scanner in this repo correctly identify real-world hardening failures — a clean result here would mean the tooling isn't working.

The CI `failure-demo` job asserts a non-zero exit code from both Conftest and Trivy against this file.

## Violations

### [DENY] No USER instruction (CIS 4.1)

```dockerfile
# No USER instruction — process runs as root inside the container
CMD ["node", "src/index.js"]
```

Without a `USER` instruction, the process runs as `root` (UID 0) inside the container. If the container is compromised, the attacker has root-equivalent access to everything the container can reach — including mounted volumes, the Docker socket if bound, and potentially the host via namespace escapes.

**Fix:** Create a dedicated non-root user and set it before `CMD`:
```dockerfile
RUN useradd --uid 10001 --no-create-home --shell /sbin/nologin appuser
USER appuser
```

---

### [DENY] Unapproved base image — `node:18` (CIS 4.2)

```dockerfile
FROM node:18
```

`node:18` reached end-of-life in April 2025 and is no longer receiving security patches. Trivy finds CRITICAL and HIGH CVEs in the base OS packages shipped with this image.

The image-source-allowlist policy also warns that the image is not pinned to a digest — any `docker pull` could silently fetch a different (potentially compromised) image.

**Fix:** Use a current, maintained release pinned to a digest:
```dockerfile
FROM node:20-slim@sha256:<digest>
```

---

### [WARN] Privileged port — `EXPOSE 80` (CIS 5.7)

```dockerfile
EXPOSE 80
```

Ports below 1024 are privileged on Linux. Binding to port 80 requires the `CAP_NET_BIND_SERVICE` capability, which must be granted at runtime — violating the principle of least privilege.

**Fix:** Expose a non-privileged port and handle routing externally (ingress controller, load balancer):
```dockerfile
EXPOSE 3000
```

---

### [WARN] Files owned by root — `COPY --chown=root:root` (CIS 4.1)

```dockerfile
COPY --chown=root:root . .
```

Files owned by root are not writable by the application user. This either forces the application to run as root, or causes runtime failures when the app tries to write to its own directory.

**Fix:** Own files by the application user:
```dockerfile
COPY --chown=appuser:appgroup . .
```

---

### [CIS 4.7] Attack-surface tools left installed

```dockerfile
RUN apt-get update && apt-get install -y curl wget
```

`curl` and `wget` are download utilities with no legitimate use in a production runtime container. Their presence gives an attacker a ready-made exfiltration and lateral movement toolkit if the container is compromised.

**Fix:** Remove them, or don't install them in the first place. If needed only at build time, install in a builder stage that never reaches production.

---

### [CIS 4.6] No HEALTHCHECK

```dockerfile
# No HEALTHCHECK defined
CMD ["node", "src/index.js"]
```

Without a `HEALTHCHECK`, container orchestrators (Docker Swarm, Kubernetes liveness probes via `docker inspect`) cannot distinguish a crashed or deadlocked process from a healthy one.

**Fix:**
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/healthz', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"
```

## Running the Demo Locally

```bash
# Conftest must find violations — exit code 1 is the expected/correct result
conftest test examples/unhardened/Dockerfile \
  --policy policies/opa/ \
  --namespace docker.security

# Trivy must find CVEs in node:18 — exit code 1 is expected
trivy image --severity CRITICAL,HIGH --exit-code 1 node:18
```

Compare with a hardened image to see the difference:

```bash
make lint IMAGE=python    # 0 failures, digest pin warning only
make lint IMAGE=node      # 0 failures, digest pin warning only
make lint IMAGE=nginx     # 0 failures, digest pin warning only
```
