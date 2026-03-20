# images/python — Hardened Python 3.12 Image

**Base:** `python:3.12-slim`
**Reference example** for the CIS Docker Benchmark hardening pattern used throughout this project.

## Hardening Decisions

### Multi-stage build (CIS 4.4)
A `builder` stage installs pip dependencies into `/install`. Only the compiled packages are copied to the `final` stage — no `pip`, `gcc`, or build tooling reaches the runtime image.

### Non-root user: `appuser` (UID 10001) (CIS 4.1)
A dedicated user and group with no home directory and `/sbin/nologin` shell. UID/GID above 10000 avoids collision with system service accounts. The `WORKDIR` is `/app`, owned by `appuser`.

### Stripped SUID/SGID bits (CIS 4.8)
All SUID/SGID bits are removed from binaries in the final stage via `chmod ug-s`. This prevents privilege escalation through misuse of setuid executables like `su`, `ping`, or `passwd`.

### Removed attack-surface packages (CIS 4.7)
`wget`, `curl`, `perl`, `gcc`, and `binutils` are removed. These are commonly abused for post-exploitation downloads or compile-and-run attacks.

### Cleaned APT cache (CIS 4.7)
`/var/lib/apt/lists/*` is purged in the same `RUN` layer as package operations to prevent the package index from appearing in the image layer, reducing size and exposure.

### HEALTHCHECK defined (CIS 4.6)
A `HEALTHCHECK` instruction is included. Container orchestrators (Docker Swarm, Kubernetes liveness probes) can use this to detect unhealthy instances. Adjust the URL to match your application.

### OCI labels
`org.opencontainers.image.*` labels are applied for traceability and provenance. In CI, `--build-arg` injects the git SHA into `org.opencontainers.image.revision`.

### No secrets in image (CIS 4.9 / 4.10)
No credentials, tokens, or environment variable secrets are baked in. Secrets must be injected at runtime via a secrets manager, mounted secrets, or environment variables set outside the image.

## Runtime Recommendations

Run with these flags to complete the hardening posture (enforced by admission policies):

```bash
docker run \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --user 10001:10001 \
  hardened-python:latest
```

| Flag | Rationale |
|---|---|
| `--read-only` | Prevents filesystem tampering at runtime |
| `--tmpfs /tmp` | Provides a writable temp area with `noexec` |
| `--cap-drop=ALL` | Removes all Linux capabilities; add back only what's required |
| `--no-new-privileges` | Prevents privilege escalation via execve |

## Building

```bash
# From repo root
make build IMAGE=python

# Directly
docker build -t hardened-python:latest images/python/
```

## Scanning

```bash
make scan IMAGE=python
# or
trivy image --exit-code 1 --severity CRITICAL,HIGH hardened-python:latest
```
