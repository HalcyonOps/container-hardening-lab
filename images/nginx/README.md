# hardened-nginx

**Base image:** `nginx:1.27-alpine`
**Runtime user:** `nginx` (UID 101)
**Exposed port:** 8080

A hardened nginx static file server with security response headers, a locked-down configuration, and zero CRITICAL/HIGH CVEs. Serves pre-built frontend assets (`dist/`) — use this as the final stage for any React, Vue, or plain HTML frontend.

---

## Hardening decisions

### Alpine over Debian (CIS 4.2)

```
nginx:1.27-alpine  ~50 MB    ← used here
nginx:1.27         ~190 MB
```

Alpine Linux uses musl libc and BusyBox, carrying far fewer packages than Debian. Fewer packages means fewer CVEs and a smaller update surface. Alpine CVEs for the nginx package are typically patched faster than the Debian equivalent.

The tradeoff: Alpine uses musl libc, which behaves differently from glibc in edge cases (locale handling, DNS resolution). For a static file server, this is irrelevant.

---

### Non-privileged port 8080 (CIS 5.7)

nginx is configured to listen on port **8080**, not 80.

Binding to any port below 1024 requires `CAP_NET_BIND_SERVICE`. That capability must be granted at runtime, which means it cannot be dropped. By moving to 8080, the container runs with `--cap-drop=ALL` at runtime — no exceptions. Port mapping from 80→8080 is handled at the load balancer or ingress controller level, where it belongs.

---

### `nginx` user (UID 101) — no root process (CIS 4.1)

The official `nginx:alpine` image ships a `nginx` user (UID 101). The worker processes run as this user. The master process that would normally bind to port 80 as root is unnecessary here since we bind to 8080.

Ownership of the directories nginx needs to write to (`/var/cache/nginx`, `/var/log/nginx`, `/var/run/nginx.pid`) is explicitly set to the `nginx` user at build time, so no runtime root access is required.

---

### Attack-surface tools removed (CIS 4.7)

Alpine's BusyBox provides `wget` and `curl` as applets. Unlike Debian, `apk del wget` does **not** remove the binary — BusyBox applets share a single binary and cannot be removed individually via the package manager. The binaries are deleted directly:

```dockerfile
&& rm -f /usr/bin/wget /usr/bin/curl /bin/wget /bin/curl
```

Without these, an attacker who achieves code execution inside the container cannot pull a second-stage payload from the internet.

---

### SUID/SGID bits stripped (CIS 4.8)

```dockerfile
find / -xdev \( -perm /4000 -o -perm /2000 \) -exec chmod ug-s {} +
```

Alpine ships with fewer SUID binaries than Debian, but this step is applied regardless. Verified by structure tests at runtime.

---

### Hardened `nginx.conf`

The configuration goes beyond defaults in several areas:

**Server identity hidden**
```nginx
server_tokens off;
```
Removes the nginx version number from `Server` response headers and error pages. Version disclosure helps attackers target known CVEs.

**Security response headers**

| Header | Value | Purpose |
|---|---|---|
| `X-Frame-Options` | `SAMEORIGIN` | Prevents clickjacking via iframe embedding |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing attacks |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS filter for older browsers |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referrer leakage on cross-origin requests |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | Explicitly disables sensitive browser APIs |
| `Content-Security-Policy` | `default-src 'self'` | Blocks inline scripts and external resource loading |
| `Strict-Transport-Security` | `max-age=31536000` | Forces HTTPS for 1 year (activate only behind TLS) |

**Hidden files blocked**
```nginx
location ~ /\. { deny all; return 404; }
```
Requests for `.git/`, `.env`, `.htaccess`, etc. return 404 with no directory listing.

**`/healthz` endpoint**
```nginx
location /healthz {
    access_log off;
    return 200 "ok\n";
}
```
Returns 200 for orchestrator health checks without polluting access logs. The `HEALTHCHECK` instruction uses `nc -z 127.0.0.1 8080` (netcat) since `curl` and `wget` are removed.

---

## CVE scan result

```
hardened-nginx:latest — Trivy scan (CRITICAL, HIGH)

hardened-nginx:latest (alpine 3.21.3)  →  Total: 0
```

Alpine's aggressive patching cadence keeps the base clean. Run `make scan IMAGE=nginx` to verify against the current DB.

---

## Serving your frontend

Replace `dist/` with your built frontend assets:

```dockerfile
# Build stage (your existing frontend build)
FROM node:20-slim AS builder
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build          # outputs to dist/

# Final stage — drop the assets into the hardened image
FROM hardened-nginx:latest
COPY --from=builder --chown=nginx:nginx /build/dist/ /usr/share/nginx/html/
```

The included [`dist/index.html`](dist/index.html) is a placeholder demonstrating the expected structure.

---

## Runtime flags

```bash
docker run \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m \
  --tmpfs /var/cache/nginx:rw,noexec,nosuid,size=32m \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --user 101:101 \
  -p 8080:8080 \
  hardened-nginx:latest
```

Two `--tmpfs` mounts are required: `/tmp` for general temp files, and `/var/cache/nginx` for nginx's proxy and FastCGI caches. Both are mounted `noexec` — nothing written there can be executed.

---

## Quick reference

```bash
make build IMAGE=nginx          # Build the image
make scan  IMAGE=nginx          # Trivy CVE scan (fails on CRITICAL/HIGH)
make sbom  IMAGE=nginx          # Generate CycloneDX + SPDX SBOM
make lint  IMAGE=nginx          # OPA/Conftest policy check on the Dockerfile
make test-structure IMAGE=nginx # 13 runtime assertions against the built image
```
