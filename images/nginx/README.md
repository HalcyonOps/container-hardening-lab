# images/nginx — Hardened nginx 1.27 Image

**Base:** `nginx:1.27-alpine`

Static file server (or reverse proxy) hardened for production use.

## Hardening Decisions

### Alpine base
`nginx:1.27-alpine` is used instead of the debian-based variant. Alpine's musl libc and minimal package set reduce both image size and attack surface. Alpine CVEs tend to be patched faster than Debian/Ubuntu for the nginx package.

### Non-root user: `nginx` (UID 101)
The official nginx Alpine image ships with a `nginx` user. The Dockerfile sets `USER nginx` and adjusts ownership of `/var/cache/nginx`, `/var/log/nginx`, and `/var/run/nginx.pid` so the process runs without root.

### Non-privileged port 8080
nginx binds to port 8080 (not 80). Binding to ports below 1024 requires `CAP_NET_BIND_SERVICE`; avoiding it allows `--cap-drop=ALL` at runtime.

### Hardened `nginx.conf`
- `server_tokens off` — hides nginx version from headers and error pages
- Security response headers: `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`, `Content-Security-Policy`, `Strict-Transport-Security`
- Hidden files (`.git`, `.env`) denied with 404
- `/healthz` endpoint for orchestrator health checks, without log noise

### Multi-stage build
Static assets are built in a `node:20-slim` builder stage. Only the compiled `dist/` directory is copied to the nginx image — no Node.js, npm, or source files remain.

### SUID/SGID stripping
All setuid/setgid bits stripped via `find / -xdev ... -exec chmod ug-s {} +`.

## Runtime Recommendations

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

## Building & Scanning

```bash
make build IMAGE=nginx
make scan  IMAGE=nginx
make sbom  IMAGE=nginx
```
