# images/node — Hardened Node.js 20 Image

**Base:** `node:20-slim`

Follow the same hardening pattern as [images/python](../python/README.md). Key differences for Node.js are noted below.

## Hardening Decisions

### Multi-stage build
`npm ci --omit=dev` in the builder stage installs only production dependencies and respects the lock file. The `node_modules` and application source are copied to the final stage; `npm` itself is not included in the runtime image.

### Non-root user: `appuser` (UID 10001)
Same pattern as Python. Node.js does not require root for typical web server workloads.

### No `npm install` at runtime
The final image has no `npm` invocation at container start. Dependencies are pre-installed and baked in during the build stage.

### `--ignore-scripts` not used for install but `COPY` excludes `.npmrc`
Post-install scripts in npm packages are a known supply-chain vector. Review `package.json` dependencies and use `--ignore-scripts` if your dependency tree supports it.

### SUID/SGID stripping and package removal
Same as Python: `wget`, `curl`, `perl` removed; all SUID/SGID bits stripped.

## Runtime Recommendations

```bash
docker run \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --user 10001:10001 \
  hardened-node:latest
```

## Building & Scanning

```bash
make build IMAGE=node
make scan  IMAGE=node
make sbom  IMAGE=node
```
