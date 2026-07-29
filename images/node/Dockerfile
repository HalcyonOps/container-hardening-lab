# =============================================================================
# Stage 1 — builder
#
# Installs production npm dependencies in an isolated stage so that the
# package manager, lock-file tooling, and devDependencies never appear in
# the final image. Only the resulting node_modules and application source
# are promoted to stage 2.
# =============================================================================
FROM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS builder

WORKDIR /build

# Copy manifests before source so Docker can cache the npm ci layer.
# If package.json and package-lock.json are unchanged, this layer is reused
# even when application source changes — dramatically faster rebuilds.
COPY package.json package-lock.json ./

# npm ci — prefer over npm install in CI/build contexts:
#   --omit=dev      only production dependencies in the final image
#   --ignore-scripts  disables postinstall/preinstall lifecycle scripts,
#                     which are a documented supply-chain attack vector
#   ci (vs install) fails if package-lock.json is out of sync, preventing
#                     silent dependency drift
RUN npm ci --omit=dev --ignore-scripts

COPY . .


# =============================================================================
# Stage 2 — final
#
# Minimal runtime image. Contains only: node binary, application source,
# production node_modules. No npm, no package manager, no build tooling.
# =============================================================================
FROM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS final

LABEL org.opencontainers.image.title="hardened-node" \
      org.opencontainers.image.description="CIS-hardened Node.js 20 runtime" \
      org.opencontainers.image.vendor="container-hardening-lab" \
      org.opencontainers.image.base.name="node:20-slim"

# --- CIS 4.7 / 4.8: Remove unnecessary packages, strip SUID/SGID bits -----
# apt-get upgrade pulls in any package fixes Debian has released since this
# base image was last rebuilt upstream (e.g. CVE-2026-33845/42010 in
# libgnutls30, fixed in deb12u7 — not yet baked into node:20-slim itself).
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get remove --purge -y \
        wget \
        curl \
        perl \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    \
    # perl-base provides /usr/bin/perl and cannot be cleanly removed via apt
    # on Debian slim images (it is a dependency of apt itself). Delete the
    # binary directly — the package entry remains but the attack surface is gone.
    && rm -f /usr/bin/perl /usr/bin/perl5* \
    \
    # CIS 4.8: Strip SUID/SGID bits from every binary in the image.
    # SUID binaries execute as their owner (typically root) regardless of the
    # calling user, enabling privilege escalation if the binary is exploitable.
    && find / -xdev \( -perm /4000 -o -perm /2000 \) -exec chmod ug-s {} + 2>/dev/null || true \
    \
    # Remove npm and all of its bundled internal packages.
    #
    # npm ships its own copies of glob, minimatch, tar, cross-spawn, and others
    # inside /usr/local/lib/node_modules/npm/node_modules/. These are separate
    # from the application's node_modules and are not updated by npm update.
    # They accumulate CVEs silently — 11 HIGH CVEs were present before this step.
    #
    # The application only needs the `node` binary at runtime; npm is a build
    # tool. Removing it eliminates the entire CVE surface with zero functional
    # impact on the running application.
    && rm -rf /usr/local/lib/node_modules/npm \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx

# --- CIS 4.1: Create a dedicated non-root user and group ------------------
# UID/GID 10001 is above the range used by system accounts (0–999) and
# typical application accounts (1000–9999), avoiding collisions.
# --no-create-home: no /home/appuser for an attacker to write to
# --shell /sbin/nologin: account cannot be used for interactive login
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

# Copy only production artifacts from the builder — node_modules and source.
# Nothing else from the builder (npm, package-lock.json, .npmrc) is included.
COPY --from=builder --chown=appuser:appgroup /build/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /build/src ./src

# --- CIS 4.1: Drop to non-root user before runtime ------------------------
USER appuser

# Non-privileged port — no CAP_NET_BIND_SERVICE required (CIS 5.7)
EXPOSE 3000

# Health check using Node's built-in http module — no curl/wget dependency.
# Adjust the path to match your application's health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/healthz', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

ENTRYPOINT ["node"]
CMD ["src/index.js"]
