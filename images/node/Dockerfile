# =============================================================================
# Stage 1: builder
# Install npm dependencies and transpile/bundle application code.
# =============================================================================
FROM node:20-slim AS builder

WORKDIR /build

# Copy manifests first to leverage layer caching
COPY package.json package-lock.json ./

# Install production deps only; ci respects lock file for reproducibility
RUN npm ci --omit=dev --ignore-scripts

COPY . .


# =============================================================================
# Stage 2: final
# Minimal runtime image; no npm, no shell scripts from node internals.
# =============================================================================
FROM node:20-slim AS final

LABEL org.opencontainers.image.title="hardened-node" \
      org.opencontainers.image.description="CIS-hardened Node.js 20 runtime" \
      org.opencontainers.image.vendor="container-hardening-lab" \
      org.opencontainers.image.base.name="node:20-slim"

# Remove attack-surface packages and strip SUID/SGID bits
RUN apt-get update && \
    apt-get remove --purge -y \
        wget \
        curl \
        perl \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    # perl-base ships /usr/bin/perl but cannot be cleanly purged via apt on slim images
    && rm -f /usr/bin/perl /usr/bin/perl5* \
    && find / -xdev \( -perm /4000 -o -perm /2000 \) -exec chmod ug-s {} + 2>/dev/null || true \
    # Remove npm and its bundled packages — only node is needed at runtime.
    # npm ships internal copies of glob, minimatch, tar, cross-spawn etc. that
    # appear as CVEs in Trivy scans even though they are never executed by the app.
    && rm -rf /usr/local/lib/node_modules/npm \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx

# Dedicated non-root user
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

# Copy only the production build artifacts and node_modules from builder
COPY --from=builder --chown=appuser:appgroup /build/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /build/src ./src

USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/healthz', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

ENTRYPOINT ["node"]
CMD ["src/index.js"]
