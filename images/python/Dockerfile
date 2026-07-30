# =============================================================================
# Stage 1: builder
# Install dependencies in a throwaway stage so build tooling never reaches
# the final image. This reduces attack surface and final image size.
# =============================================================================
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS builder

WORKDIR /build

# Upgrade pip in the builder only; not needed at runtime
RUN pip install --upgrade pip --no-cache-dir

# Copy and install application dependencies into a prefix that can be
# copied wholesale into the final stage.
COPY requirements.txt .
RUN mkdir -p /install && pip install --no-cache-dir --prefix=/install -r requirements.txt


# =============================================================================
# Stage 2: final
# Minimal runtime image with no build tooling.
# =============================================================================
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS final

# --- OCI / CIS 4.1: Apply standard labels ---------------------------------
LABEL org.opencontainers.image.title="hardened-python" \
      org.opencontainers.image.description="CIS-hardened Python 3.12 runtime" \
      org.opencontainers.image.vendor="container-hardening-lab" \
      org.opencontainers.image.base.name="python:3.12-slim"

# --- CIS 4.6 / 4.7: Remove SUID/SGID bits and unnecessary packages --------
# Remove tools that are never needed at runtime to reduce attack surface.
RUN apt-get update && \
    apt-get remove --purge -y \
        wget \
        curl \
        perl \
        gcc \
        binutils \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    # perl-base can't be removed via `apt remove` — other packages formally
    # depend on it even though nothing at runtime actually calls perl. A plain
    # `rm` of the binary leaves the package registered in dpkg, which is what
    # CVE scanners (including Trivy) actually read, so the CVEs kept showing
    # up regardless. Force-purge the dpkg record itself so the package is
    # genuinely gone, not just its binary. Safe here because no further
    # apt/dpkg operations happen later in this build.
    && dpkg --purge --force-depends --force-remove-essential perl-base \
    # Strip SUID/SGID bits from all binaries (CIS 4.8)
    && find / -xdev \( -perm /4000 -o -perm /2000 \) -exec chmod ug-s {} + 2>/dev/null || true

# --- CIS 4.1: Create a dedicated non-root user and group ------------------
# Use a high UID/GID (above 10000) to avoid conflicts with system accounts.
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

# --- Copy installed packages from builder ---------------------------------
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application source (update this COPY for your actual source layout)
COPY --chown=appuser:appgroup app/ ./

# --- CIS 4.1: Drop to non-root user before runtime ------------------------
USER appuser

# Expose only the necessary port (adjust for your application)
EXPOSE 8000

# --- CIS 4.6: Define a HEALTHCHECK ----------------------------------------
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

# Default entrypoint — override in child images or compose files
ENTRYPOINT ["python"]
CMD ["-m", "http.server", "8000"]
