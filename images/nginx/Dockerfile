# =============================================================================
# Hardened nginx 1.27 static file server
#
# Single-stage: pre-built static assets are copied from dist/ in the build
# context. For a frontend app (React/Vue/etc.) add a builder stage that runs
# `npm run build` before this stage; see images/node/Dockerfile for the
# multi-stage pattern.
# =============================================================================
FROM nginx:1.27-alpine@sha256:62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8 AS final

LABEL org.opencontainers.image.title="hardened-nginx" \
      org.opencontainers.image.description="CIS-hardened nginx 1.27 static file server" \
      org.opencontainers.image.vendor="container-hardening-lab" \
      org.opencontainers.image.base.name="nginx:1.27-alpine"

# --- CIS 4.7 / 4.8: Remove unnecessary tools, strip SUID/SGID bits --------
RUN apk upgrade --no-cache \
    \
    # Alpine's wget and curl are BusyBox applets — `apk del wget` removes the
    # package entry but leaves the BusyBox binary intact. The binaries must be
    # deleted directly. Without these, an attacker who achieves code execution
    # cannot pull a second-stage payload from the internet.
    && rm -f /usr/bin/wget /usr/bin/curl /bin/wget /bin/curl \
    \
    # CIS 4.8: Strip SUID/SGID bits from every binary.
    # Alpine ships fewer SUID binaries than Debian, but this is applied
    # unconditionally — the find runs in O(n) over the small Alpine filesystem
    # and is not a meaningful build-time cost.
    && find / -xdev \( -perm /4000 -o -perm /2000 \) -exec chmod ug-s {} + 2>/dev/null || true \
    \
    # Fix ownership so the nginx user can write to the dirs it needs at runtime
    # without root. Required because the base image owns these as root.
    #   /var/cache/nginx  — proxy/FastCGI cache
    #   /var/log/nginx    — access and error logs
    #   /etc/nginx/conf.d — include directory for vhost configs
    && chown -R nginx:nginx /var/cache/nginx /var/log/nginx /etc/nginx/conf.d \
    \
    # nginx writes its PID to /var/run/nginx.pid at startup. The file must be
    # owned by the nginx user before the process starts, otherwise startup fails.
    && touch /var/run/nginx.pid \
    && chown nginx:nginx /var/run/nginx.pid

# Copy hardened nginx configuration.
# Key settings: server_tokens off, port 8080, security headers, /healthz.
# See nginx.conf for full annotation.
COPY --chown=nginx:nginx nginx.conf /etc/nginx/nginx.conf

# Copy pre-built static assets.
# Replace this with a --from=builder COPY in a multi-stage build for
# React/Vue/Angular apps that need a build step.
COPY --chown=nginx:nginx dist/ /usr/share/nginx/html/

# --- CIS 4.1: Run as non-root nginx user (UID 101) -------------------------
# The nginx master process normally requires root to bind to port 80.
# By binding to port 8080 instead, the entire process tree — master and
# workers — runs as UID 101 with no elevated privileges.
USER nginx

# Non-privileged port — avoids CAP_NET_BIND_SERVICE (CIS 5.7).
# Map 80→8080 at the ingress/load balancer layer.
EXPOSE 8080

# Health check using netcat (ships with Alpine).
# curl and wget are removed, so nc is the only available TCP probe.
# Checks that port 8080 is accepting connections — the /healthz location
# in nginx.conf returns 200 to confirm the worker is live.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD nc -z 127.0.0.1 8080 || exit 1

CMD ["nginx", "-g", "daemon off;"]
