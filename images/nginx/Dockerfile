# =============================================================================
# Hardened nginx 1.27 static file server
#
# Single-stage: pre-built static assets are copied from dist/ in the build
# context. For a frontend app (React/Vue/etc.) add a builder stage that runs
# `npm run build` before this stage; see images/node/Dockerfile for the
# multi-stage pattern.
# =============================================================================
FROM nginx:1.27-alpine AS final

LABEL org.opencontainers.image.title="hardened-nginx" \
      org.opencontainers.image.description="CIS-hardened nginx 1.27 static file server" \
      org.opencontainers.image.vendor="container-hardening-lab" \
      org.opencontainers.image.base.name="nginx:1.27-alpine"

# --- CIS 4.7 / 4.8: Remove unnecessary packages, strip SUID/SGID bits -----
RUN apk upgrade --no-cache \
    # On Alpine, wget/curl are BusyBox applets — apk del alone won't remove them.
    # Delete the binaries directly to reduce attack surface.
    && rm -f /usr/bin/wget /usr/bin/curl /bin/wget /bin/curl \
    # Strip SUID/SGID bits
    && find / -xdev \( -perm /4000 -o -perm /2000 \) -exec chmod ug-s {} + 2>/dev/null || true \
    # Fix ownership so nginx user can write to required runtime dirs
    && chown -R nginx:nginx /var/cache/nginx /var/log/nginx /etc/nginx/conf.d \
    && touch /var/run/nginx.pid \
    && chown nginx:nginx /var/run/nginx.pid

# Copy hardened nginx configuration
COPY --chown=nginx:nginx nginx.conf /etc/nginx/nginx.conf

# Copy pre-built static assets
COPY --chown=nginx:nginx dist/ /usr/share/nginx/html/

# --- CIS 4.1: Run as non-root nginx user (UID 101) -------------------------
USER nginx

# Non-privileged port — avoids CAP_NET_BIND_SERVICE (CIS 5.7)
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD nc -z 127.0.0.1 8080 || exit 1

CMD ["nginx", "-g", "daemon off;"]
