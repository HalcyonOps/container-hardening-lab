# examples/unhardened/Dockerfile
#
# INTENTIONALLY INSECURE — demonstration of hardening violations.
# This Dockerfile is used to show what the OPA/Conftest policies reject
# and what Trivy finds when using an outdated, unrestrictive base image.
#
# DO NOT use this as a basis for production images.
#
# Violations demonstrated:
#   [OPA deny]  No USER instruction — container runs as root
#   [OPA warn]  EXPOSE 80 — privileged port, requires CAP_NET_BIND_SERVICE
#   [OPA warn]  COPY --chown=root — files owned by root
#   [OPA deny]  FROM node:18 — node:18 is EOL (reached EOL April 2025)
#               and has known CRITICAL/HIGH CVEs detectable by Trivy
#   [CIS 4.7]   curl and wget left installed
#   [CIS 4.6]   No HEALTHCHECK defined

FROM node:18

WORKDIR /app

# Unnecessary tools left in — common in dev images, dangerous in prod
RUN apt-get update && apt-get install -y curl wget

COPY --chown=root:root . .

RUN npm install

# Binds to a privileged port — requires elevated capability at runtime
EXPOSE 80

# No USER instruction — process runs as root inside the container
# No HEALTHCHECK — orchestrators cannot detect unhealthy instances

CMD ["node", "src/index.js"]
