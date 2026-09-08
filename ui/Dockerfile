# Pin: node 20.19 alpine 3.21 (2025-04)
FROM node:25-alpine3.21@sha256:32509199057d74a987fdd88cde00fdfd48ef52469adbd6bd11969fc701477761 AS frontend-builder
WORKDIR /frontend
COPY ./ui/package*.json ./
RUN npm ci
COPY ./ui/ ./
RUN npm run build

# Pin: nginx 1.27.4 alpine (2025-03)
FROM nginx:1.31.3-alpine@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752

# openssl for self-signed cert generation at boot
# Distribution packages are installed without a version constraint. That is a
# deliberate trade-off: pinning an exact apk/apt version breaks the build the
# moment the repository rotates it, which for a project that rebuilds on every
# release costs more than it buys. The consequence is accepted and bounded —
# a rebuild of a tagged release resolves different package versions than the
# one that was published and signed, so a rebuild cannot be used to verify the
# original (SECURE-BLD-03).
#
# Where a package DOES carry security weight the version is asserted after
# install instead: see proxy/Dockerfile, which fails the build if squid-openssl
# is older than its CVE floor.
RUN apk add --no-cache openssl && rm /etc/nginx/conf.d/default.conf

COPY --from=frontend-builder /frontend/dist /usr/share/nginx/html
COPY ./ui/nginx.conf.template            /etc/nginx/templates/default.conf.template
COPY ./ui/docker-entrypoint.sh           /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8011 8443

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD wget -qO- http://localhost:8011/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
