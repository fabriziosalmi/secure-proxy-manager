# Pin: node 20.19 alpine 3.21 (2025-04)
# 26, not 25: vitest 5, jsdom 30 and jest-dom 7 declare
# node ^22.22.2 || ^24.15.0 || >=26.0.0, which 25 does not satisfy. Installing
# them on 25 only warns (EBADENGINE) and the build still produced correct
# assets, but building the product on a runtime its own toolchain calls
# unsupported is not a thing to leave standing. 26 also sits above 25, so a
# later Dependabot bump cannot quietly put it back.
FROM node:26-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS frontend-builder
WORKDIR /frontend
COPY ./ui/package*.json ./
RUN npm ci
COPY ./ui/ ./
RUN npm run build

# Pin: nginx 1.31.8 alpine (2026-10)
FROM nginx:1.31.8-alpine@sha256:1ef7ca94d7879df82421428ce13bd1eaa412404953859cf7a5b6512c25e67a60

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
# Version floors for packages the published base image lags on, so the build
# fails rather than ships if the fixed package is gone: libexpat (CVE-2026-77214,
# fixed in this base since 1.31.8, floor kept), brotli-libs (CVE-2026-111497,
# nginx:1.31.8-alpine still ships 1.2.0-r1 while Alpine 3.24 has 1.2.1-r0) and
# curl/libcurl (CVE-2026-92392, the base ships 8.22.0-r0, Alpine 3.24 has
# 8.23.0-r0 since 2026-10-26).
RUN apk add --no-cache openssl 'libexpat>=2.9.0-r0' 'brotli-libs>=1.2.1-r0' 'curl>=8.23.0-r0' 'libcurl>=8.23.0-r0' && rm /etc/nginx/conf.d/default.conf

COPY --from=frontend-builder /frontend/dist /usr/share/nginx/html
COPY ./ui/nginx.conf.template            /etc/nginx/templates/default.conf.template
COPY ./ui/docker-entrypoint.sh           /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8011 8443

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD wget -qO- http://localhost:8011/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
