# Pin: node 20.19 alpine 3.21 (2025-04)
FROM node:20.19-alpine3.21@sha256:eb0b81f6eb35ec5ecd1cab181801f93a6314127580b416e6e290363b724e1686 AS frontend-builder
WORKDIR /frontend
COPY ./ui/package*.json ./
RUN npm ci
COPY ./ui/ ./
RUN npm run build

# Pin: nginx 1.27.4 alpine (2025-03)
FROM nginx:1.31.3-alpine@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752

# openssl for self-signed cert generation at boot
RUN apk add --no-cache openssl && rm /etc/nginx/conf.d/default.conf

COPY --from=frontend-builder /frontend/dist /usr/share/nginx/html
COPY ./ui/nginx.conf.template            /etc/nginx/templates/default.conf.template
COPY ./ui/docker-entrypoint.sh           /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8011 8443

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD wget -qO- http://localhost:8011/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
