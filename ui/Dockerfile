# Pin: node 20.19 alpine 3.21 (2025-04)
FROM node:20.19-alpine3.21@sha256:eb0b81f6eb35ec5ecd1cab181801f93a6314127580b416e6e290363b724e1686 AS frontend-builder
WORKDIR /frontend
COPY ./ui/package*.json ./
RUN npm ci
COPY ./ui/ ./
RUN npm run build

# Pin: nginx 1.27.4 alpine (2025-03)
FROM nginx:1.31.2-alpine@sha256:54f2a904c251d5a34adf545a72d32515a15e08418dae0266e23be2e18c66fefa

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
