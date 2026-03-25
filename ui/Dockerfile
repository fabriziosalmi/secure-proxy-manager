# Stage 1: Build React frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /frontend
COPY ./ui/package*.json ./
RUN npm ci
COPY ./ui/ ./
RUN npm run build

# Stage 2: Nginx — serves the compiled SPA and reverse-proxies /api/ to FastAPI
FROM nginx:1.27-alpine

# envsubst is in gettext; already present in nginx:alpine
RUN rm /etc/nginx/conf.d/default.conf

COPY --from=frontend-builder /frontend/dist /usr/share/nginx/html
COPY ./ui/nginx.conf.template            /etc/nginx/templates/default.conf.template
COPY ./ui/docker-entrypoint.sh           /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8011
ENTRYPOINT ["/docker-entrypoint.sh"]
