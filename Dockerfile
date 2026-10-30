# syntax=docker/dockerfile:1

# Published for amd64 and arm64. The first two stages run once on the build machine: the UI is static files and
# every runtime dependency is plain JavaScript, so their output fits every platform's image.

# ---- 1. Build the web UI -------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:24-alpine AS web
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY vite.config.ts tsconfig.json ./
COPY web ./web
COPY shared ./shared
RUN npm run build

# ---- 2. Production dependencies only -------------------------------------------
FROM --platform=$BUILDPLATFORM node:24-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# ---- 3. Runtime ----------------------------------------------------------------
FROM node:24-alpine
WORKDIR /app
LABEL org.opencontainers.image.title="UniFi Security Console" \
      org.opencontainers.image.description="Self-hosted security dashboard for UniFi networks" \
      org.opencontainers.image.source="https://github.com/kcorr/unifi-security-console" \
      org.opencontainers.image.licenses="MIT"
# HOST=0.0.0.0 is needed inside the container; publish the port on 127.0.0.1 only (see the README).
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8787 \
    DATA_DIR=/data
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY server ./server
COPY shared ./shared
COPY --from=web /app/web/dist ./web/dist
RUN mkdir -p /data && chown -R node:node /data
USER node
EXPOSE 8787
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:8787/api/health > /dev/null || exit 1
# Node 24 runs the TypeScript sources directly (type stripping) - no compile step needed.
CMD ["node", "--disable-warning=ExperimentalWarning", "server/index.ts"]
