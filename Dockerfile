# syntax=docker/dockerfile:1

FROM node:22-alpine AS build
WORKDIR /app

# === AIS Optimization: npm registry speed ===
COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn ./.yarn
RUN corepack enable \
  && yarn --version \
  && yarn config set npmRegistryServer https://registry.npmjs.org \
  && yarn config set network-timeout 600000 \
  && yarn install --immutable --inline-builds --network-timeout 600000

COPY . .
RUN yarn build


FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080
ENV SERVE_STATIC=1

# === AIS DNS Bypass: Hardcode DNS ===
ENV DNS_SERVER=1.1.1.1
ENV DNS_OVER_HTTPS=true
ENV DOH_URL=https://cloudflare-dns.com/dns-query

# === AIS Throttling Prevention ===
ENV CONCURRENCY=15
ENV TIMEOUT=3
ENV SCAN_INTERVAL=200
ENV MAX_RETRIES=2
ENV SCAN_PORTS=80,443,8080,8443,53,123,993,995,5222,5223

COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn ./.yarn
RUN corepack enable \
  && yarn --version \
  && yarn config set npmRegistryServer https://registry.npmjs.org \
  && yarn config set network-timeout 600000 \
  && yarn install --immutable --inline-builds --mode=skip-build --network-timeout 600000

COPY --from=build /app/dist ./dist
COPY --from=build /app/server ./server

# === Health Check (AIS keep-alive) ===
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8080/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

EXPOSE 8080
CMD ["node", "server/index.mjs"]
