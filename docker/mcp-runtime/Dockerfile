# Build stage: install deps from the committed lockfile (`npm ci` — exact
# versions only, no transitive drift across builds — matters here since
# this image spawns untrusted third-party MCP subprocesses).
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npx tsc --noEmit
RUN npx esbuild src/index.ts \
    --bundle --platform=node --target=node22 --format=esm \
    --outfile=dist/mcp-runtime.mjs

# Runtime stage: node slim + the bundled JS. We need npx/npm to pull MCP
# packages on demand, so we keep the full node image (not -alpine, which
# can trip musl-incompatible native deps in MCP servers).
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
# Create an unprivileged user for spawned MCP subprocesses.
RUN useradd --system --home /app --shell /usr/sbin/nologin mcp \
 && mkdir -p /tmp/mcp-cache \
 && chown mcp:mcp /app /tmp/mcp-cache
COPY --from=build --chown=mcp:mcp /app/dist/mcp-runtime.mjs ./mcp-runtime.mjs
USER mcp
ENV NODE_ENV=production \
    PACKAGE_CACHE_DIR=/tmp/mcp-cache
EXPOSE 8080
CMD ["node", "mcp-runtime.mjs"]
