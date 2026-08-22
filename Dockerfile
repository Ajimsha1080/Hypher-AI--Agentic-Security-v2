# ── Stage 1: Build ─────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies first (cached layer)
COPY package.json package-lock.json ./
RUN npm ci --include=dev

# Copy source and compile
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ── Stage 2: Production image ──────────────────────────────────────────
FROM node:20-alpine AS production

# Security: run as non-root
RUN addgroup -g 1001 -S mcpsg && \
    adduser  -u 1001 -S mcpsg -G mcpsg

WORKDIR /app

# Install production deps only
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy compiled output from builder
COPY --from=builder /app/dist ./dist

# Copy static assets needed at runtime
COPY src/public/      ./dist/public/
COPY src/dashboard/   ./dist/dashboard/
COPY src/admin/       ./dist/admin/
COPY src/analytics/   ./dist/analytics/
COPY src/auth/        ./dist/auth/
COPY src/db/          ./dist/db/
COPY src/audit/       ./dist/audit/

# Switch to non-root user
USER mcpsg

# Expose gateway port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD wget --spider -q http://localhost:3000/health/live || exit 1

# Start the compiled server
CMD ["node", "dist/proxy/server.js"]
