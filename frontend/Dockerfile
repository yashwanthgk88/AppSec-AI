# Build stage
FROM node:18-alpine AS builder

WORKDIR /app

# Copy ONLY package files first (cached layer - only rebuilds if deps change)
COPY package*.json ./

# Install dependencies
RUN npm ci --legacy-peer-deps

# Copy application code AFTER deps are installed
COPY . .

# Build argument for API URL - MUST be set in Railway
ARG VITE_API_URL
ENV VITE_API_URL=$VITE_API_URL

# Build the application
RUN echo "Building with API URL: $VITE_API_URL" && npm run build

# The public/downloads folder is already copied during COPY . . above
# Just verify the extension file is in dist/downloads after build
RUN ls -la dist/downloads/ || echo "Downloads folder will be created by vite build"

# Production stage
FROM nginx:alpine

# Install curl and gettext for healthcheck and config substitution
RUN apk add --no-cache curl gettext

# Copy nginx config template
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

# Copy built application from builder stage (includes downloads)
COPY --from=builder /app/dist /usr/share/nginx/html

# Verify the extension file is present
RUN ls -la /usr/share/nginx/html/downloads/

# Default port (Railway will override with PORT env var)
ENV PORT=80

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-80}/health || exit 1

# Start script to substitute PORT and start nginx
CMD ["/bin/sh", "-c", "envsubst '$PORT' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"]
