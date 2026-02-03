# Build stage
FROM node:18-alpine AS builder

# Cache bust: 2026-02-03-v4-copy-from-builder
ARG CACHEBUST=1

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --legacy-peer-deps

# Copy application code
COPY . .

# Debug: List public/downloads contents in builder stage
RUN echo "=== Files in builder public/downloads ===" && ls -la public/downloads/ || echo "No downloads folder"

# Build argument for API URL - MUST be set in Railway
ARG VITE_API_URL
ENV VITE_API_URL=$VITE_API_URL

# Build the application
RUN echo "Building with API URL: $VITE_API_URL" && npm run build

# Copy downloads to dist folder so they're included
RUN mkdir -p dist/downloads && cp -r public/downloads/* dist/downloads/ || echo "No downloads to copy"

# Debug: List dist/downloads contents
RUN echo "=== Files in dist/downloads ===" && ls -la dist/downloads/ || echo "No dist/downloads"

# Production stage
FROM nginx:alpine

# Install curl and gettext for healthcheck and config substitution
RUN apk add --no-cache curl gettext

# Copy nginx config template
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

# Copy built application from builder stage (includes downloads)
COPY --from=builder /app/dist /usr/share/nginx/html

# Debug: List final downloads folder
RUN echo "=== Final downloads folder ===" && ls -la /usr/share/nginx/html/downloads/ || echo "No downloads folder"

# Default port (Railway will override with PORT env var)
ENV PORT=80

# Expose port
EXPOSE 80

# Start script to substitute PORT and start nginx
CMD /bin/sh -c "envsubst '\$PORT' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"
