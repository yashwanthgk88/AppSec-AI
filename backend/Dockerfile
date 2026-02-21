# Build stage - install dependencies
# Cache bust: 2026-02-21-v2
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage - minimal runtime
FROM python:3.11-slim

WORKDIR /app

# Install only runtime dependencies (curl for health checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY . .

# Create data directory
RUN mkdir -p /app/data

ENV PORT=8080
EXPOSE 8080

# Fast startup
CMD ["sh", "-c", "python3 -c 'from models.database import init_db; init_db()' && python3 migrate_db.py 2>/dev/null || true && python3 init_custom_rules_sqlite.py && gunicorn main:app -w 1 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --timeout 600 --graceful-timeout 600 --keep-alive 120"]
