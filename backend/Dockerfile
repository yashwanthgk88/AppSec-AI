FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (cached layer)
RUN apt-get update && apt-get install -y \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (cached layer - only rebuilds if requirements change)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code LAST (changes frequently)
COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data

# Default port (Railway will override with PORT env var)
ENV PORT=8000

# Expose port
EXPOSE 8000

# Initialize database and start server with dynamic port
CMD echo "=== Starting AppSec Platform ===" && \
    echo "PORT=$PORT" && \
    echo "PWD=$(pwd)" && \
    ls -la && \
    echo "=== Initializing Database ===" && \
    python3 -c "from models.database import init_db; init_db(); print('Database initialized successfully')" && \
    echo "=== Running Migrations ===" && \
    python3 migrate_db.py || echo "Migration skipped (may already be applied)" && \
    echo "=== Initializing Custom Rules ===" && \
    python3 init_custom_rules_sqlite.py && \
    echo "=== Starting Gunicorn ===" && \
    gunicorn main:app -w 1 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --timeout 600 --graceful-timeout 600 --keep-alive 120 --log-level info --access-logfile - --error-logfile -
