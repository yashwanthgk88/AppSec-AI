FROM python:3.11-slim

# Cache bust: 2026-02-03-v2
ARG CACHEBUST=1

WORKDIR /app

# Install system dependencies including curl for healthcheck and git for repo cloning
RUN apt-get update && apt-get install -y \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements (local path since build context is backend/)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (local path since build context is backend/)
COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data

# Default port (Railway will override with PORT env var)
ENV PORT=8000

# Expose port
EXPOSE 8000

# Initialize database and start server with dynamic port
CMD python3 -c "from models.database import engine, Base; Base.metadata.create_all(bind=engine); print('Database initialized')" && \
    python3 migrate_db.py || echo "Migration skipped" && \
    gunicorn main:app -w 2 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --timeout 600 --graceful-timeout 300
