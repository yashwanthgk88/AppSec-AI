# AppSec Platform - Docker Deployment Guide

This guide explains how to deploy the AppSec Platform using Docker containers without modifying source code.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Deployment Modes](#deployment-modes)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)
- [Maintenance](#maintenance)

## Prerequisites

### Required Software

1. **Docker** (version 20.10 or higher)
   ```bash
   docker --version
   ```
   Install from: https://www.docker.com/get-started

2. **Docker Compose** (version 2.0 or higher)
   ```bash
   docker-compose --version
   ```

### System Requirements

- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Disk Space**: Minimum 10GB free space
- **CPU**: 2+ cores recommended

## Quick Start

### 1. Clone or Download the Repository

```bash
git clone https://github.com/yourusername/appsec-platform.git
cd appsec-platform
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Generate a secure secret key
openssl rand -hex 32

# Edit .env file
nano .env  # or use your preferred editor
```

**Required Configuration:**
- `SECRET_KEY`: Paste the generated secret key
- `VITE_API_URL`: Update with your backend URL
- `CORS_ORIGINS`: Add your frontend URL(s)

**Optional Configuration:**
- `ANTHROPIC_API_KEY`: For Claude AI features
- `OPENAI_API_KEY`: For GPT features
- `GEMINI_API_KEY`: For Gemini features

### 3. Deploy

```bash
# Development mode (default)
./deploy.sh

# Production mode with Nginx
./deploy.sh production
```

### 4. Access the Application

**Development Mode:**
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- VS Code Extension: http://localhost:3000/downloads/appsec-ai-scanner-1.4.0.vsix

**Production Mode:**
- Frontend: http://localhost:80
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- VS Code Extension: http://localhost/downloads/appsec-ai-scanner-1.4.0.vsix

## Configuration

### Environment Variables

All configuration is done through the `.env` file. Here are the key variables:

#### Deployment Settings

```bash
# Deployment mode
ENVIRONMENT=production

# Port configuration
BACKEND_PORT=8000
FRONTEND_PORT=3000
NGINX_HTTP_PORT=80
NGINX_HTTPS_PORT=443
```

#### Backend Configuration

```bash
# Database (SQLite by default, easiest for deployment)
DATABASE_URL=sqlite:///app/data/appsec.db

# Security
SECRET_KEY=your-generated-secret-key-here

# CORS (comma-separated list of allowed origins)
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com

# Logging
LOG_LEVEL=info
```

#### AI Provider Keys

```bash
# Optional: Add only the AI providers you plan to use
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...
OLLAMA_BASE_URL=http://host.docker.internal:11434
```

#### Frontend Configuration

```bash
# API URL (must match your backend)
VITE_API_URL=http://localhost:8000

# For production with domain:
# VITE_API_URL=https://api.yourdomain.com
```

## Deployment Modes

### Development Mode

Best for local testing and development:

```bash
./deploy.sh dev
```

**Features:**
- Direct access to backend (port 8000)
- Direct access to frontend (port 3000)
- Hot reload disabled (rebuild to see changes)
- Logs visible with `./deploy.sh logs`

### Production Mode

Optimized for production deployment with Nginx reverse proxy:

```bash
./deploy.sh production
```

**Features:**
- Nginx reverse proxy on port 80/443
- Better performance with caching
- Rate limiting enabled
- Gzip compression
- Security headers
- SSL/TLS support (configure SSL certificates)

## Production Deployment

### Step 1: Prepare Server

1. **Update System:**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install Docker:**
   ```bash
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   sudo usermod -aG docker $USER
   ```

3. **Install Docker Compose:**
   ```bash
   sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   sudo chmod +x /usr/local/bin/docker-compose
   ```

### Step 2: Configure Domain (Optional)

Update your DNS records to point to your server's IP address:

```
A Record: yourdomain.com → Your Server IP
A Record: www.yourdomain.com → Your Server IP
```

### Step 3: SSL/TLS Configuration (Optional but Recommended)

#### Option 1: Let's Encrypt (Free)

```bash
# Install Certbot
sudo apt install certbot

# Generate SSL certificate
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ./nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ./nginx/ssl/key.pem
sudo chmod 644 ./nginx/ssl/cert.pem
sudo chmod 600 ./nginx/ssl/key.pem
```

#### Option 2: Self-Signed Certificate (Development Only)

```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem
```

### Step 4: Update Configuration

Edit `.env` file:

```bash
# Update domain
DOMAIN=yourdomain.com

# Update API URL
VITE_API_URL=https://api.yourdomain.com

# Update CORS
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# Production settings
ENVIRONMENT=production
LOG_LEVEL=warning
```

Edit `nginx/nginx.conf` to uncomment HTTPS section and update domain.

### Step 5: Deploy

```bash
./deploy.sh production
```

### Step 6: Verify Deployment

```bash
# Check container status
docker-compose ps

# Check logs
./deploy.sh logs

# Test health endpoints
curl http://localhost/health
curl http://localhost:8000/health
```

## Deployment Commands

The `deploy.sh` script supports the following commands:

```bash
# Start in development mode
./deploy.sh dev

# Start in production mode
./deploy.sh production

# Stop all containers
./deploy.sh stop

# Restart containers
./deploy.sh restart

# View logs (real-time)
./deploy.sh logs

# Clean up (removes all data!)
./deploy.sh clean
```

### Manual Docker Compose Commands

```bash
# Build and start
docker-compose up -d --build

# Stop containers
docker-compose down

# View logs
docker-compose logs -f

# View logs for specific service
docker-compose logs -f backend
docker-compose logs -f frontend

# Restart specific service
docker-compose restart backend

# Scale services (not applicable for this app)
docker-compose up -d --scale backend=3
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs

# Check specific service
docker-compose logs backend
docker-compose logs frontend

# Rebuild from scratch
docker-compose down -v
docker-compose up -d --build
```

### Port Already in Use

```bash
# Find process using port
sudo lsof -i :8000
sudo lsof -i :3000
sudo lsof -i :80

# Kill process
sudo kill -9 <PID>

# Or change port in .env file
BACKEND_PORT=8001
FRONTEND_PORT=3001
```

### Database Issues

```bash
# Reset database (WARNING: Deletes all data!)
docker-compose down -v
docker-compose up -d

# Backup database
docker cp appsec-backend:/app/data/appsec.db ./backup-appsec.db

# Restore database
docker cp ./backup-appsec.db appsec-backend:/app/data/appsec.db
docker-compose restart backend
```

### Permission Issues

```bash
# Fix volume permissions
sudo chown -R $USER:$USER .
chmod +x deploy.sh
```

### Out of Memory

```bash
# Reduce number of workers in backend Dockerfile
# Change: --workers 4
# To: --workers 2

# Or increase server memory/swap
```

## Maintenance

### Backup

```bash
# Backup database
docker cp appsec-backend:/app/data/appsec.db ./backup-$(date +%Y%m%d).db

# Backup volumes
docker run --rm -v appsec-platform_appsec-data:/data -v $(pwd):/backup alpine tar czf /backup/data-backup-$(date +%Y%m%d).tar.gz /data
```

### Update

```bash
# Pull latest code
git pull

# Rebuild and restart
docker-compose down
docker-compose up -d --build
```

### Monitoring

```bash
# View resource usage
docker stats

# View specific container
docker stats appsec-backend
docker stats appsec-frontend

# Check health
curl http://localhost/health
curl http://localhost:8000/health
```

### Logs Management

```bash
# View last 100 lines
docker-compose logs --tail=100

# Save logs to file
docker-compose logs > deployment-logs.txt

# Rotate logs (prevent disk space issues)
docker-compose down
docker system prune -f
docker-compose up -d
```

## Security Best Practices

1. **Change Default Secrets:**
   - Generate unique `SECRET_KEY`
   - Use strong AI API keys

2. **Enable HTTPS:**
   - Use Let's Encrypt SSL certificates
   - Update nginx configuration for HTTPS
   - Force HTTPS redirects

3. **Firewall Configuration:**
   ```bash
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```

4. **Regular Updates:**
   - Keep Docker updated
   - Update application regularly
   - Monitor security advisories

5. **Limit Exposure:**
   - Don't expose database port (5432) publicly
   - Use environment variables for secrets
   - Enable rate limiting in nginx

## Support

For issues and questions:

- GitHub Issues: https://github.com/yourusername/appsec-platform/issues
- Documentation: https://docs.yourdomain.com
- Email: support@yourdomain.com

## License

Copyright © 2025 AppSec Platform. All rights reserved.
