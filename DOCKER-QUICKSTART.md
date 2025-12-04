# 🚀 Docker Quick Start Guide

Deploy AppSec Platform in 3 easy steps - no source code changes needed!

## Prerequisites

- Docker installed
- Docker Compose installed
- 4GB+ RAM available

## 🎯 Quick Deployment

### 1. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Generate secret key
openssl rand -hex 32

# Edit .env and paste the secret key
nano .env
```

**Minimum required changes in `.env`:**
```bash
SECRET_KEY=<paste-your-generated-key-here>
VITE_API_URL=http://localhost:8000
CORS_ORIGINS=http://localhost:3000,http://localhost:8000
```

### 2. Deploy

```bash
# Make deploy script executable
chmod +x deploy.sh

# Deploy in development mode
./deploy.sh dev

# OR deploy in production mode with Nginx
./deploy.sh production
```

### 3. Access

**Development Mode:**
- 🌐 Frontend: http://localhost:3000
- 🔧 Backend API: http://localhost:8000
- 📚 API Docs: http://localhost:8000/docs
- 💾 VS Code Extension: http://localhost:3000/downloads/appsec-ai-scanner-1.4.0.vsix

**Production Mode:**
- 🌐 Frontend: http://localhost:80
- 🔧 Backend API: http://localhost:8000
- 📚 API Docs: http://localhost:8000/docs
- 💾 VS Code Extension: http://localhost/downloads/appsec-ai-scanner-1.4.0.vsix

## 📝 Common Commands

```bash
# View logs
./deploy.sh logs

# Stop containers
./deploy.sh stop

# Restart containers
./deploy.sh restart

# Clean everything (WARNING: deletes data!)
./deploy.sh clean
```

## ⚙️ Optional: AI Provider Setup

Add AI API keys to `.env` for enhanced features:

```bash
# Anthropic Claude (Recommended)
ANTHROPIC_API_KEY=sk-ant-your-key-here

# OpenAI GPT
OPENAI_API_KEY=sk-your-key-here

# Google Gemini
GEMINI_API_KEY=your-key-here

# Local Ollama (Free, runs locally)
OLLAMA_BASE_URL=http://host.docker.internal:11434
```

## 🌍 Production Deployment with Domain

1. **Update `.env`:**
```bash
VITE_API_URL=https://api.yourdomain.com
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
DOMAIN=yourdomain.com
```

2. **Setup SSL (Optional but recommended):**
```bash
# Using Let's Encrypt
sudo certbot certonly --standalone -d yourdomain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ./nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ./nginx/ssl/key.pem
```

3. **Deploy:**
```bash
./deploy.sh production
```

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Change ports in .env
BACKEND_PORT=8001
FRONTEND_PORT=3001
```

### Container Won't Start
```bash
# Check logs
docker-compose logs backend
docker-compose logs frontend

# Rebuild from scratch
docker-compose down -v
docker-compose up -d --build
```

### Permission Denied
```bash
chmod +x deploy.sh
sudo chown -R $USER:$USER .
```

## 📖 Full Documentation

For detailed deployment options, SSL setup, monitoring, and troubleshooting:
- See [DEPLOYMENT.md](DEPLOYMENT.md)

## 🆘 Support

- GitHub Issues: Create an issue for bugs
- Documentation: See DEPLOYMENT.md for detailed guide

---

**That's it!** Your AppSec Platform is now running in Docker containers with zero source code changes needed. 🎉
