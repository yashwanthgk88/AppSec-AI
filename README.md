# AI-Enabled Application Security Platform

A comprehensive application security platform featuring threat modeling, vulnerability scanning, custom security rules, rule performance tracking, AI chatbot, and detailed reporting.

## Features

### Core Capabilities
- **Threat Modeling:** Auto-generate DFD diagrams with STRIDE and MITRE ATT&CK mapping
- **SAST Scanning:** Static code analysis with 68 OWASP security rules + custom rules
- **SCA Analysis:** Software Composition Analysis for vulnerable dependencies
- **Secret Detection:** Scan for hardcoded credentials and sensitive data
- **Custom Security Rules:** Create and manage your own detection rules
- **Rule Performance Dashboard:** Track detection rates and rule effectiveness
- **AI Chatbot:** Security assistance powered by OpenAI
- **Report Export:** Generate Excel, PDF, and XML reports
- **VS Code Extension:** Real-time security feedback in your IDE (v1.5.0)
- **Live Log Correlation:** Real-time threat detection and alerts

---

## Deployment Guide

Choose your deployment method:
- **[Option A: Docker Deployment](#option-a-docker-deployment-recommended)** - Recommended for quick setup
- **[Option B: Manual Deployment](#option-b-manual-deployment-without-docker)** - Without Docker

---

## Option A: Docker Deployment (Recommended)

### Prerequisites

| Requirement | Version | Check Command |
|-------------|---------|---------------|
| Docker | 20.10+ | `docker --version` |
| Docker Compose | 2.0+ | `docker-compose --version` |
| RAM | 4GB+ | - |
| Disk Space | 10GB+ | - |

**Install Docker (if not installed):**
```bash
# Linux/Ubuntu
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# macOS: Download Docker Desktop from https://www.docker.com/products/docker-desktop
# Windows: Download Docker Desktop from https://www.docker.com/products/docker-desktop
```

---

### A1. Local Development with Docker

**Step 1: Clone the repository**
```bash
git clone https://github.com/yashwanthgk88/AppSec-AI.git
cd AppSec-AI
```

**Step 2: Create environment file**
```bash
cp .env.example .env
```

**Step 3: Generate and set secret key**
```bash
# Generate a secure key
openssl rand -hex 32

# Open .env and update these values:
nano .env
```

**Required `.env` settings for local development:**
```bash
SECRET_KEY=<paste-generated-key-here>
VITE_API_URL=http://localhost:8000
CORS_ORIGINS=http://localhost:3000,http://localhost:8000

# Optional: AI API keys (add if you want AI features)
OPENAI_API_KEY=sk-your-key-here
```

**Step 4: Start the application**
```bash
chmod +x deploy.sh
./deploy.sh dev
```

**Step 5: Access the application**
| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |
| VS Code Extension | http://localhost:3000/downloads/appsec-ai-scanner-1.5.0.vsix |

---

### A2. Production Deployment with Docker (Cloud/VPS)

**Step 1: SSH into your server**
```bash
ssh root@your-server-ip
```

**Step 2: Install Docker and Docker Compose**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Log out and back in for group changes to take effect
exit
ssh root@your-server-ip
```

**Step 3: Clone and configure**
```bash
git clone https://github.com/yashwanthgk88/AppSec-AI.git
cd AppSec-AI
cp .env.example .env

# Generate secret key
openssl rand -hex 32
```

**Step 4: Edit `.env` for production**
```bash
nano .env
```

**Required `.env` settings for production:**
```bash
# Security - REQUIRED
SECRET_KEY=<paste-generated-key-here>
ENVIRONMENT=production

# URLs - Replace YOUR_SERVER_IP with actual IP or domain
VITE_API_URL=http://YOUR_SERVER_IP:8000
CORS_ORIGINS=http://YOUR_SERVER_IP:80,http://YOUR_SERVER_IP:8000

# Optional: AI API keys
OPENAI_API_KEY=sk-your-key-here

# Optional: Logging
LOG_LEVEL=warning
```

**Step 5: Deploy**
```bash
chmod +x deploy.sh
./deploy.sh production
```

**Step 6: Configure firewall**
```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8000/tcp
sudo ufw enable
```

**Step 7: Verify deployment**
```bash
# Check container status
docker-compose ps

# Check logs
./deploy.sh logs

# Test health endpoints
curl http://localhost/health
curl http://localhost:8000/health
```

**Access the application:**
| Service | URL |
|---------|-----|
| Frontend | http://YOUR_SERVER_IP |
| Backend API | http://YOUR_SERVER_IP:8000 |
| API Docs | http://YOUR_SERVER_IP:8000/docs |

---

### A3. Production with SSL/HTTPS (Recommended for Production)

**Step 1: Point your domain to server**
```
DNS A Record: yourdomain.com → YOUR_SERVER_IP
DNS A Record: www.yourdomain.com → YOUR_SERVER_IP
```

**Step 2: Install and generate SSL certificate**
```bash
# Install Certbot
sudo apt install certbot -y

# Stop any running services on port 80
./deploy.sh stop

# Generate certificate
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com
```

**Step 3: Copy certificates**
```bash
sudo mkdir -p nginx/ssl
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ./nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ./nginx/ssl/key.pem
sudo chmod 644 ./nginx/ssl/cert.pem
sudo chmod 600 ./nginx/ssl/key.pem
```

**Step 4: Update `.env` for HTTPS**
```bash
VITE_API_URL=https://yourdomain.com/api
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
DOMAIN=yourdomain.com
```

**Step 5: Uncomment HTTPS in nginx config**
```bash
nano nginx/nginx.conf
# Uncomment the HTTPS server block and update domain name
```

**Step 6: Redeploy**
```bash
./deploy.sh production
```

---

### Docker Management Commands

```bash
# Start services
./deploy.sh dev          # Development mode
./deploy.sh production   # Production mode

# View logs
./deploy.sh logs         # All services
docker-compose logs -f backend   # Backend only
docker-compose logs -f frontend  # Frontend only

# Stop services
./deploy.sh stop

# Restart services
./deploy.sh restart

# Clean everything (WARNING: Deletes all data!)
./deploy.sh clean

# Manual Docker commands
docker-compose up -d --build     # Build and start
docker-compose down              # Stop
docker-compose ps                # Status
docker stats                     # Resource usage
```

---

## Option B: Manual Deployment (Without Docker)

### Prerequisites

| Requirement | Version | Check Command |
|-------------|---------|---------------|
| Python | 3.9+ | `python3 --version` |
| Node.js | 18+ | `node --version` |
| npm | 8+ | `npm --version` |
| Git | Any | `git --version` |

**Install prerequisites (Ubuntu/Debian):**
```bash
# Python 3.9+
sudo apt update
sudo apt install python3 python3-pip python3-venv -y

# Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install nodejs -y

# Git
sudo apt install git -y
```

**Install prerequisites (macOS):**
```bash
# Using Homebrew
brew install python@3.11 node@18 git
```

---

### B1. Local Development (Without Docker)

**Step 1: Clone the repository**
```bash
git clone https://github.com/yashwanthgk88/AppSec-AI.git
cd AppSec-AI
```

**Step 2: Setup Backend**
```bash
cd backend

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate    # Linux/macOS
# OR
.\venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env 2>/dev/null || touch .env
```

**Step 3: Configure backend `.env`**
```bash
nano .env
```

**Backend `.env` settings:**
```bash
SECRET_KEY=your-secret-key-here-generate-with-openssl
DATABASE_URL=sqlite:///./appsec.db
CORS_ORIGINS=http://localhost:5173,http://localhost:3000

# Optional: AI API keys
OPENAI_API_KEY=sk-your-key-here
```

**Step 4: Initialize database**
```bash
# Run all migrations
python migrate_db.py
python init_custom_rules_sqlite.py
python add_rule_id_migration.py
python update_rule_performance.py
```

**Step 5: Start backend server**
```bash
# Option 1: Development server with auto-reload
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Option 2: Simple start
python main.py
```

Backend is now running at: http://localhost:8000

**Step 6: Setup Frontend (new terminal)**
```bash
cd frontend

# Install dependencies
npm install

# Create .env file
echo "VITE_API_URL=http://localhost:8000" > .env

# Start development server
npm run dev
```

Frontend is now running at: http://localhost:5173

**Access the application:**
| Service | URL |
|---------|-----|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |

---

### B2. Production Deployment (Without Docker)

**Step 1: SSH into your server**
```bash
ssh root@your-server-ip
```

**Step 2: Install system dependencies**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python
sudo apt install python3 python3-pip python3-venv -y

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install nodejs -y

# Install Nginx (for reverse proxy)
sudo apt install nginx -y

# Install PM2 (process manager for Node.js)
sudo npm install -g pm2
```

**Step 3: Clone and setup application**
```bash
cd /var/www
sudo git clone https://github.com/yashwanthgk88/AppSec-AI.git
sudo chown -R $USER:$USER AppSec-AI
cd AppSec-AI
```

**Step 4: Setup Backend**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create production .env
nano .env
```

**Backend `.env` for production:**
```bash
SECRET_KEY=<generate-with-openssl-rand-hex-32>
DATABASE_URL=sqlite:///./data/appsec.db
CORS_ORIGINS=http://YOUR_SERVER_IP,https://yourdomain.com
ENVIRONMENT=production
LOG_LEVEL=warning

# Optional: AI API keys
OPENAI_API_KEY=sk-your-key-here
```

**Step 5: Initialize database and start backend**
```bash
# Create data directory
mkdir -p data

# Run migrations
python migrate_db.py
python init_custom_rules_sqlite.py
python add_rule_id_migration.py
python update_rule_performance.py

# Start with Gunicorn (production WSGI server)
pip install gunicorn

# Create systemd service for backend
sudo nano /etc/systemd/system/appsec-backend.service
```

**Backend systemd service file:**
```ini
[Unit]
Description=AppSec Platform Backend
After=network.target

[Service]
User=root
WorkingDirectory=/var/www/AppSec-AI/backend
Environment="PATH=/var/www/AppSec-AI/backend/venv/bin"
ExecStart=/var/www/AppSec-AI/backend/venv/bin/gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
Restart=always

[Install]
WantedBy=multi-user.target
```

**Enable and start backend service:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable appsec-backend
sudo systemctl start appsec-backend
sudo systemctl status appsec-backend
```

**Step 6: Build and setup Frontend**
```bash
cd /var/www/AppSec-AI/frontend

# Create .env for build
echo "VITE_API_URL=http://YOUR_SERVER_IP:8000" > .env

# Install and build
npm install
npm run build

# The built files are in the 'dist' folder
```

**Step 7: Configure Nginx**
```bash
sudo nano /etc/nginx/sites-available/appsec
```

**Nginx configuration:**
```nginx
server {
    listen 80;
    server_name YOUR_SERVER_IP;  # Or yourdomain.com

    # Frontend
    location / {
        root /var/www/AppSec-AI/frontend/dist;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    # Backend API
    location /api {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache_bypass $http_upgrade;
    }

    # Backend direct access (for API docs)
    location /docs {
        proxy_pass http://127.0.0.1:8000/docs;
    }

    location /openapi.json {
        proxy_pass http://127.0.0.1:8000/openapi.json;
    }

    # Health check
    location /health {
        proxy_pass http://127.0.0.1:8000/health;
    }
}
```

**Enable site and restart Nginx:**
```bash
sudo ln -s /etc/nginx/sites-available/appsec /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

**Step 8: Configure firewall**
```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

**Step 9: Verify deployment**
```bash
# Check backend status
sudo systemctl status appsec-backend

# Check Nginx status
sudo systemctl status nginx

# Test endpoints
curl http://localhost/health
curl http://localhost:8000/health
```

**Access the application:**
| Service | URL |
|---------|-----|
| Frontend | http://YOUR_SERVER_IP |
| Backend API | http://YOUR_SERVER_IP:8000 |
| API Docs | http://YOUR_SERVER_IP:8000/docs |

---

### B3. Add SSL/HTTPS (Without Docker)

**Step 1: Install Certbot**
```bash
sudo apt install certbot python3-certbot-nginx -y
```

**Step 2: Get SSL certificate**
```bash
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

**Step 3: Update frontend .env and rebuild**
```bash
cd /var/www/AppSec-AI/frontend
echo "VITE_API_URL=https://yourdomain.com/api" > .env
npm run build
```

**Step 4: Update backend .env**
```bash
cd /var/www/AppSec-AI/backend
nano .env
# Update CORS_ORIGINS to use https://
```

**Step 5: Restart services**
```bash
sudo systemctl restart appsec-backend
sudo systemctl restart nginx
```

---

### Manual Deployment Management Commands

```bash
# Backend management
sudo systemctl start appsec-backend
sudo systemctl stop appsec-backend
sudo systemctl restart appsec-backend
sudo systemctl status appsec-backend
sudo journalctl -u appsec-backend -f   # View logs

# Nginx management
sudo systemctl restart nginx
sudo nginx -t                          # Test config
sudo tail -f /var/log/nginx/error.log  # View logs

# Update application
cd /var/www/AppSec-AI
git pull

# Rebuild frontend
cd frontend && npm run build

# Restart backend
sudo systemctl restart appsec-backend
```

---

## Environment Variables Reference

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `SECRET_KEY` | Application secret key | Yes | `openssl rand -hex 32` |
| `DATABASE_URL` | Database connection URL | No | `sqlite:///./appsec.db` |
| `CORS_ORIGINS` | Allowed CORS origins | Yes | `http://localhost:3000` |
| `VITE_API_URL` | Backend API URL for frontend | Yes | `http://localhost:8000` |
| `OPENAI_API_KEY` | OpenAI API key for AI features | No | `sk-...` |
| `ANTHROPIC_API_KEY` | Anthropic API key | No | `sk-ant-...` |
| `GEMINI_API_KEY` | Google Gemini API key | No | `...` |
| `ENVIRONMENT` | Environment mode | No | `production` |
| `LOG_LEVEL` | Logging level | No | `info`, `warning` |

## 📦 VS Code Extension

### Installation
1. Download the extension:
   - Development: http://localhost:3000/downloads/appsec-ai-scanner-1.5.0.vsix
   - Production: http://your-domain/downloads/appsec-ai-scanner-1.5.0.vsix

2. Install in VS Code:
   ```bash
   code --install-extension appsec-ai-scanner-1.5.0.vsix
   ```

### Features (v1.5.0)
- ✅ Separate SAST Findings view
- ✅ Dedicated SCA Vulnerabilities view
- ✅ Secret Detection view with type grouping
- ✅ Rule Performance Dashboard inline
- ✅ Real-time code scanning
- ✅ Fix suggestions with AI

## 🎯 Usage

1. **Register/Login:** Create an account or use demo credentials
2. **Create Project:** Add a new security project
3. **Upload Code:** Upload repository URL or local files
4. **Run Scans:** Execute SAST, SCA, and Secret scans
5. **Review Findings:** Analyze vulnerabilities with severity ratings
6. **Custom Rules:** Create custom security detection rules
7. **Track Performance:** Monitor rule effectiveness in dashboard
8. **Chat with AI:** Ask security questions in any language
9. **Export Reports:** Download comprehensive reports

## 📊 Rule Performance Tracking

The platform automatically tracks:
- Total detections per custom rule
- True positive vs false positive rates
- Rule precision scores
- Top performing rules
- Rules needing refinement

Access at: Settings → Rule Performance Dashboard

## 🔧 Troubleshooting

### Port Already in Use
```bash
# Change ports in .env
BACKEND_PORT=8001
FRONTEND_PORT=3001
```

### Container Won't Start
```bash
# Check logs
./deploy.sh logs

# Rebuild from scratch
docker-compose down -v
docker-compose up -d --build
```

### Database Issues
```bash
# Backup database
docker cp appsec-backend:/app/data/appsec.db ./backup-appsec.db

# Reset database
docker-compose down -v
docker-compose up -d
```

### Permission Issues
```bash
chmod +x deploy.sh
sudo chown -R $USER:$USER .
```

## 📚 Documentation

- [Docker Quick Start Guide](DOCKER-QUICKSTART.md)
- [Deployment Guide](DEPLOYMENT.md)
- API Documentation: http://localhost:8000/docs

## 🏗️ Architecture

```
appsec-platform/
├── backend/               # FastAPI backend
│   ├── services/         # Security scanning services
│   ├── models/           # Database models
│   ├── routers/          # API endpoints
│   ├── core/             # Core business logic
│   └── Dockerfile        # Backend container
├── frontend/             # React frontend
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── pages/        # Page components
│   │   └── services/     # API clients
│   ├── nginx.conf        # Frontend nginx config
│   └── Dockerfile        # Frontend container
├── vscode-extension/     # VS Code extension v1.5.0
├── nginx/                # Production reverse proxy
│   └── nginx.conf        # Production nginx config
├── docker-compose.yml    # Multi-container orchestration
└── deploy.sh             # Deployment automation script
```

## 🔒 Security Features

- **68 OWASP Security Rules** covering top vulnerabilities
- **Custom Rule Engine** for organization-specific patterns
- **Real-time Performance Tracking** of detection rules
- **Secret Detection** with pattern matching
- **SCA Analysis** for vulnerable dependencies
- **STRIDE Threat Modeling** methodology
- **MITRE ATT&CK** framework mapping
- **CWE Classification** for vulnerabilities

## 🤖 AI Capabilities

- Multi-provider support (Anthropic Claude, OpenAI, Google Gemini, Ollama)
- Auto-language detection (90+ languages)
- Context-aware security recommendations
- Vulnerability remediation suggestions
- Natural language threat modeling

## 📊 Reporting

Export options:
- Excel (.xlsx) - Detailed vulnerability reports
- PDF - Executive summaries
- XML - OWASP format for tool integration

## 🔗 API Documentation

Interactive API documentation:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 📝 Sample Credentials

For POC/Demo:
- Username: `admin@example.com`
- Password: `admin123`

## 🤝 Contributing

This is a POC demonstration project. For production use, ensure:
- Change default credentials
- Use strong SECRET_KEY
- Enable SSL/TLS
- Configure firewall
- Regular security updates
- Proper backup strategy

## 📄 License

MIT License - This is a POC demonstration project

## 🔗 Repository

GitHub: https://github.com/yashwanthgk88/AppSec-AI

## 📧 Support

For issues and questions:
- GitHub Issues: https://github.com/yashwanthgk88/AppSec-AI/issues
- Documentation: See DEPLOYMENT.md for detailed guides

---

**Built with Claude Code** 🤖
