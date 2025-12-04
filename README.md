# AI-Enabled Application Security Platform

A comprehensive application security platform featuring threat modeling, vulnerability scanning, custom security rules, rule performance tracking, multilingual AI chatbot, and detailed reporting.

## 🌟 Features

### Core Capabilities
- **Threat Modeling:** Auto-generate DFD diagrams with STRIDE and MITRE ATT&CK mapping
- **SAST Scanning:** Static code analysis with 68 OWASP security rules + custom rules
- **SCA Analysis:** Software Composition Analysis for vulnerable dependencies
- **Secret Detection:** Scan for hardcoded credentials and sensitive data
- **Custom Security Rules:** Create and manage your own detection rules
- **Rule Performance Dashboard:** Track detection rates and rule effectiveness
- **Multilingual AI Chatbot:** Security assistance in 90+ languages with auto-detection
- **Report Export:** Generate Excel, PDF, and XML reports
- **VS Code Extension:** Real-time security feedback in your IDE (v1.4.0)
- **Live Log Correlation:** Real-time threat detection and alerts

## 🚀 Quick Start with Docker (Recommended)

### Prerequisites
- Docker (20.10+)
- Docker Compose (2.0+)
- 4GB+ RAM available

### 3-Step Deployment

#### Step 1: Clone Repository
```bash
git clone https://github.com/yashwanthgk88/AppSec-AI.git
cd AppSec-AI
```

#### Step 2: Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Generate a secure secret key
openssl rand -hex 32

# Edit .env file and add the generated key
nano .env  # or use your preferred editor
```

**Minimum required changes in `.env`:**
```bash
SECRET_KEY=<paste-your-generated-key-here>
VITE_API_URL=http://localhost:8000
CORS_ORIGINS=http://localhost:3000,http://localhost:8000
```

#### Step 3: Deploy
```bash
# Make deploy script executable
chmod +x deploy.sh

# Deploy in development mode
./deploy.sh dev

# OR deploy in production mode with Nginx
./deploy.sh production
```

### Access the Application

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

## 🐳 Docker Deployment Options

### Local Development
```bash
./deploy.sh dev
```
- Hot reload disabled (rebuild to see changes)
- Direct access to backend and frontend
- Suitable for testing

### Production Deployment
```bash
./deploy.sh production
```
- Nginx reverse proxy with caching
- Rate limiting and security headers
- Gzip compression
- SSL/TLS support ready
- Optimized for production use

### Common Commands
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

## 🌍 Production Deployment to Cloud/VPS

### Deploy to DigitalOcean, AWS, Google Cloud, or Azure

#### 1. Prepare Your Server
```bash
# SSH into your server
ssh root@your-server-ip

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

#### 2. Clone and Configure
```bash
# Clone repository
git clone https://github.com/yashwanthgk88/AppSec-AI.git
cd AppSec-AI

# Configure environment
cp .env.example .env
nano .env
```

**Update `.env` for production:**
```bash
SECRET_KEY=<generate-with-openssl-rand-hex-32>
VITE_API_URL=http://your-server-ip:8000  # or https://api.yourdomain.com
CORS_ORIGINS=http://your-server-ip:3000,http://your-server-ip:8000
ENVIRONMENT=production
```

#### 3. Deploy
```bash
chmod +x deploy.sh
./deploy.sh production
```

#### 4. Configure Firewall
```bash
# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8000/tcp  # Backend API
sudo ufw enable
```

### SSL/TLS Setup (Optional but Recommended)

#### Using Let's Encrypt
```bash
# Install Certbot
sudo apt install certbot

# Generate SSL certificate
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Copy certificates
sudo mkdir -p nginx/ssl
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ./nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ./nginx/ssl/key.pem
sudo chmod 644 ./nginx/ssl/cert.pem
sudo chmod 600 ./nginx/ssl/key.pem
```

**Update `.env`:**
```bash
VITE_API_URL=https://api.yourdomain.com
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
DOMAIN=yourdomain.com
```

**Update `nginx/nginx.conf`:** Uncomment the HTTPS section and update domain.

```bash
# Redeploy
./deploy.sh production
```

## 💻 Manual Setup (Without Docker)

### Prerequisites
- Python 3.9+
- Node.js 18+
- npm or yarn

### Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run migrations
python migrate_db.py
python init_custom_rules_sqlite.py
python add_rule_id_migration.py
python update_rule_performance.py

# Start server
python main.py
```

Backend runs on http://localhost:8000

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

Frontend runs on http://localhost:5173

### Environment Variables

Create `.env` file in backend directory:
```bash
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///./appsec.db
ANTHROPIC_API_KEY=your_api_key_here  # Optional
OPENAI_API_KEY=your_api_key_here     # Optional
GEMINI_API_KEY=your_api_key_here     # Optional
CORS_ORIGINS=http://localhost:5173,http://localhost:5174
```

## 📦 VS Code Extension

### Installation
1. Download the extension:
   - Development: http://localhost:3000/downloads/appsec-ai-scanner-1.4.0.vsix
   - Production: http://your-domain/downloads/appsec-ai-scanner-1.4.0.vsix

2. Install in VS Code:
   ```bash
   code --install-extension appsec-ai-scanner-1.4.0.vsix
   ```

### Features (v1.4.0)
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
├── vscode-extension/     # VS Code extension v1.4.0
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
