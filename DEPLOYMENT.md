# SecureDev AI - Production Deployment Guide

Complete step-by-step guide to deploy SecureDev AI Platform to production.

---

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Backend Deployment](#backend-deployment)
4. [Frontend Deployment](#frontend-deployment)
5. [VS Code Extension Configuration](#vs-code-extension-configuration)
6. [Environment Variables Reference](#environment-variables-reference)
7. [Platform-Specific Guides](#platform-specific-guides)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software
- Python 3.10+
- Node.js 18+
- npm or yarn
- Git

### Required Accounts (choose based on deployment platform)
- Railway, Render, Heroku, AWS, or VPS hosting
- Domain name (optional but recommended)

### API Keys (configured via Settings page after deployment)
- Anthropic API Key OR OpenAI API Key (for AI features)
- GitHub Token (for repository scanning)
- Snyk Token (optional, for enhanced SCA)

---

## Quick Start

### Step 1: Clone the Repository
\`\`\`bash
git clone https://github.com/yashwanthgk88/AppSec-AI.git
cd AppSec-AI
\`\`\`

### Step 2: Backend Setup
\`\`\`bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env

# Edit .env with your settings
nano .env
\`\`\`

### Step 3: Frontend Setup
\`\`\`bash
cd ../frontend

# Install dependencies
npm install

# Create production environment file
echo "VITE_API_URL=https://your-backend-api.com" > .env.production
\`\`\`

### Step 4: Build & Deploy
\`\`\`bash
# Build frontend
npm run build

# Start backend
cd ../backend
uvicorn main:app --host 0.0.0.0 --port 8000
\`\`\`

---

## Backend Deployment

### Step 1: Configure Environment Variables

Create or edit \`backend/.env\`:

\`\`\`env
# ===========================================
# REQUIRED SETTINGS
# ===========================================

# Secret key for JWT tokens (generate a secure random string)
SECRET_KEY=your-super-secret-key-change-this-in-production

# CORS - Allow your frontend domain
CORS_ORIGINS=https://your-frontend-domain.com

# ===========================================
# OPTIONAL SETTINGS
# ===========================================

# AI Provider settings are configured via Settings page in the UI
# No need to set OPENAI_API_KEY or ANTHROPIC_API_KEY here

# Database (SQLite by default, or PostgreSQL for production)
# DATABASE_URL=postgresql://user:password@host:5432/dbname
\`\`\`

### Step 2: Initialize Database

\`\`\`bash
cd backend
source venv/bin/activate

# Database is auto-created on first run
python -c "from models.database import engine, Base; Base.metadata.create_all(bind=engine)"
\`\`\`

### Step 3: Create Admin User

\`\`\`bash
python -c "
from models.database import SessionLocal
from models import User
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
db = SessionLocal()

admin = User(
    email='admin@example.com',
    hashed_password=pwd_context.hash('your-secure-password'),
    full_name='Admin User',
    is_active=True
)
db.add(admin)
db.commit()
print('Admin user created!')
db.close()
"
\`\`\`

### Step 4: Start Backend Server

**Development:**
\`\`\`bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
\`\`\`

**Production (with Gunicorn):**
\`\`\`bash
pip install gunicorn
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
\`\`\`

---

## Frontend Deployment

### Step 1: Configure API URL

Create \`frontend/.env.production\`:

\`\`\`env
# Backend API URL - REQUIRED
VITE_API_URL=https://your-backend-api.com
\`\`\`

### Step 2: Build for Production

\`\`\`bash
cd frontend
npm install
npm run build
\`\`\`

This creates a \`dist/\` folder with static files.

### Step 3: Deploy Static Files

**Option A: Nginx**
\`\`\`nginx
server {
    listen 80;
    server_name your-frontend-domain.com;
    root /path/to/AppSec-AI/frontend/dist;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
    }
}
\`\`\`

**Option B: Vercel/Netlify**
- Connect GitHub repository
- Build command: \`npm run build\`
- Output directory: \`dist\`
- Environment variable: \`VITE_API_URL=https://your-backend-api.com\`

---

## VS Code Extension Configuration

### For End Users

1. **Install Extension:**
   - Download \`appsec-ai-scanner-1.8.5.vsix\` from the web app
   - VS Code: Extensions → ... → Install from VSIX

2. **Configure Server URL:**
   - Open Command Palette (Ctrl+Shift+P)
   - Run: \`SecureDev AI: Configure Server URL\`
   - Enter your production API URL

3. **Or set manually in settings.json:**
   \`\`\`json
   {
     "appsec.apiUrl": "https://your-backend-api.com"
   }
   \`\`\`

4. **Login:**
   - Command Palette → \`SecureDev AI: Login\`
   - Enter credentials

---

## Environment Variables Reference

### Backend (\`backend/.env\`)

| Variable | Required | Description |
|----------|----------|-------------|
| \`SECRET_KEY\` | Yes | JWT secret key |
| \`CORS_ORIGINS\` | Yes | Allowed frontend origins |
| \`DATABASE_URL\` | No | PostgreSQL connection string |

### Frontend (\`frontend/.env.production\`)

| Variable | Required | Description |
|----------|----------|-------------|
| \`VITE_API_URL\` | Yes | Backend API URL |

### VS Code Extension

| Setting | Description |
|---------|-------------|
| \`appsec.apiUrl\` | Backend API URL |

---

## Platform-Specific Guides

### Railway Deployment

**Backend:**
1. Create new project on Railway
2. Connect GitHub repository
3. Set root directory: \`backend\`
4. Add environment variables:
   - \`SECRET_KEY=your-secret-key\`
   - \`CORS_ORIGINS=https://your-frontend.railway.app\`

**Frontend:**
1. Create another service
2. Set root directory: \`frontend\`
3. Build command: \`npm run build\`
4. Start command: \`npx serve -s dist\`
5. Add: \`VITE_API_URL=https://your-backend.railway.app\`

### Docker Deployment

\`\`\`yaml
# docker-compose.yml
version: '3.8'

services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - SECRET_KEY=\${SECRET_KEY}
      - CORS_ORIGINS=\${CORS_ORIGINS}

  frontend:
    build: ./frontend
    ports:
      - "80:80"
    environment:
      - VITE_API_URL=http://backend:8000
\`\`\`

---

## Troubleshooting

### CORS Errors
Ensure \`CORS_ORIGINS\` includes your frontend URL:
\`\`\`env
CORS_ORIGINS=https://your-frontend.com,http://localhost:5173
\`\`\`

### API Connection Failed
1. Check \`appsec.apiUrl\` in VS Code settings
2. Test: \`curl https://your-api.com/health\`

### AI Features Not Working
Configure AI provider in Settings page:
1. Settings → AI Provider
2. Select Anthropic or OpenAI
3. Enter API key
4. Save

---

## Security Checklist

- [ ] Changed default \`SECRET_KEY\`
- [ ] HTTPS enabled
- [ ] \`CORS_ORIGINS\` restricted to your domains
- [ ] Strong admin password
- [ ] Database backups configured

---

*Last updated: February 2026*
