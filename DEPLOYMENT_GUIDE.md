# 🚀 Production Deployment Configuration Guide

## Critical Changes Needed for Production

### 📋 Quick Summary of Changes

| Component | File | What to Change | Example |
|-----------|------|----------------|---------|
| **Backend** | `.env` | SECRET_KEY, CORS_ORIGINS, DATABASE_URL | See below |
| **Frontend** | Hardcoded URLs | Replace `http://localhost:8000` with env variable | All API calls |
| **VS Code** | `package.json` | Default apiUrl configuration | `https://api.your-domain.com` |

---

## 1️⃣ Backend Changes

### File: `backend/.env`

```bash
# ⚠️ CHANGE THESE VALUES:

# 1. Generate a NEW secret key (CRITICAL!)
SECRET_KEY=REPLACE_WITH_GENERATED_KEY_AT_LEAST_32_CHARS

# 2. Update CORS to your production domain
CORS_ORIGINS=https://your-production-domain.com

# 3. Keep your OpenAI key (or use a new production key)
OPENAI_API_KEY=sk-proj-your-key-here

# 4. Recommended: Switch to PostgreSQL for production
DATABASE_URL=postgresql://user:password@host:5432/dbname
# OR keep SQLite with absolute path:
# DATABASE_URL=sqlite:////var/app/data/appsec.db

# 5. Set environment
ENVIRONMENT=production
DEBUG=false
```

**Generate Secret Key:**
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## 2️⃣ Frontend Changes

### File Changes Needed in ALL API Call Files:

Currently, your frontend has hardcoded `http://localhost:8000` in multiple files. You need to:

#### Step 1: Create API Config File

Create `frontend/src/config/api.ts`:
```typescript
export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
```

#### Step 2: Create `frontend/.env.production`:
```env
VITE_API_URL=https://api.your-domain.com
```

#### Step 3: Update These Files:

**Files to modify (search for `localhost:8000`):**
- `src/pages/LoginPage.tsx`
- `src/pages/DashboardPage.tsx` 
- `src/pages/ProjectsPage.tsx`
- `src/pages/ProjectDetailPage.tsx`
- `src/pages/ChatPage.tsx`
- `src/pages/SettingsPage.tsx`
- `src/pages/CustomRulesPage.tsx`
- `src/pages/RulePerformancePage.tsx`

**Change from:**
```typescript
await axios.post('http://localhost:8000/api/auth/login', ...)
await axios.get('http://localhost:8000/api/projects', ...)
```

**Change to:**
```typescript
import { API_BASE_URL } from '../config/api';

await axios.post(`${API_BASE_URL}/api/auth/login`, ...)
await axios.get(`${API_BASE_URL}/api/projects`, ...)
```

#### Step 4: Build for Production
```bash
cd frontend
npm run build
# Output will be in frontend/dist/
```

---

## 3️⃣ VS Code Extension Changes

### File: `vscode-extension/package.json`

**Line 220-224, change:**
```json
"appsec.apiUrl": {
  "type": "string",
  "default": "https://api.your-domain.com",  // ⚠️ CHANGE THIS
  "description": "AppSec Platform API URL"
}
```

### File: `vscode-extension/src/apiClient.ts`

**Find the baseURL initialization and ensure it reads from config:**
```typescript
private baseURL: string;

constructor() {
  this.baseURL = vscode.workspace.getConfiguration('appsec').get('apiUrl') || 'https://api.your-domain.com';
}
```

### Build Extension:
```bash
cd vscode-extension
npm install
npm run compile
npx vsce package
# Creates: appsec-ai-scanner-1.2.0.vsix
```

---

## 4️⃣ Database Setup (Production)

### Option A: PostgreSQL (Recommended)

```bash
# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# Create database
sudo -u postgres psql
CREATE DATABASE appsec_prod;
CREATE USER appsec_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE appsec_prod TO appsec_user;
\q

# Update .env
DATABASE_URL=postgresql://appsec_user:your_secure_password@localhost:5432/appsec_prod

# Install Python driver
pip install psycopg2-binary
```

### Option B: SQLite (For Smaller Deployments)

```bash
# Create data directory
mkdir -p /var/app/data

# Update .env
DATABASE_URL=sqlite:////var/app/data/appsec.db
```

---

## 5️⃣ Deployment Commands

### Backend Production Server:

```bash
# Install production server
pip install gunicorn

# Run backend
cd backend
gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### Frontend Production Build:

```bash
cd frontend
npm run build

# Serve with nginx, apache, or any static file server
# Files are in: frontend/dist/
```

---

## 6️⃣ Complete File Checklist

### ✅ Files You MUST Change:

1. **`backend/.env`**
   - [ ] SECRET_KEY (generate new)
   - [ ] CORS_ORIGINS (your domain)
   - [ ] DATABASE_URL (PostgreSQL recommended)

2. **`frontend/src/config/api.ts`** (CREATE NEW)
   - [ ] Export API_BASE_URL

3. **`frontend/.env.production`** (CREATE NEW)
   - [ ] VITE_API_URL=https://api.your-domain.com

4. **Frontend API calls** (8 files)
   - [ ] LoginPage.tsx
   - [ ] DashboardPage.tsx
   - [ ] ProjectsPage.tsx
   - [ ] ProjectDetailPage.tsx
   - [ ] ChatPage.tsx
   - [ ] SettingsPage.tsx
   - [ ] CustomRulesPage.tsx
   - [ ] RulePerformancePage.tsx

5. **`vscode-extension/package.json`**
   - [ ] Line 222: default apiUrl

6. **`vscode-extension/src/apiClient.ts`**
   - [ ] Ensure baseURL reads from config

---

## 7️⃣ Security Checklist

Before going live:

- [ ] Generate new SECRET_KEY (32+ characters)
- [ ] Update CORS_ORIGINS to production domain only
- [ ] Never commit .env file (check .gitignore)
- [ ] Use HTTPS (Let's Encrypt certificate)
- [ ] Set up firewall rules (only ports 80, 443)
- [ ] Enable database backups
- [ ] Set up monitoring/logging
- [ ] Test all endpoints after deployment

---

## 8️⃣ Quick Commands Reference

### Generate Secret Key:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Build Everything:
```bash
# Backend - no build needed, just ensure dependencies installed
cd backend && pip install -r requirements.txt

# Frontend
cd frontend && npm install && npm run build

# VS Code Extension
cd vscode-extension && npm install && npm run compile && npx vsce package
```

### Test Production Setup Locally:
```bash
# Backend with production env
cd backend
export $(cat .env.production | xargs) && gunicorn main:app --workers 2 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000

# Frontend (serve build)
cd frontend
npm install -g serve
serve -s dist -p 3000
```

---

## 🆘 Common Issues

### Issue: "CORS Error" after deployment
**Fix:** Ensure CORS_ORIGINS in backend/.env exactly matches your frontend domain (including https://)

### Issue: Extension can't connect
**Fix:** Check VS Code settings → Extensions → AppSec AI Scanner → API URL

### Issue: Database errors
**Fix:** Verify DATABASE_URL format and database server is accessible

---

## 📞 Support

If you encounter issues:
1. Check all environment variables are set correctly
2. Verify HTTPS is enabled
3. Check firewall/security group settings
4. Review application logs for specific errors
