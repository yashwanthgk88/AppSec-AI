# Production Deployment Guide

## Quick Setup - Only 3 Files to Configure!

### 1. Frontend - Create `.env.production`
```bash
cd frontend
cp .env.production.example .env.production
```

Edit `frontend/.env.production`:
```env
VITE_API_URL=https://your-production-server.com
```

### 2. Backend - Update `.env`
Edit `backend/.env`:
```env
# Update CORS to allow your frontend domain
CORS_ORIGINS=https://your-frontend-domain.com

# Your AI API keys (already configured via Settings page)
# These are stored in database, no changes needed here
```

### 3. VS Code Extension - Configure in Settings
Users configure the extension via VS Code settings:
- Open VS Code Settings (Ctrl+,)
- Search for "SecureDev"
- Set `appsec.apiUrl` to your production URL

Or use the command: `SecureDev AI: Configure Server URL`

---

## Files Changed for Centralized Configuration

| Component | Configuration Method |
|-----------|---------------------|
| Frontend | `VITE_API_URL` environment variable |
| Backend | `CORS_ORIGINS` in `.env` file |
| VS Code Extension | User setting `appsec.apiUrl` |

---

## Example Production URLs

```
# Frontend (Railway/Vercel/Netlify)
https://securedev-ai.railway.app

# Backend API
https://securedev-api.railway.app

# VS Code Extension setting
appsec.apiUrl = https://securedev-api.railway.app
```

---

## Build for Production

### Frontend
```bash
cd frontend
npm run build
# Output in dist/ folder
```

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

---

## No More Hardcoded URLs!

All localhost:8000 references have been replaced with:
- Environment variables for frontend
- User settings for VS Code extension
- Database settings for AI providers
