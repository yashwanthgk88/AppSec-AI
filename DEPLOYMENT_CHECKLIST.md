# 🚀 Deployment Checklist - AppSec AI Platform

This checklist will guide you through deploying your AppSec AI platform to the internet.

---

## ✅ Pre-Deployment Checklist

### 1. Code Repository
- [x] Code committed to GitHub: `https://github.com/yashwanthgk88/AppSec-AI`
- [x] All changes pushed to main branch
- [x] Repository is accessible

### 2. Required API Keys
- [ ] Anthropic API Key (`sk-ant-...`)
- [ ] OpenAI API Key (`sk-...`)
- [ ] Both keys are tested and working

### 3. Deployment Files Ready
- [x] `DEPLOYMENT_GUIDE.md` - Comprehensive deployment guide
- [x] `RAILWAY_DEPLOY.md` - Quick Railway deployment guide
- [x] `backend/Dockerfile` - Backend container configuration
- [x] `frontend/Dockerfile` - Frontend container configuration
- [x] `docker-compose.yml` - Full stack orchestration
- [x] `.env.example` - Environment variable template
- [x] `.dockerignore` - Docker ignore patterns
- [x] `railway.json` - Railway configuration

---

## 🎯 Recommended Deployment Path: Railway

**Estimated Time: 15 minutes**
**Cost: ~$10-15/month**
**Difficulty: Easy**

### Step-by-Step Railway Deployment

#### Step 1: Sign Up for Railway (2 minutes)
- [ ] Go to [railway.app](https://railway.app)
- [ ] Click "Login with GitHub"
- [ ] Authorize Railway to access your repositories
- [ ] Get $5 free credit to start

#### Step 2: Add PostgreSQL Database (2 minutes)
- [ ] Click "New Project" in Railway
- [ ] Select "Provision PostgreSQL"
- [ ] Wait for database to provision (30 seconds)
- [ ] Click on database → Variables tab
- [ ] Copy the `DATABASE_URL` value (starts with `postgresql://`)
- [ ] Save this URL - you'll need it for backend

#### Step 3: Deploy Backend Service (5 minutes)
- [ ] In Railway project, click "New" → "GitHub Repo"
- [ ] Select `AppSec-AI` repository
- [ ] Railway will detect the project

**Configure Backend Settings:**
- [ ] Go to Settings tab → Root Directory
- [ ] Set root directory to: `backend`
- [ ] Go to Settings tab → Start Command
- [ ] Set to: `python3 migrate_db.py && uvicorn main:app --host 0.0.0.0 --port $PORT`

**Add Backend Environment Variables:**
- [ ] Go to Variables tab
- [ ] Click "Raw Editor"
- [ ] Paste the following (replace with your actual values):

```env
DATABASE_URL=postgresql://postgres:password@hostname:5432/railway
SECRET_KEY=your-secret-key-min-32-characters-use-python-secrets
ANTHROPIC_API_KEY=sk-ant-your-anthropic-key-here
OPENAI_API_KEY=sk-your-openai-key-here
PYTHONUNBUFFERED=1
PORT=8000
```

**Generate SECRET_KEY:**
```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

- [ ] Click "Deploy" and wait for deployment to complete
- [ ] Check logs to ensure no errors

**Generate Backend Domain:**
- [ ] Go to Settings → Networking
- [ ] Click "Generate Domain"
- [ ] Copy the generated URL (e.g., `https://appsec-backend-production.up.railway.app`)
- [ ] **SAVE THIS URL** - you'll need it for frontend and VS Code extension

#### Step 4: Deploy Frontend Service (4 minutes)
- [ ] In Railway project, click "New" → "GitHub Repo"
- [ ] Select `AppSec-AI` repository again
- [ ] Railway will create a new service

**Configure Frontend Settings:**
- [ ] Go to Settings tab → Root Directory
- [ ] Set root directory to: `frontend`
- [ ] Go to Settings tab → Build Command
- [ ] Set to: `npm run build`
- [ ] Go to Settings tab → Start Command
- [ ] Set to: `npm run preview -- --host 0.0.0.0 --port $PORT`

**Add Frontend Environment Variables:**
- [ ] Go to Variables tab
- [ ] Add variable: `VITE_API_URL`
- [ ] Set value to your backend URL from Step 3 (e.g., `https://appsec-backend-production.up.railway.app`)

- [ ] Click "Deploy" and wait for deployment to complete

**Generate Frontend Domain:**
- [ ] Go to Settings → Networking
- [ ] Click "Generate Domain"
- [ ] Copy the generated URL (e.g., `https://appsec-frontend-production.up.railway.app`)
- [ ] **SAVE THIS URL** - this is your main application URL

#### Step 5: Update Backend CORS Settings (2 minutes)
- [ ] Go back to backend service
- [ ] Go to Variables tab
- [ ] Add new variable: `CORS_ORIGINS`
- [ ] Set value to your frontend URL (e.g., `https://appsec-frontend-production.up.railway.app`)
- [ ] Backend will automatically redeploy

#### Step 6: Test Your Deployment (5 minutes)
- [ ] Visit your frontend URL in browser
- [ ] You should see the AppSec AI login page
- [ ] Login with default credentials:
  - Username: `admin`
  - Password: `admin123`
- [ ] Navigate to Dashboard - should load without errors
- [ ] Go to Settings page
- [ ] Download VS Code extension (.vsix file)
- [ ] Check that API documentation is accessible at `your-backend-url/docs`

---

## 🔧 Post-Deployment Configuration

### 1. Update VS Code Extension Configuration
- [ ] Open VS Code
- [ ] Go to Settings (Cmd+, or Ctrl+,)
- [ ] Search for "AppSec"
- [ ] Update `appsec.apiUrl` to your Railway backend URL
- [ ] Reload VS Code
- [ ] Test extension login with `admin` / `admin123`
- [ ] Try scanning a file to verify it works

### 2. Change Default Admin Password
- [ ] Login to web application
- [ ] Go to Settings → Account
- [ ] Change password from `admin123` to something secure
- [ ] Save and re-login to verify

### 3. Create Additional Users (Optional)
- [ ] Go to Settings → Users
- [ ] Click "Add User"
- [ ] Create accounts for your team members
- [ ] Assign appropriate roles

### 4. Configure AI Providers (Optional)
- [ ] Go to Settings → AI Providers
- [ ] Update Anthropic/OpenAI settings if needed
- [ ] Test chatbot functionality

---

## 🎨 Optional: Custom Domain Setup

### Railway Custom Domain (Recommended)
- [ ] Purchase domain from registrar (GoDaddy, Namecheap, etc.)
- [ ] In Railway frontend service → Settings → Networking
- [ ] Click "Custom Domain"
- [ ] Enter your domain (e.g., `appsec.yourdomain.com`)
- [ ] Railway will provide DNS records (CNAME or A record)
- [ ] Go to your domain registrar
- [ ] Add the DNS records provided by Railway
- [ ] Wait 5-30 minutes for DNS propagation
- [ ] Update backend's `CORS_ORIGINS` to include your custom domain
- [ ] Test accessing your app via custom domain

---

## 📊 Monitoring & Maintenance

### View Application Logs
- [ ] In Railway, click on any service
- [ ] Go to "Deployments" tab
- [ ] Click on latest deployment
- [ ] View real-time logs
- [ ] Check for any errors

### Health Checks
- [ ] Backend health: `https://your-backend-url.railway.app/docs`
- [ ] Frontend health: `https://your-frontend-url.railway.app`
- [ ] Database: Check Railway dashboard for DB metrics

### Database Backups
- [ ] Railway automatically backs up PostgreSQL databases
- [ ] To manually export: Database → Data → Export
- [ ] Store backups securely

---

## 🐛 Troubleshooting Guide

### Issue: Build Failed
**Symptoms:** Deployment shows "Build Failed" status

**Solutions:**
- [ ] Check build logs in Railway
- [ ] Verify `requirements.txt` (backend) or `package.json` (frontend) has all dependencies
- [ ] Check for syntax errors in code
- [ ] Verify root directory setting is correct

### Issue: 502 Bad Gateway
**Symptoms:** Frontend loads but shows 502 error

**Solutions:**
- [ ] Check backend logs for errors
- [ ] Verify `DATABASE_URL` is set correctly
- [ ] Ensure database migrations ran successfully
- [ ] Check backend service is running (not crashed)

### Issue: CORS Error
**Symptoms:** Browser console shows "CORS policy" error

**Solutions:**
- [ ] Add frontend URL to backend's `CORS_ORIGINS` variable
- [ ] Make sure URL includes `https://` and no trailing slash
- [ ] Redeploy backend after changing CORS settings

### Issue: Database Connection Error
**Symptoms:** Backend logs show "connection refused" or database errors

**Solutions:**
- [ ] Verify `DATABASE_URL` in backend variables
- [ ] Check database is running in Railway dashboard
- [ ] Ensure DATABASE_URL format is correct: `postgresql://user:pass@host:5432/dbname`

### Issue: VS Code Extension Can't Connect
**Symptoms:** Extension shows "Failed to connect" or 401 errors

**Solutions:**
- [ ] Verify extension settings use Railway backend URL (not localhost)
- [ ] Check API URL doesn't have trailing slash
- [ ] Test login with correct credentials
- [ ] Check backend logs for authentication errors

### Issue: Chat/AI Features Not Working
**Symptoms:** Chatbot returns errors or doesn't respond

**Solutions:**
- [ ] Verify `ANTHROPIC_API_KEY` is set correctly
- [ ] Check API key has sufficient credits
- [ ] Test API key using curl or Postman
- [ ] Check backend logs for AI service errors

---

## 💰 Cost Estimation

### Railway Pricing
- **Free Tier:** $5 credit/month (lasts ~5-10 days for this app)
- **Hobby Plan:** $5/month base + usage
  - PostgreSQL: ~$5-7/month
  - Backend: ~$3-5/month
  - Frontend: ~$2-3/month
- **Total:** ~$10-15/month for production use

**Pro Tip:** Use the $5 free credit for testing, then upgrade to Hobby plan for production.

---

## 📝 Deployment Summary

Once you complete this checklist, you will have:

- ✅ AppSec AI platform running publicly on the internet
- ✅ Automatic HTTPS with Railway-provided SSL
- ✅ PostgreSQL database with automatic backups
- ✅ Frontend accessible at your Railway domain
- ✅ Backend API accessible at your Railway backend domain
- ✅ VS Code extension connected to your public deployment
- ✅ AI-powered security scanning available to your team

---

## 🆘 Need Help?

### Documentation
- [Railway Documentation](https://docs.railway.app)
- [Railway Discord](https://discord.gg/railway)
- [Railway Community](https://community.railway.app)

### Alternative Deployment Options
If Railway doesn't work for you, check out:
- `DEPLOYMENT_GUIDE.md` for AWS EC2, DigitalOcean, and Vercel options
- Docker deployment using `docker-compose.yml`

### Quick Reference Commands

```bash
# Generate SECRET_KEY
python3 -c 'import secrets; print(secrets.token_hex(32))'

# Test backend locally
cd backend && uvicorn main:app --reload

# Test frontend locally
cd frontend && npm run dev

# Test Docker deployment locally
docker-compose up --build

# View Railway logs (requires Railway CLI)
npm install -g @railway/cli
railway login
railway logs
```

---

## ✨ You're Ready to Deploy!

Follow the steps above and your AppSec AI platform will be live on the internet in approximately **15 minutes**.

**Next Step:** Start with [Step 1: Sign Up for Railway](#step-1-sign-up-for-railway-2-minutes)

**Default Credentials (change after first login):**
- Username: `admin`
- Password: `admin123`

---

**Questions?** Open an issue at: https://github.com/yashwanthgk88/AppSec-AI/issues
