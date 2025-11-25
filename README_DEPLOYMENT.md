# 🌐 Deploying AppSec AI Platform to the Internet

Welcome! This guide will help you deploy your AppSec AI platform to be publicly accessible on the internet.

## 📚 Deployment Documentation

We've created comprehensive guides to help you deploy:

### 1. **DEPLOYMENT_CHECKLIST.md** ⭐ START HERE
   - Step-by-step checklist for Railway deployment (recommended)
   - Interactive checklist format
   - Estimated completion time: 15 minutes
   - Includes troubleshooting guide
   - **Best for:** Following a guided deployment process

### 2. **RAILWAY_DEPLOY.md**
   - Detailed Railway-specific quick start guide
   - Environment variable reference tables
   - Custom domain setup instructions
   - Cost estimation
   - **Best for:** Quick Railway deployment with detailed explanations

### 3. **DEPLOYMENT_GUIDE.md**
   - Comprehensive guide covering all deployment options
   - Railway, Vercel, AWS EC2, DigitalOcean
   - Comparison table to help you choose
   - Docker deployment instructions
   - Security hardening steps
   - **Best for:** Exploring different deployment options

## 🚀 Quick Start - Deploy in 15 Minutes

### Option A: Railway (Recommended - Easiest)

Railway provides automatic HTTPS, built-in PostgreSQL, and zero configuration deployment.

**Cost:** ~$10-15/month | **Free Credit:** $5 to start

1. **Read the checklist:**
   ```bash
   cat DEPLOYMENT_CHECKLIST.md
   ```

2. **Follow these steps:**
   - Sign up at [railway.app](https://railway.app)
   - Deploy PostgreSQL database
   - Deploy backend from GitHub
   - Deploy frontend from GitHub
   - Configure environment variables
   - Generate domains
   - Access your app!

3. **For detailed instructions:** See [RAILWAY_DEPLOY.md](RAILWAY_DEPLOY.md)

### Option B: Test Locally First with Docker

Before deploying to production, test the full stack locally:

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Edit .env and add your API keys
nano .env

# 3. Run the local deployment test script
./deploy-local-test.sh
```

The script will:
- Check prerequisites (Docker, Docker Compose)
- Build and start all services (PostgreSQL, Backend, Frontend)
- Run health checks
- Open the app in your browser
- Display access URLs and credentials

Once local testing succeeds, you're ready for production deployment!

## 📋 Prerequisites

Before deploying, make sure you have:

- [x] GitHub account (for Railway deployment)
- [x] Anthropic API Key (`sk-ant-...`) - Get from [console.anthropic.com](https://console.anthropic.com)
- [x] OpenAI API Key (`sk-...`) - Get from [platform.openai.com](https://platform.openai.com)
- [ ] Domain name (optional but recommended)
- [x] Code pushed to GitHub: `https://github.com/yashwanthgk88/AppSec-AI`

## 🎯 Which Deployment Option Should I Choose?

### Railway ⭐ RECOMMENDED
- **Best for:** Quick deployment, automatic HTTPS, managed PostgreSQL
- **Pros:** Easiest setup, automatic deployments, great developer experience
- **Cons:** Slightly higher cost than self-hosting
- **Cost:** ~$10-15/month
- **Time:** 15 minutes
- **Guide:** [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md)

### Vercel + Railway
- **Best for:** Free frontend hosting, cost optimization
- **Pros:** Vercel free tier for frontend, Railway for backend
- **Cons:** Two platforms to manage
- **Cost:** ~$10-15/month (just backend + database)
- **Time:** 20 minutes
- **Guide:** [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md#option-2-deploy-to-vercel--railway)

### AWS EC2
- **Best for:** Full control, custom infrastructure
- **Pros:** Complete control, scalable, integrates with AWS services
- **Cons:** More complex setup, requires server management
- **Cost:** ~$10-50/month (based on instance size)
- **Time:** 45 minutes
- **Guide:** [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md#option-3-deploy-to-aws-ec2)

### DigitalOcean
- **Best for:** Simple VPS hosting, predictable pricing
- **Pros:** Simple interface, good documentation, $200 free credit
- **Cons:** Requires server management
- **Cost:** ~$6-12/month
- **Time:** 45 minutes
- **Guide:** [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md#option-4-deploy-to-digitalocean)

### Docker Compose (Self-Hosted)
- **Best for:** On-premise deployment, complete control
- **Pros:** Full control, no vendor lock-in, can run anywhere
- **Cons:** You manage everything (updates, backups, monitoring)
- **Cost:** Only infrastructure costs
- **Time:** 30 minutes (after infrastructure setup)
- **Guide:** [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)

## 🔐 Environment Variables Reference

You'll need these environment variables for deployment:

### Backend Environment Variables

```env
# Database (Railway provides this automatically)
DATABASE_URL=postgresql://user:password@host:5432/dbname

# Security (generate with: python3 -c 'import secrets; print(secrets.token_hex(32))')
SECRET_KEY=your-secret-key-min-32-characters-long

# AI Providers (required for scanning and chatbot)
ANTHROPIC_API_KEY=sk-ant-your-key-here
OPENAI_API_KEY=sk-your-key-here

# CORS (update with your frontend URL after deployment)
CORS_ORIGINS=https://your-frontend-url.railway.app

# Server
PORT=8000
PYTHONUNBUFFERED=1
```

### Frontend Environment Variables

```env
# API URL (your Railway backend URL)
VITE_API_URL=https://your-backend-url.railway.app
```

## 📦 What Gets Deployed

Your deployment includes:

1. **PostgreSQL Database**
   - Stores users, projects, scans, vulnerabilities
   - Automatic backups (on Railway)
   - Persistent storage

2. **Backend API (FastAPI)**
   - User authentication and authorization
   - Security scanning engines (SAST, SCA, Secrets)
   - AI-powered threat modeling
   - Chatbot service
   - Report generation

3. **Frontend Web App (React + Vite)**
   - Dashboard and analytics
   - Project management
   - Scan results viewer
   - Settings and configuration
   - VS Code extension download

4. **VS Code Extension** (downloaded by users)
   - Connects to your public API
   - Real-time security scanning
   - Vulnerability details panel
   - AI chatbot integration

## 🧪 Testing Your Deployment

After deployment, test these features:

### 1. Web Application
- [ ] Visit frontend URL
- [ ] Login with `admin` / `admin123`
- [ ] Create a new project
- [ ] View dashboard
- [ ] Download VS Code extension from Settings page
- [ ] Change admin password

### 2. Backend API
- [ ] Visit `your-backend-url/docs`
- [ ] Check API documentation loads
- [ ] Test authentication endpoints
- [ ] Verify database connection

### 3. VS Code Extension
- [ ] Install downloaded .vsix file
- [ ] Configure extension with your public API URL
- [ ] Login with credentials
- [ ] Scan a file
- [ ] View vulnerability details
- [ ] Test AI chatbot

## 📊 Monitoring Your Deployment

### Railway Dashboard
- View real-time logs for each service
- Monitor resource usage (CPU, memory)
- Check deployment history
- View environment variables

### Health Checks
- **Frontend:** `https://your-frontend-url.railway.app`
- **Backend:** `https://your-backend-url.railway.app/docs`
- **API Status:** `https://your-backend-url.railway.app/health` (if implemented)

### Logs
```bash
# If using Railway CLI
railway login
railway logs

# If using Docker locally
docker-compose logs -f
docker-compose logs backend
docker-compose logs frontend
docker-compose logs db
```

## 🛟 Troubleshooting

### Common Issues

1. **502 Bad Gateway**
   - Backend service might be down
   - Check backend logs in Railway
   - Verify DATABASE_URL is correct

2. **CORS Errors**
   - Update backend's CORS_ORIGINS with frontend URL
   - Ensure URL includes https:// and no trailing slash

3. **Database Connection Failed**
   - Check DATABASE_URL format
   - Verify database service is running
   - Check if migrations ran successfully

4. **VS Code Extension Can't Connect**
   - Update extension settings with production URL
   - Check API URL doesn't have trailing slash
   - Verify backend is accessible

For detailed troubleshooting, see [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md#-troubleshooting-guide)

## 💰 Cost Breakdown

### Railway (Recommended)
- PostgreSQL Database: $5-7/month
- Backend Service: $3-5/month
- Frontend Service: $2-3/month
- **Total: ~$10-15/month**
- **Free Trial: $5 credit**

### Vercel + Railway
- Vercel (Frontend): Free
- Railway (Backend + DB): $8-12/month
- **Total: ~$8-12/month**

### AWS EC2 / DigitalOcean
- Server Instance: $6-20/month
- Database: Included or separate
- Bandwidth: Usually included
- **Total: ~$6-50/month** (based on size)

## 🔄 Continuous Deployment

Once deployed to Railway:

1. **Automatic Deployments:** Push to GitHub → Railway automatically deploys
2. **Environment Variables:** Update in Railway dashboard without redeploying
3. **Rollbacks:** Easy rollback to previous deployments
4. **Monitoring:** Built-in metrics and logging

## 📝 Post-Deployment Checklist

After successful deployment:

- [ ] Change default admin password
- [ ] Create team member accounts
- [ ] Configure AI provider settings
- [ ] Test VS Code extension with production URL
- [ ] Set up custom domain (optional)
- [ ] Configure backup strategy
- [ ] Set up monitoring/alerting
- [ ] Document your deployment (URLs, credentials)
- [ ] Test all major features
- [ ] Share access with your team

## 🎉 Success!

Once deployed, you'll have:

- ✅ Public web application with HTTPS
- ✅ RESTful API for integrations
- ✅ PostgreSQL database with backups
- ✅ VS Code extension connected to your deployment
- ✅ AI-powered security scanning
- ✅ Team collaboration features

## 📞 Need Help?

### Documentation
- [Railway Docs](https://docs.railway.app)
- [FastAPI Docs](https://fastapi.tiangolo.com)
- [Vite Docs](https://vitejs.dev)

### Community
- [Railway Discord](https://discord.gg/railway)
- [GitHub Issues](https://github.com/yashwanthgk88/AppSec-AI/issues)

### Quick Commands Reference

```bash
# Generate SECRET_KEY
python3 -c 'import secrets; print(secrets.token_hex(32))'

# Test locally with Docker
./deploy-local-test.sh

# View Docker logs
docker-compose logs -f

# Stop Docker services
docker-compose down

# Install Railway CLI
npm install -g @railway/cli

# View Railway logs
railway login
railway logs
```

---

## 🚀 Ready to Deploy?

**Start here:** [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md)

**Estimated Time:** 15 minutes

**Default Credentials:**
- Username: `admin`
- Password: `admin123`

**Next Step:** Follow the Railway deployment checklist step by step!

---

*Built with ❤️ using FastAPI, React, and AI*
