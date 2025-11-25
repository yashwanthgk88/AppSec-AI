# Deploy to Railway - Quick Start Guide

Railway is the **fastest and easiest** way to deploy your AppSec AI platform to the internet.

## Why Railway?

- ✅ **Free $5 credit** to start
- ✅ **Automatic HTTPS** and custom domains
- ✅ **Zero configuration** deployment
- ✅ **Built-in PostgreSQL** database
- ✅ **Automatic deployments** from GitHub
- ✅ **Environment variable** management

---

## Step-by-Step Deployment (15 minutes)

### Step 1: Sign Up for Railway

1. Go to **[railway.app](https://railway.app)**
2. Click **"Login with GitHub"**
3. Authorize Railway to access your GitHub account

### Step 2: Create New Project

1. Click **"New Project"**
2. Select **"Deploy from GitHub repo"**
3. Choose your **`AppSec-AI`** repository
4. Railway will detect your project automatically

### Step 3: Add PostgreSQL Database

1. In your project, click **"New"**
2. Select **"Database"** → **"Add PostgreSQL"**
3. Railway will automatically provision a database
4. **Copy the DATABASE_URL** from the database service variables

### Step 4: Configure Backend Service

1. Click on your backend service (or create new from GitHub repo with `/backend` as root)
2. Go to **"Variables"** tab
3. Click **"Add Variable"** and add these:

```
DATABASE_URL=<paste from Step 3>
SECRET_KEY=<generate a random 32+ character string>
ANTHROPIC_API_KEY=sk-ant-your-key-here
OPENAI_API_KEY=sk-your-key-here
PYTHONUNBUFFERED=1
PORT=8000
```

To generate a secure SECRET_KEY, run:
```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

4. Go to **"Settings"** tab:
   - **Root Directory**: `backend`
   - **Build Command**: (leave empty, Railway auto-detects)
   - **Start Command**: `python3 migrate_db.py && uvicorn main:app --host 0.0.0.0 --port $PORT`

5. Click **"Deploy"**

### Step 5: Generate Backend Domain

1. In backend service → **Settings** → **Networking**
2. Click **"Generate Domain"**
3. Copy the generated URL (e.g., `https://appsec-backend-production.up.railway.app`)
4. **Save this URL** - you'll need it for the frontend!

### Step 6: Configure Frontend Service

1. In your project, click **"New"** → **"GitHub Repo"**
2. Select your **`AppSec-AI`** repository again
3. Go to **"Variables"** tab and add:

```
VITE_API_URL=<paste backend URL from Step 5>
```

4. Go to **"Settings"** tab:
   - **Root Directory**: `frontend`
   - **Build Command**: `npm run build`
   - **Start Command**: `npm run preview -- --host 0.0.0.0 --port $PORT`
   - **Install Command**: `npm install`

5. Click **"Deploy"**

### Step 7: Generate Frontend Domain

1. In frontend service → **Settings** → **Networking**
2. Click **"Generate Domain"**
3. Copy the generated URL (e.g., `https://appsec-frontend-production.up.railway.app`)

### Step 8: Update CORS Settings

1. Go back to backend service → **Variables**
2. Add:
```
CORS_ORIGINS=https://your-frontend-url.railway.app
```

3. Replace `https://your-frontend-url.railway.app` with your actual frontend URL from Step 7
4. Backend will automatically redeploy

### Step 9: Test Your Deployment! 🎉

1. Visit your frontend URL: `https://your-frontend-url.railway.app`
2. You should see the AppSec AI login page
3. Login with:
   - **Username**: `admin`
   - **Password**: `admin123`
4. Go to **Settings** → Download VS Code extension
5. Install the extension and connect to your public API URL!

---

## Optional: Add Custom Domain

### Step 1: Add Domain to Railway

1. In your frontend service → **Settings** → **Networking**
2. Click **"Custom Domain"**
3. Enter your domain (e.g., `appsec.yourdomain.com`)
4. Railway will provide DNS records

### Step 2: Update DNS

1. Go to your domain registrar (GoDaddy, Namecheap, etc.)
2. Add the CNAME or A record provided by Railway
3. Wait for DNS propagation (5-30 minutes)

### Step 3: Update Backend CORS

1. Add your custom domain to `CORS_ORIGINS`:
```
CORS_ORIGINS=https://appsec.yourdomain.com,https://your-frontend-url.railway.app
```

---

## Monitoring and Logs

### View Logs

1. Click on any service
2. Go to **"Deployments"** tab
3. Click on the latest deployment
4. View **real-time logs**

### Check Service Health

1. Backend health: `https://your-backend-url.railway.app/docs`
2. Frontend health: `https://your-frontend-url.railway.app`

---

## Environment Variables Reference

### Backend Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | From Railway database |
| `SECRET_KEY` | JWT secret key (32+ chars) | Random string |
| `ANTHROPIC_API_KEY` | Anthropic Claude API key | `sk-ant-...` |
| `OPENAI_API_KEY` | OpenAI API key | `sk-...` |
| `CORS_ORIGINS` | Allowed frontend URLs | Frontend Railway URL |
| `PORT` | Server port | `8000` |

### Frontend Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `VITE_API_URL` | Backend API URL | Backend Railway URL |

---

## Troubleshooting

### Issue: Build Failed

**Solution**: Check the build logs in Railway. Common issues:
- Missing dependencies in `requirements.txt` or `package.json`
- Syntax errors in code
- Wrong root directory setting

### Issue: 502 Bad Gateway

**Solution**:
1. Check backend logs for errors
2. Verify DATABASE_URL is set correctly
3. Ensure migrations ran successfully

### Issue: CORS Error

**Solution**:
1. Add frontend URL to backend's `CORS_ORIGINS`
2. Make sure URL includes `https://` and no trailing slash

### Issue: Can't Connect from VS Code Extension

**Solution**:
1. In VS Code, open Settings (Cmd+,)
2. Search for "AppSec"
3. Update `appsec.apiUrl` to your backend Railway URL
4. Reload VS Code

---

## Cost Estimation

Railway pricing is based on usage:

- **Free Tier**: $5 credit/month (lasts ~5-10 days for this app)
- **Hobby Plan**: $5/month base + usage
  - PostgreSQL: ~$5-7/month
  - Backend: ~$3-5/month
  - Frontend: ~$2-3/month
- **Total**: ~$10-15/month

**Pro Tip**: Use the $5 credit for testing, then upgrade to Hobby plan for production.

---

## Next Steps After Deployment

1. ✅ Change default admin password
2. ✅ Add your team members
3. ✅ Configure AI provider settings
4. ✅ Download and test VS Code extension
5. ✅ Set up custom domain (optional)
6. ✅ Configure backups (Railway auto-backs up database)

---

## Support

- Railway Docs: https://docs.railway.app
- Railway Discord: https://discord.gg/railway
- GitHub Issues: https://github.com/yashwanthgk88/AppSec-AI/issues

---

## Quick Commands

```bash
# Generate SECRET_KEY
python3 -c 'import secrets; print(secrets.token_hex(32))'

# Test backend locally
cd backend && uvicorn main:app --reload

# Test frontend locally
cd frontend && npm run dev

# View Railway logs (install CLI)
npm install -g @railway/cli
railway login
railway logs
```

---

**Ready to deploy?** Follow the steps above and your AppSec AI platform will be live in ~15 minutes! 🚀
