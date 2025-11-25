# AppSec AI Platform - Deployment Guide

This guide will help you deploy the AppSec AI platform to the internet for public access.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Deployment Options](#deployment-options)
3. [Option 1: Deploy to Railway (Recommended - Easiest)](#option-1-deploy-to-railway)
4. [Option 2: Deploy to Vercel + Railway](#option-2-deploy-to-vercel--railway)
5. [Option 3: Deploy to AWS EC2](#option-3-deploy-to-aws-ec2)
6. [Option 4: Deploy to DigitalOcean](#option-4-deploy-to-digitalocean)
7. [Environment Configuration](#environment-configuration)
8. [Post-Deployment Steps](#post-deployment-steps)

---

## Prerequisites

- GitHub account
- Domain name (optional but recommended)
- API keys for AI providers (Anthropic/OpenAI)
- Basic understanding of environment variables

---

## Deployment Options

### Quick Comparison

| Platform | Best For | Cost | Difficulty | Free Tier |
|----------|----------|------|------------|-----------|
| Railway | Full-stack apps | $5-20/mo | Easy | $5 credit |
| Vercel + Railway | Frontend-heavy | $0-15/mo | Easy | Yes |
| AWS EC2 | Full control | $5-50/mo | Medium | 12 months |
| DigitalOcean | Simplicity | $6-12/mo | Medium | $200 credit |

---

## Option 1: Deploy to Railway (Recommended - Easiest)

Railway provides the simplest deployment with automatic HTTPS and domains.

### Step 1: Prepare Your Repository

1. Ensure all code is pushed to GitHub:
```bash
cd /Users/yashwanthgk/appsec-platform
git add .
git commit -m "Prepare for deployment"
git push origin main
```

### Step 2: Sign Up for Railway

1. Go to [Railway.app](https://railway.app)
2. Click "Login with GitHub"
3. Authorize Railway to access your repositories

### Step 3: Deploy Backend

1. Click "New Project" → "Deploy from GitHub repo"
2. Select `AppSec-AI` repository
3. Click "Add variables" and add:
   ```
   DATABASE_URL=postgresql://user:password@hostname:5432/dbname
   SECRET_KEY=your-secret-key-here-min-32-chars
   ANTHROPIC_API_KEY=your-anthropic-key
   OPENAI_API_KEY=your-openai-key
   PYTHONUNBUFFERED=1
   PORT=8000
   ```
4. In Settings → Root Directory, set to: `backend`
5. In Settings → Start Command, set to: `uvicorn main:app --host 0.0.0.0 --port $PORT`
6. Deploy!

### Step 4: Deploy Frontend

1. Click "New" → "GitHub Repo"
2. Select same `AppSec-AI` repository
3. Click "Add variables" and add:
   ```
   VITE_API_URL=https://your-backend-url.railway.app
   ```
4. In Settings → Root Directory, set to: `frontend`
5. In Settings → Build Command, set to: `npm run build`
6. In Settings → Start Command, set to: `npm run preview -- --host 0.0.0.0 --port $PORT`
7. Deploy!

### Step 5: Add PostgreSQL Database

1. In your Railway project, click "New" → "Database" → "PostgreSQL"
2. Copy the connection string from the database variables
3. Update your backend service's `DATABASE_URL` with this value
4. Redeploy backend

### Step 6: Generate Domains

1. Go to your backend service → Settings → Networking
2. Click "Generate Domain"
3. Copy the URL (e.g., `https://appsec-backend-production.up.railway.app`)
4. Update frontend's `VITE_API_URL` with this URL
5. Generate domain for frontend service
6. Access your app at the frontend URL!

**Railway Cost**: ~$10-15/month

---

## Option 2: Deploy to Vercel + Railway

Use Vercel for frontend (free) and Railway for backend.

### Deploy Backend to Railway
Follow Steps 3-5 from Option 1 above.

### Deploy Frontend to Vercel

1. Install Vercel CLI:
```bash
npm install -g vercel
```

2. Navigate to frontend directory:
```bash
cd /Users/yashwanthgk/appsec-platform/frontend
```

3. Create `vercel.json`:
```json
{
  "buildCommand": "npm run build",
  "outputDirectory": "dist",
  "devCommand": "npm run dev",
  "installCommand": "npm install",
  "framework": "vite",
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}
```

4. Deploy:
```bash
vercel
```

5. Set environment variable:
```bash
vercel env add VITE_API_URL
# Enter your Railway backend URL
```

6. Redeploy:
```bash
vercel --prod
```

**Cost**: Free frontend + $10-15/month for backend

---

## Option 3: Deploy to AWS EC2

Full control with AWS infrastructure.

### Step 1: Launch EC2 Instance

1. Go to AWS Console → EC2 → Launch Instance
2. Choose Ubuntu 22.04 LTS
3. Instance type: t2.small (or t2.micro for testing)
4. Configure security group:
   - SSH (22) - Your IP
   - HTTP (80) - 0.0.0.0/0
   - HTTPS (443) - 0.0.0.0/0
   - Custom TCP (8000) - 0.0.0.0/0
   - Custom TCP (5173) - 0.0.0.0/0
5. Download key pair
6. Launch instance

### Step 2: Connect and Setup

```bash
# Connect to instance
ssh -i your-key.pem ubuntu@your-instance-ip

# Update system
sudo apt update && sudo apt upgrade -y

# Install Python, Node.js, PostgreSQL
sudo apt install -y python3-pip python3-venv nodejs npm postgresql postgresql-contrib nginx

# Install PM2 for process management
sudo npm install -g pm2

# Clone repository
git clone https://github.com/yashwanthgk88/AppSec-AI.git
cd AppSec-AI
```

### Step 3: Setup PostgreSQL

```bash
sudo -u postgres psql
CREATE DATABASE appsec_db;
CREATE USER appsec_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE appsec_db TO appsec_user;
\q
```

### Step 4: Setup Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create .env file
cat > .env << EOF
DATABASE_URL=postgresql://appsec_user:your_password@localhost:5432/appsec_db
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
ANTHROPIC_API_KEY=your_key
OPENAI_API_KEY=your_key
EOF

# Run migrations
python3 migrate_db.py

# Start with PM2
pm2 start "uvicorn main:app --host 0.0.0.0 --port 8000" --name appsec-backend
pm2 save
pm2 startup
```

### Step 5: Setup Frontend

```bash
cd ../frontend
npm install

# Create .env file
echo "VITE_API_URL=http://your-domain.com/api" > .env

npm run build

# Serve with PM2
pm2 start "npm run preview -- --host 0.0.0.0 --port 5173" --name appsec-frontend
pm2 save
```

### Step 6: Configure Nginx

```bash
sudo nano /etc/nginx/sites-available/appsec
```

Add this configuration:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    # Frontend
    location / {
        proxy_pass http://localhost:5173;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/appsec /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Step 7: Setup SSL with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

**AWS Cost**: ~$10-20/month (t2.small instance)

---

## Option 4: Deploy to DigitalOcean

Similar to AWS but simpler interface.

### Step 1: Create Droplet

1. Go to [DigitalOcean](https://www.digitalocean.com)
2. Create → Droplets
3. Choose Ubuntu 22.04
4. Size: Basic $6/month (2GB RAM)
5. Add SSH key
6. Create Droplet

### Step 2: Setup Application

Follow the same steps as AWS EC2 Option 3, starting from Step 2.

### Step 3: Point Domain

1. In DigitalOcean → Networking → Domains
2. Add your domain
3. Create A record pointing to your droplet IP

**DigitalOcean Cost**: $6-12/month

---

## Environment Configuration

### Backend `.env` Template

```env
# Database
DATABASE_URL=postgresql://user:password@host:5432/dbname

# Security
SECRET_KEY=your-secret-key-min-32-characters-long

# AI Providers
ANTHROPIC_API_KEY=sk-ant-xxxxx
OPENAI_API_KEY=sk-xxxxx

# Optional
CORS_ORIGINS=https://your-frontend-domain.com
PORT=8000
```

### Frontend `.env` Template

```env
VITE_API_URL=https://api.your-domain.com
```

---

## Post-Deployment Steps

### 1. Update CORS Settings

In `backend/main.py`, update:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://your-frontend-domain.com",
        "https://www.your-frontend-domain.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### 2. Update VS Code Extension Download URL

In `frontend/src/pages/SettingsPage.tsx`, the download link will automatically work with your deployed frontend.

### 3. Setup Monitoring (Optional)

```bash
# Install monitoring
pm2 install pm2-logrotate
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 7

# View logs
pm2 logs appsec-backend
pm2 logs appsec-frontend
```

### 4. Setup Backups (Recommended)

```bash
# Database backup script
cat > /home/ubuntu/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/home/ubuntu/backups"
mkdir -p $BACKUP_DIR
DATE=$(date +%Y%m%d_%H%M%S)
pg_dump -U appsec_user appsec_db > $BACKUP_DIR/backup_$DATE.sql
# Keep only last 7 days
find $BACKUP_DIR -name "backup_*.sql" -mtime +7 -delete
EOF

chmod +x /home/ubuntu/backup.sh

# Add to crontab (daily at 2 AM)
crontab -e
# Add: 0 2 * * * /home/ubuntu/backup.sh
```

### 5. Security Hardening

```bash
# Setup firewall (if using EC2/DigitalOcean)
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable

# Disable root login
sudo nano /etc/ssh/sshd_config
# Set: PermitRootLogin no
sudo systemctl restart sshd
```

---

## Testing Your Deployment

1. **Frontend**: Visit `https://your-domain.com`
2. **Backend API**: Visit `https://your-domain.com/api/docs`
3. **Login**: Use credentials `admin` / `admin123`
4. **VS Code Extension**: Download from Settings page and test connection

---

## Troubleshooting

### Issue: 502 Bad Gateway
**Solution**: Check if backend is running
```bash
pm2 status
pm2 logs appsec-backend
```

### Issue: CORS Error
**Solution**: Update CORS origins in backend/main.py to include your frontend URL

### Issue: Database Connection Failed
**Solution**: Check DATABASE_URL in .env and ensure PostgreSQL is running
```bash
sudo systemctl status postgresql
```

### Issue: VS Code Extension Can't Connect
**Solution**: Update extension settings to use your public API URL instead of localhost

---

## Recommended: Railway Deployment (Fastest)

For the quickest deployment with minimal configuration:

1. Push code to GitHub ✅ (Already done)
2. Sign up at [Railway.app](https://railway.app)
3. Click "Deploy from GitHub"
4. Select your repository
5. Add environment variables
6. Click Deploy
7. Get your public URLs

**Total time: ~15 minutes**

---

## Need Help?

- Railway Docs: https://docs.railway.app
- Vercel Docs: https://vercel.com/docs
- AWS EC2 Guide: https://docs.aws.amazon.com/ec2
- DigitalOcean Tutorials: https://www.digitalocean.com/community/tutorials

---

**Next Steps**: Choose your deployment option and follow the guide above!
