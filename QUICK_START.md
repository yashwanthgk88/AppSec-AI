# 🚀 Quick Start Guide

Get up and running with the AppSec Platform in 5 minutes!

---

## Step 1: Run Setup Script

```bash
cd appsec-platform
./SETUP.sh
```

This installs all dependencies for both backend and frontend.

---

## Step 2: Configure API Key

Edit `backend/.env` and add your Anthropic API key:

```bash
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

> **Get your API key**: https://console.anthropic.com/

> **Note**: The platform works without an API key, but the AI chatbot will be disabled.

---

## Step 3: Start Backend

```bash
cd backend
source venv/bin/activate  # Windows: venv\Scripts\activate
python main.py
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

✅ **Backend is running!**

---

## Step 4: Start Frontend (New Terminal)

```bash
cd frontend
npm run dev
```

You should see:
```
VITE v5.0.11  ready in 523 ms

➜  Local:   http://localhost:5173/
➜  Network: use --host to expose
```

✅ **Frontend is running!**

---

## Step 5: Login

1. Open browser to **http://localhost:5173**
2. Use demo credentials:
   - **Email**: `admin@example.com`
   - **Password**: `admin123`

---

## Step 6: Create Your First Project

1. Click **"New Project"**
2. Enter project details:
   - **Name**: `My E-Commerce App`
   - **Description**: `Online shopping platform`
3. Click **"Use Sample"** for architecture document
4. Click **"Create Project"**

**What happens:**
- DFD diagram is auto-generated
- STRIDE threats are identified
- MITRE ATT&CK techniques are mapped
- Trust boundaries are detected

---

## Step 7: Run Security Scan

1. Click **"Run Demo Scan"**
2. Wait 2-3 seconds for scan to complete
3. View results:
   - **SAST**: 5 critical, 8 high, 12 medium vulnerabilities
   - **SCA**: 5 vulnerable dependencies
   - **Secrets**: 5 exposed credentials

---

## Step 8: Explore Features

### View Threat Model
- Click **"Threat Model"** tab
- See interactive DFD diagram
- Browse STRIDE threats by category
- Review MITRE ATT&CK mappings

### View Vulnerabilities
- Click **"Vulnerabilities"** tab
- Filter by severity (Critical, High, Medium, Low)
- Expand any vulnerability to see:
  - Vulnerable code snippet
  - CWE and OWASP category
  - STRIDE mapping
  - Remediation guidance with secure code examples

### Chat with AI Assistant
- Click **"AI Assistant"** in navigation
- Ask questions like:
  - "How do I fix SQL injection?"
  - "¿Cómo prevenir XSS?" (Spanish)
  - "SQLインジェクションを防ぐには？" (Japanese)
- Get instant, context-aware responses in your language

### Export Reports
- Click **"Export"** dropdown
- Download:
  - **Excel**: Multi-sheet detailed report
  - **PDF**: Executive summary
  - **XML**: Machine-readable format

---

## 🎯 Example Workflows

### Workflow 1: Fix a Critical Vulnerability

1. Go to **Vulnerabilities** page
2. Click on **"SQL Injection"** (Critical)
3. Read the vulnerability details
4. Click **"Ask AI Assistant"**
5. Get step-by-step remediation in your language
6. Apply the secure code example
7. Mark as **"Resolved"**

### Workflow 2: Understand a Threat

1. Go to **Threat Model** page
2. Filter by **"Information Disclosure"**
3. Click on any threat card
4. Read the mitigation guidance
5. Click **"Ask AI"** for deeper explanation
6. Learn about real-world attack scenarios

### Workflow 3: Multilingual Support

1. Go to **AI Assistant**
2. Ask in Spanish: *"¿Cómo asegurar una API REST?"*
3. Get response in Spanish with:
   - Security best practices
   - Code examples
   - OWASP recommendations
4. Try other languages: French, German, Japanese, Hindi, etc.

### Workflow 4: Generate Executive Report

1. Go to your project
2. Click **"Export" → "Download PDF"**
3. Get professional report with:
   - Executive summary
   - Severity breakdown chart
   - Top 5 critical issues
   - Remediation recommendations
4. Share with management/stakeholders

---

## 🔍 Sample Architecture Document

Use this template when creating projects:

```markdown
Online Banking Application

System Components:

- Web Frontend: React SPA for customer account management
- Mobile App: iOS/Android native apps
- API Gateway: Routes requests to microservices
- Authentication Service: OAuth 2.0 + MFA
- Account Service: Account balance and transactions
- Transfer Service: Money transfers between accounts
- Payment Service: Bill payments and external transfers
- Notification Service: Email and SMS notifications
- Database: PostgreSQL for account data
- Cache: Redis for session management
- Message Queue: RabbitMQ for async processing
- External Services: Plaid API, Twilio SMS

Data Flows:
- Customers access via web/mobile → API Gateway → Backend services
- Backend services read/write to database
- Async notifications via message queue
- External API calls for bank integration
```

This generates a comprehensive threat model with 20+ STRIDE threats!

---

## 🐛 Troubleshooting

### Backend won't start
```bash
# Check Python version (need 3.9+)
python3 --version

# Reinstall dependencies
pip install -r requirements.txt

# Check for port conflicts
lsof -i :8000  # Kill process using port 8000
```

### Frontend won't start
```bash
# Check Node version (need 18+)
node --version

# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install

# Check for port conflicts
lsof -i :5173  # Kill process using port 5173
```

### Chatbot not working
```bash
# Check .env file has API key
cat backend/.env | grep ANTHROPIC

# Verify API key is valid
# Get new key from: https://console.anthropic.com/
```

### Database errors
```bash
# Delete and recreate database
cd backend
rm appsec.db
python main.py  # Creates fresh database with admin user
```

---

## 📖 Next Steps

1. **Read the full guide**: [DEMO_GUIDE.md](DEMO_GUIDE.md)
2. **Explore API docs**: http://localhost:8000/docs
3. **Try VS Code extension**: See `vscode-extension/README.md`
4. **Customize the platform**: Modify services in `backend/services/`
5. **Add your own vulnerability rules**: Edit `backend/services/sast_scanner.py`

---

## 💡 Pro Tips

- **Sample Questions for AI**: Try "Explain STRIDE in simple terms" or "Best practices for React security"
- **Multiple Projects**: Create projects for different apps to compare risk scores
- **Custom Architecture**: Write detailed architecture docs for better threat modeling
- **Report Filtering**: Export reports filtered by severity or scan type
- **Language Detection**: The chatbot auto-detects language - no manual selection needed!

---

## 🎉 You're Ready!

You now have a fully functional application security platform with:
- ✅ Automated threat modeling
- ✅ Vulnerability scanning
- ✅ AI-powered assistance in 90+ languages
- ✅ Professional report generation
- ✅ Modern, intuitive UI

**Happy security scanning! 🔒**

For detailed feature documentation, see [DEMO_GUIDE.md](DEMO_GUIDE.md)
