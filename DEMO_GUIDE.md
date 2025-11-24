# Application Security Platform - Complete POC Demo Guide

## Overview

This is a **fully functional proof-of-concept** of an AI-enabled application security platform featuring:

- **Threat Modeling**: Auto-generate DFD diagrams with STRIDE and MITRE ATT&CK mapping
- **SAST Scanning**: Static code analysis detecting OWASP Top 10 and SANS CWE-25 vulnerabilities
- **SCA Analysis**: Software composition analysis for vulnerable dependencies
- **Secret Detection**: Scan for hardcoded credentials and API keys
- **Multilingual AI Chatbot**: Security assistance in 90+ languages powered by Claude
- **Comprehensive Reports**: Export to Excel, PDF, and XML formats
- **Modern Web UI**: React-based dashboard with real-time insights
- **VS Code Extension**: IDE integration (scaffold included)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (React)                         │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────────┐  │
│  │Dashboard │ Projects │  Threats │   Vulns  │  AI Chatbot  │  │
│  └──────────┴──────────┴──────────┴──────────┴──────────────┘  │
└───────────────────────────┬─────────────────────────────────────┘
                            │ REST API
┌───────────────────────────┴─────────────────────────────────────┐
│                     Backend (FastAPI)                            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Authentication │ Projects │ Scans │ Reports │ Chat API   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌─────────────────── Services ──────────────────────────────┐ │
│  │                                                            │ │
│  │  • ThreatModelingService (DFD, STRIDE, MITRE)            │ │
│  │  • SASTScanner (OWASP Top 10, CWE detection)             │ │
│  │  • SCAScanner (dependency vulnerabilities)                │ │
│  │  • SecretScanner (credential detection)                   │ │
│  │  • ChatbotService (Claude API, multilingual)              │ │
│  │  • ReportService (Excel, PDF, XML generation)             │ │
│  │                                                            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Database (SQLite)                                               │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Users │ Projects │ Scans │ Vulnerabilities │ ThreatModels │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- **Python 3.9+**
- **Node.js 18+**
- **Anthropic API Key** (for chatbot feature)

### 1. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# Run backend
python main.py
```

Backend runs at: **http://localhost:8000**

API Docs:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### 2. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

Frontend runs at: **http://localhost:5173**

### 3. Login

Use demo credentials:
- **Email**: admin@example.com
- **Password**: admin123

---

## Feature Demonstrations

### 1. Create a Project with Threat Modeling

**Example Architecture Document:**

```
E-Commerce Web Application

The system consists of:

- Web Frontend: React application serving users via browser
- API Gateway: Routes requests to backend services
- Authentication Service: Handles user login and JWT tokens
- Product Service: Manages product catalog
- Payment Service: Processes credit card transactions
- Database: PostgreSQL stores user data, orders, products
- Redis Cache: Session storage and caching layer
- External Payment Gateway: Stripe API for payment processing
```

**What happens:**
1. Upload architecture → Platform auto-generates **Data Flow Diagram (DFD)**
2. **STRIDE analysis** applied to each component:
   - Spoofing threats on authentication
   - Tampering risks in data flows
   - Information disclosure in database
   - Denial of service on services
   - Elevation of privilege scenarios
3. **MITRE ATT&CK mapping**: T1190 (Exploit Public-Facing App), T1059 (Command Injection), etc.
4. Interactive DFD visualization with trust boundaries

### 2. Run Security Scans

**SAST Scan Results** (Sample realistic findings):

```python
# Finding 1: SQL Injection (CWE-89, OWASP A03:2021)
File: app/models/user.py:45
Code: query = "SELECT * FROM users WHERE id = " + user_id
Severity: CRITICAL (CVSS 9.5)
STRIDE: Tampering
MITRE: T1190

Remediation: Use parameterized queries
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Finding 2: XSS (CWE-79)
File: frontend/src/components/Dashboard.tsx:127
Code: element.innerHTML = userInput;
Severity: HIGH (CVSS 7.8)

Remediation: Use textContent or DOMPurify
element.textContent = userInput;
```

**SCA Scan Results** (Vulnerable dependencies):

```json
{
  "lodash": "4.17.15",
  "vulnerability": "Prototype Pollution",
  "cve": "CVE-2020-8203",
  "severity": "high",
  "cvss": 7.4,
  "remediation": "Upgrade to lodash >= 4.17.21"
}

{
  "django": "3.1.12",
  "vulnerability": "SQL Injection via QuerySet.order_by()",
  "cve": "CVE-2022-28346",
  "severity": "critical",
  "cvss": 9.8,
  "remediation": "Upgrade to django >= 3.2.13"
}
```

**Secret Scan Results**:

```
AWS_ACCESS_KEY_ID = 'AKIAXXXXXXXXXXXXXXXX'
File: config/aws_config.py:8
Severity: CRITICAL
Remediation: Revoke key, use AWS IAM roles

api_key = 'sk_test_XXXXXXXXXXXXXXXXXXXX'
File: payment/stripe_client.js:15
Severity: CRITICAL (Stripe test key!)
Remediation: Rotate immediately, use environment variables
```

### 3. Multilingual AI Chatbot

**Example 1: English**
```
User: "How do I fix the SQL injection in user.py?"

Bot: "This SQL injection vulnerability occurs because you're concatenating
user input directly into your SQL query. Here's how to fix it:

1. Use parameterized queries (prepared statements)
2. Let the database driver handle escaping

Secure code:
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

This prevents attackers from injecting malicious SQL commands."
```

**Example 2: Spanish (Auto-detected)**
```
User: "¿Cómo puedo prevenir ataques XSS en mi aplicación?"

Bot: "Para prevenir ataques XSS (Cross-Site Scripting):

1. Nunca uses innerHTML con datos del usuario
2. Usa textContent o frameworks con auto-escape
3. Implementa Content Security Policy (CSP)
4. Valida y sanitiza todas las entradas

Código seguro:
element.textContent = userInput;  // Escapa automáticamente"
```

**Example 3: Japanese**
```
User: "このプロトタイプ汚染の脆弱性について説明してください"

Bot: "プロトタイプ汚染は、JavaScriptオブジェクトのプロトタイプを
改変できる脆弱性です。

Lodash 4.17.15には この脆弱性が存在します。

対策:
1. Lodashをバージョン4.17.21以上にアップグレード
2. Object.freeze()でプロトタイプを保護
3. 入力検証を強化"
```

### 4. Export Reports

**Excel Report** includes multiple sheets:
1. **Executive Summary**: Total findings by severity
2. **Vulnerabilities (SAST)**: Detailed SAST findings with CWE, OWASP, CVSS
3. **Dependencies (SCA)**: Vulnerable packages with CVEs
4. **Secrets Detected**: Hardcoded credentials with masked values
5. **Threat Model (STRIDE)**: All STRIDE threats by component
6. **MITRE Mapping**: ATT&CK techniques

**PDF Report**: Executive summary with:
- Metadata and scan overview
- Summary table with severity counts
- Top 5 critical vulnerabilities
- Formatted for management presentation

**XML Report**: Machine-readable format for:
- SIEM integration
- GRC platform imports
- Automated workflows
- CI/CD pipeline integration

### 5. Dashboard Analytics

**Risk Heatmap**:
```
Project: E-Commerce App
Overall Risk Score: 8.7/10 (Critical)

Breakdown:
├─ SAST:    5 Critical, 8 High, 12 Medium
├─ SCA:     3 Critical, 5 High
├─ Secrets: 5 Critical
└─ Threats: 24 STRIDE threats identified

Top Risks:
1. SQL Injection in authentication (CVSS 9.8)
2. Hardcoded AWS credentials (CVSS 9.5)
3. Stripe API key exposure (CVSS 9.5)
4. Django CVE-2022-28346 (CVSS 9.8)
```

---

## API Endpoints

### Authentication
```
POST /api/auth/register      - Register new user
POST /api/auth/login         - Login (returns JWT token)
GET  /api/auth/me            - Get current user info
```

### Projects
```
POST /api/projects                      - Create project
GET  /api/projects                      - List all projects
GET  /api/projects/{id}                 - Get project details
GET  /api/projects/{id}/threat-model    - Get threat model with DFD
POST /api/projects/{id}/scan/demo       - Run demo scan
```

### Scans
```
GET /api/projects/{id}/scans                - List scans
GET /api/scans/{id}/vulnerabilities         - Get vulnerabilities
```

### Chatbot
```
POST /api/chat    - Send message to AI chatbot
Body: {
  "message": "How do I fix SQL injection?",
  "context_type": "vulnerability",  // optional
  "context_id": 123                 // optional
}
```

### Reports
```
GET /api/projects/{id}/reports/excel    - Download Excel report
GET /api/projects/{id}/reports/pdf      - Download PDF report
GET /api/projects/{id}/reports/xml      - Download XML report
```

---

## Realistic Sample Data

The POC includes **realistic sample vulnerabilities** based on real-world security issues:

### SAST Findings
- SQL Injection (CWE-89, OWASP A03:2021)
- XSS (CWE-79, OWASP A03:2021)
- Command Injection (CWE-78)
- Hardcoded Credentials (CWE-798, OWASP A07:2021)
- Insecure Deserialization (CWE-502, OWASP A08:2021)
- Path Traversal (CWE-22, OWASP A01:2021)
- Weak Cryptography (CWE-327, OWASP A02:2021)

### SCA Findings
- Lodash CVE-2020-8203 (Prototype Pollution)
- Django CVE-2022-28346 (SQL Injection)
- Express CVE-2022-24999 (DoS)
- Log4j CVE-2021-44228 (Log4Shell RCE)
- Spring CVE-2022-22965 (Spring4Shell RCE)

### Secret Findings
- AWS Access Keys
- Stripe Live API Keys
- GitHub Personal Access Tokens
- Database Passwords
- Private Keys (RSA, SSH)

---

## Technology Stack

### Backend
- **FastAPI**: Modern async Python web framework
- **SQLAlchemy**: ORM for database operations
- **SQLite**: Lightweight database (production: PostgreSQL)
- **Anthropic Claude**: AI-powered multilingual chatbot
- **langdetect**: Automatic language detection
- **openpyxl**: Excel report generation
- **ReportLab**: PDF report generation

### Frontend
- **React 18**: Modern UI library
- **TypeScript**: Type-safe development
- **Tailwind CSS**: Utility-first styling
- **React Router**: Client-side routing
- **TanStack Query**: Data fetching and caching
- **Recharts**: Analytics visualizations
- **D3.js**: Interactive DFD diagrams
- **Vite**: Fast build tool

### Security Scanning
- **Pattern-based SAST**: Custom regex rules for vulnerability detection
- **CWE Database**: Common Weakness Enumeration
- **OWASP Top 10 2021**: Latest web security risks
- **SANS CWE-25**: Most dangerous software weaknesses

---

## Project Structure

```
appsec-platform/
├── backend/
│   ├── main.py                      # FastAPI application
│   ├── models/
│   │   ├── database.py              # Database connection
│   │   └── models.py                # SQLAlchemy models
│   ├── core/
│   │   └── security.py              # Authentication & JWT
│   ├── services/
│   │   ├── threat_modeling.py       # DFD, STRIDE, MITRE
│   │   ├── sast_scanner.py          # Static code analysis
│   │   ├── sca_scanner.py           # Dependency scanning
│   │   ├── secret_scanner.py        # Credential detection
│   │   ├── chatbot_service.py       # Claude AI integration
│   │   └── report_service.py        # Excel/PDF/XML export
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/
│   ├── src/
│   │   ├── main.tsx                 # React entry point
│   │   ├── App.tsx                  # Main application
│   │   ├── pages/
│   │   │   ├── LoginPage.tsx
│   │   │   ├── DashboardPage.tsx
│   │   │   ├── ProjectsPage.tsx
│   │   │   ├── ThreatModelPage.tsx
│   │   │   ├── VulnerabilitiesPage.tsx
│   │   │   └── ChatPage.tsx
│   │   └── components/
│   │       └── Layout.tsx
│   ├── package.json
│   ├── vite.config.ts
│   └── tailwind.config.js
│
├── vscode-extension/                # VS Code extension scaffold
└── README.md
```

---

## Key Features Implemented

### ✅ Threat Modeling
- [x] Architecture document parsing
- [x] Auto-generate DFD Level 0 diagrams
- [x] Identify trust boundaries
- [x] STRIDE threat categorization
- [x] MITRE ATT&CK technique mapping
- [x] Interactive visualization

### ✅ SAST Scanning
- [x] OWASP Top 10 2021 detection
- [x] SANS CWE-25 coverage
- [x] CVSS score calculation
- [x] Line-level code snippets
- [x] Remediation guidance with code examples
- [x] STRIDE category mapping

### ✅ SCA Analysis
- [x] Vulnerable dependency detection
- [x] CVE mapping
- [x] License compliance checking
- [x] Version recommendations
- [x] Package.json and requirements.txt parsing

### ✅ Secret Scanning
- [x] AWS credentials detection
- [x] API keys (Stripe, GitHub, Google, etc.)
- [x] Private keys (RSA, SSH)
- [x] Database passwords
- [x] JWT tokens
- [x] Value masking for security

### ✅ Multilingual AI Chatbot
- [x] Automatic language detection (90+ languages)
- [x] Context-aware responses
- [x] Vulnerability remediation assistance
- [x] STRIDE threat explanations
- [x] Security tips and best practices
- [x] Compliance Q&A

### ✅ Report Export
- [x] Excel: Multi-sheet comprehensive reports
- [x] PDF: Executive summaries
- [x] XML: Machine-readable for tool integration
- [x] Customizable templates
- [x] Severity color coding

### ✅ Web Dashboard
- [x] User authentication (JWT)
- [x] Project management
- [x] Scan history
- [x] Risk analytics
- [x] Interactive threat model viewer
- [x] Vulnerability explorer
- [x] Chat interface

---

## Security Considerations

This POC demonstrates security scanning capabilities but is not production-hardened:

1. **Database**: Uses SQLite (upgrade to PostgreSQL for production)
2. **API Keys**: Store in secure vaults (AWS Secrets Manager, HashiCorp Vault)
3. **Authentication**: Implement MFA, SAML, OAuth providers
4. **HTTPS**: Deploy with TLS certificates
5. **Rate Limiting**: Implement API rate limits
6. **Input Validation**: Add comprehensive validation
7. **Audit Logging**: Track all security-relevant events

---

## Next Steps for Production

1. **Enhanced Scanning**:
   - Integrate Semgrep, Bandit, ESLint security plugins
   - Add DAST (Dynamic Application Security Testing)
   - Container scanning (Docker, Kubernetes)
   - Infrastructure as Code scanning (Terraform, CloudFormation)

2. **Advanced Threat Modeling**:
   - DFD Level 1, 2 expansion
   - Attack tree generation
   - Threat prioritization with business context
   - Integration with SIEM platforms

3. **Auto-Remediation**:
   - Automated pull requests with fixes
   - CI/CD pipeline integration
   - Policy enforcement gates
   - Rollback capabilities

4. **VS Code Extension**:
   - Real-time inline scanning
   - Hover tooltips with remediation
   - Quick fixes with code actions
   - Security-focused code completion

5. **Enterprise Features**:
   - SSO/SAML integration
   - RBAC (Role-Based Access Control)
   - Multi-tenancy
   - Compliance reporting (SOC 2, ISO 27001, GDPR)
   - Integration with Jira, ServiceNow

---

## Testing the POC

### Scenario 1: New Project with Threat Model
1. Create project with sample architecture
2. View auto-generated DFD diagram
3. Explore STRIDE threats
4. Review MITRE ATT&CK mappings

### Scenario 2: Security Scanning
1. Run demo scan on project
2. Review critical vulnerabilities
3. Check SCA findings for dependencies
4. Examine detected secrets

### Scenario 3: AI Chatbot Interaction
1. Ask about a specific vulnerability
2. Request remediation guidance
3. Try different languages (Spanish, Japanese, French)
4. Ask compliance questions

### Scenario 4: Report Generation
1. Export Excel report → Open multi-sheet workbook
2. Download PDF → Review executive summary
3. Get XML → Inspect machine-readable format

---

## Support & Documentation

- **API Docs**: http://localhost:8000/docs
- **GitHub Issues**: [Report bugs or request features]
- **Architecture Diagrams**: See `/docs` folder
- **Code Examples**: See `/examples` folder

---

## License

MIT License - POC Demonstration Project

---

## Acknowledgments

Built with:
- **Anthropic Claude**: AI chatbot capabilities
- **OWASP Foundation**: Security standards and frameworks
- **MITRE Corporation**: ATT&CK framework
- **SANS Institute**: CWE database

---

**This POC demonstrates a complete, functional application security platform ready for further development and production hardening.**
