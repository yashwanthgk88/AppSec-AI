# AI-Enabled Application Security Platform - POC

A comprehensive application security platform featuring threat modeling, vulnerability scanning, multilingual AI chatbot, and detailed reporting.

## Features

### Core Capabilities
- **Threat Modeling:** Auto-generate DFD diagrams with STRIDE and MITRE ATT&CK mapping
- **SAST Scanning:** Static code analysis based on OWASP Top 10 and SANS CWE-25
- **SCA Analysis:** Software Composition Analysis for vulnerable dependencies
- **Secret Detection:** Scan for hardcoded credentials and sensitive data
- **Multilingual AI Chatbot:** Security assistance in 90+ languages with auto-detection
- **Report Export:** Generate Excel, PDF, and XML reports
- **VS Code Extension:** Real-time security feedback in your IDE
- **Live Log Correlation:** Real-time threat detection and alerts

## Architecture

```
appsec-platform/
├── backend/               # FastAPI backend
│   ├── api/              # REST API endpoints
│   ├── core/             # Core business logic
│   ├── models/           # Database models
│   ├── services/         # Security scanning services
│   └── utils/            # Utilities and helpers
├── frontend/             # React frontend
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── pages/        # Page components
│   │   ├── services/     # API clients
│   │   └── utils/        # Helper functions
├── vscode-extension/     # VS Code extension
└── docs/                 # Documentation
```

## Quick Start

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
python main.py
```

Backend will run on http://localhost:8000

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

Frontend will run on http://localhost:5173

### Environment Variables

Create `.env` file in backend directory:
```
ANTHROPIC_API_KEY=your_api_key_here
DATABASE_URL=sqlite:///./appsec.db
SECRET_KEY=your_secret_key_here
```

## Usage

1. **Upload Architecture Document:** Upload system architecture in text/markdown format
2. **View Threat Model:** Explore auto-generated DFD diagrams with STRIDE analysis
3. **Scan Code:** Upload source code for SAST, SCA, and secret scanning
4. **Chat with AI:** Ask security questions in your native language
5. **Export Reports:** Download comprehensive reports in Excel, PDF, or XML

## API Documentation

Interactive API docs available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Sample Credentials

For POC demo:
- Username: `admin@example.com`
- Password: `admin123`

## License

MIT License - This is a POC demonstration project
