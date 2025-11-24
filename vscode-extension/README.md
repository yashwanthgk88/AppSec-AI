# AppSec Platform VS Code Extension

Real-time security scanning directly in your IDE with AI-powered remediation assistance.

## Features

### 🔍 Real-Time Security Scanning
- **SAST**: Detect vulnerabilities as you type
- **SCA**: Identify vulnerable dependencies
- **Secrets**: Find hardcoded credentials
- Inline error highlighting with severity indicators

### 🤖 AI Security Assistant
- Ask security questions in your native language
- Get context-aware remediation guidance
- Explain vulnerabilities in plain language
- Proactive security tips

### ⚡ Auto-Remediation
- One-click vulnerability fixes
- Automated code patches
- Secure code suggestions
- Pull request integration

### 📊 Security Dashboard
- View all vulnerabilities in sidebar
- Filter by severity (Critical, High, Medium, Low)
- Jump to vulnerable code locations
- Track remediation progress

## Installation

### From VSIX
1. Download `appsec-platform-vscode-1.0.0.vsix`
2. Open VS Code
3. Go to Extensions → ··· → Install from VSIX
4. Select the downloaded file

### From Source
```bash
cd vscode-extension
npm install
npm run compile
```

## Configuration

Open VS Code Settings and configure:

```json
{
  "appsec.apiUrl": "http://localhost:8000",
  "appsec.apiKey": "your-api-token",
  "appsec.enableRealTimeScanning": true,
  "appsec.scanOnSave": true
}
```

## Usage

### Scan Current File
1. Open any supported file (.js, .ts, .py, .java, .go)
2. Press `Cmd+Shift+P` (Mac) or `Ctrl+Shift+P` (Windows/Linux)
3. Type "AppSec: Scan Current File"

### Scan Entire Workspace
1. `Cmd+Shift+P` → "AppSec: Scan Entire Workspace"
2. Wait for scan to complete
3. View results in Problems panel

### Open Security Chatbot
1. `Cmd+Shift+P` → "AppSec: Open Security Chatbot"
2. Ask questions about vulnerabilities
3. Get AI-powered remediation guidance

### Auto-Fix Vulnerability
1. Click on a vulnerability in your code
2. `Cmd+Shift+P` → "AppSec: Auto-Fix Vulnerability"
3. Review and accept the suggested fix

## Supported Languages

- JavaScript / TypeScript
- Python
- Java
- Go
- PHP (coming soon)
- Ruby (coming soon)

## Keyboard Shortcuts

- `Cmd+K S` - Scan current file
- `Cmd+K W` - Scan workspace
- `Cmd+K C` - Open security chatbot
- `Cmd+K F` - Fix vulnerability at cursor

## Examples

### Detecting SQL Injection
```python
# This will be highlighted as CRITICAL
query = "SELECT * FROM users WHERE id = " + user_id

# Hover to see:
# [CRITICAL] SQL Injection (CWE-89)
# Use parameterized queries to prevent SQL injection

# Click to auto-fix:
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### Detecting Secrets
```javascript
// This will be flagged
const API_KEY = "sk_live_1234567890abcdef";

// Suggestion: Use environment variables
const API_KEY = process.env.STRIPE_API_KEY;
```

## Troubleshooting

### Extension not working
1. Check AppSec Platform backend is running at `http://localhost:8000`
2. Verify API token in settings
3. Check extension output: View → Output → AppSec Platform

### Scans not appearing
1. Ensure file language is supported
2. Check `appsec.enableRealTimeScanning` is enabled
3. Manually trigger scan with command palette

## Contributing

Report issues or contribute at:
https://github.com/your-org/appsec-platform

## License

MIT License
