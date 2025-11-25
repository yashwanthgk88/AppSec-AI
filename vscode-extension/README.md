# AppSec AI Security Scanner - VS Code Extension

Real-time security scanning with AI-powered threat detection directly in your VS Code editor.

## Features

- **SAST (Static Application Security Testing)**: Detect code vulnerabilities as you type
- **SCA (Software Composition Analysis)**: Find vulnerable dependencies
- **Secret Detection**: Identify hardcoded secrets and API keys
- **AI-Powered Fixes**: Get intelligent remediation suggestions
- **Real-time Diagnostics**: See security issues inline with squiggly lines
- **Tree View**: Browse all findings organized by severity
- **One-Click Fixes**: Apply AI-suggested fixes instantly

## Installation

### From Your AppSec Platform

1. Log into your AppSec platform dashboard
2. Navigate to Settings or Downloads
3. Click "Download VS Code Extension"
4. Save `appsec-ai-scanner-1.0.0.vsix` to your computer

### Install in VS Code

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X / Cmd+Shift+X)
3. Click the "..." menu → "Install from VSIX..."
4. Select the downloaded `.vsix` file
5. Reload VS Code when prompted

## Getting Started

1. **Login**: Use Command Palette (`Ctrl/Cmd+Shift+P`) → "AppSec: Login to Platform"
2. **Enter Credentials**: Use your AppSec platform credentials
3. **Scan**: Right-click in editor → "AppSec: Scan Workspace"
4. **View Results**: Check the AppSec Security sidebar

## Configuration

Open Settings (Ctrl/Cmd+,) and search for "AppSec":

- `appsec.apiUrl`: Your AppSec platform URL (default: http://localhost:8000)
- `appsec.autoScan`: Automatically scan files on save
- `appsec.minimumSeverity`: Minimum severity level to show (low/medium/high/critical)

## Usage

### Commands

- `AppSec: Login to Platform` - Authenticate with your platform
- `AppSec: Scan Workspace` - Scan entire project
- `AppSec: Scan Current File` - Scan active file only
- `AppSec: View on Web Dashboard` - Open findings in web interface
- `AppSec: Clear Security Findings` - Clear all diagnostics

### Context Menu

Right-click in any file:
- Scan Current File
- Apply AI-Suggested Fix
- Mark as Resolved
- Mark as False Positive

## Support

For issues or questions:
- Visit: Your AppSec Platform Dashboard
- GitHub: https://github.com/yashwanthgk88/AppSec-AI

## Privacy

- All API communications are secure (HTTPS)
- Auth tokens stored in VS Code's secure storage
- No data sent to third parties

## Version

Current Version: 1.0.0

