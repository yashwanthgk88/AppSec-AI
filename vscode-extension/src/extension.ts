/**
 * VS Code Extension for AppSec Platform
 * Provides real-time security scanning and AI-powered remediation
 */

import * as vscode from 'vscode';
import axios from 'axios';

// Extension state
let diagnosticCollection: vscode.DiagnosticCollection;
let apiUrl: string;
let apiToken: string;

/**
 * Extension activation
 */
export function activate(context: vscode.ExtensionContext) {
    console.log('AppSec Platform extension activated');

    // Initialize diagnostic collection
    diagnosticCollection = vscode.languages.createDiagnosticCollection('appsec');
    context.subscriptions.push(diagnosticCollection);

    // Load configuration
    loadConfiguration();

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.scanFile', scanCurrentFile),
        vscode.commands.registerCommand('appsec.scanWorkspace', scanWorkspace),
        vscode.commands.registerCommand('appsec.openChat', openSecurityChat),
        vscode.commands.registerCommand('appsec.fixVulnerability', fixVulnerability)
    );

    // Register event listeners
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(onDocumentSave),
        vscode.workspace.onDidChangeTextDocument(onDocumentChange)
    );

    // Scan open files on activation
    vscode.window.visibleTextEditors.forEach(editor => {
        scanDocument(editor.document);
    });

    vscode.window.showInformationMessage('AppSec Platform: Security scanning enabled');
}

/**
 * Load extension configuration
 */
function loadConfiguration() {
    const config = vscode.workspace.getConfiguration('appsec');
    apiUrl = config.get('apiUrl', 'http://localhost:8000');
    apiToken = config.get('apiKey', '');
}

/**
 * Scan current file
 */
async function scanCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
    }

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "AppSec: Scanning file...",
        cancellable: false
    }, async (progress) => {
        await scanDocument(editor.document);
    });

    vscode.window.showInformationMessage('Security scan completed');
}

/**
 * Scan entire workspace
 */
async function scanWorkspace() {
    const files = await vscode.workspace.findFiles('**/*.{js,ts,py,java,go}', '**/node_modules/**');

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "AppSec: Scanning workspace...",
        cancellable: false
    }, async (progress) => {
        for (let i = 0; i < files.length; i++) {
            progress.report({
                message: `${i + 1}/${files.length} files`,
                increment: (100 / files.length)
            });

            const document = await vscode.workspace.openTextDocument(files[i]);
            await scanDocument(document);
        }
    });

    vscode.window.showInformationMessage(`Scanned ${files.length} files`);
}

/**
 * Scan a document for vulnerabilities
 */
async function scanDocument(document: vscode.TextDocument) {
    if (!shouldScanDocument(document)) {
        return;
    }

    try {
        const code = document.getText();
        const fileName = document.fileName;

        // Call backend API
        const response = await axios.post(`${apiUrl}/api/scan/inline`, {
            code: code,
            file_path: fileName,
            language: document.languageId
        }, {
            headers: {
                'Authorization': `Bearer ${apiToken}`
            }
        });

        const findings = response.data.findings || [];

        // Convert findings to diagnostics
        const diagnostics: vscode.Diagnostic[] = findings.map((finding: any) => {
            const line = finding.line_number - 1;
            const range = new vscode.Range(line, 0, line, 1000);

            const severity = getSeverity(finding.severity);
            const message = `${finding.title}: ${finding.description}`;

            const diagnostic = new vscode.Diagnostic(range, message, severity);
            diagnostic.source = 'AppSec Platform';
            diagnostic.code = finding.cwe_id;

            return diagnostic;
        });

        diagnosticCollection.set(document.uri, diagnostics);

        // Show inline decorations
        showInlineDecorations(document, findings);

    } catch (error) {
        console.error('Scan failed:', error);
    }
}

/**
 * Check if document should be scanned
 */
function shouldScanDocument(document: vscode.TextDocument): boolean {
    const supportedLanguages = ['javascript', 'typescript', 'python', 'java', 'go'];
    return supportedLanguages.includes(document.languageId);
}

/**
 * Convert severity string to VS Code diagnostic severity
 */
function getSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity.toLowerCase()) {
        case 'critical':
        case 'high':
            return vscode.DiagnosticSeverity.Error;
        case 'medium':
            return vscode.DiagnosticSeverity.Warning;
        case 'low':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Hint;
    }
}

/**
 * Show inline decorations for vulnerabilities
 */
function showInlineDecorations(document: vscode.TextDocument, findings: any[]) {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document !== document) {
        return;
    }

    // Create decoration types for different severities
    const criticalDecoration = vscode.window.createTextEditorDecorationType({
        backgroundColor: 'rgba(220, 38, 38, 0.2)',
        border: '1px solid #dc2626'
    });

    const highDecoration = vscode.window.createTextEditorDecorationType({
        backgroundColor: 'rgba(239, 68, 68, 0.15)',
        border: '1px solid #ef4444'
    });

    // Apply decorations
    const criticalRanges: vscode.Range[] = [];
    const highRanges: vscode.Range[] = [];

    findings.forEach(finding => {
        const line = finding.line_number - 1;
        const range = new vscode.Range(line, 0, line, 1000);

        if (finding.severity === 'critical') {
            criticalRanges.push(range);
        } else if (finding.severity === 'high') {
            highRanges.push(range);
        }
    });

    editor.setDecorations(criticalDecoration, criticalRanges);
    editor.setDecorations(highDecoration, highRanges);
}

/**
 * Open security chatbot
 */
async function openSecurityChat() {
    const panel = vscode.window.createWebviewPanel(
        'appsecChat',
        'Security Assistant',
        vscode.ViewColumn.Beside,
        {
            enableScripts: true
        }
    );

    panel.webview.html = getChatWebviewContent();

    // Handle messages from webview
    panel.webview.onDidReceiveMessage(async message => {
        if (message.type === 'chat') {
            const response = await sendChatMessage(message.text);
            panel.webview.postMessage({ type: 'response', text: response });
        }
    });
}

/**
 * Send chat message to backend
 */
async function sendChatMessage(message: string): Promise<string> {
    try {
        const response = await axios.post(`${apiUrl}/api/chat`, {
            message: message
        }, {
            headers: {
                'Authorization': `Bearer ${apiToken}`
            }
        });

        return response.data.response;
    } catch (error) {
        return 'Error communicating with security assistant';
    }
}

/**
 * Auto-fix vulnerability
 */
async function fixVulnerability() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        return;
    }

    const position = editor.selection.active;
    const diagnostics = diagnosticCollection.get(editor.document.uri) || [];

    const diagnostic = diagnostics.find(d => d.range.contains(position));
    if (!diagnostic) {
        vscode.window.showInformationMessage('No vulnerability found at cursor position');
        return;
    }

    // Request fix from backend
    try {
        const response = await axios.post(`${apiUrl}/api/remediate`, {
            code: editor.document.getText(),
            line_number: position.line + 1,
            vulnerability_type: diagnostic.code
        }, {
            headers: {
                'Authorization': `Bearer ${apiToken}`
            }
        });

        const fixedCode = response.data.fixed_code;

        // Apply fix
        const edit = new vscode.WorkspaceEdit();
        edit.replace(
            editor.document.uri,
            diagnostic.range,
            fixedCode
        );

        await vscode.workspace.applyEdit(edit);
        vscode.window.showInformationMessage('Vulnerability fixed!');

    } catch (error) {
        vscode.window.showErrorMessage('Failed to auto-fix vulnerability');
    }
}

/**
 * Document save event handler
 */
function onDocumentSave(document: vscode.TextDocument) {
    const config = vscode.workspace.getConfiguration('appsec');
    if (config.get('scanOnSave', true)) {
        scanDocument(document);
    }
}

/**
 * Document change event handler
 */
function onDocumentChange(event: vscode.TextDocumentChangeEvent) {
    const config = vscode.workspace.getConfiguration('appsec');
    if (config.get('enableRealTimeScanning', true)) {
        // Debounce scanning
        setTimeout(() => {
            scanDocument(event.document);
        }, 1000);
    }
}

/**
 * Get chat webview HTML content
 */
function getChatWebviewContent(): string {
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {
                    padding: 10px;
                    font-family: var(--vscode-font-family);
                }
                #chat-container {
                    height: 80vh;
                    overflow-y: auto;
                    border: 1px solid var(--vscode-panel-border);
                    padding: 10px;
                    margin-bottom: 10px;
                }
                .message {
                    margin: 10px 0;
                    padding: 8px;
                    border-radius: 5px;
                }
                .user-message {
                    background: var(--vscode-input-background);
                    text-align: right;
                }
                .bot-message {
                    background: var(--vscode-editor-background);
                }
                #input-container {
                    display: flex;
                }
                #message-input {
                    flex: 1;
                    padding: 8px;
                    margin-right: 5px;
                }
            </style>
        </head>
        <body>
            <div id="chat-container"></div>
            <div id="input-container">
                <input type="text" id="message-input" placeholder="Ask a security question..." />
                <button onclick="sendMessage()">Send</button>
            </div>

            <script>
                const vscode = acquireVsCodeApi();
                const chatContainer = document.getElementById('chat-container');
                const messageInput = document.getElementById('message-input');

                function sendMessage() {
                    const text = messageInput.value.trim();
                    if (!text) return;

                    addMessage(text, 'user');
                    vscode.postMessage({ type: 'chat', text: text });
                    messageInput.value = '';
                }

                function addMessage(text, type) {
                    const div = document.createElement('div');
                    div.className = 'message ' + type + '-message';
                    div.textContent = text;
                    chatContainer.appendChild(div);
                    chatContainer.scrollTop = chatContainer.scrollHeight;
                }

                window.addEventListener('message', event => {
                    const message = event.data;
                    if (message.type === 'response') {
                        addMessage(message.text, 'bot');
                    }
                });

                messageInput.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') sendMessage();
                });
            </script>
        </body>
        </html>
    `;
}

/**
 * Extension deactivation
 */
export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
}
