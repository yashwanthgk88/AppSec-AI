"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.ChatbotPanel = void 0;
const vscode = __importStar(require("vscode"));
class ChatbotPanel {
    constructor(panel, apiClient) {
        this.apiClient = apiClient;
        this.disposables = [];
        this.messages = [];
        this.panel = panel;
        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
        this.panel.webview.onDidReceiveMessage(async (message) => {
            if (message.command === 'sendMessage') {
                await this.handleUserMessage(message.text);
            }
        }, null, this.disposables);
    }
    static show(apiClient, vulnerabilityContext) {
        const column = vscode.ViewColumn.Two;
        if (ChatbotPanel.currentPanel) {
            ChatbotPanel.currentPanel.panel.reveal(column);
            // If context provided, add it to the chat
            if (vulnerabilityContext) {
                ChatbotPanel.currentPanel.loadVulnerabilityContext(vulnerabilityContext);
            }
        }
        else {
            const panel = vscode.window.createWebviewPanel('appSecChatbot', 'AppSec AI Assistant', column, {
                enableScripts: true,
                retainContextWhenHidden: true
            });
            ChatbotPanel.currentPanel = new ChatbotPanel(panel, apiClient);
            // If context provided, add it to the chat before showing
            if (vulnerabilityContext) {
                ChatbotPanel.currentPanel.loadVulnerabilityContext(vulnerabilityContext);
            }
            ChatbotPanel.currentPanel.update();
        }
    }
    update() {
        this.panel.webview.html = this.getHtmlContent();
    }
    async loadVulnerabilityContext(vulnerability) {
        try {
            // Read the vulnerable code snippet from the file
            const document = await vscode.workspace.openTextDocument(vulnerability.file);
            const lineNumber = vulnerability.line - 1; // Convert to 0-indexed
            // Get 5 lines before and after the vulnerable line for context
            const startLine = Math.max(0, lineNumber - 5);
            const endLine = Math.min(document.lineCount - 1, lineNumber + 5);
            let codeSnippet = '';
            for (let i = startLine; i <= endLine; i++) {
                const lineText = document.lineAt(i).text;
                const linePrefix = i === lineNumber ? '>>> ' : '    '; // Mark vulnerable line
                codeSnippet += `${linePrefix}${i + 1}: ${lineText}\n`;
            }
            // Create a detailed context message
            const contextMessage = `I found a **${vulnerability.severity}** severity vulnerability in my code and need your help:

**Vulnerability:** ${vulnerability.title}
**File:** ${vulnerability.file}:${vulnerability.line}
**Category:** ${vulnerability.category || vulnerability.owasp_category || 'N/A'}
${vulnerability.cwe_id ? `**CWE:** ${vulnerability.cwe_id}` : ''}

**Description:** ${vulnerability.description || 'No description available'}

**Vulnerable Code Snippet:**
\`\`\`
${codeSnippet}\`\`\`

Can you help me understand this vulnerability better and suggest the best way to fix it?`;
            // Add the context as a user message
            this.messages.push({ role: 'user', content: contextMessage });
            this.update();
            // Get AI response
            const response = await this.apiClient.sendChatMessage(contextMessage);
            this.messages.push({ role: 'assistant', content: response.response });
            this.update();
        }
        catch (error) {
            vscode.window.showErrorMessage('Failed to load vulnerability context: ' + error.message);
        }
    }
    async handleUserMessage(userMessage) {
        this.messages.push({ role: 'user', content: userMessage });
        this.update();
        try {
            const response = await this.apiClient.sendChatMessage(userMessage);
            this.messages.push({ role: 'assistant', content: response.response });
            this.update();
        }
        catch (error) {
            this.messages.push({ role: 'assistant', content: 'Sorry, I encountered an error: ' + error.message });
            this.update();
        }
    }
    getHtmlContent() {
        const messagesHtml = this.messages.map(msg => {
            const isUser = msg.role === 'user';
            const avatar = isUser ? '👤' : '🤖';
            const timestamp = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
            return `<div class="message-wrapper ${isUser ? 'user-wrapper' : 'assistant-wrapper'}">
                <div class="message ${isUser ? 'user' : 'assistant'}">
                    <div class="message-header">
                        <span class="avatar">${avatar}</span>
                        <span class="sender">${isUser ? 'You' : 'AppSec AI'}</span>
                        <span class="timestamp">${timestamp}</span>
                    </div>
                    <div class="message-content">${this.formatMessage(msg.content)}</div>
                </div>
            </div>`;
        }).join('');
        const placeholderMessages = this.messages.length === 0 ? `
            <div class="empty-state">
                <div class="robot-icon">🛡️</div>
                <h3>AppSec AI Assistant</h3>
                <p>Ask me anything about security vulnerabilities, best practices, or code remediation!</p>
                <div class="suggestions">
                    <button class="suggestion" onclick="sendSuggestion('How do I fix SQL injection vulnerabilities?')">
                        💉 SQL Injection Help
                    </button>
                    <button class="suggestion" onclick="sendSuggestion('Explain OWASP Top 10')">
                        📚 OWASP Top 10
                    </button>
                    <button class="suggestion" onclick="sendSuggestion('Best practices for secure authentication')">
                        🔐 Authentication Security
                    </button>
                    <button class="suggestion" onclick="sendSuggestion('How to prevent XSS attacks?')">
                        🛡️ XSS Prevention
                    </button>
                </div>
            </div>
        ` : messagesHtml;
        return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .chat-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            background: white;
            margin: 20px;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .chat-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .chat-header h2 {
            font-size: 20px;
            font-weight: 600;
            margin: 0;
        }
        .chat-header .status {
            font-size: 12px;
            opacity: 0.9;
        }
        .messages {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            background: #f8f9fa;
            scroll-behavior: smooth;
        }
        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: #6b7280;
        }
        .robot-icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        .empty-state h3 {
            font-size: 24px;
            margin-bottom: 10px;
            color: #1f2937;
        }
        .empty-state p {
            font-size: 16px;
            margin-bottom: 30px;
        }
        .suggestions {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            max-width: 600px;
            margin: 0 auto;
        }
        .suggestion {
            padding: 12px 16px;
            background: white;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            text-align: left;
            transition: all 0.2s;
        }
        .suggestion:hover {
            border-color: #667eea;
            background: #f3f4f6;
            transform: translateY(-2px);
        }
        .message-wrapper {
            display: flex;
            margin-bottom: 16px;
            animation: slideIn 0.3s ease-out;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .user-wrapper { justify-content: flex-end; }
        .message {
            max-width: 70%;
            padding: 12px 16px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .message.user {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-bottom-right-radius: 4px;
        }
        .message.assistant {
            background: white;
            border: 1px solid #e5e7eb;
            border-bottom-left-radius: 4px;
        }
        .message-header {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 8px;
            font-size: 12px;
            opacity: 0.9;
        }
        .message.user .message-header {
            color: rgba(255,255,255,0.9);
        }
        .message.assistant .message-header {
            color: #6b7280;
        }
        .avatar {
            font-size: 16px;
        }
        .sender {
            font-weight: 600;
        }
        .timestamp {
            margin-left: auto;
            font-size: 11px;
        }
        .message-content {
            line-height: 1.6;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .message.assistant .message-content {
            color: #1f2937;
        }
        .message-content code {
            background: #f3f4f6;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        .message-content pre {
            background: #1f2937;
            color: #f3f4f6;
            padding: 12px;
            border-radius: 8px;
            overflow-x: auto;
            margin: 8px 0;
        }
        .message-content pre code {
            background: transparent;
            padding: 0;
            color: #f3f4f6;
        }
        .input-area {
            display: flex;
            gap: 12px;
            padding: 20px;
            background: white;
            border-top: 1px solid #e5e7eb;
        }
        .input-area input {
            flex: 1;
            padding: 14px 16px;
            border: 2px solid #e5e7eb;
            border-radius: 24px;
            font-size: 14px;
            transition: border-color 0.2s;
        }
        .input-area input:focus {
            outline: none;
            border-color: #667eea;
        }
        .input-area button {
            padding: 14px 28px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 24px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .input-area button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        .input-area button:active {
            transform: translateY(0);
        }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #f1f1f1; }
        ::-webkit-scrollbar-thumb { background: #667eea; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #764ba2; }
    </style>
</head>
<body>
    <div class="chat-container">
        <div class="chat-header">
            <span style="font-size: 24px;">🛡️</span>
            <div style="flex: 1;">
                <h2>AppSec AI Assistant</h2>
                <div class="status">● Online - Ready to help</div>
            </div>
        </div>
        <div class="messages" id="messages">${placeholderMessages}</div>
        <div class="input-area">
            <input type="text" id="userInput" placeholder="Ask me anything about security..." />
            <button onclick="sendMessage()">Send 🚀</button>
        </div>
    </div>
    <script>
        const vscode = acquireVsCodeApi();

        function sendMessage() {
            const input = document.getElementById('userInput');
            const text = input.value.trim();
            if (text) {
                vscode.postMessage({command: 'sendMessage', text: text});
                input.value = '';
                scrollToBottom();
            }
        }

        function sendSuggestion(text) {
            vscode.postMessage({command: 'sendMessage', text: text});
            scrollToBottom();
        }

        function scrollToBottom() {
            const messages = document.getElementById('messages');
            setTimeout(() => {
                messages.scrollTop = messages.scrollHeight;
            }, 100);
        }

        document.getElementById('userInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendMessage();
        });

        // Auto scroll on load
        scrollToBottom();
    </script>
</body>
</html>`;
    }
    formatMessage(content) {
        // Escape HTML first
        let formatted = content
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
        // Format code blocks (```code```)
        formatted = formatted.replace(/```([^`]+)```/g, '<pre><code>$1</code></pre>');
        // Format inline code (`code`)
        formatted = formatted.replace(/`([^`]+)`/g, '<code>$1</code>');
        // Format bold (**text**)
        formatted = formatted.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        return formatted;
    }
    escapeHtml(text) {
        return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    dispose() {
        ChatbotPanel.currentPanel = undefined;
        this.panel.dispose();
        while (this.disposables.length) {
            const disposable = this.disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }
}
exports.ChatbotPanel = ChatbotPanel;
//# sourceMappingURL=chatbotPanel.js.map