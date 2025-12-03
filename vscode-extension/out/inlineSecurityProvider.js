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
exports.InlineSecurityProvider = void 0;
const vscode = __importStar(require("vscode"));
class InlineSecurityProvider {
    constructor() {
        this.securityPatterns = [
            {
                pattern: /eval\s*\(/gi,
                message: '⚠️ Security: Using eval() can lead to code injection vulnerabilities',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Consider using JSON.parse() for data or alternative safe methods'
            },
            {
                pattern: /innerHTML\s*=/gi,
                message: '⚠️ Security: innerHTML can lead to XSS vulnerabilities',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Use textContent or createElement() instead'
            },
            {
                pattern: /document\.write\s*\(/gi,
                message: '⚠️ Security: document.write() can cause XSS vulnerabilities',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Use modern DOM manipulation methods'
            },
            {
                pattern: /exec\s*\(|spawn\s*\(/gi,
                message: '⚠️ Security: Command execution can lead to injection attacks',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Validate and sanitize all inputs before executing commands'
            },
            {
                pattern: /(password|secret|api[_-]?key)\s*=\s*['"][^'"]+['"]/gi,
                message: '🔒 Security: Hardcoded credentials detected',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use environment variables or secure credential storage'
            },
            {
                pattern: /SELECT\s+.*FROM.*WHERE.*\+|SELECT\s+.*FROM.*WHERE.*\$\{/gi,
                message: '⚠️ Security: Possible SQL injection vulnerability',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use parameterized queries or prepared statements'
            },
            {
                pattern: /md5\s*\(|sha1\s*\(/gi,
                message: '⚠️ Security: Weak cryptographic algorithm (MD5/SHA1)',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Use SHA-256 or stronger algorithms'
            },
            {
                pattern: /dangerouslySetInnerHTML/gi,
                message: '⚠️ Security: dangerouslySetInnerHTML can lead to XSS',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Ensure content is properly sanitized'
            }
        ];
    }
    provideCodeActions(document, range, context, token) {
        const codeActions = [];
        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source === 'appsec-inline') {
                const fix = this.createFix(document, range, diagnostic);
                if (fix) {
                    codeActions.push(fix);
                }
            }
        }
        return codeActions;
    }
    createFix(document, range, diagnostic) {
        const fix = new vscode.CodeAction('View security suggestion', vscode.CodeActionKind.QuickFix);
        fix.diagnostics = [diagnostic];
        fix.isPreferred = true;
        return fix;
    }
    analyzeLine(line, lineNumber) {
        const diagnostics = [];
        for (const pattern of this.securityPatterns) {
            const matches = line.matchAll(pattern.pattern);
            for (const match of matches) {
                if (match.index !== undefined) {
                    const start = new vscode.Position(lineNumber, match.index);
                    const end = new vscode.Position(lineNumber, match.index + match[0].length);
                    const range = new vscode.Range(start, end);
                    const diagnostic = new vscode.Diagnostic(range, `${pattern.message}\n💡 ${pattern.suggestion}`, pattern.severity);
                    diagnostic.source = 'appsec-inline';
                    diagnostic.code = 'security-pattern';
                    diagnostics.push(diagnostic);
                }
            }
        }
        return diagnostics;
    }
    analyzeDocument(document) {
        const diagnostics = [];
        for (let i = 0; i < document.lineCount; i++) {
            const line = document.lineAt(i).text;
            const lineDiagnostics = this.analyzeLine(line, i);
            diagnostics.push(...lineDiagnostics);
        }
        return diagnostics;
    }
}
exports.InlineSecurityProvider = InlineSecurityProvider;
InlineSecurityProvider.providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix
];
//# sourceMappingURL=inlineSecurityProvider.js.map