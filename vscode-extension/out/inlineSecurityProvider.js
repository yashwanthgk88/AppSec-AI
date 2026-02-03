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
            // Code Injection
            {
                pattern: /eval\s*\(/gi,
                message: '⚠️ Security: Using eval() can lead to code injection vulnerabilities',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Consider using JSON.parse() for data or alternative safe methods'
            },
            {
                pattern: /new\s+Function\s*\(/gi,
                message: '⚠️ Security: new Function() can lead to code injection like eval()',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Avoid dynamic code execution, use safer alternatives'
            },
            {
                pattern: /setTimeout\s*\(\s*['"`]/gi,
                message: '⚠️ Security: setTimeout with string argument acts like eval()',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Pass a function reference instead of a string'
            },
            {
                pattern: /setInterval\s*\(\s*['"`]/gi,
                message: '⚠️ Security: setInterval with string argument acts like eval()',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Pass a function reference instead of a string'
            },
            // XSS Vulnerabilities
            {
                pattern: /innerHTML\s*=/gi,
                message: '⚠️ Security: innerHTML can lead to XSS vulnerabilities',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Use textContent or createElement() instead'
            },
            {
                pattern: /outerHTML\s*=/gi,
                message: '⚠️ Security: outerHTML can lead to XSS vulnerabilities',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Use textContent or safe DOM methods instead'
            },
            {
                pattern: /document\.write\s*\(/gi,
                message: '⚠️ Security: document.write() can cause XSS vulnerabilities',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Use modern DOM manipulation methods'
            },
            {
                pattern: /\.insertAdjacentHTML\s*\(/gi,
                message: '⚠️ Security: insertAdjacentHTML can lead to XSS if input is not sanitized',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Sanitize input or use insertAdjacentText instead'
            },
            {
                pattern: /dangerouslySetInnerHTML/gi,
                message: '⚠️ Security: dangerouslySetInnerHTML can lead to XSS',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Ensure content is properly sanitized with DOMPurify'
            },
            {
                pattern: /v-html\s*=/gi,
                message: '⚠️ Security: v-html directive can lead to XSS in Vue.js',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Use v-text or sanitize the content first'
            },
            {
                pattern: /\[innerHTML\]\s*=/gi,
                message: '⚠️ Security: [innerHTML] binding can lead to XSS in Angular',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Use DomSanitizer or text interpolation instead'
            },
            // Command Injection
            {
                pattern: /exec\s*\(/gi,
                message: '⚠️ Security: exec() can lead to command injection attacks',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use execFile() with arguments array, validate all inputs'
            },
            {
                pattern: /spawn\s*\(/gi,
                message: '⚠️ Security: spawn() requires careful input validation',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Validate and sanitize all inputs, use shell: false'
            },
            {
                pattern: /child_process/gi,
                message: '⚠️ Security: child_process module requires careful handling',
                severity: vscode.DiagnosticSeverity.Information,
                suggestion: 'Ensure all inputs are validated before execution'
            },
            {
                pattern: /os\.system\s*\(/gi,
                message: '⚠️ Security: os.system() is vulnerable to command injection',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use subprocess.run() with shell=False and list arguments'
            },
            {
                pattern: /subprocess\.call\s*\([^,\]]*,\s*shell\s*=\s*True/gi,
                message: '⚠️ Security: subprocess with shell=True is vulnerable to injection',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use shell=False and pass arguments as a list'
            },
            {
                pattern: /Runtime\.getRuntime\(\)\.exec/gi,
                message: '⚠️ Security: Runtime.exec() can be vulnerable to command injection',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use ProcessBuilder with separate arguments, validate inputs'
            },
            // Hardcoded Credentials
            {
                pattern: /(password|passwd|pwd)\s*[=:]\s*['"`][^'"`]{3,}['"`]/gi,
                message: '🔒 Security: Hardcoded password detected',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use environment variables or secure credential storage'
            },
            {
                pattern: /(secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token)\s*[=:]\s*['"`][^'"`]{8,}['"`]/gi,
                message: '🔒 Security: Hardcoded secret/API key detected',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use environment variables or a secrets manager'
            },
            {
                pattern: /(aws[_-]?secret|aws[_-]?key|AKIA[A-Z0-9]{16})/gi,
                message: '🔒 Security: AWS credentials detected',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use IAM roles or AWS Secrets Manager'
            },
            {
                pattern: /private[_-]?key\s*[=:]\s*['"`]-----BEGIN/gi,
                message: '🔒 Security: Private key detected in code',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Store private keys in secure key management systems'
            },
            {
                pattern: /Bearer\s+[a-zA-Z0-9_-]{20,}/gi,
                message: '🔒 Security: Bearer token detected in code',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Never hardcode authentication tokens'
            },
            // SQL Injection
            {
                pattern: /['"]\s*\+\s*\w+\s*\+\s*['"].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)/gi,
                message: '⚠️ Security: Possible SQL injection - string concatenation in query',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use parameterized queries or prepared statements'
            },
            {
                pattern: /(?:SELECT|INSERT|UPDATE|DELETE).*\$\{/gi,
                message: '⚠️ Security: Possible SQL injection - template literal in query',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use parameterized queries instead of template literals'
            },
            {
                pattern: /(?:SELECT|INSERT|UPDATE|DELETE).*%s/gi,
                message: '⚠️ Security: Possible SQL injection - string formatting in query',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use parameterized queries with placeholders (? or $1)'
            },
            {
                pattern: /f["'](?:SELECT|INSERT|UPDATE|DELETE)/gi,
                message: '⚠️ Security: Possible SQL injection - f-string in Python query',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use parameterized queries with cursor.execute(query, params)'
            },
            {
                pattern: /\.format\s*\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
                message: '⚠️ Security: Possible SQL injection - .format() in query',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use parameterized queries instead of string formatting'
            },
            // Weak Cryptography
            {
                pattern: /md5\s*\(/gi,
                message: '⚠️ Security: MD5 is cryptographically broken',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Use SHA-256 or bcrypt for password hashing'
            },
            {
                pattern: /sha1\s*\(/gi,
                message: '⚠️ Security: SHA-1 is deprecated and weak',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Use SHA-256 or stronger algorithms'
            },
            {
                pattern: /DES|3DES|RC4|RC2/gi,
                message: '⚠️ Security: Weak/deprecated encryption algorithm',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Use AES-256-GCM for encryption'
            },
            {
                pattern: /ECB/gi,
                message: '⚠️ Security: ECB mode is insecure for encryption',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Use CBC, GCM, or CTR mode instead'
            },
            {
                pattern: /Math\.random\s*\(/gi,
                message: '⚠️ Security: Math.random() is not cryptographically secure',
                severity: vscode.DiagnosticSeverity.Information,
                suggestion: 'Use crypto.getRandomValues() for security-sensitive operations'
            },
            // Path Traversal
            {
                pattern: /\.\.\/|\.\.\\|%2e%2e/gi,
                message: '⚠️ Security: Path traversal pattern detected',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Validate and sanitize file paths, use path.resolve()'
            },
            // Insecure Deserialization
            {
                pattern: /pickle\.loads?\s*\(/gi,
                message: '⚠️ Security: pickle deserialization can execute arbitrary code',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use JSON or other safe serialization formats'
            },
            {
                pattern: /yaml\.load\s*\([^)]*\)/gi,
                message: '⚠️ Security: yaml.load() can execute arbitrary code',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use yaml.safe_load() instead'
            },
            {
                pattern: /unserialize\s*\(/gi,
                message: '⚠️ Security: unserialize() can lead to object injection',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Use JSON encoding or validate serialized data'
            },
            // Insecure Configuration
            {
                pattern: /verify\s*[=:]\s*false|verify_ssl\s*[=:]\s*false|ssl[_-]?verify\s*[=:]\s*false/gi,
                message: '🔒 Security: SSL/TLS verification disabled',
                severity: vscode.DiagnosticSeverity.Error,
                suggestion: 'Enable SSL verification to prevent MITM attacks'
            },
            {
                pattern: /CORS.*\*|Access-Control-Allow-Origin.*\*/gi,
                message: '⚠️ Security: Wildcard CORS configuration',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Restrict CORS to specific trusted origins'
            },
            {
                pattern: /debug\s*[=:]\s*true|DEBUG\s*[=:]\s*True/gi,
                message: '⚠️ Security: Debug mode should be disabled in production',
                severity: vscode.DiagnosticSeverity.Information,
                suggestion: 'Set debug=False in production environments'
            },
            // XXE (XML External Entities)
            {
                pattern: /<!ENTITY/gi,
                message: '⚠️ Security: External entity declaration may lead to XXE',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Disable external entity processing in XML parser'
            },
            // SSRF Indicators
            {
                pattern: /requests\.get\s*\(\s*[^'"`]*\+|fetch\s*\(\s*[^'"`]*\+|urllib.*\+/gi,
                message: '⚠️ Security: Dynamic URL construction may lead to SSRF',
                severity: vscode.DiagnosticSeverity.Warning,
                suggestion: 'Validate and whitelist allowed URLs/domains'
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