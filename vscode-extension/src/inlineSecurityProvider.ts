import * as vscode from 'vscode';

export class InlineSecurityProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    private securityPatterns = [
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

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const codeActions: vscode.CodeAction[] = [];

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

    private createFix(
        document: vscode.TextDocument,
        range: vscode.Range,
        diagnostic: vscode.Diagnostic
    ): vscode.CodeAction | undefined {
        const fix = new vscode.CodeAction(
            'View security suggestion',
            vscode.CodeActionKind.QuickFix
        );
        fix.diagnostics = [diagnostic];
        fix.isPreferred = true;

        return fix;
    }

    public analyzeLine(line: string, lineNumber: number): vscode.Diagnostic[] {
        const diagnostics: vscode.Diagnostic[] = [];

        for (const pattern of this.securityPatterns) {
            const matches = line.matchAll(pattern.pattern);
            for (const match of matches) {
                if (match.index !== undefined) {
                    const start = new vscode.Position(lineNumber, match.index);
                    const end = new vscode.Position(lineNumber, match.index + match[0].length);
                    const range = new vscode.Range(start, end);

                    const diagnostic = new vscode.Diagnostic(
                        range,
                        `${pattern.message}\n💡 ${pattern.suggestion}`,
                        pattern.severity
                    );
                    diagnostic.source = 'appsec-inline';
                    diagnostic.code = 'security-pattern';

                    diagnostics.push(diagnostic);
                }
            }
        }

        return diagnostics;
    }

    public analyzeDocument(document: vscode.TextDocument): vscode.Diagnostic[] {
        const diagnostics: vscode.Diagnostic[] = [];

        for (let i = 0; i < document.lineCount; i++) {
            const line = document.lineAt(i).text;
            const lineDiagnostics = this.analyzeLine(line, i);
            diagnostics.push(...lineDiagnostics);
        }

        return diagnostics;
    }
}
