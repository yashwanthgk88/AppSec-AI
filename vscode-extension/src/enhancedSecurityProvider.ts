/**
 * Enhanced Security Provider
 *
 * Provides real-time security analysis using the AST-based scanner
 * for VS Code inline diagnostics.
 */

import * as vscode from 'vscode';
import {
    SecurityScanner,
    createSecurityScanner,
    SecurityFinding,
    SupportedLanguage
} from './scanner';

export class EnhancedSecurityProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    private scanner: SecurityScanner;
    private diagnosticCollection: vscode.DiagnosticCollection;
    private debounceTimers: Map<string, NodeJS.Timeout> = new Map();
    private readonly DEBOUNCE_DELAY = 500; // ms

    // Mapping from file extensions to supported languages
    private readonly extensionToLanguage: Record<string, SupportedLanguage> = {
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.py': 'python',
        '.java': 'java',
        '.cs': 'csharp',
        '.php': 'php',
        '.kt': 'kotlin',
        '.m': 'objectivec',
        '.swift': 'swift',
        '.go': 'go',
        '.rb': 'ruby'
    };

    constructor() {
        this.scanner = createSecurityScanner({
            enableTaintAnalysis: true,
            enableCFGAnalysis: true,
            enableDFGAnalysis: true,
            enablePatternMatching: true
        });
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('appsec-enhanced');
    }

    /**
     * Analyze a document and update diagnostics
     */
    async analyzeDocument(document: vscode.TextDocument): Promise<void> {
        // Check if we support this language
        const ext = this.getFileExtension(document.uri.fsPath);
        if (!this.extensionToLanguage[ext]) {
            return;
        }

        // Debounce analysis
        const uri = document.uri.toString();
        if (this.debounceTimers.has(uri)) {
            clearTimeout(this.debounceTimers.get(uri)!);
        }

        this.debounceTimers.set(uri, setTimeout(async () => {
            await this.performAnalysis(document);
            this.debounceTimers.delete(uri);
        }, this.DEBOUNCE_DELAY));
    }

    private async performAnalysis(document: vscode.TextDocument): Promise<void> {
        try {
            const source = document.getText();
            const filePath = document.uri.fsPath;

            const result = await this.scanner.scanFile(source, filePath);
            if (!result) {
                return;
            }

            // Convert findings to VS Code diagnostics
            const diagnostics = result.findings.map(finding =>
                this.findingToDiagnostic(finding, document)
            );

            this.diagnosticCollection.set(document.uri, diagnostics);

        } catch (error) {
            console.error('Enhanced security analysis error:', error);
        }
    }

    /**
     * Convert a SecurityFinding to a VS Code Diagnostic
     */
    private findingToDiagnostic(finding: SecurityFinding, document: vscode.TextDocument): vscode.Diagnostic {
        const range = new vscode.Range(
            finding.location.startLine - 1,
            finding.location.startColumn,
            finding.location.endLine - 1,
            finding.location.endColumn
        );

        const severity = this.mapSeverity(finding.severity);

        const diagnostic = new vscode.Diagnostic(
            range,
            this.formatDiagnosticMessage(finding),
            severity
        );

        diagnostic.source = 'SecureDev AI (Enhanced)';
        if (finding.cweId) {
            diagnostic.code = {
                value: finding.cweId,
                target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${finding.cweId.replace('CWE-', '')}.html`)
            };
        } else {
            diagnostic.code = finding.type;
        }

        // Add related information for taint flows
        if (finding.taintFlow) {
            diagnostic.relatedInformation = finding.taintFlow.path.map(node => {
                const relatedRange = new vscode.Range(
                    node.location.startLine - 1,
                    node.location.startColumn,
                    node.location.endLine - 1,
                    node.location.endColumn
                );

                return new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(document.uri, relatedRange),
                    node.description
                );
            });
        }

        return diagnostic;
    }

    private formatDiagnosticMessage(finding: SecurityFinding): string {
        const lines: string[] = [];

        // Title with severity icon
        const icon = this.getSeverityIcon(finding.severity);
        lines.push(`${icon} ${finding.title}`);

        // CWE and OWASP
        if (finding.cweId) {
            lines.push(`CWE: ${finding.cweId}`);
        }
        if (finding.owaspCategory) {
            lines.push(`OWASP: ${finding.owaspCategory}`);
        }

        // Recommendation
        lines.push('');
        lines.push(`💡 ${finding.recommendation}`);

        return lines.join('\n');
    }

    private getSeverityIcon(severity: string): string {
        const icons: Record<string, string> = {
            critical: '🔴',
            high: '🟠',
            medium: '🟡',
            low: '🔵',
            info: 'ℹ️'
        };
        return icons[severity] || '⚠️';
    }

    private mapSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity) {
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

    private getFileExtension(filePath: string): string {
        const match = filePath.match(/\.[^.]+$/);
        return match ? match[0] : '';
    }

    /**
     * Provide code actions for diagnostics
     */
    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source?.includes('SecureDev AI')) {
                // Add "Learn More" action
                const learnMore = new vscode.CodeAction(
                    '📚 Learn more about this vulnerability',
                    vscode.CodeActionKind.QuickFix
                );
                learnMore.diagnostics = [diagnostic];
                learnMore.isPreferred = false;

                if (diagnostic.code && typeof diagnostic.code === 'object' && diagnostic.code.target) {
                    learnMore.command = {
                        command: 'vscode.open',
                        title: 'Open CWE Reference',
                        arguments: [diagnostic.code.target]
                    };
                }

                actions.push(learnMore);

                // Add "Discuss with AI" action
                const discussAI = new vscode.CodeAction(
                    '🤖 Discuss with AI assistant',
                    vscode.CodeActionKind.QuickFix
                );
                discussAI.diagnostics = [diagnostic];
                discussAI.command = {
                    command: 'appsec.openChatbot',
                    title: 'Open AI Assistant',
                    arguments: []
                };
                actions.push(discussAI);

                // Add "Mark as False Positive" action
                const markFP = new vscode.CodeAction(
                    '❌ Mark as false positive',
                    vscode.CodeActionKind.QuickFix
                );
                markFP.diagnostics = [diagnostic];
                // This would integrate with your backend to track false positives
                actions.push(markFP);
            }
        }

        return actions;
    }

    /**
     * Clear diagnostics for a document
     */
    clearDiagnostics(document: vscode.TextDocument): void {
        this.diagnosticCollection.delete(document.uri);
    }

    /**
     * Clear all diagnostics
     */
    clearAll(): void {
        this.diagnosticCollection.clear();
    }

    /**
     * Dispose resources
     */
    dispose(): void {
        this.diagnosticCollection.dispose();
        for (const timer of this.debounceTimers.values()) {
            clearTimeout(timer);
        }
    }
}

/**
 * Quick Analysis Result for status updates
 */
export interface QuickAnalysisResult {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    analysisTime: number;
}

/**
 * Get a quick summary of analysis results
 */
export function getAnalysisSummary(findings: SecurityFinding[]): QuickAnalysisResult {
    return {
        totalFindings: findings.length,
        criticalCount: findings.filter(f => f.severity === 'critical').length,
        highCount: findings.filter(f => f.severity === 'high').length,
        mediumCount: findings.filter(f => f.severity === 'medium').length,
        lowCount: findings.filter(f => f.severity === 'low').length,
        analysisTime: 0
    };
}
