import * as vscode from 'vscode';

export class DiagnosticsManager {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private findingsMap: Map<string, any[]> = new Map();

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('appsec');
    }

    updateFromResults(results: any): void {
        this.clear();

        const allFindings: any[] = [];

        if (results.sast?.findings) {
            allFindings.push(...results.sast.findings);
        }
        if (results.secrets?.findings) {
            allFindings.push(...results.secrets.findings);
        }

        this.processFindings(allFindings);
    }

    updateFileFromResults(fileUri: vscode.Uri, results: any): void {
        const findings: any[] = [];

        if (results.sast?.findings) {
            findings.push(...results.sast.findings);
        }
        if (results.secrets?.findings) {
            findings.push(...results.secrets.findings);
        }

        this.findingsMap.set(fileUri.fsPath, findings);
        this.updateDiagnosticsForFile(fileUri, findings);
    }

    private processFindings(findings: any[]): void {
        const fileMap: Map<string, any[]> = new Map();

        for (const finding of findings) {
            const filePath = finding.file;
            if (!fileMap.has(filePath)) {
                fileMap.set(filePath, []);
            }
            fileMap.get(filePath)!.push(finding);
        }

        fileMap.forEach((findings, filePath) => {
            this.findingsMap.set(filePath, findings);
            const fileUri = vscode.Uri.file(filePath);
            this.updateDiagnosticsForFile(fileUri, findings);
        });
    }

    private updateDiagnosticsForFile(fileUri: vscode.Uri, findings: any[]): void {
        const diagnostics: vscode.Diagnostic[] = findings.map(finding => {
            const line = Math.max(0, (finding.line || 1) - 1);
            const range = new vscode.Range(
                new vscode.Position(line, 0),
                new vscode.Position(line, 999)
            );

            const diagnostic = new vscode.Diagnostic(
                range,
                `[${finding.severity.toUpperCase()}] ${finding.title}: ${finding.description}`,
                this.getSeverityLevel(finding.severity)
            );

            diagnostic.source = 'AppSec AI Scanner';
            diagnostic.code = finding.cwe_id || finding.category;

            return diagnostic;
        });

        this.diagnosticCollection.set(fileUri, diagnostics);
    }

    private getSeverityLevel(severity: string): vscode.DiagnosticSeverity {
        const severityMap: { [key: string]: vscode.DiagnosticSeverity } = {
            'critical': vscode.DiagnosticSeverity.Error,
            'high': vscode.DiagnosticSeverity.Error,
            'medium': vscode.DiagnosticSeverity.Warning,
            'low': vscode.DiagnosticSeverity.Information
        };

        return severityMap[severity.toLowerCase()] || vscode.DiagnosticSeverity.Warning;
    }

    removeFinding(finding: any): void {
        const filePath = finding.file;
        const findings = this.findingsMap.get(filePath) || [];
        const updatedFindings = findings.filter(f => f.id !== finding.id);

        this.findingsMap.set(filePath, updatedFindings);

        const fileUri = vscode.Uri.file(filePath);
        this.updateDiagnosticsForFile(fileUri, updatedFindings);
    }

    clear(): void {
        this.diagnosticCollection.clear();
        this.findingsMap.clear();
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}
