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
exports.DiagnosticsManager = void 0;
const vscode = __importStar(require("vscode"));
class DiagnosticsManager {
    constructor() {
        this.findingsMap = new Map();
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('appsec');
    }
    updateFromResults(results) {
        this.clear();
        const allFindings = [];
        if (results.sast?.findings) {
            allFindings.push(...results.sast.findings);
        }
        if (results.secrets?.findings) {
            allFindings.push(...results.secrets.findings);
        }
        this.processFindings(allFindings);
    }
    updateFileFromResults(fileUri, results) {
        const findings = [];
        if (results.sast?.findings) {
            findings.push(...results.sast.findings);
        }
        if (results.secrets?.findings) {
            findings.push(...results.secrets.findings);
        }
        this.findingsMap.set(fileUri.fsPath, findings);
        this.updateDiagnosticsForFile(fileUri, findings);
    }
    processFindings(findings) {
        const fileMap = new Map();
        for (const finding of findings) {
            const filePath = finding.file;
            if (!fileMap.has(filePath)) {
                fileMap.set(filePath, []);
            }
            fileMap.get(filePath).push(finding);
        }
        fileMap.forEach((findings, filePath) => {
            this.findingsMap.set(filePath, findings);
            const fileUri = vscode.Uri.file(filePath);
            this.updateDiagnosticsForFile(fileUri, findings);
        });
    }
    updateDiagnosticsForFile(fileUri, findings) {
        const diagnostics = findings.map(finding => {
            const line = Math.max(0, (finding.line || 1) - 1);
            const range = new vscode.Range(new vscode.Position(line, 0), new vscode.Position(line, 999));
            const diagnostic = new vscode.Diagnostic(range, `[${finding.severity.toUpperCase()}] ${finding.title}: ${finding.description}`, this.getSeverityLevel(finding.severity));
            diagnostic.source = 'AppSec AI Scanner';
            diagnostic.code = finding.cwe_id || finding.category;
            return diagnostic;
        });
        this.diagnosticCollection.set(fileUri, diagnostics);
    }
    getSeverityLevel(severity) {
        const severityMap = {
            'critical': vscode.DiagnosticSeverity.Error,
            'high': vscode.DiagnosticSeverity.Error,
            'medium': vscode.DiagnosticSeverity.Warning,
            'low': vscode.DiagnosticSeverity.Information
        };
        return severityMap[severity.toLowerCase()] || vscode.DiagnosticSeverity.Warning;
    }
    removeFinding(finding) {
        const filePath = finding.file;
        const findings = this.findingsMap.get(filePath) || [];
        const updatedFindings = findings.filter(f => f.id !== finding.id);
        this.findingsMap.set(filePath, updatedFindings);
        const fileUri = vscode.Uri.file(filePath);
        this.updateDiagnosticsForFile(fileUri, updatedFindings);
    }
    clear() {
        this.diagnosticCollection.clear();
        this.findingsMap.clear();
    }
    dispose() {
        this.diagnosticCollection.dispose();
    }
}
exports.DiagnosticsManager = DiagnosticsManager;
//# sourceMappingURL=diagnosticsManager.js.map