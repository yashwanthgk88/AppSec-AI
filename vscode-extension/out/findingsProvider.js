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
exports.FindingsProvider = void 0;
const vscode = __importStar(require("vscode"));
class FindingsProvider {
    constructor(apiClient) {
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.findings = [];
        this.apiClient = apiClient;
    }
    refresh() {
        this._onDidChangeTreeData.fire();
    }
    setFindings(findings) {
        this.findings = findings;
        this.refresh();
    }
    getAllFindings() {
        return this.findings;
    }
    getTreeItem(element) {
        return element;
    }
    async getChildren(element) {
        if (!await this.apiClient.isAuthenticated()) {
            return [];
        }
        if (!element) {
            // Update counts for each severity
            const criticalCount = this.findings.filter(f => f.severity.toLowerCase() === 'critical').length;
            const highCount = this.findings.filter(f => f.severity.toLowerCase() === 'high').length;
            const mediumCount = this.findings.filter(f => f.severity.toLowerCase() === 'medium').length;
            const lowCount = this.findings.filter(f => f.severity.toLowerCase() === 'low').length;
            return [
                new FindingItem(`Critical (${criticalCount})`, vscode.TreeItemCollapsibleState.Expanded, 'category', 'critical'),
                new FindingItem(`High (${highCount})`, vscode.TreeItemCollapsibleState.Expanded, 'category', 'high'),
                new FindingItem(`Medium (${mediumCount})`, vscode.TreeItemCollapsibleState.Collapsed, 'category', 'medium'),
                new FindingItem(`Low (${lowCount})`, vscode.TreeItemCollapsibleState.Collapsed, 'category', 'low')
            ];
        }
        if (element.contextValue === 'category') {
            const severityLabel = element.label.split('(')[0].trim();
            return this.getFindingsByCategory(severityLabel);
        }
        return [];
    }
    getRootCategories() {
        return [
            new FindingItem('Critical', vscode.TreeItemCollapsibleState.Collapsed, 'category', 'critical'),
            new FindingItem('High', vscode.TreeItemCollapsibleState.Collapsed, 'category', 'high'),
            new FindingItem('Medium', vscode.TreeItemCollapsibleState.Collapsed, 'category', 'medium'),
            new FindingItem('Low', vscode.TreeItemCollapsibleState.Collapsed, 'category', 'low')
        ];
    }
    getFindingsByCategory(severity) {
        return this.findings
            .filter((f) => f.severity.toLowerCase() === severity.toLowerCase())
            .map((finding) => {
            // Handle both API findings (file/line) and enhanced scan findings (location.file/startLine)
            const filePath = finding.file || finding.location?.file || 'unknown';
            const lineNumber = finding.line || finding.location?.startLine || 0;
            const fileName = filePath.split('/').pop() || filePath;
            // Check if this is an inter-procedural finding
            const isInterprocedural = finding.call_chain || finding.callChain || finding.cross_function_flow;
            const callChain = finding.call_chain || finding.callChain || [];
            const item = new FindingItem(`${finding.title}`, vscode.TreeItemCollapsibleState.None, 'vulnerability', finding.severity, finding);
            // Add indicator for inter-procedural findings
            const interproceduralIndicator = isInterprocedural ? '🔗 ' : '';
            item.description = `${interproceduralIndicator}${fileName}:${lineNumber}`;
            // Create detailed tooltip with markdown
            const tooltipMarkdown = new vscode.MarkdownString();
            tooltipMarkdown.appendMarkdown(`### ${finding.title}\n\n`);
            tooltipMarkdown.appendMarkdown(`**Severity:** ${finding.severity}\n\n`);
            tooltipMarkdown.appendMarkdown(`**File:** ${filePath}:${lineNumber}\n\n`);
            tooltipMarkdown.appendMarkdown(`**Category:** ${finding.category || finding.owasp_category || 'N/A'}\n\n`);
            if (finding.cwe_id) {
                tooltipMarkdown.appendMarkdown(`**CWE:** ${finding.cwe_id}\n\n`);
            }
            tooltipMarkdown.appendMarkdown(`**Description:** ${finding.description || 'No description'}\n\n`);
            // Add call chain information for inter-procedural findings
            if (isInterprocedural && callChain.length > 0) {
                tooltipMarkdown.appendMarkdown(`---\n\n`);
                tooltipMarkdown.appendMarkdown(`**🔗 Inter-Procedural Analysis**\n\n`);
                tooltipMarkdown.appendMarkdown(`*Cross-function data flow detected*\n\n`);
                tooltipMarkdown.appendMarkdown(`**Call Chain:**\n`);
                callChain.forEach((func, idx) => {
                    const arrow = idx < callChain.length - 1 ? ' → ' : '';
                    tooltipMarkdown.appendMarkdown(`\`${func}\`${arrow}`);
                });
                tooltipMarkdown.appendMarkdown(`\n\n`);
            }
            // Add function summary if available
            if (finding.function_summary || finding.functionSummary) {
                const summary = finding.function_summary || finding.functionSummary;
                tooltipMarkdown.appendMarkdown(`**Function:** \`${summary.name || 'unknown'}\`\n\n`);
                if (summary.taint_behavior) {
                    tooltipMarkdown.appendMarkdown(`**Taint Behavior:** ${summary.taint_behavior}\n\n`);
                }
            }
            tooltipMarkdown.appendMarkdown(`---\n\n`);
            tooltipMarkdown.appendMarkdown(`*Click to view detailed information and remediation*`);
            tooltipMarkdown.isTrusted = true;
            item.tooltip = tooltipMarkdown;
            item.command = {
                command: 'appsec.showDetails',
                title: 'Show Details',
                arguments: [finding]
            };
            return item;
        });
    }
}
exports.FindingsProvider = FindingsProvider;
class FindingItem extends vscode.TreeItem {
    constructor(label, collapsibleState, contextValue, severity, finding) {
        super(label, collapsibleState);
        this.label = label;
        this.collapsibleState = collapsibleState;
        this.contextValue = contextValue;
        this.severity = severity;
        this.finding = finding;
        if (contextValue === 'category') {
            this.iconPath = this.getSeverityIcon(severity || '');
        }
        else if (contextValue === 'vulnerability' || contextValue === 'finding') {
            // Show bug icon with severity-based color
            const colorMap = {
                'critical': 'charts.red',
                'high': 'charts.orange',
                'medium': 'charts.yellow',
                'low': 'charts.green'
            };
            const color = colorMap[severity?.toLowerCase() || ''] || 'problemsErrorIcon.foreground';
            this.iconPath = new vscode.ThemeIcon('bug', new vscode.ThemeColor(color));
        }
    }
    getSeverityIcon(severity) {
        const severityMap = {
            'critical': 'error',
            'high': 'warning',
            'medium': 'info',
            'low': 'circle-outline'
        };
        const icon = severityMap[severity.toLowerCase()] || 'circle-outline';
        return new vscode.ThemeIcon(icon);
    }
}
//# sourceMappingURL=findingsProvider.js.map