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
exports.ScaFindingsProvider = void 0;
const vscode = __importStar(require("vscode"));
class ScaFindingsProvider {
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
            const criticalCount = this.findings.filter(f => f.severity?.toLowerCase() === 'critical').length;
            const highCount = this.findings.filter(f => f.severity?.toLowerCase() === 'high').length;
            const mediumCount = this.findings.filter(f => f.severity?.toLowerCase() === 'medium').length;
            const lowCount = this.findings.filter(f => f.severity?.toLowerCase() === 'low').length;
            const totalCount = this.findings.length;
            if (totalCount === 0) {
                return [new ScaFindingItem('No SCA vulnerabilities found', vscode.TreeItemCollapsibleState.None, 'empty')];
            }
            return [
                new ScaFindingItem(`Critical (${criticalCount})`, vscode.TreeItemCollapsibleState.Expanded, 'category', 'critical'),
                new ScaFindingItem(`High (${highCount})`, vscode.TreeItemCollapsibleState.Expanded, 'category', 'high'),
                new ScaFindingItem(`Medium (${mediumCount})`, vscode.TreeItemCollapsibleState.Collapsed, 'category', 'medium'),
                new ScaFindingItem(`Low (${lowCount})`, vscode.TreeItemCollapsibleState.Collapsed, 'category', 'low')
            ];
        }
        if (element.contextValue === 'category') {
            const severityLabel = element.label.split('(')[0].trim();
            return this.getFindingsByCategory(severityLabel);
        }
        return [];
    }
    getFindingsByCategory(severity) {
        return this.findings
            .filter((f) => f.severity?.toLowerCase() === severity.toLowerCase())
            .map((finding) => {
            // Handle multiple field name formats from different sources
            const packageName = finding.package_name || finding.package || finding.dependency || 'Unknown Package';
            const version = finding.version || finding.installed_version || 'Unknown';
            const item = new ScaFindingItem(`${packageName}@${version}`, vscode.TreeItemCollapsibleState.None, 'sca-vulnerability', finding.severity, finding);
            item.description = finding.vulnerability_id || finding.cve_id || '';
            // Create detailed tooltip with markdown
            const tooltipMarkdown = new vscode.MarkdownString();
            tooltipMarkdown.appendMarkdown(`### ${packageName}@${version}\n\n`);
            tooltipMarkdown.appendMarkdown(`**Severity:** ${finding.severity}\n\n`);
            if (finding.vulnerability_id || finding.cve_id) {
                tooltipMarkdown.appendMarkdown(`**CVE:** ${finding.vulnerability_id || finding.cve_id}\n\n`);
            }
            if (finding.cvss_score) {
                tooltipMarkdown.appendMarkdown(`**CVSS Score:** ${finding.cvss_score}\n\n`);
            }
            if (finding.fixed_version || finding.recommended_version) {
                tooltipMarkdown.appendMarkdown(`**Fixed Version:** ${finding.fixed_version || finding.recommended_version}\n\n`);
            }
            tooltipMarkdown.appendMarkdown(`**Description:** ${finding.description || finding.title || 'Vulnerable dependency detected'}\n\n`);
            if (finding.file_path || finding.file) {
                tooltipMarkdown.appendMarkdown(`**File:** ${finding.file_path || finding.file}\n\n`);
            }
            tooltipMarkdown.appendMarkdown(`---\n\n`);
            tooltipMarkdown.appendMarkdown(`*Click to view detailed information*`);
            tooltipMarkdown.isTrusted = true;
            item.tooltip = tooltipMarkdown;
            item.command = {
                command: 'appsec.showScaDetails',
                title: 'Show SCA Details',
                arguments: [finding]
            };
            return item;
        });
    }
}
exports.ScaFindingsProvider = ScaFindingsProvider;
class ScaFindingItem extends vscode.TreeItem {
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
        else if (contextValue === 'sca-vulnerability') {
            this.iconPath = new vscode.ThemeIcon('package', new vscode.ThemeColor('problemsWarningIcon.foreground'));
        }
        else if (contextValue === 'empty') {
            this.iconPath = new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'));
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
//# sourceMappingURL=scaFindingsProvider.js.map