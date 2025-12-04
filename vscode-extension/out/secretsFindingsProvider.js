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
exports.SecretsFindingsProvider = void 0;
const vscode = __importStar(require("vscode"));
class SecretsFindingsProvider {
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
            // Group by secret type
            const secretTypes = {};
            this.findings.forEach((f) => {
                const type = f.secret_type || f.category || 'Unknown';
                secretTypes[type] = (secretTypes[type] || 0) + 1;
            });
            if (Object.keys(secretTypes).length === 0) {
                return [new SecretFindingItem('No secrets detected', vscode.TreeItemCollapsibleState.None, 'empty')];
            }
            // Create categories sorted by count
            return Object.entries(secretTypes)
                .sort((a, b) => b[1] - a[1])
                .map(([type, count]) => new SecretFindingItem(`${type} (${count})`, vscode.TreeItemCollapsibleState.Expanded, 'category', type));
        }
        if (element.contextValue === 'category') {
            const secretType = element.label.split('(')[0].trim();
            return this.getFindingsByCategory(secretType);
        }
        return [];
    }
    getFindingsByCategory(secretType) {
        return this.findings
            .filter((f) => (f.secret_type || f.category || 'Unknown') === secretType)
            .map((finding) => {
            const fileName = (finding.file || finding.file_path || 'unknown').split('/').pop() || finding.file || 'unknown';
            const secretType = finding.secret_type || finding.category || 'Secret';
            const item = new SecretFindingItem(finding.title || `${secretType} Detected`, vscode.TreeItemCollapsibleState.None, 'secret', secretType, finding);
            item.description = `${fileName}:${finding.line || 0}`;
            // Create detailed tooltip with markdown
            const tooltipMarkdown = new vscode.MarkdownString();
            tooltipMarkdown.appendMarkdown(`### ${finding.title || 'Exposed Secret'}\n\n`);
            tooltipMarkdown.appendMarkdown(`**Type:** ${secretType}\n\n`);
            tooltipMarkdown.appendMarkdown(`**Severity:** ${finding.severity || 'High'}\n\n`);
            tooltipMarkdown.appendMarkdown(`**File:** ${finding.file || finding.file_path}:${finding.line || 0}\n\n`);
            tooltipMarkdown.appendMarkdown(`**Description:** ${finding.description || 'Potential secret or credential detected in code'}\n\n`);
            if (finding.code_snippet) {
                tooltipMarkdown.appendMarkdown(`**Code Snippet:**\n\`\`\`\n${finding.code_snippet}\n\`\`\`\n\n`);
            }
            tooltipMarkdown.appendMarkdown(`---\n\n`);
            tooltipMarkdown.appendMarkdown(`⚠️ **CRITICAL:** Rotate this credential immediately!\n\n`);
            tooltipMarkdown.appendMarkdown(`*Click to view detailed information*`);
            tooltipMarkdown.isTrusted = true;
            item.tooltip = tooltipMarkdown;
            item.command = {
                command: 'appsec.showSecretDetails',
                title: 'Show Secret Details',
                arguments: [finding]
            };
            return item;
        });
    }
}
exports.SecretsFindingsProvider = SecretsFindingsProvider;
class SecretFindingItem extends vscode.TreeItem {
    constructor(label, collapsibleState, contextValue, secretType, finding) {
        super(label, collapsibleState);
        this.label = label;
        this.collapsibleState = collapsibleState;
        this.contextValue = contextValue;
        this.secretType = secretType;
        this.finding = finding;
        if (contextValue === 'category') {
            this.iconPath = new vscode.ThemeIcon('key', new vscode.ThemeColor('problemsErrorIcon.foreground'));
        }
        else if (contextValue === 'secret') {
            this.iconPath = new vscode.ThemeIcon('lock', new vscode.ThemeColor('problemsErrorIcon.foreground'));
        }
        else if (contextValue === 'empty') {
            this.iconPath = new vscode.ThemeIcon('shield', new vscode.ThemeColor('testing.iconPassed'));
        }
    }
}
//# sourceMappingURL=secretsFindingsProvider.js.map