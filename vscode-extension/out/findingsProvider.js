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
    getTreeItem(element) {
        return element;
    }
    async getChildren(element) {
        if (!await this.apiClient.isAuthenticated()) {
            return [];
        }
        if (!element) {
            return this.getRootCategories();
        }
        if (element.contextValue === 'category') {
            return this.getFindingsByCategory(element.label);
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
    async getFindingsByCategory(severity) {
        try {
            const response = await this.apiClient.getFindings();
            const findings = response.findings || [];
            return findings
                .filter((f) => f.severity.toLowerCase() === severity.toLowerCase())
                .map((finding) => {
                const item = new FindingItem(`${finding.title} - ${finding.file}:${finding.line}`, vscode.TreeItemCollapsibleState.None, 'finding', finding.severity, finding);
                item.description = finding.category;
                item.tooltip = finding.description;
                item.command = {
                    command: 'appsec.showDetails',
                    title: 'Show Details',
                    arguments: [finding]
                };
                return item;
            });
        }
        catch (error) {
            return [];
        }
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
        else if (contextValue === 'finding') {
            this.iconPath = new vscode.ThemeIcon('bug', new vscode.ThemeColor('problemsErrorIcon.foreground'));
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