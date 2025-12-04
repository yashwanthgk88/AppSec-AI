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
exports.CustomRuleItem = exports.CustomRulesProvider = void 0;
const vscode = __importStar(require("vscode"));
class CustomRulesProvider {
    constructor(apiClient) {
        this.apiClient = apiClient;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.rules = [];
        this.loadRules();
    }
    refresh() {
        this.loadRules();
        this._onDidChangeTreeData.fire();
    }
    async loadRules() {
        try {
            this.rules = await this.apiClient.getCustomRules();
        }
        catch (error) {
            console.error('Failed to load custom rules:', error);
            this.rules = [];
        }
    }
    getRules() {
        return this.rules;
    }
    getTreeItem(element) {
        return element;
    }
    async getChildren(element) {
        if (!await this.apiClient.isAuthenticated()) {
            return [];
        }
        if (!element) {
            // Root level - group by severity
            const criticalRules = this.rules.filter(r => r.severity === 'critical');
            const highRules = this.rules.filter(r => r.severity === 'high');
            const mediumRules = this.rules.filter(r => r.severity === 'medium');
            const lowRules = this.rules.filter(r => r.severity === 'low');
            const items = [];
            if (criticalRules.length > 0) {
                items.push(new CustomRuleItem(`Critical (${criticalRules.length})`, vscode.TreeItemCollapsibleState.Expanded, 'severity', undefined, 'critical'));
            }
            if (highRules.length > 0) {
                items.push(new CustomRuleItem(`High (${highRules.length})`, vscode.TreeItemCollapsibleState.Expanded, 'severity', undefined, 'high'));
            }
            if (mediumRules.length > 0) {
                items.push(new CustomRuleItem(`Medium (${mediumRules.length})`, vscode.TreeItemCollapsibleState.Collapsed, 'severity', undefined, 'medium'));
            }
            if (lowRules.length > 0) {
                items.push(new CustomRuleItem(`Low (${lowRules.length})`, vscode.TreeItemCollapsibleState.Collapsed, 'severity', undefined, 'low'));
            }
            return items;
        }
        else if (element.type === 'severity') {
            // Show rules for this severity level
            const severityRules = this.rules.filter(r => r.severity === element.severity);
            return severityRules.map(rule => new CustomRuleItem(rule.name, vscode.TreeItemCollapsibleState.None, 'customRule', rule));
        }
        return [];
    }
}
exports.CustomRulesProvider = CustomRulesProvider;
class CustomRuleItem extends vscode.TreeItem {
    constructor(label, collapsibleState, type, rule, severity) {
        super(label, collapsibleState);
        this.label = label;
        this.collapsibleState = collapsibleState;
        this.type = type;
        this.rule = rule;
        this.severity = severity;
        if (type === 'customRule' && rule) {
            this.contextValue = 'customRule';
            this.tooltip = this.getTooltip();
            this.description = this.getDescription();
            this.iconPath = this.getIcon();
        }
        else if (type === 'severity') {
            this.iconPath = this.getSeverityIcon();
        }
    }
    getTooltip() {
        if (!this.rule) {
            return '';
        }
        const lines = [
            `Rule: ${this.rule.name}`,
            `Severity: ${this.rule.severity}`,
            `Language: ${this.rule.language || '*'}`,
            `Pattern: ${this.rule.pattern}`,
            `Enabled: ${this.rule.enabled ? 'Yes' : 'No'}`,
            ``,
            `Detections: ${this.rule.total_detections || 0}`,
            `True Positives: ${this.rule.true_positives || 0}`,
            `False Positives: ${this.rule.false_positives || 0}`,
        ];
        if (this.rule.precision !== null && this.rule.precision !== undefined) {
            lines.push(`Precision: ${(this.rule.precision * 100).toFixed(1)}%`);
        }
        if (this.rule.generated_by) {
            lines.push(`Created by: ${this.rule.generated_by === 'ai' ? 'AI' : 'User'}`);
        }
        return lines.join('\n');
    }
    getDescription() {
        if (!this.rule) {
            return '';
        }
        const parts = [];
        if (!this.rule.enabled) {
            parts.push('$(circle-slash) Disabled');
        }
        if (this.rule.generated_by === 'ai') {
            parts.push('$(sparkle) AI');
        }
        if (this.rule.total_detections > 0) {
            parts.push(`${this.rule.total_detections} detections`);
        }
        if (this.rule.precision !== null && this.rule.precision !== undefined) {
            const precision = (this.rule.precision * 100).toFixed(0);
            if (this.rule.precision < 0.85) {
                parts.push(`$(warning) ${precision}%`);
            }
            else {
                parts.push(`$(check) ${precision}%`);
            }
        }
        return parts.join(' • ');
    }
    getIcon() {
        if (!this.rule) {
            return new vscode.ThemeIcon('file-code');
        }
        if (!this.rule.enabled) {
            return new vscode.ThemeIcon('circle-slash');
        }
        switch (this.rule.severity) {
            case 'critical':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case 'high':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
            case 'medium':
                return new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
            case 'low':
                return new vscode.ThemeIcon('info');
            default:
                return new vscode.ThemeIcon('file-code');
        }
    }
    getSeverityIcon() {
        switch (this.severity) {
            case 'critical':
                return new vscode.ThemeIcon('flame', new vscode.ThemeColor('errorForeground'));
            case 'high':
                return new vscode.ThemeIcon('alert', new vscode.ThemeColor('editorWarning.foreground'));
            case 'medium':
                return new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
            case 'low':
                return new vscode.ThemeIcon('info');
            default:
                return new vscode.ThemeIcon('folder');
        }
    }
}
exports.CustomRuleItem = CustomRuleItem;
//# sourceMappingURL=customRulesProvider.js.map