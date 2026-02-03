import * as vscode from 'vscode';
import { ApiClient } from './apiClient';

export class CustomRulesProvider implements vscode.TreeDataProvider<CustomRuleItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<CustomRuleItem | undefined | null | void> = new vscode.EventEmitter<CustomRuleItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<CustomRuleItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private rules: any[] = [];
    private isLoading: boolean = false;
    private rulesLoaded: boolean = false;

    constructor(private apiClient: ApiClient) {
        // Initial load
        this.loadRules().then(() => {
            this._onDidChangeTreeData.fire();
        });
    }

    refresh(): void {
        this.rulesLoaded = false;
        this.loadRules().then(() => {
            this._onDidChangeTreeData.fire();
        });
    }

    private async loadRules(): Promise<void> {
        if (this.isLoading) {
            return;
        }

        this.isLoading = true;
        try {
            const isAuth = await this.apiClient.isAuthenticated();
            if (!isAuth) {
                this.rules = [];
                return;
            }

            this.rules = await this.apiClient.getCustomRules();
            this.rulesLoaded = true;
            console.log('Custom rules loaded:', this.rules.length);
        } catch (error) {
            console.error('Failed to load custom rules:', error);
            this.rules = [];
        } finally {
            this.isLoading = false;
        }
    }

    getRules(): any[] {
        return this.rules;
    }

    getTreeItem(element: CustomRuleItem): vscode.TreeItem {
        return element;
    }

    async getChildren(element?: CustomRuleItem): Promise<CustomRuleItem[]> {
        if (!await this.apiClient.isAuthenticated()) {
            return [];
        }

        // Ensure rules are loaded
        if (!this.rulesLoaded && !this.isLoading) {
            await this.loadRules();
        }

        if (!element) {
            // Root level - group by severity
            const criticalRules = this.rules.filter(r => r.severity === 'critical');
            const highRules = this.rules.filter(r => r.severity === 'high');
            const mediumRules = this.rules.filter(r => r.severity === 'medium');
            const lowRules = this.rules.filter(r => r.severity === 'low');

            const items: CustomRuleItem[] = [];

            if (criticalRules.length > 0) {
                items.push(new CustomRuleItem(
                    `Critical (${criticalRules.length})`,
                    vscode.TreeItemCollapsibleState.Expanded,
                    'severity',
                    undefined,
                    'critical'
                ));
            }

            if (highRules.length > 0) {
                items.push(new CustomRuleItem(
                    `High (${highRules.length})`,
                    vscode.TreeItemCollapsibleState.Expanded,
                    'severity',
                    undefined,
                    'high'
                ));
            }

            if (mediumRules.length > 0) {
                items.push(new CustomRuleItem(
                    `Medium (${mediumRules.length})`,
                    vscode.TreeItemCollapsibleState.Collapsed,
                    'severity',
                    undefined,
                    'medium'
                ));
            }

            if (lowRules.length > 0) {
                items.push(new CustomRuleItem(
                    `Low (${lowRules.length})`,
                    vscode.TreeItemCollapsibleState.Collapsed,
                    'severity',
                    undefined,
                    'low'
                ));
            }

            return items;
        } else if (element.type === 'severity') {
            // Show rules for this severity level
            const severityRules = this.rules.filter(r => r.severity === element.severity);
            return severityRules.map(rule => new CustomRuleItem(
                rule.name,
                vscode.TreeItemCollapsibleState.None,
                'customRule',
                rule
            ));
        }

        return [];
    }
}

export class CustomRuleItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly type: 'severity' | 'customRule',
        public readonly rule?: any,
        public readonly severity?: string
    ) {
        super(label, collapsibleState);

        if (type === 'customRule' && rule) {
            this.contextValue = 'customRule';
            this.tooltip = this.getTooltip();
            this.description = this.getDescription();
            this.iconPath = this.getIcon();
        } else if (type === 'severity') {
            this.iconPath = this.getSeverityIcon();
        }
    }

    private getTooltip(): string {
        if (!this.rule) {return '';}

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

    private getDescription(): string {
        if (!this.rule) {return '';}

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
            } else {
                parts.push(`$(check) ${precision}%`);
            }
        }

        return parts.join(' • ');
    }

    private getIcon(): vscode.ThemeIcon {
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

    private getSeverityIcon(): vscode.ThemeIcon {
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
