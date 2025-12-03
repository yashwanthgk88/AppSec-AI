import * as vscode from 'vscode';
import { ApiClient } from './apiClient';

export class FindingsProvider implements vscode.TreeDataProvider<FindingItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<FindingItem | undefined | null | void> = new vscode.EventEmitter<FindingItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<FindingItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private apiClient: ApiClient;
    private findings: any[] = [];

    constructor(apiClient: ApiClient) {
        this.apiClient = apiClient;
    }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: FindingItem): vscode.TreeItem {
        return element;
    }

    async getChildren(element?: FindingItem): Promise<FindingItem[]> {
        if (!await this.apiClient.isAuthenticated()) {
            return [];
        }

        if (!element) {
            return this.getRootCategories();
        }

        if (element.contextValue === 'category') {
            return this.getFindingsByCategory(element.label as string);
        }

        return [];
    }

    private getRootCategories(): FindingItem[] {
        return [
            new FindingItem('Critical', vscode.TreeItemCollapsibleState.Collapsed, 'category', 'critical'),
            new FindingItem('High', vscode.TreeItemCollapsibleState.Collapsed, 'category', 'high'),
            new FindingItem('Medium', vscode.TreeItemCollapsibleState.Collapsed, 'category', 'medium'),
            new FindingItem('Low', vscode.TreeItemCollapsibleState.Collapsed, 'category', 'low')
        ];
    }

    private async getFindingsByCategory(severity: string): Promise<FindingItem[]> {
        try {
            const response = await this.apiClient.getFindings();
            const findings = response.findings || [];

            return findings
                .filter((f: any) => f.severity.toLowerCase() === severity.toLowerCase())
                .map((finding: any) => {
                    const fileName = finding.file.split('/').pop() || finding.file;
                    const item = new FindingItem(
                        `${finding.title}`,
                        vscode.TreeItemCollapsibleState.None,
                        'vulnerability',
                        finding.severity,
                        finding
                    );

                    item.description = `${fileName}:${finding.line}`;

                    // Create detailed tooltip with markdown
                    const tooltipMarkdown = new vscode.MarkdownString();
                    tooltipMarkdown.appendMarkdown(`### ${finding.title}\n\n`);
                    tooltipMarkdown.appendMarkdown(`**Severity:** ${finding.severity}\n\n`);
                    tooltipMarkdown.appendMarkdown(`**File:** ${finding.file}:${finding.line}\n\n`);
                    tooltipMarkdown.appendMarkdown(`**Category:** ${finding.category || finding.owasp_category || 'N/A'}\n\n`);
                    if (finding.cwe_id) {
                        tooltipMarkdown.appendMarkdown(`**CWE:** ${finding.cwe_id}\n\n`);
                    }
                    tooltipMarkdown.appendMarkdown(`**Description:** ${finding.description || 'No description'}\n\n`);
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
        } catch (error) {
            return [];
        }
    }
}

class FindingItem extends vscode.TreeItem {
    public finding?: any;

    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string,
        public readonly severity?: string,
        finding?: any
    ) {
        super(label, collapsibleState);
        this.finding = finding;

        if (contextValue === 'category') {
            this.iconPath = this.getSeverityIcon(severity || '');
        } else if (contextValue === 'finding') {
            this.iconPath = new vscode.ThemeIcon('bug', new vscode.ThemeColor('problemsErrorIcon.foreground'));
        }
    }

    private getSeverityIcon(severity: string): vscode.ThemeIcon {
        const severityMap: { [key: string]: string } = {
            'critical': 'error',
            'high': 'warning',
            'medium': 'info',
            'low': 'circle-outline'
        };

        const icon = severityMap[severity.toLowerCase()] || 'circle-outline';
        return new vscode.ThemeIcon(icon);
    }
}
