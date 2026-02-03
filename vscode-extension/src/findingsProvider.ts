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

    setFindings(findings: any[]): void {
        this.findings = findings;
        this.refresh();
    }

    getAllFindings(): any[] {
        return this.findings;
    }

    getTreeItem(element: FindingItem): vscode.TreeItem {
        return element;
    }

    async getChildren(element?: FindingItem): Promise<FindingItem[]> {
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
            const severityLabel = (element.label as string).split('(')[0].trim();
            return this.getFindingsByCategory(severityLabel);
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

    private getFindingsByCategory(severity: string): FindingItem[] {
        return this.findings
            .filter((f: any) => f.severity.toLowerCase() === severity.toLowerCase())
            .map((finding: any) => {
                    // Handle both API findings (file/line) and enhanced scan findings (location.file/startLine)
                    const filePath = finding.file || finding.location?.file || 'unknown';
                    const lineNumber = finding.line || finding.location?.startLine || 0;
                    const fileName = filePath.split('/').pop() || filePath;

                    const item = new FindingItem(
                        `${finding.title}`,
                        vscode.TreeItemCollapsibleState.None,
                        'vulnerability',
                        finding.severity,
                        finding
                    );

                    item.description = `${fileName}:${lineNumber}`;

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
        } else if (contextValue === 'vulnerability' || contextValue === 'finding') {
            // Show bug icon with severity-based color
            const colorMap: { [key: string]: string } = {
                'critical': 'charts.red',
                'high': 'charts.orange',
                'medium': 'charts.yellow',
                'low': 'charts.green'
            };
            const color = colorMap[severity?.toLowerCase() || ''] || 'problemsErrorIcon.foreground';
            this.iconPath = new vscode.ThemeIcon('bug', new vscode.ThemeColor(color));
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
