import * as vscode from 'vscode';
import { ApiClient } from './apiClient';

export class ScaFindingsProvider implements vscode.TreeDataProvider<ScaFindingItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<ScaFindingItem | undefined | null | void> = new vscode.EventEmitter<ScaFindingItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<ScaFindingItem | undefined | null | void> = this._onDidChangeTreeData.event;

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

    getTreeItem(element: ScaFindingItem): vscode.TreeItem {
        return element;
    }

    async getChildren(element?: ScaFindingItem): Promise<ScaFindingItem[]> {
        const isAuthenticated = await this.apiClient.isAuthenticated();

        if (!element) {
            // Show login prompt if not authenticated
            if (!isAuthenticated) {
                const loginItem = new ScaFindingItem(
                    '🔐 Login to view SCA findings',
                    vscode.TreeItemCollapsibleState.None,
                    'login-prompt'
                );
                loginItem.command = {
                    command: 'appsec.login',
                    title: 'Login'
                };
                loginItem.tooltip = 'Click to login to SecureDev AI platform';
                return [loginItem];
            }

            // Update counts for each severity
            const criticalCount = this.findings.filter(f => f.severity?.toLowerCase() === 'critical').length;
            const highCount = this.findings.filter(f => f.severity?.toLowerCase() === 'high').length;
            const mediumCount = this.findings.filter(f => f.severity?.toLowerCase() === 'medium').length;
            const lowCount = this.findings.filter(f => f.severity?.toLowerCase() === 'low').length;
            const totalCount = this.findings.length;

            if (totalCount === 0) {
                const scanItem = new ScaFindingItem(
                    '🔍 Run scan to check dependencies',
                    vscode.TreeItemCollapsibleState.None,
                    'scan-prompt'
                );
                scanItem.command = {
                    command: 'appsec.scanWorkspace',
                    title: 'Scan Workspace'
                };
                scanItem.tooltip = 'Click to scan workspace for vulnerable dependencies';
                return [scanItem];
            }

            return [
                new ScaFindingItem(`Critical (${criticalCount})`, vscode.TreeItemCollapsibleState.Expanded, 'category', 'critical'),
                new ScaFindingItem(`High (${highCount})`, vscode.TreeItemCollapsibleState.Expanded, 'category', 'high'),
                new ScaFindingItem(`Medium (${mediumCount})`, vscode.TreeItemCollapsibleState.Collapsed, 'category', 'medium'),
                new ScaFindingItem(`Low (${lowCount})`, vscode.TreeItemCollapsibleState.Collapsed, 'category', 'low')
            ];
        }

        if (element.contextValue === 'category') {
            const severityLabel = (element.label as string).split('(')[0].trim();
            return this.getFindingsByCategory(severityLabel);
        }

        return [];
    }

    private getFindingsByCategory(severity: string): ScaFindingItem[] {
        return this.findings
            .filter((f: any) => f.severity?.toLowerCase() === severity.toLowerCase())
            .map((finding: any) => {
                // Handle multiple field name formats from different sources
                const packageName = finding.package_name || finding.package || finding.dependency || 'Unknown Package';
                const version = finding.version || finding.installed_version || 'Unknown';

                const item = new ScaFindingItem(
                    `${packageName}@${version}`,
                    vscode.TreeItemCollapsibleState.None,
                    'sca-vulnerability',
                    finding.severity,
                    finding
                );

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

class ScaFindingItem extends vscode.TreeItem {
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
        } else if (contextValue === 'sca-vulnerability') {
            this.iconPath = new vscode.ThemeIcon('package', new vscode.ThemeColor('problemsWarningIcon.foreground'));
        } else if (contextValue === 'empty') {
            this.iconPath = new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'));
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
