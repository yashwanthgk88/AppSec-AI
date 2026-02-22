import * as vscode from 'vscode';
import { ApiClient } from './apiClient';

export class SecretsFindingsProvider implements vscode.TreeDataProvider<SecretFindingItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<SecretFindingItem | undefined | null | void> = new vscode.EventEmitter<SecretFindingItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<SecretFindingItem | undefined | null | void> = this._onDidChangeTreeData.event;

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

    getTreeItem(element: SecretFindingItem): vscode.TreeItem {
        return element;
    }

    async getChildren(element?: SecretFindingItem): Promise<SecretFindingItem[]> {
        const isAuthenticated = await this.apiClient.isAuthenticated();

        if (!element) {
            // Show login prompt if not authenticated
            if (!isAuthenticated) {
                const loginItem = new SecretFindingItem(
                    '🔐 Login to view secrets',
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

            // Group by secret type
            const secretTypes: { [key: string]: number } = {};

            this.findings.forEach((f: any) => {
                const type = f.secret_type || f.category || 'Unknown';
                secretTypes[type] = (secretTypes[type] || 0) + 1;
            });

            if (Object.keys(secretTypes).length === 0) {
                const scanItem = new SecretFindingItem(
                    '🔍 Run scan to detect secrets',
                    vscode.TreeItemCollapsibleState.None,
                    'scan-prompt'
                );
                scanItem.command = {
                    command: 'appsec.scanWorkspace',
                    title: 'Scan Workspace'
                };
                scanItem.tooltip = 'Click to scan workspace for exposed secrets';
                return [scanItem];
            }

            // Create categories sorted by count
            return Object.entries(secretTypes)
                .sort((a, b) => b[1] - a[1])
                .map(([type, count]) =>
                    new SecretFindingItem(
                        `${type} (${count})`,
                        vscode.TreeItemCollapsibleState.Expanded,
                        'category',
                        type
                    )
                );
        }

        if (element.contextValue === 'category') {
            const secretType = (element.label as string).split('(')[0].trim();
            return this.getFindingsByCategory(secretType);
        }

        return [];
    }

    private getFindingsByCategory(secretType: string): SecretFindingItem[] {
        return this.findings
            .filter((f: any) => (f.secret_type || f.category || 'Unknown') === secretType)
            .map((finding: any) => {
                const fileName = (finding.file || finding.file_path || 'unknown').split('/').pop() || finding.file || 'unknown';
                const secretType = finding.secret_type || finding.category || 'Secret';

                const item = new SecretFindingItem(
                    finding.title || `${secretType} Detected`,
                    vscode.TreeItemCollapsibleState.None,
                    'secret',
                    secretType,
                    finding
                );

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

class SecretFindingItem extends vscode.TreeItem {
    public finding?: any;

    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string,
        public readonly secretType?: string,
        finding?: any
    ) {
        super(label, collapsibleState);
        this.finding = finding;

        if (contextValue === 'category') {
            this.iconPath = new vscode.ThemeIcon('key', new vscode.ThemeColor('problemsErrorIcon.foreground'));
        } else if (contextValue === 'secret') {
            this.iconPath = new vscode.ThemeIcon('lock', new vscode.ThemeColor('problemsErrorIcon.foreground'));
        } else if (contextValue === 'empty') {
            this.iconPath = new vscode.ThemeIcon('shield', new vscode.ThemeColor('testing.iconPassed'));
        }
    }
}
