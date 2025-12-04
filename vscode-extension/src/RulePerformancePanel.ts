import * as vscode from 'vscode';
import { ApiClient } from './apiClient';

export class RulePerformancePanel {
    private static currentPanel: RulePerformancePanel | undefined;
    private readonly panel: vscode.WebviewPanel;
    private disposables: vscode.Disposable[] = [];
    private dashboardData: any = null;

    private constructor(panel: vscode.WebviewPanel, private apiClient: ApiClient) {
        this.panel = panel;
        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);

        this.panel.webview.onDidReceiveMessage(
            async (message) => {
                switch (message.command) {
                    case 'refresh':
                        await this.loadDashboardData();
                        break;
                    case 'viewRuleDetails':
                        await this.viewRuleDetails(message.ruleId);
                        break;
                }
            },
            null,
            this.disposables
        );

        // Load initial data
        this.loadDashboardData();
    }

    public static show(apiClient: ApiClient) {
        const column = vscode.ViewColumn.Two;

        if (RulePerformancePanel.currentPanel) {
            RulePerformancePanel.currentPanel.panel.reveal(column);
            RulePerformancePanel.currentPanel.loadDashboardData();
        } else {
            const panel = vscode.window.createWebviewPanel(
                'rulePerformance',
                'Rule Performance Dashboard',
                column,
                {
                    enableScripts: true,
                    retainContextWhenHidden: true
                }
            );

            RulePerformancePanel.currentPanel = new RulePerformancePanel(panel, apiClient);
        }
    }

    private async loadDashboardData() {
        try {
            this.panel.webview.postMessage({ command: 'loading', value: true });

            console.log('Loading rule performance dashboard data...');
            const data = await this.apiClient.getRulePerformanceStats();
            console.log('Dashboard data loaded:', data);
            this.dashboardData = data;

            this.update();
            this.panel.webview.postMessage({ command: 'loading', value: false });
        } catch (error: any) {
            console.error('Failed to load dashboard:', error);
            vscode.window.showErrorMessage('Failed to load dashboard: ' + error.message);
            this.panel.webview.postMessage({ command: 'loading', value: false });
            this.panel.webview.postMessage({ command: 'error', message: error.message });
        }
    }

    private async viewRuleDetails(ruleId: number) {
        try {
            const rule = await this.apiClient.getCustomRule(ruleId);

            const panel = vscode.window.createWebviewPanel(
                'ruleDetails',
                `Rule: ${rule.name}`,
                vscode.ViewColumn.Beside,
                { enableScripts: true }
            );

            panel.webview.html = this.getRuleDetailsHtml(rule);
        } catch (error: any) {
            vscode.window.showErrorMessage('Failed to load rule details: ' + error.message);
        }
    }

    private update() {
        this.panel.webview.html = this.getHtmlContent();
    }

    private getHtmlContent(): string {
        if (!this.dashboardData) {
            return this.getLoadingHtml();
        }

        const stats = this.dashboardData.overall_stats || {};
        const severityBreakdown = this.dashboardData.severity_breakdown || [];
        const topPerformers = this.dashboardData.top_performers || [];
        const needsAttention = this.dashboardData.needs_attention || [];

        const totalRules = stats.total_rules || 0;
        const enabledRules = stats.enabled_rules || 0;
        const totalDetections = stats.total_detections || 0;
        const totalTruePositives = stats.total_true_positives || 0;
        const totalFalsePositives = stats.total_false_positives || 0;
        const avgPrecision = stats.avg_precision ? (stats.avg_precision * 100).toFixed(1) : 'N/A';
        const rulesNeedingRefinement = stats.rules_needing_refinement || 0;
        const aiGeneratedRules = stats.ai_generated_rules || 0;
        const userCreatedRules = stats.user_created_rules || 0;

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1e1e1e;
            color: #cccccc;
            padding: 0;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 24px;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .refresh-btn {
            padding: 10px 20px;
            background: rgba(255,255,255,0.2);
            border: 1px solid rgba(255,255,255,0.3);
            border-radius: 6px;
            color: white;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s;
        }
        .refresh-btn:hover {
            background: rgba(255,255,255,0.3);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: #252526;
            border: 1px solid #3e3e42;
            border-radius: 8px;
            padding: 20px;
            transition: transform 0.2s;
        }
        .stat-card:hover {
            transform: translateY(-2px);
            border-color: #667eea;
        }
        .stat-label {
            font-size: 12px;
            text-transform: uppercase;
            color: #858585;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        .stat-value {
            font-size: 32px;
            font-weight: 700;
            color: #4ec9b0;
            margin-bottom: 4px;
        }
        .stat-subtitle {
            font-size: 13px;
            color: #858585;
        }
        .section {
            background: #252526;
            border: 1px solid #3e3e42;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .section-header {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 16px;
            color: #4ec9b0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .severity-badges {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }
        .severity-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .severity-critical { background: #fef2f2; color: #dc2626; border: 2px solid #fca5a5; }
        .severity-high { background: #fff7ed; color: #ea580c; border: 2px solid #fdba74; }
        .severity-medium { background: #fefce8; color: #ca8a04; border: 2px solid #fde047; }
        .severity-low { background: #f0fdf4; color: #16a34a; border: 2px solid #86efac; }
        .rule-list {
            list-style: none;
            padding: 0;
        }
        .rule-item {
            background: #1e1e1e;
            border: 1px solid #3e3e42;
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 12px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .rule-item:hover {
            border-color: #667eea;
            transform: translateX(4px);
        }
        .rule-name {
            font-weight: 600;
            font-size: 15px;
            color: #d4d4d4;
            margin-bottom: 8px;
        }
        .rule-meta {
            display: flex;
            gap: 16px;
            font-size: 12px;
            color: #858585;
            flex-wrap: wrap;
        }
        .rule-meta span {
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .precision-high { color: #16a34a; font-weight: 600; }
        .precision-medium { color: #ca8a04; font-weight: 600; }
        .precision-low { color: #dc2626; font-weight: 600; }
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #858585;
        }
        .icon { font-size: 20px; }
        .loading {
            text-align: center;
            padding: 60px 20px;
            color: #858585;
        }
        .loading-spinner {
            font-size: 48px;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><span>📊</span> Rule Performance Dashboard</h1>
            <button class="refresh-btn" onclick="refresh()">🔄 Refresh</button>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Rules</div>
                <div class="stat-value">${totalRules}</div>
                <div class="stat-subtitle">${enabledRules} enabled</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Detections</div>
                <div class="stat-value">${totalDetections}</div>
                <div class="stat-subtitle">${totalTruePositives} true positives</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Average Precision</div>
                <div class="stat-value">${avgPrecision}%</div>
                <div class="stat-subtitle">${totalFalsePositives} false positives</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Needs Refinement</div>
                <div class="stat-value">${rulesNeedingRefinement}</div>
                <div class="stat-subtitle">Rules with low precision</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">AI Generated</div>
                <div class="stat-value">${aiGeneratedRules}</div>
                <div class="stat-subtitle">Created by AI</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">User Created</div>
                <div class="stat-value">${userCreatedRules}</div>
                <div class="stat-subtitle">Manually created</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header"><span class="icon">🎯</span> Rules by Severity</div>
            <div class="severity-badges">
                ${severityBreakdown.map((s: any) => `
                    <div class="severity-badge severity-${s.severity}">
                        <span>${s.severity.toUpperCase()}</span>
                        <span>${s.count} rules (${s.detections || 0} detections)</span>
                    </div>
                `).join('')}
                ${severityBreakdown.length === 0 ? '<div class="empty-state">No rules found</div>' : ''}
            </div>
        </div>

        <div class="section">
            <div class="section-header"><span class="icon">🏆</span> Top Performing Rules</div>
            <ul class="rule-list">
                ${topPerformers.map((rule: any) => {
                    const precision = rule.precision ? (rule.precision * 100).toFixed(1) : 'N/A';
                    const precisionClass = rule.precision >= 0.95 ? 'precision-high' :
                                          rule.precision >= 0.85 ? 'precision-medium' : 'precision-low';
                    return `
                        <li class="rule-item" onclick="viewRule(${rule.id})">
                            <div class="rule-name">${this.escapeHtml(rule.name)}</div>
                            <div class="rule-meta">
                                <span class="severity-badge severity-${rule.severity}">${rule.severity}</span>
                                <span>📈 ${rule.total_detections} detections</span>
                                <span class="${precisionClass}">🎯 ${precision}% precision</span>
                                <span>🤖 ${rule.generated_by === 'ai' ? 'AI Generated' : 'User Created'}</span>
                            </div>
                        </li>
                    `;
                }).join('')}
                ${topPerformers.length === 0 ? '<div class="empty-state">No top performers yet. Rules need detections to appear here.</div>' : ''}
            </ul>
        </div>

        <div class="section">
            <div class="section-header"><span class="icon">⚠️</span> Rules Needing Attention</div>
            <ul class="rule-list">
                ${needsAttention.map((rule: any) => {
                    const precision = rule.precision ? (rule.precision * 100).toFixed(1) : 'N/A';
                    const precisionClass = 'precision-low';
                    return `
                        <li class="rule-item" onclick="viewRule(${rule.id})">
                            <div class="rule-name">${this.escapeHtml(rule.name)}</div>
                            <div class="rule-meta">
                                <span class="severity-badge severity-${rule.severity}">${rule.severity}</span>
                                <span>📈 ${rule.total_detections} detections</span>
                                <span>❌ ${rule.false_positives} false positives</span>
                                <span class="${precisionClass}">🎯 ${precision}% precision</span>
                            </div>
                        </li>
                    `;
                }).join('')}
                ${needsAttention.length === 0 ? '<div class="empty-state">Great! No rules need attention right now.</div>' : ''}
            </ul>
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();

        function refresh() {
            vscode.postMessage({ command: 'refresh' });
            document.body.innerHTML = '<div class="loading"><div class="loading-spinner">⏳</div><p>Loading dashboard data...</p></div>';
        }

        function viewRule(ruleId) {
            vscode.postMessage({ command: 'viewRuleDetails', ruleId: ruleId });
        }

        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.command) {
                case 'loading':
                    if (message.value) {
                        // Show loading state
                    }
                    break;
                case 'error':
                    document.body.innerHTML = '<div class="loading"><div style="font-size: 48px;">❌</div><p>Error: ' + message.message + '</p><button class="refresh-btn" onclick="refresh()">Retry</button></div>';
                    break;
            }
        });
    </script>
</body>
</html>`;
    }

    private getLoadingHtml(): string {
        return `<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1e1e1e;
            color: #cccccc;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .loading {
            text-align: center;
        }
        .spinner {
            font-size: 64px;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="loading">
        <div class="spinner">⏳</div>
        <p>Loading Rule Performance Dashboard...</p>
    </div>
</body>
</html>`;
    }

    private getRuleDetailsHtml(rule: any): string {
        const precision = rule.precision ? (rule.precision * 100).toFixed(1) : 'N/A';

        return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1e1e1e;
            color: #cccccc;
            padding: 20px;
            line-height: 1.6;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            color: white;
        }
        h1 { font-size: 22px; margin-bottom: 8px; }
        .section {
            background: #252526;
            border: 1px solid #3e3e42;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }
        .section h2 {
            font-size: 16px;
            color: #4ec9b0;
            margin-bottom: 12px;
        }
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
        }
        .meta-item {
            background: #1e1e1e;
            padding: 12px;
            border-radius: 6px;
        }
        .meta-label {
            font-size: 11px;
            text-transform: uppercase;
            color: #858585;
            margin-bottom: 4px;
        }
        .meta-value {
            font-size: 14px;
            color: #d4d4d4;
            font-weight: 600;
        }
        pre {
            background: #1e1e1e;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 13px;
            color: #ce9178;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>${this.escapeHtml(rule.name)}</h1>
        <p>${this.escapeHtml(rule.description || 'No description')}</p>
    </div>

    <div class="section">
        <h2>📊 Performance Metrics</h2>
        <div class="meta-grid">
            <div class="meta-item">
                <div class="meta-label">Total Detections</div>
                <div class="meta-value">${rule.total_detections || 0}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">True Positives</div>
                <div class="meta-value">${rule.true_positives || 0}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">False Positives</div>
                <div class="meta-value">${rule.false_positives || 0}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Precision</div>
                <div class="meta-value">${precision}%</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>🔍 Rule Details</h2>
        <div class="meta-grid">
            <div class="meta-item">
                <div class="meta-label">Severity</div>
                <div class="meta-value">${rule.severity}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Language</div>
                <div class="meta-value">${rule.language}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">CWE</div>
                <div class="meta-value">${rule.cwe || 'N/A'}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">OWASP</div>
                <div class="meta-value">${rule.owasp || 'N/A'}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Created By</div>
                <div class="meta-value">${rule.created_by || 'Unknown'}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Generated By</div>
                <div class="meta-value">${rule.generated_by || 'User'}</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>💻 Pattern</h2>
        <pre>${this.escapeHtml(rule.pattern)}</pre>
    </div>

    ${rule.remediation ? `
    <div class="section">
        <h2>🔧 Remediation</h2>
        <p>${this.escapeHtml(rule.remediation)}</p>
    </div>
    ` : ''}
</body>
</html>`;
    }

    private escapeHtml(text: string): string {
        if (!text) return '';
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    public dispose() {
        RulePerformancePanel.currentPanel = undefined;
        this.panel.dispose();
        while (this.disposables.length) {
            const disposable = this.disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }
}
