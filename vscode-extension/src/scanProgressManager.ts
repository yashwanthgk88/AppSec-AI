import * as vscode from 'vscode';

export interface ScanProgress {
    stage: 'initializing' | 'analyzing' | 'detecting' | 'completing' | 'complete';
    message: string;
    percentage: number;
    details?: string;
}

export class ScanProgressManager {
    private progressResolve?: (value: void) => void;
    private currentProgress?: vscode.Progress<{ message?: string; increment?: number }>;

    async showScanProgress(
        title: string,
        scanCallback: (updateProgress: (progress: ScanProgress) => void) => Promise<any>
    ): Promise<any> {
        return await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: title,
            cancellable: true
        }, async (progress, token) => {
            this.currentProgress = progress;
            let lastPercentage = 0;

            const updateProgress = (scanProgress: ScanProgress) => {
                const increment = scanProgress.percentage - lastPercentage;
                lastPercentage = scanProgress.percentage;

                const icon = this.getStageIcon(scanProgress.stage);
                const message = `${icon} ${scanProgress.message}`;
                const details = scanProgress.details ? ` - ${scanProgress.details}` : '';

                progress.report({
                    message: message + details,
                    increment: increment
                });
            };

            // Handle cancellation
            token.onCancellationRequested(() => {
                vscode.window.showWarningMessage('Scan cancelled by user');
            });

            try {
                return await scanCallback(updateProgress);
            } finally {
                this.currentProgress = undefined;
            }
        });
    }

    async showDetailedProgress(
        title: string,
        stages: Array<{name: string, task: () => Promise<any>}>
    ): Promise<any[]> {
        return await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: title,
            cancellable: false
        }, async (progress) => {
            const results: any[] = [];
            const stageIncrement = 100 / stages.length;

            for (let i = 0; i < stages.length; i++) {
                const stage = stages[i];

                progress.report({
                    message: `(${i + 1}/${stages.length}) ${stage.name}...`,
                    increment: 0
                });

                try {
                    const result = await stage.task();
                    results.push(result);

                    progress.report({
                        increment: stageIncrement
                    });
                } catch (error) {
                    vscode.window.showErrorMessage(`Failed at stage: ${stage.name}`);
                    throw error;
                }
            }

            return results;
        });
    }

    showScanComplete(findings: number, duration: number) {
        const message = findings > 0
            ? `🔍 Scan complete: Found ${findings} security issue${findings !== 1 ? 's' : ''} in ${duration.toFixed(1)}s`
            : `✅ Scan complete: No security issues found in ${duration.toFixed(1)}s`;

        vscode.window.showInformationMessage(message, 'View Results').then(selection => {
            if (selection === 'View Results') {
                vscode.commands.executeCommand('workbench.view.extension.appsec-sidebar');
            }
        });
    }

    showScanError(error: string) {
        vscode.window.showErrorMessage(`❌ Scan failed: ${error}`, 'Retry', 'Report Issue').then(selection => {
            if (selection === 'Retry') {
                vscode.commands.executeCommand('appsec.scanWorkspace');
            } else if (selection === 'Report Issue') {
                vscode.env.openExternal(vscode.Uri.parse('https://github.com/yashwanthgk88/AppSec-AI/issues'));
            }
        });
    }

    private getStageIcon(stage: string): string {
        const icons: {[key: string]: string} = {
            'initializing': '🚀',
            'analyzing': '🔍',
            'detecting': '🔬',
            'completing': '📊',
            'complete': '✅'
        };
        return icons[stage] || '⚙️';
    }
}
