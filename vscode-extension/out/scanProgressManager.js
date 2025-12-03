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
exports.ScanProgressManager = void 0;
const vscode = __importStar(require("vscode"));
class ScanProgressManager {
    async showScanProgress(title, scanCallback) {
        return await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: title,
            cancellable: true
        }, async (progress, token) => {
            this.currentProgress = progress;
            let lastPercentage = 0;
            const updateProgress = (scanProgress) => {
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
            }
            finally {
                this.currentProgress = undefined;
            }
        });
    }
    async showDetailedProgress(title, stages) {
        return await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: title,
            cancellable: false
        }, async (progress) => {
            const results = [];
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
                }
                catch (error) {
                    vscode.window.showErrorMessage(`Failed at stage: ${stage.name}`);
                    throw error;
                }
            }
            return results;
        });
    }
    showScanComplete(findings, duration) {
        const message = findings > 0
            ? `🔍 Scan complete: Found ${findings} security issue${findings !== 1 ? 's' : ''} in ${duration.toFixed(1)}s`
            : `✅ Scan complete: No security issues found in ${duration.toFixed(1)}s`;
        vscode.window.showInformationMessage(message, 'View Results').then(selection => {
            if (selection === 'View Results') {
                vscode.commands.executeCommand('workbench.view.extension.appsec-sidebar');
            }
        });
    }
    showScanError(error) {
        vscode.window.showErrorMessage(`❌ Scan failed: ${error}`, 'Retry', 'Report Issue').then(selection => {
            if (selection === 'Retry') {
                vscode.commands.executeCommand('appsec.scanWorkspace');
            }
            else if (selection === 'Report Issue') {
                vscode.env.openExternal(vscode.Uri.parse('https://github.com/yashwanthgk88/AppSec-AI/issues'));
            }
        });
    }
    getStageIcon(stage) {
        const icons = {
            'initializing': '🚀',
            'analyzing': '🔍',
            'detecting': '🔬',
            'completing': '📊',
            'complete': '✅'
        };
        return icons[stage] || '⚙️';
    }
}
exports.ScanProgressManager = ScanProgressManager;
//# sourceMappingURL=scanProgressManager.js.map