import * as vscode from 'vscode';
import { ApiClient } from './apiClient';
import { FindingsProvider } from './findingsProvider';
import { DiagnosticsManager } from './diagnosticsManager';
import { VulnerabilityDetailsPanel } from './vulnerabilityDetailsPanel';
import { ChatbotPanel } from './chatbotPanel';
import { ScanProgressManager } from './scanProgressManager';
import { InlineSecurityProvider } from './inlineSecurityProvider';

let apiClient: ApiClient;
let findingsProvider: FindingsProvider;
let diagnosticsManager: DiagnosticsManager;
let statusBarItem: vscode.StatusBarItem;
let scanProgressManager: ScanProgressManager;
let inlineSecurityProvider: InlineSecurityProvider;
let inlineDiagnostics: vscode.DiagnosticCollection;

export async function activate(context: vscode.ExtensionContext) {
    console.log('AppSec AI Scanner extension activated');

    apiClient = new ApiClient(context);
    diagnosticsManager = new DiagnosticsManager();
    findingsProvider = new FindingsProvider(apiClient);
    scanProgressManager = new ScanProgressManager();
    inlineSecurityProvider = new InlineSecurityProvider();
    inlineDiagnostics = vscode.languages.createDiagnosticCollection('appsec-inline');

    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.text = "$(shield) AppSec";
    statusBarItem.tooltip = "AppSec AI Scanner";
    statusBarItem.command = 'appsec.scanWorkspace';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    vscode.window.registerTreeDataProvider('appsecFindings', findingsProvider);

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.login', async () => {
            await loginCommand(context);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.logout', async () => {
            await apiClient.logout();
            vscode.window.showInformationMessage('Logged out from AppSec platform');
            findingsProvider.refresh();
            updateStatusBar('disconnected');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.scanWorkspace', async () => {
            await scanWorkspaceCommand();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.scanCurrentFile', async () => {
            await scanCurrentFileCommand();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.refreshFindings', async () => {
            await refreshFindingsCommand();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.clearFindings', () => {
            diagnosticsManager.clear();
            vscode.window.showInformationMessage('Security findings cleared');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.viewOnDashboard', async () => {
            const config = vscode.workspace.getConfiguration('appsec');
            const apiUrl = config.get<string>('apiUrl', 'http://localhost:8000');
            const webUrl = apiUrl.replace(':8000', ':5173');
            vscode.env.openExternal(vscode.Uri.parse(webUrl));
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.applyFix', async (finding: any) => {
            await applyFixCommand(finding);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.markResolved', async (finding: any) => {
            await markStatusCommand(finding, 'resolved');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.markFalsePositive', async (finding: any) => {
            await markStatusCommand(finding, 'false_positive');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.showDetails', (finding: any) => {
            VulnerabilityDetailsPanel.show(finding, apiClient);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.openChatbot', () => {
            ChatbotPanel.show(apiClient);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.discussWithAI', (finding: any) => {
            ChatbotPanel.show(apiClient, finding);
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (document) => {
            const config = vscode.workspace.getConfiguration('appsec');
            const autoScan = config.get<boolean>('autoScan', false);

            if (autoScan && await apiClient.isAuthenticated()) {
                await scanFile(document.uri);
            }
        })
    );

    // Inline security analysis as you type
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(e => {
            if (e.document.uri.scheme === 'file') {
                analyzeDocumentInline(e.document);
            }
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(document => {
            if (document.uri.scheme === 'file') {
                analyzeDocumentInline(document);
            }
        })
    );

    // Register code action provider for inline suggestions
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            { scheme: 'file' },
            inlineSecurityProvider,
            {
                providedCodeActionKinds: InlineSecurityProvider.providedCodeActionKinds
            }
        )
    );

    // Analyze currently open documents
    if (vscode.window.activeTextEditor) {
        analyzeDocumentInline(vscode.window.activeTextEditor.document);
    }

    context.subscriptions.push(inlineDiagnostics);

    if (await apiClient.isAuthenticated()) {
        updateStatusBar('connected');
        vscode.window.showInformationMessage('Connected to AppSec platform');
    }
}

async function loginCommand(context: vscode.ExtensionContext) {
    const username = await vscode.window.showInputBox({
        prompt: 'Enter your AppSec platform username',
        placeHolder: 'username',
        ignoreFocusOut: true
    });

    if (!username) {
        return;
    }

    const password = await vscode.window.showInputBox({
        prompt: 'Enter your password',
        password: true,
        ignoreFocusOut: true
    });

    if (!password) {
        return;
    }

    try {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Logging in to AppSec platform...',
            cancellable: false
        }, async () => {
            await apiClient.login(username, password);
        });

        vscode.window.showInformationMessage('Successfully logged in to AppSec platform');
        updateStatusBar('connected');
        await refreshFindingsCommand();
    } catch (error: any) {
        vscode.window.showErrorMessage('Login failed: ' + error.message);
    }
}

async function scanWorkspaceCommand() {
    if (!await apiClient.isAuthenticated()) {
        const login = await vscode.window.showWarningMessage(
            'Please login to AppSec platform first',
            'Login'
        );
        if (login === 'Login') {
            await vscode.commands.executeCommand('appsec.login');
        }
        return;
    }

    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        vscode.window.showErrorMessage('No workspace folder open');
        return;
    }

    const startTime = Date.now();

    try {
        updateStatusBar('scanning');

        const results = await scanProgressManager.showScanProgress(
            'AppSec Security Scan',
            async (updateProgress) => {
                const workspacePath = workspaceFolders[0].uri.fsPath;

                updateProgress({
                    stage: 'initializing',
                    message: 'Initializing scan',
                    percentage: 10,
                    details: 'Preparing workspace analysis'
                });

                await new Promise(resolve => setTimeout(resolve, 500));

                updateProgress({
                    stage: 'analyzing',
                    message: 'Analyzing code',
                    percentage: 30,
                    details: 'Running SAST scanner'
                });

                updateProgress({
                    stage: 'detecting',
                    message: 'Detecting vulnerabilities',
                    percentage: 60,
                    details: 'Running SCA and secret detection'
                });

                const scanResults = await apiClient.scanWorkspace(workspacePath);

                updateProgress({
                    stage: 'completing',
                    message: 'Processing results',
                    percentage: 90,
                    details: 'Updating findings'
                });

                // Extract all findings from scan results
                const allFindings: any[] = [];
                if (scanResults.sast?.findings) {
                    allFindings.push(...scanResults.sast.findings);
                }
                if (scanResults.sca?.findings) {
                    allFindings.push(...scanResults.sca.findings);
                }
                if (scanResults.secrets?.findings) {
                    allFindings.push(...scanResults.secrets.findings);
                }

                diagnosticsManager.updateFromResults(scanResults);
                findingsProvider.setFindings(allFindings);

                updateProgress({
                    stage: 'complete',
                    message: 'Scan complete',
                    percentage: 100
                });

                return scanResults;
            }
        );

        updateStatusBar('connected');

        const duration = (Date.now() - startTime) / 1000;
        const totalFindings = (results.sast?.findings?.length || 0) +
                             (results.sca?.findings?.length || 0) +
                             (results.secrets?.findings?.length || 0);

        scanProgressManager.showScanComplete(totalFindings, duration);

    } catch (error: any) {
        updateStatusBar('error');
        scanProgressManager.showScanError(error.message);
        setTimeout(() => updateStatusBar('connected'), 3000);
    }
}

async function scanCurrentFileCommand() {
    if (!await apiClient.isAuthenticated()) {
        const login = await vscode.window.showWarningMessage(
            'Please login to AppSec platform first',
            'Login'
        );
        if (login === 'Login') {
            await vscode.commands.executeCommand('appsec.login');
        }
        return;
    }

    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active file');
        return;
    }

    await scanFile(editor.document.uri);
}

async function scanFile(fileUri: vscode.Uri) {
    const startTime = Date.now();
    const fileName = fileUri.fsPath.split('/').pop();

    try {
        updateStatusBar('scanning');

        const results = await scanProgressManager.showScanProgress(
            `Scanning ${fileName}`,
            async (updateProgress) => {
                updateProgress({
                    stage: 'analyzing',
                    message: 'Analyzing file',
                    percentage: 30,
                    details: fileName || ''
                });

                const scanResults = await apiClient.scanFile(fileUri.fsPath);

                updateProgress({
                    stage: 'completing',
                    message: 'Processing results',
                    percentage: 80,
                    details: 'Updating diagnostics'
                });

                // Extract findings from file scan results
                const fileFindings: any[] = [];
                if (scanResults.sast?.findings) {
                    fileFindings.push(...scanResults.sast.findings);
                }
                if (scanResults.secrets?.findings) {
                    fileFindings.push(...scanResults.secrets.findings);
                }

                // Merge with existing findings
                const existingFindings = findingsProvider.getAllFindings();
                const otherFindings = existingFindings.filter((f: any) => f.file !== fileUri.fsPath);
                const allFindings = [...otherFindings, ...fileFindings];

                diagnosticsManager.updateFileFromResults(fileUri, scanResults);
                findingsProvider.setFindings(allFindings);

                updateProgress({
                    stage: 'complete',
                    message: 'Scan complete',
                    percentage: 100
                });

                return scanResults;
            }
        );

        updateStatusBar('connected');

        const duration = (Date.now() - startTime) / 1000;
        const findings = results.sast?.findings || [];

        if (findings.length > 0) {
            vscode.window.showWarningMessage(
                `⚠️ Found ${findings.length} issue${findings.length !== 1 ? 's' : ''} in ${fileName}`,
                'View Results'
            ).then(selection => {
                if (selection === 'View Results') {
                    vscode.commands.executeCommand('workbench.view.extension.appsec-sidebar');
                }
            });
        } else {
            vscode.window.showInformationMessage(`✅ No issues found in ${fileName}`);
        }

    } catch (error: any) {
        updateStatusBar('error');
        scanProgressManager.showScanError(error.message);
        setTimeout(() => updateStatusBar('connected'), 3000);
    }
}

async function refreshFindingsCommand() {
    if (!await apiClient.isAuthenticated()) {
        return;
    }

    try {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Refreshing findings...',
            cancellable: false
        }, async () => {
            findingsProvider.refresh();
        });
    } catch (error: any) {
        vscode.window.showErrorMessage('Failed to refresh: ' + error.message);
    }
}

async function applyFixCommand(finding: any) {
    if (!finding || !finding.fix) {
        vscode.window.showWarningMessage('No fix available for this finding');
        return;
    }

    try {
        const document = await vscode.workspace.openTextDocument(finding.file);
        const editor = await vscode.window.showTextDocument(document);

        const edit = new vscode.WorkspaceEdit();

        if (finding.fix.code) {
            const range = new vscode.Range(
                finding.line - 1, 0,
                finding.line, 0
            );
            edit.replace(document.uri, range, finding.fix.code);
        }

        const success = await vscode.workspace.applyEdit(edit);

        if (success) {
            vscode.window.showInformationMessage('Fix applied successfully');
            await markStatusCommand(finding, 'resolved');
        }
    } catch (error: any) {
        vscode.window.showErrorMessage('Failed to apply fix: ' + error.message);
    }
}

async function markStatusCommand(finding: any, status: string) {
    if (!finding) {
        return;
    }

    try {
        await apiClient.updateFindingStatus(finding.id, status);
        vscode.window.showInformationMessage('Finding marked as ' + status);
        findingsProvider.refresh();

        if (status === 'resolved') {
            diagnosticsManager.removeFinding(finding);
        }
    } catch (error: any) {
        vscode.window.showErrorMessage('Failed to update status: ' + error.message);
    }
}

function analyzeDocumentInline(document: vscode.TextDocument) {
    // Only analyze source code files
    const supportedLanguages = ['javascript', 'typescript', 'python', 'java', 'csharp', 'php', 'ruby', 'go'];
    if (!supportedLanguages.includes(document.languageId)) {
        return;
    }

    const diagnostics = inlineSecurityProvider.analyzeDocument(document);
    inlineDiagnostics.set(document.uri, diagnostics);
}

function updateStatusBar(status: 'connected' | 'disconnected' | 'scanning' | 'error') {
    switch (status) {
        case 'connected':
            statusBarItem.text = "$(shield) AppSec";
            statusBarItem.tooltip = "AppSec AI Scanner - Connected";
            statusBarItem.backgroundColor = undefined;
            break;
        case 'disconnected':
            statusBarItem.text = "$(shield) AppSec (disconnected)";
            statusBarItem.tooltip = "Click to login";
            statusBarItem.command = 'appsec.login';
            break;
        case 'scanning':
            statusBarItem.text = "$(loading~spin) Scanning...";
            statusBarItem.tooltip = "AppSec AI Scanner - Scanning";
            break;
        case 'error':
            statusBarItem.text = "$(shield) AppSec (error)";
            statusBarItem.tooltip = "AppSec AI Scanner - Error";
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            break;
    }
}

export function deactivate() {
    diagnosticsManager.dispose();
    inlineDiagnostics.dispose();
}
