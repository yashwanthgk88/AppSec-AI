import * as vscode from 'vscode';
import { ApiClient } from './apiClient';
import { FindingsProvider } from './findingsProvider';
import { ScaFindingsProvider } from './scaFindingsProvider';
import { SecretsFindingsProvider } from './secretsFindingsProvider';
import { DiagnosticsManager } from './diagnosticsManager';
import { VulnerabilityDetailsPanel } from './vulnerabilityDetailsPanel';
import { ChatbotPanel } from './chatbotPanel';
import { ScanProgressManager } from './scanProgressManager';
import { InlineSecurityProvider } from './inlineSecurityProvider';
import { CustomRulesProvider } from './customRulesProvider';
import { RulePerformancePanel } from './RulePerformancePanel';

let apiClient: ApiClient;
let findingsProvider: FindingsProvider;
let scaFindingsProvider: ScaFindingsProvider;
let secretsFindingsProvider: SecretsFindingsProvider;
let customRulesProvider: CustomRulesProvider;
let diagnosticsManager: DiagnosticsManager;
let statusBarItem: vscode.StatusBarItem;
let scanProgressManager: ScanProgressManager;
let inlineSecurityProvider: InlineSecurityProvider;
let inlineDiagnostics: vscode.DiagnosticCollection;

export async function activate(context: vscode.ExtensionContext) {
    console.log('SecureDev AI Scanner extension activated');

    apiClient = new ApiClient(context);
    diagnosticsManager = new DiagnosticsManager();
    findingsProvider = new FindingsProvider(apiClient);
    scaFindingsProvider = new ScaFindingsProvider(apiClient);
    secretsFindingsProvider = new SecretsFindingsProvider(apiClient);
    customRulesProvider = new CustomRulesProvider(apiClient);
    scanProgressManager = new ScanProgressManager();
    inlineSecurityProvider = new InlineSecurityProvider();
    inlineDiagnostics = vscode.languages.createDiagnosticCollection('appsec-inline');

    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.text = "$(shield) SecureDev AI";
    statusBarItem.tooltip = "SecureDev AI Scanner";
    statusBarItem.command = 'appsec.scanWorkspace';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    vscode.window.registerTreeDataProvider('appsecFindings', findingsProvider);
    vscode.window.registerTreeDataProvider('appsecScaFindings', scaFindingsProvider);
    vscode.window.registerTreeDataProvider('appsecSecretsFindings', secretsFindingsProvider);
    vscode.window.registerTreeDataProvider('appsecCustomRules', customRulesProvider);

    // Listen for configuration changes to reload API client
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration('appsec.apiUrl') || e.affectsConfiguration('appsec.frontendUrl')) {
                apiClient = new ApiClient(context);
                findingsProvider = new FindingsProvider(apiClient);
                scaFindingsProvider = new ScaFindingsProvider(apiClient);
                secretsFindingsProvider = new SecretsFindingsProvider(apiClient);
                customRulesProvider = new CustomRulesProvider(apiClient);
                vscode.window.showInformationMessage('SecureDev AI: Server configuration updated. Please login again.');
            }
        })
    );

    // Configure Server URL Command
    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.configureServer', async () => {
            await configureServerCommand();
        })
    );

    // Test Connection Command
    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.testConnection', async () => {
            await testConnectionCommand();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.login', async () => {
            await loginCommand(context);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.logout', async () => {
            await apiClient.logout();
            vscode.window.showInformationMessage('Logged out from SecureDev AI platform');
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
            const frontendUrl = config.get<string>('frontendUrl', 'http://localhost:5173');
            vscode.env.openExternal(vscode.Uri.parse(frontendUrl));
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
        vscode.commands.registerCommand('appsec.showScaDetails', (finding: any) => {
            VulnerabilityDetailsPanel.show(finding, apiClient);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.showSecretDetails', (finding: any) => {
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

    // Custom Rules Commands

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.viewOnWeb', () => {
            const config = vscode.workspace.getConfiguration('appsec');
            const frontendUrl = config.get<string>('frontendUrl', 'http://localhost:5173');
            vscode.env.openExternal(vscode.Uri.parse(frontendUrl));
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.manageCustomRules', () => {
            const config = vscode.workspace.getConfiguration('appsec');
            const frontendUrl = config.get<string>('frontendUrl', 'http://localhost:5173');
            vscode.env.openExternal(vscode.Uri.parse(frontendUrl + '/custom-rules'));
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.viewRulePerformance', async () => {
            try {
                console.log('Opening Rule Performance Dashboard...');
                RulePerformancePanel.show(apiClient);
            } catch (error: any) {
                console.error('Error opening Rule Performance Dashboard:', error);
                vscode.window.showErrorMessage('Failed to open Rule Performance Dashboard: ' + error.message);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.refreshCustomRules', () => {
            customRulesProvider.refresh();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.createCustomRule', async () => {
            await createCustomRuleCommand();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.editCustomRule', async (ruleItem: any) => {
            await editCustomRuleCommand(ruleItem);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.deleteCustomRule', async (ruleItem: any) => {
            await deleteCustomRuleCommand(ruleItem);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.toggleCustomRule', async (ruleItem: any) => {
            await toggleCustomRuleCommand(ruleItem);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.generateRuleWithAI', async () => {
            await generateRuleWithAICommand();
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
        vscode.window.showInformationMessage('Connected to SecureDev AI platform');
    }
}

// Configure Server URL Command
async function configureServerCommand() {
    const config = vscode.workspace.getConfiguration('appsec');
    const currentApiUrl = config.get<string>('apiUrl', 'http://localhost:8000');
    const currentFrontendUrl = config.get<string>('frontendUrl', 'http://localhost:5173');

    const choice = await vscode.window.showQuickPick([
        { label: 'Configure API URL', description: `Current: ${currentApiUrl}`, value: 'api' },
        { label: 'Configure Web Dashboard URL', description: `Current: ${currentFrontendUrl}`, value: 'frontend' },
        { label: 'Configure Both', description: 'Set both API and Web Dashboard URLs', value: 'both' },
        { label: 'Use Local Development', description: 'localhost:8000 / localhost:5173', value: 'local' },
        { label: 'Open Settings', description: 'Open VS Code settings for full configuration', value: 'settings' }
    ], { placeHolder: 'Select configuration option' });

    if (!choice) {return;}

    switch (choice.value) {
        case 'api':
            const newApiUrl = await vscode.window.showInputBox({
                prompt: 'Enter the SecureDev AI API URL',
                placeHolder: 'https://your-domain.com or http://localhost:8000',
                value: currentApiUrl,
                validateInput: (value) => {
                    try {
                        new URL(value);
                        return null;
                    } catch {
                        return 'Please enter a valid URL';
                    }
                }
            });
            if (newApiUrl) {
                await config.update('apiUrl', newApiUrl, vscode.ConfigurationTarget.Global);
                vscode.window.showInformationMessage(`API URL updated to: ${newApiUrl}`);
            }
            break;

        case 'frontend':
            const newFrontendUrl = await vscode.window.showInputBox({
                prompt: 'Enter the SecureDev AI Web Dashboard URL',
                placeHolder: 'https://your-domain.com or http://localhost:5173',
                value: currentFrontendUrl,
                validateInput: (value) => {
                    try {
                        new URL(value);
                        return null;
                    } catch {
                        return 'Please enter a valid URL';
                    }
                }
            });
            if (newFrontendUrl) {
                await config.update('frontendUrl', newFrontendUrl, vscode.ConfigurationTarget.Global);
                vscode.window.showInformationMessage(`Web Dashboard URL updated to: ${newFrontendUrl}`);
            }
            break;

        case 'both':
            const baseUrl = await vscode.window.showInputBox({
                prompt: 'Enter your SecureDev AI server domain/IP (without port)',
                placeHolder: 'https://your-domain.com or http://192.168.1.100',
                validateInput: (value) => {
                    try {
                        new URL(value);
                        return null;
                    } catch {
                        return 'Please enter a valid URL';
                    }
                }
            });
            if (baseUrl) {
                const url = new URL(baseUrl);
                const apiEndpoint = url.protocol === 'https:'
                    ? `${url.origin}/api`
                    : `${url.protocol}//${url.hostname}:8000`;
                const frontendEndpoint = url.protocol === 'https:'
                    ? url.origin
                    : `${url.protocol}//${url.hostname}:5173`;

                await config.update('apiUrl', apiEndpoint, vscode.ConfigurationTarget.Global);
                await config.update('frontendUrl', frontendEndpoint, vscode.ConfigurationTarget.Global);
                vscode.window.showInformationMessage(`Server configured: API=${apiEndpoint}, Web=${frontendEndpoint}`);
            }
            break;

        case 'local':
            await config.update('apiUrl', 'http://localhost:8000', vscode.ConfigurationTarget.Global);
            await config.update('frontendUrl', 'http://localhost:5173', vscode.ConfigurationTarget.Global);
            vscode.window.showInformationMessage('Configured for local development');
            break;

        case 'settings':
            vscode.commands.executeCommand('workbench.action.openSettings', 'appsec');
            break;
    }
}

// Test Connection Command
async function testConnectionCommand() {
    const config = vscode.workspace.getConfiguration('appsec');
    const apiUrl = config.get<string>('apiUrl', 'http://localhost:8000');

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Testing connection to SecureDev AI server...',
        cancellable: false
    }, async () => {
        try {
            const axios = require('axios');
            const response = await axios.get(`${apiUrl}/health`, { timeout: 10000 });

            if (response.status === 200) {
                vscode.window.showInformationMessage(
                    `✅ Successfully connected to SecureDev AI server at ${apiUrl}`,
                    'Login Now'
                ).then(selection => {
                    if (selection === 'Login Now') {
                        vscode.commands.executeCommand('appsec.login');
                    }
                });
            }
        } catch (error: any) {
            const errorMessage = error.code === 'ECONNREFUSED'
                ? 'Connection refused - Is the server running?'
                : error.code === 'ETIMEDOUT'
                ? 'Connection timed out - Check the URL'
                : error.message;

            vscode.window.showErrorMessage(
                `❌ Failed to connect to ${apiUrl}: ${errorMessage}`,
                'Configure Server'
            ).then(selection => {
                if (selection === 'Configure Server') {
                    vscode.commands.executeCommand('appsec.configureServer');
                }
            });
        }
    });
}

async function loginCommand(context: vscode.ExtensionContext) {
    const username = await vscode.window.showInputBox({
        prompt: 'Enter your SecureDev AI platform username',
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
            title: 'Logging in to SecureDev AI platform...',
            cancellable: false
        }, async () => {
            await apiClient.login(username, password);
        });

        vscode.window.showInformationMessage('Successfully logged in to SecureDev AI platform');
        updateStatusBar('connected');
        await refreshFindingsCommand();
    } catch (error: any) {
        vscode.window.showErrorMessage('Login failed: ' + error.message);
    }
}

async function scanWorkspaceCommand() {
    if (!await apiClient.isAuthenticated()) {
        const login = await vscode.window.showWarningMessage(
            'Please login to SecureDev AI platform first',
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
            'SecureDev AI Security Scan',
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

                // Extract findings by type
                const sastFindings: any[] = [];
                const scaFindings: any[] = [];
                const secretsFindings: any[] = [];

                if (scanResults.sast?.findings) {
                    sastFindings.push(...scanResults.sast.findings);
                }
                if (scanResults.sca?.findings) {
                    scaFindings.push(...scanResults.sca.findings);
                }
                if (scanResults.secrets?.findings) {
                    secretsFindings.push(...scanResults.secrets.findings);
                }

                diagnosticsManager.updateFromResults(scanResults);
                findingsProvider.setFindings(sastFindings);
                scaFindingsProvider.setFindings(scaFindings);
                secretsFindingsProvider.setFindings(secretsFindings);

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
            'Please login to SecureDev AI platform first',
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

                // Extract findings by type from file scan
                const fileSastFindings: any[] = [];
                const fileSecretsFindings: any[] = [];

                if (scanResults.sast?.findings) {
                    fileSastFindings.push(...scanResults.sast.findings);
                }
                if (scanResults.secrets?.findings) {
                    fileSecretsFindings.push(...scanResults.secrets.findings);
                }

                // Merge with existing findings for each type
                const existingSastFindings = findingsProvider.getAllFindings();
                const otherSastFindings = existingSastFindings.filter((f: any) => f.file !== fileUri.fsPath);
                const allSastFindings = [...otherSastFindings, ...fileSastFindings];

                const existingSecretsFindings = secretsFindingsProvider.getAllFindings();
                const otherSecretsFindings = existingSecretsFindings.filter((f: any) => f.file !== fileUri.fsPath);
                const allSecretsFindings = [...otherSecretsFindings, ...fileSecretsFindings];

                diagnosticsManager.updateFileFromResults(fileUri, scanResults);
                findingsProvider.setFindings(allSastFindings);
                secretsFindingsProvider.setFindings(allSecretsFindings);

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
            statusBarItem.text = "$(shield) SecureDev AI";
            statusBarItem.tooltip = "SecureDev AI Scanner - Connected";
            statusBarItem.backgroundColor = undefined;
            break;
        case 'disconnected':
            statusBarItem.text = "$(shield) SecureDev AI (disconnected)";
            statusBarItem.tooltip = "Click to login";
            statusBarItem.command = 'appsec.login';
            break;
        case 'scanning':
            statusBarItem.text = "$(loading~spin) Scanning...";
            statusBarItem.tooltip = "SecureDev AI Scanner - Scanning";
            break;
        case 'error':
            statusBarItem.text = "$(shield) SecureDev AI (error)";
            statusBarItem.tooltip = "SecureDev AI Scanner - Error";
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            break;
    }
}

// Custom Rules Command Handlers

async function createCustomRuleCommand() {
    if (!await apiClient.isAuthenticated()) {
        vscode.window.showWarningMessage('Please login first');
        return;
    }

    const name = await vscode.window.showInputBox({
        prompt: 'Enter rule name',
        placeHolder: 'e.g., Hardcoded API Key'
    });
    if (!name) {return;}

    const pattern = await vscode.window.showInputBox({
        prompt: 'Enter regex pattern',
        placeHolder: 'e.g., api[_-]?key["\']\\s*[:=]\\s*["\'][a-zA-Z0-9]{20,}'
    });
    if (!pattern) {return;}

    const severity = await vscode.window.showQuickPick(
        ['critical', 'high', 'medium', 'low'],
        { placeHolder: 'Select severity level' }
    );
    if (!severity) {return;}

    const description = await vscode.window.showInputBox({
        prompt: 'Enter description',
        placeHolder: 'Describe what this rule detects'
    });
    if (!description) {return;}

    const language = await vscode.window.showInputBox({
        prompt: 'Enter programming language (* for all)',
        placeHolder: '* or javascript, python, etc.',
        value: '*'
    });

    try {
        await apiClient.createCustomRule({
            name,
            pattern,
            severity,
            description,
            language: language || '*',
            enabled: true
        });

        vscode.window.showInformationMessage(`Rule "${name}" created successfully`);
        customRulesProvider.refresh();
    } catch (error: any) {
        vscode.window.showErrorMessage('Failed to create rule: ' + error.message);
    }
}

async function editCustomRuleCommand(ruleItem: any) {
    if (!ruleItem || !ruleItem.rule) {
        vscode.window.showWarningMessage('No rule selected');
        return;
    }

    const rule = ruleItem.rule;

    const options = await vscode.window.showQuickPick([
        { label: 'Edit Name', value: 'name' },
        { label: 'Edit Pattern', value: 'pattern' },
        { label: 'Edit Description', value: 'description' },
        { label: 'Change Severity', value: 'severity' },
        { label: 'Change Language', value: 'language' }
    ], { placeHolder: 'What would you like to edit?' });

    if (!options) {return;}

    try {
        let updates: any = {};

        switch (options.value) {
            case 'name':
                const newName = await vscode.window.showInputBox({
                    prompt: 'Enter new name',
                    value: rule.name
                });
                if (newName) {updates.name = newName;}
                break;

            case 'pattern':
                const newPattern = await vscode.window.showInputBox({
                    prompt: 'Enter new pattern',
                    value: rule.pattern
                });
                if (newPattern) {updates.pattern = newPattern;}
                break;

            case 'description':
                const newDesc = await vscode.window.showInputBox({
                    prompt: 'Enter new description',
                    value: rule.description
                });
                if (newDesc) {updates.description = newDesc;}
                break;

            case 'severity':
                const newSeverity = await vscode.window.showQuickPick(
                    ['critical', 'high', 'medium', 'low'],
                    { placeHolder: 'Select severity level' }
                );
                if (newSeverity) {updates.severity = newSeverity;}
                break;

            case 'language':
                const newLang = await vscode.window.showInputBox({
                    prompt: 'Enter language',
                    value: rule.language
                });
                if (newLang) {updates.language = newLang;}
                break;
        }

        if (Object.keys(updates).length > 0) {
            await apiClient.updateCustomRule(rule.id, updates);
            vscode.window.showInformationMessage('Rule updated successfully');
            customRulesProvider.refresh();
        }
    } catch (error: any) {
        vscode.window.showErrorMessage('Failed to update rule: ' + error.message);
    }
}

async function deleteCustomRuleCommand(ruleItem: any) {
    if (!ruleItem || !ruleItem.rule) {
        vscode.window.showWarningMessage('No rule selected');
        return;
    }

    const rule = ruleItem.rule;

    const confirm = await vscode.window.showWarningMessage(
        `Are you sure you want to delete rule "${rule.name}"?`,
        { modal: true },
        'Delete'
    );

    if (confirm !== 'Delete') {return;}

    try {
        await apiClient.deleteCustomRule(rule.id);
        vscode.window.showInformationMessage(`Rule "${rule.name}" deleted successfully`);
        customRulesProvider.refresh();
    } catch (error: any) {
        vscode.window.showErrorMessage('Failed to delete rule: ' + error.message);
    }
}

async function toggleCustomRuleCommand(ruleItem: any) {
    if (!ruleItem || !ruleItem.rule) {
        vscode.window.showWarningMessage('No rule selected');
        return;
    }

    const rule = ruleItem.rule;

    try {
        await apiClient.updateCustomRule(rule.id, { enabled: !rule.enabled });
        vscode.window.showInformationMessage(
            `Rule "${rule.name}" ${!rule.enabled ? 'enabled' : 'disabled'}`
        );
        customRulesProvider.refresh();
    } catch (error: any) {
        vscode.window.showErrorMessage('Failed to toggle rule: ' + error.message);
    }
}

async function generateRuleWithAICommand() {
    if (!await apiClient.isAuthenticated()) {
        vscode.window.showWarningMessage('Please login first');
        return;
    }

    const ruleName = await vscode.window.showInputBox({
        prompt: 'Enter a name for the rule',
        placeHolder: 'e.g., SQL Injection Detection'
    });
    if (!ruleName) {return;}

    const vulnDescription = await vscode.window.showInputBox({
        prompt: 'Describe the vulnerability this rule should detect',
        placeHolder: 'e.g., Detect SQL injection vulnerabilities in database queries'
    });
    if (!vulnDescription) {return;}

    const severity = await vscode.window.showQuickPick(
        ['critical', 'high', 'medium', 'low'],
        { placeHolder: 'Select severity level' }
    );
    if (!severity) {return;}

    const languagesInput = await vscode.window.showInputBox({
        prompt: 'Enter programming languages (comma-separated) or * for all',
        placeHolder: 'javascript,python,java or *',
        value: '*'
    });

    const languages = languagesInput === '*' ? ['*'] : languagesInput?.split(',').map(l => l.trim()) || ['*'];

    try {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Generating rule with AI...',
            cancellable: false
        }, async () => {
            const result = await apiClient.generateRuleWithAI({
                rule_name: ruleName,
                vulnerability_description: vulnDescription,
                severity,
                languages
            });

            // Poll for job completion
            if (result.job_id) {
                await pollJobStatus(result.job_id);
            }
        });

        vscode.window.showInformationMessage('AI rule generation completed');
        customRulesProvider.refresh();
    } catch (error: any) {
        vscode.window.showErrorMessage('Failed to generate rule: ' + error.message);
    }
}

async function pollJobStatus(jobId: number, maxAttempts = 30) {
    for (let i = 0; i < maxAttempts; i++) {
        await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds

        try {
            const job = await apiClient.getEnhancementJobStatus(jobId);

            if (job.status === 'completed') {
                return;
            } else if (job.status === 'failed') {
                throw new Error('Job failed: ' + (job.errors || 'Unknown error'));
            }
        } catch (error) {
            console.error('Error polling job status:', error);
        }
    }

    throw new Error('Job timed out');
}

export function deactivate() {
    diagnosticsManager.dispose();
    inlineDiagnostics.dispose();
}
