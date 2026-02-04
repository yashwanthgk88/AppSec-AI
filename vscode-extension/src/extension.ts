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
import { EnhancedSecurityProvider } from './enhancedSecurityProvider';
import { TaintFlowPanel } from './taintFlowPanel';
import { createSecurityScanner, SecurityFinding } from './scanner';

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
let enhancedSecurityProvider: EnhancedSecurityProvider;
let enhancedFindings: SecurityFinding[] = [];

export async function activate(context: vscode.ExtensionContext) {
    try {
        console.log('SecureDev AI Scanner extension activating...');

        apiClient = new ApiClient(context);
        diagnosticsManager = new DiagnosticsManager();
        findingsProvider = new FindingsProvider(apiClient);
        scaFindingsProvider = new ScaFindingsProvider(apiClient);
        secretsFindingsProvider = new SecretsFindingsProvider(apiClient);
        customRulesProvider = new CustomRulesProvider(apiClient);
        scanProgressManager = new ScanProgressManager();
        inlineSecurityProvider = new InlineSecurityProvider();
        inlineDiagnostics = vscode.languages.createDiagnosticCollection('appsec-inline');
        enhancedSecurityProvider = new EnhancedSecurityProvider();

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

    // Deep Inter-Procedural Scan Command
    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.deepScan', async () => {
            await deepScanCommand(context);
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
        vscode.commands.registerCommand('appsec.markResolved', async (findingOrItem: any) => {
            const finding = findingOrItem?.finding || findingOrItem;
            await markStatusCommand(finding, 'resolved');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.markFalsePositive', async (findingOrItem: any) => {
            const finding = findingOrItem?.finding || findingOrItem;
            await markStatusCommand(finding, 'false_positive');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.showDetails', async (findingOrItem: any) => {
            // Handle both direct finding objects and FindingItem tree items
            const finding = findingOrItem?.finding || findingOrItem;

            // Show the vulnerability details panel
            VulnerabilityDetailsPanel.show(finding, apiClient);

            // Also open the file and navigate to the vulnerable line
            // Check all possible file path field names
            const filePathRaw = finding?.file || finding?.file_path || finding?.location?.file;
            if (finding && filePathRaw) {
                try {
                    let filePath = filePathRaw;

                    // Resolve relative path to absolute path using workspace folder
                    if (!filePath.startsWith('/') && !filePath.match(/^[a-zA-Z]:\\/)) {
                        const workspaceFolders = vscode.workspace.workspaceFolders;
                        if (workspaceFolders && workspaceFolders.length > 0) {
                            filePath = vscode.Uri.joinPath(workspaceFolders[0].uri, filePath).fsPath;
                        }
                    }

                    const fileUri = vscode.Uri.file(filePath);
                    const document = await vscode.workspace.openTextDocument(fileUri);
                    const editor = await vscode.window.showTextDocument(document, vscode.ViewColumn.One);

                    const lineNum = finding.line || finding.line_number || finding.location?.startLine || 1;
                    const line = Math.max(0, lineNum - 1);
                    const lineLength = document.lineAt(line).text.length;
                    const range = new vscode.Range(line, 0, line, lineLength);

                    // Highlight the entire line
                    editor.selection = new vscode.Selection(range.start, range.end);
                    editor.revealRange(range, vscode.TextEditorRevealType.InCenter);

                    // Add a decoration to make the line more visible
                    const decorationType = vscode.window.createTextEditorDecorationType({
                        backgroundColor: 'rgba(255, 0, 0, 0.3)',
                        isWholeLine: true,
                        borderWidth: '2px',
                        borderStyle: 'solid',
                        borderColor: 'rgba(255, 0, 0, 0.8)',
                        overviewRulerColor: 'red',
                        overviewRulerLane: vscode.OverviewRulerLane.Full
                    });
                    editor.setDecorations(decorationType, [range]);

                    // Clear decoration after 5 seconds
                    setTimeout(() => {
                        decorationType.dispose();
                    }, 5000);
                } catch (error: any) {
                    console.error('Failed to open file:', error);
                }
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.showScaDetails', (findingOrItem: any) => {
            const finding = findingOrItem?.finding || findingOrItem;
            VulnerabilityDetailsPanel.show(finding, apiClient);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.showSecretDetails', (findingOrItem: any) => {
            const finding = findingOrItem?.finding || findingOrItem;
            VulnerabilityDetailsPanel.show(finding, apiClient);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.openChatbot', () => {
            ChatbotPanel.show(apiClient);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.discussWithAI', (findingOrItem: any) => {
            const finding = findingOrItem?.finding || findingOrItem;
            ChatbotPanel.show(apiClient, finding);
        })
    );

    // Taint Flow Visualization Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.showTaintFlow', () => {
            if (enhancedFindings.length === 0) {
                vscode.window.showInformationMessage('No taint flow vulnerabilities detected. Run an enhanced scan first.');
                return;
            }
            TaintFlowPanel.show(enhancedFindings, context.extensionUri);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.showFindingTaintFlow', (findingOrItem: any) => {
            // Handle both direct finding objects and FindingItem tree items
            const finding = findingOrItem?.finding || findingOrItem;
            if (finding && finding.taintFlow) {
                TaintFlowPanel.show([finding], context.extensionUri);
            } else if (finding) {
                // Generate taint flow on-the-fly for API findings
                const enhancedFinding = generateTaintFlowForFinding(finding);
                TaintFlowPanel.show([enhancedFinding], context.extensionUri);
            } else {
                vscode.window.showWarningMessage('No finding selected for taint flow visualization.');
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('appsec.enhancedScan', async () => {
            await runEnhancedScan(context);
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

    // Inline security analysis as you type - REAL-TIME DETECTION
    console.log('[SecureDev AI] Registering inline security analysis...');

    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(e => {
            // Analyze on EVERY text change
            if (e.document.uri.scheme === 'file' && e.contentChanges.length > 0) {
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

    // Also trigger on active editor change
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && editor.document.uri.scheme === 'file') {
                analyzeDocumentInline(editor.document);
            }
        })
    );

    // Register code action provider for ALL languages
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            { scheme: 'file', pattern: '**/*' },
            inlineSecurityProvider,
            {
                providedCodeActionKinds: InlineSecurityProvider.providedCodeActionKinds
            }
        )
    );

    // Analyze ALL currently open documents
    vscode.workspace.textDocuments.forEach(document => {
        if (document.uri.scheme === 'file') {
            analyzeDocumentInline(document);
        }
    });

    // Also analyze active editor
    if (vscode.window.activeTextEditor) {
        analyzeDocumentInline(vscode.window.activeTextEditor.document);
    }

    console.log('[SecureDev AI] Inline security analysis registered successfully!');

    context.subscriptions.push(inlineDiagnostics);

    if (await apiClient.isAuthenticated()) {
        updateStatusBar('connected');
        vscode.window.showInformationMessage('Connected to SecureDev AI platform');
    }

    console.log('SecureDev AI Scanner extension activated successfully');
    } catch (error: any) {
        console.error('SecureDev AI Scanner activation failed:', error);
        vscode.window.showErrorMessage(`SecureDev AI Scanner failed to activate: ${error.message}`);
        throw error;
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

/**
 * Deep Inter-Procedural Scan Command
 * Uses the backend's inter-procedural analyzer for cross-function taint tracking
 */
async function deepScanCommand(context: vscode.ExtensionContext) {
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
        vscode.window.showErrorMessage('No active file to scan');
        return;
    }

    const fileUri = editor.document.uri;
    const fileName = fileUri.fsPath.split('/').pop() || 'file';
    const startTime = Date.now();

    try {
        updateStatusBar('scanning');

        const results = await scanProgressManager.showScanProgress(
            `Deep Scanning ${fileName}`,
            async (updateProgress) => {
                updateProgress({
                    stage: 'initializing',
                    message: 'Initializing deep scan',
                    percentage: 10,
                    details: 'Preparing inter-procedural analysis'
                });

                await new Promise(resolve => setTimeout(resolve, 300));

                updateProgress({
                    stage: 'analyzing',
                    message: 'Building call graph',
                    percentage: 30,
                    details: 'Analyzing function calls'
                });

                updateProgress({
                    stage: 'analyzing',
                    message: 'Generating function summaries',
                    percentage: 50,
                    details: 'Tracking taint behavior across functions'
                });

                // Use the deep scan endpoint
                const scanResults = await apiClient.deepScanFile(fileUri.fsPath);

                updateProgress({
                    stage: 'detecting',
                    message: 'Tracking cross-function data flows',
                    percentage: 70,
                    details: 'Detecting vulnerabilities with inter-procedural analysis'
                });

                updateProgress({
                    stage: 'completing',
                    message: 'Processing results',
                    percentage: 90,
                    details: 'Updating findings'
                });

                // Process findings from deep scan
                const deepFindings: any[] = [];

                // Handle SAST findings with inter-procedural data
                if (scanResults.sast?.findings) {
                    deepFindings.push(...scanResults.sast.findings);
                }

                // Handle inter-procedural specific findings
                if (scanResults.interprocedural?.taint_findings) {
                    scanResults.interprocedural.taint_findings.forEach((finding: any) => {
                        deepFindings.push({
                            ...finding,
                            title: finding.title || `Cross-Function ${finding.vulnerability_type || 'Vulnerability'}`,
                            severity: finding.severity || 'high',
                            category: 'Inter-Procedural Analysis',
                            call_chain: finding.call_chain || [],
                            function_summary: finding.function_summary,
                            cross_function_flow: finding.taint_path || finding.path
                        });
                    });
                }

                // Merge with existing findings
                const existingFindings = findingsProvider.getAllFindings();
                const otherFindings = existingFindings.filter((f: any) =>
                    (f.file || f.location?.file) !== fileUri.fsPath
                );
                const allFindings = [...otherFindings, ...deepFindings];

                diagnosticsManager.updateFileFromResults(fileUri, scanResults);
                findingsProvider.setFindings(allFindings);

                // Store for taint flow visualization
                if (deepFindings.length > 0) {
                    enhancedFindings = deepFindings.map(f => ({
                        id: f.id || `deep_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`,
                        title: f.title,
                        type: f.type || f.vulnerability_type || 'security-issue',
                        severity: f.severity,
                        description: f.description,
                        recommendation: f.recommendation || f.remediation || 'Review and fix the security vulnerability',
                        location: f.location || { file: f.file, startLine: f.line || 1, startColumn: 0, endLine: f.line || 1, endColumn: 80 },
                        codeSnippet: f.code_snippet || f.codeSnippet || '',
                        cweId: f.cwe_id || f.cweId,
                        owaspCategory: f.owasp_category || f.owaspCategory,
                        confidence: f.confidence || 'high',
                        taintFlow: f.taintFlow || (f.call_chain ? {
                            source: { id: 'src', name: f.call_chain[0] || 'source', category: 'user-input', pattern: { type: 'call' as const }, description: 'Taint source' },
                            sink: { id: 'sink', name: f.call_chain[f.call_chain.length - 1] || 'sink', category: 'dangerous-call', pattern: { type: 'call' as const }, vulnerabilityType: f.type, description: 'Taint sink' },
                            taintedValue: { variable: 'data', source: null as any, location: f.location, path: [] },
                            path: f.call_chain.map((func: string, idx: number) => ({
                                location: f.location || { file: fileUri.fsPath, startLine: f.line || 1, startColumn: 0, endLine: f.line || 1, endColumn: 80 },
                                description: idx === 0 ? `SOURCE: ${func}` : idx === f.call_chain.length - 1 ? `SINK: ${func}` : `FLOW: ${func}`,
                                node: { type: 'Call' as const, location: f.location }
                            })),
                            sanitizers: []
                        } : undefined)
                    }));
                }

                updateProgress({
                    stage: 'complete',
                    message: 'Deep scan complete',
                    percentage: 100
                });

                return { ...scanResults, deepFindings };
            }
        );

        updateStatusBar('connected');

        const totalFindings = results.deepFindings?.length || 0;
        const callGraphInfo = results.interprocedural?.call_graph;
        const functionsAnalyzed = callGraphInfo?.nodes?.length || 0;

        if (totalFindings > 0) {
            const interproceduralCount = results.deepFindings?.filter((f: any) => f.call_chain?.length > 0).length || 0;

            const action = await vscode.window.showWarningMessage(
                `🔗 Deep scan found ${totalFindings} issue(s) (${interproceduralCount} cross-function flows) in ${fileName}`,
                'View Taint Flows',
                'View Details'
            );

            if (action === 'View Taint Flows' && enhancedFindings.length > 0) {
                TaintFlowPanel.show(enhancedFindings, context.extensionUri);
            } else if (action === 'View Details') {
                vscode.commands.executeCommand('workbench.view.extension.appsec-sidebar');
            }
        } else {
            vscode.window.showInformationMessage(
                `✅ Deep scan complete: No cross-function vulnerabilities found. Analyzed ${functionsAnalyzed} functions.`
            );
        }

    } catch (error: any) {
        updateStatusBar('error');
        vscode.window.showErrorMessage('Deep scan failed: ' + error.message);
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

async function applyFixCommand(findingOrItem: any) {
    if (!findingOrItem) {
        vscode.window.showWarningMessage('No finding selected');
        return;
    }

    // Handle both direct finding objects and FindingItem tree items
    // When triggered from tree view context menu, VS Code passes the FindingItem object
    // which has the actual finding in .finding property
    const finding = findingOrItem.finding || findingOrItem;

    try {
        // Get file path and line from all possible field name formats:
        // - API direct scan: file, line
        // - API stored findings: file_path, line_number
        // - Enhanced scan: location.file, location.startLine
        const filePath = finding.file || finding.file_path || finding.location?.file;
        const lineNumber = finding.line || finding.line_number || finding.location?.startLine;

        if (!filePath) {
            vscode.window.showWarningMessage('Could not determine file path for this finding. File path: ' + JSON.stringify({file: finding.file, file_path: finding.file_path, location: finding.location}));
            return;
        }

        // If no fix available, try to get AI-generated fix from API
        if (!finding.fix || !finding.fix.code) {
            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Generating AI fix...',
                cancellable: false
            }, async () => {
                try {
                    // Check if user is authenticated
                    if (!await apiClient.isAuthenticated()) {
                        vscode.window.showWarningMessage('Please login to use AI-powered fixes. Using local fix suggestions instead.');
                        return;
                    }

                    // Determine if this is a database-stored finding (numeric ID) or local scan finding
                    const findingIdStr = String(finding.id || '');
                    const isDbFinding = finding.id &&
                        !isNaN(Number(finding.id)) &&
                        !findingIdStr.startsWith('pattern_') &&
                        !findingIdStr.startsWith('taint_');

                    if (isDbFinding) {
                        // For database-stored findings, use the original endpoint
                        const aiFixResult = await apiClient.getAIFix(finding.id);
                        if (aiFixResult && (aiFixResult.remediation_code || aiFixResult.fixed_code)) {
                            finding.fix = {
                                code: (aiFixResult.remediation_code || aiFixResult.fixed_code) + '\n',
                                description: aiFixResult.explanation || 'AI-generated security fix'
                            };
                        }
                    } else {
                        // For local/enhanced scan findings, use the AI fix generation endpoint
                        // Build location object from various possible formats
                        const locationObj = finding.location || {
                            file: filePath,
                            startLine: lineNumber || 1
                        };

                        // Get code snippet - try various sources
                        const codeSnippet = finding.codeSnippet || finding.code_snippet || finding.vulnerable_code || '';

                        const aiFixResult = await apiClient.generateAIFix({
                            type: finding.type || finding.vulnerability_type || finding.category || 'Security Issue',
                            title: finding.title || finding.name || 'Security Vulnerability',
                            severity: finding.severity || 'medium',
                            codeSnippet: codeSnippet,
                            location: locationObj,
                            description: finding.description,
                            cweId: finding.cweId || finding.cwe_id,
                            recommendation: finding.recommendation || finding.remediation
                        });

                        if (aiFixResult && aiFixResult.success && aiFixResult.remediation_code) {
                            finding.fix = {
                                code: aiFixResult.remediation_code + '\n',
                                description: aiFixResult.explanation || 'AI-generated security fix'
                            };
                        }
                    }
                } catch (e: any) {
                    console.warn('Failed to get AI fix from API:', e);
                    // Fall back to local fix if available
                    if (finding.recommendation) {
                        vscode.window.showWarningMessage(`AI fix failed: ${e.message}. Using local recommendation.`);
                    }
                }
            });
        }

        if (!finding.fix || !finding.fix.code) {
            vscode.window.showWarningMessage('No fix available for this finding. Try using "Discuss with AI" for remediation guidance.');
            return;
        }

        // Open the file and navigate to the vulnerable line
        const document = await vscode.workspace.openTextDocument(filePath);
        const editor = await vscode.window.showTextDocument(document, vscode.ViewColumn.One);

        const line = Math.max(0, (lineNumber || 1) - 1);
        const lineText = document.lineAt(line);

        // Highlight the vulnerable line
        const range = new vscode.Range(line, 0, line, lineText.text.length);
        editor.selection = new vscode.Selection(range.start, range.end);
        editor.revealRange(range, vscode.TextEditorRevealType.InCenter);

        // Show fix preview with options
        const fixDescription = finding.fix.description || finding.recommendation || 'Apply security fix';
        const action = await vscode.window.showInformationMessage(
            `Fix for ${finding.title || finding.type}:\n\n${fixDescription}`,
            { modal: false },
            'Insert Fix Below',
            'Replace Line',
            'Copy to Clipboard'
        );

        if (action === 'Insert Fix Below') {
            const edit = new vscode.WorkspaceEdit();
            const insertPosition = new vscode.Position(line + 1, 0);
            edit.insert(document.uri, insertPosition, '\n// SECURITY FIX:\n' + finding.fix.code + '\n');
            await vscode.workspace.applyEdit(edit);
            vscode.window.showInformationMessage('Fix inserted below the vulnerable line');
        } else if (action === 'Replace Line') {
            const edit = new vscode.WorkspaceEdit();
            const fullLineRange = new vscode.Range(line, 0, line + 1, 0);
            edit.replace(document.uri, fullLineRange, finding.fix.code + '\n');
            await vscode.workspace.applyEdit(edit);
            vscode.window.showInformationMessage('Line replaced with fix');
        } else if (action === 'Copy to Clipboard') {
            await vscode.env.clipboard.writeText(finding.fix.code);
            vscode.window.showInformationMessage('Fix code copied to clipboard');
        }
    } catch (error: any) {
        vscode.window.showErrorMessage('Failed to apply fix: ' + error.message);
    }
}

/**
 * Generate taint flow visualization for any finding (API or local)
 * This creates a simulated taint flow based on the vulnerability type
 */
function generateTaintFlowForFinding(finding: any): any {
    // Get file path and line from all possible field name formats
    const filePath = finding.file || finding.file_path || finding.location?.file || 'unknown';
    const lineNumber = finding.line || finding.line_number || finding.location?.startLine || 1;
    const codeSnippet = finding.code_snippet || finding.codeSnippet || '';
    const title = finding.title || finding.type || 'Security Issue';
    const category = finding.category || finding.owasp_category || 'Security';

    // Determine vulnerability type from category/title
    const vulnType = determineVulnType(title, category);

    // Create source location
    const sourceLocation = {
        file: filePath,
        startLine: lineNumber,
        startColumn: 0,
        endLine: lineNumber,
        endColumn: 80
    };

    // Generate taint flow based on vulnerability type
    const taintFlow = {
        source: {
            id: `source_${finding.id || 'api'}`,
            name: getTaintSourceName(vulnType),
            category: getTaintSourceCategory(vulnType),
            pattern: { type: 'function-call' as const },
            description: `User-controlled input enters the application`
        },
        sink: {
            id: `sink_${finding.id || 'api'}`,
            name: getTaintSinkName(vulnType),
            category: getTaintSinkCategory(vulnType),
            pattern: { type: 'function-call' as const },
            vulnerabilityType: vulnType,
            description: `Tainted data reaches dangerous operation`
        },
        taintedValue: {
            variable: 'userInput',
            source: null as any,
            location: sourceLocation,
            path: [] as any[]
        },
        path: [
            {
                location: { ...sourceLocation, startLine: Math.max(1, lineNumber - 2) },
                description: `📥 SOURCE: ${getTaintSourceName(vulnType)}`,
                node: { type: 'CallExpression' as const, location: sourceLocation }
            },
            {
                location: sourceLocation,
                description: `🔄 PROPAGATION: Data flows through application`,
                node: { type: 'Assignment' as const, location: sourceLocation }
            },
            {
                location: { ...sourceLocation, startLine: lineNumber },
                description: `⚠️ SINK: ${getTaintSinkName(vulnType)} - ${title}`,
                node: { type: 'CallExpression' as const, location: sourceLocation }
            }
        ],
        sanitizers: [] as any[]
    };

    // Set the source reference
    taintFlow.taintedValue.source = taintFlow.source;

    // Return enhanced finding with taint flow
    return {
        ...finding,
        id: finding.id || `api_${Date.now()}`,
        type: vulnType,
        severity: finding.severity || 'medium',
        title: title,
        description: finding.description || 'Security vulnerability detected',
        location: sourceLocation,
        codeSnippet: codeSnippet,
        recommendation: finding.remediation || finding.recommendation || 'Review and fix the security issue',
        confidence: 'medium' as const,
        taintFlow: taintFlow
    };
}

function determineVulnType(title: string, category: string): string {
    const text = (title + ' ' + category).toLowerCase();
    if (text.includes('sql') || text.includes('injection')) return 'sql-injection';
    if (text.includes('xss') || text.includes('cross-site') || text.includes('script')) return 'xss';
    if (text.includes('command') || text.includes('exec') || text.includes('shell')) return 'command-injection';
    if (text.includes('path') || text.includes('traversal') || text.includes('directory')) return 'path-traversal';
    if (text.includes('xxe') || text.includes('xml')) return 'xxe';
    if (text.includes('ssrf') || text.includes('request forgery')) return 'ssrf';
    if (text.includes('deseriali')) return 'deserialization';
    if (text.includes('redirect') || text.includes('open redirect')) return 'open-redirect';
    if (text.includes('secret') || text.includes('credential') || text.includes('password') || text.includes('key')) return 'hardcoded-secret';
    if (text.includes('crypto') || text.includes('encrypt')) return 'weak-crypto';
    if (text.includes('random')) return 'insecure-random';
    if (text.includes('auth')) return 'missing-auth';
    if (text.includes('access')) return 'broken-access-control';
    return 'code-injection';
}

function getTaintSourceName(vulnType: string): string {
    const sources: Record<string, string> = {
        'sql-injection': 'request.query / request.body',
        'xss': 'request.params / user input',
        'command-injection': 'process.argv / request.body',
        'path-traversal': 'request.query.file / user path',
        'xxe': 'request.body (XML)',
        'ssrf': 'request.query.url',
        'deserialization': 'request.body (serialized)',
        'open-redirect': 'request.query.redirect',
        'hardcoded-secret': 'source code literal',
        'weak-crypto': 'crypto configuration',
        'insecure-random': 'Math.random()',
        'missing-auth': 'unauthenticated request',
        'broken-access-control': 'user role/permission',
        'code-injection': 'eval() / Function()'
    };
    return sources[vulnType] || 'user input';
}

function getTaintSourceCategory(vulnType: string): string {
    if (['hardcoded-secret', 'weak-crypto', 'insecure-random'].includes(vulnType)) {
        return 'environment';
    }
    return 'user-input';
}

function getTaintSinkName(vulnType: string): string {
    const sinks: Record<string, string> = {
        'sql-injection': 'db.query() / db.execute()',
        'xss': 'innerHTML / document.write()',
        'command-injection': 'exec() / spawn() / system()',
        'path-traversal': 'fs.readFile() / open()',
        'xxe': 'XMLParser.parse()',
        'ssrf': 'fetch() / http.request()',
        'deserialization': 'JSON.parse() / pickle.loads()',
        'open-redirect': 'response.redirect()',
        'hardcoded-secret': 'credential usage',
        'weak-crypto': 'crypto operation',
        'insecure-random': 'security-sensitive operation',
        'missing-auth': 'protected resource',
        'broken-access-control': 'privileged operation',
        'code-injection': 'eval() / new Function()'
    };
    return sinks[vulnType] || 'dangerous function';
}

function getTaintSinkCategory(vulnType: string): string {
    const categories: Record<string, string> = {
        'sql-injection': 'sql-query',
        'xss': 'html-output',
        'command-injection': 'command-execution',
        'path-traversal': 'file-operation',
        'xxe': 'xml-parse',
        'ssrf': 'url-redirect',
        'deserialization': 'deserialization',
        'open-redirect': 'url-redirect',
        'code-injection': 'code-execution'
    };
    return categories[vulnType] || 'code-execution';
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

// Debounce timer for inline analysis
let analyzeDebounceTimer: NodeJS.Timeout | undefined;

function analyzeDocumentInline(document: vscode.TextDocument) {
    // Clear previous timer
    if (analyzeDebounceTimer) {
        clearTimeout(analyzeDebounceTimer);
    }

    // Debounce analysis to avoid too many calls while typing
    analyzeDebounceTimer = setTimeout(() => {
        performInlineAnalysis(document);
    }, 300); // 300ms debounce
}

function performInlineAnalysis(document: vscode.TextDocument) {
    // Analyze ALL text files - no restrictions!
    // Only skip binary files and very large files for performance

    // Skip if file is too large (> 1MB)
    if (document.getText().length > 1000000) {
        return;
    }

    // Only skip obvious binary/media files
    const skipExtensions = [
        '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.bmp', '.svg',
        '.mp3', '.mp4', '.avi', '.mov', '.wav', '.flac', '.ogg',
        '.zip', '.tar', '.gz', '.rar', '.7z', '.jar', '.war',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.exe', '.dll', '.so', '.dylib', '.bin', '.class',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.min.js', '.min.css', // Skip minified files
        '.map' // Skip source maps
    ];

    const fileName = document.fileName.toLowerCase();
    if (skipExtensions.some(ext => fileName.endsWith(ext))) {
        return;
    }

    try {
        const diagnostics = inlineSecurityProvider.analyzeDocument(document);
        inlineDiagnostics.set(document.uri, diagnostics);

        if (diagnostics.length > 0) {
            console.log(`[SecureDev AI] Found ${diagnostics.length} security issues in ${document.fileName}`);
        }
    } catch (error) {
        console.error('[SecureDev AI] Error analyzing document:', error);
    }
}

/**
 * Run enhanced AST-based security scan with taint analysis
 */
async function runEnhancedScan(context: vscode.ExtensionContext) {
    const supportedExtensions = ['.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.cs', '.php', '.go', '.rb', '.kt', '.swift', '.m'];
    const editor = vscode.window.activeTextEditor;

    // If no active editor, scan workspace
    if (!editor) {
        await runEnhancedWorkspaceScan(context, supportedExtensions);
        return;
    }

    const document = editor.document;
    const filePath = document.uri.fsPath;
    const source = document.getText();

    // Check if file type is supported
    const ext = filePath.substring(filePath.lastIndexOf('.'));
    if (!supportedExtensions.includes(ext)) {
        vscode.window.showWarningMessage(`Enhanced scan not supported for ${ext} files yet`);
        return;
    }

    try {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Running Enhanced Security Scan...',
            cancellable: false
        }, async (progress) => {
            progress.report({ message: 'Parsing source code...', increment: 20 });

            const scanner = createSecurityScanner({
                enableTaintAnalysis: true,
                enableCFGAnalysis: true,
                enableDFGAnalysis: true,
                enablePatternMatching: true
            });

            progress.report({ message: 'Building control flow graph...', increment: 20 });
            progress.report({ message: 'Running taint analysis...', increment: 20 });

            const result = await scanner.scanFile(source, filePath);

            console.log('[EnhancedScan] Scan result:', result);
            console.log('[EnhancedScan] Findings count:', result?.findings?.length || 0);

            progress.report({ message: 'Processing findings...', increment: 20 });

            if (result && result.findings.length > 0) {
                // Store findings for taint flow visualization
                enhancedFindings = result.findings;

                // Update enhanced security provider diagnostics (non-blocking)
                try {
                    enhancedSecurityProvider.analyzeDocument(document);
                } catch (e) {
                    console.warn('[EnhancedScan] Failed to update diagnostics:', e);
                }

                progress.report({ message: 'Complete!', increment: 20 });

                // Show results summary
                const taintFindings = result.findings.filter(f => f.taintFlow);
                const message = `Found ${result.findings.length} security issue(s)` +
                    (taintFindings.length > 0 ? ` (${taintFindings.length} with taint flow)` : '');

                const action = await vscode.window.showWarningMessage(
                    message,
                    'View Taint Flows',
                    'View Details'
                );

                if (action === 'View Taint Flows' && taintFindings.length > 0) {
                    TaintFlowPanel.show(taintFindings, context.extensionUri);
                } else if (action === 'View Details') {
                    vscode.commands.executeCommand('workbench.view.extension.appsec-sidebar');
                }
            } else {
                progress.report({ message: 'Complete!', increment: 20 });
                if (result === null) {
                    vscode.window.showWarningMessage('Enhanced scan could not parse this file. Check the Output panel for details.');
                } else {
                    vscode.window.showInformationMessage(`No security issues found in enhanced scan. Scanned ${result.metrics?.linesOfCode || 0} lines.`);
                }
            }
        });
    } catch (error: any) {
        console.error('Enhanced scan error:', error);
        vscode.window.showErrorMessage('Enhanced scan failed: ' + error.message + '. Check Developer Tools console for details.');
    }
}

/**
 * Run enhanced scan on all supported files in workspace
 */
async function runEnhancedWorkspaceScan(context: vscode.ExtensionContext, supportedExtensions: string[]) {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        vscode.window.showErrorMessage('No workspace folder open');
        return;
    }

    try {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Running Enhanced Workspace Scan...',
            cancellable: true
        }, async (progress, token) => {
            const scanner = createSecurityScanner({
                enableTaintAnalysis: true,
                enableCFGAnalysis: true,
                enableDFGAnalysis: true,
                enablePatternMatching: true
            });

            // Find all supported files
            const globPattern = `**/*{${supportedExtensions.join(',')}}`;
            const excludePattern = '**/node_modules/**';

            progress.report({ message: 'Finding files...', increment: 10 });

            const files = await vscode.workspace.findFiles(globPattern, excludePattern, 500);

            if (files.length === 0) {
                vscode.window.showInformationMessage('No supported files found in workspace');
                return;
            }

            const allFindings: SecurityFinding[] = [];
            let scannedFiles = 0;
            let totalLines = 0;

            for (const file of files) {
                if (token.isCancellationRequested) {
                    vscode.window.showInformationMessage('Scan cancelled');
                    return;
                }

                try {
                    const document = await vscode.workspace.openTextDocument(file);
                    const source = document.getText();
                    const filePath = file.fsPath;

                    const percentComplete = Math.round((scannedFiles / files.length) * 80) + 10;
                    progress.report({
                        message: `Scanning ${scannedFiles + 1}/${files.length}: ${file.fsPath.split('/').pop()}`,
                        increment: 80 / files.length
                    });

                    const result = await scanner.scanFile(source, filePath);

                    if (result) {
                        allFindings.push(...result.findings);
                        totalLines += result.metrics?.linesOfCode || 0;
                    }

                    scannedFiles++;
                } catch (e) {
                    console.warn(`[EnhancedScan] Failed to scan ${file.fsPath}:`, e);
                }
            }

            progress.report({ message: 'Processing results...', increment: 10 });

            // Store findings for taint flow visualization
            enhancedFindings = allFindings;

            if (allFindings.length > 0) {
                const taintFindings = allFindings.filter(f => f.taintFlow);
                const message = `Workspace scan complete: Found ${allFindings.length} security issue(s) in ${scannedFiles} files` +
                    (taintFindings.length > 0 ? ` (${taintFindings.length} with taint flow)` : '');

                const action = await vscode.window.showWarningMessage(
                    message,
                    'View Taint Flows',
                    'View Details'
                );

                if (action === 'View Taint Flows' && taintFindings.length > 0) {
                    TaintFlowPanel.show(taintFindings, context.extensionUri);
                } else if (action === 'View Details') {
                    vscode.commands.executeCommand('workbench.view.extension.appsec-sidebar');
                }
            } else {
                vscode.window.showInformationMessage(
                    `Workspace scan complete: No security issues found. Scanned ${scannedFiles} files (${totalLines} lines).`
                );
            }
        });
    } catch (error: any) {
        console.error('Enhanced workspace scan error:', error);
        vscode.window.showErrorMessage('Enhanced workspace scan failed: ' + error.message);
    }
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
