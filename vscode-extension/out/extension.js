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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const apiClient_1 = require("./apiClient");
const findingsProvider_1 = require("./findingsProvider");
const scaFindingsProvider_1 = require("./scaFindingsProvider");
const secretsFindingsProvider_1 = require("./secretsFindingsProvider");
const diagnosticsManager_1 = require("./diagnosticsManager");
const vulnerabilityDetailsPanel_1 = require("./vulnerabilityDetailsPanel");
const chatbotPanel_1 = require("./chatbotPanel");
const scanProgressManager_1 = require("./scanProgressManager");
const inlineSecurityProvider_1 = require("./inlineSecurityProvider");
const customRulesProvider_1 = require("./customRulesProvider");
const RulePerformancePanel_1 = require("./RulePerformancePanel");
let apiClient;
let findingsProvider;
let scaFindingsProvider;
let secretsFindingsProvider;
let customRulesProvider;
let diagnosticsManager;
let statusBarItem;
let scanProgressManager;
let inlineSecurityProvider;
let inlineDiagnostics;
async function activate(context) {
    console.log('AppSec AI Scanner extension activated');
    apiClient = new apiClient_1.ApiClient(context);
    diagnosticsManager = new diagnosticsManager_1.DiagnosticsManager();
    findingsProvider = new findingsProvider_1.FindingsProvider(apiClient);
    scaFindingsProvider = new scaFindingsProvider_1.ScaFindingsProvider(apiClient);
    secretsFindingsProvider = new secretsFindingsProvider_1.SecretsFindingsProvider(apiClient);
    customRulesProvider = new customRulesProvider_1.CustomRulesProvider(apiClient);
    scanProgressManager = new scanProgressManager_1.ScanProgressManager();
    inlineSecurityProvider = new inlineSecurityProvider_1.InlineSecurityProvider();
    inlineDiagnostics = vscode.languages.createDiagnosticCollection('appsec-inline');
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.text = "$(shield) AppSec";
    statusBarItem.tooltip = "AppSec AI Scanner";
    statusBarItem.command = 'appsec.scanWorkspace';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);
    vscode.window.registerTreeDataProvider('appsecFindings', findingsProvider);
    vscode.window.registerTreeDataProvider('appsecScaFindings', scaFindingsProvider);
    vscode.window.registerTreeDataProvider('appsecSecretsFindings', secretsFindingsProvider);
    vscode.window.registerTreeDataProvider('appsecCustomRules', customRulesProvider);
    context.subscriptions.push(vscode.commands.registerCommand('appsec.login', async () => {
        await loginCommand(context);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.logout', async () => {
        await apiClient.logout();
        vscode.window.showInformationMessage('Logged out from AppSec platform');
        findingsProvider.refresh();
        updateStatusBar('disconnected');
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.scanWorkspace', async () => {
        await scanWorkspaceCommand();
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.scanCurrentFile', async () => {
        await scanCurrentFileCommand();
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.refreshFindings', async () => {
        await refreshFindingsCommand();
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.clearFindings', () => {
        diagnosticsManager.clear();
        vscode.window.showInformationMessage('Security findings cleared');
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.viewOnDashboard', async () => {
        const config = vscode.workspace.getConfiguration('appsec');
        const apiUrl = config.get('apiUrl', 'http://localhost:8000');
        const webUrl = apiUrl.replace(':8000', ':5173');
        vscode.env.openExternal(vscode.Uri.parse(webUrl));
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.applyFix', async (finding) => {
        await applyFixCommand(finding);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.markResolved', async (finding) => {
        await markStatusCommand(finding, 'resolved');
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.markFalsePositive', async (finding) => {
        await markStatusCommand(finding, 'false_positive');
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.showDetails', (finding) => {
        vulnerabilityDetailsPanel_1.VulnerabilityDetailsPanel.show(finding, apiClient);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.showScaDetails', (finding) => {
        vulnerabilityDetailsPanel_1.VulnerabilityDetailsPanel.show(finding, apiClient);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.showSecretDetails', (finding) => {
        vulnerabilityDetailsPanel_1.VulnerabilityDetailsPanel.show(finding, apiClient);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.openChatbot', () => {
        chatbotPanel_1.ChatbotPanel.show(apiClient);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.discussWithAI', (finding) => {
        chatbotPanel_1.ChatbotPanel.show(apiClient, finding);
    }));
    // Custom Rules Commands
    context.subscriptions.push(vscode.commands.registerCommand('appsec.viewOnWeb', () => {
        const config = vscode.workspace.getConfiguration('appsec');
        const apiUrl = config.get('apiUrl', 'http://localhost:8000');
        const webUrl = apiUrl.replace(':8000', ':5174');
        vscode.env.openExternal(vscode.Uri.parse(webUrl));
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.manageCustomRules', () => {
        const config = vscode.workspace.getConfiguration('appsec');
        const apiUrl = config.get('apiUrl', 'http://localhost:8000');
        const webUrl = apiUrl.replace(':8000', ':5174') + '/custom-rules';
        vscode.env.openExternal(vscode.Uri.parse(webUrl));
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.viewRulePerformance', async () => {
        try {
            console.log('Opening Rule Performance Dashboard...');
            RulePerformancePanel_1.RulePerformancePanel.show(apiClient);
        }
        catch (error) {
            console.error('Error opening Rule Performance Dashboard:', error);
            vscode.window.showErrorMessage('Failed to open Rule Performance Dashboard: ' + error.message);
        }
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.refreshCustomRules', () => {
        customRulesProvider.refresh();
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.createCustomRule', async () => {
        await createCustomRuleCommand();
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.editCustomRule', async (ruleItem) => {
        await editCustomRuleCommand(ruleItem);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.deleteCustomRule', async (ruleItem) => {
        await deleteCustomRuleCommand(ruleItem);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.toggleCustomRule', async (ruleItem) => {
        await toggleCustomRuleCommand(ruleItem);
    }));
    context.subscriptions.push(vscode.commands.registerCommand('appsec.generateRuleWithAI', async () => {
        await generateRuleWithAICommand();
    }));
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('appsec');
        const autoScan = config.get('autoScan', false);
        if (autoScan && await apiClient.isAuthenticated()) {
            await scanFile(document.uri);
        }
    }));
    // Inline security analysis as you type
    context.subscriptions.push(vscode.workspace.onDidChangeTextDocument(e => {
        if (e.document.uri.scheme === 'file') {
            analyzeDocumentInline(e.document);
        }
    }));
    context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(document => {
        if (document.uri.scheme === 'file') {
            analyzeDocumentInline(document);
        }
    }));
    // Register code action provider for inline suggestions
    context.subscriptions.push(vscode.languages.registerCodeActionsProvider({ scheme: 'file' }, inlineSecurityProvider, {
        providedCodeActionKinds: inlineSecurityProvider_1.InlineSecurityProvider.providedCodeActionKinds
    }));
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
async function loginCommand(context) {
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
    }
    catch (error) {
        vscode.window.showErrorMessage('Login failed: ' + error.message);
    }
}
async function scanWorkspaceCommand() {
    if (!await apiClient.isAuthenticated()) {
        const login = await vscode.window.showWarningMessage('Please login to AppSec platform first', 'Login');
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
        const results = await scanProgressManager.showScanProgress('AppSec Security Scan', async (updateProgress) => {
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
            const sastFindings = [];
            const scaFindings = [];
            const secretsFindings = [];
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
        });
        updateStatusBar('connected');
        const duration = (Date.now() - startTime) / 1000;
        const totalFindings = (results.sast?.findings?.length || 0) +
            (results.sca?.findings?.length || 0) +
            (results.secrets?.findings?.length || 0);
        scanProgressManager.showScanComplete(totalFindings, duration);
    }
    catch (error) {
        updateStatusBar('error');
        scanProgressManager.showScanError(error.message);
        setTimeout(() => updateStatusBar('connected'), 3000);
    }
}
async function scanCurrentFileCommand() {
    if (!await apiClient.isAuthenticated()) {
        const login = await vscode.window.showWarningMessage('Please login to AppSec platform first', 'Login');
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
async function scanFile(fileUri) {
    const startTime = Date.now();
    const fileName = fileUri.fsPath.split('/').pop();
    try {
        updateStatusBar('scanning');
        const results = await scanProgressManager.showScanProgress(`Scanning ${fileName}`, async (updateProgress) => {
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
            const fileSastFindings = [];
            const fileSecretsFindings = [];
            if (scanResults.sast?.findings) {
                fileSastFindings.push(...scanResults.sast.findings);
            }
            if (scanResults.secrets?.findings) {
                fileSecretsFindings.push(...scanResults.secrets.findings);
            }
            // Merge with existing findings for each type
            const existingSastFindings = findingsProvider.getAllFindings();
            const otherSastFindings = existingSastFindings.filter((f) => f.file !== fileUri.fsPath);
            const allSastFindings = [...otherSastFindings, ...fileSastFindings];
            const existingSecretsFindings = secretsFindingsProvider.getAllFindings();
            const otherSecretsFindings = existingSecretsFindings.filter((f) => f.file !== fileUri.fsPath);
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
        });
        updateStatusBar('connected');
        const duration = (Date.now() - startTime) / 1000;
        const findings = results.sast?.findings || [];
        if (findings.length > 0) {
            vscode.window.showWarningMessage(`⚠️ Found ${findings.length} issue${findings.length !== 1 ? 's' : ''} in ${fileName}`, 'View Results').then(selection => {
                if (selection === 'View Results') {
                    vscode.commands.executeCommand('workbench.view.extension.appsec-sidebar');
                }
            });
        }
        else {
            vscode.window.showInformationMessage(`✅ No issues found in ${fileName}`);
        }
    }
    catch (error) {
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
    }
    catch (error) {
        vscode.window.showErrorMessage('Failed to refresh: ' + error.message);
    }
}
async function applyFixCommand(finding) {
    if (!finding || !finding.fix) {
        vscode.window.showWarningMessage('No fix available for this finding');
        return;
    }
    try {
        const document = await vscode.workspace.openTextDocument(finding.file);
        const editor = await vscode.window.showTextDocument(document);
        const edit = new vscode.WorkspaceEdit();
        if (finding.fix.code) {
            const range = new vscode.Range(finding.line - 1, 0, finding.line, 0);
            edit.replace(document.uri, range, finding.fix.code);
        }
        const success = await vscode.workspace.applyEdit(edit);
        if (success) {
            vscode.window.showInformationMessage('Fix applied successfully');
            await markStatusCommand(finding, 'resolved');
        }
    }
    catch (error) {
        vscode.window.showErrorMessage('Failed to apply fix: ' + error.message);
    }
}
async function markStatusCommand(finding, status) {
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
    }
    catch (error) {
        vscode.window.showErrorMessage('Failed to update status: ' + error.message);
    }
}
function analyzeDocumentInline(document) {
    // Only analyze source code files
    const supportedLanguages = ['javascript', 'typescript', 'python', 'java', 'csharp', 'php', 'ruby', 'go'];
    if (!supportedLanguages.includes(document.languageId)) {
        return;
    }
    const diagnostics = inlineSecurityProvider.analyzeDocument(document);
    inlineDiagnostics.set(document.uri, diagnostics);
}
function updateStatusBar(status) {
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
    if (!name) {
        return;
    }
    const pattern = await vscode.window.showInputBox({
        prompt: 'Enter regex pattern',
        placeHolder: 'e.g., api[_-]?key["\']\\s*[:=]\\s*["\'][a-zA-Z0-9]{20,}'
    });
    if (!pattern) {
        return;
    }
    const severity = await vscode.window.showQuickPick(['critical', 'high', 'medium', 'low'], { placeHolder: 'Select severity level' });
    if (!severity) {
        return;
    }
    const description = await vscode.window.showInputBox({
        prompt: 'Enter description',
        placeHolder: 'Describe what this rule detects'
    });
    if (!description) {
        return;
    }
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
    }
    catch (error) {
        vscode.window.showErrorMessage('Failed to create rule: ' + error.message);
    }
}
async function editCustomRuleCommand(ruleItem) {
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
    if (!options) {
        return;
    }
    try {
        let updates = {};
        switch (options.value) {
            case 'name':
                const newName = await vscode.window.showInputBox({
                    prompt: 'Enter new name',
                    value: rule.name
                });
                if (newName) {
                    updates.name = newName;
                }
                break;
            case 'pattern':
                const newPattern = await vscode.window.showInputBox({
                    prompt: 'Enter new pattern',
                    value: rule.pattern
                });
                if (newPattern) {
                    updates.pattern = newPattern;
                }
                break;
            case 'description':
                const newDesc = await vscode.window.showInputBox({
                    prompt: 'Enter new description',
                    value: rule.description
                });
                if (newDesc) {
                    updates.description = newDesc;
                }
                break;
            case 'severity':
                const newSeverity = await vscode.window.showQuickPick(['critical', 'high', 'medium', 'low'], { placeHolder: 'Select severity level' });
                if (newSeverity) {
                    updates.severity = newSeverity;
                }
                break;
            case 'language':
                const newLang = await vscode.window.showInputBox({
                    prompt: 'Enter language',
                    value: rule.language
                });
                if (newLang) {
                    updates.language = newLang;
                }
                break;
        }
        if (Object.keys(updates).length > 0) {
            await apiClient.updateCustomRule(rule.id, updates);
            vscode.window.showInformationMessage('Rule updated successfully');
            customRulesProvider.refresh();
        }
    }
    catch (error) {
        vscode.window.showErrorMessage('Failed to update rule: ' + error.message);
    }
}
async function deleteCustomRuleCommand(ruleItem) {
    if (!ruleItem || !ruleItem.rule) {
        vscode.window.showWarningMessage('No rule selected');
        return;
    }
    const rule = ruleItem.rule;
    const confirm = await vscode.window.showWarningMessage(`Are you sure you want to delete rule "${rule.name}"?`, { modal: true }, 'Delete');
    if (confirm !== 'Delete') {
        return;
    }
    try {
        await apiClient.deleteCustomRule(rule.id);
        vscode.window.showInformationMessage(`Rule "${rule.name}" deleted successfully`);
        customRulesProvider.refresh();
    }
    catch (error) {
        vscode.window.showErrorMessage('Failed to delete rule: ' + error.message);
    }
}
async function toggleCustomRuleCommand(ruleItem) {
    if (!ruleItem || !ruleItem.rule) {
        vscode.window.showWarningMessage('No rule selected');
        return;
    }
    const rule = ruleItem.rule;
    try {
        await apiClient.updateCustomRule(rule.id, { enabled: !rule.enabled });
        vscode.window.showInformationMessage(`Rule "${rule.name}" ${!rule.enabled ? 'enabled' : 'disabled'}`);
        customRulesProvider.refresh();
    }
    catch (error) {
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
    if (!ruleName) {
        return;
    }
    const vulnDescription = await vscode.window.showInputBox({
        prompt: 'Describe the vulnerability this rule should detect',
        placeHolder: 'e.g., Detect SQL injection vulnerabilities in database queries'
    });
    if (!vulnDescription) {
        return;
    }
    const severity = await vscode.window.showQuickPick(['critical', 'high', 'medium', 'low'], { placeHolder: 'Select severity level' });
    if (!severity) {
        return;
    }
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
    }
    catch (error) {
        vscode.window.showErrorMessage('Failed to generate rule: ' + error.message);
    }
}
async function pollJobStatus(jobId, maxAttempts = 30) {
    for (let i = 0; i < maxAttempts; i++) {
        await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
        try {
            const job = await apiClient.getEnhancementJobStatus(jobId);
            if (job.status === 'completed') {
                return;
            }
            else if (job.status === 'failed') {
                throw new Error('Job failed: ' + (job.errors || 'Unknown error'));
            }
        }
        catch (error) {
            console.error('Error polling job status:', error);
        }
    }
    throw new Error('Job timed out');
}
function deactivate() {
    diagnosticsManager.dispose();
    inlineDiagnostics.dispose();
}
//# sourceMappingURL=extension.js.map