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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ApiClient = void 0;
const vscode = __importStar(require("vscode"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const axios_1 = __importDefault(require("axios"));
class ApiClient {
    constructor(context) {
        this.tokenKey = 'appsec.authToken';
        this.context = context;
        const config = vscode.workspace.getConfiguration('appsec');
        const apiUrl = config.get('apiUrl', 'http://localhost:8000');
        this.axiosInstance = axios_1.default.create({
            baseURL: apiUrl,
            timeout: 60000,
            headers: {
                'Content-Type': 'application/json'
            }
        });
        this.axiosInstance.interceptors.request.use(async (config) => {
            const token = await this.getToken();
            if (token) {
                config.headers.Authorization = `Bearer ${token}`;
            }
            return config;
        });
    }
    async login(username, password) {
        try {
            const config = vscode.workspace.getConfiguration('appsec');
            const apiUrl = config.get('apiUrl', 'http://localhost:8000');
            console.log(`[SecureDev AI] Attempting login to: ${apiUrl}/api/auth/login`);
            const response = await this.axiosInstance.post('/api/auth/login', {
                username,
                password
            });
            const token = response.data.access_token;
            await this.context.secrets.store(this.tokenKey, token);
            console.log('[SecureDev AI] Login successful');
        }
        catch (error) {
            console.error('[SecureDev AI] Login error:', error.message);
            if (error.code === 'ECONNREFUSED') {
                throw new Error('Cannot connect to server. Is the backend running?');
            }
            if (error.code === 'ERR_NETWORK' || error.message?.includes('Network Error')) {
                throw new Error('Network error. Check your API URL in settings.');
            }
            if (error.response?.status === 401) {
                throw new Error('Invalid username or password');
            }
            throw new Error(error.response?.data?.detail || error.message || 'Login failed');
        }
    }
    async logout() {
        await this.context.secrets.delete(this.tokenKey);
    }
    async isAuthenticated() {
        const token = await this.getToken();
        if (!token) {
            return false;
        }
        // Validate token by calling /api/auth/me
        try {
            await this.axiosInstance.get('/api/auth/me');
            return true;
        }
        catch (error) {
            // Token is invalid or expired
            if (error.response?.status === 401) {
                // Clear invalid token
                await this.context.secrets.delete(this.tokenKey);
                return false;
            }
            // Network error - assume authenticated if we have a token
            return true;
        }
    }
    async getToken() {
        return await this.context.secrets.get(this.tokenKey);
    }
    /**
     * Clear stored authentication token
     */
    async clearToken() {
        await this.context.secrets.delete(this.tokenKey);
    }
    async scanWorkspace(workspacePath, onProgress) {
        try {
            // For remote backends, we need to scan files individually
            // Get all scannable files in the workspace
            const files = this.getScannableFiles(workspacePath);
            if (files.length === 0) {
                return {
                    sast: { findings: [] },
                    sca: { findings: [] },
                    secrets: { findings: [] },
                    summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 }
                };
            }
            // Aggregate results from scanning each file
            const allVulnerabilities = [];
            const allScaVulnerabilities = [];
            const allSecrets = [];
            const errors = [];
            // Prioritize source files likely to have vulnerabilities
            const prioritizedFiles = files.sort((a, b) => {
                const priorityPatterns = ['source/', 'src/', 'lib/', 'app/', 'controller', 'model', 'handler'];
                const aHasPriority = priorityPatterns.some(p => a.toLowerCase().includes(p));
                const bHasPriority = priorityPatterns.some(p => b.toLowerCase().includes(p));
                if (aHasPriority && !bHasPriority)
                    return -1;
                if (!aHasPriority && bHasPriority)
                    return 1;
                return 0;
            });
            // Scan up to 50 files for better coverage
            const filesToScan = prioritizedFiles.slice(0, 50);
            let scannedCount = 0;
            console.log(`[SecureDev AI] Scanning ${filesToScan.length} files out of ${files.length} total`);
            // Scan files in parallel batches of 5
            const batchSize = 5;
            for (let i = 0; i < filesToScan.length; i += batchSize) {
                const batch = filesToScan.slice(i, i + batchSize);
                const batchPromises = batch.map(async (filePath) => {
                    try {
                        const fileContent = fs.readFileSync(filePath, 'utf-8');
                        const fileName = path.relative(workspacePath, filePath);
                        const response = await this.axiosInstance.post('/api/scan/deep', {
                            source_code: fileContent,
                            file_name: fileName,
                            include_call_graph: false,
                            include_function_summaries: false,
                            include_taint_flows: false // Skip for speed
                        }, { timeout: 15000 }); // Shorter timeout
                        return { success: true, data: response.data, fileName };
                    }
                    catch (fileError) {
                        console.log(`[SecureDev AI] Skipping ${filePath}: ${fileError.message}`);
                        return { success: false, error: fileError.message, filePath };
                    }
                });
                const batchResults = await Promise.all(batchPromises);
                for (const result of batchResults) {
                    scannedCount++;
                    if (onProgress) {
                        onProgress(scannedCount, filesToScan.length);
                    }
                    if (result.success && result.data?.findings) {
                        for (const finding of result.data.findings) {
                            finding.file_path = result.fileName;
                            finding.file = result.fileName;
                            if (finding.source === 'secret_scanning' || finding.type === 'secret') {
                                allSecrets.push(finding);
                            }
                            else {
                                allVulnerabilities.push(finding);
                            }
                        }
                    }
                    else if (!result.success) {
                        errors.push(`${result.filePath}: ${result.error}`);
                    }
                }
            }
            // Calculate summary
            const summary = {
                total: allVulnerabilities.length + allSecrets.length,
                critical: allVulnerabilities.filter(v => v.severity === 'critical').length,
                high: allVulnerabilities.filter(v => v.severity === 'high').length,
                medium: allVulnerabilities.filter(v => v.severity === 'medium').length,
                low: allVulnerabilities.filter(v => v.severity === 'low').length,
                files_scanned: filesToScan.length,
                files_total: files.length
            };
            // Return in format expected by extension.ts
            return {
                sast: { findings: allVulnerabilities },
                sca: { findings: allScaVulnerabilities },
                secrets: { findings: allSecrets },
                summary,
                errors: errors.length > 0 ? errors : undefined
            };
        }
        catch (error) {
            if (error.response?.status === 401) {
                await this.clearToken();
                throw new Error('Session expired. Please login again.');
            }
            throw new Error(error.response?.data?.detail || 'Scan failed');
        }
    }
    /**
     * Get all scannable source code files in a directory
     */
    getScannableFiles(dirPath, files = []) {
        const extensions = ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.php', '.rb', '.cs', '.c', '.cpp', '.h'];
        const ignoreDirs = ['node_modules', '.git', '__pycache__', 'venv', 'env', '.venv', 'dist', 'build', 'target', '.next'];
        try {
            const entries = fs.readdirSync(dirPath, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(dirPath, entry.name);
                if (entry.isDirectory()) {
                    if (!ignoreDirs.includes(entry.name) && !entry.name.startsWith('.')) {
                        this.getScannableFiles(fullPath, files);
                    }
                }
                else if (entry.isFile()) {
                    const ext = path.extname(entry.name).toLowerCase();
                    if (extensions.includes(ext)) {
                        files.push(fullPath);
                    }
                }
            }
        }
        catch (err) {
            // Skip directories we can't read
        }
        return files;
    }
    async scanFile(filePath) {
        try {
            // Read file content to send to remote backend
            const fileContent = fs.readFileSync(filePath, 'utf-8');
            const fileName = path.basename(filePath);
            // Try the new deep scan endpoint first (includes inter-procedural analysis)
            const response = await this.axiosInstance.post('/api/scan/deep', {
                source_code: fileContent,
                file_name: fileName,
                include_call_graph: true,
                include_function_summaries: true,
                include_taint_flows: true
            }, { timeout: 120000 }); // 2 min timeout for deep analysis
            return response.data;
        }
        catch (error) {
            // Handle authentication errors
            if (error.response?.status === 401) {
                // Clear invalid token
                await this.clearToken();
                throw new Error('Session expired. Please login again.');
            }
            // Fallback to standard scan if deep scan endpoint not found
            if (error.response?.status === 404) {
                try {
                    const fileContent = fs.readFileSync(filePath, 'utf-8');
                    const fileName = path.basename(filePath);
                    const fallbackResponse = await this.axiosInstance.post('/api/scan/file', {
                        source_code: fileContent,
                        file_name: fileName,
                        scan_types: ['sast', 'secrets']
                    });
                    return fallbackResponse.data;
                }
                catch (fallbackError) {
                    if (fallbackError.response?.status === 401) {
                        await this.clearToken();
                        throw new Error('Session expired. Please login again.');
                    }
                    throw new Error(fallbackError.response?.data?.detail || 'File scan failed');
                }
            }
            throw new Error(error.response?.data?.detail || 'File scan failed');
        }
    }
    /**
     * Deep scan with inter-procedural analysis
     * Tracks data flow across function boundaries
     */
    async deepScanFile(filePath) {
        try {
            // Read file content to send to remote backend
            const fileContent = fs.readFileSync(filePath, 'utf-8');
            const fileName = path.basename(filePath);
            const response = await this.axiosInstance.post('/api/scan/deep', {
                source_code: fileContent,
                file_name: fileName,
                include_call_graph: true,
                include_function_summaries: true,
                include_taint_flows: true
            }, { timeout: 180000 }); // 3 min timeout
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Deep scan failed');
        }
    }
    /**
     * Inter-procedural analysis only
     * Returns call graph, function summaries, and cross-function taint flows
     */
    async interproceduralScan(filePath) {
        try {
            // Read file content to send to remote backend
            const fileContent = fs.readFileSync(filePath, 'utf-8');
            const fileName = path.basename(filePath);
            const response = await this.axiosInstance.post('/api/scan/interprocedural', {
                source_code: fileContent,
                file_name: fileName,
                include_call_graph: true,
                include_function_summaries: true,
                include_taint_flows: true
            }, { timeout: 120000 });
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Inter-procedural scan failed');
        }
    }
    async getFindings(scanId) {
        try {
            if (scanId) {
                // Get vulnerabilities for a specific scan
                const response = await this.axiosInstance.get(`/api/scans/${scanId}/vulnerabilities`);
                return response.data;
            }
            else {
                // Get all scans and their vulnerabilities
                const scansResponse = await this.axiosInstance.get('/api/scans/');
                const scans = scansResponse.data;
                // Collect all vulnerabilities from all scans
                const allVulnerabilities = [];
                for (const scan of scans.slice(0, 5)) { // Limit to recent 5 scans
                    try {
                        const vulnResponse = await this.axiosInstance.get(`/api/scans/${scan.id}/vulnerabilities`);
                        allVulnerabilities.push(...(vulnResponse.data || []));
                    }
                    catch {
                        // Skip if scan has no vulnerabilities
                    }
                }
                return allVulnerabilities;
            }
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to fetch findings');
        }
    }
    async updateFindingStatus(findingId, status) {
        try {
            await this.axiosInstance.patch(`/api/vulnerabilities/${findingId}/status`, {
                status
            });
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to update finding status');
        }
    }
    async getAIFix(findingId) {
        try {
            const response = await this.axiosInstance.post(`/api/vulnerabilities/${findingId}/auto-remediate`);
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to get AI fix');
        }
    }
    /**
     * Generate AI fix for any vulnerability (including local enhanced scan findings)
     */
    async generateAIFix(finding) {
        try {
            const response = await this.axiosInstance.post('/api/ai/generate-fix', {
                vulnerability_type: finding.type,
                title: finding.title,
                severity: finding.severity,
                code_snippet: finding.codeSnippet,
                file_path: finding.location.file,
                line_number: finding.location.startLine,
                description: finding.description,
                cwe_id: finding.cweId,
                recommendation: finding.recommendation
            });
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to generate AI fix');
        }
    }
    async sendChatMessage(message, contextType, contextId) {
        try {
            const response = await this.axiosInstance.post('/api/chat', {
                message,
                context_type: contextType,
                context_id: contextId
            });
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Chat request failed');
        }
    }
    // Custom Rules API Methods
    async getCustomRules(severity, language, enabledOnly) {
        try {
            const params = {};
            if (severity) {
                params.severity = severity;
            }
            if (language) {
                params.language = language;
            }
            if (enabledOnly) {
                params.enabled_only = enabledOnly;
            }
            const response = await this.axiosInstance.get('/api/rules', { params });
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to fetch custom rules');
        }
    }
    async getCustomRule(ruleId) {
        try {
            const response = await this.axiosInstance.get(`/api/rules/${ruleId}`);
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to fetch rule');
        }
    }
    async createCustomRule(rule) {
        try {
            const response = await this.axiosInstance.post('/api/rules/', rule);
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to create rule');
        }
    }
    async updateCustomRule(ruleId, updates) {
        try {
            const response = await this.axiosInstance.put(`/api/rules/${ruleId}`, updates);
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to update rule');
        }
    }
    async deleteCustomRule(ruleId) {
        try {
            await this.axiosInstance.delete(`/api/rules/${ruleId}`);
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to delete rule');
        }
    }
    async generateRuleWithAI(request) {
        try {
            const response = await this.axiosInstance.post('/api/rules/generate', request);
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to generate rule');
        }
    }
    async getEnhancementJobStatus(jobId) {
        try {
            const response = await this.axiosInstance.get(`/api/rules/jobs/${jobId}`);
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to fetch job status');
        }
    }
    async getRulePerformanceStats() {
        try {
            const response = await this.axiosInstance.get('/api/rules/performance/dashboard');
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to fetch performance stats');
        }
    }
    async submitRuleFeedback(ruleId, findingId, feedback, comment) {
        try {
            const response = await this.axiosInstance.post('/api/rules/performance/feedback', {
                rule_id: ruleId,
                finding_id: findingId,
                user_feedback: feedback,
                feedback_comment: comment
            });
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to submit feedback');
        }
    }
}
exports.ApiClient = ApiClient;
//# sourceMappingURL=apiClient.js.map