import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import axios, { AxiosInstance } from 'axios';

export class ApiClient {
    private context: vscode.ExtensionContext;
    private axiosInstance: AxiosInstance;
    private tokenKey = 'appsec.authToken';

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
        const config = vscode.workspace.getConfiguration('appsec');
        const apiUrl = config.get<string>('apiUrl', 'http://localhost:8000');

        this.axiosInstance = axios.create({
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

    async login(username: string, password: string): Promise<void> {
        try {
            const config = vscode.workspace.getConfiguration('appsec');
            const apiUrl = config.get<string>('apiUrl', 'http://localhost:8000');
            console.log(`[SecureDev AI] Attempting login to: ${apiUrl}/api/auth/login`);

            const response = await this.axiosInstance.post('/api/auth/login', {
                username,
                password
            });

            const token = response.data.access_token;
            await this.context.secrets.store(this.tokenKey, token);
            console.log('[SecureDev AI] Login successful');
        } catch (error: any) {
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

    async logout(): Promise<void> {
        await this.context.secrets.delete(this.tokenKey);
    }

    async isAuthenticated(): Promise<boolean> {
        const token = await this.getToken();
        if (!token) {
            return false;
        }
        // Validate token by calling /api/auth/me
        try {
            await this.axiosInstance.get('/api/auth/me');
            return true;
        } catch (error: any) {
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

    private async getToken(): Promise<string | undefined> {
        return await this.context.secrets.get(this.tokenKey);
    }

    /**
     * Clear stored authentication token
     */
    async clearToken(): Promise<void> {
        await this.context.secrets.delete(this.tokenKey);
    }

    async scanWorkspace(workspacePath: string): Promise<any> {
        try {
            const response = await this.axiosInstance.post('/api/scan', {
                path: workspacePath,
                scan_types: ['sast', 'sca', 'secrets']
            });

            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Scan failed');
        }
    }

    async scanFile(filePath: string): Promise<any> {
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
        } catch (error: any) {
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
                } catch (fallbackError: any) {
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
    async deepScanFile(filePath: string): Promise<any> {
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
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Deep scan failed');
        }
    }

    /**
     * Inter-procedural analysis only
     * Returns call graph, function summaries, and cross-function taint flows
     */
    async interproceduralScan(filePath: string): Promise<any> {
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
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Inter-procedural scan failed');
        }
    }

    async getFindings(scanId?: string): Promise<any> {
        try {
            if (scanId) {
                // Get vulnerabilities for a specific scan
                const response = await this.axiosInstance.get(`/api/scans/${scanId}/vulnerabilities`);
                return response.data;
            } else {
                // Get all scans and their vulnerabilities
                const scansResponse = await this.axiosInstance.get('/api/scans/');
                const scans = scansResponse.data;

                // Collect all vulnerabilities from all scans
                const allVulnerabilities: any[] = [];
                for (const scan of scans.slice(0, 5)) { // Limit to recent 5 scans
                    try {
                        const vulnResponse = await this.axiosInstance.get(`/api/scans/${scan.id}/vulnerabilities`);
                        allVulnerabilities.push(...(vulnResponse.data || []));
                    } catch {
                        // Skip if scan has no vulnerabilities
                    }
                }
                return allVulnerabilities;
            }
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to fetch findings');
        }
    }

    async updateFindingStatus(findingId: string, status: string): Promise<void> {
        try {
            await this.axiosInstance.patch(`/api/vulnerabilities/${findingId}/status`, {
                status
            });
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to update finding status');
        }
    }

    async getAIFix(findingId: string): Promise<any> {
        try {
            const response = await this.axiosInstance.post(`/api/vulnerabilities/${findingId}/auto-remediate`);
            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to get AI fix');
        }
    }

    /**
     * Generate AI fix for any vulnerability (including local enhanced scan findings)
     */
    async generateAIFix(finding: {
        type: string;
        title: string;
        severity: string;
        codeSnippet: string;
        location: { file: string; startLine: number };
        description?: string;
        cweId?: string;
        recommendation?: string;
    }): Promise<any> {
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
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to generate AI fix');
        }
    }

    async sendChatMessage(message: string, contextType?: string, contextId?: number): Promise<any> {
        try {
            const response = await this.axiosInstance.post('/api/chat', {
                message,
                context_type: contextType,
                context_id: contextId
            });
            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Chat request failed');
        }
    }

    // Custom Rules API Methods

    async getCustomRules(severity?: string, language?: string, enabledOnly?: boolean): Promise<any> {
        try {
            const params: any = {};
            if (severity) {params.severity = severity;}
            if (language) {params.language = language;}
            if (enabledOnly) {params.enabled_only = enabledOnly;}

            const response = await this.axiosInstance.get('/api/rules', { params });
            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to fetch custom rules');
        }
    }

    async getCustomRule(ruleId: number): Promise<any> {
        try {
            const response = await this.axiosInstance.get(`/api/rules/${ruleId}`);
            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to fetch rule');
        }
    }

    async createCustomRule(rule: any): Promise<any> {
        try {
            const response = await this.axiosInstance.post('/api/rules/', rule);
            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to create rule');
        }
    }

    async updateCustomRule(ruleId: number, updates: any): Promise<any> {
        try {
            const response = await this.axiosInstance.put(`/api/rules/${ruleId}`, updates);
            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to update rule');
        }
    }

    async deleteCustomRule(ruleId: number): Promise<void> {
        try {
            await this.axiosInstance.delete(`/api/rules/${ruleId}`);
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to delete rule');
        }
    }

    async generateRuleWithAI(request: any): Promise<any> {
        try {
            const response = await this.axiosInstance.post('/api/rules/generate', request);
            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to generate rule');
        }
    }

    async getEnhancementJobStatus(jobId: number): Promise<any> {
        try {
            const response = await this.axiosInstance.get(`/api/rules/jobs/${jobId}`);
            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to fetch job status');
        }
    }

    async getRulePerformanceStats(): Promise<any> {
        try {
            const response = await this.axiosInstance.get('/api/rules/performance/dashboard');
            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to fetch performance stats');
        }
    }

    async submitRuleFeedback(ruleId: number, findingId: number, feedback: string, comment?: string): Promise<any> {
        try {
            const response = await this.axiosInstance.post('/api/rules/performance/feedback', {
                rule_id: ruleId,
                finding_id: findingId,
                user_feedback: feedback,
                feedback_comment: comment
            });
            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to submit feedback');
        }
    }
}
