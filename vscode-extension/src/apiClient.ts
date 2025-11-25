import * as vscode from 'vscode';
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
            const response = await this.axiosInstance.post('/api/auth/login', {
                username,
                password
            });

            const token = response.data.access_token;
            await this.context.secrets.store(this.tokenKey, token);
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Login failed');
        }
    }

    async logout(): Promise<void> {
        await this.context.secrets.delete(this.tokenKey);
    }

    async isAuthenticated(): Promise<boolean> {
        const token = await this.getToken();
        return token !== undefined;
    }

    private async getToken(): Promise<string | undefined> {
        return await this.context.secrets.get(this.tokenKey);
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
            const response = await this.axiosInstance.post('/api/scan/file', {
                file_path: filePath,
                scan_types: ['sast', 'secrets']
            });

            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'File scan failed');
        }
    }

    async getFindings(projectId?: string): Promise<any> {
        try {
            let url = '/findings';
            if (projectId) {
                url += `?project_id=${projectId}`;
            }

            const response = await this.axiosInstance.get(url);
            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to fetch findings');
        }
    }

    async updateFindingStatus(findingId: string, status: string): Promise<void> {
        try {
            await this.axiosInstance.patch(`/findings/${findingId}`, {
                status
            });
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to update finding status');
        }
    }

    async getAIFix(findingId: string): Promise<any> {
        try {
            const response = await this.axiosInstance.post(`/findings/${findingId}/fix`);
            return response.data;
        } catch (error: any) {
            throw new Error(error.response?.data?.detail || 'Failed to get AI fix');
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
}
