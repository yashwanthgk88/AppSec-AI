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
            const response = await this.axiosInstance.post('/api/auth/login', {
                username,
                password
            });
            const token = response.data.access_token;
            await this.context.secrets.store(this.tokenKey, token);
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Login failed');
        }
    }
    async logout() {
        await this.context.secrets.delete(this.tokenKey);
    }
    async isAuthenticated() {
        const token = await this.getToken();
        return token !== undefined;
    }
    async getToken() {
        return await this.context.secrets.get(this.tokenKey);
    }
    async scanWorkspace(workspacePath) {
        try {
            const response = await this.axiosInstance.post('/api/scan', {
                path: workspacePath,
                scan_types: ['sast', 'sca', 'secrets']
            });
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Scan failed');
        }
    }
    async scanFile(filePath) {
        try {
            const response = await this.axiosInstance.post('/api/scan/file', {
                file_path: filePath,
                scan_types: ['sast', 'secrets']
            });
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'File scan failed');
        }
    }
    async getFindings(projectId) {
        try {
            let url = '/findings';
            if (projectId) {
                url += `?project_id=${projectId}`;
            }
            const response = await this.axiosInstance.get(url);
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to fetch findings');
        }
    }
    async updateFindingStatus(findingId, status) {
        try {
            await this.axiosInstance.patch(`/findings/${findingId}`, {
                status
            });
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to update finding status');
        }
    }
    async getAIFix(findingId) {
        try {
            const response = await this.axiosInstance.post(`/findings/${findingId}/fix`);
            return response.data;
        }
        catch (error) {
            throw new Error(error.response?.data?.detail || 'Failed to get AI fix');
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
}
exports.ApiClient = ApiClient;
//# sourceMappingURL=apiClient.js.map