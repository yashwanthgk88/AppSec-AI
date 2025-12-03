import { useState, useEffect } from 'react'
import { Save, Key, AlertCircle, CheckCircle, Brain, Download, Code } from 'lucide-react'
import axios from 'axios'

interface Settings {
  openai_api_key: string
  has_openai_key: boolean
  ai_provider?: string
  ai_model?: string
  ai_base_url?: string
  ai_api_version?: string
  has_ai_key?: boolean
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [apiKey, setApiKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  // AI Provider Configuration
  const [aiProvider, setAiProvider] = useState('anthropic')
  const [aiApiKey, setAiApiKey] = useState('')
  const [aiModel, setAiModel] = useState('')
  const [aiBaseUrl, setAiBaseUrl] = useState('')
  const [aiApiVersion, setAiApiVersion] = useState('')
  const [savingAi, setSavingAi] = useState(false)
  const [aiMessage, setAiMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  useEffect(() => {
    loadSettings()
  }, [])

  const loadSettings = async () => {
    setLoading(true)
    try {
      const token = localStorage.getItem('token')
      const response = await axios.get('/api/settings', {
        headers: { Authorization: `Bearer ${token}` },
      })
      setSettings(response.data)
      setApiKey('') // Don't show the masked key in input

      // Load AI provider settings
      if (response.data.ai_provider) {
        setAiProvider(response.data.ai_provider)
      }
      if (response.data.ai_model) {
        setAiModel(response.data.ai_model)
      }
      if (response.data.ai_base_url) {
        setAiBaseUrl(response.data.ai_base_url)
      }
      if (response.data.ai_api_version) {
        setAiApiVersion(response.data.ai_api_version)
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Failed to load settings' })
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    if (!apiKey.trim()) {
      setMessage({ type: 'error', text: 'Please enter an API key' })
      return
    }

    setSaving(true)
    setMessage(null)

    try {
      const token = localStorage.getItem('token')
      const response = await axios.put(
        '/api/settings',
        { openai_api_key: apiKey },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      )

      if (response.data.success) {
        setMessage({ type: 'success', text: response.data.message })
        setApiKey('')
        // Reload settings to get masked key
        await loadSettings()
      } else {
        setMessage({ type: 'error', text: response.data.message })
      }
    } catch (error: any) {
      setMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to update settings',
      })
    } finally {
      setSaving(false)
    }
  }

  const handleSaveAiConfig = async () => {
    if (!aiApiKey.trim()) {
      setAiMessage({ type: 'error', text: 'Please enter an API key' })
      return
    }

    setSavingAi(true)
    setAiMessage(null)

    try {
      const token = localStorage.getItem('token')
      const response = await axios.put(
        '/api/settings/ai-provider',
        {
          ai_provider: aiProvider,
          ai_api_key: aiApiKey,
          ai_model: aiModel.trim() || null,
          ai_base_url: aiBaseUrl.trim() || null,
          ai_api_version: aiApiVersion.trim() || null,
        },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      )

      if (response.data.success) {
        setAiMessage({ type: 'success', text: response.data.message })
        setAiApiKey('')
        await loadSettings()
      } else {
        setAiMessage({ type: 'error', text: response.data.message })
      }
    } catch (error: any) {
      setAiMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to update AI provider settings',
      })
    } finally {
      setSavingAi(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
      </div>
    )
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Settings</h1>
        <p className="mt-2 text-gray-600">Manage your application settings and API keys</p>
      </div>

      {/* OpenAI API Key Section */}
      <div className="bg-white shadow rounded-lg p-6 mb-6">
        <div className="flex items-center mb-4">
          <Key className="h-6 w-6 text-indigo-600 mr-2" />
          <h2 className="text-xl font-semibold text-gray-900">OpenAI API Key</h2>
        </div>

        <p className="text-gray-600 mb-4">
          Configure your OpenAI API key for the AI chatbot functionality. The key will be stored
          securely in the backend configuration.
        </p>

        {settings?.has_openai_key && (
          <div className="mb-4 p-3 bg-green-50 border border-green-200 rounded-md">
            <div className="flex items-center text-green-800">
              <CheckCircle className="h-5 w-5 mr-2" />
              <span className="font-medium">API Key Configured</span>
            </div>
            <p className="text-sm text-green-700 mt-1">Current key: {settings.openai_api_key}</p>
          </div>
        )}

        {!settings?.has_openai_key && (
          <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-md">
            <div className="flex items-center text-yellow-800">
              <AlertCircle className="h-5 w-5 mr-2" />
              <span className="font-medium">No API Key Configured</span>
            </div>
            <p className="text-sm text-yellow-700 mt-1">
              The chatbot will not work without an OpenAI API key.
            </p>
          </div>
        )}

        <div className="space-y-4">
          <div>
            <label htmlFor="apiKey" className="block text-sm font-medium text-gray-700 mb-2">
              {settings?.has_openai_key ? 'New API Key' : 'API Key'}
            </label>
            <input
              type="password"
              id="apiKey"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="sk-proj-..."
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
            />
            <p className="mt-2 text-sm text-gray-500">
              Get your API key from{' '}
              <a
                href="https://platform.openai.com/api-keys"
                target="_blank"
                rel="noopener noreferrer"
                className="text-indigo-600 hover:text-indigo-500"
              >
                OpenAI Platform
              </a>
            </p>
          </div>

          {message && (
            <div
              className={`p-4 rounded-md ${
                message.type === 'success'
                  ? 'bg-green-50 border border-green-200 text-green-800'
                  : 'bg-red-50 border border-red-200 text-red-800'
              }`}
            >
              <div className="flex items-center">
                {message.type === 'success' ? (
                  <CheckCircle className="h-5 w-5 mr-2" />
                ) : (
                  <AlertCircle className="h-5 w-5 mr-2" />
                )}
                <span>{message.text}</span>
              </div>
            </div>
          )}

          <button
            onClick={handleSave}
            disabled={saving || !apiKey.trim()}
            className="btn btn-primary inline-flex items-center"
          >
            {saving ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                Saving...
              </>
            ) : (
              <>
                <Save className="h-4 w-4 mr-2" />
                Save API Key
              </>
            )}
          </button>
        </div>
      </div>

      {/* AI Provider Configuration Section */}
      <div className="bg-white shadow rounded-lg p-6 mb-6">
        <div className="flex items-center mb-4">
          <Brain className="h-6 w-6 text-indigo-600 mr-2" />
          <h2 className="text-xl font-semibold text-gray-900">AI Provider Configuration</h2>
        </div>

        <p className="text-gray-600 mb-4">
          Configure your AI provider for threat modeling and security analysis. Choose from multiple providers and use your own API keys.
        </p>

        {settings?.has_ai_key && (
          <div className="mb-4 p-3 bg-green-50 border border-green-200 rounded-md">
            <div className="flex items-center text-green-800">
              <CheckCircle className="h-5 w-5 mr-2" />
              <span className="font-medium">AI Provider Configured: {settings.ai_provider?.toUpperCase()}</span>
            </div>
          </div>
        )}

        <div className="space-y-4">
          <div>
            <label htmlFor="aiProvider" className="block text-sm font-medium text-gray-700 mb-2">
              AI Provider
            </label>
            <select
              id="aiProvider"
              value={aiProvider}
              onChange={(e) => setAiProvider(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
            >
              <option value="anthropic">Anthropic Claude</option>
              <option value="openai">OpenAI</option>
              <option value="azure">Azure OpenAI</option>
              <option value="google">Google Gemini</option>
              <option value="ollama">Ollama (Local)</option>
            </select>
          </div>

          <div>
            <label htmlFor="aiApiKey" className="block text-sm font-medium text-gray-700 mb-2">
              API Key
            </label>
            <input
              type="password"
              id="aiApiKey"
              value={aiApiKey}
              onChange={(e) => setAiApiKey(e.target.value)}
              placeholder={
                aiProvider === 'anthropic' ? 'sk-ant-...' :
                aiProvider === 'openai' ? 'sk-...' :
                aiProvider === 'azure' ? 'Azure API Key' :
                aiProvider === 'google' ? 'Google API Key' :
                'Not required for local Ollama'
              }
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
              disabled={aiProvider === 'ollama'}
            />
          </div>

          <div>
            <label htmlFor="aiModel" className="block text-sm font-medium text-gray-700 mb-2">
              Model Name (Optional)
            </label>
            <input
              type="text"
              id="aiModel"
              value={aiModel}
              onChange={(e) => setAiModel(e.target.value)}
              placeholder={
                aiProvider === 'anthropic' ? 'claude-3-5-sonnet-20241022' :
                aiProvider === 'openai' ? 'gpt-4' :
                aiProvider === 'azure' ? 'Deployment name' :
                aiProvider === 'google' ? 'gemini-pro' :
                'llama2'
              }
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
            />
            <p className="mt-1 text-xs text-gray-500">Leave empty to use the default model</p>
          </div>

          {(aiProvider === 'azure' || aiProvider === 'ollama') && (
            <div>
              <label htmlFor="aiBaseUrl" className="block text-sm font-medium text-gray-700 mb-2">
                {aiProvider === 'azure' ? 'Azure Endpoint' : 'Ollama Base URL'}
              </label>
              <input
                type="text"
                id="aiBaseUrl"
                value={aiBaseUrl}
                onChange={(e) => setAiBaseUrl(e.target.value)}
                placeholder={
                  aiProvider === 'azure' ? 'https://your-resource.openai.azure.com/' :
                  'http://localhost:11434'
                }
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
              />
            </div>
          )}

          {aiProvider === 'azure' && (
            <div>
              <label htmlFor="aiApiVersion" className="block text-sm font-medium text-gray-700 mb-2">
                API Version
              </label>
              <input
                type="text"
                id="aiApiVersion"
                value={aiApiVersion}
                onChange={(e) => setAiApiVersion(e.target.value)}
                placeholder="2024-02-15-preview"
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
              />
            </div>
          )}

          {aiMessage && (
            <div
              className={`p-4 rounded-md ${
                aiMessage.type === 'success'
                  ? 'bg-green-50 border border-green-200 text-green-800'
                  : 'bg-red-50 border border-red-200 text-red-800'
              }`}
            >
              <div className="flex items-center">
                {aiMessage.type === 'success' ? (
                  <CheckCircle className="h-5 w-5 mr-2" />
                ) : (
                  <AlertCircle className="h-5 w-5 mr-2" />
                )}
                <span>{aiMessage.text}</span>
              </div>
            </div>
          )}

          <button
            onClick={handleSaveAiConfig}
            disabled={savingAi || (aiProvider !== 'ollama' && !aiApiKey.trim())}
            className="btn btn-primary inline-flex items-center"
          >
            {savingAi ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                Saving...
              </>
            ) : (
              <>
                <Save className="h-4 w-4 mr-2" />
                Save AI Configuration
              </>
            )}
          </button>
        </div>
      </div>

      {/* VS Code Extension Download Section */}
      <div className="bg-white shadow rounded-lg p-6 mb-6">
        <div className="flex items-center mb-4">
          <Code className="h-6 w-6 text-indigo-600 mr-2" />
          <h2 className="text-xl font-semibold text-gray-900">VS Code Extension</h2>
        </div>

        <p className="text-gray-600 mb-4">
          Download our VS Code extension for real-time security scanning directly in your editor. Get instant feedback on vulnerabilities as you code.
        </p>

        <div className="bg-gradient-to-r from-indigo-50 to-purple-50 border border-indigo-200 rounded-lg p-6 mb-4">
          <h3 className="text-lg font-semibold text-gray-900 mb-3">Features</h3>
          <ul className="space-y-2 text-gray-700">
            <li className="flex items-start">
              <CheckCircle className="h-5 w-5 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
              <span>Real-time SAST, SCA, and secret detection as you code</span>
            </li>
            <li className="flex items-start">
              <CheckCircle className="h-5 w-5 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
              <span>Inline diagnostics with squiggly lines for security issues</span>
            </li>
            <li className="flex items-start">
              <CheckCircle className="h-5 w-5 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
              <span>AI-powered fix suggestions with one-click apply</span>
            </li>
            <li className="flex items-start">
              <CheckCircle className="h-5 w-5 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
              <span>Sidebar tree view organized by severity</span>
            </li>
            <li className="flex items-start">
              <CheckCircle className="h-5 w-5 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
              <span>Auto-scan on save (optional)</span>
            </li>
          </ul>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <a
              href="/downloads/appsec-ai-scanner-1.2.0.vsix"
              download
              className="btn btn-primary inline-flex items-center"
            >
              <Download className="h-5 w-5 mr-2" />
              Download VS Code Extension
            </a>
            <p className="mt-2 text-sm text-gray-500">Version 1.2.0 • 924 KB</p>
          </div>
        </div>

        <div className="mt-6 bg-gradient-to-r from-purple-50 to-blue-50 border border-purple-200 rounded-lg p-4">
          <h4 className="font-semibold text-gray-900 mb-2 flex items-center">
            <span className="bg-purple-600 text-white text-xs px-2 py-1 rounded mr-2">LATEST</span>
            What's New in v1.2.0
          </h4>
          <ul className="list-disc list-inside text-sm text-gray-700 space-y-1">
            <li><strong>💬 AI-Powered Vulnerability Discussion:</strong> Click "Discuss with AI" on any finding to open chatbot with full vulnerability context, code snippet, and start an interactive conversation about the security issue</li>
            <li><strong>📝 Detailed Impact & Remediation:</strong> Category-specific detailed impact analysis (6-12 points) and step-by-step remediation guides (10-12 steps) with actionable instructions</li>
            <li><strong>💻 Always-Available Remediation Code:</strong> Every vulnerability now includes before/after code examples - actual fixes when available, or intelligent category-specific examples as fallback</li>
            <li><strong>🎨 Enhanced Vulnerability Details Panel:</strong> Beautiful dark theme with comprehensive vulnerability information, impact analysis, and remediation steps</li>
            <li><strong>📊 Scan Progress Bar:</strong> Real-time progress tracking with stage indicators and detailed status messages</li>
            <li><strong>✅ Auto-Remediation with Git:</strong> One-click fix application with automatic git commit and customizable commit messages</li>
            <li><strong>⚡ Real-Time Inline Security Suggestions:</strong> Get instant security warnings as you type - detects eval(), innerHTML, SQL injection, hardcoded secrets, weak crypto, and more</li>
            <li><strong>🔍 Improved Findings Sidebar:</strong> Shows vulnerability counts per severity, rich tooltips with markdown, and organized tree view</li>
            <li><strong>📁 File Navigation:</strong> Click file location to jump directly to vulnerable code in editor</li>
            <li><strong>📋 Code Snippets:</strong> View vulnerable code and suggested fixes side-by-side with syntax highlighting</li>
            <li><strong>💡 Quick Fixes:</strong> Hover over inline security warnings for suggested remediation steps</li>
          </ul>
        </div>

        <div className="mt-4 bg-gray-50 border border-gray-200 rounded-lg p-4">
          <h4 className="font-semibold text-gray-900 mb-2">Installation Instructions</h4>
          <ol className="list-decimal list-inside text-sm text-gray-700 space-y-1">
            <li>Download the extension file above</li>
            <li>Open VS Code</li>
            <li>Go to Extensions (Ctrl+Shift+X / Cmd+Shift+X)</li>
            <li>Click the "..." menu → "Install from VSIX..."</li>
            <li>Select the downloaded .vsix file</li>
            <li>Reload VS Code when prompted</li>
            <li>Use Command Palette (Ctrl+Shift+P) → "AppSec: Login to Platform"</li>
          </ol>
        </div>
      </div>

      {/* Information Section */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-blue-900 mb-2">About AI Configuration</h3>
        <ul className="list-disc list-inside text-blue-800 space-y-1 text-sm">
          <li>Your API keys are stored securely and encrypted in the database</li>
          <li>Different AI providers offer different capabilities and pricing</li>
          <li>Anthropic Claude is recommended for security analysis and threat modeling</li>
          <li>Ollama allows you to run models locally without API costs</li>
          <li>You can switch providers anytime to compare results</li>
        </ul>
      </div>
    </div>
  )
}
