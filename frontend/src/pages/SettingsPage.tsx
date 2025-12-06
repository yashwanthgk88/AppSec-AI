import { useState, useEffect } from 'react'
import { Save, Key, AlertCircle, CheckCircle, Brain, Download, Code, Shield, Globe, RefreshCw, Trash2 } from 'lucide-react'
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

interface ThreatIntelSettings {
  nvd_api_key: string
  has_nvd_key: boolean
  misp_api_key: string
  has_misp_key: boolean
  misp_url: string
  sources: {
    [key: string]: {
      name: string
      description: string
      requires_key: boolean
      key_url: string | null
      benefits: string
    }
  }
}

interface ConnectionTestResult {
  status: 'success' | 'error' | 'unknown'
  message: string
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

  // Threat Intel Configuration
  const [threatIntelSettings, setThreatIntelSettings] = useState<ThreatIntelSettings | null>(null)
  const [nvdApiKey, setNvdApiKey] = useState('')
  const [mispApiKey, setMispApiKey] = useState('')
  const [mispUrl, setMispUrl] = useState('')
  const [savingThreatIntel, setSavingThreatIntel] = useState(false)
  const [threatIntelMessage, setThreatIntelMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [testingConnection, setTestingConnection] = useState(false)
  const [connectionResults, setConnectionResults] = useState<{ [key: string]: ConnectionTestResult } | null>(null)

  useEffect(() => {
    loadSettings()
    loadThreatIntelSettings()
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

  const loadThreatIntelSettings = async () => {
    try {
      const token = localStorage.getItem('token')
      const response = await axios.get('/api/settings/threat-intel', {
        headers: { Authorization: `Bearer ${token}` },
      })
      setThreatIntelSettings(response.data)
      if (response.data.misp_url) {
        setMispUrl(response.data.misp_url)
      }
    } catch (error) {
      console.error('Failed to load threat intel settings:', error)
    }
  }

  const handleSaveThreatIntel = async () => {
    setSavingThreatIntel(true)
    setThreatIntelMessage(null)

    try {
      const token = localStorage.getItem('token')
      const payload: { nvd_api_key?: string; misp_api_key?: string; misp_url?: string } = {}

      if (nvdApiKey.trim()) {
        payload.nvd_api_key = nvdApiKey.trim()
      }
      if (mispApiKey.trim()) {
        payload.misp_api_key = mispApiKey.trim()
      }
      if (mispUrl.trim()) {
        payload.misp_url = mispUrl.trim()
      }

      const response = await axios.put('/api/settings/threat-intel', payload, {
        headers: { Authorization: `Bearer ${token}` },
      })

      if (response.data.success) {
        setThreatIntelMessage({ type: 'success', text: response.data.message })
        setNvdApiKey('')
        setMispApiKey('')
        await loadThreatIntelSettings()
      }
    } catch (error: any) {
      setThreatIntelMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to update threat intel settings',
      })
    } finally {
      setSavingThreatIntel(false)
    }
  }

  const handleTestConnection = async () => {
    setTestingConnection(true)
    setConnectionResults(null)

    try {
      const token = localStorage.getItem('token')
      const response = await axios.post('/api/settings/threat-intel/test', {}, {
        headers: { Authorization: `Bearer ${token}` },
      })
      setConnectionResults(response.data.results)
    } catch (error: any) {
      setThreatIntelMessage({
        type: 'error',
        text: 'Failed to test connections',
      })
    } finally {
      setTestingConnection(false)
    }
  }

  const handleDeleteKey = async (keyType: string) => {
    try {
      const token = localStorage.getItem('token')
      await axios.delete(`/api/settings/threat-intel/${keyType}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      setThreatIntelMessage({ type: 'success', text: `${keyType.toUpperCase()} key deleted` })
      await loadThreatIntelSettings()
    } catch (error: any) {
      setThreatIntelMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to delete key',
      })
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

      {/* Threat Intelligence API Keys Section */}
      <div className="bg-white shadow rounded-lg p-6 mb-6">
        <div className="flex items-center mb-4">
          <Shield className="h-6 w-6 text-red-600 mr-2" />
          <h2 className="text-xl font-semibold text-gray-900">Threat Intelligence API Keys</h2>
        </div>

        <p className="text-gray-600 mb-4">
          Configure API keys for threat intelligence sources. These keys enable enhanced threat data fetching with higher rate limits.
        </p>

        {/* Source Status Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          {/* NVD */}
          <div className="border rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-gray-900">NVD</h3>
              {threatIntelSettings?.has_nvd_key ? (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Configured
                </span>
              ) : (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                  <AlertCircle className="w-3 h-3 mr-1" />
                  Limited
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500">National Vulnerability Database</p>
            {threatIntelSettings?.has_nvd_key && (
              <p className="text-xs text-gray-400 mt-1">Key: {threatIntelSettings.nvd_api_key}</p>
            )}
          </div>

          {/* CISA KEV */}
          <div className="border rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-gray-900">CISA KEV</h3>
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                <CheckCircle className="w-3 h-3 mr-1" />
                Free
              </span>
            </div>
            <p className="text-xs text-gray-500">Known Exploited Vulnerabilities</p>
            <p className="text-xs text-gray-400 mt-1">No API key required</p>
          </div>

          {/* MISP Galaxy */}
          <div className="border rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-gray-900">MISP Galaxy</h3>
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                <CheckCircle className="w-3 h-3 mr-1" />
                Free
              </span>
            </div>
            <p className="text-xs text-gray-500">Threat Actors & Malware</p>
            <p className="text-xs text-gray-400 mt-1">Uses public GitHub data</p>
          </div>
        </div>

        {/* Test Connection Button */}
        <div className="mb-6">
          <button
            onClick={handleTestConnection}
            disabled={testingConnection}
            className="btn btn-secondary inline-flex items-center"
          >
            {testingConnection ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-indigo-600 mr-2"></div>
                Testing...
              </>
            ) : (
              <>
                <RefreshCw className="h-4 w-4 mr-2" />
                Test All Connections
              </>
            )}
          </button>
        </div>

        {/* Connection Test Results */}
        {connectionResults && (
          <div className="mb-6 space-y-2">
            {Object.entries(connectionResults).map(([source, result]) => (
              <div
                key={source}
                className={`p-3 rounded-lg flex items-center justify-between ${
                  result.status === 'success'
                    ? 'bg-green-50 border border-green-200'
                    : 'bg-red-50 border border-red-200'
                }`}
              >
                <div className="flex items-center">
                  {result.status === 'success' ? (
                    <CheckCircle className="h-5 w-5 text-green-600 mr-2" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
                  )}
                  <span className="font-medium text-gray-900">{source.toUpperCase()}</span>
                </div>
                <span className={result.status === 'success' ? 'text-green-700' : 'text-red-700'}>
                  {result.message}
                </span>
              </div>
            ))}
          </div>
        )}

        {/* API Key Inputs */}
        <div className="space-y-4">
          {/* NVD API Key */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label htmlFor="nvdApiKey" className="block text-sm font-medium text-gray-700">
                NVD API Key
              </label>
              {threatIntelSettings?.has_nvd_key && (
                <button
                  onClick={() => handleDeleteKey('nvd')}
                  className="text-red-600 hover:text-red-800 text-sm flex items-center"
                >
                  <Trash2 className="h-3 w-3 mr-1" />
                  Remove
                </button>
              )}
            </div>
            <input
              type="password"
              id="nvdApiKey"
              value={nvdApiKey}
              onChange={(e) => setNvdApiKey(e.target.value)}
              placeholder={threatIntelSettings?.has_nvd_key ? 'Enter new key to replace...' : 'Enter NVD API key...'}
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
            />
            <p className="mt-1 text-xs text-gray-500">
              Get a free key from{' '}
              <a
                href="https://nvd.nist.gov/developers/request-an-api-key"
                target="_blank"
                rel="noopener noreferrer"
                className="text-indigo-600 hover:text-indigo-500"
              >
                NVD Developers Portal
              </a>
              . Increases rate limit from 5 to 50 requests per 30 seconds.
            </p>
          </div>

          {/* MISP Private Instance (Optional) */}
          <div className="border-t pt-4">
            <h4 className="text-sm font-medium text-gray-700 mb-2">MISP Private Instance (Optional)</h4>
            <p className="text-xs text-gray-500 mb-3">
              If you have a private MISP instance, configure it here for additional threat data.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label htmlFor="mispUrl" className="block text-sm font-medium text-gray-700 mb-1">
                  MISP URL
                </label>
                <input
                  type="text"
                  id="mispUrl"
                  value={mispUrl}
                  onChange={(e) => setMispUrl(e.target.value)}
                  placeholder="https://your-misp-instance.com"
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                />
              </div>
              <div>
                <label htmlFor="mispApiKey" className="block text-sm font-medium text-gray-700 mb-1">
                  MISP API Key
                </label>
                <input
                  type="password"
                  id="mispApiKey"
                  value={mispApiKey}
                  onChange={(e) => setMispApiKey(e.target.value)}
                  placeholder="Enter MISP API key..."
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                />
              </div>
            </div>
          </div>

          {threatIntelMessage && (
            <div
              className={`p-4 rounded-md ${
                threatIntelMessage.type === 'success'
                  ? 'bg-green-50 border border-green-200 text-green-800'
                  : 'bg-red-50 border border-red-200 text-red-800'
              }`}
            >
              <div className="flex items-center">
                {threatIntelMessage.type === 'success' ? (
                  <CheckCircle className="h-5 w-5 mr-2" />
                ) : (
                  <AlertCircle className="h-5 w-5 mr-2" />
                )}
                <span>{threatIntelMessage.text}</span>
              </div>
            </div>
          )}

          <button
            onClick={handleSaveThreatIntel}
            disabled={savingThreatIntel || (!nvdApiKey.trim() && !mispApiKey.trim() && !mispUrl.trim())}
            className="btn btn-primary inline-flex items-center"
          >
            {savingThreatIntel ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                Saving...
              </>
            ) : (
              <>
                <Save className="h-4 w-4 mr-2" />
                Save Threat Intel Settings
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
              href="/downloads/appsec-ai-scanner-1.4.0.vsix"
              download
              className="btn btn-primary inline-flex items-center"
            >
              <Download className="h-5 w-5 mr-2" />
              Download VS Code Extension
            </a>
            <p className="mt-2 text-sm text-gray-500">Version 1.4.0 • 957 KB</p>
          </div>
        </div>

        <div className="mt-6 bg-gradient-to-r from-purple-50 to-blue-50 border border-purple-200 rounded-lg p-4">
          <h4 className="font-semibold text-gray-900 mb-2 flex items-center">
            <span className="bg-purple-600 text-white text-xs px-2 py-1 rounded mr-2">LATEST</span>
            What's New in v1.4.0
          </h4>
          <ul className="list-disc list-inside text-sm text-gray-700 space-y-1">
            <li><strong>📦 Separate SCA Vulnerabilities View:</strong> Dedicated tree view for dependency vulnerabilities with package info, CVE details, CVSS scores, and fixed versions</li>
            <li><strong>🔐 Dedicated Secret Detection View:</strong> New tree view for exposed secrets grouped by type (API Keys, Passwords, Tokens) with critical security warnings</li>
            <li><strong>📊 Rule Performance Dashboard:</strong> Inline VS Code panel to view rule statistics, precision metrics, top performers, and rules needing attention - no browser needed!</li>
            <li><strong>🎯 Enhanced Findings Organization:</strong> SAST findings now in separate view from SCA and Secrets for better clarity and navigation</li>
            <li><strong>🐛 Bug Fixes:</strong> Fixed missing command registration errors and improved error handling throughout the extension</li>
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
