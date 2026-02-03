import { useState, useEffect } from 'react'
import { Save, Key, AlertCircle, CheckCircle, Brain, Download, Code, Shield, Globe, RefreshCw, Trash2, Package, Link2, Server, Cloud } from 'lucide-react'
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

interface ScaFeedsSettings {
  has_github_token: boolean
  has_snyk_token: boolean
  github_token_masked?: string
  snyk_token_masked?: string
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

interface IntegrationSettings {
  id?: number
  integration_type: string
  base_url: string
  username?: string
  is_connected: boolean
  last_connected_at?: string
  abuse_cases_field?: string
  security_req_field?: string
  connection_error?: string
}

interface IntegrationStatus {
  jira: { configured: boolean; connected: boolean; url?: string }
  ado: { configured: boolean; connected: boolean; url?: string }
  snow: { configured: boolean; connected: boolean; url?: string }
}

interface SecureReqPromptSettings {
  use_custom_prompts: boolean
  custom_abuse_case_prompt: string | null
  custom_security_req_prompt: string | null
  default_abuse_case_prompt: string
  default_security_req_prompt: string
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

  // SCA Vulnerability Feeds Configuration
  const [scaFeedsSettings, setScaFeedsSettings] = useState<ScaFeedsSettings | null>(null)
  const [githubToken, setGithubToken] = useState('')
  const [snykToken, setSnykToken] = useState('')
  const [savingScaFeeds, setSavingScaFeeds] = useState(false)
  const [scaFeedsMessage, setScaFeedsMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [testingScaFeeds, setTestingScaFeeds] = useState(false)
  const [scaFeedsResults, setScaFeedsResults] = useState<{ [key: string]: ConnectionTestResult } | null>(null)

  // Integration Settings State
  const [integrationStatus, setIntegrationStatus] = useState<IntegrationStatus | null>(null)
  const [activeIntegrationTab, setActiveIntegrationTab] = useState<'jira' | 'ado' | 'snow'>('jira')

  // Jira settings
  const [jiraUrl, setJiraUrl] = useState('')
  const [jiraEmail, setJiraEmail] = useState('')
  const [jiraToken, setJiraToken] = useState('')
  const [jiraAbuseCasesField, setJiraAbuseCasesField] = useState('')
  const [jiraSecurityReqField, setJiraSecurityReqField] = useState('')
  const [savingJira, setSavingJira] = useState(false)
  const [testingJira, setTestingJira] = useState(false)
  const [jiraMessage, setJiraMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  // ADO settings
  const [adoOrgUrl, setAdoOrgUrl] = useState('')
  const [adoPat, setAdoPat] = useState('')
  const [adoAbuseCasesField, setAdoAbuseCasesField] = useState('')
  const [adoSecurityReqField, setAdoSecurityReqField] = useState('')
  const [savingAdo, setSavingAdo] = useState(false)
  const [testingAdo, setTestingAdo] = useState(false)
  const [adoMessage, setAdoMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  // SNOW settings
  const [snowUrl, setSnowUrl] = useState('')
  const [snowUsername, setSnowUsername] = useState('')
  const [snowPassword, setSnowPassword] = useState('')
  const [snowAbuseCasesField, setSnowAbuseCasesField] = useState('')
  const [snowSecurityReqField, setSnowSecurityReqField] = useState('')
  const [savingSnow, setSavingSnow] = useState(false)
  const [testingSnow, setTestingSnow] = useState(false)
  const [snowMessage, setSnowMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  // SecureReq Prompt Settings
  const [promptSettings, setPromptSettings] = useState<SecureReqPromptSettings | null>(null)
  const [useCustomPrompts, setUseCustomPrompts] = useState(false)
  const [customAbuseCasePrompt, setCustomAbuseCasePrompt] = useState('')
  const [customSecurityReqPrompt, setCustomSecurityReqPrompt] = useState('')
  const [savingPrompts, setSavingPrompts] = useState(false)
  const [promptMessage, setPromptMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [showDefaultPrompts, setShowDefaultPrompts] = useState(false)

  useEffect(() => {
    loadSettings()
    loadThreatIntelSettings()
    loadScaFeedsSettings()
    loadIntegrationStatus()
    loadPromptSettings()
  }, [])

  const loadIntegrationStatus = async () => {
    try {
      const token = localStorage.getItem('token')
      const response = await axios.get('/api/integrations/status', {
        headers: { Authorization: `Bearer ${token}` },
      })
      setIntegrationStatus(response.data)
    } catch (error) {
      console.error('Failed to load integration status:', error)
    }
  }

  const loadPromptSettings = async () => {
    try {
      const token = localStorage.getItem('token')
      const response = await axios.get('/api/settings/securereq-prompts', {
        headers: { Authorization: `Bearer ${token}` },
      })
      setPromptSettings(response.data)
      setUseCustomPrompts(response.data.use_custom_prompts || false)
      setCustomAbuseCasePrompt(response.data.custom_abuse_case_prompt || '')
      setCustomSecurityReqPrompt(response.data.custom_security_req_prompt || '')
    } catch (error) {
      console.error('Failed to load prompt settings:', error)
    }
  }

  const handleSavePrompts = async () => {
    setSavingPrompts(true)
    setPromptMessage(null)
    try {
      const token = localStorage.getItem('token')
      await axios.put('/api/settings/securereq-prompts', {
        use_custom_prompts: useCustomPrompts,
        custom_abuse_case_prompt: customAbuseCasePrompt || null,
        custom_security_req_prompt: customSecurityReqPrompt || null,
      }, { headers: { Authorization: `Bearer ${token}` } })
      setPromptMessage({ type: 'success', text: 'Prompt settings saved successfully' })
    } catch (error: any) {
      setPromptMessage({ type: 'error', text: error.response?.data?.detail || 'Failed to save prompt settings' })
    } finally {
      setSavingPrompts(false)
    }
  }

  const handleResetPrompts = async () => {
    setSavingPrompts(true)
    setPromptMessage(null)
    try {
      const token = localStorage.getItem('token')
      await axios.post('/api/settings/securereq-prompts/reset', {}, {
        headers: { Authorization: `Bearer ${token}` },
      })
      setPromptMessage({ type: 'success', text: 'Prompts reset to defaults' })
      await loadPromptSettings()
    } catch (error: any) {
      setPromptMessage({ type: 'error', text: error.response?.data?.detail || 'Failed to reset prompts' })
    } finally {
      setSavingPrompts(false)
    }
  }

  const handleSaveJira = async () => {
    if (!jiraUrl.trim() || !jiraToken.trim()) {
      setJiraMessage({ type: 'error', text: 'URL and API Token are required' })
      return
    }
    setSavingJira(true)
    setJiraMessage(null)
    try {
      const token = localStorage.getItem('token')
      await axios.put('/api/integrations/jira', {
        base_url: jiraUrl,
        username: jiraEmail,
        api_token: jiraToken,
        abuse_cases_field: jiraAbuseCasesField || null,
        security_req_field: jiraSecurityReqField || null,
      }, { headers: { Authorization: `Bearer ${token}` } })
      setJiraMessage({ type: 'success', text: 'Jira settings saved successfully' })
      setJiraToken('')
      loadIntegrationStatus()
    } catch (error: any) {
      setJiraMessage({ type: 'error', text: error.response?.data?.detail || 'Failed to save' })
    } finally {
      setSavingJira(false)
    }
  }

  const handleTestJira = async () => {
    setTestingJira(true)
    try {
      const token = localStorage.getItem('token')
      const response = await axios.post('/api/integrations/jira/test', {}, {
        headers: { Authorization: `Bearer ${token}` },
      })
      setJiraMessage({ type: response.data.success ? 'success' : 'error', text: response.data.message })
      loadIntegrationStatus()
    } catch (error: any) {
      setJiraMessage({ type: 'error', text: 'Connection test failed' })
    } finally {
      setTestingJira(false)
    }
  }

  const handleSaveAdo = async () => {
    if (!adoOrgUrl.trim() || !adoPat.trim()) {
      setAdoMessage({ type: 'error', text: 'Organization URL and PAT are required' })
      return
    }
    setSavingAdo(true)
    setAdoMessage(null)
    try {
      const token = localStorage.getItem('token')
      await axios.put('/api/integrations/ado', {
        org_url: adoOrgUrl,
        pat: adoPat,
        abuse_cases_field: adoAbuseCasesField || null,
        security_req_field: adoSecurityReqField || null,
      }, { headers: { Authorization: `Bearer ${token}` } })
      setAdoMessage({ type: 'success', text: 'Azure DevOps settings saved successfully' })
      setAdoPat('')
      loadIntegrationStatus()
    } catch (error: any) {
      setAdoMessage({ type: 'error', text: error.response?.data?.detail || 'Failed to save' })
    } finally {
      setSavingAdo(false)
    }
  }

  const handleTestAdo = async () => {
    setTestingAdo(true)
    try {
      const token = localStorage.getItem('token')
      const response = await axios.post('/api/integrations/ado/test', {}, {
        headers: { Authorization: `Bearer ${token}` },
      })
      setAdoMessage({ type: response.data.success ? 'success' : 'error', text: response.data.message })
      loadIntegrationStatus()
    } catch (error: any) {
      setAdoMessage({ type: 'error', text: 'Connection test failed' })
    } finally {
      setTestingAdo(false)
    }
  }

  const handleSaveSnow = async () => {
    if (!snowUrl.trim() || !snowUsername.trim() || !snowPassword.trim()) {
      setSnowMessage({ type: 'error', text: 'Instance URL, username, and password are required' })
      return
    }
    setSavingSnow(true)
    setSnowMessage(null)
    try {
      const token = localStorage.getItem('token')
      await axios.put('/api/integrations/snow', {
        base_url: snowUrl,
        username: snowUsername,
        api_token: snowPassword,
        abuse_cases_field: snowAbuseCasesField || null,
        security_req_field: snowSecurityReqField || null,
      }, { headers: { Authorization: `Bearer ${token}` } })
      setSnowMessage({ type: 'success', text: 'ServiceNow settings saved successfully' })
      setSnowPassword('')
      loadIntegrationStatus()
    } catch (error: any) {
      setSnowMessage({ type: 'error', text: error.response?.data?.detail || 'Failed to save' })
    } finally {
      setSavingSnow(false)
    }
  }

  const handleTestSnow = async () => {
    setTestingSnow(true)
    try {
      const token = localStorage.getItem('token')
      const response = await axios.post('/api/integrations/snow/test', {}, {
        headers: { Authorization: `Bearer ${token}` },
      })
      setSnowMessage({ type: response.data.success ? 'success' : 'error', text: response.data.message })
      loadIntegrationStatus()
    } catch (error: any) {
      setSnowMessage({ type: 'error', text: 'Connection test failed' })
    } finally {
      setTestingSnow(false)
    }
  }

  const loadScaFeedsSettings = async () => {
    try {
      const token = localStorage.getItem('token')
      const response = await axios.get('/api/settings/sca-feeds', {
        headers: { Authorization: `Bearer ${token}` },
      })
      setScaFeedsSettings(response.data)
    } catch (error) {
      console.error('Failed to load SCA feeds settings:', error)
    }
  }

  const handleSaveScaFeeds = async () => {
    setSavingScaFeeds(true)
    setScaFeedsMessage(null)

    try {
      const token = localStorage.getItem('token')
      const payload: { github_token?: string; snyk_token?: string } = {}

      if (githubToken.trim()) {
        payload.github_token = githubToken.trim()
      }
      if (snykToken.trim()) {
        payload.snyk_token = snykToken.trim()
      }

      const response = await axios.put('/api/settings/sca-feeds', payload, {
        headers: { Authorization: `Bearer ${token}` },
      })

      if (response.data.success) {
        setScaFeedsMessage({ type: 'success', text: response.data.message })
        setGithubToken('')
        setSnykToken('')
        await loadScaFeedsSettings()
      }
    } catch (error: any) {
      setScaFeedsMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to update SCA feeds settings',
      })
    } finally {
      setSavingScaFeeds(false)
    }
  }

  const handleTestScaFeeds = async () => {
    setTestingScaFeeds(true)
    setScaFeedsResults(null)

    try {
      const token = localStorage.getItem('token')
      const response = await axios.post('/api/settings/sca-feeds/test', {}, {
        headers: { Authorization: `Bearer ${token}` },
      })
      setScaFeedsResults(response.data.results)
    } catch (error: any) {
      setScaFeedsMessage({
        type: 'error',
        text: 'Failed to test SCA feed connections',
      })
    } finally {
      setTestingScaFeeds(false)
    }
  }

  const handleDeleteScaKey = async (keyType: string) => {
    try {
      const token = localStorage.getItem('token')
      await axios.delete(`/api/settings/sca-feeds/${keyType}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      setScaFeedsMessage({ type: 'success', text: `${keyType.replace('_', ' ').toUpperCase()} deleted` })
      await loadScaFeedsSettings()
    } catch (error: any) {
      setScaFeedsMessage({
        type: 'error',
        text: error.response?.data?.detail || 'Failed to delete key',
      })
    }
  }

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

      {/* SecureReq Analysis Prompts Section */}
      <div className="bg-white shadow rounded-lg p-6 mb-6">
        <div className="flex items-center mb-4">
          <Code className="h-6 w-6 text-purple-600 mr-2" />
          <h2 className="text-xl font-semibold text-gray-900">SecureReq Analysis Prompts</h2>
        </div>

        <p className="text-gray-600 mb-4">
          Customize the AI prompts used for generating abuse cases and security requirements.
          This allows you to tailor the analysis output without redeploying the application.
        </p>

        <div className="space-y-4">
          {/* Toggle for custom prompts */}
          <div className="flex items-center">
            <input
              type="checkbox"
              id="useCustomPrompts"
              checked={useCustomPrompts}
              onChange={(e) => setUseCustomPrompts(e.target.checked)}
              className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
            />
            <label htmlFor="useCustomPrompts" className="ml-2 block text-sm font-medium text-gray-700">
              Use Custom Prompts
            </label>
          </div>

          {useCustomPrompts && (
            <>
              {/* Abuse Case Prompt */}
              <div>
                <label htmlFor="abuseCasePrompt" className="block text-sm font-medium text-gray-700 mb-2">
                  Abuse Case Instructions
                </label>
                <textarea
                  id="abuseCasePrompt"
                  rows={8}
                  value={customAbuseCasePrompt}
                  onChange={(e) => setCustomAbuseCasePrompt(e.target.value)}
                  placeholder="Enter custom instructions for abuse case generation..."
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
                />
                <p className="mt-1 text-xs text-gray-500">
                  Define how many abuse cases to generate and what details to include (attack narratives, tools, mitigations, etc.)
                </p>
              </div>

              {/* Security Requirements Prompt */}
              <div>
                <label htmlFor="secReqPrompt" className="block text-sm font-medium text-gray-700 mb-2">
                  Security Requirements Instructions
                </label>
                <textarea
                  id="secReqPrompt"
                  rows={8}
                  value={customSecurityReqPrompt}
                  onChange={(e) => setCustomSecurityReqPrompt(e.target.value)}
                  placeholder="Enter custom instructions for security requirements generation..."
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
                />
                <p className="mt-1 text-xs text-gray-500">
                  Define how many requirements to generate, categories to cover, and what details to include (libraries, configs, CWE/OWASP references, etc.)
                </p>
              </div>
            </>
          )}

          {/* View Default Prompts (Collapsible) */}
          <div className="border rounded-lg">
            <button
              onClick={() => setShowDefaultPrompts(!showDefaultPrompts)}
              className="w-full px-4 py-3 flex items-center justify-between text-left text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              <span>View Default Prompts</span>
              <span className={`transform transition-transform ${showDefaultPrompts ? 'rotate-180' : ''}`}>
                ▼
              </span>
            </button>
            {showDefaultPrompts && promptSettings && (
              <div className="px-4 pb-4 space-y-4 border-t">
                <div>
                  <h4 className="text-sm font-medium text-gray-700 mt-3 mb-2">Default Abuse Case Instructions:</h4>
                  <pre className="bg-gray-50 p-3 rounded text-xs overflow-x-auto whitespace-pre-wrap">
                    {promptSettings.default_abuse_case_prompt}
                  </pre>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-gray-700 mb-2">Default Security Requirements Instructions:</h4>
                  <pre className="bg-gray-50 p-3 rounded text-xs overflow-x-auto whitespace-pre-wrap">
                    {promptSettings.default_security_req_prompt}
                  </pre>
                </div>
              </div>
            )}
          </div>

          {promptMessage && (
            <div
              className={`p-4 rounded-md ${
                promptMessage.type === 'success'
                  ? 'bg-green-50 border border-green-200 text-green-800'
                  : 'bg-red-50 border border-red-200 text-red-800'
              }`}
            >
              <div className="flex items-center">
                {promptMessage.type === 'success' ? (
                  <CheckCircle className="h-5 w-5 mr-2" />
                ) : (
                  <AlertCircle className="h-5 w-5 mr-2" />
                )}
                <span>{promptMessage.text}</span>
              </div>
            </div>
          )}

          <div className="flex space-x-3">
            <button
              onClick={handleSavePrompts}
              disabled={savingPrompts}
              className="btn btn-primary inline-flex items-center"
            >
              {savingPrompts ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Saving...
                </>
              ) : (
                <>
                  <Save className="h-4 w-4 mr-2" />
                  Save Prompts
                </>
              )}
            </button>
            <button
              onClick={handleResetPrompts}
              disabled={savingPrompts}
              className="btn btn-secondary inline-flex items-center"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Reset to Defaults
            </button>
          </div>
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

      {/* SCA Vulnerability Feeds Section */}
      <div className="bg-white shadow rounded-lg p-6 mb-6">
        <div className="flex items-center mb-4">
          <Package className="h-6 w-6 text-purple-600 mr-2" />
          <h2 className="text-xl font-semibold text-gray-900">SCA Vulnerability Feeds</h2>
        </div>

        <p className="text-gray-600 mb-4">
          Configure API tokens for live vulnerability feeds. These enable real-time vulnerability lookups for your dependencies from multiple sources.
        </p>

        {/* Feed Status Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {/* GitHub Advisory */}
          <div className="border rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-gray-900">GitHub Advisory</h3>
              {scaFeedsSettings?.has_github_token ? (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Configured
                </span>
              ) : (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                  <AlertCircle className="w-3 h-3 mr-1" />
                  Not Set
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500">GitHub Security Advisory Database</p>
            {scaFeedsSettings?.has_github_token && scaFeedsSettings.github_token_masked && (
              <p className="text-xs text-gray-400 mt-1">Token: {scaFeedsSettings.github_token_masked}</p>
            )}
          </div>

          {/* OSV */}
          <div className="border rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-gray-900">OSV</h3>
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                <CheckCircle className="w-3 h-3 mr-1" />
                Free
              </span>
            </div>
            <p className="text-xs text-gray-500">Open Source Vulnerabilities</p>
            <p className="text-xs text-gray-400 mt-1">No API key required</p>
          </div>

          {/* NVD */}
          <div className="border rounded-lg p-4 border-red-200 bg-red-50">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-gray-900">NVD</h3>
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                <CheckCircle className="w-3 h-3 mr-1" />
                Active
              </span>
            </div>
            <p className="text-xs text-gray-500">NIST National Vulnerability Database</p>
            <p className="text-xs text-gray-400 mt-1">API key optional (set in Threat Intel)</p>
          </div>

          {/* Snyk */}
          <div className="border rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-gray-900">Snyk</h3>
              {scaFeedsSettings?.has_snyk_token ? (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Configured
                </span>
              ) : (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                  <AlertCircle className="w-3 h-3 mr-1" />
                  Not Set
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500">Snyk Vulnerability Database</p>
            {scaFeedsSettings?.has_snyk_token && scaFeedsSettings.snyk_token_masked && (
              <p className="text-xs text-gray-400 mt-1">Token: {scaFeedsSettings.snyk_token_masked}</p>
            )}
          </div>
        </div>

        {/* Test Connection Button */}
        <div className="mb-6">
          <button
            onClick={handleTestScaFeeds}
            disabled={testingScaFeeds}
            className="btn btn-secondary inline-flex items-center"
          >
            {testingScaFeeds ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-indigo-600 mr-2"></div>
                Testing...
              </>
            ) : (
              <>
                <RefreshCw className="h-4 w-4 mr-2" />
                Test All Feeds
              </>
            )}
          </button>
        </div>

        {/* Test Results */}
        {scaFeedsResults && (
          <div className="mb-6 space-y-2">
            {Object.entries(scaFeedsResults).map(([source, result]) => (
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
                  <span className="font-medium text-gray-900">{source}</span>
                </div>
                <span className={result.status === 'success' ? 'text-green-700' : 'text-red-700'}>
                  {result.message}
                </span>
              </div>
            ))}
          </div>
        )}

        {/* API Token Inputs */}
        <div className="space-y-4">
          {/* GitHub Token */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label htmlFor="githubToken" className="block text-sm font-medium text-gray-700">
                GitHub Personal Access Token
              </label>
              {scaFeedsSettings?.has_github_token && (
                <button
                  onClick={() => handleDeleteScaKey('github_token')}
                  className="text-red-600 hover:text-red-800 text-sm flex items-center"
                >
                  <Trash2 className="h-3 w-3 mr-1" />
                  Remove
                </button>
              )}
            </div>
            <input
              type="password"
              id="githubToken"
              value={githubToken}
              onChange={(e) => setGithubToken(e.target.value)}
              placeholder={scaFeedsSettings?.has_github_token ? 'Enter new token to replace...' : 'ghp_xxxxxxxxxxxx'}
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
            />
            <p className="mt-1 text-xs text-gray-500">
              Required for GitHub Advisory Database. Create at{' '}
              <a
                href="https://github.com/settings/tokens"
                target="_blank"
                rel="noopener noreferrer"
                className="text-indigo-600 hover:text-indigo-500"
              >
                GitHub Settings → Developer settings → Personal access tokens
              </a>
              . No special scopes needed for public advisory access.
            </p>
          </div>

          {/* Snyk Token */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label htmlFor="snykToken" className="block text-sm font-medium text-gray-700">
                Snyk API Token
              </label>
              {scaFeedsSettings?.has_snyk_token && (
                <button
                  onClick={() => handleDeleteScaKey('snyk_token')}
                  className="text-red-600 hover:text-red-800 text-sm flex items-center"
                >
                  <Trash2 className="h-3 w-3 mr-1" />
                  Remove
                </button>
              )}
            </div>
            <input
              type="password"
              id="snykToken"
              value={snykToken}
              onChange={(e) => setSnykToken(e.target.value)}
              placeholder={scaFeedsSettings?.has_snyk_token ? 'Enter new token to replace...' : 'Enter Snyk API token...'}
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
            />
            <p className="mt-1 text-xs text-gray-500">
              Get your API token from{' '}
              <a
                href="https://app.snyk.io/account"
                target="_blank"
                rel="noopener noreferrer"
                className="text-indigo-600 hover:text-indigo-500"
              >
                Snyk Account Settings
              </a>
              . Enables Snyk vulnerability database integration.
            </p>
          </div>

          {scaFeedsMessage && (
            <div
              className={`p-4 rounded-md ${
                scaFeedsMessage.type === 'success'
                  ? 'bg-green-50 border border-green-200 text-green-800'
                  : 'bg-red-50 border border-red-200 text-red-800'
              }`}
            >
              <div className="flex items-center">
                {scaFeedsMessage.type === 'success' ? (
                  <CheckCircle className="h-5 w-5 mr-2" />
                ) : (
                  <AlertCircle className="h-5 w-5 mr-2" />
                )}
                <span>{scaFeedsMessage.text}</span>
              </div>
            </div>
          )}

          <button
            onClick={handleSaveScaFeeds}
            disabled={savingScaFeeds || (!githubToken.trim() && !snykToken.trim())}
            className="btn btn-primary inline-flex items-center"
          >
            {savingScaFeeds ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                Saving...
              </>
            ) : (
              <>
                <Save className="h-4 w-4 mr-2" />
                Save SCA Feed Settings
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
              <span>Deep inter-procedural analysis with cross-function taint tracking</span>
            </li>
            <li className="flex items-start">
              <CheckCircle className="h-5 w-5 text-green-600 mr-2 mt-0.5 flex-shrink-0" />
              <span>Interactive taint flow visualization with call chain diagrams</span>
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
              href="/downloads/appsec-ai-scanner-1.8.7.vsix"
              download
              className="btn btn-primary inline-flex items-center"
            >
              <Download className="h-5 w-5 mr-2" />
              Download VS Code Extension
            </a>
            <p className="mt-2 text-sm text-gray-500">Version 1.8.7 • 4.3 MB</p>
          </div>
        </div>

        <div className="mt-6 bg-gradient-to-r from-purple-50 to-blue-50 border border-purple-200 rounded-lg p-4">
          <h4 className="font-semibold text-gray-900 mb-2 flex items-center">
            <span className="bg-purple-600 text-white text-xs px-2 py-1 rounded mr-2">LATEST</span>
            What's New in v1.8.7
          </h4>
          <ul className="list-disc list-inside text-sm text-gray-700 space-y-1">
            <li><strong>🔗 DEEP INTER-PROCEDURAL ANALYSIS:</strong> Cross-function taint tracking that follows data flow across method boundaries</li>
            <li><strong>📊 Call Chain Visualization:</strong> Interactive SVG diagrams showing complete data flow from source to sink</li>
            <li><strong>🔍 Function Summaries:</strong> Detailed analysis of how each function processes and propagates tainted data</li>
            <li><strong>🎯 Enhanced Taint Flow Panel:</strong> Visualize inter-procedural flows with call chain sections</li>
            <li><strong>⚡ New Deep Scan Command:</strong> Dedicated command for comprehensive inter-procedural security analysis</li>
            <li><strong>🛡️ Complete OWASP Top 10 2021 Coverage:</strong> All 10 categories with 100+ security patterns</li>
            <li><strong>💉 SQL Injection Detection:</strong> Catches string concatenation, template literals, f-strings, format()</li>
            <li><strong>🔒 Cryptographic Failures:</strong> MD5, SHA1, weak ciphers, hardcoded secrets, API keys</li>
            <li><strong>📂 ALL File Types Supported:</strong> JS, TS, Python, Java, Go, PHP, C#, Ruby, and more</li>
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
            <li>Use Command Palette (Ctrl+Shift+P) → "SecureDev AI: Configure Server URL" to set your production server</li>
            <li>Use Command Palette (Ctrl+Shift+P) → "SecureDev AI: Test Server Connection" to verify connectivity</li>
            <li>Use Command Palette (Ctrl+Shift+P) → "SecureDev AI: Login to Platform" to authenticate</li>
          </ol>
        </div>

        <div className="mt-4 bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <h4 className="font-semibold text-yellow-900 mb-2 flex items-center">
            <Globe className="h-5 w-5 mr-2" />
            Connecting to Production Server
          </h4>
          <p className="text-sm text-yellow-800 mb-2">
            After deploying SecureDev AI to production, configure the VS Code extension to connect to your server:
          </p>
          <ol className="list-decimal list-inside text-sm text-yellow-800 space-y-1">
            <li>Open Command Palette (Ctrl+Shift+P / Cmd+Shift+P)</li>
            <li>Search for "SecureDev AI: Configure Server URL"</li>
            <li>Choose "Configure Both" to set API and Web Dashboard URLs</li>
            <li>Enter your production server URL (e.g., https://your-domain.com)</li>
            <li>Test the connection, then login with your credentials</li>
          </ol>
        </div>
      </div>

      {/* SecureReq Integrations Section */}
      <div className="bg-white shadow rounded-lg p-6 mb-6">
        <div className="flex items-center mb-4">
          <Link2 className="h-6 w-6 text-indigo-600 mr-2" />
          <h2 className="text-xl font-semibold text-gray-900">SecureReq Integrations</h2>
        </div>

        <p className="text-gray-600 mb-4">
          Connect to Jira, Azure DevOps, or ServiceNow to sync user stories and publish security analysis results.
        </p>

        {/* Integration Status Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className={`border rounded-lg p-4 ${integrationStatus?.jira?.connected ? 'border-green-300 bg-green-50' : 'border-gray-200'}`}>
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-gray-900 flex items-center">
                <Server className="w-4 h-4 mr-2" />
                Jira
              </h3>
              {integrationStatus?.jira?.connected ? (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Connected
                </span>
              ) : integrationStatus?.jira?.configured ? (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                  <AlertCircle className="w-3 h-3 mr-1" />
                  Not Connected
                </span>
              ) : (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                  Not Configured
                </span>
              )}
            </div>
            {integrationStatus?.jira?.url && (
              <p className="text-xs text-gray-500 truncate">{integrationStatus.jira.url}</p>
            )}
          </div>

          <div className={`border rounded-lg p-4 ${integrationStatus?.ado?.connected ? 'border-green-300 bg-green-50' : 'border-gray-200'}`}>
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-gray-900 flex items-center">
                <Cloud className="w-4 h-4 mr-2" />
                Azure DevOps
              </h3>
              {integrationStatus?.ado?.connected ? (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Connected
                </span>
              ) : integrationStatus?.ado?.configured ? (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                  <AlertCircle className="w-3 h-3 mr-1" />
                  Not Connected
                </span>
              ) : (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                  Not Configured
                </span>
              )}
            </div>
            {integrationStatus?.ado?.url && (
              <p className="text-xs text-gray-500 truncate">{integrationStatus.ado.url}</p>
            )}
          </div>

          <div className={`border rounded-lg p-4 ${integrationStatus?.snow?.connected ? 'border-green-300 bg-green-50' : 'border-gray-200'}`}>
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-gray-900 flex items-center">
                <Globe className="w-4 h-4 mr-2" />
                ServiceNow
              </h3>
              {integrationStatus?.snow?.connected ? (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Connected
                </span>
              ) : integrationStatus?.snow?.configured ? (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                  <AlertCircle className="w-3 h-3 mr-1" />
                  Not Connected
                </span>
              ) : (
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                  Not Configured
                </span>
              )}
            </div>
            {integrationStatus?.snow?.url && (
              <p className="text-xs text-gray-500 truncate">{integrationStatus.snow.url}</p>
            )}
          </div>
        </div>

        {/* Integration Tabs */}
        <div className="border-b border-gray-200 mb-4">
          <nav className="-mb-px flex space-x-8">
            <button
              onClick={() => setActiveIntegrationTab('jira')}
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeIntegrationTab === 'jira'
                  ? 'border-indigo-500 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Jira
            </button>
            <button
              onClick={() => setActiveIntegrationTab('ado')}
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeIntegrationTab === 'ado'
                  ? 'border-indigo-500 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Azure DevOps
            </button>
            <button
              onClick={() => setActiveIntegrationTab('snow')}
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeIntegrationTab === 'snow'
                  ? 'border-indigo-500 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              ServiceNow
            </button>
          </nav>
        </div>

        {/* Jira Tab */}
        {activeIntegrationTab === 'jira' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Jira URL</label>
                <input
                  type="text"
                  value={jiraUrl}
                  onChange={(e) => setJiraUrl(e.target.value)}
                  placeholder="https://your-domain.atlassian.net"
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                <input
                  type="email"
                  value={jiraEmail}
                  onChange={(e) => setJiraEmail(e.target.value)}
                  placeholder="your-email@company.com"
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">API Token</label>
              <input
                type="password"
                value={jiraToken}
                onChange={(e) => setJiraToken(e.target.value)}
                placeholder="Enter Jira API token..."
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
              />
              <p className="mt-1 text-xs text-gray-500">
                Create at <a href="https://id.atlassian.com/manage/api-tokens" target="_blank" rel="noopener noreferrer" className="text-indigo-600 hover:text-indigo-500">Atlassian API Tokens</a>
              </p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Abuse Cases Field (Optional)</label>
                <input
                  type="text"
                  value={jiraAbuseCasesField}
                  onChange={(e) => setJiraAbuseCasesField(e.target.value)}
                  placeholder="customfield_10001 or field name"
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Security Requirements Field (Optional)</label>
                <input
                  type="text"
                  value={jiraSecurityReqField}
                  onChange={(e) => setJiraSecurityReqField(e.target.value)}
                  placeholder="customfield_10002 or field name"
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
                />
              </div>
            </div>
            {jiraMessage && (
              <div className={`p-3 rounded-md ${jiraMessage.type === 'success' ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800'}`}>
                {jiraMessage.text}
              </div>
            )}
            <div className="flex space-x-3">
              <button onClick={handleSaveJira} disabled={savingJira} className="btn btn-primary inline-flex items-center">
                {savingJira ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <Save className="w-4 h-4 mr-2" />}
                Save Jira Settings
              </button>
              <button onClick={handleTestJira} disabled={testingJira} className="btn btn-secondary inline-flex items-center">
                {testingJira ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <RefreshCw className="w-4 h-4 mr-2" />}
                Test Connection
              </button>
            </div>
          </div>
        )}

        {/* ADO Tab */}
        {activeIntegrationTab === 'ado' && (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Organization URL</label>
              <input
                type="text"
                value={adoOrgUrl}
                onChange={(e) => setAdoOrgUrl(e.target.value)}
                placeholder="https://dev.azure.com/your-org"
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Personal Access Token (PAT)</label>
              <input
                type="password"
                value={adoPat}
                onChange={(e) => setAdoPat(e.target.value)}
                placeholder="Enter Azure DevOps PAT..."
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
              />
              <p className="mt-1 text-xs text-gray-500">
                Create at Azure DevOps → User Settings → Personal Access Tokens (needs Work Items Read & Write scope)
              </p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Abuse Cases Field (Optional)</label>
                <input
                  type="text"
                  value={adoAbuseCasesField}
                  onChange={(e) => setAdoAbuseCasesField(e.target.value)}
                  placeholder="Custom.AbuseCases"
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Security Requirements Field (Optional)</label>
                <input
                  type="text"
                  value={adoSecurityReqField}
                  onChange={(e) => setAdoSecurityReqField(e.target.value)}
                  placeholder="Custom.SecurityRequirements"
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
                />
              </div>
            </div>
            {adoMessage && (
              <div className={`p-3 rounded-md ${adoMessage.type === 'success' ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800'}`}>
                {adoMessage.text}
              </div>
            )}
            <div className="flex space-x-3">
              <button onClick={handleSaveAdo} disabled={savingAdo} className="btn btn-primary inline-flex items-center">
                {savingAdo ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <Save className="w-4 h-4 mr-2" />}
                Save ADO Settings
              </button>
              <button onClick={handleTestAdo} disabled={testingAdo} className="btn btn-secondary inline-flex items-center">
                {testingAdo ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <RefreshCw className="w-4 h-4 mr-2" />}
                Test Connection
              </button>
            </div>
          </div>
        )}

        {/* SNOW Tab */}
        {activeIntegrationTab === 'snow' && (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Instance URL</label>
              <input
                type="text"
                value={snowUrl}
                onChange={(e) => setSnowUrl(e.target.value)}
                placeholder="https://your-instance.service-now.com"
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
              />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
                <input
                  type="text"
                  value={snowUsername}
                  onChange={(e) => setSnowUsername(e.target.value)}
                  placeholder="admin"
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                <input
                  type="password"
                  value={snowPassword}
                  onChange={(e) => setSnowPassword(e.target.value)}
                  placeholder="Enter password..."
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
                />
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Abuse Cases Field (Optional)</label>
                <input
                  type="text"
                  value={snowAbuseCasesField}
                  onChange={(e) => setSnowAbuseCasesField(e.target.value)}
                  placeholder="u_abuse_cases"
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Security Requirements Field (Optional)</label>
                <input
                  type="text"
                  value={snowSecurityReqField}
                  onChange={(e) => setSnowSecurityReqField(e.target.value)}
                  placeholder="u_security_requirements"
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500"
                />
              </div>
            </div>
            {snowMessage && (
              <div className={`p-3 rounded-md ${snowMessage.type === 'success' ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800'}`}>
                {snowMessage.text}
              </div>
            )}
            <div className="flex space-x-3">
              <button onClick={handleSaveSnow} disabled={savingSnow} className="btn btn-primary inline-flex items-center">
                {savingSnow ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <Save className="w-4 h-4 mr-2" />}
                Save SNOW Settings
              </button>
              <button onClick={handleTestSnow} disabled={testingSnow} className="btn btn-secondary inline-flex items-center">
                {testingSnow ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <RefreshCw className="w-4 h-4 mr-2" />}
                Test Connection
              </button>
            </div>
          </div>
        )}
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
