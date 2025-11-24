import { useState, useEffect } from 'react'
import { Save, Key, AlertCircle, CheckCircle } from 'lucide-react'
import axios from 'axios'

interface Settings {
  openai_api_key: string
  has_openai_key: boolean
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [apiKey, setApiKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

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

      {/* Information Section */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-blue-900 mb-2">About API Keys</h3>
        <ul className="list-disc list-inside text-blue-800 space-y-1 text-sm">
          <li>Your API key is stored securely in the backend environment</li>
          <li>The chatbot uses the gpt-4o-mini model for cost-effective responses</li>
          <li>Make sure your OpenAI account has sufficient credits</li>
          <li>You can update the API key anytime if you need to change it</li>
        </ul>
      </div>
    </div>
  )
}
