import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  Shield, Plus, Play, ArrowLeft, FileText, AlertTriangle,
  CheckCircle, Trash2, ChevronDown, ChevronUp,
  Target, Lock, RefreshCw, ExternalLink, Download, Upload, Cloud
} from 'lucide-react'
import axios from 'axios'

interface UserStory {
  id: number
  project_id: number
  title: string
  description: string
  acceptance_criteria: string | null
  source: string
  external_id: string | null
  external_url: string | null
  is_analyzed: boolean
  risk_score: number
  threat_count: number
  requirement_count: number
  created_at: string
  updated_at: string | null
}

interface ProjectSummary {
  project_id: number
  project_name: string
  total_stories: number
  analyzed_stories: number
  total_threats: number
  total_requirements: number
  average_risk_score: number
  high_risk_stories: number
}

interface Project {
  id: number
  name: string
}

export default function SecurityRequirementsPage() {
  const { id } = useParams<{ id: string }>()
  const [stories, setStories] = useState<UserStory[]>([])
  const [summary, setSummary] = useState<ProjectSummary | null>(null)
  const [_project, setProject] = useState<Project | null>(null)
  const [loading, setLoading] = useState(true)
  const [showAddModal, setShowAddModal] = useState(false)
  const [analyzingAll, setAnalyzingAll] = useState(false)
  const [analyzingStory, setAnalyzingStory] = useState<number | null>(null)
  const [showSyncModal, setShowSyncModal] = useState(false)
  const [syncSource, setSyncSource] = useState<'jira' | 'ado' | 'snow'>('jira')
  const [syncProjectId, setSyncProjectId] = useState('')
  const [syncing, setSyncing] = useState(false)
  const [syncMessage, setSyncMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [integrationStatus, setIntegrationStatus] = useState<{
    jira: { configured: boolean; connected: boolean }
    ado: { configured: boolean; connected: boolean }
    snow: { configured: boolean; connected: boolean }
  } | null>(null)

  // Form state
  const [newStory, setNewStory] = useState({
    title: '',
    description: '',
    acceptance_criteria: ''
  })

  useEffect(() => {
    fetchData()
    fetchIntegrationStatus()
  }, [id])

  const fetchIntegrationStatus = async () => {
    try {
      const token = localStorage.getItem('token')
      const response = await axios.get('/api/integrations/status', {
        headers: { Authorization: `Bearer ${token}` }
      })
      setIntegrationStatus(response.data)
    } catch (error) {
      console.error('Failed to fetch integration status:', error)
    }
  }

  const handleSync = async () => {
    if (!syncProjectId.trim()) {
      setSyncMessage({ type: 'error', text: 'Please enter a project ID' })
      return
    }

    setSyncing(true)
    setSyncMessage(null)

    try {
      const token = localStorage.getItem('token')
      const response = await axios.post(`/api/securereq/projects/${id}/sync/${syncSource}`, {
        external_project_id: syncProjectId,
        max_results: 100
      }, {
        headers: { Authorization: `Bearer ${token}` }
      })

      setSyncMessage({ type: 'success', text: response.data.message })
      fetchData()
      setTimeout(() => {
        setShowSyncModal(false)
        setSyncMessage(null)
      }, 2000)
    } catch (error: any) {
      setSyncMessage({ type: 'error', text: error.response?.data?.detail || 'Sync failed' })
    } finally {
      setSyncing(false)
    }
  }

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('token')
      const headers = { Authorization: `Bearer ${token}` }

      const [projectRes, storiesRes, summaryRes] = await Promise.all([
        axios.get(`/api/projects/${id}`, { headers }),
        axios.get(`/api/securereq/projects/${id}/stories`, { headers }),
        axios.get(`/api/securereq/projects/${id}/summary`, { headers }).catch(() => null)
      ])

      setProject(projectRes.data)
      setStories(storiesRes.data)
      if (summaryRes) setSummary(summaryRes.data)
    } catch (error) {
      console.error('Failed to fetch data:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleAddStory = async () => {
    if (!newStory.title || !newStory.description) return

    try {
      const token = localStorage.getItem('token')
      await axios.post(`/api/securereq/projects/${id}/stories`, newStory, {
        headers: { Authorization: `Bearer ${token}` }
      })

      setNewStory({ title: '', description: '', acceptance_criteria: '' })
      setShowAddModal(false)
      fetchData()
    } catch (error) {
      console.error('Failed to add story:', error)
    }
  }

  const handleAnalyzeStory = async (storyId: number) => {
    setAnalyzingStory(storyId)
    try {
      const token = localStorage.getItem('token')
      await axios.post(`/api/securereq/stories/${storyId}/analyze`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      })
      fetchData()
    } catch (error) {
      console.error('Failed to analyze story:', error)
    } finally {
      setAnalyzingStory(null)
    }
  }

  const handleAnalyzeAll = async () => {
    setAnalyzingAll(true)
    try {
      const token = localStorage.getItem('token')
      await axios.post(`/api/securereq/projects/${id}/analyze-all`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      })
      fetchData()
    } catch (error) {
      console.error('Failed to analyze all:', error)
    } finally {
      setAnalyzingAll(false)
    }
  }

  const handleDeleteStory = async (storyId: number) => {
    if (!confirm('Are you sure you want to delete this story?')) return

    try {
      const token = localStorage.getItem('token')
      await axios.delete(`/api/securereq/stories/${storyId}`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      fetchData()
    } catch (error) {
      console.error('Failed to delete story:', error)
    }
  }

  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-red-600 bg-red-100'
    if (score >= 40) return 'text-amber-600 bg-amber-100'
    return 'text-green-600 bg-green-100'
  }

  const getRiskLabel = (score: number) => {
    if (score >= 70) return 'High Risk'
    if (score >= 40) return 'Medium Risk'
    return 'Low Risk'
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Link
            to={`/projects/${id}`}
            className="inline-flex items-center text-sm text-gray-600 hover:text-gray-900 mb-2"
          >
            <ArrowLeft className="w-4 h-4 mr-1" />
            Back to Project
          </Link>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center">
            <Shield className="w-7 h-7 mr-2 text-indigo-600" />
            Security Requirements
          </h1>
          <p className="text-gray-600 mt-1">
            Analyze user stories for security threats and generate requirements
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setShowSyncModal(true)}
            className="btn btn-secondary inline-flex items-center"
            title="Sync stories from Jira/ADO/SNOW"
          >
            <Download className="w-4 h-4 mr-2" />
            Sync Stories
          </button>
          <button
            onClick={handleAnalyzeAll}
            disabled={analyzingAll || stories.filter(s => !s.is_analyzed).length === 0}
            className="btn btn-secondary inline-flex items-center"
          >
            {analyzingAll ? (
              <>
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Play className="w-4 h-4 mr-2" />
                Analyze All
              </>
            )}
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="btn btn-primary inline-flex items-center"
          >
            <Plus className="w-4 h-4 mr-2" />
            Add Story
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="card p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Total Stories</p>
                <p className="text-2xl font-bold text-gray-900">{summary.total_stories}</p>
                <p className="text-xs text-gray-500">{summary.analyzed_stories} analyzed</p>
              </div>
              <FileText className="w-8 h-8 text-indigo-500" />
            </div>
          </div>

          <div className="card p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Total Threats</p>
                <p className="text-2xl font-bold text-red-600">{summary.total_threats}</p>
                <p className="text-xs text-gray-500">STRIDE identified</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
          </div>

          <div className="card p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Requirements</p>
                <p className="text-2xl font-bold text-green-600">{summary.total_requirements}</p>
                <p className="text-xs text-gray-500">Security controls</p>
              </div>
              <CheckCircle className="w-8 h-8 text-green-500" />
            </div>
          </div>

          <div className="card p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Avg Risk Score</p>
                <p className={`text-2xl font-bold ${summary.average_risk_score >= 70 ? 'text-red-600' : summary.average_risk_score >= 40 ? 'text-amber-600' : 'text-green-600'}`}>
                  {summary.average_risk_score}
                </p>
                <p className="text-xs text-gray-500">{summary.high_risk_stories} high risk</p>
              </div>
              <Target className="w-8 h-8 text-amber-500" />
            </div>
          </div>
        </div>
      )}

      {/* Stories List */}
      <div className="card">
        <div className="p-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">User Stories</h2>
        </div>

        {stories.length === 0 ? (
          <div className="p-8 text-center">
            <FileText className="w-12 h-12 text-gray-300 mx-auto mb-3" />
            <p className="text-gray-500">No user stories yet</p>
            <p className="text-sm text-gray-400 mt-1">Add your first story to begin security analysis</p>
            <button
              onClick={() => setShowAddModal(true)}
              className="btn btn-primary mt-4 inline-flex items-center"
            >
              <Plus className="w-4 h-4 mr-2" />
              Add Story
            </button>
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {stories.map((story) => (
              <StoryCard
                key={story.id}
                story={story}
                projectId={id!}
                onAnalyze={() => handleAnalyzeStory(story.id)}
                onDelete={() => handleDeleteStory(story.id)}
                isAnalyzing={analyzingStory === story.id}
                getRiskColor={getRiskColor}
                getRiskLabel={getRiskLabel}
              />
            ))}
          </div>
        )}
      </div>

      {/* Add Story Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-lg mx-4">
            <div className="p-6 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">Add User Story</h3>
              <p className="text-sm text-gray-500 mt-1">Enter the details of your user story for security analysis</p>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Title <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={newStory.title}
                  onChange={(e) => setNewStory({ ...newStory, title: e.target.value })}
                  placeholder="As a user, I want to..."
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Description <span className="text-red-500">*</span>
                </label>
                <textarea
                  value={newStory.description}
                  onChange={(e) => setNewStory({ ...newStory, description: e.target.value })}
                  placeholder="Detailed description of the feature..."
                  rows={4}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Acceptance Criteria
                </label>
                <textarea
                  value={newStory.acceptance_criteria}
                  onChange={(e) => setNewStory({ ...newStory, acceptance_criteria: e.target.value })}
                  placeholder="Given... When... Then..."
                  rows={3}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                />
              </div>
            </div>

            <div className="p-6 border-t border-gray-200 flex justify-end space-x-3">
              <button
                onClick={() => setShowAddModal(false)}
                className="btn btn-secondary"
              >
                Cancel
              </button>
              <button
                onClick={handleAddStory}
                disabled={!newStory.title || !newStory.description}
                className="btn btn-primary"
              >
                Add Story
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Sync Stories Modal */}
      {showSyncModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-lg mx-4">
            <div className="p-6 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                <Download className="w-5 h-5 mr-2 text-indigo-600" />
                Sync Stories from External System
              </h3>
              <p className="text-sm text-gray-500 mt-1">
                Import user stories from Jira, Azure DevOps, or ServiceNow
              </p>
            </div>

            <div className="p-6 space-y-4">
              {/* Source Selection */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Source</label>
                <div className="grid grid-cols-3 gap-3">
                  <button
                    onClick={() => setSyncSource('jira')}
                    disabled={!integrationStatus?.jira?.connected}
                    className={`p-3 border rounded-lg text-center transition ${
                      syncSource === 'jira'
                        ? 'border-indigo-500 bg-indigo-50 text-indigo-700'
                        : integrationStatus?.jira?.connected
                        ? 'border-gray-200 hover:border-gray-300'
                        : 'border-gray-200 bg-gray-50 text-gray-400 cursor-not-allowed'
                    }`}
                  >
                    <Cloud className="w-6 h-6 mx-auto mb-1" />
                    <span className="text-sm font-medium">Jira</span>
                    {!integrationStatus?.jira?.connected && (
                      <p className="text-xs text-gray-400 mt-1">Not connected</p>
                    )}
                  </button>
                  <button
                    onClick={() => setSyncSource('ado')}
                    disabled={!integrationStatus?.ado?.connected}
                    className={`p-3 border rounded-lg text-center transition ${
                      syncSource === 'ado'
                        ? 'border-indigo-500 bg-indigo-50 text-indigo-700'
                        : integrationStatus?.ado?.connected
                        ? 'border-gray-200 hover:border-gray-300'
                        : 'border-gray-200 bg-gray-50 text-gray-400 cursor-not-allowed'
                    }`}
                  >
                    <Cloud className="w-6 h-6 mx-auto mb-1" />
                    <span className="text-sm font-medium">Azure DevOps</span>
                    {!integrationStatus?.ado?.connected && (
                      <p className="text-xs text-gray-400 mt-1">Not connected</p>
                    )}
                  </button>
                  <button
                    onClick={() => setSyncSource('snow')}
                    disabled={!integrationStatus?.snow?.connected}
                    className={`p-3 border rounded-lg text-center transition ${
                      syncSource === 'snow'
                        ? 'border-indigo-500 bg-indigo-50 text-indigo-700'
                        : integrationStatus?.snow?.connected
                        ? 'border-gray-200 hover:border-gray-300'
                        : 'border-gray-200 bg-gray-50 text-gray-400 cursor-not-allowed'
                    }`}
                  >
                    <Cloud className="w-6 h-6 mx-auto mb-1" />
                    <span className="text-sm font-medium">ServiceNow</span>
                    {!integrationStatus?.snow?.connected && (
                      <p className="text-xs text-gray-400 mt-1">Not connected</p>
                    )}
                  </button>
                </div>
              </div>

              {/* Project ID Input */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  {syncSource === 'jira' ? 'Jira Project Key/ID' :
                   syncSource === 'ado' ? 'Azure DevOps Project Name' :
                   'ServiceNow Product/Group ID'}
                </label>
                <input
                  type="text"
                  value={syncProjectId}
                  onChange={(e) => setSyncProjectId(e.target.value)}
                  placeholder={
                    syncSource === 'jira' ? 'e.g., PROJ or 10001' :
                    syncSource === 'ado' ? 'e.g., MyProject' :
                    'e.g., product_sys_id'
                  }
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                />
                <p className="mt-1 text-xs text-gray-500">
                  {syncSource === 'jira' ? 'Enter the Jira project key (e.g., PROJ) or numeric project ID' :
                   syncSource === 'ado' ? 'Enter the Azure DevOps project name' :
                   'Enter the ServiceNow product sys_id or assignment group'}
                </p>
              </div>

              {syncMessage && (
                <div className={`p-3 rounded-md ${
                  syncMessage.type === 'success' ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800'
                }`}>
                  {syncMessage.text}
                </div>
              )}

              {!integrationStatus?.jira?.connected && !integrationStatus?.ado?.connected && !integrationStatus?.snow?.connected && (
                <div className="p-3 rounded-md bg-yellow-50 text-yellow-800">
                  No integrations configured. Go to <a href="/settings" className="underline font-medium">Settings</a> to configure Jira, Azure DevOps, or ServiceNow.
                </div>
              )}
            </div>

            <div className="p-6 border-t border-gray-200 flex justify-end space-x-3">
              <button
                onClick={() => {
                  setShowSyncModal(false)
                  setSyncMessage(null)
                }}
                className="btn btn-secondary"
              >
                Cancel
              </button>
              <button
                onClick={handleSync}
                disabled={syncing || !syncProjectId.trim() || (
                  syncSource === 'jira' && !integrationStatus?.jira?.connected ||
                  syncSource === 'ado' && !integrationStatus?.ado?.connected ||
                  syncSource === 'snow' && !integrationStatus?.snow?.connected
                )}
                className="btn btn-primary inline-flex items-center"
              >
                {syncing ? (
                  <>
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                    Syncing...
                  </>
                ) : (
                  <>
                    <Download className="w-4 h-4 mr-2" />
                    Sync Stories
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// Story Card Component
function StoryCard({
  story,
  projectId,
  onAnalyze,
  onDelete,
  isAnalyzing,
  getRiskColor,
  getRiskLabel
}: {
  story: UserStory
  projectId: string
  onAnalyze: () => void
  onDelete: () => void
  isAnalyzing: boolean
  getRiskColor: (score: number) => string
  getRiskLabel: (score: number) => string
}) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="p-4 hover:bg-gray-50 transition">
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <div className="flex items-center space-x-3">
            <h3 className="text-sm font-semibold text-gray-900 truncate">
              {story.title}
            </h3>
            {story.is_analyzed ? (
              <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getRiskColor(story.risk_score)}`}>
                {getRiskLabel(story.risk_score)} ({story.risk_score})
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                Not Analyzed
              </span>
            )}
            {story.source !== 'manual' && (
              <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-700">
                {story.source.toUpperCase()}
              </span>
            )}
          </div>

          <p className="text-sm text-gray-600 mt-1 line-clamp-2">{story.description}</p>

          {story.is_analyzed && (
            <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500">
              <span className="flex items-center">
                <AlertTriangle className="w-3 h-3 mr-1 text-red-500" />
                {story.threat_count} threats
              </span>
              <span className="flex items-center">
                <Lock className="w-3 h-3 mr-1 text-green-500" />
                {story.requirement_count} requirements
              </span>
            </div>
          )}
        </div>

        <div className="flex items-center space-x-2 ml-4">
          {story.is_analyzed ? (
            <Link
              to={`/projects/${projectId}/stories/${story.id}`}
              className="btn btn-secondary text-sm py-1 px-3"
            >
              View Analysis
            </Link>
          ) : (
            <button
              onClick={onAnalyze}
              disabled={isAnalyzing}
              className="btn btn-primary text-sm py-1 px-3 inline-flex items-center"
            >
              {isAnalyzing ? (
                <>
                  <RefreshCw className="w-3 h-3 mr-1 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Play className="w-3 h-3 mr-1" />
                  Analyze
                </>
              )}
            </button>
          )}

          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1 text-gray-400 hover:text-gray-600"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          <button
            onClick={onDelete}
            className="p-1 text-gray-400 hover:text-red-600"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {expanded && (
        <div className="mt-4 pt-4 border-t border-gray-100">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="text-xs font-semibold text-gray-500 uppercase mb-2">Description</h4>
              <p className="text-sm text-gray-700">{story.description}</p>
            </div>
            {story.acceptance_criteria && (
              <div>
                <h4 className="text-xs font-semibold text-gray-500 uppercase mb-2">Acceptance Criteria</h4>
                <p className="text-sm text-gray-700 whitespace-pre-wrap">{story.acceptance_criteria}</p>
              </div>
            )}
          </div>
          {story.external_url && (
            <a
              href={story.external_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center text-sm text-indigo-600 hover:text-indigo-700 mt-3"
            >
              <ExternalLink className="w-3 h-3 mr-1" />
              View in {story.source}
            </a>
          )}
        </div>
      )}
    </div>
  )
}
