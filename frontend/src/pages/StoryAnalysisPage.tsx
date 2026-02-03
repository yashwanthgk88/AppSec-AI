import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  Shield, ArrowLeft, AlertTriangle, CheckCircle, Target,
  RefreshCw, Clock, FileText, Upload,
  Lock, Zap, Eye, EyeOff, User, Database, Server
} from 'lucide-react'
import axios from 'axios'

interface UserStory {
  id: number
  project_id: number
  title: string
  description: string
  acceptance_criteria: string | null
  risk_score: number
  threat_count: number
  requirement_count: number
  external_id: string | null
  source: string | null
}

interface AbuseCase {
  id: string
  title: string
  description: string
  threat_actor: string
  impact: string
  likelihood: string
  mitigations?: string[]
}

// Helper function to format text as bullet points
const formatAsBulletPoints = (text: string): string[] => {
  if (!text) return []

  // First, normalize the text - replace escaped newlines with actual newlines
  let normalizedText = text
    .replace(/\\n/g, '\n')  // Convert escaped \n to actual newlines
    .replace(/\\r/g, '')    // Remove escaped \r
    .replace(/\n{3,}/g, '\n\n')  // Normalize multiple newlines

  // Split by various delimiters
  const lines = normalizedText
    .split(/[\n\r]+/)  // Split by newlines first
    .flatMap(line => {
      // Then split by bullet points and numbered items
      return line.split(/(?:^|\s)(?:•|●|◦|▪|‣|\*|-|–|—)\s*|(?:^\d+[\.\)]\s*)/gm)
    })
    .map(line => line.trim())
    .filter(line => line.length > 0 && line !== '•' && line !== '-')

  // If still just one line with multiple sentences, split by sentences
  if (lines.length <= 1 && normalizedText.length > 100 && normalizedText.includes('.')) {
    const sentences = normalizedText
      .split(/(?<=[.!?])\s+(?=[A-Z])/)
      .map(s => s.trim())
      .filter(s => s.length > 10)  // Filter very short fragments

    if (sentences.length > 1) {
      return sentences
    }
  }

  // If we have good content but formatting stripped it to one line, try markdown headers
  if (lines.length === 1 && lines[0].includes(':')) {
    const parts = lines[0].split(/(?=[A-Z][a-z]+:)/)
    if (parts.length > 1) {
      return parts.map(p => p.trim()).filter(p => p.length > 0)
    }
  }

  return lines.length > 0 ? lines : [text]
}

interface StrideThreat {
  id: string
  threat: string
  mitigation: string
}

interface SecurityRequirement {
  id: string
  category: string
  requirement: string
  priority: string
  rationale: string
  acceptance_criteria: string
}

interface RiskFactor {
  factor: string
  score: number
  description: string
}

interface Analysis {
  id: number
  user_story_id: number
  version: number
  abuse_cases: AbuseCase[]
  stride_threats: Record<string, StrideThreat[]>
  security_requirements: SecurityRequirement[]
  risk_score: number
  risk_factors: RiskFactor[]
  ai_model_used: string | null
  analysis_duration_ms: number | null
  created_at: string
}

interface ComplianceMapping {
  id: number
  requirement_id: string
  requirement_text: string
  standard_name: string
  control_id: string
  control_title: string
  relevance_score: number
}

const STRIDE_INFO: Record<string, { name: string; icon: any; color: string; description: string }> = {
  S: { name: 'Spoofing', icon: User, color: 'bg-purple-100 text-purple-700 border-purple-300', description: 'Identity theft' },
  T: { name: 'Tampering', icon: Database, color: 'bg-orange-100 text-orange-700 border-orange-300', description: 'Data modification' },
  R: { name: 'Repudiation', icon: EyeOff, color: 'bg-gray-100 text-gray-700 border-gray-300', description: 'Deny actions' },
  I: { name: 'Info Disclosure', icon: Eye, color: 'bg-blue-100 text-blue-700 border-blue-300', description: 'Data exposure' },
  D: { name: 'Denial of Service', icon: Server, color: 'bg-red-100 text-red-700 border-red-300', description: 'Service disruption' },
  E: { name: 'Elevation', icon: Zap, color: 'bg-yellow-100 text-yellow-700 border-yellow-300', description: 'Privilege escalation' },
}

export default function StoryAnalysisPage() {
  const { id, storyId } = useParams<{ id: string; storyId: string }>()
  const [story, setStory] = useState<UserStory | null>(null)
  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const [compliance, setCompliance] = useState<ComplianceMapping[]>([])
  const [loading, setLoading] = useState(true)
  const [reanalyzing, setReanalyzing] = useState(false)
  const [publishing, setPublishing] = useState(false)
  const [publishMessage, setPublishMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [activeTab, setActiveTab] = useState<'threats' | 'requirements' | 'compliance'>('threats')

  useEffect(() => {
    fetchData()
  }, [storyId])

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('token')
      const headers = { Authorization: `Bearer ${token}` }

      // Fetch story
      const storyRes = await axios.get(`/api/securereq/stories/${storyId}`, { headers })
      setStory(storyRes.data)

      // Fetch analyses
      const analysesRes = await axios.get(`/api/securereq/stories/${storyId}/analyses`, { headers })
      if (analysesRes.data.length > 0) {
        const latestAnalysis = analysesRes.data[0]
        setAnalysis(latestAnalysis)

        // Fetch compliance mappings
        const complianceRes = await axios.get(`/api/securereq/analyses/${latestAnalysis.id}/compliance`, { headers })
        setCompliance(complianceRes.data)
      }
    } catch (error) {
      console.error('Failed to fetch data:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleReanalyze = async () => {
    setReanalyzing(true)
    try {
      const token = localStorage.getItem('token')
      await axios.post(`/api/securereq/stories/${storyId}/analyze`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      })
      fetchData()
    } catch (error) {
      console.error('Failed to reanalyze:', error)
    } finally {
      setReanalyzing(false)
    }
  }

  const handlePublish = async () => {
    if (!story) return
    setPublishing(true)
    setPublishMessage(null)
    try {
      const token = localStorage.getItem('token')
      await axios.post(`/api/securereq/stories/${storyId}/publish`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      })
      setPublishMessage({ type: 'success', text: 'Analysis published to external system successfully!' })
    } catch (error: any) {
      const message = error.response?.data?.detail || 'Failed to publish analysis'
      setPublishMessage({ type: 'error', text: message })
    } finally {
      setPublishing(false)
    }
  }

  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-red-600'
    if (score >= 40) return 'text-amber-600'
    return 'text-green-600'
  }

  const getImpactColor = (impact: string) => {
    switch (impact.toLowerCase()) {
      case 'high': return 'bg-red-100 text-red-700'
      case 'medium': return 'bg-amber-100 text-amber-700'
      case 'low': return 'bg-green-100 text-green-700'
      default: return 'bg-gray-100 text-gray-700'
    }
  }

  const getPriorityColor = (priority: string) => {
    switch (priority.toLowerCase()) {
      case 'must': return 'bg-red-100 text-red-700 border-red-300'
      case 'should': return 'bg-amber-100 text-amber-700 border-amber-300'
      case 'could': return 'bg-blue-100 text-blue-700 border-blue-300'
      default: return 'bg-gray-100 text-gray-700 border-gray-300'
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
      </div>
    )
  }

  if (!story) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">Story not found</p>
      </div>
    )
  }

  const totalThreats = analysis ? Object.values(analysis.stride_threats).flat().length : 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Link
            to={`/projects/${id}/security-requirements`}
            className="inline-flex items-center text-sm text-gray-600 hover:text-gray-900 mb-2"
          >
            <ArrowLeft className="w-4 h-4 mr-1" />
            Back to Stories
          </Link>
          <h1 className="text-2xl font-bold text-gray-900">{story.title}</h1>
          <p className="text-gray-600 mt-1">{story.description}</p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={handlePublish}
            disabled={publishing || !story?.external_id}
            className="btn btn-primary inline-flex items-center"
            title={!story?.external_id ? 'Story not synced from external system' : 'Publish analysis to external system'}
          >
            {publishing ? (
              <>
                <Upload className="w-4 h-4 mr-2 animate-pulse" />
                Publishing...
              </>
            ) : (
              <>
                <Upload className="w-4 h-4 mr-2" />
                Publish
              </>
            )}
          </button>
          <button
            onClick={handleReanalyze}
            disabled={reanalyzing}
            className="btn btn-secondary inline-flex items-center"
          >
            {reanalyzing ? (
              <>
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                Reanalyzing...
              </>
            ) : (
              <>
                <RefreshCw className="w-4 h-4 mr-2" />
                Reanalyze
              </>
            )}
          </button>
        </div>
      </div>

      {/* Publish Message */}
      {publishMessage && (
        <div className={`p-4 rounded-lg ${
          publishMessage.type === 'success'
            ? 'bg-green-50 border border-green-200 text-green-800'
            : 'bg-red-50 border border-red-200 text-red-800'
        }`}>
          <div className="flex items-center justify-between">
            <span>{publishMessage.text}</span>
            <button
              onClick={() => setPublishMessage(null)}
              className="text-gray-500 hover:text-gray-700"
            >
              ×
            </button>
          </div>
        </div>
      )}

      {/* Summary Cards */}
      {analysis && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="card p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Risk Score</p>
                <p className={`text-3xl font-bold ${getRiskColor(analysis.risk_score)}`}>
                  {analysis.risk_score}
                </p>
              </div>
              <Target className={`w-10 h-10 ${getRiskColor(analysis.risk_score)}`} />
            </div>
          </div>

          <div className="card p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Abuse Cases</p>
                <p className="text-3xl font-bold text-purple-600">{analysis.abuse_cases.length}</p>
              </div>
              <AlertTriangle className="w-10 h-10 text-purple-500" />
            </div>
          </div>

          <div className="card p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">STRIDE Threats</p>
                <p className="text-3xl font-bold text-red-600">{totalThreats}</p>
              </div>
              <Shield className="w-10 h-10 text-red-500" />
            </div>
          </div>

          <div className="card p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Requirements</p>
                <p className="text-3xl font-bold text-green-600">{analysis.security_requirements.length}</p>
              </div>
              <CheckCircle className="w-10 h-10 text-green-500" />
            </div>
          </div>
        </div>
      )}

      {/* Analysis metadata */}
      {analysis && (
        <div className="card p-4">
          <div className="flex items-center justify-between text-sm text-gray-500">
            <div className="flex items-center space-x-4">
              <span className="flex items-center">
                <Clock className="w-4 h-4 mr-1" />
                Version {analysis.version}
              </span>
              {analysis.ai_model_used && (
                <span className="px-2 py-0.5 bg-indigo-100 text-indigo-700 rounded-full text-xs">
                  {analysis.ai_model_used}
                </span>
              )}
              {analysis.analysis_duration_ms && (
                <span>Analyzed in {analysis.analysis_duration_ms}ms</span>
              )}
            </div>
            <span>
              {new Date(analysis.created_at).toLocaleString()}
            </span>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex space-x-8">
          {[
            { key: 'threats', label: 'Threats & Abuse Cases', count: totalThreats + (analysis?.abuse_cases.length || 0) },
            { key: 'requirements', label: 'Security Requirements', count: analysis?.security_requirements.length || 0 },
            { key: 'compliance', label: 'Compliance Mapping', count: compliance.length },
          ].map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key as any)}
              className={`pb-4 px-1 border-b-2 font-medium text-sm transition ${
                activeTab === tab.key
                  ? 'border-indigo-600 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              {tab.label}
              <span className={`ml-2 px-2 py-0.5 rounded-full text-xs ${
                activeTab === tab.key ? 'bg-indigo-100 text-indigo-600' : 'bg-gray-100 text-gray-600'
              }`}>
                {tab.count}
              </span>
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {analysis && activeTab === 'threats' && (
        <div className="space-y-6">
          {/* Abuse Cases */}
          <div className="card">
            <div className="p-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                <AlertTriangle className="w-5 h-5 mr-2 text-purple-600" />
                Abuse Cases
              </h3>
            </div>
            <div className="divide-y divide-gray-100">
              {analysis.abuse_cases.map((abuse) => (
                <div key={abuse.id} className="p-4 hover:bg-gray-50">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2 mb-2">
                        <span className="text-xs font-mono bg-purple-100 text-purple-700 px-2 py-0.5 rounded">{abuse.id}</span>
                        <h4 className="font-semibold text-gray-900">{abuse.title}</h4>
                      </div>

                      {/* Description as bullet points */}
                      <div className="mt-2 mb-3">
                        <h5 className="text-sm font-medium text-gray-700 mb-1">Attack Description:</h5>
                        <ul className="list-disc list-inside text-sm text-gray-600 space-y-1 ml-2">
                          {formatAsBulletPoints(abuse.description).map((point, idx) => (
                            <li key={idx}>{point}</li>
                          ))}
                        </ul>
                      </div>

                      {/* Mitigations if available */}
                      {abuse.mitigations && abuse.mitigations.length > 0 && (
                        <div className="mt-3 mb-3 bg-green-50 border border-green-200 rounded-lg p-3">
                          <h5 className="text-sm font-medium text-green-800 mb-2 flex items-center">
                            <Shield className="w-4 h-4 mr-1" />
                            Recommended Mitigations:
                          </h5>
                          <ul className="list-disc list-inside text-sm text-green-700 space-y-1 ml-2">
                            {abuse.mitigations.map((mitigation, idx) => (
                              <li key={idx}>{mitigation}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      <div className="flex items-center flex-wrap gap-2 mt-3">
                        <span className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs flex items-center">
                          <Target className="w-3 h-3 mr-1" />
                          Actor: {abuse.threat_actor}
                        </span>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getImpactColor(abuse.impact)}`}>
                          Impact: {abuse.impact}
                        </span>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getImpactColor(abuse.likelihood)}`}>
                          Likelihood: {abuse.likelihood}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
              {analysis.abuse_cases.length === 0 && (
                <div className="p-8 text-center text-gray-500">No abuse cases identified</div>
              )}
            </div>
          </div>

          {/* STRIDE Threats */}
          <div className="card">
            <div className="p-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                <Shield className="w-5 h-5 mr-2 text-red-600" />
                STRIDE Threat Analysis
              </h3>
            </div>
            <div className="p-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(STRIDE_INFO).map(([key, info]) => {
                  const threats = analysis.stride_threats[key] || []
                  const Icon = info.icon
                  return (
                    <div key={key} className={`border rounded-lg p-4 ${threats.length > 0 ? info.color : 'bg-gray-50 border-gray-200'}`}>
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center">
                          <Icon className="w-5 h-5 mr-2" />
                          <span className="font-semibold">{info.name}</span>
                        </div>
                        <span className="px-2 py-0.5 bg-white bg-opacity-50 rounded-full text-xs font-medium">
                          {threats.length}
                        </span>
                      </div>
                      {threats.length > 0 ? (
                        <div className="space-y-2">
                          {threats.map((threat) => (
                            <div key={threat.id} className="bg-white bg-opacity-50 rounded p-2">
                              <p className="text-sm font-medium">{threat.threat}</p>
                              <p className="text-xs text-gray-600 mt-1">
                                <span className="font-medium">Mitigation:</span> {threat.mitigation}
                              </p>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-gray-500">No threats identified</p>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {analysis && activeTab === 'requirements' && (
        <div className="card">
          <div className="p-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 flex items-center">
              <Lock className="w-5 h-5 mr-2 text-green-600" />
              Security Requirements
            </h3>
          </div>
          <div className="divide-y divide-gray-100">
            {analysis.security_requirements.map((req) => (
              <div key={req.id} className="p-4 hover:bg-gray-50">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center flex-wrap gap-2 mb-3">
                      <span className="text-xs font-mono bg-green-100 text-green-700 px-2 py-0.5 rounded">{req.id}</span>
                      <span className={`px-2 py-1 rounded text-xs font-semibold border ${getPriorityColor(req.priority)}`}>
                        {req.priority.toUpperCase()} PRIORITY
                      </span>
                      <span className="px-2 py-1 bg-indigo-100 text-indigo-700 rounded text-xs font-medium">
                        {req.category}
                      </span>
                    </div>

                    {/* Requirement Title */}
                    <h4 className="font-semibold text-gray-900 text-base mb-3">{req.requirement}</h4>

                    {/* Rationale as bullet points */}
                    <div className="mt-2 mb-3 bg-blue-50 border border-blue-200 rounded-lg p-3">
                      <h5 className="text-sm font-medium text-blue-800 mb-2">📋 Rationale:</h5>
                      <ul className="list-disc list-inside text-sm text-blue-700 space-y-1 ml-2">
                        {formatAsBulletPoints(req.rationale).map((point, idx) => (
                          <li key={idx}>{point}</li>
                        ))}
                      </ul>
                    </div>

                    {/* Acceptance Criteria as bullet points */}
                    <div className="mt-2 bg-green-50 border border-green-200 rounded-lg p-3">
                      <h5 className="text-sm font-medium text-green-800 mb-2">✅ Acceptance Criteria:</h5>
                      <ul className="list-disc list-inside text-sm text-green-700 space-y-1 ml-2">
                        {formatAsBulletPoints(req.acceptance_criteria).map((point, idx) => (
                          <li key={idx}>{point}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            ))}
            {analysis.security_requirements.length === 0 && (
              <div className="p-8 text-center text-gray-500">No requirements generated</div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'compliance' && (
        <div className="card">
          <div className="p-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 flex items-center">
              <FileText className="w-5 h-5 mr-2 text-blue-600" />
              Compliance Mapping
            </h3>
          </div>
          {compliance.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Requirement</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Standard</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Control</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Relevance</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {compliance.map((mapping) => (
                    <tr key={mapping.id} className="hover:bg-gray-50">
                      <td className="px-4 py-3">
                        <span className="text-xs font-mono text-gray-500">{mapping.requirement_id}</span>
                        <p className="text-sm text-gray-900 mt-0.5 line-clamp-2">{mapping.requirement_text}</p>
                      </td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 bg-blue-100 text-blue-700 rounded text-xs font-medium">
                          {mapping.standard_name}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-sm">{mapping.control_id}</span>
                        <p className="text-xs text-gray-500 mt-0.5">{mapping.control_title}</p>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center">
                          <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
                            <div
                              className="bg-green-500 h-2 rounded-full"
                              style={{ width: `${mapping.relevance_score * 100}%` }}
                            />
                          </div>
                          <span className="text-xs text-gray-500">
                            {Math.round(mapping.relevance_score * 100)}%
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-8 text-center text-gray-500">No compliance mappings available</div>
          )}
        </div>
      )}
    </div>
  )
}
