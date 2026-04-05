import { useState, useEffect, useMemo, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Shield, Plus, Trash2, CheckCircle2, AlertTriangle, Clock, XCircle, ArrowLeft, Edit2, Save, X, ChevronDown, ChevronUp, Sparkles, Loader2, Search, Check, Link2, Upload, Download, FileText } from 'lucide-react'
import axios from 'axios'

interface SecurityControl {
  id: number
  project_id: number
  name: string
  description: string | null
  control_type: string
  status: string
  stride_categories: string[] | null
  effectiveness: number
  owner: string | null
  evidence: string | null
  linked_threat_ids: string[] | null
  linked_requirement_ids: string[] | null
  created_at: string | null
  updated_at: string | null
}

interface ProjectThreat {
  id: string
  title: string
  category: string
  severity: string
  component: string
  description: string
}

interface CoverageSummary {
  summary: {
    total_controls: number
    implemented: number
    planned: number
    partial: number
    not_implemented: number
    average_effectiveness: number
    threats_mitigated: number
    requirements_satisfied: number
  }
  stride_coverage: Record<string, any[]>
  threat_coverage: Record<string, any[]>
  requirement_coverage: Record<string, any[]>
}

const STRIDE_CATEGORIES = [
  'spoofing', 'tampering', 'repudiation',
  'information_disclosure', 'denial_of_service', 'elevation_of_privilege'
]

const CONTROL_TYPES = ['preventive', 'detective', 'corrective', 'compensating']
const CONTROL_STATUSES = ['implemented', 'planned', 'partial', 'not_implemented']

const STATUS_COLORS: Record<string, string> = {
  implemented: 'bg-green-100 text-green-800',
  planned: 'bg-blue-100 text-blue-800',
  partial: 'bg-yellow-100 text-yellow-800',
  not_implemented: 'bg-red-100 text-red-800',
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-green-100 text-green-800',
}

const STATUS_ICONS: Record<string, any> = {
  implemented: CheckCircle2,
  planned: Clock,
  partial: AlertTriangle,
  not_implemented: XCircle,
}

export default function SecurityControlsPage({ embedded, embeddedProjectId }: { embedded?: boolean; embeddedProjectId?: string } = {}) {
  const params = useParams<{ id: string }>()
  const projectId = embeddedProjectId || params.id
  const [controls, setControls] = useState<SecurityControl[]>([])
  const [coverage, setCoverage] = useState<CoverageSummary | null>(null)
  const [threats, setThreats] = useState<ProjectThreat[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [activeTab, setActiveTab] = useState<'controls' | 'coverage'>('controls')

  // Threat mapping state
  const [mappingControlId, setMappingControlId] = useState<number | null>(null)
  const [selectedThreatIds, setSelectedThreatIds] = useState<Set<string>>(new Set())
  const [threatSearch, setThreatSearch] = useState('')
  const [autoMapLoading, setAutoMapLoading] = useState(false)
  const [autoMapScores, setAutoMapScores] = useState<Record<string, number>>({})
  const [savingMapping, setSavingMapping] = useState(false)

  // Upload state
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadResult, setUploadResult] = useState<{ message: string; errors?: string[]; type: 'success' | 'error' } | null>(null)

  // Form state
  const [form, setForm] = useState({
    name: '',
    description: '',
    control_type: 'preventive',
    status: 'implemented',
    stride_categories: [] as string[],
    effectiveness: 0.7,
    owner: '',
    evidence: '',
  })

  const token = localStorage.getItem('token')
  const headers = { Authorization: `Bearer ${token}` }

  useEffect(() => {
    fetchData()
  }, [projectId])

  const fetchData = async () => {
    try {
      setLoading(true)
      const [controlsRes, coverageRes, threatsRes] = await Promise.all([
        axios.get(`/api/security-controls/projects/${projectId}/controls`, { headers }),
        axios.get(`/api/security-controls/projects/${projectId}/coverage`, { headers }),
        axios.get(`/api/security-controls/projects/${projectId}/threats`, { headers }),
      ])
      setControls(controlsRes.data)
      setCoverage(coverageRes.data)
      setThreats(threatsRes.data)
    } catch (err) {
      console.error('Failed to fetch controls:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async () => {
    try {
      if (editingId) {
        await axios.put(`/api/security-controls/controls/${editingId}`, form, { headers })
      } else {
        await axios.post(`/api/security-controls/projects/${projectId}/controls`, form, { headers })
      }
      resetForm()
      fetchData()
    } catch (err) {
      console.error('Failed to save control:', err)
    }
  }

  const handleDelete = async (controlId: number) => {
    if (!confirm('Delete this control?')) return
    try {
      await axios.delete(`/api/security-controls/controls/${controlId}`, { headers })
      fetchData()
    } catch (err) {
      console.error('Failed to delete control:', err)
    }
  }

  const handleEdit = (control: SecurityControl) => {
    setForm({
      name: control.name,
      description: control.description || '',
      control_type: control.control_type,
      status: control.status,
      stride_categories: control.stride_categories || [],
      effectiveness: control.effectiveness,
      owner: control.owner || '',
      evidence: control.evidence || '',
    })
    setEditingId(control.id)
    setShowForm(true)
  }

  const resetForm = () => {
    setForm({
      name: '', description: '', control_type: 'preventive', status: 'implemented',
      stride_categories: [], effectiveness: 0.7, owner: '', evidence: '',
    })
    setEditingId(null)
    setShowForm(false)
  }

  const toggleStrideCategory = (cat: string) => {
    setForm(prev => ({
      ...prev,
      stride_categories: prev.stride_categories.includes(cat)
        ? prev.stride_categories.filter(c => c !== cat)
        : [...prev.stride_categories, cat]
    }))
  }

  // ====== Threat Mapping ======

  const openThreatMapper = (control: SecurityControl) => {
    setMappingControlId(control.id)
    setSelectedThreatIds(new Set(control.linked_threat_ids || []))
    setThreatSearch('')
    setAutoMapScores({})
  }

  const closeThreatMapper = () => {
    setMappingControlId(null)
    setSelectedThreatIds(new Set())
    setAutoMapScores({})
    setThreatSearch('')
  }

  const toggleThreatSelection = (threatId: string) => {
    setSelectedThreatIds(prev => {
      const next = new Set(prev)
      if (next.has(threatId)) {
        next.delete(threatId)
      } else {
        next.add(threatId)
      }
      return next
    })
  }

  const handleAutoMap = async (controlId: number) => {
    setAutoMapLoading(true)
    try {
      const res = await axios.post(`/api/security-controls/controls/${controlId}/auto-map`, {}, { headers })
      const scores: Record<string, number> = {}
      const suggested = new Set(selectedThreatIds)
      for (const t of res.data.matched_threats || []) {
        scores[t.threat_id] = t.relevance_score
        if (t.relevance_score >= 0.4) {
          suggested.add(t.threat_id)
        }
      }
      setAutoMapScores(scores)
      setSelectedThreatIds(suggested)
    } catch (err) {
      console.error('Failed to auto-map:', err)
    } finally {
      setAutoMapLoading(false)
    }
  }

  const saveThreatMapping = async (controlId: number) => {
    setSavingMapping(true)
    try {
      await axios.put(`/api/security-controls/controls/${controlId}/threats`, {
        threat_ids: Array.from(selectedThreatIds)
      }, { headers })
      closeThreatMapper()
      fetchData()
    } catch (err) {
      console.error('Failed to save mapping:', err)
    } finally {
      setSavingMapping(false)
    }
  }

  const removeThreat = async (controlId: number, threatId: string) => {
    const control = controls.find(c => c.id === controlId)
    if (!control) return
    const updated = (control.linked_threat_ids || []).filter(id => id !== threatId)
    try {
      await axios.put(`/api/security-controls/controls/${controlId}/threats`, {
        threat_ids: updated
      }, { headers })
      fetchData()
    } catch (err) {
      console.error('Failed to remove threat:', err)
    }
  }

  const removeRequirement = async (controlId: number, reqId: string) => {
    const control = controls.find(c => c.id === controlId)
    if (!control) return
    const updated = (control.linked_requirement_ids || []).filter(id => id !== reqId)
    try {
      await axios.put(`/api/security-controls/controls/${controlId}/requirements`, {
        requirement_ids: updated
      }, { headers })
      fetchData()
    } catch (err) {
      console.error('Failed to remove requirement:', err)
    }
  }

  // Threat title lookup
  const threatMap = useMemo(() => {
    const map: Record<string, ProjectThreat> = {}
    for (const t of threats) map[t.id] = t
    return map
  }, [threats])

  // Filtered threats for the mapper
  const filteredThreats = useMemo(() => {
    if (!threatSearch.trim()) return threats
    const q = threatSearch.toLowerCase()
    return threats.filter(t =>
      t.title.toLowerCase().includes(q) ||
      t.category.toLowerCase().includes(q) ||
      t.component.toLowerCase().includes(q) ||
      t.severity.toLowerCase().includes(q)
    )
  }, [threats, threatSearch])

  // Group filtered threats by STRIDE category
  const groupedThreats = useMemo(() => {
    const groups: Record<string, ProjectThreat[]> = {}
    for (const t of filteredThreats) {
      const cat = t.category || 'Other'
      if (!groups[cat]) groups[cat] = []
      groups[cat].push(t)
    }
    return groups
  }, [filteredThreats])

  const isFormValid = form.name.trim() && form.description.trim() && form.stride_categories.length > 0 && form.owner.trim()

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    )
  }

  const summary = coverage?.summary
  const mappingControl = controls.find(c => c.id === mappingControlId)

  return (
    <div className={embedded ? '' : 'max-w-7xl mx-auto px-4 py-6'}>
      {/* Header */}
      {!embedded && (
      <div className="flex items-center gap-3 mb-6">
        <Link to={`/projects/${projectId}`} className="text-gray-500 hover:text-gray-700">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <Shield className="w-6 h-6 text-blue-600" />
        <h1 className="text-2xl font-bold text-gray-900">Security Controls Registry</h1>
      </div>
      )}

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-white rounded-lg border p-4">
            <div className="text-sm text-gray-500">Total Controls</div>
            <div className="text-2xl font-bold text-gray-900">{summary.total_controls}</div>
          </div>
          <div className="bg-white rounded-lg border p-4">
            <div className="text-sm text-gray-500">Implemented</div>
            <div className="text-2xl font-bold text-green-600">{summary.implemented}</div>
          </div>
          <div className="bg-white rounded-lg border p-4">
            <div className="text-sm text-gray-500">Avg Effectiveness</div>
            <div className="text-2xl font-bold text-blue-600">{(summary.average_effectiveness * 100).toFixed(0)}%</div>
          </div>
          <div className="bg-white rounded-lg border p-4">
            <div className="text-sm text-gray-500">Threats Mitigated</div>
            <div className="text-2xl font-bold text-purple-600">{summary.threats_mitigated}</div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-4 mb-6 border-b">
        <button
          onClick={() => setActiveTab('controls')}
          className={`pb-2 px-1 text-sm font-medium border-b-2 ${activeTab === 'controls' ? 'border-blue-600 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
        >
          Controls ({controls.length})
        </button>
        <button
          onClick={() => setActiveTab('coverage')}
          className={`pb-2 px-1 text-sm font-medium border-b-2 ${activeTab === 'coverage' ? 'border-blue-600 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
        >
          STRIDE Coverage
        </button>
      </div>

      {activeTab === 'controls' && (
        <>
          {/* Action Buttons */}
          <div className="mb-4 flex items-center gap-3">
            <button
              onClick={() => { resetForm(); setShowForm(true) }}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm"
            >
              <Plus className="w-4 h-4" /> Add Control
            </button>
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
              className="flex items-center gap-2 px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 text-sm disabled:opacity-50"
            >
              <Upload className="w-4 h-4" /> {uploading ? 'Uploading...' : 'Bulk Upload CSV'}
            </button>
            <button
              onClick={async () => {
                try {
                  const res = await axios.get('/api/security-controls/download-template', {
                    headers, responseType: 'blob',
                  })
                  const url = window.URL.createObjectURL(new Blob([res.data]))
                  const a = document.createElement('a')
                  a.href = url
                  a.download = 'security_controls_template.csv'
                  a.click()
                  window.URL.revokeObjectURL(url)
                } catch (err) {
                  console.error('Failed to download template:', err)
                }
              }}
              className="flex items-center gap-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 text-sm"
            >
              <Download className="w-4 h-4" /> CSV Template
            </button>
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv"
              className="hidden"
              onChange={async (e) => {
                const file = e.target.files?.[0]
                if (!file) return
                setUploading(true)
                setUploadResult(null)
                try {
                  const formData = new FormData()
                  formData.append('file', file)
                  const res = await axios.post(
                    `/api/security-controls/projects/${projectId}/controls/upload`,
                    formData,
                    { headers: { ...headers, 'Content-Type': 'multipart/form-data' } }
                  )
                  setUploadResult({
                    message: res.data.message,
                    errors: res.data.errors,
                    type: 'success',
                  })
                  fetchData()
                } catch (err: any) {
                  setUploadResult({
                    message: err.response?.data?.detail || 'Upload failed',
                    type: 'error',
                  })
                } finally {
                  setUploading(false)
                  if (fileInputRef.current) fileInputRef.current.value = ''
                }
              }}
            />
          </div>
          <p className="text-xs text-gray-500 mb-4 -mt-2 flex items-center gap-1">
            <FileText className="w-3 h-3" />
            To bulk upload controls,{' '}
            <button
              onClick={async () => {
                try {
                  const res = await axios.get('/api/security-controls/download-template', {
                    headers, responseType: 'blob',
                  })
                  const url = window.URL.createObjectURL(new Blob([res.data]))
                  const a = document.createElement('a')
                  a.href = url
                  a.download = 'security_controls_template.csv'
                  a.click()
                  window.URL.revokeObjectURL(url)
                } catch (err) {
                  console.error('Failed to download template:', err)
                }
              }}
              className="text-blue-600 hover:underline font-medium"
            >
              download the CSV template
            </button>
            , fill in your controls (name, description, type, status, STRIDE categories, effectiveness, owner), then click "Bulk Upload CSV".
          </p>

          {/* Upload Result Banner */}
          {uploadResult && (
            <div className={`mb-4 p-3 rounded-lg border flex items-start gap-2 ${
              uploadResult.type === 'success'
                ? 'bg-green-50 border-green-200 text-green-800'
                : 'bg-red-50 border-red-200 text-red-800'
            }`}>
              {uploadResult.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 mt-0.5 flex-shrink-0" />
              ) : (
                <XCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
              )}
              <div className="flex-1">
                <p className="text-sm font-medium">{uploadResult.message}</p>
                {uploadResult.errors && uploadResult.errors.length > 0 && (
                  <ul className="text-xs mt-1 space-y-0.5">
                    {uploadResult.errors.map((err, i) => (
                      <li key={i} className="text-amber-700">{err}</li>
                    ))}
                  </ul>
                )}
              </div>
              <button onClick={() => setUploadResult(null)} className="text-gray-400 hover:text-gray-600">
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Add/Edit Form */}
          {showForm && (
            <div className="bg-white border rounded-lg p-6 mb-6">
              <h3 className="text-lg font-semibold mb-4">{editingId ? 'Edit Control' : 'Add New Control'}</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Name <span className="text-red-500">*</span></label>
                  <input
                    type="text"
                    value={form.name}
                    onChange={e => setForm({ ...form, name: e.target.value })}
                    className={`w-full border rounded-md px-3 py-2 text-sm ${!form.name.trim() ? 'border-red-300' : ''}`}
                    placeholder="e.g., Web Application Firewall (WAF)"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Owner <span className="text-red-500">*</span></label>
                  <input
                    type="text"
                    value={form.owner}
                    onChange={e => setForm({ ...form, owner: e.target.value })}
                    className={`w-full border rounded-md px-3 py-2 text-sm ${!form.owner.trim() ? 'border-red-300' : ''}`}
                    placeholder="e.g., Security Team"
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-1">Description <span className="text-red-500">*</span></label>
                  <textarea
                    value={form.description}
                    onChange={e => setForm({ ...form, description: e.target.value })}
                    className={`w-full border rounded-md px-3 py-2 text-sm ${!form.description.trim() ? 'border-red-300' : ''}`}
                    rows={2}
                    placeholder="What does this control do? Be specific for better AI auto-mapping."
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
                  <select
                    value={form.control_type}
                    onChange={e => setForm({ ...form, control_type: e.target.value })}
                    className="w-full border rounded-md px-3 py-2 text-sm"
                  >
                    {CONTROL_TYPES.map(t => (
                      <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                  <select
                    value={form.status}
                    onChange={e => setForm({ ...form, status: e.target.value })}
                    className="w-full border rounded-md px-3 py-2 text-sm"
                  >
                    {CONTROL_STATUSES.map(s => (
                      <option key={s} value={s}>{s.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Effectiveness ({(form.effectiveness * 100).toFixed(0)}%)</label>
                  <input
                    type="range"
                    min="0" max="1" step="0.05"
                    value={form.effectiveness}
                    onChange={e => setForm({ ...form, effectiveness: parseFloat(e.target.value) })}
                    className="w-full"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Evidence / Link</label>
                  <input
                    type="text"
                    value={form.evidence}
                    onChange={e => setForm({ ...form, evidence: e.target.value })}
                    className="w-full border rounded-md px-3 py-2 text-sm"
                    placeholder="URL or description of evidence"
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-1">STRIDE Categories Covered <span className="text-red-500">*</span></label>
                  <div className="flex flex-wrap gap-2">
                    {STRIDE_CATEGORIES.map(cat => (
                      <button
                        key={cat}
                        onClick={() => toggleStrideCategory(cat)}
                        className={`px-3 py-1 rounded-full text-xs font-medium border ${
                          form.stride_categories.includes(cat)
                            ? 'bg-blue-100 text-blue-800 border-blue-300'
                            : 'bg-gray-50 text-gray-600 border-gray-200 hover:bg-gray-100'
                        }`}
                      >
                        {cat.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              <div className="flex gap-2 mt-4">
                <button onClick={handleSubmit} disabled={!isFormValid} className={`flex items-center gap-1 px-4 py-2 rounded-lg text-sm ${isFormValid ? 'bg-blue-600 text-white hover:bg-blue-700' : 'bg-gray-300 text-gray-500 cursor-not-allowed'}`}>
                  <Save className="w-4 h-4" /> {editingId ? 'Update' : 'Save'}
                </button>
                <button onClick={resetForm} className="flex items-center gap-1 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 text-sm">
                  <X className="w-4 h-4" /> Cancel
                </button>
              </div>
            </div>
          )}

          {/* Controls List */}
          {controls.length === 0 ? (
            <div className="bg-white border rounded-lg p-12 text-center">
              <Shield className="w-12 h-12 text-gray-300 mx-auto mb-3" />
              <p className="text-gray-500">No security controls registered yet.</p>
              <p className="text-sm text-gray-400 mt-1">Add your existing controls so the threat model can account for them.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {controls.map(control => {
                const StatusIcon = STATUS_ICONS[control.status] || Shield
                const isExpanded = expandedId === control.id
                const linkedThreats = (control.linked_threat_ids || []).map(id => threatMap[id]).filter(Boolean)
                const linkedCount = control.linked_threat_ids?.length || 0

                return (
                  <div key={control.id} className="bg-white border rounded-lg overflow-hidden">
                    <div className="flex items-center justify-between p-4">
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <StatusIcon className={`w-5 h-5 flex-shrink-0 ${
                          control.status === 'implemented' ? 'text-green-500' :
                          control.status === 'planned' ? 'text-blue-500' :
                          control.status === 'partial' ? 'text-yellow-500' : 'text-red-500'
                        }`} />
                        <div className="min-w-0">
                          <div className="font-medium text-gray-900 truncate">{control.name}</div>
                          {control.description && (
                            <div className="text-sm text-gray-500 truncate">{control.description}</div>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0 ml-4">
                        {linkedCount > 0 && (
                          <span className="px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-700">
                            {linkedCount} threat{linkedCount !== 1 ? 's' : ''}
                          </span>
                        )}
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_COLORS[control.status] || 'bg-gray-100 text-gray-800'}`}>
                          {control.status.replace('_', ' ')}
                        </span>
                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-600">
                          {control.control_type}
                        </span>
                        <span className="text-xs text-gray-500">{(control.effectiveness * 100).toFixed(0)}%</span>
                        <button onClick={() => handleEdit(control)} className="p-1 text-gray-400 hover:text-blue-600">
                          <Edit2 className="w-4 h-4" />
                        </button>
                        <button onClick={() => handleDelete(control.id)} className="p-1 text-gray-400 hover:text-red-600">
                          <Trash2 className="w-4 h-4" />
                        </button>
                        <button onClick={() => setExpandedId(isExpanded ? null : control.id)} className="p-1 text-gray-400 hover:text-gray-600">
                          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="border-t px-4 py-3 bg-gray-50 space-y-4">
                        {/* STRIDE categories & Owner */}
                        <div className="flex flex-wrap gap-6 text-sm">
                          {control.stride_categories && control.stride_categories.length > 0 && (
                            <div>
                              <span className="text-xs font-medium text-gray-500">STRIDE: </span>
                              {control.stride_categories.map(cat => (
                                <span key={cat} className="px-2 py-0.5 bg-blue-50 text-blue-700 rounded text-xs mr-1">
                                  {cat.replace('_', ' ')}
                                </span>
                              ))}
                            </div>
                          )}
                          {control.owner && <div><span className="text-gray-500">Owner:</span> {control.owner}</div>}
                          {control.evidence && <div><span className="text-gray-500">Evidence:</span> {control.evidence}</div>}
                        </div>

                        {/* Linked Threats — shown as readable cards with remove */}
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <div className="text-xs font-semibold text-gray-600 uppercase tracking-wide">Mapped Threats</div>
                            <button
                              onClick={() => openThreatMapper(control)}
                              className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-purple-600 text-white rounded-md hover:bg-purple-700 font-medium"
                            >
                              <Sparkles className="w-3.5 h-3.5" /> Map Threats
                            </button>
                          </div>
                          {linkedThreats.length > 0 ? (
                            <div className="space-y-1.5">
                              {linkedThreats.map(t => (
                                <div key={t.id} className="flex items-center gap-2 bg-white border rounded-md px-3 py-2 group">
                                  <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${SEVERITY_COLORS[t.severity] || 'bg-gray-100 text-gray-600'}`}>
                                    {t.severity}
                                  </span>
                                  <span className="text-sm text-gray-800 flex-1 truncate">{t.title}</span>
                                  <span className="text-xs text-gray-400">{t.category}</span>
                                  <button
                                    onClick={() => removeThreat(control.id, t.id)}
                                    className="p-0.5 text-gray-300 hover:text-red-500 opacity-0 group-hover:opacity-100 transition-opacity"
                                    title="Remove mapping"
                                  >
                                    <X className="w-3.5 h-3.5" />
                                  </button>
                                </div>
                              ))}
                              {/* Show IDs that don't match any known threat */}
                              {(control.linked_threat_ids || []).filter(id => !threatMap[id]).map(id => (
                                <div key={id} className="flex items-center gap-2 bg-white border border-dashed rounded-md px-3 py-2 group">
                                  <span className="text-xs text-gray-400 font-mono flex-1">{id}</span>
                                  <button
                                    onClick={() => removeThreat(control.id, id)}
                                    className="p-0.5 text-gray-300 hover:text-red-500 opacity-0 group-hover:opacity-100 transition-opacity"
                                  >
                                    <X className="w-3.5 h-3.5" />
                                  </button>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div className="text-sm text-gray-400 py-2">No threats mapped. Click "Map Threats" to start.</div>
                          )}
                        </div>

                        {/* Linked Requirements */}
                        <div>
                          <div className="text-xs font-semibold text-gray-600 uppercase tracking-wide mb-2">Linked Requirements</div>
                          {(control.linked_requirement_ids || []).length > 0 ? (
                            <div className="flex flex-wrap gap-1.5">
                              {(control.linked_requirement_ids || []).map(rid => (
                                <span key={rid} className="inline-flex items-center gap-1 px-2 py-1 bg-indigo-50 text-indigo-700 rounded-md text-xs group">
                                  {rid}
                                  <button
                                    onClick={() => removeRequirement(control.id, rid)}
                                    className="text-indigo-300 hover:text-red-500 opacity-0 group-hover:opacity-100 transition-opacity"
                                  >
                                    <X className="w-3 h-3" />
                                  </button>
                                </span>
                              ))}
                            </div>
                          ) : (
                            <div className="text-sm text-gray-400">No requirements linked</div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </>
      )}

      {activeTab === 'coverage' && coverage && (
        <div className="space-y-6">
          {/* STRIDE Coverage Matrix */}
          <div className="bg-white border rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">STRIDE Coverage Matrix</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {STRIDE_CATEGORIES.map(cat => {
                const catControls = coverage.stride_coverage[cat] || []
                const hasCoverage = catControls.length > 0
                return (
                  <div key={cat} className={`border rounded-lg p-4 ${hasCoverage ? 'border-green-200 bg-green-50' : 'border-red-200 bg-red-50'}`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-sm capitalize">{cat.replace('_', ' ')}</span>
                      {hasCoverage ? (
                        <CheckCircle2 className="w-4 h-4 text-green-600" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-500" />
                      )}
                    </div>
                    {hasCoverage ? (
                      <div className="space-y-1">
                        {catControls.map((c: any, i: number) => (
                          <div key={i} className="text-xs text-gray-700 flex justify-between">
                            <span>{c.name}</span>
                            <span className={`px-1.5 rounded ${STATUS_COLORS[c.status] || ''}`}>{(c.effectiveness * 100).toFixed(0)}%</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-xs text-red-600">No controls covering this category</div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          {/* Gap Analysis */}
          <div className="bg-white border rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">Gap Analysis</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center p-3 bg-green-50 rounded-lg">
                <div className="text-2xl font-bold text-green-600">
                  {STRIDE_CATEGORIES.filter(c => (coverage.stride_coverage[c] || []).length > 0).length}
                </div>
                <div className="text-xs text-gray-500 mt-1">STRIDE Categories Covered</div>
              </div>
              <div className="text-center p-3 bg-red-50 rounded-lg">
                <div className="text-2xl font-bold text-red-600">
                  {STRIDE_CATEGORIES.filter(c => (coverage.stride_coverage[c] || []).length === 0).length}
                </div>
                <div className="text-xs text-gray-500 mt-1">Uncovered Categories</div>
              </div>
              <div className="text-center p-3 bg-purple-50 rounded-lg">
                <div className="text-2xl font-bold text-purple-600">{summary?.requirements_satisfied || 0}</div>
                <div className="text-xs text-gray-500 mt-1">Requirements Satisfied</div>
              </div>
              <div className="text-center p-3 bg-orange-50 rounded-lg">
                <div className="text-2xl font-bold text-orange-600">{summary?.planned || 0}</div>
                <div className="text-xs text-gray-500 mt-1">Controls Planned</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ====== Threat Mapper Modal ====== */}
      {mappingControl && (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-2xl w-full max-w-3xl max-h-[85vh] flex flex-col">
            {/* Modal Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Map Threats to Control</h3>
                <p className="text-sm text-gray-500 mt-0.5">
                  <span className="font-medium text-gray-700">{mappingControl.name}</span> — select threats this control mitigates
                </p>
              </div>
              <button onClick={closeThreatMapper} className="p-1 text-gray-400 hover:text-gray-600">
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Toolbar: Search + Auto-Map */}
            <div className="flex items-center gap-3 px-6 py-3 border-b bg-gray-50">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  value={threatSearch}
                  onChange={e => setThreatSearch(e.target.value)}
                  placeholder="Search threats by title, category, component..."
                  className="w-full pl-9 pr-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-purple-200 focus:border-purple-400 outline-none"
                />
              </div>
              <button
                onClick={() => handleAutoMap(mappingControl.id)}
                disabled={autoMapLoading}
                className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 text-sm font-medium disabled:opacity-50 whitespace-nowrap"
              >
                {autoMapLoading ? (
                  <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing...</>
                ) : (
                  <><Sparkles className="w-4 h-4" /> AI Auto-Map</>
                )}
              </button>
            </div>

            {/* Selection summary */}
            <div className="px-6 py-2 bg-purple-50 border-b text-sm">
              <span className="text-purple-700 font-medium">{selectedThreatIds.size}</span>
              <span className="text-purple-600"> threat{selectedThreatIds.size !== 1 ? 's' : ''} selected</span>
              {Object.keys(autoMapScores).length > 0 && (
                <span className="text-purple-500 ml-2">
                  — AI suggested {Object.values(autoMapScores).filter(s => s >= 0.4).length} matches
                </span>
              )}
            </div>

            {/* Threat List */}
            <div className="flex-1 overflow-y-auto px-6 py-3">
              {threats.length === 0 ? (
                <div className="text-center py-12 text-gray-400">
                  <AlertTriangle className="w-8 h-8 mx-auto mb-2" />
                  <p>No threat model found. Generate a threat model first.</p>
                </div>
              ) : filteredThreats.length === 0 ? (
                <div className="text-center py-8 text-gray-400">
                  <Search className="w-6 h-6 mx-auto mb-2" />
                  <p>No threats match your search.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {Object.entries(groupedThreats).map(([category, categoryThreats]) => (
                    <div key={category}>
                      <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2 sticky top-0 bg-white py-1">
                        {category} ({categoryThreats.length})
                      </div>
                      <div className="space-y-1">
                        {categoryThreats.map(threat => {
                          const isSelected = selectedThreatIds.has(threat.id)
                          const relevance = autoMapScores[threat.id]
                          const isSuggested = relevance !== undefined && relevance >= 0.4
                          return (
                            <button
                              key={threat.id}
                              onClick={() => toggleThreatSelection(threat.id)}
                              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-colors ${
                                isSelected
                                  ? 'bg-purple-50 border border-purple-200'
                                  : 'bg-white border border-gray-100 hover:bg-gray-50'
                              }`}
                            >
                              {/* Checkbox */}
                              <div className={`w-5 h-5 rounded border-2 flex items-center justify-center flex-shrink-0 ${
                                isSelected ? 'bg-purple-600 border-purple-600' : 'border-gray-300'
                              }`}>
                                {isSelected && <Check className="w-3.5 h-3.5 text-white" />}
                              </div>

                              {/* Severity badge */}
                              <span className={`px-1.5 py-0.5 rounded text-xs font-medium flex-shrink-0 ${SEVERITY_COLORS[threat.severity] || 'bg-gray-100 text-gray-600'}`}>
                                {threat.severity}
                              </span>

                              {/* Title + component */}
                              <div className="flex-1 min-w-0">
                                <div className="text-sm text-gray-800 truncate">{threat.title}</div>
                                {threat.component && (
                                  <div className="text-xs text-gray-400 truncate">{threat.component}</div>
                                )}
                              </div>

                              {/* Relevance score from AI */}
                              {relevance !== undefined && (
                                <span className={`px-2 py-0.5 rounded-full text-xs font-medium flex-shrink-0 ${
                                  isSuggested ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'
                                }`}>
                                  {(relevance * 100).toFixed(0)}% match
                                </span>
                              )}
                            </button>
                          )
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-between px-6 py-4 border-t bg-gray-50">
              <button
                onClick={() => setSelectedThreatIds(new Set())}
                className="text-sm text-gray-500 hover:text-gray-700"
              >
                Clear all
              </button>
              <div className="flex gap-3">
                <button
                  onClick={closeThreatMapper}
                  className="px-4 py-2 text-sm text-gray-700 bg-white border rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={() => saveThreatMapping(mappingControl.id)}
                  disabled={savingMapping}
                  className="flex items-center gap-1.5 px-4 py-2 text-sm text-white bg-purple-600 rounded-lg hover:bg-purple-700 disabled:opacity-50 font-medium"
                >
                  {savingMapping ? (
                    <><Loader2 className="w-4 h-4 animate-spin" /> Saving...</>
                  ) : (
                    <><Link2 className="w-4 h-4" /> Save Mapping ({selectedThreatIds.size})</>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
