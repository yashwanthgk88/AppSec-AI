import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Shield, Plus, Trash2, Link2, CheckCircle2, AlertTriangle, Clock, XCircle, ArrowLeft, Edit2, Save, X, ChevronDown, ChevronUp } from 'lucide-react'
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

const STATUS_ICONS: Record<string, any> = {
  implemented: CheckCircle2,
  planned: Clock,
  partial: AlertTriangle,
  not_implemented: XCircle,
}

export default function SecurityControlsPage() {
  const { id: projectId } = useParams<{ id: string }>()
  const [controls, setControls] = useState<SecurityControl[]>([])
  const [coverage, setCoverage] = useState<CoverageSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [activeTab, setActiveTab] = useState<'controls' | 'coverage'>('controls')
  const [linkThreatId, setLinkThreatId] = useState('')
  const [linkReqId, setLinkReqId] = useState('')
  const [linkingControlId, setLinkingControlId] = useState<number | null>(null)

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
      const [controlsRes, coverageRes] = await Promise.all([
        axios.get(`/api/security-controls/projects/${projectId}/controls`, { headers }),
        axios.get(`/api/security-controls/projects/${projectId}/coverage`, { headers }),
      ])
      setControls(controlsRes.data)
      setCoverage(coverageRes.data)
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

  const handleLinkThreat = async (controlId: number) => {
    if (!linkThreatId.trim()) return
    try {
      await axios.post(`/api/security-controls/controls/${controlId}/link-threats`, {
        threat_ids: [linkThreatId.trim()]
      }, { headers })
      setLinkThreatId('')
      setLinkingControlId(null)
      fetchData()
    } catch (err) {
      console.error('Failed to link threat:', err)
    }
  }

  const handleLinkRequirement = async (controlId: number) => {
    if (!linkReqId.trim()) return
    try {
      await axios.post(`/api/security-controls/controls/${controlId}/link-requirements`, {
        requirement_ids: [linkReqId.trim()]
      }, { headers })
      setLinkReqId('')
      setLinkingControlId(null)
      fetchData()
    } catch (err) {
      console.error('Failed to link requirement:', err)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    )
  }

  const summary = coverage?.summary

  return (
    <div className="max-w-7xl mx-auto px-4 py-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <Link to={`/projects/${projectId}`} className="text-gray-500 hover:text-gray-700">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <Shield className="w-6 h-6 text-blue-600" />
        <h1 className="text-2xl font-bold text-gray-900">Security Controls Registry</h1>
      </div>

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
          {/* Add Control Button */}
          <div className="mb-4">
            <button
              onClick={() => { resetForm(); setShowForm(true) }}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm"
            >
              <Plus className="w-4 h-4" /> Add Control
            </button>
          </div>

          {/* Add/Edit Form */}
          {showForm && (
            <div className="bg-white border rounded-lg p-6 mb-6">
              <h3 className="text-lg font-semibold mb-4">{editingId ? 'Edit Control' : 'Add New Control'}</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Name *</label>
                  <input
                    type="text"
                    value={form.name}
                    onChange={e => setForm({ ...form, name: e.target.value })}
                    className="w-full border rounded-md px-3 py-2 text-sm"
                    placeholder="e.g., Web Application Firewall (WAF)"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Owner</label>
                  <input
                    type="text"
                    value={form.owner}
                    onChange={e => setForm({ ...form, owner: e.target.value })}
                    className="w-full border rounded-md px-3 py-2 text-sm"
                    placeholder="e.g., Security Team"
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                  <textarea
                    value={form.description}
                    onChange={e => setForm({ ...form, description: e.target.value })}
                    className="w-full border rounded-md px-3 py-2 text-sm"
                    rows={2}
                    placeholder="What does this control do?"
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
                  <label className="block text-sm font-medium text-gray-700 mb-1">STRIDE Categories Covered</label>
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
                <button onClick={handleSubmit} className="flex items-center gap-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm">
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
                      <div className="border-t px-4 py-3 bg-gray-50 space-y-3">
                        {/* STRIDE categories */}
                        {control.stride_categories && control.stride_categories.length > 0 && (
                          <div>
                            <div className="text-xs font-medium text-gray-500 mb-1">STRIDE Coverage</div>
                            <div className="flex flex-wrap gap-1">
                              {control.stride_categories.map(cat => (
                                <span key={cat} className="px-2 py-0.5 bg-blue-50 text-blue-700 rounded text-xs">
                                  {cat.replace('_', ' ')}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Owner & Evidence */}
                        <div className="flex gap-6 text-sm">
                          {control.owner && <div><span className="text-gray-500">Owner:</span> {control.owner}</div>}
                          {control.evidence && <div><span className="text-gray-500">Evidence:</span> {control.evidence}</div>}
                        </div>

                        {/* Linked Threats */}
                        <div>
                          <div className="text-xs font-medium text-gray-500 mb-1">Linked Threats</div>
                          <div className="flex flex-wrap gap-1 mb-2">
                            {(control.linked_threat_ids || []).map(tid => (
                              <span key={tid} className="px-2 py-0.5 bg-red-50 text-red-700 rounded text-xs">{tid}</span>
                            ))}
                            {(!control.linked_threat_ids || control.linked_threat_ids.length === 0) && (
                              <span className="text-xs text-gray-400">No threats linked</span>
                            )}
                          </div>
                          {linkingControlId === control.id ? (
                            <div className="flex gap-2">
                              <input
                                type="text"
                                value={linkThreatId}
                                onChange={e => setLinkThreatId(e.target.value)}
                                placeholder="Enter threat ID"
                                className="border rounded px-2 py-1 text-xs flex-1"
                              />
                              <button onClick={() => handleLinkThreat(control.id)} className="px-2 py-1 bg-blue-600 text-white rounded text-xs">Link</button>
                              <button onClick={() => setLinkingControlId(null)} className="px-2 py-1 bg-gray-200 text-gray-700 rounded text-xs">Cancel</button>
                            </div>
                          ) : (
                            <button
                              onClick={() => { setLinkingControlId(control.id); setLinkThreatId('') }}
                              className="flex items-center gap-1 text-xs text-blue-600 hover:text-blue-800"
                            >
                              <Link2 className="w-3 h-3" /> Link Threat
                            </button>
                          )}
                        </div>

                        {/* Linked Requirements */}
                        <div>
                          <div className="text-xs font-medium text-gray-500 mb-1">Linked Requirements</div>
                          <div className="flex flex-wrap gap-1 mb-2">
                            {(control.linked_requirement_ids || []).map(rid => (
                              <span key={rid} className="px-2 py-0.5 bg-purple-50 text-purple-700 rounded text-xs">{rid}</span>
                            ))}
                            {(!control.linked_requirement_ids || control.linked_requirement_ids.length === 0) && (
                              <span className="text-xs text-gray-400">No requirements linked</span>
                            )}
                          </div>
                          {linkingControlId === -control.id ? (
                            <div className="flex gap-2">
                              <input
                                type="text"
                                value={linkReqId}
                                onChange={e => setLinkReqId(e.target.value)}
                                placeholder="Enter requirement ID (e.g. SR-001)"
                                className="border rounded px-2 py-1 text-xs flex-1"
                              />
                              <button onClick={() => handleLinkRequirement(control.id)} className="px-2 py-1 bg-blue-600 text-white rounded text-xs">Link</button>
                              <button onClick={() => setLinkingControlId(null)} className="px-2 py-1 bg-gray-200 text-gray-700 rounded text-xs">Cancel</button>
                            </div>
                          ) : (
                            <button
                              onClick={() => { setLinkingControlId(-control.id); setLinkReqId('') }}
                              className="flex items-center gap-1 text-xs text-purple-600 hover:text-purple-800"
                            >
                              <Link2 className="w-3 h-3" /> Link Requirement
                            </button>
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
    </div>
  )
}
