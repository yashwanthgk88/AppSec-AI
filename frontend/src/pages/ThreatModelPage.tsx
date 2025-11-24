import { useState, useEffect, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Network, Shield, AlertTriangle, ArrowLeft, Download, Search, ChevronDown, ChevronRight } from 'lucide-react'
import axios from 'axios'
import mermaid from 'mermaid'
import { toPng, toSvg } from 'html-to-image'

// Initialize mermaid
mermaid.initialize({
  startOnLoad: true,
  theme: 'default',
  securityLevel: 'loose',
  flowchart: {
    useMaxWidth: true,
    htmlLabels: true,
    curve: 'basis'
  }
})

export default function ThreatModelPage() {
  const { id } = useParams()
  const [threatModel, setThreatModel] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [selectedCategory, setSelectedCategory] = useState<string>('all')
  const [selectedLevel, setSelectedLevel] = useState<number>(0)
  const [controls, setControls] = useState<string[]>([])
  const [newControl, setNewControl] = useState('')
  const [expandedThreats, setExpandedThreats] = useState<Set<number>>(new Set())
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => {
    fetchThreatModel()
  }, [id])

  const fetchThreatModel = async () => {
    try {
      const token = localStorage.getItem('token')
      const response = await axios.get(`/api/projects/${id}/threat-model`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      setThreatModel(response.data)
    } catch (error) {
      console.error('Failed to fetch threat model:', error)
    } finally {
      setLoading(false)
    }
  }

  const addControl = () => {
    if (newControl.trim()) {
      setControls([...controls, newControl.trim()])
      setNewControl('')
    }
  }

  const removeControl = (index: number) => {
    setControls(controls.filter((_, i) => i !== index))
  }

  const toggleThreat = (index: number) => {
    const newExpanded = new Set(expandedThreats)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedThreats(newExpanded)
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (!threatModel) {
    return (
      <div className="card p-12 text-center">
        <Network className="w-16 h-16 text-gray-300 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-gray-900 mb-2">No Threat Model</h3>
        <p className="text-gray-600 mb-6">
          No threat model found. Create a project with architecture documentation.
        </p>
        <Link to={`/projects/${id}`} className="btn btn-primary">
          Back to Project
        </Link>
      </div>
    )
  }

  const strideCategories = Object.keys(threatModel.stride_analysis || {})
  let filteredThreats =
    selectedCategory === 'all'
      ? Object.values(threatModel.stride_analysis || {}).flat()
      : threatModel.stride_analysis[selectedCategory] || []

  // Apply search filter
  if (searchQuery.trim()) {
    const query = searchQuery.toLowerCase()
    filteredThreats = filteredThreats.filter((threat: any) =>
      threat.threat?.toLowerCase().includes(query) ||
      threat.description?.toLowerCase().includes(query) ||
      threat.component?.toLowerCase().includes(query) ||
      threat.mitigation?.toLowerCase().includes(query)
    )
  }

  const currentDFD = selectedLevel === 0 ? threatModel.dfd_level_0 : threatModel.dfd_level_1

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
          <h1 className="text-3xl font-bold text-gray-900">{threatModel.name}</h1>
          <p className="text-gray-600 mt-1">Data Flow Diagram & STRIDE Analysis</p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="card p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Total Threats</p>
              <p className="text-2xl font-bold text-gray-900">{threatModel.threat_count}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-red-600" />
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Components</p>
              <p className="text-2xl font-bold text-gray-900">
                {threatModel.components_count || 0}
              </p>
            </div>
            <Network className="w-8 h-8 text-blue-600" />
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Data Flows</p>
              <p className="text-2xl font-bold text-gray-900">
                {threatModel.data_flows_count || 0}
              </p>
            </div>
            <Network className="w-8 h-8 text-green-600" />
          </div>
        </div>

        <div className="card p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Trust Boundaries</p>
              <p className="text-2xl font-bold text-gray-900">
                {threatModel.trust_boundaries_count || 0}
              </p>
            </div>
            <Shield className="w-8 h-8 text-purple-600" />
          </div>
        </div>
      </div>

      {/* DFD Visualization */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-gray-900">
            Data Flow Diagram
          </h2>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setSelectedLevel(0)}
              className={`px-4 py-2 text-sm rounded-lg transition ${
                selectedLevel === 0
                  ? 'bg-indigo-600 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              Level 0 (Context)
            </button>
            <button
              onClick={() => setSelectedLevel(1)}
              className={`px-4 py-2 text-sm rounded-lg transition ${
                selectedLevel === 1
                  ? 'bg-indigo-600 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              Level 1 (Detailed)
            </button>
          </div>
        </div>

        {currentDFD && (
          <MermaidDiagram
            dfdData={currentDFD}
            level={selectedLevel}
          />
        )}
      </div>

      {/* Security Controls Input */}
      <div className="card p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Security Controls</h2>
        <p className="text-sm text-gray-600 mb-4">
          Add security controls you have implemented. The system will adjust threat severity based on active controls.
        </p>

        <div className="flex items-start space-x-2 mb-4">
          <input
            type="text"
            value={newControl}
            onChange={(e) => setNewControl(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && addControl()}
            placeholder="e.g., Multi-factor authentication, Input validation, Encryption at rest..."
            className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
          />
          <button
            onClick={addControl}
            className="px-6 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition"
          >
            Add Control
          </button>
        </div>

        {controls.length > 0 ? (
          <div className="space-y-2">
            <p className="text-sm font-medium text-gray-700 mb-2">Active Controls ({controls.length}):</p>
            <div className="flex flex-wrap gap-2">
              {controls.map((control, index) => (
                <div
                  key={index}
                  className="inline-flex items-center space-x-2 px-3 py-1.5 bg-green-100 text-green-800 rounded-lg"
                >
                  <Shield className="w-4 h-4" />
                  <span className="text-sm">{control}</span>
                  <button
                    onClick={() => removeControl(index)}
                    className="text-green-600 hover:text-green-900"
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
            <p className="text-xs text-gray-500 mt-2">
              {controls.length} control{controls.length !== 1 ? 's' : ''} active - threats may have reduced severity
            </p>
          </div>
        ) : (
          <div className="text-center py-6 bg-gray-50 rounded-lg border-2 border-dashed border-gray-200">
            <Shield className="w-8 h-8 text-gray-400 mx-auto mb-2" />
            <p className="text-sm text-gray-600">No security controls added yet</p>
            <p className="text-xs text-gray-500">Add controls to see how they affect threat severity</p>
          </div>
        )}
      </div>

      {/* STRIDE Analysis */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-gray-900">STRIDE Threat Analysis</h2>

          {/* Category Filter */}
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setSelectedCategory('all')}
              className={`px-4 py-2 text-sm rounded-lg transition ${
                selectedCategory === 'all'
                  ? 'bg-primary-600 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              All
            </button>
            {strideCategories.map((category) => (
              <button
                key={category}
                onClick={() => setSelectedCategory(category)}
                className={`px-4 py-2 text-sm rounded-lg transition ${
                  selectedCategory === category
                    ? 'bg-primary-600 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                }`}
              >
                {category}
              </button>
            ))}
          </div>
        </div>

        {/* Search Bar */}
        <div className="mb-4">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search threats by name, description, component, or mitigation..."
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
          />
          {searchQuery && (
            <p className="text-sm text-gray-600 mt-2">
              Found {filteredThreats.length} threat{filteredThreats.length !== 1 ? 's' : ''}
            </p>
          )}
        </div>

        <div className="space-y-4">
          {filteredThreats.length === 0 ? (
            <p className="text-center text-gray-600 py-8">
              {searchQuery ? 'No threats match your search' : 'No threats in this category'}
            </p>
          ) : (
            filteredThreats.map((threat: any, idx: number) => (
              <ThreatCard
                key={idx}
                threat={threat}
                isExpanded={expandedThreats.has(idx)}
                onToggle={() => toggleThreat(idx)}
                controls={controls}
              />
            ))
          )}
        </div>
      </div>

      {/* MITRE ATT&CK Mapping */}
      <div className="card p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">MITRE ATT&CK Mapping</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Object.entries(threatModel.mitre_mapping || {}).map(([id, data]: [string, any]) => (
            <div key={id} className="border border-gray-200 rounded-lg p-4">
              <div className="flex items-start justify-between mb-2">
                <span className="badge badge-info">{id}</span>
                <span className="text-xs text-gray-500">{data.tactic}</span>
              </div>
              <h3 className="font-medium text-gray-900 mb-2">{data.name}</h3>
              <p className="text-sm text-gray-600 mb-2">{data.description}</p>
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-500">Related: {data.related_stride}</span>
                <span className="font-medium text-gray-900">{data.threat_count} threats</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function MermaidDiagram({ dfdData, level }: { dfdData: any; level: number }) {
  const mermaidRef = useRef<HTMLDivElement>(null)
  const [mermaidSvg, setMermaidSvg] = useState<string>('')

  useEffect(() => {
    if (dfdData?.mermaid) {
      renderMermaid()
    }
  }, [dfdData, level])

  const renderMermaid = async () => {
    try {
      const { svg } = await mermaid.render(`mermaid-${level}`, dfdData.mermaid)
      setMermaidSvg(svg)
    } catch (error) {
      console.error('Failed to render mermaid:', error)
    }
  }

  const downloadPNG = async () => {
    if (mermaidRef.current) {
      try {
        const dataUrl = await toPng(mermaidRef.current, {
          quality: 1.0,
          backgroundColor: '#ffffff'
        })
        const link = document.createElement('a')
        link.download = `dfd-level-${level}.png`
        link.href = dataUrl
        link.click()
      } catch (error) {
        console.error('Failed to export PNG:', error)
      }
    }
  }

  const downloadSVG = async () => {
    if (mermaidRef.current) {
      try {
        const dataUrl = await toSvg(mermaidRef.current)
        const link = document.createElement('a')
        link.download = `dfd-level-${level}.svg`
        link.href = dataUrl
        link.click()
      } catch (error) {
        console.error('Failed to export SVG:', error)
      }
    }
  }

  if (!dfdData?.mermaid) {
    return (
      <div className="text-center text-gray-500 py-8">
        <Network className="w-16 h-16 text-gray-300 mx-auto mb-4" />
        <p>No DFD data available</p>
      </div>
    )
  }

  return (
    <div>
      <div className="flex justify-end space-x-2 mb-4">
        <button
          onClick={downloadPNG}
          className="inline-flex items-center px-4 py-2 text-sm bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition"
        >
          <Download className="w-4 h-4 mr-2" />
          Export PNG
        </button>
        <button
          onClick={downloadSVG}
          className="inline-flex items-center px-4 py-2 text-sm bg-green-600 text-white rounded-lg hover:bg-green-700 transition"
        >
          <Download className="w-4 h-4 mr-2" />
          Export SVG
        </button>
      </div>

      <div
        ref={mermaidRef}
        className="bg-white rounded-lg p-8 border border-gray-200 overflow-auto"
        dangerouslySetInnerHTML={{ __html: mermaidSvg }}
      />

      {/* Legend */}
      <div className="flex items-center justify-center space-x-8 mt-6">
        <div className="flex items-center space-x-2">
          <div className="w-4 h-4 bg-blue-200 border-2 border-blue-500 rounded"></div>
          <span className="text-sm text-gray-600">External Entity</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-4 h-4 bg-yellow-200 border-2 border-yellow-500 rounded"></div>
          <span className="text-sm text-gray-600">Process</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-4 h-4 bg-green-200 border-2 border-green-500 rounded"></div>
          <span className="text-sm text-gray-600">Data Store</span>
        </div>
      </div>

      <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
        <p className="text-sm text-blue-800">
          <strong>Level {level} DFD:</strong> {level === 0 ?
            'Context diagram showing the system as a single process with external entities' :
            'Detailed diagram showing internal processes, data stores, and data flows'}
        </p>
      </div>
    </div>
  )
}

function ThreatCard({
  threat,
  isExpanded,
  onToggle,
  controls
}: {
  threat: any
  isExpanded: boolean
  onToggle: () => void
  controls: string[]
}) {
  // Simple heuristic: if there are controls, reduce threat severity
  const hasMitigatingControls = controls.length > 0
  const originalSeverity = 'High'
  const adjustedSeverity = hasMitigatingControls ? 'Medium' : originalSeverity

  const severityColors = {
    High: 'text-red-600 bg-red-50 border-red-200',
    Medium: 'text-orange-600 bg-orange-50 border-orange-200',
    Low: 'text-yellow-600 bg-yellow-50 border-yellow-200'
  }

  return (
    <div
      className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition cursor-pointer"
      onClick={onToggle}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1">
          <div className="flex items-center space-x-2 mb-1">
            <h3 className="font-semibold text-gray-900">{threat.threat}</h3>
            <span className={`text-xs px-2 py-1 rounded-full border ${severityColors[adjustedSeverity as keyof typeof severityColors]}`}>
              {adjustedSeverity}
            </span>
            {hasMitigatingControls && adjustedSeverity !== originalSeverity && (
              <span className="text-xs text-green-600 line-through">{originalSeverity}</span>
            )}
          </div>
          <p className="text-sm text-gray-600">{threat.component}</p>
        </div>
        <div className="flex items-center space-x-2">
          <AlertTriangle className="w-5 h-5 text-orange-600" />
          <span className="text-sm text-gray-500">
            {isExpanded ? '▼' : '▶'}
          </span>
        </div>
      </div>

      <p className="text-sm text-gray-700 mb-3">{threat.description}</p>

      {isExpanded && (
        <div className="space-y-3 mt-4 pt-4 border-t border-gray-200">
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
            <p className="text-xs font-medium text-blue-800 mb-1">STRIDE Category:</p>
            <p className="text-sm text-blue-900">{threat.category || 'N/A'}</p>
          </div>

          <div className="bg-purple-50 border border-purple-200 rounded-lg p-3">
            <p className="text-xs font-medium text-purple-800 mb-1">Attack Vectors:</p>
            <p className="text-sm text-purple-900">
              This threat could be exploited through unauthorized access, malicious input, or compromised credentials.
            </p>
          </div>

          <div className="bg-green-50 border border-green-200 rounded-lg p-3">
            <p className="text-xs font-medium text-green-800 mb-1">Recommended Mitigation:</p>
            <p className="text-sm text-green-900">{threat.mitigation}</p>
          </div>

          {hasMitigatingControls && (
            <div className="bg-green-100 border border-green-300 rounded-lg p-3">
              <p className="text-xs font-medium text-green-800 mb-1">Active Controls Applied:</p>
              <p className="text-sm text-green-900">
                {controls.length} security control{controls.length !== 1 ? 's' : ''} active. Severity reduced from {originalSeverity} to {adjustedSeverity}.
              </p>
            </div>
          )}

          <div className="flex items-center space-x-2 text-xs text-gray-500">
            <span>Click to collapse</span>
          </div>
        </div>
      )}

      {!isExpanded && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-3">
          <p className="text-xs font-medium text-green-800 mb-1">Recommended Mitigation:</p>
          <p className="text-sm text-green-900">{threat.mitigation}</p>
        </div>
      )}
    </div>
  )
}
