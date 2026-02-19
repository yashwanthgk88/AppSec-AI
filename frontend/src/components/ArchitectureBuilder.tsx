import { useState, useEffect, useCallback } from 'react'
import {
  Plus, Trash2, Upload, Server, Database, Globe, Shield, Lock,
  ArrowRight, ChevronDown, ChevronUp, AlertTriangle, CheckCircle,
  Zap, RefreshCw, Eye, X, FileImage, Layers, GitBranch
} from 'lucide-react'
import axios from 'axios'

// Types
interface Component {
  id: string
  name: string
  type: string
  technology: string
  trust_zone: string
  description: string
  data_handled: string[]
  data_stored: string[]
  security_controls: string[]
  exposed_ports: number[]
  third_party: boolean
  internal_only: boolean
}

interface DataFlow {
  id: string
  source_id: string
  target_id: string
  protocol: string
  data_types: string[]
  is_encrypted: boolean
  authentication: string
  description: string
}

interface TrustBoundary {
  id: string
  name: string
  zone: string
  component_ids: string[]
}

interface ComponentLibrary {
  component_types: Array<{ value: string; label: string }>
  trust_zones: Array<{ value: string; label: string; description: string }>
  data_classifications: Array<{ value: string; label: string; description: string }>
  security_controls: Record<string, Array<{ value: string; label: string }>>
  technology_options: Record<string, string[]>
  protocols: string[]
  auth_methods: string[]
  compliance_frameworks: string[]
  cloud_providers: string[]
}

interface ArchitectureBuilderProps {
  projectId: string
  onSave?: (data: any) => void
  initialData?: any
}

interface ValidationWarning {
  type: string
  component?: string
  flow?: string
  message: string
}

const defaultComponent: Component = {
  id: '',
  name: '',
  type: 'rest_api',
  technology: '',
  trust_zone: 'internal',
  description: '',
  data_handled: [],
  data_stored: [],
  security_controls: [],
  exposed_ports: [],
  third_party: false,
  internal_only: false,
}

const defaultDataFlow: DataFlow = {
  id: '',
  source_id: '',
  target_id: '',
  protocol: 'HTTPS',
  data_types: [],
  is_encrypted: true,
  authentication: 'JWT',
  description: '',
}

export default function ArchitectureBuilder({ projectId, onSave, initialData }: ArchitectureBuilderProps) {
  // State
  const [activeTab, setActiveTab] = useState<'components' | 'flows' | 'diagram' | 'review'>('components')
  const [components, setComponents] = useState<Component[]>([])
  const [dataFlows, setDataFlows] = useState<DataFlow[]>([])
  const [trustBoundaries, setTrustBoundaries] = useState<TrustBoundary[]>([])
  const [library, setLibrary] = useState<ComponentLibrary | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [extracting, setExtracting] = useState(false)
  const [warnings, setWarnings] = useState<ValidationWarning[]>([])
  const [extractedArchitecture, setExtractedArchitecture] = useState<any>(null)
  const [showMergeDialog, setShowMergeDialog] = useState(false)

  // Project metadata
  const [projectName, setProjectName] = useState('')
  const [description, setDescription] = useState('')
  const [deploymentModel, setDeploymentModel] = useState('cloud')
  const [cloudProviders, setCloudProviders] = useState<string[]>([])
  const [compliance, setCompliance] = useState<string[]>([])

  // Expanded states
  const [expandedComponents, setExpandedComponents] = useState<Set<string>>(new Set())
  const [expandedFlows, setExpandedFlows] = useState<Set<string>>(new Set())

  // Load component library
  useEffect(() => {
    const loadLibrary = async () => {
      try {
        const token = localStorage.getItem('token')
        const response = await axios.get('/api/architecture/component-library', {
          headers: { Authorization: `Bearer ${token}` }
        })
        setLibrary(response.data)
      } catch (error) {
        console.error('Failed to load component library:', error)
      } finally {
        setLoading(false)
      }
    }
    loadLibrary()
  }, [])

  // Load existing architecture
  useEffect(() => {
    const loadExisting = async () => {
      if (!projectId) return
      try {
        const token = localStorage.getItem('token')
        const response = await axios.get(`/api/projects/${projectId}/architecture`, {
          headers: { Authorization: `Bearer ${token}` }
        })
        if (response.data.structured_data) {
          const data = response.data.structured_data
          setProjectName(data.project_name || '')
          setDescription(data.description || '')
          setDeploymentModel(data.deployment_model || 'cloud')
          setCloudProviders(data.cloud_providers || [])
          setCompliance(data.compliance_requirements || [])
          setComponents(data.components || [])
          setDataFlows(data.data_flows || [])
          setTrustBoundaries(data.trust_boundaries || [])
        }
      } catch (error) {
        console.error('Failed to load existing architecture:', error)
      }
    }
    loadExisting()
  }, [projectId])

  // Generate unique ID
  const generateId = () => `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`

  // Component management
  const addComponent = () => {
    const newComponent: Component = {
      ...defaultComponent,
      id: generateId(),
      name: `Component ${components.length + 1}`,
    }
    setComponents([...components, newComponent])
    setExpandedComponents(new Set([...expandedComponents, newComponent.id]))
  }

  const updateComponent = (id: string, updates: Partial<Component>) => {
    setComponents(components.map(c => c.id === id ? { ...c, ...updates } : c))
  }

  const removeComponent = (id: string) => {
    setComponents(components.filter(c => c.id !== id))
    // Also remove related data flows
    setDataFlows(dataFlows.filter(f => f.source_id !== id && f.target_id !== id))
  }

  const toggleComponentExpand = (id: string) => {
    const newExpanded = new Set(expandedComponents)
    if (newExpanded.has(id)) {
      newExpanded.delete(id)
    } else {
      newExpanded.add(id)
    }
    setExpandedComponents(newExpanded)
  }

  // Data flow management
  const addDataFlow = () => {
    if (components.length < 2) {
      alert('Please add at least 2 components before creating data flows')
      return
    }
    const newFlow: DataFlow = {
      ...defaultDataFlow,
      id: generateId(),
      source_id: components[0]?.id || '',
      target_id: components[1]?.id || '',
    }
    setDataFlows([...dataFlows, newFlow])
    setExpandedFlows(new Set([...expandedFlows, newFlow.id]))
  }

  const updateDataFlow = (id: string, updates: Partial<DataFlow>) => {
    setDataFlows(dataFlows.map(f => f.id === id ? { ...f, ...updates } : f))
  }

  const removeDataFlow = (id: string) => {
    setDataFlows(dataFlows.filter(f => f.id !== id))
  }

  // Diagram upload and extraction
  const handleDiagramUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    setExtracting(true)
    try {
      const formData = new FormData()
      formData.append('file', file)

      const token = localStorage.getItem('token')
      const response = await axios.post(
        `/api/projects/${projectId}/architecture/extract-diagram`,
        formData,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'multipart/form-data'
          }
        }
      )

      if (response.data.success) {
        setExtractedArchitecture(response.data.architecture)
        // If we already have components, show merge dialog
        if (components.length > 0) {
          setShowMergeDialog(true)
        } else {
          // Apply extracted architecture directly
          applyExtractedArchitecture(response.data.architecture)
        }
      }
    } catch (error: any) {
      alert(error.response?.data?.detail || 'Failed to extract from diagram')
    } finally {
      setExtracting(false)
    }
  }

  const applyExtractedArchitecture = (arch: any) => {
    setProjectName(arch.project_name || projectName)
    setDescription(arch.description || description)
    setComponents(arch.components || [])
    setDataFlows(arch.data_flows || [])
    setTrustBoundaries(arch.trust_boundaries || [])
    setExtractedArchitecture(null)
  }

  const mergeArchitectures = async () => {
    if (!extractedArchitecture) return

    try {
      const token = localStorage.getItem('token')
      const response = await axios.post(
        `/api/projects/${projectId}/architecture/merge`,
        {
          manual: {
            project_name: projectName,
            description,
            components,
            data_flows: dataFlows,
            trust_boundaries: trustBoundaries,
            deployment_model: deploymentModel,
            cloud_providers: cloudProviders,
            compliance_requirements: compliance,
          },
          extracted: extractedArchitecture
        },
        { headers: { Authorization: `Bearer ${token}` } }
      )

      if (response.data.success) {
        const merged = response.data.merged_architecture
        setComponents(merged.components || [])
        setDataFlows(merged.data_flows || [])
        setTrustBoundaries(merged.trust_boundaries || [])
        setWarnings(response.data.warnings || [])
      }
    } catch (error: any) {
      alert(error.response?.data?.detail || 'Failed to merge architectures')
    } finally {
      setShowMergeDialog(false)
      setExtractedArchitecture(null)
    }
  }

  // Save architecture
  const saveArchitecture = async () => {
    setSaving(true)
    try {
      const token = localStorage.getItem('token')
      const response = await axios.post(
        `/api/projects/${projectId}/architecture/structured`,
        {
          project_name: projectName,
          description,
          components,
          data_flows: dataFlows,
          trust_boundaries: trustBoundaries,
          deployment_model: deploymentModel,
          cloud_providers: cloudProviders,
          compliance_requirements: compliance,
        },
        { headers: { Authorization: `Bearer ${token}` } }
      )

      if (response.data.success) {
        setWarnings(response.data.warnings || [])
        onSave?.(response.data)
        alert('Architecture saved successfully!')
      }
    } catch (error: any) {
      alert(error.response?.data?.detail || 'Failed to save architecture')
    } finally {
      setSaving(false)
    }
  }

  // Get component name by ID
  const getComponentName = (id: string) => {
    return components.find(c => c.id === id)?.name || 'Unknown'
  }

  // Get technology options for a component type
  const getTechnologyOptions = (type: string) => {
    return library?.technology_options[type] || []
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center p-12">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
        <span className="ml-3 text-gray-600">Loading component library...</span>
      </div>
    )
  }

  return (
    <div className="bg-white rounded-lg shadow-lg">
      {/* Header */}
      <div className="border-b border-gray-200 p-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold text-gray-900 flex items-center">
              <Layers className="w-6 h-6 mr-2 text-blue-600" />
              Architecture Builder
            </h2>
            <p className="text-sm text-gray-600 mt-1">
              Define your system architecture with components, data flows, and security controls
            </p>
          </div>
          <button
            onClick={saveArchitecture}
            disabled={saving}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center"
          >
            {saving ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <CheckCircle className="w-4 h-4 mr-2" />}
            Save Architecture
          </button>
        </div>

        {/* Tabs */}
        <div className="flex space-x-4 mt-6">
          {[
            { id: 'components', label: 'Components', icon: Server, count: components.length },
            { id: 'flows', label: 'Data Flows', icon: GitBranch, count: dataFlows.length },
            { id: 'diagram', label: 'Upload Diagram', icon: FileImage },
            { id: 'review', label: 'Review', icon: Eye, warnings: warnings.length },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center px-4 py-2 rounded-lg font-medium transition ${
                activeTab === tab.id
                  ? 'bg-blue-100 text-blue-700'
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              <tab.icon className="w-4 h-4 mr-2" />
              {tab.label}
              {tab.count !== undefined && (
                <span className="ml-2 px-2 py-0.5 bg-gray-200 text-gray-700 text-xs rounded-full">
                  {tab.count}
                </span>
              )}
              {tab.warnings !== undefined && tab.warnings > 0 && (
                <span className="ml-2 px-2 py-0.5 bg-yellow-200 text-yellow-800 text-xs rounded-full">
                  {tab.warnings}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="p-6">
        {/* Project Info (always visible) */}
        <div className="mb-6 grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Project Name</label>
            <input
              type="text"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="My Application"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Deployment Model</label>
            <select
              value={deploymentModel}
              onChange={(e) => setDeploymentModel(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
            >
              <option value="cloud">Cloud</option>
              <option value="on-premise">On-Premise</option>
              <option value="hybrid">Hybrid</option>
            </select>
          </div>
          <div className="col-span-2">
            <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              rows={2}
              placeholder="Brief description of your system..."
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Cloud Providers</label>
            <div className="flex flex-wrap gap-2">
              {library?.cloud_providers.map(provider => (
                <label key={provider} className="flex items-center">
                  <input
                    type="checkbox"
                    checked={cloudProviders.includes(provider)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setCloudProviders([...cloudProviders, provider])
                      } else {
                        setCloudProviders(cloudProviders.filter(p => p !== provider))
                      }
                    }}
                    className="mr-1"
                  />
                  <span className="text-sm">{provider}</span>
                </label>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Compliance Requirements</label>
            <div className="flex flex-wrap gap-2">
              {library?.compliance_frameworks.map(framework => (
                <label key={framework} className="flex items-center">
                  <input
                    type="checkbox"
                    checked={compliance.includes(framework)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setCompliance([...compliance, framework])
                      } else {
                        setCompliance(compliance.filter(c => c !== framework))
                      }
                    }}
                    className="mr-1"
                  />
                  <span className="text-sm">{framework}</span>
                </label>
              ))}
            </div>
          </div>
        </div>

        {/* Components Tab */}
        {activeTab === 'components' && (
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-semibold text-gray-900">System Components</h3>
              <button
                onClick={addComponent}
                className="px-3 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 flex items-center text-sm"
              >
                <Plus className="w-4 h-4 mr-1" />
                Add Component
              </button>
            </div>

            {components.length === 0 ? (
              <div className="text-center py-12 bg-gray-50 rounded-lg border-2 border-dashed border-gray-300">
                <Server className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <h4 className="text-lg font-medium text-gray-900 mb-2">No Components Yet</h4>
                <p className="text-gray-600 mb-4">Start by adding your system components</p>
                <button
                  onClick={addComponent}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Add Your First Component
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                {components.map((comp) => (
                  <ComponentCard
                    key={comp.id}
                    component={comp}
                    library={library!}
                    expanded={expandedComponents.has(comp.id)}
                    onToggle={() => toggleComponentExpand(comp.id)}
                    onChange={(updates) => updateComponent(comp.id, updates)}
                    onRemove={() => removeComponent(comp.id)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Data Flows Tab */}
        {activeTab === 'flows' && (
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-semibold text-gray-900">Data Flows</h3>
              <button
                onClick={addDataFlow}
                disabled={components.length < 2}
                className="px-3 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 flex items-center text-sm"
              >
                <Plus className="w-4 h-4 mr-1" />
                Add Data Flow
              </button>
            </div>

            {components.length < 2 ? (
              <div className="text-center py-12 bg-yellow-50 rounded-lg border border-yellow-200">
                <AlertTriangle className="w-12 h-12 text-yellow-500 mx-auto mb-4" />
                <h4 className="text-lg font-medium text-gray-900 mb-2">Add Components First</h4>
                <p className="text-gray-600">You need at least 2 components to define data flows</p>
              </div>
            ) : dataFlows.length === 0 ? (
              <div className="text-center py-12 bg-gray-50 rounded-lg border-2 border-dashed border-gray-300">
                <GitBranch className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <h4 className="text-lg font-medium text-gray-900 mb-2">No Data Flows Yet</h4>
                <p className="text-gray-600 mb-4">Define how data flows between your components</p>
                <button
                  onClick={addDataFlow}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Add Your First Data Flow
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                {dataFlows.map((flow) => (
                  <DataFlowCard
                    key={flow.id}
                    flow={flow}
                    components={components}
                    library={library!}
                    expanded={expandedFlows.has(flow.id)}
                    onToggle={() => {
                      const newExpanded = new Set(expandedFlows)
                      if (newExpanded.has(flow.id)) {
                        newExpanded.delete(flow.id)
                      } else {
                        newExpanded.add(flow.id)
                      }
                      setExpandedFlows(newExpanded)
                    }}
                    onChange={(updates) => updateDataFlow(flow.id, updates)}
                    onRemove={() => removeDataFlow(flow.id)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Diagram Upload Tab */}
        {activeTab === 'diagram' && (
          <div className="space-y-6">
            <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
              <div className="flex items-start space-x-3">
                <Zap className="w-5 h-5 text-purple-600 mt-0.5" />
                <div>
                  <h3 className="font-medium text-purple-900">AI-Powered Diagram Extraction</h3>
                  <p className="text-sm text-purple-700 mt-1">
                    Upload your architecture diagram and AI will automatically extract components,
                    data flows, and trust boundaries. You can then edit and refine the results.
                  </p>
                </div>
              </div>
            </div>

            <div className="border-2 border-dashed border-gray-300 rounded-lg p-12 text-center">
              <input
                type="file"
                accept="image/*"
                onChange={handleDiagramUpload}
                className="hidden"
                id="diagram-upload"
                disabled={extracting}
              />
              <label
                htmlFor="diagram-upload"
                className={`cursor-pointer ${extracting ? 'opacity-50' : ''}`}
              >
                {extracting ? (
                  <>
                    <RefreshCw className="w-16 h-16 text-purple-500 mx-auto mb-4 animate-spin" />
                    <h4 className="text-lg font-medium text-gray-900 mb-2">Extracting Architecture...</h4>
                    <p className="text-gray-600">AI is analyzing your diagram</p>
                  </>
                ) : (
                  <>
                    <Upload className="w-16 h-16 text-gray-400 mx-auto mb-4" />
                    <h4 className="text-lg font-medium text-gray-900 mb-2">Upload Architecture Diagram</h4>
                    <p className="text-gray-600 mb-4">PNG, JPG, or WebP (max 10MB)</p>
                    <span className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 inline-block">
                      Choose File
                    </span>
                  </>
                )}
              </label>
            </div>

            <div className="text-sm text-gray-500">
              <p className="font-medium mb-2">Tips for best results:</p>
              <ul className="list-disc list-inside space-y-1">
                <li>Use clear, high-resolution diagrams</li>
                <li>Label your components with names and technologies</li>
                <li>Use arrows to show data flow direction</li>
                <li>Mark trust boundaries with dotted lines or boxes</li>
              </ul>
            </div>
          </div>
        )}

        {/* Review Tab */}
        {activeTab === 'review' && (
          <div className="space-y-6">
            {/* Summary */}
            <div className="grid grid-cols-4 gap-4">
              <div className="bg-blue-50 rounded-lg p-4">
                <div className="text-2xl font-bold text-blue-700">{components.length}</div>
                <div className="text-sm text-blue-600">Components</div>
              </div>
              <div className="bg-green-50 rounded-lg p-4">
                <div className="text-2xl font-bold text-green-700">{dataFlows.length}</div>
                <div className="text-sm text-green-600">Data Flows</div>
              </div>
              <div className="bg-purple-50 rounded-lg p-4">
                <div className="text-2xl font-bold text-purple-700">
                  {components.reduce((acc, c) => acc + c.security_controls.length, 0)}
                </div>
                <div className="text-sm text-purple-600">Security Controls</div>
              </div>
              <div className="bg-yellow-50 rounded-lg p-4">
                <div className="text-2xl font-bold text-yellow-700">{warnings.length}</div>
                <div className="text-sm text-yellow-600">Warnings</div>
              </div>
            </div>

            {/* Warnings */}
            {warnings.length > 0 && (
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                <h4 className="font-medium text-yellow-900 flex items-center mb-3">
                  <AlertTriangle className="w-5 h-5 mr-2" />
                  Validation Warnings
                </h4>
                <div className="space-y-2">
                  {warnings.map((warning, idx) => (
                    <div key={idx} className="flex items-start text-sm text-yellow-800">
                      <span className="w-2 h-2 bg-yellow-500 rounded-full mt-1.5 mr-2 flex-shrink-0" />
                      <span>{warning.message}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Component Summary */}
            <div>
              <h4 className="font-medium text-gray-900 mb-3">Components by Trust Zone</h4>
              <div className="space-y-2">
                {library?.trust_zones.map(zone => {
                  const zoneComponents = components.filter(c => c.trust_zone === zone.value)
                  if (zoneComponents.length === 0) return null
                  return (
                    <div key={zone.value} className="bg-gray-50 rounded-lg p-3">
                      <div className="font-medium text-gray-700 mb-2">{zone.label}</div>
                      <div className="flex flex-wrap gap-2">
                        {zoneComponents.map(c => (
                          <span key={c.id} className="px-2 py-1 bg-white border border-gray-200 rounded text-sm">
                            {c.name}
                          </span>
                        ))}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Ready to Generate */}
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-medium text-green-900">Ready to Generate Threat Model</h4>
                  <p className="text-sm text-green-700">
                    Your architecture is ready. Save it and generate the threat model.
                  </p>
                </div>
                <button
                  onClick={saveArchitecture}
                  disabled={saving || components.length === 0}
                  className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50"
                >
                  {saving ? 'Saving...' : 'Save & Continue'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Merge Dialog */}
      {showMergeDialog && extractedArchitecture && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-lg w-full mx-4">
            <h3 className="text-lg font-bold text-gray-900 mb-4">Merge Architectures?</h3>
            <p className="text-gray-600 mb-4">
              You already have {components.length} components defined.
              The diagram extraction found {extractedArchitecture.components?.length || 0} components.
            </p>
            <div className="flex justify-end space-x-3">
              <button
                onClick={() => {
                  applyExtractedArchitecture(extractedArchitecture)
                  setShowMergeDialog(false)
                }}
                className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
              >
                Replace All
              </button>
              <button
                onClick={mergeArchitectures}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Merge Both
              </button>
              <button
                onClick={() => {
                  setShowMergeDialog(false)
                  setExtractedArchitecture(null)
                }}
                className="px-4 py-2 text-gray-600 hover:text-gray-800"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// Component Card Sub-component
interface ComponentCardProps {
  component: Component
  library: ComponentLibrary
  expanded: boolean
  onToggle: () => void
  onChange: (updates: Partial<Component>) => void
  onRemove: () => void
}

function ComponentCard({ component, library, expanded, onToggle, onChange, onRemove }: ComponentCardProps) {
  const typeLabel = library.component_types.find(t => t.value === component.type)?.label || component.type
  const zoneLabel = library.trust_zones.find(z => z.value === component.trust_zone)?.label || component.trust_zone
  const techOptions = library.technology_options[component.type] || []

  return (
    <div className="border border-gray-200 rounded-lg overflow-hidden">
      {/* Header */}
      <div
        className="flex items-center justify-between p-4 bg-gray-50 cursor-pointer hover:bg-gray-100"
        onClick={onToggle}
      >
        <div className="flex items-center space-x-3">
          <Server className="w-5 h-5 text-blue-600" />
          <div>
            <div className="font-medium text-gray-900">{component.name || 'Unnamed Component'}</div>
            <div className="text-sm text-gray-500">{typeLabel} • {zoneLabel}</div>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          {component.security_controls.length > 0 && (
            <span className="px-2 py-0.5 bg-green-100 text-green-700 text-xs rounded-full">
              {component.security_controls.length} controls
            </span>
          )}
          <button
            onClick={(e) => { e.stopPropagation(); onRemove(); }}
            className="p-1 text-red-500 hover:bg-red-50 rounded"
          >
            <Trash2 className="w-4 h-4" />
          </button>
          {expanded ? <ChevronUp className="w-5 h-5 text-gray-400" /> : <ChevronDown className="w-5 h-5 text-gray-400" />}
        </div>
      </div>

      {/* Expanded Content */}
      {expanded && (
        <div className="p-4 space-y-4 border-t border-gray-200">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Component Name *</label>
              <input
                type="text"
                value={component.name}
                onChange={(e) => onChange({ name: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                placeholder="e.g., User Service"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Component Type *</label>
              <select
                value={component.type}
                onChange={(e) => onChange({ type: e.target.value, technology: '' })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              >
                {library.component_types.map(t => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Technology</label>
              <select
                value={component.technology}
                onChange={(e) => onChange({ technology: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              >
                <option value="">Select technology...</option>
                {techOptions.map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
                <option value="other">Other</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Trust Zone *</label>
              <select
                value={component.trust_zone}
                onChange={(e) => onChange({ trust_zone: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              >
                {library.trust_zones.map(z => (
                  <option key={z.value} value={z.value}>{z.label}</option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
            <textarea
              value={component.description}
              onChange={(e) => onChange({ description: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              rows={2}
              placeholder="What does this component do?"
            />
          </div>

          {/* Data Classifications */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Data Handled</label>
            <div className="flex flex-wrap gap-2">
              {library.data_classifications.map(d => (
                <label key={d.value} className="flex items-center px-3 py-1 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={component.data_handled.includes(d.value)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        onChange({ data_handled: [...component.data_handled, d.value] })
                      } else {
                        onChange({ data_handled: component.data_handled.filter(x => x !== d.value) })
                      }
                    }}
                    className="mr-2"
                  />
                  <span className="text-sm" title={d.description}>{d.label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Security Controls */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              <Shield className="w-4 h-4 inline mr-1" />
              Security Controls
            </label>
            <div className="space-y-3">
              {Object.entries(library.security_controls).map(([category, controls]) => (
                <div key={category}>
                  <div className="text-xs font-medium text-gray-500 mb-1">{category}</div>
                  <div className="flex flex-wrap gap-2">
                    {controls.map(ctrl => (
                      <label key={ctrl.value} className={`flex items-center px-2 py-1 border rounded text-sm cursor-pointer ${
                        component.security_controls.includes(ctrl.value)
                          ? 'bg-green-50 border-green-300 text-green-700'
                          : 'border-gray-200 hover:bg-gray-50'
                      }`}>
                        <input
                          type="checkbox"
                          checked={component.security_controls.includes(ctrl.value)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              onChange({ security_controls: [...component.security_controls, ctrl.value] })
                            } else {
                              onChange({ security_controls: component.security_controls.filter(x => x !== ctrl.value) })
                            }
                          }}
                          className="mr-1.5"
                        />
                        {ctrl.label}
                      </label>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Additional Options */}
          <div className="flex items-center space-x-6 pt-2 border-t border-gray-200">
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={component.third_party}
                onChange={(e) => onChange({ third_party: e.target.checked })}
                className="mr-2"
              />
              <span className="text-sm text-gray-700">Third-party service</span>
            </label>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={component.internal_only}
                onChange={(e) => onChange({ internal_only: e.target.checked })}
                className="mr-2"
              />
              <span className="text-sm text-gray-700">Internal only (not exposed)</span>
            </label>
          </div>
        </div>
      )}
    </div>
  )
}

// Data Flow Card Sub-component
interface DataFlowCardProps {
  flow: DataFlow
  components: Component[]
  library: ComponentLibrary
  expanded: boolean
  onToggle: () => void
  onChange: (updates: Partial<DataFlow>) => void
  onRemove: () => void
}

function DataFlowCard({ flow, components, library, expanded, onToggle, onChange, onRemove }: DataFlowCardProps) {
  const sourceName = components.find(c => c.id === flow.source_id)?.name || 'Unknown'
  const targetName = components.find(c => c.id === flow.target_id)?.name || 'Unknown'

  return (
    <div className="border border-gray-200 rounded-lg overflow-hidden">
      {/* Header */}
      <div
        className="flex items-center justify-between p-4 bg-gray-50 cursor-pointer hover:bg-gray-100"
        onClick={onToggle}
      >
        <div className="flex items-center space-x-3">
          <div className="flex items-center">
            <span className="font-medium text-gray-900">{sourceName}</span>
            <ArrowRight className="w-4 h-4 mx-2 text-gray-400" />
            <span className="font-medium text-gray-900">{targetName}</span>
          </div>
          <span className="px-2 py-0.5 bg-blue-100 text-blue-700 text-xs rounded">{flow.protocol}</span>
          {flow.is_encrypted && (
            <span title="Connection uses encryption">
              <Lock className="w-4 h-4 text-green-600" />
            </span>
          )}
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={(e) => { e.stopPropagation(); onRemove(); }}
            className="p-1 text-red-500 hover:bg-red-50 rounded"
          >
            <Trash2 className="w-4 h-4" />
          </button>
          {expanded ? <ChevronUp className="w-5 h-5 text-gray-400" /> : <ChevronDown className="w-5 h-5 text-gray-400" />}
        </div>
      </div>

      {/* Expanded Content */}
      {expanded && (
        <div className="p-4 space-y-4 border-t border-gray-200">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Source Component</label>
              <select
                value={flow.source_id}
                onChange={(e) => onChange({ source_id: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              >
                {components.map(c => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Target Component</label>
              <select
                value={flow.target_id}
                onChange={(e) => onChange({ target_id: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              >
                {components.map(c => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Protocol</label>
              <select
                value={flow.protocol}
                onChange={(e) => onChange({ protocol: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              >
                {library.protocols.map(p => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Authentication</label>
              <select
                value={flow.authentication}
                onChange={(e) => onChange({ authentication: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              >
                {library.auth_methods.map(a => (
                  <option key={a} value={a}>{a}</option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Data Types Flowing</label>
            <input
              type="text"
              value={flow.data_types.join(', ')}
              onChange={(e) => onChange({ data_types: e.target.value.split(',').map(s => s.trim()).filter(Boolean) })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              placeholder="e.g., User credentials, API requests, JSON data"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
            <input
              type="text"
              value={flow.description}
              onChange={(e) => onChange({ description: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              placeholder="What is this data flow for?"
            />
          </div>

          <label className="flex items-center">
            <input
              type="checkbox"
              checked={flow.is_encrypted}
              onChange={(e) => onChange({ is_encrypted: e.target.checked })}
              className="mr-2"
            />
            <Lock className="w-4 h-4 mr-1 text-green-600" />
            <span className="text-sm text-gray-700">Data is encrypted in transit</span>
          </label>
        </div>
      )}
    </div>
  )
}
