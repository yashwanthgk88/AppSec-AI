import { useState, useEffect, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  Network, Shield, AlertTriangle, ArrowLeft, Download,
  Target, TrendingUp, ExternalLink, ChevronRight, Zap,
  AlertCircle, CheckCircle, XCircle, Activity, Route, Lock,
  RefreshCw, Layers, FileText, GitBranch, Clock, Upload,
  FileImage, File, X, Eye, Info, Trash2
} from 'lucide-react'
import axios from 'axios'
import mermaid from 'mermaid'
import { toPng, toSvg } from 'html-to-image'
import ArchitectureBuilder from '../components/ArchitectureBuilder'
import { ThreatStatusBadge, ThreatLifecycleSummary, ThreatChangeReason, ThreatStatus } from '../components/ThreatStatusBadge'
import { ThreatHistoryPanel, ThreatTimeline } from '../components/ThreatHistory'
import { Toast, useToast } from '../components/Toast'

// Initialize mermaid with enhanced config
mermaid.initialize({
  startOnLoad: true,
  theme: 'default',
  securityLevel: 'loose',
  flowchart: {
    useMaxWidth: true,
    htmlLabels: true,
    curve: 'basis',
    padding: 15,
    nodeSpacing: 50,
    rankSpacing: 50
  }
})

// Risk level configurations
const RISK_LEVELS = {
  critical: { color: 'red', bg: 'bg-red-600', text: 'text-red-600', border: 'border-red-500', light: 'bg-red-50' },
  high: { color: 'orange', bg: 'bg-orange-500', text: 'text-orange-600', border: 'border-orange-500', light: 'bg-orange-50' },
  medium: { color: 'yellow', bg: 'bg-yellow-500', text: 'text-yellow-600', border: 'border-yellow-500', light: 'bg-yellow-50' },
  low: { color: 'green', bg: 'bg-green-500', text: 'text-green-600', border: 'border-green-500', light: 'bg-green-50' }
}

const SEVERITY_COLORS = {
  critical: 'text-red-700 bg-red-100 border-red-300',
  high: 'text-orange-700 bg-orange-100 border-orange-300',
  medium: 'text-yellow-700 bg-yellow-100 border-yellow-300',
  low: 'text-green-700 bg-green-100 border-green-300'
}

// Sample architecture for demo purposes
const SAMPLE_ARCHITECTURE = `E-Commerce Web Application

The system consists of the following components:

1. Web Frontend (React SPA)
   - Serves end users via browser
   - Handles user authentication flows
   - Displays product catalog and shopping cart

2. API Gateway (Node.js/Express)
   - Routes and authenticates incoming API requests
   - Rate limiting and request validation
   - JWT token verification

3. Authentication Service
   - User registration and login
   - Password hashing with bcrypt
   - JWT token generation and refresh
   - OAuth2 integration (Google, GitHub)

4. Product Service (Python/FastAPI)
   - Product catalog management
   - Inventory tracking
   - Search and filtering

5. Order Service (Python/FastAPI)
   - Shopping cart management
   - Order processing and status tracking
   - Order history

6. Payment Service
   - Stripe API integration
   - Payment processing
   - Refund handling

7. Database Layer
   - PostgreSQL for user data and orders
   - Redis for session management and caching
   - Elasticsearch for product search

8. External Integrations
   - Stripe for payments
   - SendGrid for email notifications
   - AWS S3 for image storage

Data Flows:
- Users → Frontend → API Gateway → Backend Services
- Backend Services → PostgreSQL/Redis
- Payment Service → Stripe API
- Order Service → SendGrid (email notifications)`

// Progress steps for threat model generation
const GENERATION_STEPS = [
  { id: 1, name: 'Analyzing Architecture', description: 'Parsing system components and data flows' },
  { id: 2, name: 'Generating STRIDE Threats', description: 'Identifying security threats using STRIDE methodology' },
  { id: 3, name: 'Mapping MITRE ATT&CK', description: 'Correlating threats with MITRE ATT&CK framework' },
  { id: 4, name: 'Building Attack Paths', description: 'Analyzing potential attack vectors' },
  { id: 5, name: 'Finalizing', description: 'Completing threat model generation' },
]

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
  const [activeTab, setActiveTab] = useState<'threats' | 'attack-paths' | 'mitre' | 'history'>('threats')
  const [regenerating, setRegenerating] = useState(false)
  const [showHistoryPanel, setShowHistoryPanel] = useState(false)
  const [uploadedDocs, setUploadedDocs] = useState<File[]>([])
  const [analyzingDocs, setAnalyzingDocs] = useState(false)
  const [docAnalysisProgress, setDocAnalysisProgress] = useState(0)
  const [extractedFromDocs, setExtractedFromDocs] = useState<any>(null)
  const [generationProgress, setGenerationProgress] = useState(0)
  const [currentStep, setCurrentStep] = useState(0)
  const [generationComplete, setGenerationComplete] = useState(false)
  const [inputMode, setInputMode] = useState<'select' | 'builder' | 'sample' | 'docs'>('select')

  // Toast notifications
  const { toasts, addToast, removeToast, warning, error: showError, info } = useToast()

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

  // Poll status endpoint for generation progress
  const pollGenerationStatus = async () => {
    const token = localStorage.getItem('token')
    let attempts = 0
    const maxAttempts = 120 // 10 minutes max (5 second intervals)

    const poll = async () => {
      try {
        const response = await axios.get(`/api/projects/${id}/threat-model/status`, {
          headers: { Authorization: `Bearer ${token}` },
        })

        const { status, step, progress, threat_count, error } = response.data

        // Map backend step to frontend step index
        const stepMapping: { [key: string]: number } = {
          'starting': 1,
          'analyzing': 1,
          'generating': 2,
          'saving': 4,
          'done': 5
        }
        setCurrentStep(stepMapping[step] || 1)
        setGenerationProgress(progress || 0)

        if (status === 'completed') {
          setGenerationProgress(100)
          setCurrentStep(GENERATION_STEPS.length)
          setGenerationComplete(true)
          // Show success for 2 seconds, then fetch and display
          setTimeout(async () => {
            await fetchThreatModel()
            setRegenerating(false)
            setGenerationProgress(0)
            setCurrentStep(0)
            setGenerationComplete(false)
          }, 2000)
          return
        }

        if (status === 'failed') {
          alert(error || 'Failed to generate threat model. Please try again.')
          setRegenerating(false)
          setGenerationProgress(0)
          setCurrentStep(0)
          return
        }

        // Continue polling if still in progress
        attempts++
        if (attempts < maxAttempts) {
          setTimeout(poll, 5000) // Poll every 5 seconds
        } else {
          alert('Generation is taking too long. Please check back later.')
          setRegenerating(false)
        }
      } catch (error) {
        console.error('Failed to poll status:', error)
        attempts++
        if (attempts < maxAttempts) {
          setTimeout(poll, 5000)
        }
      }
    }

    // Start polling after a brief delay
    setTimeout(poll, 2000)
  }

  const regenerateThreatModel = async () => {
    setRegenerating(true)
    setGenerationComplete(false)
    setCurrentStep(1)
    setGenerationProgress(5)

    try {
      const token = localStorage.getItem('token')
      const response = await axios.post(`/api/projects/${id}/threat-model/regenerate`, {}, {
        headers: { Authorization: `Bearer ${token}` },
      })

      // Start polling for status
      pollGenerationStatus()
    } catch (error: any) {
      console.error('Failed to start threat model generation:', error)
      const errorMessage = error.response?.data?.detail || 'Failed to start threat model generation. Please try again.'
      alert(errorMessage)
      setRegenerating(false)
      setGenerationProgress(0)
      setCurrentStep(0)
    }
  }

  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [deleting, setDeleting] = useState(false)

  const deleteThreatModel = async () => {
    setDeleting(true)
    try {
      const token = localStorage.getItem('token')
      await axios.delete(`/api/projects/${id}/threat-model`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      setThreatModel(null)
      setShowDeleteConfirm(false)
      info('Threat model deleted successfully')
    } catch (error: any) {
      console.error('Failed to delete threat model:', error)
      const errorMessage = error.response?.data?.detail || 'Failed to delete threat model. Please try again.'
      showError(errorMessage)
    } finally {
      setDeleting(false)
    }
  }

  const generateWithSample = async () => {
    setRegenerating(true)
    setGenerationComplete(false)
    setCurrentStep(1)
    setGenerationProgress(5)

    try {
      const token = localStorage.getItem('token')
      // First update the project with sample architecture
      await axios.put(`/api/projects/${id}`, {
        architecture_doc: SAMPLE_ARCHITECTURE
      }, {
        headers: { Authorization: `Bearer ${token}` },
      })

      // Then start threat model generation
      await axios.post(`/api/projects/${id}/threat-model/regenerate`, {}, {
        headers: { Authorization: `Bearer ${token}` },
      })

      setInputMode('select')

      // Start polling for status
      pollGenerationStatus()
    } catch (error: any) {
      console.error('Failed to generate threat model with sample:', error)
      const errorMessage = error.response?.data?.detail || 'Failed to generate threat model. Please try again.'
      alert(errorMessage)
      setRegenerating(false)
      setGenerationProgress(0)
      setCurrentStep(0)
    }
  }

  const handleArchitectureSubmit = async (architecture: any) => {
    // Validate that sufficient data is provided
    if (!architecture || !architecture.components || architecture.components.length === 0) {
      warning('Please add at least one component to your architecture before generating the threat model.')
      return
    }

    // Check if components have meaningful data
    const hasValidComponent = architecture.components.some((c: any) =>
      c.name && c.name.trim() && c.type
    )
    if (!hasValidComponent) {
      warning('Please provide component names and types for accurate threat analysis.')
      return
    }

    setRegenerating(true)
    setGenerationComplete(false)
    setCurrentStep(1)
    setGenerationProgress(5)

    try {
      const token = localStorage.getItem('token')

      // Convert structured architecture to detailed text description for threat modeling
      const architectureDoc = convertArchitectureToDoc(architecture)

      // Update the project with the structured architecture
      await axios.put(`/api/projects/${id}`, {
        architecture_doc: architectureDoc
      }, {
        headers: { Authorization: `Bearer ${token}` },
      })

      // Start threat model generation
      await axios.post(`/api/projects/${id}/threat-model/regenerate`, {}, {
        headers: { Authorization: `Bearer ${token}` },
      })

      setInputMode('select')

      // Start polling for status
      pollGenerationStatus()
    } catch (error: any) {
      console.error('Failed to generate threat model:', error)
      const errorMessage = error.response?.data?.detail || 'Failed to generate threat model. Please try again.'
      alert(errorMessage)
      setRegenerating(false)
      setGenerationProgress(0)
      setCurrentStep(0)
    }
  }

  // Convert structured architecture to detailed documentation
  const convertArchitectureToDoc = (arch: any): string => {
    const lines: string[] = []

    lines.push(`# Application Architecture`)
    lines.push('')

    // Components
    if (arch.components && arch.components.length > 0) {
      lines.push('## Components')
      lines.push('')

      // Group by trust zone
      const byZone: { [key: string]: any[] } = {}
      arch.components.forEach((c: any) => {
        const zone = c.trust_zone || 'unclassified'
        if (!byZone[zone]) byZone[zone] = []
        byZone[zone].push(c)
      })

      Object.entries(byZone).forEach(([zone, components]) => {
        lines.push(`### Trust Zone: ${zone.replace(/_/g, ' ').toUpperCase()}`)
        lines.push('')

        components.forEach((c: any) => {
          lines.push(`#### ${c.name} (${c.type})`)
          lines.push(`- Technology: ${c.technology}`)
          if (c.description) lines.push(`- Description: ${c.description}`)
          if (c.data_handled && c.data_handled.length > 0) {
            lines.push(`- Data Handled: ${c.data_handled.join(', ')}`)
          }
          if (c.security_controls && c.security_controls.length > 0) {
            lines.push(`- Security Controls: ${c.security_controls.join(', ')}`)
          }
          if (c.ports && c.ports.length > 0) {
            lines.push(`- Exposed Ports: ${c.ports.join(', ')}`)
          }
          if (c.authentication_method) {
            lines.push(`- Authentication: ${c.authentication_method}`)
          }
          lines.push('')
        })
      })
    }

    // Data Flows
    if (arch.data_flows && arch.data_flows.length > 0) {
      lines.push('## Data Flows')
      lines.push('')

      arch.data_flows.forEach((flow: any, idx: number) => {
        const sourceComp = arch.components?.find((c: any) => c.id === flow.source_id)
        const targetComp = arch.components?.find((c: any) => c.id === flow.target_id)
        const sourceName = sourceComp?.name || flow.source_id
        const targetName = targetComp?.name || flow.target_id

        lines.push(`### Flow ${idx + 1}: ${sourceName} → ${targetName}`)
        lines.push(`- Protocol: ${flow.protocol}`)
        lines.push(`- Encrypted: ${flow.is_encrypted ? 'Yes' : 'No'}`)
        if (flow.authentication) lines.push(`- Authentication: ${flow.authentication}`)
        if (flow.data_types && flow.data_types.length > 0) {
          lines.push(`- Data Types: ${flow.data_types.join(', ')}`)
        }
        if (flow.description) lines.push(`- Description: ${flow.description}`)
        lines.push('')
      })
    }

    // External Integrations
    const externalComponents = arch.components?.filter((c: any) =>
      c.type?.includes('external') || c.trust_zone === 'internet'
    ) || []

    if (externalComponents.length > 0) {
      lines.push('## External Integrations')
      lines.push('')
      externalComponents.forEach((c: any) => {
        lines.push(`- ${c.name}: ${c.description || c.technology}`)
      })
      lines.push('')
    }

    // Security Summary
    const allControls = new Set<string>()
    arch.components?.forEach((c: any) => {
      c.security_controls?.forEach((ctrl: string) => allControls.add(ctrl))
    })

    if (allControls.size > 0) {
      lines.push('## Security Controls Summary')
      lines.push('')
      Array.from(allControls).sort().forEach((ctrl: string) => {
        lines.push(`- ${ctrl.replace(/_/g, ' ')}`)
      })
      lines.push('')
    }

    return lines.join('\n')
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
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Analyzing architecture and generating threat model...</p>
        </div>
      </div>
    )
  }

  if (!threatModel) {
    // Show generation progress if generating
    if (regenerating) {
      return (
        <div className="card p-8">
          <div className="border border-gray-200 rounded-lg p-4 bg-white">
            {generationComplete ? (
              <div className="text-center py-4">
                <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <CheckCircle className="w-10 h-10 text-green-600" />
                </div>
                <h3 className="text-lg font-semibold text-green-700 mb-2">Threat Model Generated!</h3>
                <p className="text-gray-600">Loading your threat analysis...</p>
                <div className="mt-4">
                  <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-green-600 mx-auto"></div>
                </div>
              </div>
            ) : (
              <>
                <div className="mb-4">
                  <div className="flex justify-between text-sm mb-2">
                    <span className="font-medium text-gray-700">Generating Threat Model...</span>
                    <span className="text-gray-500">{Math.round(generationProgress)}%</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2.5">
                    <div
                      className="bg-primary-600 h-2.5 rounded-full transition-all duration-500 ease-out"
                      style={{ width: `${generationProgress}%` }}
                    ></div>
                  </div>
                </div>
                <div className="space-y-2">
                  {GENERATION_STEPS.map((step, index) => (
                    <div
                      key={step.id}
                      className={`flex items-center space-x-3 text-sm ${
                        currentStep > index
                          ? 'text-green-600'
                          : currentStep === index
                          ? 'text-primary-600 font-medium'
                          : 'text-gray-400'
                      }`}
                    >
                      <div className={`w-5 h-5 rounded-full flex items-center justify-center ${
                        currentStep > index
                          ? 'bg-green-100'
                          : currentStep === index
                          ? 'bg-primary-100'
                          : 'bg-gray-100'
                      }`}>
                        {currentStep > index ? (
                          <CheckCircle className="w-4 h-4" />
                        ) : currentStep === index ? (
                          <div className="w-2 h-2 bg-primary-600 rounded-full animate-pulse" />
                        ) : (
                          <div className="w-2 h-2 bg-gray-300 rounded-full" />
                        )}
                      </div>
                      <div>
                        <span>{step.name}</span>
                        {currentStep === index && (
                          <span className="text-xs text-gray-500 ml-2">— {step.description}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      )
    }

    // Show Architecture Builder
    if (inputMode === 'builder') {
      return (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <button
                onClick={() => setInputMode('select')}
                className="inline-flex items-center text-sm text-gray-600 hover:text-gray-900 mb-2"
              >
                <ArrowLeft className="w-4 h-4 mr-1" />
                Back to Options
              </button>
              <h1 className="text-2xl font-bold text-gray-900">Build Your Architecture</h1>
              <p className="text-gray-600 mt-1">
                Define components, data flows, and security controls for comprehensive threat modeling
              </p>
            </div>
          </div>

          <ArchitectureBuilder
            projectId={id || ''}
            onSave={handleArchitectureSubmit}
          />
        </div>
      )
    }

    // Show Sample Architecture option
    if (inputMode === 'sample') {
      return (
        <div className="card p-8">
          <div className="flex items-center mb-6">
            <button
              onClick={() => setInputMode('select')}
              className="inline-flex items-center text-sm text-gray-600 hover:text-gray-900"
            >
              <ArrowLeft className="w-4 h-4 mr-1" />
              Back to Options
            </button>
          </div>

          <div className="text-center mb-6">
            <Activity className="w-12 h-12 text-blue-500 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-gray-900 mb-2">Sample E-Commerce Architecture</h3>
            <p className="text-sm text-gray-600">
              This sample describes a typical e-commerce application with authentication, payment processing, and multiple backend services.
            </p>
          </div>

          <pre className="bg-gray-50 border border-gray-200 rounded-lg p-4 text-xs text-gray-700 max-h-64 overflow-y-auto mb-6 whitespace-pre-wrap">
            {SAMPLE_ARCHITECTURE}
          </pre>

          <button
            onClick={generateWithSample}
            disabled={regenerating}
            className="btn btn-primary w-full inline-flex items-center justify-center space-x-2"
          >
            <Zap className="w-4 h-4" />
            <span>Generate Threat Model with Sample</span>
          </button>
        </div>
      )
    }

    // Show Document Upload mode
    if (inputMode === 'docs') {
      return (
        <DocumentUploadSection
          projectId={id || ''}
          onBack={() => setInputMode('select')}
          uploadedDocs={uploadedDocs}
          setUploadedDocs={setUploadedDocs}
          analyzingDocs={analyzingDocs}
          setAnalyzingDocs={setAnalyzingDocs}
          docAnalysisProgress={docAnalysisProgress}
          setDocAnalysisProgress={setDocAnalysisProgress}
          extractedFromDocs={extractedFromDocs}
          setExtractedFromDocs={setExtractedFromDocs}
          onShowNotification={warning}
          onGenerateThreatModel={async (architecture: any) => {
            // Validate extracted architecture has sufficient data
            if (!architecture || !architecture.components || architecture.components.length === 0) {
              warning('No architecture components could be extracted from the documents. Please upload clearer diagrams or documents with more architectural details.')
              return
            }

            // Use the extracted architecture to generate threat model
            setRegenerating(true)
            setInputMode('select')
            try {
              const token = localStorage.getItem('token')
              await axios.post(
                `/api/projects/${id}/threat-model/regenerate`,
                { architecture_data: architecture },
                { headers: { Authorization: `Bearer ${token}` } }
              )
              pollGenerationStatus()
            } catch (error: any) {
              console.error('Failed to generate threat model:', error)
              showError('Failed to generate threat model. Please try again.')
              setRegenerating(false)
            }
          }}
        />
      )
    }

    // Default: Show input method selection
    return (
      <div className="card p-8">
        <div className="text-center mb-8">
          <Network className="w-16 h-16 text-gray-300 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-gray-900 mb-2">Generate Threat Model</h3>
          <p className="text-gray-600">
            Choose how you want to describe your application architecture for AI-powered STRIDE analysis.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          {/* Option 1: Build Architecture */}
          <div
            onClick={() => setInputMode('builder')}
            className="border-2 border-gray-200 rounded-xl p-6 hover:border-primary-500 hover:shadow-lg transition cursor-pointer group"
          >
            <div className="w-14 h-14 bg-primary-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-primary-200 transition">
              <Layers className="w-7 h-7 text-primary-600" />
            </div>
            <h4 className="font-semibold text-gray-900 mb-2">Build Architecture</h4>
            <p className="text-sm text-gray-600 mb-4">
              Use the interactive builder to define components, data flows, and security controls.
              Upload diagrams for AI extraction.
            </p>
            <div className="space-y-2">
              <div className="flex items-center text-xs text-gray-500">
                <CheckCircle className="w-3 h-3 text-green-500 mr-2" />
                <span>30+ component types</span>
              </div>
              <div className="flex items-center text-xs text-gray-500">
                <CheckCircle className="w-3 h-3 text-green-500 mr-2" />
                <span>40+ security controls</span>
              </div>
              <div className="flex items-center text-xs text-gray-500">
                <CheckCircle className="w-3 h-3 text-green-500 mr-2" />
                <span>Diagram AI extraction</span>
              </div>
              <div className="flex items-center text-xs text-gray-500">
                <CheckCircle className="w-3 h-3 text-green-500 mr-2" />
                <span>Validation warnings</span>
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-gray-100">
              <span className="text-xs font-medium text-primary-600 group-hover:text-primary-700">
                Recommended for comprehensive analysis →
              </span>
            </div>
          </div>

          {/* Option 2: Upload Documents */}
          <div
            onClick={() => setInputMode('docs')}
            className="border-2 border-gray-200 rounded-xl p-6 hover:border-blue-500 hover:shadow-lg transition cursor-pointer group"
          >
            <div className="w-14 h-14 bg-blue-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-blue-200 transition">
              <Upload className="w-7 h-7 text-blue-600" />
            </div>
            <h4 className="font-semibold text-gray-900 mb-2">Upload Documents</h4>
            <p className="text-sm text-gray-600 mb-4">
              Upload design documents, architecture diagrams, or use case documents for AI analysis.
            </p>
            <div className="space-y-2">
              <div className="flex items-center text-xs text-gray-500">
                <CheckCircle className="w-3 h-3 text-green-500 mr-2" />
                <span>PDF, PNG, JPG, DOCX</span>
              </div>
              <div className="flex items-center text-xs text-gray-500">
                <CheckCircle className="w-3 h-3 text-green-500 mr-2" />
                <span>Multiple file support</span>
              </div>
              <div className="flex items-center text-xs text-gray-500">
                <CheckCircle className="w-3 h-3 text-green-500 mr-2" />
                <span>Diagram analysis with AI vision</span>
              </div>
              <div className="flex items-center text-xs text-gray-500">
                <CheckCircle className="w-3 h-3 text-green-500 mr-2" />
                <span>Text content extraction</span>
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-gray-100">
              <span className="text-xs font-medium text-blue-600 group-hover:text-blue-700">
                Best for existing documentation →
              </span>
            </div>
          </div>

          {/* Option 3: Sample Architecture */}
          <div
            onClick={() => setInputMode('sample')}
            className="border-2 border-gray-200 rounded-xl p-6 hover:border-green-500 hover:shadow-lg transition cursor-pointer group"
          >
            <div className="w-14 h-14 bg-green-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-green-200 transition">
              <Activity className="w-7 h-7 text-green-600" />
            </div>
            <h4 className="font-semibold text-gray-900 mb-2">Try Sample</h4>
            <p className="text-sm text-gray-600 mb-4">
              See threat modeling in action with a sample e-commerce architecture.
            </p>
            <div className="space-y-2">
              <div className="flex items-center text-xs text-gray-500">
                <CheckCircle className="w-3 h-3 text-green-500 mr-2" />
                <span>Pre-built example</span>
              </div>
              <div className="flex items-center text-xs text-gray-500">
                <CheckCircle className="w-3 h-3 text-green-500 mr-2" />
                <span>Instant demo</span>
              </div>
              <div className="flex items-center text-xs text-gray-500">
                <CheckCircle className="w-3 h-3 text-green-500 mr-2" />
                <span>Learn the workflow</span>
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-gray-100">
              <span className="text-xs font-medium text-green-600 group-hover:text-green-700">
                Great for first-time users →
              </span>
            </div>
          </div>
        </div>

        <div className="text-center">
          <Link to={`/projects/${id}`} className="text-sm text-gray-500 hover:text-gray-700">
            ← Back to Project
          </Link>
        </div>
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
      threat.mitigation?.toLowerCase().includes(query) ||
      threat.cwe?.toLowerCase().includes(query)
    )
  }

  const currentDFD = selectedLevel === 0 ? threatModel.dfd_level_0 : threatModel.dfd_level_1
  const riskLevel = threatModel.risk_level || 'medium'
  const riskScore = threatModel.risk_score || 50
  const attackPaths = threatModel.attack_paths || []
  const mitreMapping = threatModel.mitre_mapping || {}

  // Calculate threat stats
  const threatsBySeverity = {
    critical: filteredThreats.filter((t: any) => t.severity === 'critical').length,
    high: filteredThreats.filter((t: any) => t.severity === 'high').length,
    medium: filteredThreats.filter((t: any) => t.severity === 'medium').length,
    low: filteredThreats.filter((t: any) => t.severity === 'low').length
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
          <h1 className="text-3xl font-bold text-gray-900">{threatModel.name}</h1>
          <p className="text-gray-600 mt-1">AI-Powered Threat Modeling with STRIDE & MITRE ATT&CK</p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={regenerateThreatModel}
            disabled={regenerating}
            className="btn btn-secondary inline-flex items-center space-x-2"
            title="Regenerate threat model with latest analysis"
          >
            <RefreshCw className={`w-4 h-4 ${regenerating ? 'animate-spin' : ''}`} />
            <span>{regenerating ? 'Regenerating...' : 'Regenerate'}</span>
          </button>
          <button
            onClick={() => setShowDeleteConfirm(true)}
            disabled={regenerating || deleting}
            className="btn btn-secondary inline-flex items-center space-x-2 text-red-600 hover:text-red-700 hover:border-red-300"
            title="Delete threat model"
          >
            <Trash2 className="w-4 h-4" />
            <span>Delete</span>
          </button>
          <RiskGauge score={riskScore} level={riskLevel} />
        </div>
      </div>

      {/* Risk Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div className="card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wide">Risk Score</p>
              <p className={`text-2xl font-bold ${RISK_LEVELS[riskLevel as keyof typeof RISK_LEVELS]?.text || 'text-gray-900'}`}>
                {riskScore}/100
              </p>
            </div>
            <div className={`w-12 h-12 rounded-full ${RISK_LEVELS[riskLevel as keyof typeof RISK_LEVELS]?.bg || 'bg-gray-500'} flex items-center justify-center`}>
              <Activity className="w-6 h-6 text-white" />
            </div>
          </div>
        </div>

        <div className="card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wide">Total Threats</p>
              <p className="text-2xl font-bold text-gray-900">{threatModel.threat_count}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-red-500" />
          </div>
        </div>

        <div className="card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wide">Attack Paths</p>
              <p className="text-2xl font-bold text-gray-900">{attackPaths.length}</p>
            </div>
            <Route className="w-8 h-8 text-purple-500" />
          </div>
        </div>

        <div className="card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wide">Components</p>
              <p className="text-2xl font-bold text-gray-900">{threatModel.components_count || 0}</p>
            </div>
            <Network className="w-8 h-8 text-blue-500" />
          </div>
        </div>

        <div className="card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wide">MITRE Techniques</p>
              <p className="text-2xl font-bold text-gray-900">{mitreMapping.total_techniques || Object.keys(mitreMapping.techniques || mitreMapping).filter(k => !['attack_chain', 'total_techniques', 'tactics_covered'].includes(k)).length}</p>
            </div>
            <Target className="w-8 h-8 text-orange-500" />
          </div>
        </div>
      </div>

      {/* Threat Severity Breakdown */}
      <div className="card p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-semibold text-gray-900">Threat Severity Distribution</h3>
          <div className="flex items-center space-x-4 text-sm">
            <span className="flex items-center"><span className="w-3 h-3 rounded-full bg-red-600 mr-1"></span> Critical: {threatsBySeverity.critical}</span>
            <span className="flex items-center"><span className="w-3 h-3 rounded-full bg-orange-500 mr-1"></span> High: {threatsBySeverity.high}</span>
            <span className="flex items-center"><span className="w-3 h-3 rounded-full bg-yellow-500 mr-1"></span> Medium: {threatsBySeverity.medium}</span>
            <span className="flex items-center"><span className="w-3 h-3 rounded-full bg-green-500 mr-1"></span> Low: {threatsBySeverity.low}</span>
          </div>
        </div>
        <div className="flex h-4 rounded-full overflow-hidden bg-gray-200">
          {threatsBySeverity.critical > 0 && (
            <div className="bg-red-600" style={{ width: `${(threatsBySeverity.critical / threatModel.threat_count) * 100}%` }}></div>
          )}
          {threatsBySeverity.high > 0 && (
            <div className="bg-orange-500" style={{ width: `${(threatsBySeverity.high / threatModel.threat_count) * 100}%` }}></div>
          )}
          {threatsBySeverity.medium > 0 && (
            <div className="bg-yellow-500" style={{ width: `${(threatsBySeverity.medium / threatModel.threat_count) * 100}%` }}></div>
          )}
          {threatsBySeverity.low > 0 && (
            <div className="bg-green-500" style={{ width: `${(threatsBySeverity.low / threatModel.threat_count) * 100}%` }}></div>
          )}
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

      {/* Eraser AI Professional Diagrams */}
      {threatModel.eraser_diagrams?.enabled && (
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold text-gray-900 flex items-center">
              <Zap className="w-5 h-5 mr-2 text-purple-500" />
              Eraser AI Professional Diagrams
              <span className="ml-2 text-sm font-normal text-gray-500">
                ({threatModel.eraser_diagrams_count || 0} diagrams)
              </span>
            </h2>
            <span className="px-3 py-1 bg-purple-100 text-purple-700 rounded-full text-sm">
              Powered by Eraser AI
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Object.entries(threatModel.eraser_diagrams?.diagrams || {}).map(([name, diagram]: [string, any]) => (
              diagram.success && (
                <div key={name} className="border rounded-lg overflow-hidden hover:shadow-lg transition-shadow">
                  <div className="bg-gray-50 px-4 py-2 border-b">
                    <h3 className="font-medium text-gray-800 capitalize">
                      {name.replace(/_/g, ' ')}
                    </h3>
                  </div>
                  <div className="relative aspect-video bg-white">
                    {diagram.image_url ? (
                      <img
                        src={diagram.image_url}
                        alt={`${name} diagram`}
                        className="w-full h-full object-contain"
                      />
                    ) : (
                      <div className="flex items-center justify-center h-full text-gray-400">
                        <Network className="w-12 h-12" />
                      </div>
                    )}
                  </div>
                  <div className="p-3 bg-gray-50 flex justify-between items-center">
                    {diagram.editor_url && (
                      <a
                        href={diagram.editor_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-indigo-600 hover:text-indigo-800 flex items-center"
                      >
                        <ExternalLink className="w-4 h-4 mr-1" />
                        Edit in Eraser
                      </a>
                    )}
                    {diagram.image_url && (
                      <a
                        href={diagram.image_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-gray-600 hover:text-gray-800 flex items-center"
                      >
                        <Download className="w-4 h-4 mr-1" />
                        Download
                      </a>
                    )}
                  </div>
                </div>
              )
            ))}
          </div>

          {(!threatModel.eraser_diagrams?.diagrams || Object.keys(threatModel.eraser_diagrams.diagrams).length === 0) && (
            <div className="text-center py-8 text-gray-500">
              <Network className="w-12 h-12 mx-auto mb-2 opacity-50" />
              <p>No Eraser diagrams available. Regenerate the threat model to create professional diagrams.</p>
            </div>
          )}
        </div>
      )}

      {/* Main Content Tabs */}
      <div className="card">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6" aria-label="Tabs">
            <button
              onClick={() => setActiveTab('threats')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'threats'
                  ? 'border-primary-600 text-primary-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4" />
                <span>STRIDE Threats</span>
                <span className="bg-gray-100 text-gray-600 px-2 py-0.5 rounded-full text-xs">
                  {threatModel.threat_count}
                </span>
              </div>
            </button>
            <button
              onClick={() => setActiveTab('attack-paths')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'attack-paths'
                  ? 'border-primary-600 text-primary-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                <Route className="w-4 h-4" />
                <span>Attack Paths</span>
                <span className="bg-purple-100 text-purple-600 px-2 py-0.5 rounded-full text-xs">
                  {attackPaths.length}
                </span>
              </div>
            </button>
            <button
              onClick={() => setActiveTab('mitre')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'mitre'
                  ? 'border-primary-600 text-primary-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                <Target className="w-4 h-4" />
                <span>MITRE ATT&CK</span>
                <span className="bg-orange-100 text-orange-600 px-2 py-0.5 rounded-full text-xs">
                  {mitreMapping.total_techniques || Object.keys(mitreMapping.techniques || {}).length}
                </span>
              </div>
            </button>
            <button
              onClick={() => setActiveTab('history')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'history'
                  ? 'border-primary-600 text-primary-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                <GitBranch className="w-4 h-4" />
                <span>Version History</span>
              </div>
            </button>
          </nav>
        </div>

        <div className="p-6">
          {activeTab === 'threats' && (
            <ThreatsTab
              strideCategories={strideCategories}
              selectedCategory={selectedCategory}
              setSelectedCategory={setSelectedCategory}
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
              filteredThreats={filteredThreats}
              expandedThreats={expandedThreats}
              toggleThreat={toggleThreat}
              controls={controls}
            />
          )}

          {activeTab === 'attack-paths' && (
            <AttackPathsTab attackPaths={attackPaths} projectId={id || ''} />
          )}

          {activeTab === 'mitre' && (
            <MitreTab mitreMapping={mitreMapping} />
          )}

          {activeTab === 'history' && (
            <HistoryTab projectId={Number(id)} />
          )}
        </div>
      </div>

      {/* Lifecycle Summary (shown when incremental model) */}
      {threatModel.lifecycle_summary && (
        <div className="card p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold text-gray-900 flex items-center gap-2">
              <Clock className="w-4 h-4" />
              Threat Lifecycle Summary
            </h3>
            {threatModel.is_incremental && (
              <span className="text-xs bg-blue-100 text-blue-700 px-2 py-1 rounded">
                Incremental Analysis
              </span>
            )}
          </div>
          <ThreatLifecycleSummary summary={threatModel.lifecycle_summary} />
          {threatModel.architecture_version?.change_description && (
            <p className="mt-3 text-sm text-gray-600">
              <span className="font-medium">Latest changes:</span>{' '}
              {threatModel.architecture_version.change_description}
            </p>
          )}
        </div>
      )}

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
          </div>
        ) : (
          <div className="text-center py-6 bg-gray-50 rounded-lg border-2 border-dashed border-gray-200">
            <Shield className="w-8 h-8 text-gray-400 mx-auto mb-2" />
            <p className="text-sm text-gray-600">No security controls added yet</p>
            <p className="text-xs text-gray-500">Add controls to see how they affect threat severity</p>
          </div>
        )}
      </div>

      {/* Delete Confirmation Dialog */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white rounded-lg shadow-xl p-6 max-w-md w-full mx-4">
            <div className="flex items-center space-x-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-red-100 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-red-600" />
              </div>
              <h3 className="text-lg font-semibold text-gray-900">Delete Threat Model</h3>
            </div>
            <p className="text-gray-600 mb-6">
              Are you sure you want to delete this threat model? This action cannot be undone.
              You can always regenerate a new threat model later.
            </p>
            <div className="flex justify-end space-x-3">
              <button
                onClick={() => setShowDeleteConfirm(false)}
                disabled={deleting}
                className="btn btn-secondary"
              >
                Cancel
              </button>
              <button
                onClick={deleteThreatModel}
                disabled={deleting}
                className="btn bg-red-600 text-white hover:bg-red-700 inline-flex items-center space-x-2"
              >
                {deleting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Deleting...</span>
                  </>
                ) : (
                  <>
                    <Trash2 className="w-4 h-4" />
                    <span>Delete</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toast Notifications */}
      {toasts.map((toast) => (
        <Toast
          key={toast.id}
          message={toast.message}
          type={toast.type}
          onClose={() => removeToast(toast.id)}
        />
      ))}
    </div>
  )
}

// Risk Gauge Component
function RiskGauge({ score, level }: { score: number; level: string }) {
  const levelConfig = RISK_LEVELS[level as keyof typeof RISK_LEVELS] || RISK_LEVELS.medium

  return (
    <div className="flex items-center space-x-4 bg-white border border-gray-200 rounded-xl px-4 py-3 shadow-sm">
      <div className="relative">
        <svg className="w-16 h-16 transform -rotate-90">
          <circle
            cx="32"
            cy="32"
            r="28"
            fill="none"
            stroke="#e5e7eb"
            strokeWidth="6"
          />
          <circle
            cx="32"
            cy="32"
            r="28"
            fill="none"
            stroke={level === 'critical' ? '#dc2626' : level === 'high' ? '#f97316' : level === 'medium' ? '#eab308' : '#22c55e'}
            strokeWidth="6"
            strokeDasharray={`${(score / 100) * 176} 176`}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-sm font-bold text-gray-900">{score}</span>
        </div>
      </div>
      <div>
        <p className="text-xs text-gray-500 uppercase">Risk Level</p>
        <p className={`text-lg font-bold capitalize ${levelConfig.text}`}>{level}</p>
      </div>
    </div>
  )
}

// Threats Tab Component
function ThreatsTab({
  strideCategories,
  selectedCategory,
  setSelectedCategory,
  searchQuery,
  setSearchQuery,
  filteredThreats,
  expandedThreats,
  toggleThreat,
  controls
}: any) {
  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-2 flex-wrap">
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
          {strideCategories.map((category: string) => (
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
          placeholder="Search threats by name, description, CWE, component, or mitigation..."
          className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-600 focus:border-transparent"
        />
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
  )
}

// Attack Paths Tab Component
function AttackPathsTab({ attackPaths, projectId }: { attackPaths: any[], projectId: string }) {
  const [expandedPaths, setExpandedPaths] = useState<Set<number>>(new Set())
  const [generatedDiagrams, setGeneratedDiagrams] = useState<Record<number, any>>({})
  const [generatingDiagram, setGeneratingDiagram] = useState<number | null>(null)
  const [diagramError, setDiagramError] = useState<string | null>(null)

  const generateDiagram = async (idx: number, path: any) => {
    setGeneratingDiagram(idx)
    setDiagramError(null)

    try {
      const token = localStorage.getItem('token')
      const response = await axios.post(
        `/api/projects/${projectId}/threat-model/generate-attack-diagram`,
        {
          attack_path_index: idx,
          theme: 'dark'
        },
        { headers: { Authorization: `Bearer ${token}` } }
      )

      if (response.data.success) {
        setGeneratedDiagrams(prev => ({
          ...prev,
          [idx]: {
            imageUrl: response.data.image_url,
            editUrl: response.data.editor_url,
            name: response.data.attack_path_name
          }
        }))
      } else {
        setDiagramError(response.data.error || 'Failed to generate diagram')
      }
    } catch (error: any) {
      setDiagramError(error.response?.data?.detail || 'Failed to generate diagram')
    } finally {
      setGeneratingDiagram(null)
    }
  }

  const togglePath = (idx: number) => {
    const newExpanded = new Set(expandedPaths)
    if (newExpanded.has(idx)) {
      newExpanded.delete(idx)
    } else {
      newExpanded.add(idx)
    }
    setExpandedPaths(newExpanded)
  }

  if (attackPaths.length === 0) {
    return (
      <div className="text-center py-12">
        <Route className="w-16 h-16 text-gray-300 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-gray-900 mb-2">No Attack Paths Found</h3>
        <p className="text-gray-600">Attack path analysis did not identify any critical paths.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="bg-purple-50 border border-purple-200 rounded-lg p-4 mb-6">
        <div className="flex items-start space-x-3">
          <Zap className="w-5 h-5 text-purple-600 mt-0.5" />
          <div>
            <h3 className="font-medium text-purple-900">Attack Path Analysis</h3>
            <p className="text-sm text-purple-700 mt-1">
              These paths show how an attacker could move through your system from entry points to critical assets.
              Each path is sorted by risk score. Click on a path to see detailed attack scenarios and exploitation steps.
            </p>
          </div>
        </div>
      </div>

      {attackPaths.map((path, idx) => {
        const isExpanded = expandedPaths.has(idx)
        return (
          <div
            key={idx}
            className="border border-gray-200 rounded-lg hover:shadow-md transition cursor-pointer"
            onClick={() => togglePath(idx)}
          >
            <div className="p-4">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                    path.risk_score >= 80 ? 'bg-red-100' : path.risk_score >= 60 ? 'bg-orange-100' : 'bg-yellow-100'
                  }`}>
                    <Route className={`w-5 h-5 ${
                      path.risk_score >= 80 ? 'text-red-600' : path.risk_score >= 60 ? 'text-orange-600' : 'text-yellow-600'
                    }`} />
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-900">Attack Path #{idx + 1}</h3>
                    <p className="text-sm text-gray-500">{path.path?.length || 0} hops • {path.difficulty?.level || 'Unknown'} difficulty</p>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      generateDiagram(idx, path)
                    }}
                    disabled={generatingDiagram === idx || generatedDiagrams[idx]}
                    className={`px-3 py-1 rounded-lg text-sm font-medium flex items-center space-x-1 transition ${
                      generatedDiagrams[idx]
                        ? 'bg-green-100 text-green-700 cursor-default'
                        : generatingDiagram === idx
                        ? 'bg-purple-100 text-purple-700 cursor-wait'
                        : 'bg-purple-100 text-purple-700 hover:bg-purple-200'
                    }`}
                  >
                    {generatingDiagram === idx ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Generating...</span>
                      </>
                    ) : generatedDiagrams[idx] ? (
                      <>
                        <CheckCircle className="w-4 h-4" />
                        <span>Diagram Ready</span>
                      </>
                    ) : (
                      <>
                        <Zap className="w-4 h-4" />
                        <span>Generate Diagram</span>
                      </>
                    )}
                  </button>
                  <div className={`px-3 py-1 rounded-full text-sm font-medium ${
                    path.risk_score >= 80 ? 'bg-red-100 text-red-700' :
                    path.risk_score >= 60 ? 'bg-orange-100 text-orange-700' :
                    'bg-yellow-100 text-yellow-700'
                  }`}>
                    Risk: {path.risk_score}/100
                  </div>
                  <span className="text-gray-400">{isExpanded ? '▼' : '▶'}</span>
                </div>
              </div>

              {/* Path Visualization */}
              <div className="flex items-center flex-wrap gap-2 mb-4">
                {path.path?.map((node: string, nodeIdx: number) => (
                  <div key={nodeIdx} className="flex items-center">
                    <div className={`px-3 py-2 rounded-lg ${
                      nodeIdx === 0 ? 'bg-blue-100 border-2 border-blue-400' :
                      nodeIdx === path.path.length - 1 ? 'bg-red-100 border-2 border-red-400' :
                      'bg-gray-100 border border-gray-300'
                    }`}>
                      <p className="text-sm font-medium text-gray-900">{node}</p>
                      <p className="text-xs text-gray-500">
                        {nodeIdx === 0 ? 'Entry Point' : nodeIdx === path.path.length - 1 ? 'Target' : 'Hop'}
                      </p>
                    </div>
                    {nodeIdx < path.path.length - 1 && (
                      <ChevronRight className="w-5 h-5 text-gray-400 mx-1" />
                    )}
                  </div>
                ))}
              </div>

              {/* Attack Scenario Summary */}
              {path.attack_scenario && (
                <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 mb-3">
                  <p className="text-sm text-amber-900">{path.attack_scenario}</p>
                </div>
              )}

              {/* Threats Along Path */}
              {path.threats && path.threats.length > 0 && (
                <div className="bg-gray-50 rounded-lg p-3">
                  <p className="text-xs font-medium text-gray-600 mb-2">Threats Along This Path:</p>
                  <div className="flex flex-wrap gap-2">
                    {path.threats.map((threat: string, tIdx: number) => (
                      <span key={tIdx} className="text-xs px-2 py-1 bg-white border border-gray-200 rounded text-gray-700">
                        {threat}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Expanded Details */}
            {isExpanded && (
              <div className="border-t border-gray-200 p-4 bg-gray-50 space-y-4" onClick={(e) => e.stopPropagation()}>
                {/* Exploitation Steps */}
                {path.exploitation_steps && path.exploitation_steps.length > 0 && (
                  <div className="bg-white border border-red-200 rounded-lg p-4">
                    <div className="flex items-center space-x-2 mb-3">
                      <AlertTriangle className="w-4 h-4 text-red-600" />
                      <h4 className="font-semibold text-red-900">Exploitation Steps</h4>
                    </div>
                    <div className="space-y-3">
                      {path.exploitation_steps.map((step: any, stepIdx: number) => (
                        <div key={stepIdx} className="flex items-start space-x-3">
                          <div className="flex-shrink-0 w-6 h-6 bg-red-100 text-red-700 rounded-full flex items-center justify-center text-sm font-medium">
                            {step.step || stepIdx + 1}
                          </div>
                          <div className="flex-1">
                            <p className="font-medium text-gray-900">{step.action}</p>
                            <p className="text-sm text-gray-600 mt-1">{step.details}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Potential Impact */}
                {path.potential_impact && (
                  <div className="bg-white border border-orange-200 rounded-lg p-4">
                    <div className="flex items-center space-x-2 mb-3">
                      <Zap className="w-4 h-4 text-orange-600" />
                      <h4 className="font-semibold text-orange-900">Potential Impact</h4>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {path.potential_impact.data_exposure && (
                        <div className="bg-orange-50 rounded p-3">
                          <p className="text-xs font-medium text-orange-800 mb-1">Data Exposure</p>
                          <p className="text-sm text-orange-900">{path.potential_impact.data_exposure}</p>
                        </div>
                      )}
                      {path.potential_impact.system_impact && (
                        <div className="bg-orange-50 rounded p-3">
                          <p className="text-xs font-medium text-orange-800 mb-1">System Impact</p>
                          <p className="text-sm text-orange-900">{path.potential_impact.system_impact}</p>
                        </div>
                      )}
                      {path.potential_impact.business_impact && (
                        <div className="bg-orange-50 rounded p-3">
                          <p className="text-xs font-medium text-orange-800 mb-1">Business Impact</p>
                          <p className="text-sm text-orange-900">{path.potential_impact.business_impact}</p>
                        </div>
                      )}
                      {path.potential_impact.compliance_impact && (
                        <div className="bg-orange-50 rounded p-3">
                          <p className="text-xs font-medium text-orange-800 mb-1">Compliance Impact</p>
                          <p className="text-sm text-orange-900">{path.potential_impact.compliance_impact}</p>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Difficulty Assessment */}
                {path.difficulty && (
                  <div className="bg-white border border-purple-200 rounded-lg p-4">
                    <div className="flex items-center space-x-2 mb-3">
                      <Activity className="w-4 h-4 text-purple-600" />
                      <h4 className="font-semibold text-purple-900">Attack Difficulty</h4>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      <div className="bg-purple-50 rounded p-3">
                        <p className="text-xs font-medium text-purple-800 mb-1">Difficulty Level</p>
                        <p className="text-sm font-semibold text-purple-900">{path.difficulty.level}</p>
                      </div>
                      <div className="bg-purple-50 rounded p-3">
                        <p className="text-xs font-medium text-purple-800 mb-1">Required Skills</p>
                        <p className="text-sm text-purple-900">{path.difficulty.required_skills}</p>
                      </div>
                      <div className="bg-purple-50 rounded p-3">
                        <p className="text-xs font-medium text-purple-800 mb-1">Estimated Time</p>
                        <p className="text-sm text-purple-900">{path.difficulty.time_estimate}</p>
                      </div>
                    </div>
                    {path.difficulty.tools_needed && path.difficulty.tools_needed.length > 0 && (
                      <div className="mt-3">
                        <p className="text-xs font-medium text-purple-800 mb-2">Tools Needed:</p>
                        <div className="flex flex-wrap gap-2">
                          {path.difficulty.tools_needed.map((tool: string, toolIdx: number) => (
                            <span key={toolIdx} className="text-xs px-2 py-1 bg-purple-100 text-purple-700 rounded">
                              {tool}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Detection Opportunities */}
                {path.detection_opportunities && path.detection_opportunities.length > 0 && (
                  <div className="bg-white border border-blue-200 rounded-lg p-4">
                    <div className="flex items-center space-x-2 mb-3">
                      <AlertCircle className="w-4 h-4 text-blue-600" />
                      <h4 className="font-semibold text-blue-900">Detection Opportunities</h4>
                    </div>
                    <div className="space-y-2">
                      {path.detection_opportunities.map((detection: any, detIdx: number) => (
                        <div key={detIdx} className="bg-blue-50 rounded p-3">
                          <div className="flex items-center justify-between mb-1">
                            <p className="font-medium text-blue-900">{detection.point}</p>
                            <span className={`text-xs px-2 py-0.5 rounded ${
                              detection.effectiveness === 'High' ? 'bg-green-100 text-green-700' :
                              detection.effectiveness === 'Medium' ? 'bg-yellow-100 text-yellow-700' :
                              'bg-gray-100 text-gray-700'
                            }`}>
                              {detection.effectiveness} Effectiveness
                            </span>
                          </div>
                          <p className="text-sm text-blue-800">{detection.method}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommended Controls */}
                {path.recommended_controls && path.recommended_controls.length > 0 && (
                  <div className="bg-white border border-green-200 rounded-lg p-4">
                    <div className="flex items-center space-x-2 mb-3">
                      <Shield className="w-4 h-4 text-green-600" />
                      <h4 className="font-semibold text-green-900">Recommended Controls</h4>
                    </div>
                    <div className="space-y-2">
                      {path.recommended_controls.map((control: any, ctrlIdx: number) => (
                        <div key={ctrlIdx} className="bg-green-50 rounded p-3">
                          <div className="flex items-center justify-between mb-1">
                            <p className="font-medium text-green-900">{control.control}</p>
                            <span className={`text-xs px-2 py-0.5 rounded ${
                              control.priority === 'Critical' ? 'bg-red-100 text-red-700' :
                              control.priority === 'High' ? 'bg-orange-100 text-orange-700' :
                              'bg-yellow-100 text-yellow-700'
                            }`}>
                              {control.priority} Priority
                            </span>
                          </div>
                          <p className="text-sm text-green-800">{control.implementation}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Generated Eraser Diagram */}
                {generatedDiagrams[idx] && (
                  <div className="bg-white border border-purple-200 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-2">
                        <Zap className="w-4 h-4 text-purple-600" />
                        <h4 className="font-semibold text-purple-900">Attack Path Diagram</h4>
                      </div>
                      <div className="flex items-center space-x-2">
                        <a
                          href={generatedDiagrams[idx].editUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs px-2 py-1 bg-purple-100 text-purple-700 rounded hover:bg-purple-200 flex items-center space-x-1"
                        >
                          <ExternalLink className="w-3 h-3" />
                          <span>Edit in Eraser</span>
                        </a>
                        <a
                          href={generatedDiagrams[idx].imageUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs px-2 py-1 bg-gray-100 text-gray-700 rounded hover:bg-gray-200 flex items-center space-x-1"
                        >
                          <Download className="w-3 h-3" />
                          <span>Download</span>
                        </a>
                      </div>
                    </div>
                    <div className="bg-gray-900 rounded-lg p-4 flex items-center justify-center">
                      <img
                        src={generatedDiagrams[idx].imageUrl}
                        alt={`Attack Path #${idx + 1} Diagram`}
                        className="max-w-full h-auto rounded"
                        style={{ maxHeight: '400px' }}
                      />
                    </div>
                  </div>
                )}

                {/* Diagram Error */}
                {diagramError && generatingDiagram === null && (
                  <div className="bg-red-50 border border-red-200 rounded-lg p-3">
                    <div className="flex items-center space-x-2">
                      <XCircle className="w-4 h-4 text-red-600" />
                      <p className="text-sm text-red-700">{diagramError}</p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// History Tab Component
function HistoryTab({ projectId }: { projectId: number }) {
  const [selectedVersionId, setSelectedVersionId] = useState<number | null>(null)
  const [versionData, setVersionData] = useState<any>(null)
  const [loadingVersion, setLoadingVersion] = useState(false)
  const token = localStorage.getItem('token') || ''

  const loadVersionData = async (versionId: number) => {
    setLoadingVersion(true)
    try {
      const response = await axios.get(
        `/api/projects/${projectId}/threat-model/version/${versionId}`,
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setVersionData(response.data)
      setSelectedVersionId(versionId)
    } catch (error) {
      console.error('Failed to load version:', error)
    } finally {
      setLoadingVersion(false)
    }
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div>
        <ThreatHistoryPanel
          projectId={projectId}
          token={token}
          onVersionSelect={loadVersionData}
          currentVersionId={selectedVersionId || undefined}
        />
      </div>
      <div>
        {loadingVersion ? (
          <div className="text-center py-12 text-gray-500">
            <Activity className="w-8 h-8 mx-auto mb-3 text-gray-400 animate-spin" />
            <p>Loading version...</p>
          </div>
        ) : versionData ? (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-700">
                Version {versionData.version?.version_number} Threats
              </h3>
              <button
                onClick={() => {
                  setVersionData(null)
                  setSelectedVersionId(null)
                }}
                className="text-xs text-gray-500 hover:text-gray-700"
              >
                Clear selection
              </button>
            </div>

            {versionData.version?.change_description && (
              <p className="text-sm text-gray-600 bg-gray-50 p-3 rounded-lg">
                {versionData.version.change_description}
              </p>
            )}

            <div className="space-y-2 max-h-[500px] overflow-y-auto">
              {versionData.threats && versionData.threats.length > 0 ? (
                versionData.threats.map((threat: any, idx: number) => (
                  <div
                    key={idx}
                    className="border rounded-lg p-3 bg-white hover:bg-gray-50"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-gray-900">
                        {threat.threat_data?.name || threat.threat_id}
                      </span>
                      <ThreatStatusBadge status={threat.status as ThreatStatus} size="sm" />
                    </div>
                    {threat.threat_data?.description && (
                      <p className="text-xs text-gray-600 mb-2">
                        {threat.threat_data.description}
                      </p>
                    )}
                    {threat.change_reason && (
                      <p className="text-xs text-blue-600 bg-blue-50 px-2 py-1 rounded">
                        {threat.change_reason}
                      </p>
                    )}
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <Shield className="w-8 h-8 mx-auto mb-2 text-gray-300" />
                  <p className="text-sm">No threats recorded for this version</p>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="text-center py-12 text-gray-500">
            <Clock className="w-12 h-12 mx-auto mb-3 text-gray-300" />
            <p>Select a version from the left to view its threats</p>
            <p className="text-xs mt-2 text-gray-400">
              Each version shows the threats identified at that point in time
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

// MITRE Tab Component
function MitreTab({ mitreMapping }: { mitreMapping: any }) {
  // Handle nested structure from backend: { techniques: {...}, attack_chain: {...} }
  const techniquesData = mitreMapping.techniques || mitreMapping
  const techniques = Object.entries(techniquesData).filter(([key]) =>
    !['attack_chain', 'total_techniques', 'tactics_covered'].includes(key)
  )

  // Attack chain from backend is organized by tactic, convert to array for visualization
  const attackChainData = mitreMapping.attack_chain || {}
  const attackChain: any[] = []
  const tacticOrderForChain = [
    'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
    'Collection', 'Exfiltration', 'Impact'
  ]
  tacticOrderForChain.forEach(tactic => {
    const techsInTactic = attackChainData[tactic]
    if (techsInTactic && techsInTactic.length > 0) {
      // Pick the first technique from each tactic for the chain visualization
      attackChain.push({ tactic, ...techsInTactic[0] })
    }
  })

  // Group by tactic
  const tacticGroups: { [key: string]: any[] } = {}
  techniques.forEach(([id, data]: [string, any]) => {
    if (id === 'attack_chain') return
    const tactic = data.tactic || 'Unknown'
    if (!tacticGroups[tactic]) tacticGroups[tactic] = []
    tacticGroups[tactic].push({ id, ...data })
  })

  const tacticOrder = [
    'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
    'Collection', 'Exfiltration', 'Impact'
  ]

  // Check if there are any techniques
  if (techniques.length === 0) {
    return (
      <div className="text-center py-12">
        <Target className="w-16 h-16 text-gray-300 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-gray-900 mb-2">No MITRE ATT&CK Mappings</h3>
        <p className="text-gray-600">MITRE ATT&CK mappings will appear here once threats are analyzed.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Attack Chain Visualization */}
      {attackChain.length > 0 && (
        <div className="bg-gradient-to-r from-orange-50 to-red-50 border border-orange-200 rounded-lg p-6 mb-6">
          <div className="flex items-center space-x-2 mb-4">
            <Target className="w-5 h-5 text-orange-600" />
            <h3 className="font-semibold text-orange-900">Potential Attack Chain</h3>
          </div>
          <div className="flex items-center flex-wrap gap-3">
            {attackChain.map((step: any, idx: number) => (
              <div key={idx} className="flex items-center">
                <div className="bg-white border-2 border-orange-300 rounded-lg p-3 shadow-sm">
                  <p className="text-xs text-orange-600 font-medium">{step.tactic}</p>
                  <p className="text-sm font-semibold text-gray-900">{step.technique}</p>
                  <a
                    href={step.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-blue-600 hover:underline flex items-center mt-1"
                  >
                    {step.id} <ExternalLink className="w-3 h-3 ml-1" />
                  </a>
                </div>
                {idx < attackChain.length - 1 && (
                  <ChevronRight className="w-6 h-6 text-orange-400 mx-2" />
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Techniques by Tactic */}
      <div className="space-y-4">
        {tacticOrder.map((tactic) => {
          const techsInTactic = tacticGroups[tactic]
          if (!techsInTactic || techsInTactic.length === 0) return null

          return (
            <div key={tactic} className="border border-gray-200 rounded-lg overflow-hidden">
              <div className="bg-gray-50 px-4 py-3 border-b border-gray-200">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-gray-900">{tactic}</h3>
                  <span className="text-sm text-gray-500">{techsInTactic.length} technique(s)</span>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 p-4">
                {techsInTactic.map((tech: any) => (
                  <div key={tech.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition">
                    <div className="flex items-start justify-between mb-2">
                      <span className="text-xs font-mono bg-orange-100 text-orange-700 px-2 py-0.5 rounded">
                        {tech.id}
                      </span>
                      <span className="text-xs text-gray-500">{tech.threat_count} threats</span>
                    </div>
                    <h4 className="font-medium text-gray-900 mb-2">{tech.name}</h4>
                    <p className="text-sm text-gray-600 mb-3 line-clamp-2">{tech.description}</p>
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-500">STRIDE: {tech.related_stride}</span>
                      {tech.url && (
                        <a
                          href={tech.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-blue-600 hover:underline flex items-center"
                        >
                          Learn more <ExternalLink className="w-3 h-3 ml-1" />
                        </a>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )
        })}
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
      const { svg } = await mermaid.render(`mermaid-${level}-${Date.now()}`, dfdData.mermaid)
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
        <div className="flex items-center space-x-2">
          <div className="w-4 h-4 bg-red-100 border-2 border-red-400 rounded"></div>
          <span className="text-sm text-gray-600">Trust Boundary</span>
        </div>
      </div>

      <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
        <p className="text-sm text-blue-800">
          <strong>Level {level} DFD:</strong> {level === 0 ?
            'Context diagram showing the system as a single process with external entities' :
            'Detailed diagram showing internal processes, data stores, and data flows with trust boundaries'}
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
  const hasMitigatingControls = controls.length > 0
  const severity = threat.severity || 'medium'
  const severityColor = SEVERITY_COLORS[severity as keyof typeof SEVERITY_COLORS] || SEVERITY_COLORS.medium

  return (
    <div
      className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition cursor-pointer"
      onClick={onToggle}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1">
          <div className="flex items-center space-x-2 mb-1 flex-wrap gap-y-1">
            <h3 className="font-semibold text-gray-900">{threat.threat}</h3>
            <span className={`text-xs px-2 py-1 rounded-full border ${severityColor}`}>
              {severity.charAt(0).toUpperCase() + severity.slice(1)}
            </span>
            {threat.lifecycle_status && (
              <ThreatStatusBadge status={threat.lifecycle_status as ThreatStatus} size="sm" />
            )}
            {threat.cwe && (
              <a
                href={`https://cwe.mitre.org/data/definitions/${threat.cwe.replace('CWE-', '')}.html`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs px-2 py-0.5 bg-purple-100 text-purple-700 rounded hover:bg-purple-200"
                onClick={(e) => e.stopPropagation()}
              >
                {threat.cwe}
              </a>
            )}
            {threat.risk_score && (
              <span className="text-xs px-2 py-0.5 bg-gray-100 text-gray-600 rounded">
                Risk: {threat.risk_score}
              </span>
            )}
            {threat.attack_complexity && (
              <span className={`text-xs px-2 py-0.5 rounded ${
                threat.attack_complexity.skill_level === 'Advanced' ? 'bg-red-100 text-red-700' :
                threat.attack_complexity.skill_level === 'Intermediate' ? 'bg-orange-100 text-orange-700' :
                'bg-green-100 text-green-700'
              }`}>
                {threat.attack_complexity.skill_level}
              </span>
            )}
          </div>
          <p className="text-sm text-gray-600">{threat.component}</p>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-gray-500">
            {isExpanded ? '▼' : '▶'}
          </span>
        </div>
      </div>

      <p className="text-sm text-gray-700 mb-3">{threat.description}</p>

      {/* Change Reason (for incremental analysis) */}
      {threat.change_reason && threat.lifecycle_status && (
        <ThreatChangeReason reason={threat.change_reason} status={threat.lifecycle_status as ThreatStatus} />
      )}

      {/* MITRE Techniques */}
      {threat.mitre && threat.mitre.length > 0 && (
        <div className="flex items-center space-x-2 mb-3">
          <Target className="w-4 h-4 text-orange-500" />
          <div className="flex flex-wrap gap-1">
            {threat.mitre.map((technique: string, idx: number) => (
              <a
                key={idx}
                href={`https://attack.mitre.org/techniques/${technique.replace('.', '/')}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs px-2 py-0.5 bg-orange-100 text-orange-700 rounded hover:bg-orange-200"
                onClick={(e) => e.stopPropagation()}
              >
                {technique}
              </a>
            ))}
          </div>
        </div>
      )}

      {isExpanded && (
        <div className="space-y-3 mt-4 pt-4 border-t border-gray-200" onClick={(e) => e.stopPropagation()}>
          {/* STRIDE Category */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
            <p className="text-xs font-medium text-blue-800 mb-1">STRIDE Category:</p>
            <p className="text-sm text-blue-900">{threat.category || 'N/A'}</p>
          </div>

          {/* Attack Vector */}
          {threat.attack_vector && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-3">
              <div className="flex items-center space-x-2 mb-2">
                <AlertTriangle className="w-4 h-4 text-red-600" />
                <p className="text-xs font-medium text-red-800">Attack Vector</p>
              </div>
              <p className="text-sm text-red-900 mb-2">{threat.attack_vector.description}</p>
              {threat.attack_vector.entry_points && threat.attack_vector.entry_points.length > 0 && (
                <div className="mt-2">
                  <p className="text-xs font-medium text-red-800 mb-1">Entry Points:</p>
                  <div className="flex flex-wrap gap-1">
                    {threat.attack_vector.entry_points.map((point: string, idx: number) => (
                      <span key={idx} className="text-xs px-2 py-0.5 bg-red-100 text-red-700 rounded">
                        {point}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {threat.attack_vector.techniques && threat.attack_vector.techniques.length > 0 && (
                <div className="mt-2">
                  <p className="text-xs font-medium text-red-800 mb-1">Techniques:</p>
                  <ul className="text-xs text-red-700 list-disc list-inside">
                    {threat.attack_vector.techniques.map((tech: string, idx: number) => (
                      <li key={idx}>{tech}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Business Impact */}
          {threat.business_impact && (
            <div className="bg-orange-50 border border-orange-200 rounded-lg p-3">
              <div className="flex items-center space-x-2 mb-2">
                <TrendingUp className="w-4 h-4 text-orange-600" />
                <p className="text-xs font-medium text-orange-800">Business Impact</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {threat.business_impact.financial && (
                  <div className="bg-orange-100 rounded p-2">
                    <p className="text-xs font-medium text-orange-800">Financial</p>
                    <p className="text-xs text-orange-700">{threat.business_impact.financial}</p>
                  </div>
                )}
                {threat.business_impact.reputational && (
                  <div className="bg-orange-100 rounded p-2">
                    <p className="text-xs font-medium text-orange-800">Reputational</p>
                    <p className="text-xs text-orange-700">{threat.business_impact.reputational}</p>
                  </div>
                )}
                {threat.business_impact.operational && (
                  <div className="bg-orange-100 rounded p-2">
                    <p className="text-xs font-medium text-orange-800">Operational</p>
                    <p className="text-xs text-orange-700">{threat.business_impact.operational}</p>
                  </div>
                )}
                {threat.business_impact.compliance && (
                  <div className="bg-orange-100 rounded p-2">
                    <p className="text-xs font-medium text-orange-800">Compliance</p>
                    <p className="text-xs text-orange-700">{threat.business_impact.compliance}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Affected Assets */}
          {threat.affected_assets && threat.affected_assets.length > 0 && (
            <div className="bg-purple-50 border border-purple-200 rounded-lg p-3">
              <p className="text-xs font-medium text-purple-800 mb-2">Affected Assets:</p>
              <div className="flex flex-wrap gap-2">
                {threat.affected_assets.map((asset: string, idx: number) => (
                  <span key={idx} className="text-xs px-2 py-1 bg-purple-100 text-purple-700 rounded">
                    {asset}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Prerequisites */}
          {threat.prerequisites && (
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
              <div className="flex items-center space-x-2 mb-2">
                <Lock className="w-4 h-4 text-yellow-600" />
                <p className="text-xs font-medium text-yellow-800">Attack Prerequisites</p>
              </div>
              {threat.prerequisites.access_required && (
                <p className="text-xs text-yellow-700 mb-1">
                  <span className="font-medium">Access Required:</span> {threat.prerequisites.access_required}
                </p>
              )}
              {threat.prerequisites.conditions && threat.prerequisites.conditions.length > 0 && (
                <div>
                  <p className="text-xs font-medium text-yellow-800 mb-1">Conditions:</p>
                  <ul className="text-xs text-yellow-700 list-disc list-inside">
                    {threat.prerequisites.conditions.map((cond: string, idx: number) => (
                      <li key={idx}>{cond}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Attack Complexity */}
          {threat.attack_complexity && (
            <div className="bg-indigo-50 border border-indigo-200 rounded-lg p-3">
              <div className="flex items-center space-x-2 mb-2">
                <Activity className="w-4 h-4 text-indigo-600" />
                <p className="text-xs font-medium text-indigo-800">Attack Complexity</p>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div className="bg-indigo-100 rounded p-2">
                  <p className="text-xs font-medium text-indigo-800">Skill Level</p>
                  <p className="text-xs text-indigo-700">{threat.attack_complexity.skill_level}</p>
                </div>
                <div className="bg-indigo-100 rounded p-2">
                  <p className="text-xs font-medium text-indigo-800">Time Required</p>
                  <p className="text-xs text-indigo-700">{threat.attack_complexity.time_required}</p>
                </div>
              </div>
            </div>
          )}

          {/* Legacy Attack Vectors (for backwards compatibility) */}
          {threat.attack_vectors && !threat.attack_vector && (
            <div className="bg-purple-50 border border-purple-200 rounded-lg p-3">
              <p className="text-xs font-medium text-purple-800 mb-1">Attack Vectors:</p>
              <ul className="text-sm text-purple-900 list-disc list-inside">
                {threat.attack_vectors.map((vector: string, idx: number) => (
                  <li key={idx}>{vector}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Recommended Mitigation */}
          <div className="bg-green-50 border border-green-200 rounded-lg p-3">
            <div className="flex items-center space-x-2 mb-2">
              <Shield className="w-4 h-4 text-green-600" />
              <p className="text-xs font-medium text-green-800">Recommended Mitigation</p>
            </div>
            <p className="text-sm text-green-900">{threat.mitigation}</p>
          </div>

          {/* References */}
          {threat.references && (
            <div className="bg-gray-50 border border-gray-200 rounded-lg p-3">
              <p className="text-xs font-medium text-gray-700 mb-2">References:</p>
              <div className="flex flex-wrap gap-2">
                {threat.references.cwe && (
                  <a
                    href={threat.references.cwe}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs px-2 py-1 bg-purple-100 text-purple-700 rounded hover:bg-purple-200 flex items-center"
                  >
                    CWE <ExternalLink className="w-3 h-3 ml-1" />
                  </a>
                )}
                {threat.references.mitre && (
                  <a
                    href={threat.references.mitre}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs px-2 py-1 bg-orange-100 text-orange-700 rounded hover:bg-orange-200 flex items-center"
                  >
                    MITRE ATT&CK <ExternalLink className="w-3 h-3 ml-1" />
                  </a>
                )}
                {threat.references.owasp && (
                  <a
                    href={threat.references.owasp}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs px-2 py-1 bg-blue-100 text-blue-700 rounded hover:bg-blue-200 flex items-center"
                  >
                    OWASP <ExternalLink className="w-3 h-3 ml-1" />
                  </a>
                )}
              </div>
            </div>
          )}

          {hasMitigatingControls && (
            <div className="bg-green-100 border border-green-300 rounded-lg p-3">
              <p className="text-xs font-medium text-green-800 mb-1">Active Controls Applied:</p>
              <p className="text-sm text-green-900">
                {controls.length} security control{controls.length !== 1 ? 's' : ''} active.
              </p>
            </div>
          )}
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

// Document Upload Section Component
function DocumentUploadSection({
  projectId,
  onBack,
  uploadedDocs,
  setUploadedDocs,
  analyzingDocs,
  setAnalyzingDocs,
  docAnalysisProgress,
  setDocAnalysisProgress,
  extractedFromDocs,
  setExtractedFromDocs,
  onShowNotification,
  onGenerateThreatModel
}: {
  projectId: string
  onBack: () => void
  uploadedDocs: File[]
  setUploadedDocs: (files: File[]) => void
  analyzingDocs: boolean
  setAnalyzingDocs: (analyzing: boolean) => void
  docAnalysisProgress: number
  setDocAnalysisProgress: (progress: number) => void
  extractedFromDocs: any
  setExtractedFromDocs: (data: any) => void
  onShowNotification: (message: string) => void
  onGenerateThreatModel: (architecture: any) => void
}) {
  const [dragActive, setDragActive] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const ACCEPTED_TYPES = [
    'application/pdf',
    'image/png',
    'image/jpeg',
    'image/jpg',
    'image/webp',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ]

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const newFiles = Array.from(e.dataTransfer.files).filter(file =>
        ACCEPTED_TYPES.includes(file.type)
      )
      setUploadedDocs([...uploadedDocs, ...newFiles])
    }
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const newFiles = Array.from(e.target.files).filter(file =>
        ACCEPTED_TYPES.includes(file.type)
      )
      setUploadedDocs([...uploadedDocs, ...newFiles])
    }
  }

  const removeFile = (index: number) => {
    setUploadedDocs(uploadedDocs.filter((_, i) => i !== index))
  }

  const getFileIcon = (type: string) => {
    if (type.startsWith('image/')) return <FileImage className="w-5 h-5 text-blue-500" />
    if (type === 'application/pdf') return <File className="w-5 h-5 text-red-500" />
    return <FileText className="w-5 h-5 text-gray-500" />
  }

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  }

  const analyzeDocuments = async () => {
    if (uploadedDocs.length === 0) {
      onShowNotification('Please upload at least one document (PDF, image, or DOCX) before analyzing.')
      return
    }

    setAnalyzingDocs(true)
    setDocAnalysisProgress(0)

    try {
      const formData = new FormData()
      uploadedDocs.forEach((file, index) => {
        formData.append('files', file)
      })

      const token = localStorage.getItem('token')

      // Start analysis
      setDocAnalysisProgress(10)

      const response = await axios.post(
        `/api/projects/${projectId}/architecture/analyze-documents`,
        formData,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'multipart/form-data'
          },
          onUploadProgress: (progressEvent) => {
            const progress = progressEvent.total
              ? Math.round((progressEvent.loaded * 30) / progressEvent.total) + 10
              : 20
            setDocAnalysisProgress(progress)
          }
        }
      )

      setDocAnalysisProgress(100)

      if (response.data.success) {
        const arch = response.data.architecture
        if (!arch.components || arch.components.length === 0) {
          onShowNotification('No architecture components could be extracted from the uploaded documents. Please upload documents with clearer architecture diagrams or more detailed descriptions.')
        }
        setExtractedFromDocs(arch)
      } else {
        onShowNotification(response.data.error || 'Failed to analyze documents. Please try again.')
      }
    } catch (error: any) {
      console.error('Document analysis failed:', error)
      onShowNotification(error.response?.data?.detail || 'Failed to analyze documents. Please try again.')
    } finally {
      setAnalyzingDocs(false)
    }
  }

  return (
    <div className="card p-8">
      <div className="flex items-center mb-6">
        <button
          onClick={onBack}
          className="inline-flex items-center text-sm text-gray-600 hover:text-gray-900"
        >
          <ArrowLeft className="w-4 h-4 mr-1" />
          Back to Options
        </button>
      </div>

      <div className="text-center mb-6">
        <Upload className="w-12 h-12 text-blue-500 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-gray-900 mb-2">Upload Project Documents</h3>
        <p className="text-sm text-gray-600">
          Upload architecture diagrams, design documents, or use case documents.
          Our AI will analyze them to understand your system architecture.
        </p>
      </div>

      {/* Drop Zone */}
      <div
        className={`border-2 border-dashed rounded-xl p-8 text-center transition-colors ${
          dragActive
            ? 'border-blue-500 bg-blue-50'
            : 'border-gray-300 hover:border-gray-400'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept=".pdf,.png,.jpg,.jpeg,.webp,.docx"
          onChange={handleFileSelect}
          className="hidden"
        />
        <div className="space-y-3">
          <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto">
            <Upload className="w-8 h-8 text-gray-400" />
          </div>
          <div>
            <button
              onClick={() => fileInputRef.current?.click()}
              className="text-blue-600 hover:text-blue-700 font-medium"
            >
              Click to upload
            </button>
            <span className="text-gray-500"> or drag and drop</span>
          </div>
          <p className="text-xs text-gray-400">
            PDF, PNG, JPG, WEBP, or DOCX (max 20MB each)
          </p>
        </div>
      </div>

      {/* Uploaded Files List */}
      {uploadedDocs.length > 0 && (
        <div className="mt-6 space-y-2">
          <h4 className="text-sm font-medium text-gray-700">Uploaded Documents ({uploadedDocs.length})</h4>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {uploadedDocs.map((file, index) => (
              <div
                key={index}
                className="flex items-center justify-between bg-gray-50 rounded-lg px-4 py-2"
              >
                <div className="flex items-center space-x-3">
                  {getFileIcon(file.type)}
                  <div>
                    <p className="text-sm font-medium text-gray-900 truncate max-w-xs">
                      {file.name}
                    </p>
                    <p className="text-xs text-gray-500">{formatFileSize(file.size)}</p>
                  </div>
                </div>
                <button
                  onClick={() => removeFile(index)}
                  className="text-gray-400 hover:text-red-500 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Analysis Progress */}
      {analyzingDocs && (
        <div className="mt-6 bg-blue-50 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-blue-700">Analyzing documents...</span>
            <span className="text-sm text-blue-600">{docAnalysisProgress}%</span>
          </div>
          <div className="w-full bg-blue-200 rounded-full h-2">
            <div
              className="bg-blue-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${docAnalysisProgress}%` }}
            />
          </div>
          <p className="text-xs text-blue-600 mt-2">
            {docAnalysisProgress < 40
              ? 'Uploading documents...'
              : docAnalysisProgress < 70
              ? 'Extracting content and analyzing diagrams...'
              : 'Building architecture model...'}
          </p>
        </div>
      )}

      {/* Extracted Architecture Preview */}
      {extractedFromDocs && (
        <div className="mt-6 bg-green-50 border border-green-200 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center space-x-2">
              <CheckCircle className="w-5 h-5 text-green-600" />
              <span className="font-medium text-green-800">Architecture Extracted</span>
            </div>
            <button
              onClick={() => setExtractedFromDocs(null)}
              className="text-gray-400 hover:text-gray-600"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="grid grid-cols-3 gap-4 mb-4">
            <div className="bg-white rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-gray-900">
                {extractedFromDocs.components?.length || 0}
              </p>
              <p className="text-xs text-gray-500">Components</p>
            </div>
            <div className="bg-white rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-gray-900">
                {extractedFromDocs.data_flows?.length || 0}
              </p>
              <p className="text-xs text-gray-500">Data Flows</p>
            </div>
            <div className="bg-white rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-gray-900">
                {extractedFromDocs.trust_boundaries?.length || 0}
              </p>
              <p className="text-xs text-gray-500">Trust Boundaries</p>
            </div>
          </div>

          {extractedFromDocs.description && (
            <div className="bg-white rounded-lg p-3 mb-4">
              <p className="text-xs font-medium text-gray-500 mb-1">System Overview</p>
              <p className="text-sm text-gray-700">{extractedFromDocs.description}</p>
            </div>
          )}

          {extractedFromDocs.components && extractedFromDocs.components.length > 0 && (
            <div className="bg-white rounded-lg p-3">
              <p className="text-xs font-medium text-gray-500 mb-2">Identified Components</p>
              <div className="flex flex-wrap gap-2">
                {extractedFromDocs.components.slice(0, 10).map((comp: any, idx: number) => (
                  <span
                    key={idx}
                    className="px-2 py-1 bg-gray-100 text-gray-700 text-xs rounded"
                  >
                    {comp.name}
                  </span>
                ))}
                {extractedFromDocs.components.length > 10 && (
                  <span className="px-2 py-1 bg-gray-200 text-gray-600 text-xs rounded">
                    +{extractedFromDocs.components.length - 10} more
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Action Buttons */}
      <div className="mt-6 flex space-x-3">
        {!extractedFromDocs ? (
          <button
            onClick={analyzeDocuments}
            disabled={uploadedDocs.length === 0 || analyzingDocs}
            className="btn btn-primary flex-1 inline-flex items-center justify-center space-x-2"
          >
            {analyzingDocs ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Eye className="w-4 h-4" />
                <span>Analyze Documents</span>
              </>
            )}
          </button>
        ) : (
          <button
            onClick={() => onGenerateThreatModel(extractedFromDocs)}
            className="btn btn-primary flex-1 inline-flex items-center justify-center space-x-2"
          >
            <Zap className="w-4 h-4" />
            <span>Generate Threat Model</span>
          </button>
        )}
      </div>

      {/* Supported Formats Info */}
      <div className="mt-6 p-4 bg-gray-50 rounded-lg">
        <h4 className="text-sm font-medium text-gray-700 mb-3">Supported Document Types</h4>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="flex items-center space-x-2 text-sm text-gray-600">
            <FileImage className="w-4 h-4 text-blue-500" />
            <span>Architecture Diagrams</span>
          </div>
          <div className="flex items-center space-x-2 text-sm text-gray-600">
            <File className="w-4 h-4 text-red-500" />
            <span>PDF Documents</span>
          </div>
          <div className="flex items-center space-x-2 text-sm text-gray-600">
            <FileImage className="w-4 h-4 text-green-500" />
            <span>Use Case Diagrams</span>
          </div>
          <div className="flex items-center space-x-2 text-sm text-gray-600">
            <FileText className="w-4 h-4 text-purple-500" />
            <span>Design Documents</span>
          </div>
        </div>
      </div>
    </div>
  )
}
