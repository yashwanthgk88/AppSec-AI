import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Plus, FileText, Calendar, TrendingUp, Download, Play } from 'lucide-react'
import axios from 'axios'

export default function ProjectsPage() {
  const [projects, setProjects] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)

  useEffect(() => {
    fetchProjects()
  }, [])

  const fetchProjects = async () => {
    try {
      const token = localStorage.getItem('token')
      const response = await axios.get('/api/projects', {
        headers: { Authorization: `Bearer ${token}` }
      })
      setProjects(response.data)
    } catch (error) {
      console.error('Failed to fetch projects:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleCreateProject = async (formData: any) => {
    try {
      const token = localStorage.getItem('token')
      await axios.post('/api/projects', formData, {
        headers: { Authorization: `Bearer ${token}` }
      })
      setShowCreateModal(false)
      fetchProjects()
    } catch (error) {
      console.error('Failed to create project:', error)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Projects</h1>
          <p className="text-gray-600 mt-1">Manage your application security projects</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn btn-primary inline-flex items-center space-x-2"
        >
          <Plus className="w-5 h-5" />
          <span>New Project</span>
        </button>
      </div>

      {/* Projects Grid */}
      {projects.length === 0 ? (
        <div className="card p-12 text-center">
          <FileText className="w-16 h-16 text-gray-300 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900 mb-2">No projects yet</h3>
          <p className="text-gray-600 mb-6">Create your first project to start security scanning</p>
          <button
            onClick={() => setShowCreateModal(true)}
            className="btn btn-primary inline-flex items-center space-x-2"
          >
            <Plus className="w-5 h-5" />
            <span>Create First Project</span>
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((project) => (
            <ProjectCard key={project.id} project={project} />
          ))}
        </div>
      )}

      {/* Create Project Modal */}
      {showCreateModal && (
        <CreateProjectModal
          onClose={() => setShowCreateModal(false)}
          onCreate={handleCreateProject}
        />
      )}
    </div>
  )
}

function ProjectCard({ project }: { project: any }) {
  const riskLevel = project.risk_score >= 7 ? 'high' : project.risk_score >= 4 ? 'medium' : 'low'
  const riskColors = {
    high: 'bg-red-100 text-red-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-green-100 text-green-800',
  }

  return (
    <div className="card p-6 hover:shadow-lg transition">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center space-x-3">
          <div className="w-12 h-12 bg-primary-100 rounded-lg flex items-center justify-center">
            <FileText className="w-6 h-6 text-primary-600" />
          </div>
          <div>
            <Link
              to={`/projects/${project.id}`}
              className="font-semibold text-gray-900 hover:text-primary-600"
            >
              {project.name}
            </Link>
            <p className="text-sm text-gray-500 flex items-center mt-1">
              <Calendar className="w-3 h-3 mr-1" />
              {new Date(project.created_at).toLocaleDateString()}
            </p>
          </div>
        </div>
      </div>

      <p className="text-sm text-gray-600 mb-4 line-clamp-2">
        {project.description || 'No description provided'}
      </p>

      <div className="flex items-center justify-between mb-4">
        <div>
          <div className="text-xs text-gray-500">Risk Score</div>
          <div className="flex items-center space-x-2">
            <TrendingUp className="w-4 h-4 text-gray-400" />
            <span className="text-2xl font-bold text-gray-900">
              {project.risk_score?.toFixed(1) || '0.0'}
            </span>
            <span className="text-sm text-gray-500">/10</span>
          </div>
        </div>
        <span className={`badge ${riskColors[riskLevel]}`}>
          {riskLevel.toUpperCase()}
        </span>
      </div>

      <div className="flex items-center space-x-2">
        <Link
          to={`/projects/${project.id}`}
          className="btn btn-secondary flex-1 text-sm py-2"
        >
          View Details
        </Link>
        <Link
          to={`/projects/${project.id}/threat-model`}
          className="btn btn-secondary p-2"
          title="View Threat Model"
        >
          <FileText className="w-4 h-4" />
        </Link>
      </div>
    </div>
  )
}

function CreateProjectModal({ onClose, onCreate }: any) {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    architecture_doc: '',
    repository_url: '',
    technology_stack: [] as string[],
    compliance_targets: ['OWASP Top 10', 'SANS CWE-25'],
    auto_scan_types: ['threat_model', 'sast', 'sca', 'secret'] as string[],
  })

  const toggleScanType = (scanType: string) => {
    setFormData(prev => ({
      ...prev,
      auto_scan_types: prev.auto_scan_types.includes(scanType)
        ? prev.auto_scan_types.filter(t => t !== scanType)
        : [...prev.auto_scan_types, scanType]
    }))
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onCreate(formData)
  }

  const sampleArchitecture = `E-Commerce Web Application

The system consists of the following components:

- Web Frontend: React single-page application serving end users
- API Gateway: Routes and authenticates incoming requests
- Authentication Service: Handles user login, registration, JWT tokens
- Product Service: Manages product catalog and inventory
- Order Service: Processes customer orders
- Payment Service: Integrates with Stripe for payment processing
- Database: PostgreSQL for persistent data storage
- Cache Layer: Redis for session management and caching
- External Services: Stripe API, SendGrid email service`

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6 border-b border-gray-200">
          <h2 className="text-2xl font-bold text-gray-900">Create New Project</h2>
          <p className="text-gray-600 mt-1">Add architecture details for threat modeling</p>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="label">Project Name *</label>
            <input
              type="text"
              className="input"
              placeholder="E-Commerce Web App"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              required
            />
          </div>

          <div>
            <label className="label">Description</label>
            <input
              type="text"
              className="input"
              placeholder="Brief description of the project"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            />
          </div>

          <div>
            <label className="label">Repository URL</label>
            <input
              type="url"
              className="input"
              placeholder="https://github.com/org/repo"
              value={formData.repository_url}
              onChange={(e) => setFormData({ ...formData, repository_url: e.target.value })}
            />
          </div>

          <div>
            <label className="label">
              Architecture Document *
              <button
                type="button"
                onClick={() => setFormData({ ...formData, architecture_doc: sampleArchitecture })}
                className="ml-2 text-xs text-primary-600 hover:text-primary-700"
              >
                Use Sample
              </button>
            </label>
            <textarea
              className="input min-h-[200px]"
              placeholder="Describe your system architecture, components, data flows..."
              value={formData.architecture_doc}
              onChange={(e) => setFormData({ ...formData, architecture_doc: e.target.value })}
              required
            />
            <p className="text-xs text-gray-500 mt-1">
              Describe components, services, databases, and data flows for automatic DFD generation
            </p>
          </div>

          <div>
            <label className="label">Automatic Security Scans</label>
            <p className="text-xs text-gray-500 mb-3">
              Select which security scans to run automatically after project creation
            </p>
            <div className="space-y-2">
              <label className="flex items-center space-x-3 p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.auto_scan_types.includes('threat_model')}
                  onChange={() => toggleScanType('threat_model')}
                  className="w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
                />
                <div className="flex-1">
                  <div className="font-medium text-gray-900">Threat Modeling</div>
                  <div className="text-xs text-gray-500">Generate DFD and STRIDE analysis</div>
                </div>
              </label>

              <label className="flex items-center space-x-3 p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.auto_scan_types.includes('sast')}
                  onChange={() => toggleScanType('sast')}
                  className="w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
                />
                <div className="flex-1">
                  <div className="font-medium text-gray-900">SAST Scanning</div>
                  <div className="text-xs text-gray-500">Static application security testing - code vulnerabilities</div>
                </div>
              </label>

              <label className="flex items-center space-x-3 p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.auto_scan_types.includes('sca')}
                  onChange={() => toggleScanType('sca')}
                  className="w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
                />
                <div className="flex-1">
                  <div className="font-medium text-gray-900">SCA Scanning</div>
                  <div className="text-xs text-gray-500">Software composition analysis - dependency vulnerabilities</div>
                </div>
              </label>

              <label className="flex items-center space-x-3 p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.auto_scan_types.includes('secret')}
                  onChange={() => toggleScanType('secret')}
                  className="w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
                />
                <div className="flex-1">
                  <div className="font-medium text-gray-900">Secret Scanning</div>
                  <div className="text-xs text-gray-500">Detect hardcoded credentials and API keys</div>
                </div>
              </label>
            </div>
          </div>

          <div className="flex items-center justify-end space-x-3 pt-4">
            <button type="button" onClick={onClose} className="btn btn-secondary">
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              Create Project
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
