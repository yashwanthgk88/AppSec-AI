import { useState, useEffect } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import {
  Shield,
  AlertTriangle,
  Download,
  Play,
  FileText,
  Network,
  Bug,
  Package,
  Key,
  CheckCircle,
  Trash2,
  ClipboardCheck,
} from 'lucide-react'
import axios from 'axios'

export default function ProjectDetailPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [project, setProject] = useState<any>(null)
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)

  useEffect(() => {
    fetchProjectData()
  }, [id])

  const fetchProjectData = async () => {
    try {
      const token = localStorage.getItem('token')

      const [projectRes, scansRes] = await Promise.all([
        axios.get(`/api/projects/${id}`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
        axios.get(`/api/projects/${id}/scans`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      ])

      setProject(projectRes.data)
      setScans(scansRes.data)

      // Recalculate risk score if it's 0 or undefined (for existing projects)
      if (!projectRes.data.risk_score || projectRes.data.risk_score === 0) {
        try {
          const riskScoreRes = await axios.post(
            `/api/projects/${id}/calculate-risk-score`,
            {},
            {
              headers: { Authorization: `Bearer ${token}` },
            }
          )
          // Update project with new risk score
          if (riskScoreRes.data.success) {
            setProject((prev: any) => ({
              ...prev,
              risk_score: riskScoreRes.data.risk_score,
            }))
          }
        } catch (error) {
          console.error('Failed to recalculate risk score:', error)
        }
      }
    } catch (error) {
      console.error('Failed to fetch project:', error)
    } finally {
      setLoading(false)
    }
  }

  const runSecurityScan = async () => {
    setScanning(true)
    try {
      const token = localStorage.getItem('token')
      const response = await axios.post(`/api/projects/${id}/scan`, {}, {
        headers: { Authorization: `Bearer ${token}` },
      })
      console.log('Scan completed:', response.data)
      await fetchProjectData()
    } catch (error) {
      console.error('Scan failed:', error)
      alert('Scan failed. Please try again.')
    } finally {
      setScanning(false)
    }
  }

  const downloadReport = async (format: 'excel' | 'pdf' | 'xml') => {
    try {
      const token = localStorage.getItem('token')
      const response = await axios.get(`/api/projects/${id}/reports/${format}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob',
      })

      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url

      const extensions = { excel: 'xlsx', pdf: 'pdf', xml: 'xml' }
      link.setAttribute('download', `${project.name}_report.${extensions[format]}`)
      document.body.appendChild(link)
      link.click()
      link.remove()
    } catch (error) {
      console.error('Download failed:', error)
    }
  }

  const deleteProject = async () => {
    if (!window.confirm(`Are you sure you want to delete "${project.name}"? This action cannot be undone and will delete all scans, vulnerabilities, and threat models associated with this project.`)) {
      return
    }

    try {
      const token = localStorage.getItem('token')
      await axios.delete(`/api/projects/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      navigate('/projects')
    } catch (error) {
      console.error('Delete failed:', error)
      alert('Failed to delete project. Please try again.')
    }
  }

  const deleteScan = async (scanId: number, scanType: string) => {
    if (!window.confirm(`Are you sure you want to delete this ${scanType.toUpperCase()} scan? This will also delete all vulnerabilities found in this scan.`)) {
      return
    }

    try {
      const token = localStorage.getItem('token')
      await axios.delete(`/api/scans/${scanId}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      // Refresh the project data to update the scans list
      await fetchProjectData()
    } catch (error) {
      console.error('Delete scan failed:', error)
      alert('Failed to delete scan. Please try again.')
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  const latestScan = scans[0]
  const totalFindings = latestScan?.total_findings || 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">{project.name}</h1>
          <p className="text-gray-600 mt-1">{project.description || 'No description'}</p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={runSecurityScan}
            disabled={scanning}
            className="btn btn-primary inline-flex items-center space-x-2"
          >
            <Play className="w-4 h-4" />
            <span>{scanning ? 'Scanning...' : 'Run Security Scans'}</span>
          </button>
          <div className="relative group">
            <button className="btn btn-secondary inline-flex items-center space-x-2">
              <Download className="w-4 h-4" />
              <span>Export</span>
            </button>
            <div className="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg border border-gray-200 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition z-10">
              <button
                onClick={() => downloadReport('excel')}
                className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
              >
                Download Excel
              </button>
              <button
                onClick={() => downloadReport('pdf')}
                className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
              >
                Download PDF
              </button>
              <button
                onClick={() => downloadReport('xml')}
                className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
              >
                Download XML
              </button>
            </div>
          </div>
          <button
            onClick={deleteProject}
            className="btn bg-red-600 hover:bg-red-700 text-white inline-flex items-center space-x-2"
          >
            <Trash2 className="w-4 h-4" />
            <span>Delete</span>
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Findings"
          value={totalFindings}
          icon={<Bug className="w-6 h-6" />}
          color="red"
        />
        <StatCard
          title="Critical"
          value={latestScan?.critical_count || 0}
          icon={<AlertTriangle className="w-6 h-6" />}
          color="red"
        />
        <StatCard
          title="High"
          value={latestScan?.high_count || 0}
          icon={<Shield className="w-6 h-6" />}
          color="orange"
        />
        <StatCard
          title="Risk Score"
          value={`${project.risk_score?.toFixed(1) || '0.0'}/10`}
          icon={<FileText className="w-6 h-6" />}
          color="blue"
        />
      </div>

      {/* Quick Links */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <QuickLink
          to={`/projects/${id}/threat-model`}
          icon={<Network className="w-6 h-6" />}
          title="Threat Model"
          description="View DFD & STRIDE analysis"
          color="blue"
        />
        <QuickLink
          to={`/projects/${id}/vulnerabilities?scanType=sast`}
          icon={<Bug className="w-6 h-6" />}
          title="Vulnerabilities"
          description="SAST scan results"
          color="red"
        />
        <QuickLink
          to={`/projects/${id}/vulnerabilities?scanType=sca`}
          icon={<Package className="w-6 h-6" />}
          title="Dependencies"
          description="SCA findings"
          color="orange"
        />
        <QuickLink
          to={`/projects/${id}/vulnerabilities?scanType=secret`}
          icon={<Key className="w-6 h-6" />}
          title="Secrets"
          description="Detected credentials"
          color="purple"
        />
        <QuickLink
          to={`/projects/${id}/security-requirements`}
          icon={<ClipboardCheck className="w-6 h-6" />}
          title="SecureReq"
          description="Security requirements"
          color="green"
        />
      </div>

      {/* Scan History */}
      <div className="card p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Scan History</h2>

        {scans.length === 0 ? (
          <div className="text-center py-12">
            <Shield className="w-16 h-16 text-gray-300 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-gray-900 mb-2">No scans yet</h3>
            <p className="text-gray-600 mb-6">Run your first security scan to see results here</p>
            <button onClick={runSecurityScan} className="btn btn-primary">
              Run Security Scans
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            {scans.map((scan) => (
              <div
                key={scan.id}
                className="flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition"
              >
                <div className="flex items-center space-x-4">
                  <div className="w-12 h-12 bg-primary-100 rounded-lg flex items-center justify-center">
                    {scan.scan_type === 'sast' && <Bug className="w-6 h-6 text-primary-600" />}
                    {scan.scan_type === 'sca' && <Package className="w-6 h-6 text-primary-600" />}
                    {scan.scan_type === 'secret' && <Key className="w-6 h-6 text-primary-600" />}
                  </div>
                  <div>
                    <h3 className="font-medium text-gray-900">
                      {scan.scan_type.toUpperCase()} Scan
                    </h3>
                    <p className="text-sm text-gray-600">
                      {new Date(scan.started_at).toLocaleString()}
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-6">
                  <div className="text-center">
                    <div className="text-sm text-gray-500">Total</div>
                    <div className="text-lg font-semibold text-gray-900">{scan.total_findings}</div>
                  </div>
                  <div className="text-center">
                    <div className="text-sm text-red-600">Critical</div>
                    <div className="text-lg font-semibold text-red-600">{scan.critical_count}</div>
                  </div>
                  <div className="text-center">
                    <div className="text-sm text-orange-600">High</div>
                    <div className="text-lg font-semibold text-orange-600">{scan.high_count}</div>
                  </div>
                  <div className="text-center">
                    <div className="text-sm text-yellow-600">Medium</div>
                    <div className="text-lg font-semibold text-yellow-600">{scan.medium_count}</div>
                  </div>

                  {scan.status === 'completed' && (
                    <CheckCircle className="w-6 h-6 text-green-600" />
                  )}

                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      deleteScan(scan.id, scan.scan_type)
                    }}
                    className="ml-4 p-2 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition"
                    title="Delete this scan"
                  >
                    <Trash2 className="w-5 h-5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Project Details */}
      <div className="card p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Project Details</h2>
        <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <dt className="text-sm font-medium text-gray-500">Repository URL</dt>
            <dd className="mt-1 text-sm text-gray-900">
              {project.repository_url || 'Not provided'}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500">Created At</dt>
            <dd className="mt-1 text-sm text-gray-900">
              {new Date(project.created_at).toLocaleString()}
            </dd>
          </div>
          <div className="md:col-span-2">
            <dt className="text-sm font-medium text-gray-500">Compliance Targets</dt>
            <dd className="mt-1 flex flex-wrap gap-2">
              {project.compliance_targets?.map((target: string) => (
                <span key={target} className="badge badge-info">
                  {target}
                </span>
              ))}
            </dd>
          </div>
        </dl>
      </div>
    </div>
  )
}

function StatCard({ title, value, icon, color }: any) {
  const colorClasses = {
    blue: 'bg-blue-100 text-blue-600',
    red: 'bg-red-100 text-red-600',
    orange: 'bg-orange-100 text-orange-600',
    green: 'bg-green-100 text-green-600',
  }

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600 mb-1">{title}</p>
          <p className="text-2xl font-bold text-gray-900">{value}</p>
        </div>
        <div className={`p-3 rounded-lg ${colorClasses[color as keyof typeof colorClasses]}`}>
          {icon}
        </div>
      </div>
    </div>
  )
}

function QuickLink({ to, icon, title, description, color }: any) {
  const colorClasses = {
    blue: 'bg-blue-100 text-blue-600',
    red: 'bg-red-100 text-red-600',
    orange: 'bg-orange-100 text-orange-600',
    purple: 'bg-purple-100 text-purple-600',
    green: 'bg-green-100 text-green-600',
  }

  return (
    <Link
      to={to}
      className="card p-4 hover:shadow-lg transition flex items-center space-x-4"
    >
      <div className={`p-3 rounded-lg ${colorClasses[color as keyof typeof colorClasses]}`}>
        {icon}
      </div>
      <div className="flex-1 min-w-0">
        <h3 className="font-medium text-gray-900 truncate">{title}</h3>
        <p className="text-sm text-gray-600 truncate">{description}</p>
      </div>
    </Link>
  )
}
