import { useState, useEffect } from 'react'
import axios from 'axios'
import {
  FileSpreadsheet, FileText, File, Download, Shield, ChevronDown,
  CheckCircle, Clock, AlertTriangle, BarChart3, Table, BookOpen
} from 'lucide-react'

interface Project {
  id: number
  name: string
  description: string
}

type ReportFormat = 'excel' | 'pdf' | 'xml'

const REPORT_FORMATS: {
  id: ReportFormat
  name: string
  ext: string
  mime: string
  icon: typeof FileSpreadsheet
  color: string
  gradient: string
  description: string
  features: string[]
}[] = [
  {
    id: 'excel',
    name: 'Excel Report',
    ext: '.xlsx',
    mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    icon: FileSpreadsheet,
    color: 'text-emerald-600',
    gradient: 'from-emerald-600 to-teal-600',
    description: 'Comprehensive workbook for security analysts with workflow tracking',
    features: [
      '20+ detailed sheets (SAST, SCA, Secrets, Threat Model, MITRE)',
      'Analyst workflow columns: Status, Assignee, Due Date, Priority, Notes',
      'Data validation dropdowns for status & priority tracking',
      'SLA-based due dates auto-calculated by severity',
      'SCA reachability column with color-coded exploitability',
      'STRIDE & MITRE ATT&CK mapping per finding',
      'Business & Technical Impact columns',
      'Severity color-coding & conditional formatting',
      'GitHub commit monitor summary sheet',
    ],
  },
  {
    id: 'pdf',
    name: 'PDF Report',
    ext: '.pdf',
    mime: 'application/pdf',
    icon: FileText,
    color: 'text-red-600',
    gradient: 'from-red-600 to-rose-600',
    description: 'Professional security assessment report for executives and stakeholders',
    features: [
      'Branded cover page with risk rating & project metadata',
      'Table of Contents with 10+ sections',
      'Executive summary with key metrics dashboard',
      'Severity distribution pie chart & bar chart',
      'Detailed SAST, SCA, and Secrets findings tables',
      'STRIDE threat model analysis summary',
      'MITRE ATT&CK technique mapping',
      'Compliance mapping (OWASP, NIST, PCI DSS, SOC 2)',
      'Detailed critical & high findings with code snippets',
      'Phased remediation roadmap (Immediate → Long-term)',
      'Methodology & scoring appendix',
    ],
  },
  {
    id: 'xml',
    name: 'XML Report',
    ext: '.xml',
    mime: 'application/xml',
    icon: File,
    color: 'text-blue-600',
    gradient: 'from-blue-600 to-indigo-600',
    description: 'Machine-readable format for tool integration and automation',
    features: [
      'Structured XML with SAST, SCA, Secret, and Threat Model sections',
      'CWE, CVE, and OWASP category mapping',
      'CVSS scores and severity classification',
      'Compatible with SIEM and GRC platform imports',
      'Remediation recommendations per finding',
    ],
  },
]

export default function ReportCenterPage() {
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProject, setSelectedProject] = useState<number | null>(null)
  const [loading, setLoading] = useState<ReportFormat | null>(null)
  const [success, setSuccess] = useState<ReportFormat | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dropdownOpen, setDropdownOpen] = useState(false)

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) return
    axios
      .get('/api/projects', { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => {
        setProjects(res.data)
        if (res.data.length > 0) setSelectedProject(res.data[0].id)
      })
      .catch(() => {})
  }, [])

  const handleDownload = async (format: ReportFormat) => {
    if (!selectedProject) return
    setLoading(format)
    setError(null)
    setSuccess(null)

    const token = localStorage.getItem('token')
    const fmt = REPORT_FORMATS.find((f) => f.id === format)!

    try {
      const response = await axios.get(
        `/api/projects/${selectedProject}/reports/${format}`,
        {
          headers: { Authorization: `Bearer ${token}` },
          responseType: 'blob',
        }
      )

      const projectName =
        projects.find((p) => p.id === selectedProject)?.name || 'report'
      const blob = new Blob([response.data], { type: fmt.mime })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `${projectName}_security_report${fmt.ext}`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)

      setSuccess(format)
      setTimeout(() => setSuccess(null), 3000)
    } catch (err: any) {
      setError(
        err.response?.status === 404
          ? 'Project not found or no scan data available'
          : 'Failed to generate report. Please try again.'
      )
    } finally {
      setLoading(null)
    }
  }

  const selectedProjectObj = projects.find((p) => p.id === selectedProject)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="max-w-7xl mx-auto mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 bg-gradient-to-br from-violet-600 to-purple-600 rounded-lg">
            <BookOpen className="w-6 h-6 text-gray-900" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900">Report Center</h1>
        </div>
        <p className="text-gray-500 ml-12">
          Generate enterprise-grade security reports matching Checkmarx, Snyk & Veracode quality
        </p>
      </div>

      <div className="max-w-7xl mx-auto">
        {/* Project Selector */}
        <div className="bg-white border border-gray-200 rounded-xl p-6 mb-8 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                <Shield className="w-5 h-5 text-violet-600" />
                Select Project
              </h2>
              <p className="text-sm text-gray-500 mt-1">
                Choose the project to generate reports for
              </p>
            </div>
            <div className="relative">
              <button
                onClick={() => setDropdownOpen(!dropdownOpen)}
                className="flex items-center gap-3 bg-gray-100 hover:bg-gray-100 text-gray-900 px-5 py-3 rounded-lg border border-gray-300 transition-colors min-w-[280px] justify-between"
              >
                <span className="truncate">
                  {selectedProjectObj?.name || 'Select a project...'}
                </span>
                <ChevronDown
                  className={`w-4 h-4 transition-transform ${dropdownOpen ? 'rotate-180' : ''}`}
                />
              </button>
              {dropdownOpen && (
                <div className="absolute right-0 mt-2 w-full bg-gray-100 border border-gray-300 rounded-lg shadow-xl z-10 max-h-60 overflow-y-auto">
                  {projects.map((project) => (
                    <button
                      key={project.id}
                      onClick={() => {
                        setSelectedProject(project.id)
                        setDropdownOpen(false)
                      }}
                      className={`w-full text-left px-4 py-3 hover:bg-gray-100 transition-colors ${
                        selectedProject === project.id
                          ? 'bg-violet-50 text-violet-700'
                          : 'text-gray-200'
                      }`}
                    >
                      <div className="font-medium">{project.name}</div>
                      {project.description && (
                        <div className="text-xs text-gray-500 truncate mt-0.5">
                          {project.description}
                        </div>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Error / Success Messages */}
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6 flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0" />
            <span className="text-red-600">{error}</span>
          </div>
        )}

        {/* Report Format Cards */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {REPORT_FORMATS.map((format) => {
            const Icon = format.icon
            const isLoading = loading === format.id
            const isSuccess = success === format.id

            return (
              <div
                key={format.id}
                className="bg-white border border-gray-200 rounded-xl overflow-hidden hover:border-gray-300 transition-all group"
              >
                {/* Card Header */}
                <div className={`bg-gradient-to-r ${format.gradient} p-5`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Icon className="w-8 h-8 text-gray-900" />
                      <div>
                        <h3 className="text-lg font-bold text-gray-900">{format.name}</h3>
                        <span className="text-xs text-gray-500 font-mono">{format.ext}</span>
                      </div>
                    </div>
                    {isSuccess && (
                      <CheckCircle className="w-6 h-6 text-gray-900 animate-bounce" />
                    )}
                  </div>
                </div>

                {/* Card Body */}
                <div className="p-5">
                  <p className="text-gray-600 text-sm mb-4">{format.description}</p>

                  <div className="space-y-2 mb-5">
                    {format.features.map((feature, idx) => (
                      <div key={idx} className="flex items-start gap-2">
                        <CheckCircle className="w-3.5 h-3.5 text-green-600 mt-0.5 flex-shrink-0" />
                        <span className="text-xs text-gray-500">{feature}</span>
                      </div>
                    ))}
                  </div>

                  {/* Download Button */}
                  <button
                    onClick={() => handleDownload(format.id)}
                    disabled={!selectedProject || isLoading}
                    className={`w-full flex items-center justify-center gap-2 py-3 px-4 rounded-lg font-medium transition-all ${
                      !selectedProject
                        ? 'bg-gray-100 text-gray-500 cursor-not-allowed'
                        : isLoading
                          ? 'bg-gray-600 text-gray-600 cursor-wait'
                          : isSuccess
                            ? 'bg-green-600 text-gray-900'
                            : `bg-gradient-to-r ${format.gradient} text-gray-900 hover:shadow-lg hover:scale-[1.02]`
                    }`}
                  >
                    {isLoading ? (
                      <>
                        <Clock className="w-4 h-4 animate-spin" />
                        Generating...
                      </>
                    ) : isSuccess ? (
                      <>
                        <CheckCircle className="w-4 h-4" />
                        Downloaded!
                      </>
                    ) : (
                      <>
                        <Download className="w-4 h-4" />
                        Download {format.name}
                      </>
                    )}
                  </button>
                </div>
              </div>
            )
          })}
        </div>

        {/* Report Details Section */}
        <div className="bg-white border border-gray-200 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2 mb-4">
            <BarChart3 className="w-5 h-5 text-violet-600" />
            Report Contents Overview
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              {
                title: 'SAST Analysis',
                icon: Shield,
                color: 'text-blue-600',
                items: [
                  'Findings by severity (Critical → Info)',
                  'Grouped by CWE, OWASP, File',
                  'STRIDE & MITRE mapping',
                  'Code snippets & remediation',
                ],
              },
              {
                title: 'SCA Analysis',
                icon: Table,
                color: 'text-emerald-600',
                items: [
                  'Vulnerable dependencies',
                  'CVE details & CVSS scores',
                  'Reachability assessment',
                  'Package & version tracking',
                ],
              },
              {
                title: 'Secrets Detection',
                icon: AlertTriangle,
                color: 'text-red-600',
                items: [
                  'Hardcoded credentials',
                  'API keys & tokens',
                  'File path & line numbers',
                  'SLA-based remediation dates',
                ],
              },
              {
                title: 'Threat Model',
                icon: BookOpen,
                color: 'text-purple-600',
                items: [
                  'STRIDE analysis per component',
                  'MITRE ATT&CK techniques',
                  'Trust boundaries',
                  'Remediation roadmap',
                ],
              },
            ].map((section) => {
              const SIcon = section.icon
              return (
                <div
                  key={section.title}
                  className="bg-gray-100/30 rounded-lg p-4 border border-gray-200/50"
                >
                  <div className="flex items-center gap-2 mb-3">
                    <SIcon className={`w-4 h-4 ${section.color}`} />
                    <h3 className="text-sm font-semibold text-gray-900">{section.title}</h3>
                  </div>
                  <ul className="space-y-1.5">
                    {section.items.map((item, idx) => (
                      <li key={idx} className="text-xs text-gray-500 flex items-start gap-1.5">
                        <span className="text-gray-600 mt-0.5">•</span>
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
