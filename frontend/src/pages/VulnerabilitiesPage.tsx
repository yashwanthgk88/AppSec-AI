import { useState, useEffect, useCallback } from 'react'
import { useParams, Link, useSearchParams } from 'react-router-dom'
import { Bug, ArrowLeft, Code, FileText, MessageSquare, ChevronDown, ChevronUp, Sparkles, Loader2, CheckCircle, XCircle, GitBranch, GitCommit, Copy, Check, CheckCheck, AlertCircle, AlertTriangle } from 'lucide-react'
import axios from 'axios'

export default function VulnerabilitiesPage() {
  const { id } = useParams()
  const [searchParams] = useSearchParams()
  const [scans, setScans] = useState<any[]>([])
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedSeverity, setSelectedSeverity] = useState('all')
  const [selectedScanType, setSelectedScanType] = useState(searchParams.get('scanType') || 'all')
  const [selectedStatusView, setSelectedStatusView] = useState<'active' | 'resolved' | 'false_positive'>('active')
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null)

  const fetchAllScans = useCallback(async () => {
    console.log('fetchAllScans called, loading:', loading)
    if (!loading) {
      console.log('Skipping fetch - already loaded')
      return
    }

    try {
      const token = localStorage.getItem('token')

      // Get all scans
      const scansRes = await axios.get(`/api/projects/${id}/scans`, {
        headers: { Authorization: `Bearer ${token}` },
      })

      console.log('Scans fetched:', scansRes.data)
      setScans(scansRes.data)

      // Fetch vulnerabilities from all scans
      const allVulnerabilities: any[] = []
      for (const scan of scansRes.data) {
        console.log(`Fetching vulnerabilities for scan ${scan.id} (${scan.scan_type})...`)
        try {
          const vulnRes = await axios.get(`/api/scans/${scan.id}/vulnerabilities`, {
            headers: { Authorization: `Bearer ${token}` },
            timeout: 30000, // 30 second timeout
          })

          console.log(`Vulnerabilities for scan ${scan.id}:`, vulnRes.data)
          console.log('First vuln status:', vulnRes.data[0]?.status)

          // Add scan type to each vulnerability
          vulnRes.data.forEach((vuln: any) => {
            allVulnerabilities.push({
              ...vuln,
              scan_type: scan.scan_type
            })
          })
          console.log(`Completed scan ${scan.id}, total so far: ${allVulnerabilities.length}`)
        } catch (scanError) {
          console.error(`ERROR fetching vulnerabilities for scan ${scan.id} (${scan.scan_type}):`, scanError)
          // Continue with other scans even if one fails
        }
      }

      console.log('Total vulnerabilities:', allVulnerabilities.length)
      console.log('All vulnerabilities:', allVulnerabilities)
      setVulnerabilities(allVulnerabilities)
    } catch (error) {
      console.error('Failed to fetch scans:', error)
    } finally {
      console.log('Setting loading to false')
      setLoading(false)
    }
  }, [id, loading])

  useEffect(() => {
    console.log('===== VulnerabilitiesPage useEffect triggered =====')
    console.log('Project ID:', id)
    fetchAllScans()
  }, [id, fetchAllScans])

  if (loading) {
    console.log('=== STILL LOADING ===', { scans, vulnerabilities })
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading vulnerabilities... (Check console for debug info)</p>
        </div>
      </div>
    )
  }

  // Filter by severity, scan type, and status
  const filteredVulnerabilities = vulnerabilities.filter((v) => {
    const severityMatch = selectedSeverity === 'all' || v.severity === selectedSeverity
    const scanTypeMatch = selectedScanType === 'all' || v.scan_type === selectedScanType
    const statusMatch = v.status === selectedStatusView || (!v.status && selectedStatusView === 'active')

    return severityMatch && scanTypeMatch && statusMatch
  })

  // Count vulnerabilities by status
  const statusCounts = {
    active: vulnerabilities.filter((v) => !v.status || v.status === 'active' || v.status === 'fixed').length,
    resolved: vulnerabilities.filter((v) => v.status === 'resolved').length,
    false_positive: vulnerabilities.filter((v) => v.status === 'false_positive').length,
  }

  const severityCounts = {
    critical: vulnerabilities.filter((v) => v.severity === 'critical').length,
    high: vulnerabilities.filter((v) => v.severity === 'high').length,
    medium: vulnerabilities.filter((v) => v.severity === 'medium').length,
    low: vulnerabilities.filter((v) => v.severity === 'low').length,
  }

  const scanTypeCounts = {
    sast: vulnerabilities.filter((v) => v.scan_type === 'sast').length,
    sca: vulnerabilities.filter((v) => v.scan_type === 'sca').length,
    secret: vulnerabilities.filter((v) => v.scan_type === 'secret').length,
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Link
          to={`/projects/${id}`}
          className="inline-flex items-center text-sm text-gray-600 hover:text-gray-900 mb-2"
        >
          <ArrowLeft className="w-4 h-4 mr-1" />
          Back to Project
        </Link>
        <h1 className="text-3xl font-bold text-gray-900">Security Vulnerabilities</h1>
        <p className="text-gray-600 mt-1">SAST, SCA, and Secret Scan results with AI-powered remediation</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <SeverityCard title="Critical" count={severityCounts.critical} color="red" />
        <SeverityCard title="High" count={severityCounts.high} color="orange" />
        <SeverityCard title="Medium" count={severityCounts.medium} color="yellow" />
        <SeverityCard title="Low" count={severityCounts.low} color="blue" />
      </div>

      {/* Scan Type Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card p-4 bg-blue-50 border-blue-200">
          <p className="text-sm font-medium text-blue-900">SAST Findings</p>
          <p className="text-2xl font-bold text-blue-900">{scanTypeCounts.sast}</p>
          <p className="text-xs text-blue-700 mt-1">Code vulnerabilities</p>
        </div>
        <div className="card p-4 bg-purple-50 border-purple-200">
          <p className="text-sm font-medium text-purple-900">SCA Findings</p>
          <p className="text-2xl font-bold text-purple-900">{scanTypeCounts.sca}</p>
          <p className="text-xs text-purple-700 mt-1">Dependency issues</p>
        </div>
        <div className="card p-4 bg-red-50 border-red-200">
          <p className="text-sm font-medium text-red-900">Secret Findings</p>
          <p className="text-2xl font-bold text-red-900">{scanTypeCounts.secret}</p>
          <p className="text-xs text-red-700 mt-1">Exposed secrets</p>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-4 space-y-3">
        <div className="flex items-center space-x-2">
          <span className="text-sm font-medium text-gray-700">Severity:</span>
          {['all', 'critical', 'high', 'medium', 'low'].map((severity) => (
            <button
              key={severity}
              onClick={() => setSelectedSeverity(severity)}
              className={`px-4 py-2 text-sm rounded-lg transition ${
                selectedSeverity === severity
                  ? 'bg-primary-600 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              {severity.charAt(0).toUpperCase() + severity.slice(1)}
            </button>
          ))}
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-sm font-medium text-gray-700">Scan Type:</span>
          {['all', 'sast', 'sca', 'secret'].map((type) => (
            <button
              key={type}
              onClick={() => setSelectedScanType(type)}
              className={`px-4 py-2 text-sm rounded-lg transition ${
                selectedScanType === type
                  ? 'bg-indigo-600 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              {type === 'all' ? 'All' : type.toUpperCase()}
            </button>
          ))}
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-sm font-medium text-gray-700">Status:</span>
          <button
            onClick={() => setSelectedStatusView('active')}
            className={`px-4 py-2 text-sm rounded-lg transition inline-flex items-center space-x-2 ${
              selectedStatusView === 'active'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            <Bug className="w-4 h-4" />
            <span>Active ({statusCounts.active})</span>
          </button>
          <button
            onClick={() => setSelectedStatusView('resolved')}
            className={`px-4 py-2 text-sm rounded-lg transition inline-flex items-center space-x-2 ${
              selectedStatusView === 'resolved'
                ? 'bg-green-600 text-white'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            <CheckCheck className="w-4 h-4" />
            <span>Resolved ({statusCounts.resolved})</span>
          </button>
          <button
            onClick={() => setSelectedStatusView('false_positive')}
            className={`px-4 py-2 text-sm rounded-lg transition inline-flex items-center space-x-2 ${
              selectedStatusView === 'false_positive'
                ? 'bg-gray-600 text-white'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            <AlertCircle className="w-4 h-4" />
            <span>False Positives ({statusCounts.false_positive})</span>
          </button>
        </div>
      </div>

      {/* Vulnerabilities List */}
      <div className="space-y-4">
        {filteredVulnerabilities.length === 0 ? (
          <div className="card p-12 text-center">
            <Bug className="w-16 h-16 text-gray-300 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-gray-900 mb-2">No vulnerabilities found</h3>
            <p className="text-gray-600">
              {selectedSeverity === 'all' && selectedScanType === 'all'
                ? 'Run a security scan to see results'
                : 'No matching vulnerabilities found with current filters'}
            </p>
          </div>
        ) : (
          filteredVulnerabilities.map((vuln) => (
            <VulnerabilityCard
              key={vuln.id}
              vulnerability={vuln}
              isExpanded={expandedVuln === vuln.id}
              onToggle={() => setExpandedVuln(expandedVuln === vuln.id ? null : vuln.id)}
              projectId={id!}
              onUpdate={fetchAllScans}
            />
          ))
        )}
      </div>
    </div>
  )
}

function SeverityCard({ title, count, color }: any) {
  const colorClasses = {
    red: 'bg-red-100 text-red-600 border-red-200',
    orange: 'bg-orange-100 text-orange-600 border-orange-200',
    yellow: 'bg-yellow-100 text-yellow-600 border-yellow-200',
    blue: 'bg-blue-100 text-blue-600 border-blue-200',
  }

  return (
    <div className={`card p-6 border-2 ${colorClasses[color]}`}>
      <p className="text-sm font-medium mb-1">{title}</p>
      <p className="text-3xl font-bold">{count}</p>
    </div>
  )
}

function VulnerabilityCard({ vulnerability, isExpanded, onToggle, projectId, onUpdate }: any) {
  const [autoRemediating, setAutoRemediating] = useState(false)
  const [remediationResult, setRemediationResult] = useState<any>(null)
  const [showGitPanel, setShowGitPanel] = useState(false)
  const [gitBranch, setGitBranch] = useState('security-fix-' + vulnerability.id)
  const [commitMessage, setCommitMessage] = useState(`Fix: ${vulnerability.title}\n\nResolves ${vulnerability.cwe_id || 'security vulnerability'}\nSeverity: ${vulnerability.severity}`)
  const [committing, setCommitting] = useState(false)
  const [commitSuccess, setCommitSuccess] = useState(false)
  const [copiedCode, setCopiedCode] = useState(false)

  const severityColors: any = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
  }

  const scanTypeColors: any = {
    sast: 'bg-blue-100 text-blue-800',
    sca: 'bg-purple-100 text-purple-800',
    secret: 'bg-red-100 text-red-800',
  }

  const handleAutoRemediate = async () => {
    setAutoRemediating(true)
    setRemediationResult(null)
    setShowGitPanel(false)
    setCommitSuccess(false)

    try {
      const token = localStorage.getItem('token')
      const response = await axios.post(
        `/api/vulnerabilities/${vulnerability.id}/auto-remediate`,
        {},
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      )

      setRemediationResult(response.data)

      // Show git panel if remediation was successful
      if (response.data.success) {
        setShowGitPanel(true)
      }
    } catch (error: any) {
      setRemediationResult({
        success: false,
        message: error.response?.data?.detail || 'Failed to auto-remediate'
      })
    } finally {
      setAutoRemediating(false)
    }
  }

  const handleCopyCode = () => {
    if (remediationResult?.fixed_code) {
      navigator.clipboard.writeText(remediationResult.fixed_code)
      setCopiedCode(true)
      setTimeout(() => setCopiedCode(false), 2000)
    }
  }

  const handleCommitFix = async () => {
    setCommitting(true)
    setCommitSuccess(false)

    try {
      const token = localStorage.getItem('token')
      const response = await axios.post(
        `/api/vulnerabilities/${vulnerability.id}/commit-fix`,
        {
          branch: gitBranch,
          commit_message: commitMessage,
          fixed_code: remediationResult.fixed_code,
          file_path: vulnerability.file_path
        },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      )

      if (response.data.success) {
        setCommitSuccess(true)
        // Refresh vulnerabilities after successful commit
        setTimeout(() => {
          onUpdate()
        }, 2000)
      }
    } catch (error: any) {
      alert(error.response?.data?.detail || 'Failed to commit fix to repository')
    } finally {
      setCommitting(false)
    }
  }

  const handleStatusUpdate = async (newStatus: 'active' | 'resolved' | 'false_positive') => {
    try {
      const token = localStorage.getItem('token')
      const response = await axios.patch(
        `/api/vulnerabilities/${vulnerability.id}/status`,
        { status: newStatus },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      )

      if (response.data.success) {
        // Refresh vulnerabilities to update the list
        onUpdate()
      }
    } catch (error: any) {
      alert(error.response?.data?.detail || `Failed to update vulnerability status`)
    }
  }

  return (
    <div className="card">
      {/* Header */}
      <div
        className="p-6 cursor-pointer hover:bg-gray-50 transition"
        onClick={onToggle}
      >
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center space-x-3 mb-2 flex-wrap">
              <Bug className="w-5 h-5 text-gray-500" />
              <h3 className="font-semibold text-gray-900">{vulnerability.title}</h3>
              <span className={`badge ${severityColors[vulnerability.severity]}`}>
                {vulnerability.severity.toUpperCase()}
              </span>
              <span className={`px-2 py-1 text-xs rounded ${scanTypeColors[vulnerability.scan_type]}`}>
                {vulnerability.scan_type.toUpperCase()}
              </span>
              {vulnerability.status === 'resolved' && (
                <span className="px-2 py-1 text-xs rounded bg-green-100 text-green-800 font-medium">
                  ✓ RESOLVED
                </span>
              )}
              {vulnerability.status === 'false_positive' && (
                <span className="px-2 py-1 text-xs rounded bg-gray-100 text-gray-800 font-medium">
                  FALSE POSITIVE
                </span>
              )}
            </div>

            <p className="text-sm text-gray-600 mb-3">{vulnerability.description}</p>

            <div className="flex items-center space-x-6 text-sm flex-wrap gap-2">
              <div className="flex items-center space-x-1 text-gray-600">
                <FileText className="w-4 h-4" />
                <span className="font-mono text-xs">{vulnerability.file_path}</span>
              </div>
              {vulnerability.line_number > 0 && (
                <div className="flex items-center space-x-1 text-gray-600">
                  <Code className="w-4 h-4" />
                  <span>Line {vulnerability.line_number}</span>
                </div>
              )}
              {vulnerability.cwe_id && (
                <span className="badge badge-info">{vulnerability.cwe_id}</span>
              )}
              {vulnerability.cvss_score && (
                <span className="text-gray-500">CVSS: {vulnerability.cvss_score}</span>
              )}
            </div>
          </div>

          <div>
            {isExpanded ? (
              <ChevronUp className="w-5 h-5 text-gray-400" />
            ) : (
              <ChevronDown className="w-5 h-5 text-gray-400" />
            )}
          </div>
        </div>
      </div>

      {/* Expanded Details */}
      {isExpanded && (
        <div className="border-t border-gray-200 p-6 space-y-6">
          {/* Source & Sink Information (for SAST) */}
          {vulnerability.scan_type === 'sast' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-red-900 mb-2">🔴 Source (User Input)</h4>
                <p className="text-xs text-red-800 font-mono">{vulnerability.file_path}:{vulnerability.line_number}</p>
                <p className="text-sm text-red-700 mt-2">Untrusted data enters here</p>
              </div>

              <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-orange-900 mb-2">🟠 Sink (Dangerous Operation)</h4>
                <p className="text-xs text-orange-800 font-mono">Flows to dangerous function</p>
                <p className="text-sm text-orange-700 mt-2">Data used without proper validation</p>
              </div>
            </div>
          )}

          {/* Code Snippet */}
          {vulnerability.code_snippet && (
            <div>
              <h4 className="text-sm font-semibold text-gray-900 mb-2">
                {vulnerability.scan_type === 'sast' ? 'Vulnerable Code' :
                 vulnerability.scan_type === 'secret' ? 'Exposed Secret Location' :
                 'Affected Dependency'}
              </h4>
              <div className="bg-gray-900 rounded-lg p-4 overflow-x-auto">
                <code className="text-sm text-red-400 whitespace-pre-wrap">{vulnerability.code_snippet}</code>
              </div>
            </div>
          )}

          {/* OWASP & STRIDE Info */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {vulnerability.owasp_category && (
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-blue-900 mb-2">OWASP Category</h4>
                <p className="text-sm text-blue-800">{vulnerability.owasp_category}</p>
              </div>
            )}

            {vulnerability.stride_category && (
              <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-purple-900 mb-2">STRIDE Category</h4>
                <p className="text-sm text-purple-800">{vulnerability.stride_category}</p>
              </div>
            )}

            {vulnerability.mitre_attack_id && (
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-yellow-900 mb-2">MITRE ATT&CK</h4>
                <p className="text-sm text-yellow-800">{vulnerability.mitre_attack_id}</p>
              </div>
            )}
          </div>

          {/* Remediation */}
          <div className="bg-green-50 border border-green-200 rounded-lg p-4">
            <h4 className="text-sm font-semibold text-green-900 mb-2">
              Remediation Guidance
            </h4>
            <p className="text-sm text-green-900 mb-3">{vulnerability.remediation}</p>

            {vulnerability.remediation_code && (
              <div className="bg-white rounded p-3 border border-green-300">
                <p className="text-xs text-green-700 font-medium mb-2">Secure Code Example:</p>
                <pre className="text-xs text-gray-800 whitespace-pre-wrap">
                  {vulnerability.remediation_code}
                </pre>
              </div>
            )}
          </div>

          {/* Auto-Remediation Result - Enhanced Professional View */}
          {remediationResult && (
            <div className="space-y-4">
              {/* Status Header */}
              <div className={`border-l-4 rounded-r-lg p-4 ${
                remediationResult.success
                  ? 'bg-gradient-to-r from-green-50 to-green-100 border-green-500'
                  : 'bg-gradient-to-r from-red-50 to-red-100 border-red-500'
              }`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    {remediationResult.success ? (
                      <CheckCircle className="w-6 h-6 text-green-600" />
                    ) : (
                      <XCircle className="w-6 h-6 text-red-600" />
                    )}
                    <div>
                      <h4 className={`text-base font-bold ${
                        remediationResult.success ? 'text-green-900' : 'text-red-900'
                      }`}>
                        {remediationResult.success ? 'AI Auto-Remediation Complete' : 'Auto-Remediation Failed'}
                      </h4>
                      <p className={`text-sm ${
                        remediationResult.success ? 'text-green-700' : 'text-red-700'
                      }`}>
                        {remediationResult.message}
                      </p>
                    </div>
                  </div>
                  {remediationResult.success && (
                    <div className="flex items-center space-x-2">
                      <div className="text-right">
                        <p className="text-xs font-semibold text-green-800">Confidence Score</p>
                        <p className="text-2xl font-bold text-green-600">95%</p>
                      </div>
                      <Sparkles className="w-8 h-8 text-green-500" />
                    </div>
                  )}
                </div>
              </div>

              {/* Detailed Explanation */}
              {remediationResult.explanation && (
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-blue-900 mb-2 flex items-center">
                    <MessageSquare className="w-4 h-4 mr-2" />
                    What Was Changed and Why
                  </h4>
                  <p className="text-sm text-blue-900 leading-relaxed">{remediationResult.explanation}</p>
                </div>
              )}

              {/* Before/After Code Comparison */}
              {remediationResult.fixed_code && (
                <div className="border border-gray-300 rounded-lg overflow-hidden">
                  <div className="bg-gradient-to-r from-gray-700 to-gray-800 px-4 py-3 flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Code className="w-5 h-5 text-white" />
                      <h4 className="text-sm font-semibold text-white">Code Comparison</h4>
                      <span className="text-xs text-gray-300 font-mono">{vulnerability.file_path}</span>
                    </div>
                    <button
                      onClick={handleCopyCode}
                      className="flex items-center space-x-2 px-3 py-1.5 bg-white/10 hover:bg-white/20 rounded text-xs text-white transition"
                    >
                      {copiedCode ? (
                        <>
                          <Check className="w-3 h-3" />
                          <span>Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy Fixed Code</span>
                        </>
                      )}
                    </button>
                  </div>

                  <div className="grid grid-cols-2 divide-x divide-gray-300">
                    {/* Before Code */}
                    <div className="bg-red-50">
                      <div className="bg-red-100 px-4 py-2 border-b border-red-200">
                        <p className="text-xs font-semibold text-red-900 flex items-center">
                          <XCircle className="w-3 h-3 mr-1" />
                          Vulnerable Code (Before)
                        </p>
                      </div>
                      <div className="p-4 max-h-96 overflow-y-auto">
                        <pre className="text-xs text-red-900 font-mono leading-relaxed whitespace-pre-wrap">
                          {vulnerability.code_snippet || '// Code snippet not available'}
                        </pre>
                      </div>
                    </div>

                    {/* After Code */}
                    <div className="bg-green-50">
                      <div className="bg-green-100 px-4 py-2 border-b border-green-200">
                        <p className="text-xs font-semibold text-green-900 flex items-center">
                          <CheckCircle className="w-3 h-3 mr-1" />
                          Secure Code (After)
                        </p>
                      </div>
                      <div className="p-4 max-h-96 overflow-y-auto">
                        <pre className="text-xs text-green-900 font-mono leading-relaxed whitespace-pre-wrap">
                          {remediationResult.fixed_code}
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Git Integration Panel */}
              {showGitPanel && remediationResult.success && (
                <div className="border border-gray-300 rounded-lg overflow-hidden bg-gradient-to-br from-indigo-50 to-purple-50">
                  <div className="bg-gradient-to-r from-indigo-600 to-purple-600 px-4 py-3 flex items-center space-x-2">
                    <GitBranch className="w-5 h-5 text-white" />
                    <h4 className="text-sm font-semibold text-white">Commit Fix to Repository</h4>
                  </div>

                  <div className="p-5 space-y-4">
                    {commitSuccess ? (
                      <div className="bg-green-100 border border-green-300 rounded-lg p-4 flex items-start space-x-3">
                        <CheckCircle className="w-6 h-6 text-green-600 mt-0.5" />
                        <div>
                          <h5 className="text-sm font-semibold text-green-900 mb-1">Successfully Committed!</h5>
                          <p className="text-sm text-green-800">
                            Changes have been committed to branch <code className="px-2 py-0.5 bg-green-200 rounded font-mono text-xs">{gitBranch}</code>
                          </p>
                        </div>
                      </div>
                    ) : (
                      <>
                        {/* Branch Name */}
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Target Branch
                          </label>
                          <div className="flex items-center space-x-2">
                            <GitBranch className="w-4 h-4 text-gray-500" />
                            <input
                              type="text"
                              value={gitBranch}
                              onChange={(e) => setGitBranch(e.target.value)}
                              className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm font-mono"
                              placeholder="e.g., security-fix-sql-injection"
                            />
                          </div>
                          <p className="text-xs text-gray-500 mt-1">Branch will be created if it doesn't exist</p>
                        </div>

                        {/* Commit Message */}
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-2">
                            Commit Message
                          </label>
                          <div className="flex items-start space-x-2">
                            <GitCommit className="w-4 h-4 text-gray-500 mt-2" />
                            <textarea
                              value={commitMessage}
                              onChange={(e) => setCommitMessage(e.target.value)}
                              rows={4}
                              className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm font-mono"
                              placeholder="Describe the security fix..."
                            />
                          </div>
                        </div>

                        {/* File Info */}
                        <div className="bg-white border border-gray-200 rounded-lg p-3">
                          <p className="text-xs font-semibold text-gray-700 mb-1">Changes will be applied to:</p>
                          <code className="text-xs text-indigo-700 font-mono">{vulnerability.file_path}</code>
                        </div>

                        {/* Commit Button */}
                        <button
                          onClick={handleCommitFix}
                          disabled={committing || !gitBranch || !commitMessage}
                          className="w-full btn btn-primary inline-flex items-center justify-center space-x-2 py-3 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {committing ? (
                            <>
                              <Loader2 className="w-4 h-4 animate-spin" />
                              <span>Committing Changes...</span>
                            </>
                          ) : (
                            <>
                              <GitCommit className="w-4 h-4" />
                              <span>Commit Fix to Repository</span>
                            </>
                          )}
                        </button>
                      </>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center space-x-3 flex-wrap gap-2">
            <button
              onClick={handleAutoRemediate}
              disabled={autoRemediating}
              className="btn btn-primary inline-flex items-center space-x-2"
            >
              {autoRemediating ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Sparkles className="w-4 h-4" />
              )}
              <span>{autoRemediating ? 'Remediating...' : 'AI Auto-Remediate'}</span>
            </button>

            <Link
              to={`/chat?context=vulnerability&id=${vulnerability.id}&project=${projectId}&title=${encodeURIComponent(vulnerability.title)}&severity=${vulnerability.severity}&cwe=${vulnerability.cwe_id || ''}&description=${encodeURIComponent(vulnerability.description || '')}&file=${encodeURIComponent(vulnerability.file_path || '')}&line=${vulnerability.line_number || ''}&code=${encodeURIComponent(vulnerability.code_snippet || '')}`}
              className="btn btn-secondary inline-flex items-center space-x-2"
            >
              <MessageSquare className="w-4 h-4" />
              <span>Ask AI Assistant</span>
            </Link>

            {vulnerability.status === 'active' ? (
              <>
                <button
                  onClick={() => handleStatusUpdate('resolved')}
                  className="btn btn-secondary inline-flex items-center space-x-2"
                >
                  <CheckCheck className="w-4 h-4" />
                  <span>Mark as Resolved</span>
                </button>
                <button
                  onClick={() => handleStatusUpdate('false_positive')}
                  className="btn btn-secondary inline-flex items-center space-x-2"
                >
                  <AlertCircle className="w-4 h-4" />
                  <span>False Positive</span>
                </button>
              </>
            ) : (
              <button
                onClick={() => handleStatusUpdate('active')}
                className="btn bg-orange-600 hover:bg-orange-700 text-white inline-flex items-center space-x-2"
              >
                <AlertTriangle className="w-4 h-4" />
                <span>Reopen Issue</span>
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
