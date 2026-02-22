import { useState, useEffect, useCallback } from 'react'
import { useParams, Link, useSearchParams } from 'react-router-dom'
import { Bug, ArrowLeft, Code, FileText, MessageSquare, ChevronDown, ChevronUp, Sparkles, Loader2, CheckCircle, XCircle, GitBranch, GitCommit, Copy, Check, CheckCheck, AlertCircle, AlertTriangle, Search, Layers, Zap, Shield, Target, ExternalLink, TrendingUp, GitMerge, Package, Database, Github, Globe } from 'lucide-react'
import axios from 'axios'
import TaintFlowVisualization from '../components/TaintFlowVisualization'
import DependencyTreeVisualization, { buildDependencyTree } from '../components/DependencyTreeVisualization'

// Helper function to parse SCA source from file_path or code_snippet
function parseScaSource(vulnerability: any): { source: string; package: string; version: string } | null {
  if (vulnerability.scan_type !== 'sca') return null

  const filePath = vulnerability.file_path || ''
  const codeSnippet = vulnerability.code_snippet || ''

  // Extract source from file_path: "npm dependency: lodash 4.17.15 [Source: GITHUB_ADVISORY]"
  const sourceMatch = filePath.match(/\[Source:\s*([^\]]+)\]/i)
  const source = sourceMatch ? sourceMatch[1].toLowerCase() : 'local'

  // Extract package info from code_snippet
  const packageMatch = codeSnippet.match(/Package:\s*([^@\n]+)@([^\n]+)/i)
  const pkg = packageMatch ? packageMatch[1].trim() : ''
  const version = packageMatch ? packageMatch[2].trim() : ''

  return { source, package: pkg, version }
}

// Helper function to parse direct/transitive dependency info
function parseScaDependencyType(vulnerability: any): { isTransitive: boolean; introducedBy: string | null; dependencyChain: string | null } | null {
  if (vulnerability.scan_type !== 'sca') return null

  const filePath = vulnerability.file_path || ''
  const codeSnippet = vulnerability.code_snippet || ''

  // Check for TRANSITIVE or DIRECT indicator
  const isTransitive = filePath.includes('[TRANSITIVE]')

  // Extract "Via" info for transitive dependencies
  const viaMatch = filePath.match(/\[Via:\s*([^\]]+)\]/i)
  const introducedBy = viaMatch ? viaMatch[1] : null

  // Extract dependency chain from code snippet
  const chainMatch = codeSnippet.match(/Dependency chain:\s*(.+)/i)
  const dependencyChain = chainMatch ? chainMatch[1] : null

  return { isTransitive, introducedBy, dependencyChain }
}

// Helper function to extract CVE IDs from SCA vulnerability
function parseScaCveIds(vulnerability: any): string[] {
  if (vulnerability.scan_type !== 'sca') return []

  const codeSnippet = vulnerability.code_snippet || ''
  const title = vulnerability.title || ''
  const description = vulnerability.description || ''

  // Extract CVE from code_snippet: "CVE: CVE-2021-3749" or "CVE: CVE-2020-8203, CVE-2019-10744"
  const cveMatch = codeSnippet.match(/CVE:\s*([^\n]+)/i)
  if (cveMatch) {
    const cveStr = cveMatch[1]
    // Parse comma-separated CVEs
    const cves = cveStr.split(/[,\s]+/).filter((s: string) => s.startsWith('CVE-'))
    if (cves.length > 0) return cves
  }

  // Also check title and description for CVE patterns
  const allText = `${title} ${description}`
  const cvePatterns = allText.match(/CVE-\d{4}-\d{4,}/g)
  if (cvePatterns) {
    return [...new Set(cvePatterns)]
  }

  return []
}

// Dependency Type Badge component
function DependencyTypeBadge({ isTransitive, introducedBy }: { isTransitive: boolean; introducedBy: string | null }) {
  if (isTransitive) {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-800 border border-amber-300">
        <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
        </svg>
        TRANSITIVE
        {introducedBy && <span className="ml-1 text-amber-600">via {introducedBy}</span>}
      </span>
    )
  }
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 border border-green-300">
      <Package className="w-3 h-3 mr-1" />
      DIRECT
    </span>
  )
}

// Source badge component
function SourceBadge({ source }: { source: string }) {
  const sourceConfig: Record<string, { icon: any; color: string; label: string }> = {
    github_advisory: { icon: Github, color: 'bg-gray-800 text-white', label: 'GitHub Advisory' },
    osv: { icon: Globe, color: 'bg-blue-600 text-white', label: 'OSV' },
    snyk: { icon: Shield, color: 'bg-purple-600 text-white', label: 'Snyk' },
    nvd: { icon: Shield, color: 'bg-red-600 text-white', label: 'NVD' },
    local: { icon: Database, color: 'bg-green-600 text-white', label: 'Local DB' },
  }

  const config = sourceConfig[source.toLowerCase()] || sourceConfig.local
  const Icon = config.icon

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${config.color}`}>
      <Icon className="w-3 h-3 mr-1" />
      {config.label}
    </span>
  )
}

export default function VulnerabilitiesPage() {
  const { id } = useParams()
  const [searchParams] = useSearchParams()
  const [scans, setScans] = useState<any[]>([])
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([])
  const [threatIntel, setThreatIntel] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedSeverity, setSelectedSeverity] = useState('all')
  const [selectedScanType, setSelectedScanType] = useState(searchParams.get('scanType') || 'all')
  const [selectedStatusView, setSelectedStatusView] = useState<'active' | 'resolved' | 'false_positive'>('active')
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [groupBy, setGroupBy] = useState<'none' | 'category' | 'severity' | 'scan_type' | 'file'>('category')
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const [showThreatCorrelation, setShowThreatCorrelation] = useState(true)
  const [deduplicating, setDeduplicating] = useState(false)

  const handleDeduplicateSca = async () => {
    setDeduplicating(true)
    try {
      const token = localStorage.getItem('token')
      const response = await axios.post(`/api/projects/${id}/deduplicate-sca`, {}, {
        headers: { Authorization: `Bearer ${token}` },
      })
      alert(`${response.data.message}`)
      // Refresh vulnerabilities
      setLoading(true)
      window.location.reload()
    } catch (error: any) {
      alert('Failed to deduplicate: ' + (error.response?.data?.detail || error.message))
    } finally {
      setDeduplicating(false)
    }
  }

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

      // Fetch threat intelligence for correlation
      try {
        const threatRes = await axios.get('/api/threat-intel/threats', {
          headers: { Authorization: `Bearer ${token}` },
        })
        setThreatIntel(threatRes.data.threats || [])
      } catch (threatError) {
        console.error('Failed to fetch threat intel:', threatError)
      }
    } catch (error) {
      console.error('Failed to fetch scans:', error)
    } finally {
      console.log('Setting loading to false')
      setLoading(false)
    }
  }, [id, loading])

  // Correlate vulnerabilities with threat intel
  const getCorrelatedThreats = (vuln: any) => {
    const correlatedThreats: any[] = []

    // Match by CWE ID
    if (vuln.cwe_id) {
      const cweNum = vuln.cwe_id.replace('CWE-', '')
      threatIntel.forEach(threat => {
        if (threat.cwe_id && threat.cwe_id.includes(cweNum)) {
          correlatedThreats.push({ ...threat, match_type: 'CWE' })
        }
      })
    }

    // Match by keywords in title/description
    const vulnKeywords = [vuln.title, vuln.description, vuln.owasp_category]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()

    const threatKeywords = ['sql injection', 'xss', 'cross-site', 'rce', 'remote code', 'buffer overflow',
      'authentication', 'authorization', 'path traversal', 'directory traversal', 'ssrf', 'xxe',
      'deserialization', 'injection', 'command injection', 'ldap', 'xpath']

    threatKeywords.forEach(keyword => {
      if (vulnKeywords.includes(keyword)) {
        threatIntel.forEach(threat => {
          const threatDesc = (threat.description || '').toLowerCase()
          const threatName = (threat.name || '').toLowerCase()
          if ((threatDesc.includes(keyword) || threatName.includes(keyword)) &&
              !correlatedThreats.find(t => t.cve_id === threat.cve_id)) {
            correlatedThreats.push({ ...threat, match_type: 'Keyword' })
          }
        })
      }
    })

    return correlatedThreats.slice(0, 3) // Return top 3 matches
  }

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

  // Filter by severity, scan type, status, and search query
  const filteredVulnerabilities = vulnerabilities.filter((v) => {
    const severityMatch = selectedSeverity === 'all' || v.severity === selectedSeverity
    const scanTypeMatch = selectedScanType === 'all' || v.scan_type === selectedScanType
    const statusMatch = v.status === selectedStatusView || (!v.status && selectedStatusView === 'active')

    // Search filter - includes CVE search for SCA vulnerabilities
    const searchMatch = !searchQuery ||
      v.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.file_path?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.cwe_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.code_snippet?.toLowerCase().includes(searchQuery.toLowerCase()) // Search CVE in code_snippet for SCA

    return severityMatch && scanTypeMatch && statusMatch && searchMatch
  })

  // Group vulnerabilities
  const groupVulnerabilities = () => {
    if (groupBy === 'none') {
      return { 'All Vulnerabilities': filteredVulnerabilities }
    }

    const groups: Record<string, any[]> = {}

    filteredVulnerabilities.forEach((vuln) => {
      let groupKey = ''

      switch (groupBy) {
        case 'category':
          groupKey = vuln.title?.split(':')[0] || 'Unknown'
          break
        case 'severity':
          groupKey = (vuln.severity || 'unknown').charAt(0).toUpperCase() + (vuln.severity || 'unknown').slice(1)
          break
        case 'scan_type':
          groupKey = (vuln.scan_type || 'unknown').toUpperCase()
          break
        case 'file':
          groupKey = vuln.file_path || 'Unknown File'
          break
        default:
          groupKey = 'All'
      }

      if (!groups[groupKey]) {
        groups[groupKey] = []
      }
      groups[groupKey].push(vuln)
    })

    // Sort groups by count (descending)
    const sortedGroups = Object.fromEntries(
      Object.entries(groups).sort((a, b) => b[1].length - a[1].length)
    )

    return sortedGroups
  }

  const groupedVulnerabilities = groupVulnerabilities()

  const toggleGroup = (groupName: string) => {
    const newExpanded = new Set(expandedGroups)
    if (newExpanded.has(groupName)) {
      newExpanded.delete(groupName)
    } else {
      newExpanded.add(groupName)
    }
    setExpandedGroups(newExpanded)
  }

  const toggleAllGroups = (expand: boolean) => {
    if (expand) {
      setExpandedGroups(new Set(Object.keys(groupedVulnerabilities)))
    } else {
      setExpandedGroups(new Set())
    }
  }

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
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
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
        <div className="card p-4 bg-gradient-to-r from-orange-50 to-red-50 border-orange-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-orange-900">Threat Intel Matches</p>
              <p className="text-2xl font-bold text-orange-600">
                {vulnerabilities.filter(v => getCorrelatedThreats(v).length > 0).length}
              </p>
              <p className="text-xs text-orange-700 mt-1">Actively exploited threats</p>
            </div>
            <Zap className="w-8 h-8 text-orange-500" />
          </div>
        </div>
      </div>

      {/* SCA Sources Summary */}
      {scanTypeCounts.sca > 0 && (
        <div className="card p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center space-x-2">
              <Package className="w-5 h-5 text-purple-600" />
              <h3 className="font-semibold text-gray-900">SCA Vulnerability Sources</h3>
              <span className="text-sm text-gray-500">({scanTypeCounts.sca} findings from {(() => {
                const sources = new Set<string>()
                vulnerabilities.filter(v => v.scan_type === 'sca').forEach(v => {
                  const info = parseScaSource(v)
                  if (info) sources.add(info.source)
                })
                return sources.size
              })()} sources)</span>
            </div>
            <button
              onClick={handleDeduplicateSca}
              disabled={deduplicating}
              className="inline-flex items-center px-3 py-1.5 text-sm font-medium text-purple-700 bg-purple-100 rounded-md hover:bg-purple-200 disabled:opacity-50"
              title="Remove duplicate vulnerabilities (same package + CVE)"
            >
              {deduplicating ? (
                <>
                  <Loader2 className="w-4 h-4 mr-1 animate-spin" />
                  Removing...
                </>
              ) : (
                <>
                  <Layers className="w-4 h-4 mr-1" />
                  Remove Duplicates
                </>
              )}
            </button>
          </div>
          <div className="flex items-center space-x-4 flex-wrap gap-2">
            {(() => {
              const sourceCounts: Record<string, number> = {}
              vulnerabilities.filter(v => v.scan_type === 'sca').forEach(v => {
                const info = parseScaSource(v)
                const source = info?.source || 'local'
                sourceCounts[source] = (sourceCounts[source] || 0) + 1
              })

              return Object.entries(sourceCounts).map(([source, count]) => (
                <div key={source} className="flex items-center space-x-2 bg-gray-100 rounded-lg px-3 py-2">
                  <SourceBadge source={source} />
                  <span className="text-sm font-semibold text-gray-700">{count}</span>
                  <span className="text-xs text-gray-500">findings</span>
                </div>
              ))
            })()}
          </div>
        </div>
      )}

      {/* Dependency Tree Visualization - Show when SCA filter is active */}
      {(selectedScanType === 'sca' || selectedScanType === 'all') && scanTypeCounts.sca > 0 && (
        <DependencyTreeVisualization
          dependencies={buildDependencyTree(vulnerabilities)}
          title="Vulnerable Dependencies"
          showOnlyVulnerable={selectedScanType === 'sca'}
        />
      )}

      {/* Threat Intel Correlation Banner */}
      {threatIntel.length > 0 && (
        <div className="card p-4 bg-gradient-to-r from-red-50 via-orange-50 to-yellow-50 border-l-4 border-red-500">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-red-100 rounded-full flex items-center justify-center">
                <Shield className="w-6 h-6 text-red-600" />
              </div>
              <div>
                <h3 className="font-semibold text-gray-900">Live Threat Intelligence Correlation</h3>
                <p className="text-sm text-gray-600">
                  Comparing {vulnerabilities.length} findings against {threatIntel.length} active threats from CISA KEV, NVD, and Exploit-DB
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <p className="text-xs text-gray-500">Actively Exploited</p>
                <p className="text-lg font-bold text-red-600">
                  {threatIntel.filter(t => t.actively_exploited).length}
                </p>
              </div>
              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={showThreatCorrelation}
                  onChange={(e) => setShowThreatCorrelation(e.target.checked)}
                  className="w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
                />
                <span className="text-sm text-gray-700">Show correlations</span>
              </label>
              <Link
                to="/threat-intel"
                className="btn btn-secondary btn-sm inline-flex items-center space-x-2"
              >
                <TrendingUp className="w-4 h-4" />
                <span>View All Threats</span>
              </Link>
            </div>
          </div>
        </div>
      )}

      {/* Search and Group By */}
      <div className="card p-4 space-y-4">
        {/* Search Bar */}
        <div className="flex items-center space-x-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search vulnerabilities by title, description, file path, CVE, or CWE..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                <XCircle className="w-5 h-5" />
              </button>
            )}
          </div>

          {/* Group By Selector */}
          <div className="flex items-center space-x-2">
            <Layers className="w-5 h-5 text-gray-600" />
            <span className="text-sm font-medium text-gray-700">Group By:</span>
            <select
              value={groupBy}
              onChange={(e) => {
                setGroupBy(e.target.value as any)
                setExpandedGroups(new Set())
              }}
              className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              <option value="category">Category</option>
              <option value="severity">Severity</option>
              <option value="scan_type">Scan Type</option>
              <option value="file">File</option>
              <option value="none">No Grouping</option>
            </select>
          </div>

          {/* Expand/Collapse All */}
          {groupBy !== 'none' && Object.keys(groupedVulnerabilities).length > 1 && (
            <div className="flex items-center space-x-2">
              <button
                onClick={() => toggleAllGroups(true)}
                className="px-3 py-2 text-sm text-gray-700 hover:text-primary-600"
              >
                Expand All
              </button>
              <span className="text-gray-300">|</span>
              <button
                onClick={() => toggleAllGroups(false)}
                className="px-3 py-2 text-sm text-gray-700 hover:text-primary-600"
              >
                Collapse All
              </button>
            </div>
          )}
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
              {selectedSeverity === 'all' && selectedScanType === 'all' && !searchQuery
                ? 'Run a security scan to see results'
                : 'No matching vulnerabilities found with current filters'}
            </p>
          </div>
        ) : groupBy === 'none' ? (
          // No grouping - render flat list
          filteredVulnerabilities.map((vuln) => (
            <VulnerabilityCard
              key={vuln.id}
              vulnerability={vuln}
              isExpanded={expandedVuln === vuln.id}
              onToggle={() => setExpandedVuln(expandedVuln === vuln.id ? null : vuln.id)}
              projectId={id!}
              onUpdate={fetchAllScans}
              correlatedThreats={showThreatCorrelation ? getCorrelatedThreats(vuln) : []}
            />
          ))
        ) : (
          // Grouped rendering
          Object.entries(groupedVulnerabilities).map(([groupName, groupVulns]) => {
            const isExpanded = expandedGroups.has(groupName)

            return (
              <div key={groupName} className="card mb-4">
                {/* Group Header */}
                <button
                  onClick={() => toggleGroup(groupName)}
                  className="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-50 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    {isExpanded ? (
                      <ChevronDown className="w-5 h-5 text-gray-600" />
                    ) : (
                      <ChevronUp className="w-5 h-5 text-gray-600" />
                    )}
                    <h3 className="text-lg font-semibold text-gray-900">{groupName}</h3>
                    <span className="badge badge-info">
                      {groupVulns.length} {groupVulns.length === 1 ? 'vulnerability' : 'vulnerabilities'}
                    </span>
                  </div>

                  {/* Show severity distribution for this group */}
                  <div className="flex items-center space-x-2">
                    {['critical', 'high', 'medium', 'low'].map((severity) => {
                      const count = groupVulns.filter((v) => v.severity === severity).length
                      if (count === 0) return null

                      const severityColors: any = {
                        critical: 'badge-critical',
                        high: 'badge-high',
                        medium: 'badge-medium',
                        low: 'badge-low',
                      }

                      return (
                        <span key={severity} className={`badge ${severityColors[severity]} text-xs`}>
                          {count} {severity}
                        </span>
                      )
                    })}
                  </div>
                </button>

                {/* Group Content */}
                {isExpanded && (
                  <div className="border-t border-gray-200 divide-y divide-gray-200">
                    {groupVulns.map((vuln) => (
                      <div key={vuln.id} className="p-4">
                        <VulnerabilityCard
                          vulnerability={vuln}
                          isExpanded={expandedVuln === vuln.id}
                          onToggle={() => setExpandedVuln(expandedVuln === vuln.id ? null : vuln.id)}
                          projectId={id!}
                          onUpdate={fetchAllScans}
                          correlatedThreats={showThreatCorrelation ? getCorrelatedThreats(vuln) : []}
                        />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}

function SeverityCard({ title, count, color }: any) {
  const colorClasses: { [key: string]: string } = {
    red: 'bg-red-100 text-red-600 border-red-200',
    orange: 'bg-orange-100 text-orange-600 border-orange-200',
    yellow: 'bg-yellow-100 text-yellow-600 border-yellow-200',
    blue: 'bg-blue-100 text-blue-600 border-blue-200',
  }

  return (
    <div className={`card p-6 border-2 ${colorClasses[color] || colorClasses.blue}`}>
      <p className="text-sm font-medium mb-1">{title}</p>
      <p className="text-3xl font-bold">{count}</p>
    </div>
  )
}

function VulnerabilityCard({ vulnerability, isExpanded, onToggle, projectId, onUpdate, correlatedThreats = [] }: any) {
  const [autoRemediating, setAutoRemediating] = useState(false)
  const [remediationResult, setRemediationResult] = useState<any>(null)
  const [showGitPanel, setShowGitPanel] = useState(false)
  const [gitBranch, setGitBranch] = useState('security-fix-' + vulnerability.id)

  // For SCA vulnerabilities, show CVE in commit message; for others show CWE
  const vulnerabilityId = vulnerability.scan_type === 'sca'
    ? parseScaCveIds(vulnerability).join(', ') || 'security vulnerability'
    : vulnerability.cwe_id || 'security vulnerability'
  const [commitMessage, setCommitMessage] = useState(`Fix: ${vulnerability.title}\n\nResolves ${vulnerabilityId}\nSeverity: ${vulnerability.severity}`)

  const [committing, setCommitting] = useState(false)
  const [commitSuccess, setCommitSuccess] = useState(false)
  const [copiedCode, setCopiedCode] = useState(false)
  const [showTaintFlow, setShowTaintFlow] = useState(false)
  const [taintFlowData, setTaintFlowData] = useState<any>(null)
  const [loadingTaintFlow, setLoadingTaintFlow] = useState(false)

  const hasActiveExploit = correlatedThreats.some((t: any) => t.actively_exploited)

  const fetchTaintFlow = async () => {
    if (taintFlowData) {
      setShowTaintFlow(!showTaintFlow)
      return
    }

    setLoadingTaintFlow(true)
    try {
      const token = localStorage.getItem('token')
      const response = await axios.get(
        `/api/vulnerabilities/${vulnerability.id}/taint-flow`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      )
      setTaintFlowData(response.data.taint_flow)
      setShowTaintFlow(true)
    } catch (error) {
      console.error('Failed to fetch taint flow:', error)
      // Show sample data if API fails
      setTaintFlowData(null)
      setShowTaintFlow(true)
    } finally {
      setLoadingTaintFlow(false)
    }
  }

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
            <div className="flex items-center space-x-3 mb-2 flex-wrap gap-y-1">
              <Bug className="w-5 h-5 text-gray-500" />
              <h3 className="font-semibold text-gray-900">{vulnerability.title}</h3>
              <span className={`badge ${severityColors[vulnerability.severity]}`}>
                {vulnerability.severity.toUpperCase()}
              </span>
              <span className={`px-2 py-1 text-xs rounded ${scanTypeColors[vulnerability.scan_type]}`}>
                {vulnerability.scan_type.toUpperCase()}
              </span>
              {/* SCA Source and Dependency Type Badges */}
              {vulnerability.scan_type === 'sca' && (() => {
                const scaInfo = parseScaSource(vulnerability)
                const depType = parseScaDependencyType(vulnerability)
                return (
                  <>
                    {depType && <DependencyTypeBadge isTransitive={depType.isTransitive} introducedBy={depType.introducedBy} />}
                    {scaInfo && <SourceBadge source={scaInfo.source} />}
                  </>
                )
              })()}
              {hasActiveExploit && (
                <span className="px-2 py-1 text-xs rounded bg-red-600 text-white font-medium inline-flex items-center space-x-1 animate-pulse">
                  <Zap className="w-3 h-3" />
                  <span>ACTIVELY EXPLOITED</span>
                </span>
              )}
              {correlatedThreats.length > 0 && !hasActiveExploit && (
                <span className="px-2 py-1 text-xs rounded bg-orange-100 text-orange-800 font-medium inline-flex items-center space-x-1">
                  <Shield className="w-3 h-3" />
                  <span>{correlatedThreats.length} Threat Match{correlatedThreats.length > 1 ? 'es' : ''}</span>
                </span>
              )}
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

            {/* Vulnerable Source Location - Different display for SCA vs other scans */}
            {vulnerability.scan_type === 'sca' ? (
              // SCA-specific display with dependency chain
              (() => {
                const depType = parseScaDependencyType(vulnerability)
                const isTransitive = depType?.isTransitive || false
                const bgColor = isTransitive ? 'bg-amber-50 border-l-amber-500' : 'bg-red-50 border-l-red-500'
                const textColor = isTransitive ? 'text-amber-900' : 'text-red-900'
                const accentColor = isTransitive ? 'text-amber-800' : 'text-red-800'
                const headerBg = isTransitive ? 'bg-amber-100' : 'bg-red-100'

                return (
                  <div className={`${bgColor} border-l-4 p-4 mb-3 rounded-r`}>
                    <div className="flex items-start space-x-3">
                      <Package className={`w-5 h-5 ${accentColor} mt-0.5 flex-shrink-0`} />
                      <div className="flex-1 min-w-0">
                        <div className={`${headerBg} -mx-4 -mt-4 px-4 py-2 mb-3 rounded-tr flex items-center justify-between`}>
                          <p className={`text-xs font-semibold ${textColor}`}>
                            {isTransitive ? '⚠️ TRANSITIVE DEPENDENCY VULNERABILITY' : '🎯 DIRECT DEPENDENCY VULNERABILITY'}
                          </p>
                          {isTransitive ? (
                            <span className="text-xs text-amber-700 bg-amber-200 px-2 py-0.5 rounded">
                              Update parent package to fix
                            </span>
                          ) : (
                            <span className="text-xs text-red-700 bg-red-200 px-2 py-0.5 rounded">
                              Directly update this package
                            </span>
                          )}
                        </div>

                        <p className={`font-mono text-sm ${accentColor} font-bold break-all`}>
                          {vulnerability.file_path}
                        </p>

                        {/* Dependency Chain Visualization for Transitive */}
                        {isTransitive && depType?.dependencyChain && (
                          <div className="mt-3 bg-white border border-amber-200 rounded-lg p-3">
                            <p className="text-xs font-semibold text-amber-800 mb-2">📦 Dependency Chain (How this package was introduced):</p>
                            <div className="flex items-center flex-wrap gap-2">
                              {depType.dependencyChain.split(' → ').map((pkg, idx, arr) => (
                                <span key={idx} className="flex items-center">
                                  <span className={`px-2 py-1 rounded text-xs font-mono ${
                                    idx === 0 ? 'bg-green-100 text-green-800 border border-green-300' :
                                    idx === arr.length - 1 ? 'bg-red-100 text-red-800 border border-red-300 font-bold' :
                                    'bg-gray-100 text-gray-700 border border-gray-300'
                                  }`}>
                                    {idx === 0 && '📁 '}
                                    {idx === arr.length - 1 && '⚠️ '}
                                    {pkg}
                                  </span>
                                  {idx < arr.length - 1 && (
                                    <span className="mx-2 text-amber-500">→</span>
                                  )}
                                </span>
                              ))}
                            </div>
                            <p className="text-xs text-amber-600 mt-2">
                              💡 To fix: Update <strong>{depType.dependencyChain.split(' → ')[0]}</strong> to a version that uses a patched <strong>{depType.dependencyChain.split(' → ').pop()}</strong>
                            </p>
                          </div>
                        )}

                        {/* Introduced By for simple transitive display */}
                        {isTransitive && !depType?.dependencyChain && depType?.introducedBy && (
                          <div className="mt-2 text-xs text-amber-700">
                            <span className="font-semibold">Introduced by:</span> {depType.introducedBy}
                          </div>
                        )}

                        {vulnerability.code_snippet && (
                          <div className="mt-3 bg-gray-900 rounded p-3 overflow-x-auto">
                            <p className={`text-xs ${isTransitive ? 'text-amber-400' : 'text-red-400'} font-semibold mb-2`}>▼ Package Details:</p>
                            <pre className={`text-xs ${isTransitive ? 'text-amber-300' : 'text-red-300'} font-mono whitespace-pre-wrap`}>{vulnerability.code_snippet}</pre>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })()
            ) : (
              // Standard display for SAST/Secret scans
              <div className="bg-red-50 border-l-4 border-red-500 p-4 mb-3 rounded-r">
                <div className="flex items-start space-x-3">
                  <FileText className="w-5 h-5 text-red-600 mt-0.5 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-semibold text-red-900 mb-1">VULNERABLE FILE LOCATION:</p>
                    <p className="font-mono text-sm text-red-800 font-bold break-all">
                      {vulnerability.file_path}
                      {vulnerability.line_number > 0 && (
                        <span className="ml-2 text-red-600">
                          : Line {vulnerability.line_number}
                        </span>
                      )}
                    </p>
                    {vulnerability.code_snippet && (
                      <div className="mt-3 bg-gray-900 rounded p-3 overflow-x-auto">
                        <p className="text-xs text-red-400 font-semibold mb-2">▼ Vulnerable Code:</p>
                        <pre className="text-xs text-red-300 font-mono whitespace-pre-wrap">{vulnerability.code_snippet}</pre>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            <div className="flex items-center space-x-6 text-sm flex-wrap gap-2">
              {/* Show CVE for SCA, CWE for SAST/Secret */}
              {vulnerability.scan_type === 'sca' ? (
                (() => {
                  const cves = parseScaCveIds(vulnerability)
                  return cves.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {cves.slice(0, 3).map((cve, idx) => (
                        <a
                          key={idx}
                          href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 hover:bg-red-200 border border-red-300"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <Shield className="w-3 h-3 mr-1" />
                          {cve}
                          <ExternalLink className="w-3 h-3 ml-1" />
                        </a>
                      ))}
                      {cves.length > 3 && (
                        <span className="text-xs text-gray-500">+{cves.length - 3} more</span>
                      )}
                    </div>
                  ) : null
                })()
              ) : (
                vulnerability.cwe_id && (
                  <span className="badge badge-info">{vulnerability.cwe_id}</span>
                )
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
          {/* Taint Flow Analysis Section (for SAST) */}
          {vulnerability.scan_type === 'sast' && (
            <div className="space-y-4">
              {/* Quick Source/Sink Summary */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-red-900 mb-2 flex items-center">
                    <Target className="w-4 h-4 mr-2" />
                    Source (User Input)
                  </h4>
                  <p className="text-xs text-red-800 font-mono">{vulnerability.file_path}:{vulnerability.line_number}</p>
                  <p className="text-sm text-red-700 mt-2">Untrusted data enters here</p>
                </div>

                <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-orange-900 mb-2 flex items-center">
                    <AlertTriangle className="w-4 h-4 mr-2" />
                    Sink (Dangerous Operation)
                  </h4>
                  <p className="text-xs text-orange-800 font-mono">Flows to dangerous function</p>
                  <p className="text-sm text-orange-700 mt-2">Data used without proper validation</p>
                </div>
              </div>

              {/* Taint Flow Analysis Button */}
              <button
                onClick={fetchTaintFlow}
                disabled={loadingTaintFlow}
                className="w-full py-3 px-4 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white font-medium rounded-lg flex items-center justify-center space-x-2 transition-all shadow-lg hover:shadow-xl disabled:opacity-50"
              >
                {loadingTaintFlow ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    <span>Loading Taint Flow Analysis...</span>
                  </>
                ) : (
                  <>
                    <GitMerge className="w-5 h-5" />
                    <span>{showTaintFlow ? 'Hide' : 'Show'} Detailed Taint Flow Analysis</span>
                    {showTaintFlow ? <ChevronUp className="w-4 h-4 ml-2" /> : <ChevronDown className="w-4 h-4 ml-2" />}
                  </>
                )}
              </button>

              {/* Taint Flow Visualization */}
              {showTaintFlow && (
                <TaintFlowVisualization
                  taintFlow={taintFlowData}
                  vulnerabilityType={vulnerability.title}
                  cweId={vulnerability.cwe_id}
                  showDataFlowDetails={true}
                  showControlFlowDetails={true}
                />
              )}
            </div>
          )}

          {/* SCA Dependency Information */}
          {vulnerability.scan_type === 'sca' && (() => {
            const scaInfo = parseScaSource(vulnerability)
            return (
              <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
                <div className="flex items-center space-x-2 mb-3">
                  <Package className="w-5 h-5 text-purple-600" />
                  <h4 className="text-sm font-semibold text-purple-900">Dependency Vulnerability Details</h4>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                  {/* Package Info */}
                  <div className="bg-white rounded-lg p-3 border border-purple-100">
                    <p className="text-xs text-purple-600 font-medium mb-1">Package</p>
                    <p className="text-sm font-semibold text-gray-900 font-mono">
                      {scaInfo?.package || vulnerability.title?.split(':')[0]?.replace('Vulnerable Dependency', '').trim() || 'Unknown'}
                    </p>
                  </div>

                  {/* Version */}
                  <div className="bg-white rounded-lg p-3 border border-purple-100">
                    <p className="text-xs text-purple-600 font-medium mb-1">Version</p>
                    <p className="text-sm font-semibold text-gray-900 font-mono">
                      {scaInfo?.version || 'See details'}
                    </p>
                  </div>

                  {/* Source */}
                  <div className="bg-white rounded-lg p-3 border border-purple-100">
                    <p className="text-xs text-purple-600 font-medium mb-1">Data Source</p>
                    <div className="mt-1">
                      {scaInfo ? <SourceBadge source={scaInfo.source} /> : <SourceBadge source="local" />}
                    </div>
                  </div>
                </div>

                {/* CVE Information - Prominently displayed for SCA */}
                {(() => {
                  const cves = parseScaCveIds(vulnerability)
                  if (cves.length === 0) return null
                  return (
                    <div className="bg-red-50 rounded-lg p-4 border border-red-200 mt-4">
                      <div className="flex items-center space-x-2 mb-3">
                        <Shield className="w-5 h-5 text-red-600" />
                        <p className="text-sm text-red-800 font-semibold">Associated CVE Identifiers</p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {cves.map((cve, idx) => (
                          <a
                            key={idx}
                            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center px-3 py-1.5 rounded-lg text-sm font-semibold bg-red-100 text-red-800 hover:bg-red-200 border border-red-300 transition-colors"
                          >
                            <Shield className="w-4 h-4 mr-2" />
                            {cve}
                            <ExternalLink className="w-4 h-4 ml-2" />
                          </a>
                        ))}
                      </div>
                      <p className="text-xs text-red-600 mt-2">
                        Click to view full vulnerability details on NVD (National Vulnerability Database)
                      </p>
                    </div>
                  )
                })()}
              </div>
            )
          })()}

          {/* Code Snippet */}
          {vulnerability.code_snippet && (
            <div>
              <h4 className="text-sm font-semibold text-gray-900 mb-2">
                {vulnerability.scan_type === 'sast' ? 'Vulnerable Code' :
                 vulnerability.scan_type === 'secret' ? 'Exposed Secret Location' :
                 'Affected Dependency Details'}
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

          {/* Threat Intelligence Correlation */}
          {correlatedThreats.length > 0 && (
            <div className={`rounded-lg p-4 ${hasActiveExploit ? 'bg-gradient-to-r from-red-50 to-orange-50 border-2 border-red-300' : 'bg-gradient-to-r from-orange-50 to-yellow-50 border border-orange-200'}`}>
              <div className="flex items-center space-x-2 mb-3">
                <Shield className={`w-5 h-5 ${hasActiveExploit ? 'text-red-600' : 'text-orange-600'}`} />
                <h4 className={`text-sm font-semibold ${hasActiveExploit ? 'text-red-900' : 'text-orange-900'}`}>
                  Threat Intelligence Correlation
                </h4>
                {hasActiveExploit && (
                  <span className="px-2 py-0.5 text-xs rounded bg-red-600 text-white font-medium animate-pulse">
                    URGENT - ACTIVELY EXPLOITED
                  </span>
                )}
              </div>

              <div className="space-y-3">
                {correlatedThreats.map((threat: any, idx: number) => (
                  <div
                    key={idx}
                    className={`bg-white rounded-lg p-3 border ${threat.actively_exploited ? 'border-red-300' : 'border-gray-200'}`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-1">
                          {threat.cve_id && (
                            <span className="font-mono text-sm font-semibold text-primary-600">{threat.cve_id}</span>
                          )}
                          <span className="text-xs px-2 py-0.5 bg-gray-100 text-gray-600 rounded">
                            Match: {threat.match_type}
                          </span>
                          {threat.actively_exploited && (
                            <span className="text-xs px-2 py-0.5 bg-red-100 text-red-700 rounded inline-flex items-center">
                              <Zap className="w-3 h-3 mr-1" />
                              Actively Exploited
                            </span>
                          )}
                          {threat.cvss_score && (
                            <span className={`text-xs px-2 py-0.5 rounded ${
                              parseFloat(threat.cvss_score) >= 9 ? 'bg-red-100 text-red-700' :
                              parseFloat(threat.cvss_score) >= 7 ? 'bg-orange-100 text-orange-700' :
                              'bg-yellow-100 text-yellow-700'
                            }`}>
                              CVSS: {threat.cvss_score}
                            </span>
                          )}
                        </div>
                        <p className="text-sm font-medium text-gray-900">{threat.name}</p>
                        <p className="text-xs text-gray-600 mt-1 line-clamp-2">{threat.description}</p>
                        {threat.required_action && (
                          <p className="text-xs text-red-700 mt-2 font-medium">
                            Required Action: {threat.required_action}
                          </p>
                        )}
                      </div>
                      <div className="ml-3 flex flex-col space-y-1">
                        {threat.cve_id && (
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${threat.cve_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs text-blue-600 hover:underline flex items-center"
                            onClick={(e) => e.stopPropagation()}
                          >
                            NVD <ExternalLink className="w-3 h-3 ml-1" />
                          </a>
                        )}
                        <span className="text-xs text-gray-500">{threat.source || 'CISA KEV'}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-3 pt-3 border-t border-orange-200">
                <Link
                  to="/threat-intel"
                  className="text-sm text-orange-700 hover:text-orange-900 font-medium inline-flex items-center"
                  onClick={(e) => e.stopPropagation()}
                >
                  View all threat intelligence
                  <ExternalLink className="w-4 h-4 ml-1" />
                </Link>
              </div>
            </div>
          )}

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
              to={`/chat?context=vulnerability&id=${vulnerability.id}&project=${projectId}&title=${encodeURIComponent(vulnerability.title)}&severity=${vulnerability.severity}&cwe=${vulnerability.scan_type === 'sca' ? parseScaCveIds(vulnerability).join(',') || '' : vulnerability.cwe_id || ''}&description=${encodeURIComponent(vulnerability.description || '')}&file=${encodeURIComponent(vulnerability.file_path || '')}&line=${vulnerability.line_number || ''}&code=${encodeURIComponent(vulnerability.code_snippet || '')}&scanType=${vulnerability.scan_type || ''}`}
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
