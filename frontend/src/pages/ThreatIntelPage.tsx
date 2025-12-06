import { useState, useEffect } from 'react'
import { Shield, AlertTriangle, TrendingUp, Zap, ExternalLink, Download, Sparkles, Target, Clock, CheckCircle2, XCircle, Users, Lock, Bug, Globe, Search, Filter, X } from 'lucide-react'
import axios from 'axios'

export default function ThreatIntelPage() {
  const [threats, setThreats] = useState<any[]>([])
  const [stats, setStats] = useState<any>(null)
  const [correlations, setCorrelations] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'threats' | 'correlations' | 'rules'>('threats')
  const [selectedThreat, setSelectedThreat] = useState<any>(null)
  const [generatingRule, setGeneratingRule] = useState(false)
  const [generatedRule, setGeneratedRule] = useState<any>(null)

  // Filter states
  const [searchQuery, setSearchQuery] = useState('')
  const [sourceFilter, setSourceFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [threatTypeFilter, setThreatTypeFilter] = useState<string>('all')
  const [exploitedOnly, setExploitedOnly] = useState(false)

  // Get unique sources from threats (including from sources array)
  const sources = [...new Set(threats.flatMap(t => {
    const allSources = t.sources || [t.source]
    return allSources.filter(Boolean)
  }))]

  // Filter threats based on selected filters
  const filteredThreats = threats.filter(threat => {
    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      const matchesSearch =
        (threat.name?.toLowerCase().includes(query)) ||
        (threat.cve_id?.toLowerCase().includes(query)) ||
        (threat.description?.toLowerCase().includes(query))
      if (!matchesSearch) return false
    }

    // Source filter - check both source and sources array
    if (sourceFilter !== 'all') {
      const threatSources = threat.sources || [threat.source]
      if (!threatSources.includes(sourceFilter)) return false
    }

    // Severity filter
    if (severityFilter !== 'all' && threat.severity !== severityFilter) return false

    // Threat type filter
    if (threatTypeFilter !== 'all') {
      if (threatTypeFilter === 'cve' && threat.threat_type) return false
      if (threatTypeFilter !== 'cve' && threat.threat_type !== threatTypeFilter) return false
    }

    // Actively exploited filter
    if (exploitedOnly && !threat.actively_exploited) return false

    return true
  })

  // Clear all filters
  const clearFilters = () => {
    setSearchQuery('')
    setSourceFilter('all')
    setSeverityFilter('all')
    setThreatTypeFilter('all')
    setExploitedOnly(false)
  }

  const hasActiveFilters = searchQuery || sourceFilter !== 'all' || severityFilter !== 'all' || threatTypeFilter !== 'all' || exploitedOnly

  useEffect(() => {
    fetchThreatData()
  }, [])

  const fetchThreatData = async () => {
    try {
      setLoading(true)
      const token = localStorage.getItem('token')

      // Fetch threats and stats in parallel - use allSettled to handle individual failures
      const [threatsResult, statsResult, correlationsResult] = await Promise.allSettled([
        axios.get('/api/threat-intel/threats', {
          headers: { Authorization: `Bearer ${token}` }
        }),
        axios.get('/api/threat-intel/stats', {
          headers: { Authorization: `Bearer ${token}` }
        }),
        axios.get('/api/threat-intel/correlate', {
          headers: { Authorization: `Bearer ${token}` }
        })
      ])

      // Handle each result independently - don't let one failure break everything
      if (threatsResult.status === 'fulfilled') {
        setThreats(threatsResult.value.data.threats || [])
      } else {
        console.error('Failed to fetch threats:', threatsResult.reason)
      }

      if (statsResult.status === 'fulfilled') {
        setStats(statsResult.value.data)
      } else {
        console.error('Failed to fetch stats:', statsResult.reason)
        // Set default stats so UI doesn't break
        setStats({
          total_threats: 0,
          actively_exploited: 0,
          by_severity: { critical: 0, high: 0, medium: 0, low: 0 }
        })
      }

      if (correlationsResult.status === 'fulfilled') {
        setCorrelations(correlationsResult.value.data.correlations || [])
      } else {
        console.error('Failed to fetch correlations:', correlationsResult.reason)
      }
    } catch (error) {
      console.error('Failed to fetch threat intelligence:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleGenerateRule = async (threat: any) => {
    try {
      setGeneratingRule(true)
      const token = localStorage.getItem('token')

      const response = await axios.post(
        '/api/threat-intel/generate-rule',
        { threat_cve_id: threat.cve_id },
        { headers: { Authorization: `Bearer ${token}` } }
      )

      setGeneratedRule(response.data.rule)
      setSelectedThreat(threat)
      setActiveTab('rules')
    } catch (error: any) {
      console.error('Failed to generate rule:', error)
      alert(error.response?.data?.detail || 'Failed to generate rule')
    } finally {
      setGeneratingRule(false)
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
          <h1 className="text-3xl font-bold text-gray-900 flex items-center space-x-3">
            <Shield className="w-8 h-8 text-primary-600" />
            <span>Live Threat Intelligence</span>
          </h1>
          <p className="text-gray-600 mt-1">
            Real-time threat data from CISA KEV, NVD, MISP Galaxy, and Exploit-DB
          </p>
        </div>
        <button
          onClick={fetchThreatData}
          className="btn btn-primary inline-flex items-center space-x-2"
        >
          <TrendingUp className="w-5 h-5" />
          <span>Refresh Feed</span>
        </button>
      </div>

      {/* Stats Overview */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          <div className="card p-4 border-l-4 border-red-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-600">Actively Exploited</p>
                <p className="text-2xl font-bold text-red-600">{stats.actively_exploited}</p>
              </div>
              <Zap className="w-8 h-8 text-red-500 opacity-20" />
            </div>
          </div>

          <div className="card p-4 border-l-4 border-orange-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-600">Critical Threats</p>
                <p className="text-2xl font-bold text-orange-600">{stats.critical_threats || stats.by_severity?.critical || 0}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-orange-500 opacity-20" />
            </div>
          </div>

          <div className="card p-4 border-l-4 border-purple-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-600">Threat Actors</p>
                <p className="text-2xl font-bold text-purple-600">{stats.threat_actors || 0}</p>
              </div>
              <Users className="w-8 h-8 text-purple-500 opacity-20" />
            </div>
          </div>

          <div className="card p-4 border-l-4 border-pink-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-600">Ransomware</p>
                <p className="text-2xl font-bold text-pink-600">{stats.ransomware_families || 0}</p>
              </div>
              <Lock className="w-8 h-8 text-pink-500 opacity-20" />
            </div>
          </div>

          <div className="card p-4 border-l-4 border-indigo-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-600">Exploit Kits</p>
                <p className="text-2xl font-bold text-indigo-600">{stats.exploit_kits || 0}</p>
              </div>
              <Bug className="w-8 h-8 text-indigo-500 opacity-20" />
            </div>
          </div>

          <div className="card p-4 border-l-4 border-blue-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-600">Total Threats</p>
                <p className="text-2xl font-bold text-blue-600">{stats.total_threats}</p>
              </div>
              <Globe className="w-8 h-8 text-blue-500 opacity-20" />
            </div>
          </div>
        </div>
      )}

      {/* Source Breakdown */}
      {stats?.by_source && (
        <div className="card p-4">
          <h3 className="text-sm font-semibold text-gray-700 mb-3">Threat Sources</h3>
          <div className="flex flex-wrap gap-3">
            {Object.entries(stats.by_source).map(([source, count]: [string, any]) => (
              <button
                key={source}
                onClick={() => setSourceFilter(sourceFilter === source ? 'all' : source)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-full transition-colors cursor-pointer ${
                  sourceFilter === source
                    ? 'bg-primary-100 border-2 border-primary-500'
                    : 'bg-gray-100 hover:bg-gray-200'
                }`}
              >
                <span className="text-xs font-medium text-gray-700">{source}</span>
                <span className="text-xs font-bold text-primary-600">{count}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card p-4">
        <div className="flex items-center gap-2 mb-3">
          <Filter className="w-4 h-4 text-gray-500" />
          <h3 className="text-sm font-semibold text-gray-700">Filters</h3>
          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="ml-auto flex items-center gap-1 text-xs text-red-600 hover:text-red-700"
            >
              <X className="w-3 h-3" />
              Clear all
            </button>
          )}
        </div>

        <div className="flex flex-wrap gap-4">
          {/* Search */}
          <div className="flex-1 min-w-[200px]">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search threats, CVEs, descriptions..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              />
            </div>
          </div>

          {/* Source Filter */}
          <div className="min-w-[150px]">
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="all">All Sources</option>
              {sources.map(source => (
                <option key={source} value={source}>{source}</option>
              ))}
            </select>
          </div>

          {/* Severity Filter */}
          <div className="min-w-[130px]">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Threat Type Filter */}
          <div className="min-w-[150px]">
            <select
              value={threatTypeFilter}
              onChange={(e) => setThreatTypeFilter(e.target.value)}
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="all">All Types</option>
              <option value="cve">CVE / Vulnerability</option>
              <option value="threat_actor">Threat Actor</option>
              <option value="ransomware">Ransomware</option>
              <option value="exploit_kit">Exploit Kit</option>
            </select>
          </div>

          {/* Actively Exploited Toggle */}
          <label className="flex items-center gap-2 px-3 py-2 bg-gray-50 rounded-lg cursor-pointer hover:bg-gray-100">
            <input
              type="checkbox"
              checked={exploitedOnly}
              onChange={(e) => setExploitedOnly(e.target.checked)}
              className="w-4 h-4 text-red-600 border-gray-300 rounded focus:ring-red-500"
            />
            <Zap className="w-4 h-4 text-red-500" />
            <span className="text-sm text-gray-700">Actively Exploited Only</span>
          </label>
        </div>

        {/* Active filters summary */}
        {hasActiveFilters && (
          <div className="mt-3 pt-3 border-t border-gray-200 flex items-center gap-2 text-sm text-gray-600">
            <span>Showing {filteredThreats.length} of {threats.length} threats</span>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="card">
        <div className="border-b border-gray-200">
          <div className="flex space-x-8 px-6">
            <button
              onClick={() => setActiveTab('threats')}
              className={`py-4 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'threats'
                  ? 'border-primary-600 text-primary-600'
                  : 'border-transparent text-gray-600 hover:text-gray-900'
              }`}
            >
              Active Threats ({filteredThreats.length})
            </button>
            <button
              onClick={() => setActiveTab('correlations')}
              className={`py-4 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'correlations'
                  ? 'border-primary-600 text-primary-600'
                  : 'border-transparent text-gray-600 hover:text-gray-900'
              }`}
            >
              Correlated Vulnerabilities ({correlations.length})
            </button>
            <button
              onClick={() => setActiveTab('rules')}
              className={`py-4 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'rules'
                  ? 'border-primary-600 text-primary-600'
                  : 'border-transparent text-gray-600 hover:text-gray-900'
              }`}
            >
              Auto-Generated Rules
            </button>
          </div>
        </div>

        <div className="p-6">
          {/* Active Threats Tab */}
          {activeTab === 'threats' && (
            <div className="space-y-4">
              {filteredThreats.length === 0 ? (
                <div className="text-center py-12">
                  <Search className="w-16 h-16 text-gray-300 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">
                    No Threats Found
                  </h3>
                  <p className="text-gray-600 mb-4">
                    {hasActiveFilters
                      ? 'No threats match your current filters. Try adjusting your search criteria.'
                      : 'No threat data available. Click Refresh Feed to fetch the latest threats.'}
                  </p>
                  {hasActiveFilters && (
                    <button
                      onClick={clearFilters}
                      className="btn btn-secondary inline-flex items-center gap-2"
                    >
                      <X className="w-4 h-4" />
                      Clear Filters
                    </button>
                  )}
                </div>
              ) : (
                filteredThreats.map((threat, index) => (
                  <ThreatCard
                    key={threat.cve_id || `threat-${index}`}
                    threat={threat}
                    onGenerateRule={handleGenerateRule}
                    generatingRule={generatingRule}
                  />
                ))
              )}
            </div>
          )}

          {/* Correlations Tab */}
          {activeTab === 'correlations' && (
            <div className="space-y-4">
              {correlations.length === 0 ? (
                <div className="text-center py-12">
                  <CheckCircle2 className="w-16 h-16 text-green-500 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">
                    No Correlated Threats Found
                  </h3>
                  <p className="text-gray-600">
                    Your current vulnerabilities don't match any active threats. Keep monitoring!
                  </p>
                </div>
              ) : (
                correlations.map((corr, idx) => (
                  <CorrelationCard key={idx} correlation={corr} />
                ))
              )}
            </div>
          )}

          {/* Auto-Generated Rules Tab */}
          {activeTab === 'rules' && (
            <div className="space-y-4">
              {!generatedRule ? (
                <div className="text-center py-12">
                  <Sparkles className="w-16 h-16 text-primary-500 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">
                    AI-Powered Rule Generation
                  </h3>
                  <p className="text-gray-600">
                    Select a threat from the Active Threats tab to auto-generate a custom detection rule
                  </p>
                </div>
              ) : (
                <GeneratedRuleDisplay rule={generatedRule} threat={selectedThreat} />
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ThreatCard({ threat, onGenerateRule, generatingRule }: any) {
  const severityColors: any = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
  }

  const threatTypeColors: any = {
    threat_actor: 'bg-purple-100 text-purple-800 border-purple-200',
    ransomware: 'bg-pink-100 text-pink-800 border-pink-200',
    exploit_kit: 'bg-indigo-100 text-indigo-800 border-indigo-200',
    indicator: 'bg-cyan-100 text-cyan-800 border-cyan-200',
  }

  const threatTypeLabels: any = {
    threat_actor: 'Threat Actor',
    ransomware: 'Ransomware',
    exploit_kit: 'Exploit Kit',
    indicator: 'IOC',
  }

  return (
    <div className="card p-6 hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center flex-wrap gap-2 mb-2">
            <h3 className="text-lg font-semibold text-gray-900">{threat.name || threat.cve_id}</h3>
            {threat.threat_type && threatTypeLabels[threat.threat_type] && (
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${threatTypeColors[threat.threat_type]}`}>
                {threatTypeLabels[threat.threat_type]}
              </span>
            )}
            {threat.actively_exploited && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 border border-red-200">
                <Zap className="w-3 h-3 mr-1" />
                Actively Exploited
              </span>
            )}
            <span className={`badge ${severityColors[threat.severity]} text-xs font-semibold`}>
              {threat.severity?.toUpperCase()}
            </span>
          </div>

          <p className="text-sm text-gray-700 mb-3">{threat.description}</p>

          <div className="flex items-center flex-wrap gap-4 text-sm text-gray-600">
            {threat.cve_id && (
              <span className="font-mono font-semibold text-primary-600">{threat.cve_id}</span>
            )}
            {threat.cvss_score && (
              <span className="flex items-center space-x-1">
                <Target className="w-4 h-4" />
                <span>CVSS: {threat.cvss_score}</span>
              </span>
            )}
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4" />
              <span>Sources:</span>
              <div className="flex flex-wrap gap-1">
                {(threat.sources || [threat.source]).filter(Boolean).map((src: string, idx: number) => (
                  <span
                    key={idx}
                    className={`px-2 py-0.5 rounded text-xs font-medium ${
                      src === 'NVD' ? 'bg-blue-100 text-blue-800' :
                      src === 'CISA KEV' ? 'bg-red-100 text-red-800' :
                      src === 'MISP Galaxy' ? 'bg-purple-100 text-purple-800' :
                      src === 'Exploit-DB' ? 'bg-orange-100 text-orange-800' :
                      'bg-gray-100 text-gray-800'
                    }`}
                  >
                    {src}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {threat.required_action && (
            <div className="mt-3 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
              <p className="text-sm font-medium text-yellow-900">
                <strong>Required Action:</strong> {threat.required_action}
              </p>
            </div>
          )}
        </div>

        <div className="ml-4 flex flex-col space-y-2">
          <button
            onClick={() => onGenerateRule(threat)}
            disabled={generatingRule}
            className="btn btn-primary btn-sm inline-flex items-center space-x-2"
          >
            <Sparkles className="w-4 h-4" />
            <span>{generatingRule ? 'Generating...' : 'Generate Rule'}</span>
          </button>
          {threat.cve_id && (
            <a
              href={`https://nvd.nist.gov/vuln/detail/${threat.cve_id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-secondary btn-sm inline-flex items-center space-x-2"
            >
              <ExternalLink className="w-4 h-4" />
              <span>View NVD</span>
            </a>
          )}
        </div>
      </div>
    </div>
  )
}

function CorrelationCard({ correlation }: any) {
  const { vulnerability, threat, risk_elevation, match_confidence } = correlation

  return (
    <div className={`card p-6 border-l-4 ${risk_elevation ? 'border-red-500 bg-red-50' : 'border-yellow-500 bg-yellow-50'}`}>
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <div className="flex items-center space-x-3 mb-2">
            <AlertTriangle className={`w-5 h-5 ${risk_elevation ? 'text-red-600' : 'text-yellow-600'}`} />
            <h3 className="text-lg font-semibold text-gray-900">
              {vulnerability.title}
            </h3>
            {risk_elevation && (
              <span className="badge bg-red-100 text-red-800 border-red-200">
                HIGH RISK - ACTIVELY EXPLOITED
              </span>
            )}
          </div>

          <div className="grid grid-cols-2 gap-4 mb-3">
            <div>
              <p className="text-xs font-semibold text-gray-600 uppercase">Your Vulnerability</p>
              <p className="text-sm text-gray-700">File: {vulnerability.file_path}</p>
              <p className="text-sm text-gray-700">Severity: {vulnerability.severity}</p>
              <p className="text-sm text-gray-700">CWE: {vulnerability.cwe_id}</p>
            </div>
            <div>
              <p className="text-xs font-semibold text-gray-600 uppercase">Matching Threat</p>
              <p className="text-sm text-gray-700">{threat.name || threat.cve_id}</p>
              <p className="text-sm text-gray-700">CVSS: {threat.cvss_score || 'N/A'}</p>
              <p className="text-sm text-gray-700">Match Confidence: {match_confidence}</p>
            </div>
          </div>

          <div className="p-3 bg-white border border-gray-200 rounded-lg">
            <p className="text-sm text-gray-700">
              <strong>Recommendation:</strong> {threat.required_action || 'Remediate immediately as this vulnerability matches an active threat.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

function GeneratedRuleDisplay({ rule, threat }: any) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    const ruleText = JSON.stringify(rule, null, 2)
    navigator.clipboard.writeText(ruleText)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="space-y-4">
      <div className="card p-6 bg-green-50 border-green-200">
        <div className="flex items-center space-x-3 mb-4">
          <CheckCircle2 className="w-6 h-6 text-green-600" />
          <h3 className="text-lg font-semibold text-green-900">
            Rule Generated Successfully
          </h3>
        </div>
        <p className="text-sm text-green-800">
          Auto-generated detection rule for <strong>{threat?.name || threat?.cve_id}</strong>
        </p>
      </div>

      <div className="card p-6">
        <div className="flex items-center justify-between mb-4">
          <h4 className="font-semibold text-gray-900">Rule Details</h4>
          <button
            onClick={handleCopy}
            className="btn btn-secondary btn-sm inline-flex items-center space-x-2"
          >
            {copied ? <CheckCircle2 className="w-4 h-4" /> : <Download className="w-4 h-4" />}
            <span>{copied ? 'Copied!' : 'Copy Rule'}</span>
          </button>
        </div>

        <div className="space-y-3">
          <div>
            <label className="text-xs font-semibold text-gray-600 uppercase">Rule Name</label>
            <p className="text-sm text-gray-900 font-medium">{rule.name}</p>
          </div>

          <div>
            <label className="text-xs font-semibold text-gray-600 uppercase">Description</label>
            <p className="text-sm text-gray-700">{rule.description}</p>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="text-xs font-semibold text-gray-600 uppercase">Severity</label>
              <span className={`badge badge-${rule.severity} mt-1`}>{rule.severity}</span>
            </div>
            <div>
              <label className="text-xs font-semibold text-gray-600 uppercase">CWE ID</label>
              <p className="text-sm text-gray-900">{rule.cwe_id || 'N/A'}</p>
            </div>
            <div>
              <label className="text-xs font-semibold text-gray-600 uppercase">CVE ID</label>
              <p className="text-sm text-gray-900">{rule.cve_id}</p>
            </div>
          </div>

          <div>
            <label className="text-xs font-semibold text-gray-600 uppercase">Detection Pattern</label>
            <pre className="mt-1 p-3 bg-gray-900 text-green-400 rounded-lg text-xs font-mono overflow-x-auto">
              {rule.pattern}
            </pre>
          </div>

          <div>
            <label className="text-xs font-semibold text-gray-600 uppercase">Remediation</label>
            <p className="text-sm text-gray-700 mt-1">{rule.remediation}</p>
          </div>

          <div className="pt-3 border-t border-gray-200">
            <p className="text-xs text-gray-500">
              Source: {rule.source} | Generated: {new Date(rule.generated_at).toLocaleString()}
            </p>
          </div>
        </div>
      </div>

      <div className="card p-4 bg-blue-50 border-blue-200">
        <div className="flex items-start space-x-3">
          <Sparkles className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-blue-900 mb-1">Next Steps</p>
            <ul className="text-sm text-blue-800 space-y-1 list-disc list-inside">
              <li>Review the generated pattern for accuracy</li>
              <li>Test the rule against your codebase</li>
              <li>Add to Custom Rules page for automated scanning</li>
              <li>Monitor for false positives and refine as needed</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}
