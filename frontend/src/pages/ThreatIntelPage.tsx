import { useState, useEffect, useRef } from 'react'
import { Shield, AlertTriangle, TrendingUp, Zap, ExternalLink, Download, Sparkles, Target, Clock, CheckCircle2, XCircle, Users, Lock, Bug, Globe, Search, Filter, X, Upload, Plus, Trash2, Edit3, FileText, Database, ChevronDown, ChevronUp, Save, Key, Copy, Eye, EyeOff } from 'lucide-react'
import axios from 'axios'

export default function ThreatIntelPage() {
  const [threats, setThreats] = useState<any[]>([])
  const [stats, setStats] = useState<any>(null)
  const [correlations, setCorrelations] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'threats' | 'correlations' | 'rules' | 'custom' | 'api-keys' | 'feeds'>('threats')
  const [feeds, setFeeds] = useState<any[]>([])
  const [iocs, setIocs] = useState<any[]>([])
  const [iocStats, setIocStats] = useState<any>(null)
  const [feedFormOpen, setFeedFormOpen] = useState(false)
  const [newFeed, setNewFeed] = useState({ name: '', feed_type: 'stix_url', url: '', api_key: '', poll_interval_minutes: 1440 })
  const [pollingFeedId, setPollingFeedId] = useState<number | null>(null)
  const [iocSearch, setIocSearch] = useState('')
  const [iocTypeFilter, setIocTypeFilter] = useState('all')
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
            <button
              onClick={() => setActiveTab('custom')}
              className={`py-4 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'custom'
                  ? 'border-primary-600 text-primary-600'
                  : 'border-transparent text-gray-600 hover:text-gray-900'
              }`}
            >
              <span className="flex items-center gap-2">
                <Database className="w-4 h-4" />
                Custom Intel
              </span>
            </button>
            <button
              onClick={() => setActiveTab('feeds')}
              className={`py-4 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'feeds'
                  ? 'border-primary-600 text-primary-600'
                  : 'border-transparent text-gray-600 hover:text-gray-900'
              }`}
            >
              <span className="flex items-center gap-2">
                <Globe className="w-4 h-4" />
                Threat Feeds & IOCs
              </span>
            </button>
            <button
              onClick={() => setActiveTab('api-keys')}
              className={`py-4 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'api-keys'
                  ? 'border-primary-600 text-primary-600'
                  : 'border-transparent text-gray-600 hover:text-gray-900'
              }`}
            >
              <span className="flex items-center gap-2">
                <Key className="w-4 h-4" />
                API Keys
              </span>
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

          {/* Custom Intel Tab */}
          {activeTab === 'custom' && (
            <CustomIntelTab />
          )}

          {/* Threat Feeds & IOCs Tab */}
          {activeTab === 'feeds' && (
            <ThreatFeedsTab
              feeds={feeds} setFeeds={setFeeds}
              iocs={iocs} setIocs={setIocs}
              iocStats={iocStats} setIocStats={setIocStats}
              feedFormOpen={feedFormOpen} setFeedFormOpen={setFeedFormOpen}
              newFeed={newFeed} setNewFeed={setNewFeed}
              pollingFeedId={pollingFeedId} setPollingFeedId={setPollingFeedId}
              iocSearch={iocSearch} setIocSearch={setIocSearch}
              iocTypeFilter={iocTypeFilter} setIocTypeFilter={setIocTypeFilter}
            />
          )}

          {/* API Keys Tab */}
          {activeTab === 'api-keys' && (
            <APIKeysTab />
          )}
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Threat Feeds & IOCs Tab
// ---------------------------------------------------------------------------
function ThreatFeedsTab({ feeds, setFeeds, iocs, setIocs, iocStats, setIocStats, feedFormOpen, setFeedFormOpen, newFeed, setNewFeed, pollingFeedId, setPollingFeedId, iocSearch, setIocSearch, iocTypeFilter, setIocTypeFilter }: any) {
  const [subTab, setSubTab] = useState<'feeds' | 'iocs'>('feeds')
  const [loadingFeeds, setLoadingFeeds] = useState(false)
  const [loadingIocs, setLoadingIocs] = useState(false)

  const token = localStorage.getItem('token')
  const headers = { Authorization: `Bearer ${token}` }

  const fetchFeeds = async () => {
    setLoadingFeeds(true)
    try {
      const res = await axios.get('/api/threat-intel/feeds', { headers })
      setFeeds(res.data.feeds || [])
    } catch { /* */ }
    setLoadingFeeds(false)
  }

  const fetchIocs = async () => {
    setLoadingIocs(true)
    try {
      const params: any = { limit: 100 }
      if (iocSearch) params.search = iocSearch
      if (iocTypeFilter !== 'all') params.ioc_type = iocTypeFilter
      const res = await axios.get('/api/threat-intel/iocs', { headers, params })
      setIocs(res.data.iocs || [])
      setIocStats({ total: res.data.total_all, type_counts: res.data.type_counts })
    } catch { /* */ }
    setLoadingIocs(false)
  }

  const fetchDashboard = async () => {
    try {
      const res = await axios.get('/api/threat-intel/iocs/dashboard/stats', { headers })
      setIocStats(res.data)
    } catch { /* */ }
  }

  useEffect(() => {
    fetchFeeds()
    fetchIocs()
    fetchDashboard()
  }, [])

  const handleCreateFeed = async () => {
    if (!newFeed.name || !newFeed.url) return
    try {
      await axios.post('/api/threat-intel/feeds', newFeed, { headers })
      setFeedFormOpen(false)
      setNewFeed({ name: '', feed_type: 'stix_url', url: '', api_key: '', poll_interval_minutes: 1440 })
      fetchFeeds()
    } catch { /* */ }
  }

  const handlePollFeed = async (feedId: number) => {
    setPollingFeedId(feedId)
    try {
      const res = await axios.post(`/api/threat-intel/feeds/${feedId}/poll`, {}, { headers })
      alert(`Ingested ${res.data.ingested} IOCs`)
      fetchFeeds()
      fetchIocs()
      fetchDashboard()
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Poll failed')
    }
    setPollingFeedId(null)
  }

  const handleDeleteFeed = async (feedId: number) => {
    if (!confirm('Delete this feed and all its IOCs?')) return
    try {
      await axios.delete(`/api/threat-intel/feeds/${feedId}`, { headers })
      fetchFeeds()
      fetchIocs()
    } catch { /* */ }
  }

  const handleToggleFeed = async (feedId: number, active: number) => {
    try {
      await axios.put(`/api/threat-intel/feeds/${feedId}`, { is_active: active ? 0 : 1 }, { headers })
      fetchFeeds()
    } catch { /* */ }
  }

  const FEED_TYPE_LABELS: Record<string, string> = {
    stix_url: 'STIX/TAXII URL', csv_url: 'CSV Feed', alienvault_otx: 'AlienVault OTX',
    abuse_ipdb: 'AbuseIPDB', taxii: 'TAXII 2.1', misp: 'MISP',
  }

  const IOC_TYPE_ICONS: Record<string, string> = {
    ip: '🌐', domain: '🔗', url: '🔗', hash_md5: '#', hash_sha1: '#', hash_sha256: '#',
    email: '✉', cve: '🛡', file_path: '📁',
  }

  return (
    <div className="space-y-6">
      {/* Stats Row */}
      {iocStats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-blue-50 rounded-lg p-4 border border-blue-200">
            <div className="text-2xl font-bold text-blue-700">{iocStats.total_iocs || iocStats.total || 0}</div>
            <div className="text-sm text-blue-600">Total IOCs</div>
          </div>
          <div className="bg-green-50 rounded-lg p-4 border border-green-200">
            <div className="text-2xl font-bold text-green-700">{iocStats.active_feeds || 0}</div>
            <div className="text-sm text-green-600">Active Feeds</div>
          </div>
          <div className="bg-orange-50 rounded-lg p-4 border border-orange-200">
            <div className="text-2xl font-bold text-orange-700">{iocStats.recent_24h || 0}</div>
            <div className="text-sm text-orange-600">New (24h)</div>
          </div>
          <div className="bg-red-50 rounded-lg p-4 border border-red-200">
            <div className="text-2xl font-bold text-red-700">{iocStats.total_correlations || 0}</div>
            <div className="text-sm text-red-600">Correlations</div>
          </div>
        </div>
      )}

      {/* Sub-tabs */}
      <div className="flex gap-2">
        <button onClick={() => setSubTab('feeds')} className={`px-4 py-2 rounded-lg text-sm font-medium ${subTab === 'feeds' ? 'bg-primary-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'}`}>
          Feed Management
        </button>
        <button onClick={() => { setSubTab('iocs'); fetchIocs() }} className={`px-4 py-2 rounded-lg text-sm font-medium ${subTab === 'iocs' ? 'bg-primary-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'}`}>
          IOC Browser
        </button>
      </div>

      {/* Feed Management Sub-tab */}
      {subTab === 'feeds' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold text-gray-900">Configured Feeds</h3>
            <button onClick={() => setFeedFormOpen(!feedFormOpen)} className="flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm">
              <Plus className="w-4 h-4" /> Add Feed
            </button>
          </div>

          {/* Add Feed Form */}
          {feedFormOpen && (
            <div className="bg-gray-50 border border-gray-200 rounded-lg p-6 space-y-4">
              <h4 className="font-semibold text-gray-900">New Feed Subscription</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="label">Feed Name</label>
                  <input className="input" placeholder="e.g., AlienVault OTX Pulse" value={newFeed.name} onChange={e => setNewFeed({ ...newFeed, name: e.target.value })} />
                </div>
                <div>
                  <label className="label">Feed Type</label>
                  <select className="input" value={newFeed.feed_type} onChange={e => setNewFeed({ ...newFeed, feed_type: e.target.value })}>
                    <option value="stix_url">STIX/TAXII URL</option>
                    <option value="csv_url">CSV Feed URL</option>
                    <option value="alienvault_otx">AlienVault OTX</option>
                    <option value="abuse_ipdb">AbuseIPDB</option>
                    <option value="taxii">TAXII 2.1</option>
                    <option value="misp">MISP</option>
                  </select>
                </div>
                <div className="md:col-span-2">
                  <label className="label">Feed URL</label>
                  <input className="input" placeholder="https://..." value={newFeed.url} onChange={e => setNewFeed({ ...newFeed, url: e.target.value })} />
                </div>
                <div>
                  <label className="label">API Key (optional)</label>
                  <input className="input" type="password" placeholder="API key for authenticated feeds" value={newFeed.api_key} onChange={e => setNewFeed({ ...newFeed, api_key: e.target.value })} />
                </div>
                <div>
                  <label className="label">Poll Interval (minutes)</label>
                  <input className="input" type="number" value={newFeed.poll_interval_minutes} onChange={e => setNewFeed({ ...newFeed, poll_interval_minutes: parseInt(e.target.value) || 1440 })} />
                </div>
              </div>
              <div className="flex gap-2">
                <button onClick={handleCreateFeed} className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm">Create Feed</button>
                <button onClick={() => setFeedFormOpen(false)} className="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 text-sm">Cancel</button>
              </div>
            </div>
          )}

          {/* Feeds List */}
          {loadingFeeds ? (
            <div className="text-center py-8 text-gray-500">Loading feeds...</div>
          ) : feeds.length === 0 ? (
            <div className="text-center py-12 text-gray-500">
              <Globe className="w-12 h-12 mx-auto mb-3 text-gray-300" />
              <p className="text-lg font-medium">No feeds configured</p>
              <p className="text-sm mt-1">Add a STIX, CSV, AlienVault OTX, or AbuseIPDB feed to start ingesting IOCs.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {feeds.map((feed: any) => (
                <div key={feed.id} className={`bg-white border rounded-lg p-4 ${feed.is_active ? 'border-gray-200' : 'border-gray-200 opacity-60'}`}>
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3">
                        <h4 className="font-semibold text-gray-900">{feed.name}</h4>
                        <span className="px-2 py-0.5 text-xs font-medium rounded bg-blue-100 text-blue-700">{FEED_TYPE_LABELS[feed.feed_type] || feed.feed_type}</span>
                        <span className={`px-2 py-0.5 text-xs font-medium rounded ${feed.is_active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
                          {feed.is_active ? 'Active' : 'Disabled'}
                        </span>
                      </div>
                      <p className="text-sm text-gray-500 mt-1 truncate max-w-xl">{feed.url}</p>
                      <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                        <span>IOCs: <strong>{feed.total_iocs_ingested || 0}</strong></span>
                        <span>Last poll: {feed.last_polled_at || 'Never'}</span>
                        {feed.last_poll_status && (
                          <span className={feed.last_poll_status === 'success' ? 'text-green-600' : 'text-red-600'}>
                            {feed.last_poll_status}
                          </span>
                        )}
                        <span>Interval: {feed.poll_interval_minutes}m</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 ml-4">
                      <button
                        onClick={() => handlePollFeed(feed.id)}
                        disabled={pollingFeedId === feed.id}
                        className="px-3 py-1.5 bg-blue-600 text-white rounded text-xs hover:bg-blue-700 disabled:opacity-50"
                      >
                        {pollingFeedId === feed.id ? 'Polling...' : 'Poll Now'}
                      </button>
                      <button onClick={() => handleToggleFeed(feed.id, feed.is_active)} className="px-3 py-1.5 bg-gray-100 text-gray-700 rounded text-xs hover:bg-gray-200">
                        {feed.is_active ? 'Disable' : 'Enable'}
                      </button>
                      <button onClick={() => handleDeleteFeed(feed.id)} className="px-3 py-1.5 bg-red-50 text-red-600 rounded text-xs hover:bg-red-100">
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* IOC Browser Sub-tab */}
      {subTab === 'iocs' && (
        <div className="space-y-4">
          <div className="flex items-center gap-4">
            <div className="flex-1 relative">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
              <input
                className="input pl-10"
                placeholder="Search IOCs (IP, domain, hash, CVE...)"
                value={iocSearch}
                onChange={e => setIocSearch(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && fetchIocs()}
              />
            </div>
            <select className="input w-auto" value={iocTypeFilter} onChange={e => { setIocTypeFilter(e.target.value); setTimeout(fetchIocs, 0) }}>
              <option value="all">All Types</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="hash_sha256">SHA-256</option>
              <option value="hash_sha1">SHA-1</option>
              <option value="hash_md5">MD5</option>
              <option value="email">Email</option>
              <option value="cve">CVE</option>
            </select>
            <button onClick={fetchIocs} className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm">
              Search
            </button>
          </div>

          {/* Type distribution */}
          {iocStats?.type_counts && Object.keys(iocStats.type_counts).length > 0 && (
            <div className="flex flex-wrap gap-2">
              {Object.entries(iocStats.type_counts).map(([type, count]: any) => (
                <button
                  key={type}
                  onClick={() => { setIocTypeFilter(type); setTimeout(fetchIocs, 0) }}
                  className={`px-3 py-1 text-xs rounded-full border ${iocTypeFilter === type ? 'bg-primary-100 border-primary-300 text-primary-700' : 'bg-gray-50 border-gray-200 text-gray-600 hover:bg-gray-100'}`}
                >
                  {IOC_TYPE_ICONS[type] || '?'} {type} ({count})
                </button>
              ))}
            </div>
          )}

          {/* IOC Table */}
          {loadingIocs ? (
            <div className="text-center py-8 text-gray-500">Loading IOCs...</div>
          ) : iocs.length === 0 ? (
            <div className="text-center py-12 text-gray-500">
              <Shield className="w-12 h-12 mx-auto mb-3 text-gray-300" />
              <p className="text-lg font-medium">No IOCs found</p>
              <p className="text-sm mt-1">Configure and poll a feed to ingest indicators of compromise.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 text-left">
                    <th className="py-3 px-3 font-medium text-gray-500">Type</th>
                    <th className="py-3 px-3 font-medium text-gray-500">Value</th>
                    <th className="py-3 px-3 font-medium text-gray-500">Severity</th>
                    <th className="py-3 px-3 font-medium text-gray-500">Confidence</th>
                    <th className="py-3 px-3 font-medium text-gray-500">Threat</th>
                    <th className="py-3 px-3 font-medium text-gray-500">Source</th>
                    <th className="py-3 px-3 font-medium text-gray-500">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {iocs.map((ioc: any) => (
                    <tr key={ioc.id} className="hover:bg-gray-50">
                      <td className="py-2.5 px-3">
                        <span className="px-2 py-0.5 text-xs font-mono rounded bg-gray-100 text-gray-700">
                          {IOC_TYPE_ICONS[ioc.ioc_type]} {ioc.ioc_type}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-xs max-w-xs truncate" title={ioc.ioc_value}>{ioc.ioc_value}</td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 text-xs rounded font-medium ${
                          ioc.severity === 'critical' ? 'bg-red-100 text-red-800' :
                          ioc.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                          ioc.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                          'bg-blue-100 text-blue-800'
                        }`}>{ioc.severity}</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 bg-gray-200 rounded-full h-1.5">
                            <div className={`h-1.5 rounded-full ${ioc.confidence >= 80 ? 'bg-red-500' : ioc.confidence >= 60 ? 'bg-orange-500' : ioc.confidence >= 40 ? 'bg-yellow-500' : 'bg-blue-500'}`} style={{ width: `${ioc.confidence}%` }} />
                          </div>
                          <span className="text-xs text-gray-500">{ioc.confidence}%</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-xs text-gray-600">{ioc.threat_type || '-'}</td>
                      <td className="py-2.5 px-3 text-xs text-gray-500">{ioc.feed_name || ioc.source || '-'}</td>
                      <td className="py-2.5 px-3 text-xs text-gray-500">{ioc.last_seen ? new Date(ioc.last_seen).toLocaleDateString() : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Custom Intel Tab — Upload, manage, and view client threat intel
// ---------------------------------------------------------------------------
function CustomIntelTab() {
  const [projects, setProjects] = useState<any[]>([])
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null)
  const [entries, setEntries] = useState<any[]>([])
  const [loadingEntries, setLoadingEntries] = useState(false)
  const [showForm, setShowForm] = useState(false)
  const [editingEntry, setEditingEntry] = useState<any>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadResult, setUploadResult] = useState<any>(null)
  const [intelFilter, setIntelFilter] = useState<string>('all')
  const [intelSearch, setIntelSearch] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Form state
  const [form, setForm] = useState({
    intel_type: 'scenario',
    title: '',
    description: '',
    severity: 'medium',
    threat_category: '',
    mitre_techniques: '',
    regulatory_impact: '',
    recommended_controls: '',
    tags: '',
    source: 'client_upload',
  })

  const token = localStorage.getItem('token')
  const authHeader = { Authorization: `Bearer ${token}` }

  useEffect(() => {
    fetchProjects()
  }, [])

  useEffect(() => {
    if (selectedProjectId) fetchEntries()
  }, [selectedProjectId])

  const fetchProjects = async () => {
    try {
      const res = await axios.get('/api/projects', { headers: authHeader })
      const list = res.data.projects || res.data || []
      setProjects(list)
      if (list.length > 0 && !selectedProjectId) {
        setSelectedProjectId(list[0].id)
      }
    } catch (e) { console.error('Failed to fetch projects', e) }
  }

  const fetchEntries = async () => {
    if (!selectedProjectId) return
    setLoadingEntries(true)
    try {
      const res = await axios.get(`/api/threat-intel/${selectedProjectId}`, {
        headers: authHeader,
        params: { active_only: false },
      })
      setEntries(res.data.entries || [])
    } catch (e) { console.error('Failed to fetch entries', e) }
    finally { setLoadingEntries(false) }
  }

  const resetForm = () => {
    setForm({
      intel_type: 'scenario', title: '', description: '', severity: 'medium',
      threat_category: '', mitre_techniques: '', regulatory_impact: '',
      recommended_controls: '', tags: '', source: 'client_upload',
    })
    setEditingEntry(null)
    setShowForm(false)
  }

  const handleSubmit = async () => {
    if (!form.title.trim()) return alert('Title is required.')
    if (!selectedProjectId) return alert('Select a project first.')

    const payload = {
      ...form,
      project_id: selectedProjectId,
      mitre_techniques: form.mitre_techniques ? form.mitre_techniques.split(';').map(s => s.trim()).filter(Boolean) : [],
      regulatory_impact: form.regulatory_impact ? form.regulatory_impact.split(';').map(s => s.trim()).filter(Boolean) : [],
      recommended_controls: form.recommended_controls ? form.recommended_controls.split(';').map(s => s.trim()).filter(Boolean) : [],
      tags: form.tags ? form.tags.split(';').map(s => s.trim()).filter(Boolean) : [],
      threat_category: form.threat_category || null,
    }

    try {
      if (editingEntry) {
        const { project_id, source, ...updatePayload } = payload
        await axios.put(`/api/threat-intel/${editingEntry.id}`, updatePayload, { headers: authHeader })
      } else {
        await axios.post('/api/threat-intel', payload, { headers: authHeader })
      }
      resetForm()
      fetchEntries()
    } catch (e: any) {
      alert(e.response?.data?.detail || 'Failed to save entry')
    }
  }

  const handleEdit = (entry: any) => {
    setForm({
      intel_type: entry.intel_type || 'scenario',
      title: entry.title || '',
      description: entry.description || '',
      severity: entry.severity || 'medium',
      threat_category: entry.threat_category || '',
      mitre_techniques: (entry.mitre_techniques || []).join('; '),
      regulatory_impact: (entry.regulatory_impact || []).join('; '),
      recommended_controls: (entry.recommended_controls || []).join('; '),
      tags: (entry.tags || []).join('; '),
      source: entry.source || 'client_upload',
    })
    setEditingEntry(entry)
    setShowForm(true)
  }

  const handleDelete = async (entryId: number) => {
    if (!confirm('Delete this threat intel entry?')) return
    try {
      await axios.delete(`/api/threat-intel/${entryId}`, { headers: authHeader })
      fetchEntries()
    } catch (e) { console.error('Failed to delete', e) }
  }

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file || !selectedProjectId) return

    const formData = new FormData()
    formData.append('file', file)
    formData.append('project_id', String(selectedProjectId))

    setUploading(true)
    setUploadResult(null)
    try {
      const res = await axios.post('/api/threat-intel/upload-file', formData, {
        headers: { ...authHeader, 'Content-Type': 'multipart/form-data' },
      })
      setUploadResult({ success: true, ...res.data })
      fetchEntries()
    } catch (e: any) {
      setUploadResult({ success: false, message: e.response?.data?.detail || 'Upload failed' })
    } finally {
      setUploading(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  const handleDownloadTemplate = async () => {
    try {
      const res = await axios.get('/api/threat-intel/download-template', {
        headers: authHeader,
        responseType: 'blob',
      })
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const a = document.createElement('a')
      a.href = url
      a.download = 'threat_intel_template.csv'
      a.click()
      window.URL.revokeObjectURL(url)
    } catch (e) { console.error('Failed to download template', e) }
  }

  const filteredEntries = entries.filter(entry => {
    if (intelFilter !== 'all' && entry.intel_type !== intelFilter) return false
    if (intelSearch) {
      const q = intelSearch.toLowerCase()
      return (entry.title?.toLowerCase().includes(q)) ||
             (entry.description?.toLowerCase().includes(q)) ||
             (entry.tags || []).some((t: string) => t.toLowerCase().includes(q))
    }
    return true
  })

  const typeCounts: any = {}
  entries.forEach(e => { typeCounts[e.intel_type] = (typeCounts[e.intel_type] || 0) + 1 })

  const severityColors: any = {
    critical: 'bg-red-100 text-red-800',
    high: 'bg-orange-100 text-orange-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-blue-100 text-blue-800',
  }

  const typeLabels: any = {
    scenario: 'Threat Scenario',
    threat_actor: 'Threat Actor',
    incident: 'Incident',
    regulation: 'Regulation',
    control: 'Control',
    asset: 'Asset',
    pentest_finding: 'Pentest Finding',
    risk_appetite: 'Risk Appetite',
  }

  return (
    <div className="space-y-6">
      {/* Project Selector + Actions */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex-1 min-w-[200px]">
          <label className="block text-xs font-semibold text-gray-600 mb-1">Project</label>
          <select
            value={selectedProjectId || ''}
            onChange={(e) => setSelectedProjectId(Number(e.target.value))}
            className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500"
          >
            <option value="">Select a project...</option>
            {projects.map((p: any) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
        </div>

        <div className="flex items-end gap-2">
          <button
            onClick={() => { setShowForm(true); setEditingEntry(null) }}
            disabled={!selectedProjectId}
            className="btn btn-primary btn-sm inline-flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Add Entry
          </button>

          <label className={`btn btn-secondary btn-sm inline-flex items-center gap-2 cursor-pointer ${!selectedProjectId || uploading ? 'opacity-50 pointer-events-none' : ''}`}>
            <Upload className="w-4 h-4" />
            {uploading ? 'Uploading...' : 'Upload File'}
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv,.json"
              onChange={handleFileUpload}
              className="hidden"
              disabled={!selectedProjectId || uploading}
            />
          </label>

          <button
            onClick={handleDownloadTemplate}
            className="btn btn-secondary btn-sm inline-flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            CSV Template
          </button>
        </div>
      </div>

      {/* Upload Result */}
      {uploadResult && (
        <div className={`p-4 rounded-lg border ${uploadResult.success ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}`}>
          <div className="flex items-center gap-2">
            {uploadResult.success ? <CheckCircle2 className="w-5 h-5 text-green-600" /> : <XCircle className="w-5 h-5 text-red-600" />}
            <span className={`font-medium ${uploadResult.success ? 'text-green-800' : 'text-red-800'}`}>
              {uploadResult.message}
            </span>
          </div>
          {uploadResult.success && (
            <p className="text-sm text-green-700 mt-1">
              {uploadResult.created} entries imported from {uploadResult.file_type} file ({uploadResult.filename})
            </p>
          )}
          <button onClick={() => setUploadResult(null)} className="mt-2 text-xs underline text-gray-500">Dismiss</button>
        </div>
      )}

      {/* Upload Info */}
      <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
        <div className="flex items-start gap-3">
          <FileText className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-blue-900">Supported Upload Formats</p>
            <ul className="text-sm text-blue-800 mt-1 space-y-0.5">
              <li><strong>CSV</strong> — Use semicolons to separate list values. Download the template for the expected format.</li>
              <li><strong>JSON</strong> — Array of objects with title, description, severity, intel_type, mitre_techniques, tags, etc.</li>
              <li><strong>STIX 2.1</strong> — Standard bundle format. Supported types: indicator, malware, threat-actor, attack-pattern, vulnerability, campaign, intrusion-set.</li>
            </ul>
            <p className="text-xs text-blue-700 mt-2">Uploaded intel is automatically included in threat model generation for the selected project.</p>
          </div>
        </div>
      </div>

      {/* Manual Entry Form */}
      {showForm && (
        <div className="card p-6 border-2 border-primary-200">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">
              {editingEntry ? 'Edit Threat Intel Entry' : 'Add Threat Intel Entry'}
            </h3>
            <button onClick={resetForm} className="text-gray-400 hover:text-gray-600">
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-gray-600 mb-1">Title *</label>
              <input
                value={form.title}
                onChange={e => setForm({ ...form, title: e.target.value })}
                placeholder="e.g., SQL Injection in Authentication Module"
                className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-gray-600 mb-1">Description</label>
              <textarea
                value={form.description}
                onChange={e => setForm({ ...form, description: e.target.value })}
                rows={3}
                placeholder="Detailed description of the threat, vulnerability, or intelligence..."
                className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1">Type</label>
              <select
                value={form.intel_type}
                onChange={e => setForm({ ...form, intel_type: e.target.value })}
                className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500"
              >
                <option value="scenario">Threat Scenario</option>
                <option value="threat_actor">Threat Actor</option>
                <option value="incident">Incident</option>
                <option value="regulation">Regulation</option>
                <option value="control">Control</option>
                <option value="asset">Asset</option>
                <option value="pentest_finding">Pentest Finding</option>
                <option value="risk_appetite">Risk Appetite</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1">Severity</label>
              <select
                value={form.severity}
                onChange={e => setForm({ ...form, severity: e.target.value })}
                className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1">STRIDE Category</label>
              <select
                value={form.threat_category}
                onChange={e => setForm({ ...form, threat_category: e.target.value })}
                className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500"
              >
                <option value="">None</option>
                <option value="Spoofing">Spoofing</option>
                <option value="Tampering">Tampering</option>
                <option value="Repudiation">Repudiation</option>
                <option value="Information Disclosure">Information Disclosure</option>
                <option value="Denial of Service">Denial of Service</option>
                <option value="Elevation of Privilege">Elevation of Privilege</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1">Source</label>
              <input
                value={form.source}
                onChange={e => setForm({ ...form, source: e.target.value })}
                placeholder="e.g., internal_pentest, vendor_report"
                className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-gray-600 mb-1">
                MITRE ATT&CK Techniques <span className="text-gray-400 font-normal">(semicolon-separated)</span>
              </label>
              <input
                value={form.mitre_techniques}
                onChange={e => setForm({ ...form, mitre_techniques: e.target.value })}
                placeholder="e.g., T1190; T1059.001; T1078"
                className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-gray-600 mb-1">
                Regulatory Impact <span className="text-gray-400 font-normal">(semicolon-separated)</span>
              </label>
              <input
                value={form.regulatory_impact}
                onChange={e => setForm({ ...form, regulatory_impact: e.target.value })}
                placeholder="e.g., PCI-DSS v4.0 Req 6.2; OWASP Top 10 A03"
                className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-gray-600 mb-1">
                Recommended Controls <span className="text-gray-400 font-normal">(semicolon-separated)</span>
              </label>
              <input
                value={form.recommended_controls}
                onChange={e => setForm({ ...form, recommended_controls: e.target.value })}
                placeholder="e.g., Input validation; Parameterized queries; WAF rules"
                className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-gray-600 mb-1">
                Tags <span className="text-gray-400 font-normal">(semicolon-separated)</span>
              </label>
              <input
                value={form.tags}
                onChange={e => setForm({ ...form, tags: e.target.value })}
                placeholder="e.g., SQLi; authentication; pentest; Q1-2025"
                className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500"
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 mt-6 pt-4 border-t">
            <button onClick={resetForm} className="btn btn-secondary btn-sm">Cancel</button>
            <button onClick={handleSubmit} className="btn btn-primary btn-sm inline-flex items-center gap-2">
              <Save className="w-4 h-4" />
              {editingEntry ? 'Update Entry' : 'Save Entry'}
            </button>
          </div>
        </div>
      )}

      {/* Entries List */}
      {selectedProjectId && (
        <>
          {/* Filter bar */}
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  value={intelSearch}
                  onChange={e => setIntelSearch(e.target.value)}
                  placeholder="Search custom intel..."
                  className="w-full pl-10 pr-4 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500"
                />
              </div>
            </div>
            <div className="flex gap-2 flex-wrap">
              <button
                onClick={() => setIntelFilter('all')}
                className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${intelFilter === 'all' ? 'bg-primary-100 text-primary-800 border border-primary-300' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}`}
              >
                All ({entries.length})
              </button>
              {Object.entries(typeCounts).map(([type, count]: [string, any]) => (
                <button
                  key={type}
                  onClick={() => setIntelFilter(intelFilter === type ? 'all' : type)}
                  className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${intelFilter === type ? 'bg-primary-100 text-primary-800 border border-primary-300' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}`}
                >
                  {typeLabels[type] || type} ({count})
                </button>
              ))}
            </div>
          </div>

          {/* Entries */}
          {loadingEntries ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mx-auto"></div>
            </div>
          ) : filteredEntries.length === 0 ? (
            <div className="text-center py-12">
              <Database className="w-16 h-16 text-gray-300 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                {entries.length === 0 ? 'No Custom Intel Yet' : 'No Matching Entries'}
              </h3>
              <p className="text-gray-600 mb-4">
                {entries.length === 0
                  ? 'Add threat intel manually or upload a CSV/JSON/STIX file to enrich your threat models.'
                  : 'Try adjusting your search or filter criteria.'}
              </p>
              {entries.length === 0 && (
                <div className="flex items-center justify-center gap-3">
                  <button onClick={() => { setShowForm(true); setEditingEntry(null) }} className="btn btn-primary btn-sm inline-flex items-center gap-2">
                    <Plus className="w-4 h-4" /> Add Entry
                  </button>
                  <label className="btn btn-secondary btn-sm inline-flex items-center gap-2 cursor-pointer">
                    <Upload className="w-4 h-4" /> Upload File
                    <input ref={fileInputRef} type="file" accept=".csv,.json" onChange={handleFileUpload} className="hidden" />
                  </label>
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              {filteredEntries.map((entry: any) => (
                <CustomIntelCard
                  key={entry.id}
                  entry={entry}
                  severityColors={severityColors}
                  typeLabels={typeLabels}
                  onEdit={handleEdit}
                  onDelete={handleDelete}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function CustomIntelCard({ entry, severityColors, typeLabels, onEdit, onDelete }: any) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="card p-5 hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <div className="flex items-center flex-wrap gap-2 mb-1">
            <h4 className="font-semibold text-gray-900 truncate">{entry.title}</h4>
            <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${severityColors[entry.severity] || 'bg-gray-100 text-gray-800'}`}>
              {entry.severity?.toUpperCase()}
            </span>
            <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-700">
              {typeLabels[entry.intel_type] || entry.intel_type}
            </span>
            {entry.threat_category && (
              <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-indigo-100 text-indigo-700">
                {entry.threat_category}
              </span>
            )}
            <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-teal-100 text-teal-700">
              {entry.source}
            </span>
          </div>

          {entry.description && (
            <p className="text-sm text-gray-600 mt-1 line-clamp-2">{entry.description}</p>
          )}

          {/* Tags */}
          {entry.tags && entry.tags.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {entry.tags.map((tag: string, i: number) => (
                <span key={i} className="px-2 py-0.5 rounded text-xs bg-gray-200 text-gray-700">{tag}</span>
              ))}
            </div>
          )}

          {/* Expandable details */}
          {expanded && (
            <div className="mt-3 pt-3 border-t border-gray-200 space-y-2">
              {entry.mitre_techniques?.length > 0 && (
                <div>
                  <span className="text-xs font-semibold text-gray-500">MITRE ATT&CK:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {entry.mitre_techniques.map((t: string, i: number) => (
                      <a key={i} href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer"
                         className="px-2 py-0.5 rounded text-xs font-mono bg-red-50 text-red-700 hover:bg-red-100">{t}</a>
                    ))}
                  </div>
                </div>
              )}
              {entry.regulatory_impact?.length > 0 && (
                <div>
                  <span className="text-xs font-semibold text-gray-500">Regulatory Impact:</span>
                  <ul className="mt-1 text-sm text-gray-700 list-disc list-inside">
                    {entry.regulatory_impact.map((r: string, i: number) => <li key={i}>{r}</li>)}
                  </ul>
                </div>
              )}
              {entry.recommended_controls?.length > 0 && (
                <div>
                  <span className="text-xs font-semibold text-gray-500">Recommended Controls:</span>
                  <ul className="mt-1 text-sm text-gray-700 list-disc list-inside">
                    {entry.recommended_controls.map((c: string, i: number) => <li key={i}>{c}</li>)}
                  </ul>
                </div>
              )}
              <div className="text-xs text-gray-400 pt-1">
                Created by {entry.created_by} {entry.created_at && `on ${new Date(entry.created_at).toLocaleDateString()}`}
              </div>
            </div>
          )}
        </div>

        <div className="flex items-center gap-1 ml-3 flex-shrink-0">
          <button onClick={() => setExpanded(!expanded)} className="p-1.5 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-600">
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
          <button onClick={() => onEdit(entry)} className="p-1.5 rounded hover:bg-blue-100 text-gray-400 hover:text-blue-600">
            <Edit3 className="w-4 h-4" />
          </button>
          <button onClick={() => onDelete(entry.id)} className="p-1.5 rounded hover:bg-red-100 text-gray-400 hover:text-red-600">
            <Trash2 className="w-4 h-4" />
          </button>
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


// ---------------------------------------------------------------------------
// API Keys Tab — Create, manage, and view integration API keys
// ---------------------------------------------------------------------------
function APIKeysTab() {
  const [keys, setKeys] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyExpiry, setNewKeyExpiry] = useState<string>('')
  const [creating, setCreating] = useState(false)
  const [newlyCreatedKey, setNewlyCreatedKey] = useState<string | null>(null)
  const [copiedKey, setCopiedKey] = useState(false)
  const [showDocs, setShowDocs] = useState(false)

  const fetchKeys = async () => {
    try {
      setLoading(true)
      const token = localStorage.getItem('token')
      const res = await axios.get('/api/threat-intel/api-keys', {
        headers: { Authorization: `Bearer ${token}` }
      })
      setKeys(res.data.keys || [])
    } catch (err) {
      console.error('Failed to fetch API keys:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchKeys() }, [])

  const handleCreate = async () => {
    if (!newKeyName.trim()) return
    try {
      setCreating(true)
      const token = localStorage.getItem('token')
      const res = await axios.post('/api/threat-intel/api-keys', {
        name: newKeyName.trim(),
        scopes: ['threat_intel'],
        expires_in_days: newKeyExpiry ? parseInt(newKeyExpiry) : null,
      }, {
        headers: { Authorization: `Bearer ${token}` }
      })
      setNewlyCreatedKey(res.data.api_key)
      setNewKeyName('')
      setNewKeyExpiry('')
      fetchKeys()
    } catch (err) {
      console.error('Failed to create API key:', err)
    } finally {
      setCreating(false)
    }
  }

  const handleRevoke = async (keyId: number) => {
    if (!confirm('Revoke this API key? External systems using it will lose access.')) return
    try {
      const token = localStorage.getItem('token')
      await axios.delete(`/api/threat-intel/api-keys/${keyId}`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      fetchKeys()
    } catch (err) {
      console.error('Failed to revoke API key:', err)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopiedKey(true)
    setTimeout(() => setCopiedKey(false), 2000)
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-gray-900">API Keys</h3>
          <p className="text-sm text-gray-500 mt-1">
            Generate API keys for external systems to push threat intel into your projects.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowDocs(!showDocs)}
            className="btn-secondary text-sm flex items-center gap-2"
          >
            <FileText className="w-4 h-4" />
            {showDocs ? 'Hide' : 'Show'} API Docs
          </button>
          <button
            onClick={() => { setShowCreate(true); setNewlyCreatedKey(null) }}
            className="btn-primary text-sm flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Create API Key
          </button>
        </div>
      </div>

      {/* Newly created key banner */}
      {newlyCreatedKey && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-5 h-5 text-green-600 mt-0.5" />
            <div className="flex-1">
              <p className="text-sm font-medium text-green-900">API Key Created</p>
              <p className="text-xs text-green-700 mt-1 mb-2">
                Copy this key now — it will not be shown again.
              </p>
              <div className="flex items-center gap-2 bg-white border border-green-300 rounded-md px-3 py-2">
                <code className="text-sm text-gray-800 flex-1 font-mono break-all">{newlyCreatedKey}</code>
                <button
                  onClick={() => copyToClipboard(newlyCreatedKey)}
                  className="text-green-600 hover:text-green-800 p-1"
                  title="Copy to clipboard"
                >
                  {copiedKey ? <CheckCircle2 className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <button onClick={() => setNewlyCreatedKey(null)} className="text-green-400 hover:text-green-600">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Create key form */}
      {showCreate && !newlyCreatedKey && (
        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
          <h4 className="text-sm font-medium text-gray-900 mb-3">New API Key</h4>
          <div className="flex items-end gap-3">
            <div className="flex-1">
              <label className="block text-xs text-gray-600 mb-1">Key Name</label>
              <input
                type="text"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                placeholder="e.g., SIEM Integration, CI/CD Pipeline"
                className="input text-sm w-full"
              />
            </div>
            <div className="w-40">
              <label className="block text-xs text-gray-600 mb-1">Expires In (days)</label>
              <input
                type="number"
                value={newKeyExpiry}
                onChange={(e) => setNewKeyExpiry(e.target.value)}
                placeholder="Never"
                min="1"
                className="input text-sm w-full"
              />
            </div>
            <button
              onClick={handleCreate}
              disabled={creating || !newKeyName.trim()}
              className="btn-primary text-sm"
            >
              {creating ? 'Creating...' : 'Generate'}
            </button>
            <button
              onClick={() => setShowCreate(false)}
              className="btn-secondary text-sm"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* API Documentation */}
      {showDocs && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 space-y-4">
          <h4 className="text-sm font-semibold text-blue-900">Integration Guide</h4>

          <div>
            <p className="text-xs font-medium text-blue-900 mb-1">Authentication</p>
            <p className="text-xs text-blue-800">
              Include your API key in the <code className="bg-blue-100 px-1 rounded">X-API-Key</code> header with every request.
            </p>
          </div>

          <div>
            <p className="text-xs font-medium text-blue-900 mb-2">Endpoints</p>
            <div className="space-y-2">
              <div className="bg-white rounded p-2 border border-blue-100">
                <code className="text-xs text-gray-800">POST /api/threat-intel/external/ingest</code>
                <p className="text-xs text-gray-500 mt-1">Push a single threat intel entry</p>
              </div>
              <div className="bg-white rounded p-2 border border-blue-100">
                <code className="text-xs text-gray-800">POST /api/threat-intel/external/ingest/bulk</code>
                <p className="text-xs text-gray-500 mt-1">Push multiple entries at once</p>
              </div>
              <div className="bg-white rounded p-2 border border-blue-100">
                <code className="text-xs text-gray-800">GET /api/threat-intel/external/intel/{'<project_id>'}</code>
                <p className="text-xs text-gray-500 mt-1">Read intel entries for a project</p>
              </div>
            </div>
          </div>

          <div>
            <p className="text-xs font-medium text-blue-900 mb-1">Example: Push a Single Entry</p>
            <pre className="bg-gray-900 text-green-400 rounded p-3 text-xs overflow-x-auto">{`curl -X POST https://your-instance/api/threat-intel/external/ingest \\
  -H "X-API-Key: apsk_..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "project_id": 1,
    "title": "Supply Chain Attack via npm",
    "description": "Malicious packages targeting build pipelines",
    "intel_type": "scenario",
    "severity": "critical",
    "mitre_techniques": ["T1195.002"],
    "source": "internal_ti_team"
  }'`}</pre>
          </div>

          <div>
            <p className="text-xs font-medium text-blue-900 mb-1">Example: Bulk Upload</p>
            <pre className="bg-gray-900 text-green-400 rounded p-3 text-xs overflow-x-auto">{`curl -X POST https://your-instance/api/threat-intel/external/ingest/bulk \\
  -H "X-API-Key: apsk_..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "project_id": 1,
    "entries": [
      {"intel_type": "scenario", "title": "...", "severity": "high"},
      {"intel_type": "threat_actor", "title": "...", "severity": "critical"}
    ]
  }'`}</pre>
          </div>

          <div>
            <p className="text-xs font-medium text-blue-900 mb-1">Supported intel_type values</p>
            <div className="flex flex-wrap gap-1">
              {['incident', 'threat_actor', 'asset', 'scenario', 'regulation', 'control', 'pentest_finding', 'risk_appetite'].map(t => (
                <span key={t} className="px-2 py-0.5 bg-blue-100 text-blue-800 rounded text-xs font-mono">{t}</span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Keys list */}
      {loading ? (
        <div className="text-center py-8 text-gray-500">Loading API keys...</div>
      ) : keys.length === 0 ? (
        <div className="text-center py-12 text-gray-400">
          <Key className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p className="font-medium">No API keys yet</p>
          <p className="text-sm mt-1">Create an API key to allow external systems to integrate with your threat intel.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {keys.map((key) => (
            <div
              key={key.id}
              className={`border rounded-lg p-4 ${key.is_active ? 'bg-white border-gray-200' : 'bg-gray-50 border-gray-200 opacity-60'}`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Key className={`w-5 h-5 ${key.is_active ? 'text-primary-600' : 'text-gray-400'}`} />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-gray-900">{key.name}</span>
                      {key.is_active ? (
                        <span className="px-2 py-0.5 bg-green-100 text-green-800 rounded-full text-xs">Active</span>
                      ) : (
                        <span className="px-2 py-0.5 bg-gray-100 text-gray-600 rounded-full text-xs">Revoked</span>
                      )}
                    </div>
                    <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                      <span>Key: <code className="font-mono">{key.key_prefix}...</code></span>
                      <span>Created: {new Date(key.created_at).toLocaleDateString()}</span>
                      {key.last_used_at && (
                        <span>Last used: {new Date(key.last_used_at).toLocaleDateString()}</span>
                      )}
                      {key.expires_at && (
                        <span>Expires: {new Date(key.expires_at).toLocaleDateString()}</span>
                      )}
                      {key.scopes && (
                        <span>Scopes: {key.scopes.join(', ')}</span>
                      )}
                    </div>
                  </div>
                </div>
                {key.is_active && (
                  <button
                    onClick={() => handleRevoke(key.id)}
                    className="text-red-500 hover:text-red-700 text-sm flex items-center gap-1"
                  >
                    <Trash2 className="w-4 h-4" />
                    Revoke
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
