import { useState, useEffect, useCallback } from 'react'
import {
  GitBranch, RefreshCw, AlertTriangle, Shield, Users, FileWarning,
  ChevronDown, ChevronRight, CheckCircle, Clock, Eye, Trash2, Plus,
  Activity, TrendingUp, TrendingDown, Minus
} from 'lucide-react'
import axios from 'axios'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface MonitoredRepo {
  id: number
  owner: string
  repo: string
  full_name: string
  description?: string
  default_branch: string
  active: number
  last_scanned_at?: string
  total_commits_scanned: number
  added_by: string
  created_at: string
}

interface CommitScan {
  id: number
  repo_id: number
  sha: string
  author_name: string
  author_email: string
  commit_message: string
  committed_at: string
  files_changed: number
  additions: number
  deletions: number
  risk_score: number
  risk_level: string
  signals: string[]
  repo_full_name: string
  finding_count: number
  sensitive_file_count: number
}

interface CommitFinding {
  id: number
  rule_name: string
  severity: string
  file_path?: string
  line_number?: number
  matched_text?: string
  category: string
}

interface SensitiveFileAlert {
  id: number
  file_path: string
  pattern_matched: string
  author_email: string
  committed_at: string
  acknowledged: number
  sha: string
  repo_full_name: string
}

interface DeveloperProfile {
  id: number
  author_email: string
  author_name: string
  total_commits: number
  high_risk_commits: number
  total_findings: number
  avg_risk_score: number
  risk_trend: string
  last_commit_at?: string
}

interface Summary {
  total_monitored_repos: number
  total_commits_scanned: number
  high_risk_commits: number
  total_findings: number
  unacknowledged_alerts: number
  at_risk_developers: number
  recent_high_risk_commits: CommitScan[]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
  clean: 'bg-green-100 text-green-800 border-green-200',
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-blue-100 text-blue-700',
}

function RiskBadge({ level }: { level: string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border ${RISK_COLORS[level] || RISK_COLORS.clean}`}>
      {level.toUpperCase()}
    </span>
  )
}

function SignalChip({ signal }: { signal: string }) {
  const icons: Record<string, string> = {
    off_hours: '🕐',
    author_committer_mismatch: '👤',
    unsigned_commit: '🔓',
    large_deletion: '🗑️',
    force_push: '⚡',
  }
  if (signal.startsWith('sast_findings:')) {
    const count = signal.split(':')[1]
    return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-red-50 text-red-700 border border-red-200">🔍 {count} finding{parseInt(count) !== 1 ? 's' : ''}</span>
  }
  if (signal.startsWith('sensitive_files:')) {
    const count = signal.split(':')[1]
    return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-amber-50 text-amber-700 border border-amber-200">🗂️ {count} sensitive file{parseInt(count) !== 1 ? 's' : ''}</span>
  }
  const icon = icons[signal] || '⚠️'
  const label = signal.replace(/_/g, ' ')
  return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700 border border-gray-200">{icon} {label}</span>
}

function formatDate(dt?: string) {
  if (!dt) return '—'
  try {
    return new Date(dt).toLocaleString()
  } catch {
    return dt
  }
}

function timeAgo(dt?: string) {
  if (!dt) return '—'
  const diff = Date.now() - new Date(dt).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

// ---------------------------------------------------------------------------
// API helper
// ---------------------------------------------------------------------------
function apiHeaders() {
  return { Authorization: `Bearer ${localStorage.getItem('token')}` }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

// Commit row with expandable detail
function CommitRow({ commit, onExpand, expanded }: {
  commit: CommitScan
  onExpand: (id: number) => void
  expanded: boolean
}) {
  return (
    <div className="border border-gray-200 rounded-lg overflow-hidden mb-2">
      <div
        className="flex items-center justify-between p-3 cursor-pointer hover:bg-gray-50"
        onClick={() => onExpand(commit.id)}
      >
        <div className="flex items-center space-x-3 flex-1 min-w-0">
          {expanded ? <ChevronDown className="w-4 h-4 text-gray-400 flex-shrink-0" /> : <ChevronRight className="w-4 h-4 text-gray-400 flex-shrink-0" />}
          <div className="min-w-0">
            <div className="flex items-center space-x-2 mb-1 flex-wrap gap-1">
              <code className="text-xs bg-gray-100 px-1.5 py-0.5 rounded font-mono">{commit.sha.slice(0, 8)}</code>
              <span className="text-xs text-gray-500">{commit.repo_full_name}</span>
              <RiskBadge level={commit.risk_level} />
              <span className="text-xs font-semibold text-gray-600">Score: {commit.risk_score.toFixed(1)}</span>
            </div>
            <p className="text-sm text-gray-700 truncate">{commit.commit_message?.split('\n')[0]}</p>
            <div className="flex items-center space-x-3 mt-1 text-xs text-gray-500">
              <span>{commit.author_name} ({commit.author_email})</span>
              <span>·</span>
              <span>{timeAgo(commit.committed_at)}</span>
              <span>·</span>
              <span>+{commit.additions} / -{commit.deletions}</span>
            </div>
          </div>
        </div>
        <div className="flex items-center space-x-1 flex-shrink-0 ml-2 flex-wrap gap-1">
          {(commit.signals || []).map((s, i) => <SignalChip key={i} signal={s} />)}
        </div>
      </div>
      {expanded && <CommitDetail scanId={commit.id} />}
    </div>
  )
}

function CommitDetail({ scanId }: { scanId: number }) {
  const [detail, setDetail] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    axios.get(`/api/github-monitor/commits/${scanId}`, { headers: apiHeaders() })
      .then(r => setDetail(r.data))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [scanId])

  if (loading) return <div className="p-4 text-sm text-gray-500">Loading details...</div>
  if (!detail) return null

  return (
    <div className="border-t border-gray-200 bg-gray-50 p-4 space-y-4">
      {detail.findings?.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-gray-700 mb-2">SAST Findings</h4>
          <div className="space-y-1">
            {detail.findings.map((f: CommitFinding) => (
              <div key={f.id} className="flex items-start space-x-2 text-xs">
                <span className={`px-1.5 py-0.5 rounded font-medium ${SEVERITY_COLORS[f.severity] || ''}`}>{f.severity}</span>
                <span className="font-medium text-gray-700">{f.rule_name}</span>
                {f.file_path && <span className="text-gray-500">{f.file_path}:{f.line_number}</span>}
              </div>
            ))}
          </div>
        </div>
      )}
      {detail.sensitive_file_alerts?.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-amber-700 mb-2">Sensitive Files Touched</h4>
          <div className="space-y-1">
            {detail.sensitive_file_alerts.map((a: SensitiveFileAlert) => (
              <div key={a.id} className="flex items-center space-x-2 text-xs">
                <FileWarning className="w-3 h-3 text-amber-500" />
                <code className="text-amber-700">{a.file_path}</code>
                <span className="text-gray-400">({a.pattern_matched})</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {detail.findings?.length === 0 && detail.sensitive_file_alerts?.length === 0 && (
        <p className="text-xs text-gray-500">No detailed findings. Risk score driven by metadata signals only.</p>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

function CommitFeedTab() {
  const [commits, setCommits] = useState<CommitScan[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [filterRisk, setFilterRisk] = useState('')
  const [filterAuthor, setFilterAuthor] = useState('')
  const [repos, setRepos] = useState<MonitoredRepo[]>([])
  const [filterRepo, setFilterRepo] = useState<string>('')

  const loadRepos = useCallback(async () => {
    const r = await axios.get('/api/github-monitor/repos', { headers: apiHeaders() })
    setRepos(r.data)
  }, [])

  const loadCommits = useCallback(async () => {
    setLoading(true)
    try {
      const params: any = { page, page_size: 20 }
      if (filterRisk) params.risk_level = filterRisk
      if (filterAuthor) params.author = filterAuthor
      if (filterRepo) params.repo_id = parseInt(filterRepo)
      const r = await axios.get('/api/github-monitor/commits', { headers: apiHeaders(), params })
      setCommits(r.data.commits)
      setTotal(r.data.total)
    } finally {
      setLoading(false)
    }
  }, [page, filterRisk, filterAuthor, filterRepo])

  useEffect(() => {
    loadRepos()
  }, [loadRepos])

  useEffect(() => {
    loadCommits()
  }, [loadCommits])

  const handleExpand = (id: number) => setExpandedId(prev => prev === id ? null : id)

  return (
    <div>
      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-4">
        <select
          value={filterRisk}
          onChange={e => { setFilterRisk(e.target.value); setPage(1) }}
          className="px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="">All Risk Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="clean">Clean</option>
        </select>
        <select
          value={filterRepo}
          onChange={e => { setFilterRepo(e.target.value); setPage(1) }}
          className="px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="">All Repos</option>
          {repos.map(r => <option key={r.id} value={r.id}>{r.full_name}</option>)}
        </select>
        <input
          type="text"
          value={filterAuthor}
          onChange={e => { setFilterAuthor(e.target.value); setPage(1) }}
          placeholder="Filter by author..."
          className="px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
        <button onClick={loadCommits} className="inline-flex items-center px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 rounded-md">
          <RefreshCw className="w-3.5 h-3.5 mr-1" /> Refresh
        </button>
      </div>

      {/* Commit list */}
      {loading ? (
        <div className="text-center py-8 text-gray-500">Loading commits...</div>
      ) : commits.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <GitBranch className="w-12 h-12 mx-auto mb-3 text-gray-300" />
          <p className="font-medium">No commits scanned yet</p>
          <p className="text-sm mt-1">Add a repository and click "Scan Now" to get started.</p>
        </div>
      ) : (
        <>
          <p className="text-sm text-gray-500 mb-3">{total} commits total</p>
          {commits.map(c => (
            <CommitRow key={c.id} commit={c} expanded={expandedId === c.id} onExpand={handleExpand} />
          ))}
          {/* Pagination */}
          <div className="flex justify-center space-x-2 mt-4">
            <button disabled={page === 1} onClick={() => setPage(p => p - 1)} className="px-3 py-1.5 text-sm border rounded disabled:opacity-40">Prev</button>
            <span className="px-3 py-1.5 text-sm text-gray-600">Page {page} of {Math.ceil(total / 20) || 1}</span>
            <button disabled={page >= Math.ceil(total / 20)} onClick={() => setPage(p => p + 1)} className="px-3 py-1.5 text-sm border rounded disabled:opacity-40">Next</button>
          </div>
        </>
      )}
    </div>
  )
}

function DeveloperProfilesTab() {
  const [developers, setDevelopers] = useState<DeveloperProfile[]>([])
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const r = await axios.get('/api/github-monitor/developers', { headers: apiHeaders() })
      setDevelopers(r.data)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  function TrendIcon({ trend }: { trend: string }) {
    if (trend === 'increasing') return <TrendingUp className="w-4 h-4 text-red-500" />
    if (trend === 'decreasing') return <TrendingDown className="w-4 h-4 text-green-500" />
    return <Minus className="w-4 h-4 text-gray-400" />
  }

  if (loading) return <div className="text-center py-8 text-gray-500">Loading profiles...</div>

  if (developers.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        <Users className="w-12 h-12 mx-auto mb-3 text-gray-300" />
        <p className="font-medium">No developer profiles yet</p>
        <p className="text-sm mt-1">Profiles are created automatically when commits are scanned.</p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Developer</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Commits</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">High-Risk</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Findings</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Avg Risk</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Trend</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Commit</th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {developers.map(dev => (
            <tr key={dev.id} className="hover:bg-gray-50">
              <td className="px-4 py-3">
                <div>
                  <p className="text-sm font-medium text-gray-900">{dev.author_name || '—'}</p>
                  <p className="text-xs text-gray-500">{dev.author_email}</p>
                </div>
              </td>
              <td className="px-4 py-3 text-sm text-gray-700">{dev.total_commits}</td>
              <td className="px-4 py-3">
                <span className={`text-sm font-medium ${dev.high_risk_commits > 0 ? 'text-red-600' : 'text-gray-500'}`}>
                  {dev.high_risk_commits}
                </span>
              </td>
              <td className="px-4 py-3 text-sm text-gray-700">{dev.total_findings}</td>
              <td className="px-4 py-3">
                <span className={`text-sm font-bold ${dev.avg_risk_score >= 4 ? 'text-red-600' : dev.avg_risk_score >= 2 ? 'text-amber-600' : 'text-green-600'}`}>
                  {dev.avg_risk_score.toFixed(1)}
                </span>
              </td>
              <td className="px-4 py-3">
                <TrendIcon trend={dev.risk_trend} />
              </td>
              <td className="px-4 py-3 text-xs text-gray-500">{timeAgo(dev.last_commit_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function SensitiveFileAlertsTab({ unackCount, onAckChange }: { unackCount: number; onAckChange: () => void }) {
  const [alerts, setAlerts] = useState<SensitiveFileAlert[]>([])
  const [loading, setLoading] = useState(false)
  const [filterAck, setFilterAck] = useState<string>('false')
  const [acknowledging, setAcknowledging] = useState<number | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: any = {}
      if (filterAck !== '') params.acknowledged = filterAck === 'true'
      const r = await axios.get('/api/github-monitor/alerts/sensitive-files', { headers: apiHeaders(), params })
      setAlerts(r.data)
    } finally {
      setLoading(false)
    }
  }, [filterAck])

  useEffect(() => { load() }, [load])

  const handleAck = async (alertId: number) => {
    setAcknowledging(alertId)
    try {
      await axios.post(`/api/github-monitor/alerts/sensitive-files/${alertId}/acknowledge`, {}, { headers: apiHeaders() })
      await load()
      onAckChange()
    } finally {
      setAcknowledging(null)
    }
  }

  return (
    <div>
      <div className="flex items-center space-x-3 mb-4">
        <select
          value={filterAck}
          onChange={e => setFilterAck(e.target.value)}
          className="px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="false">Unacknowledged</option>
          <option value="true">Acknowledged</option>
          <option value="">All</option>
        </select>
        <button onClick={load} className="inline-flex items-center px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 rounded-md">
          <RefreshCw className="w-3.5 h-3.5 mr-1" /> Refresh
        </button>
      </div>

      {loading ? (
        <div className="text-center py-8 text-gray-500">Loading alerts...</div>
      ) : alerts.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <FileWarning className="w-12 h-12 mx-auto mb-3 text-gray-300" />
          <p className="font-medium">No alerts</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">File</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Pattern</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Author</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Commit</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Repo</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Date</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {alerts.map(a => (
                <tr key={a.id} className={a.acknowledged ? 'opacity-50' : 'hover:bg-amber-50'}>
                  <td className="px-4 py-3"><code className="text-xs text-amber-700">{a.file_path}</code></td>
                  <td className="px-4 py-3 text-xs text-gray-500">{a.pattern_matched}</td>
                  <td className="px-4 py-3 text-xs text-gray-600">{a.author_email}</td>
                  <td className="px-4 py-3"><code className="text-xs bg-gray-100 px-1 rounded">{a.sha?.slice(0, 8)}</code></td>
                  <td className="px-4 py-3 text-xs text-gray-600">{a.repo_full_name}</td>
                  <td className="px-4 py-3 text-xs text-gray-500">{timeAgo(a.committed_at)}</td>
                  <td className="px-4 py-3">
                    {!a.acknowledged && (
                      <button
                        onClick={() => handleAck(a.id)}
                        disabled={acknowledging === a.id}
                        className="inline-flex items-center px-2 py-1 text-xs bg-green-50 text-green-700 border border-green-200 rounded hover:bg-green-100"
                      >
                        {acknowledging === a.id ? <RefreshCw className="w-3 h-3 animate-spin" /> : <CheckCircle className="w-3 h-3 mr-1" />}
                        Acknowledge
                      </button>
                    )}
                    {a.acknowledged && <span className="text-xs text-gray-400">Acknowledged</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function MonitoredReposTab({ onScanComplete }: { onScanComplete: () => void }) {
  const [repos, setRepos] = useState<MonitoredRepo[]>([])
  const [loading, setLoading] = useState(false)
  const [addOwner, setAddOwner] = useState('')
  const [addRepo, setAddRepo] = useState('')
  const [adding, setAdding] = useState(false)
  const [scanning, setScanning] = useState<number | null>(null)
  const [removing, setRemoving] = useState<number | null>(null)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const loadRepos = useCallback(async () => {
    setLoading(true)
    try {
      const r = await axios.get('/api/github-monitor/repos', { headers: apiHeaders() })
      setRepos(r.data)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadRepos() }, [loadRepos])

  const handleAdd = async () => {
    if (!addOwner.trim() || !addRepo.trim()) return
    setAdding(true)
    setMessage(null)
    try {
      await axios.post('/api/github-monitor/repos', { owner: addOwner.trim(), repo: addRepo.trim() }, { headers: apiHeaders() })
      setMessage({ type: 'success', text: `Now monitoring ${addOwner}/${addRepo}` })
      setAddOwner('')
      setAddRepo('')
      await loadRepos()
    } catch (e: any) {
      setMessage({ type: 'error', text: e.response?.data?.detail || 'Failed to add repository' })
    } finally {
      setAdding(false)
    }
  }

  const handleScan = async (repoId: number) => {
    setScanning(repoId)
    setMessage(null)
    try {
      await axios.post(`/api/github-monitor/scan/${repoId}`, {}, { headers: apiHeaders() })
      setMessage({ type: 'success', text: 'Scan queued. Results will appear in the Commit Feed.' })
      onScanComplete()
    } catch (e: any) {
      setMessage({ type: 'error', text: e.response?.data?.detail || 'Scan failed' })
    } finally {
      setScanning(null)
    }
  }

  const handleRemove = async (repoId: number, fullName: string) => {
    if (!confirm(`Remove ${fullName} from monitoring?`)) return
    setRemoving(repoId)
    try {
      await axios.delete(`/api/github-monitor/repos/${repoId}`, { headers: apiHeaders() })
      await loadRepos()
    } finally {
      setRemoving(null)
    }
  }

  return (
    <div className="space-y-6">
      {/* Add repo form */}
      <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Add Repository</h3>
        <div className="flex flex-wrap gap-2">
          <input
            type="text"
            value={addOwner}
            onChange={e => setAddOwner(e.target.value)}
            placeholder="owner / org"
            className="px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 w-40"
          />
          <span className="self-center text-gray-400">/</span>
          <input
            type="text"
            value={addRepo}
            onChange={e => setAddRepo(e.target.value)}
            placeholder="repository"
            className="px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 w-48"
            onKeyDown={e => e.key === 'Enter' && handleAdd()}
          />
          <button
            onClick={handleAdd}
            disabled={adding || !addOwner || !addRepo}
            className="inline-flex items-center px-4 py-2 text-sm bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
          >
            {adding ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> : <Plus className="w-4 h-4 mr-2" />}
            Add
          </button>
        </div>
        {message && (
          <div className={`mt-3 p-2 rounded text-sm ${message.type === 'success' ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'}`}>
            {message.text}
          </div>
        )}
      </div>

      {/* Repo list */}
      {loading ? (
        <div className="text-center py-8 text-gray-500">Loading repositories...</div>
      ) : repos.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <GitBranch className="w-12 h-12 mx-auto mb-3 text-gray-300" />
          <p className="font-medium">No repositories added yet</p>
          <p className="text-sm mt-1">Add a repository above to start monitoring.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {repos.map(repo => (
            <div key={repo.id} className="bg-white border border-gray-200 rounded-lg p-4 flex items-center justify-between">
              <div>
                <div className="flex items-center space-x-2">
                  <GitBranch className="w-4 h-4 text-gray-400" />
                  <span className="font-medium text-gray-900">{repo.full_name}</span>
                  <code className="text-xs bg-gray-100 px-1.5 py-0.5 rounded">{repo.default_branch}</code>
                </div>
                {repo.description && <p className="text-sm text-gray-500 mt-1">{repo.description}</p>}
                <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500">
                  <span>{repo.total_commits_scanned} commits scanned</span>
                  {repo.last_scanned_at && <span>Last: {timeAgo(repo.last_scanned_at)}</span>}
                  <span>Added by {repo.added_by}</span>
                </div>
              </div>
              <div className="flex items-center space-x-2 ml-4">
                <button
                  onClick={() => handleScan(repo.id)}
                  disabled={scanning === repo.id}
                  className="inline-flex items-center px-3 py-1.5 text-sm bg-indigo-50 text-indigo-700 border border-indigo-200 rounded hover:bg-indigo-100"
                >
                  {scanning === repo.id ? <RefreshCw className="w-3.5 h-3.5 mr-1 animate-spin" /> : <Activity className="w-3.5 h-3.5 mr-1" />}
                  Scan Now
                </button>
                <button
                  onClick={() => handleRemove(repo.id, repo.full_name)}
                  disabled={removing === repo.id}
                  className="inline-flex items-center px-2 py-1.5 text-sm text-red-600 border border-red-200 rounded hover:bg-red-50"
                >
                  {removing === repo.id ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------
export default function GitHubMonitorPage() {
  const [activeTab, setActiveTab] = useState<'commits' | 'developers' | 'alerts' | 'repos'>('commits')
  const [summary, setSummary] = useState<Summary | null>(null)
  const [unackAlerts, setUnackAlerts] = useState(0)

  const loadSummary = useCallback(async () => {
    try {
      const r = await axios.get('/api/github-monitor/summary', { headers: apiHeaders() })
      setSummary(r.data)
      setUnackAlerts(r.data.unacknowledged_alerts)
    } catch (e) {
      console.error('Failed to load summary:', e)
    }
  }, [])

  useEffect(() => {
    loadSummary()
  }, [loadSummary])

  const tabs = [
    { id: 'commits', label: 'Commit Feed', icon: GitBranch },
    { id: 'developers', label: 'Developer Profiles', icon: Users },
    { id: 'alerts', label: 'Sensitive File Alerts', icon: FileWarning, badge: unackAlerts },
    { id: 'repos', label: 'Monitored Repos', icon: Activity },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">GitHub Commit Monitor</h1>
        <p className="text-gray-500 text-sm mt-1">Detect insider threat signals in commit activity across monitored repositories.</p>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <div className="bg-white border border-gray-200 rounded-lg p-4 text-center">
            <p className="text-2xl font-bold text-gray-900">{summary.total_monitored_repos}</p>
            <p className="text-xs text-gray-500 mt-1">Repos Monitored</p>
          </div>
          <div className="bg-white border border-gray-200 rounded-lg p-4 text-center">
            <p className="text-2xl font-bold text-gray-900">{summary.total_commits_scanned}</p>
            <p className="text-xs text-gray-500 mt-1">Commits Scanned</p>
          </div>
          <div className={`border rounded-lg p-4 text-center ${summary.high_risk_commits > 0 ? 'bg-red-50 border-red-200' : 'bg-white border-gray-200'}`}>
            <p className={`text-2xl font-bold ${summary.high_risk_commits > 0 ? 'text-red-700' : 'text-gray-900'}`}>{summary.high_risk_commits}</p>
            <p className="text-xs text-gray-500 mt-1">High-Risk Commits</p>
          </div>
          <div className="bg-white border border-gray-200 rounded-lg p-4 text-center">
            <p className="text-2xl font-bold text-gray-900">{summary.total_findings}</p>
            <p className="text-xs text-gray-500 mt-1">SAST Findings</p>
          </div>
          <div className={`border rounded-lg p-4 text-center ${summary.unacknowledged_alerts > 0 ? 'bg-amber-50 border-amber-200' : 'bg-white border-gray-200'}`}>
            <p className={`text-2xl font-bold ${summary.unacknowledged_alerts > 0 ? 'text-amber-700' : 'text-gray-900'}`}>{summary.unacknowledged_alerts}</p>
            <p className="text-xs text-gray-500 mt-1">Open Alerts</p>
          </div>
          <div className={`border rounded-lg p-4 text-center ${summary.at_risk_developers > 0 ? 'bg-orange-50 border-orange-200' : 'bg-white border-gray-200'}`}>
            <p className={`text-2xl font-bold ${summary.at_risk_developers > 0 ? 'text-orange-700' : 'text-gray-900'}`}>{summary.at_risk_developers}</p>
            <p className="text-xs text-gray-500 mt-1">At-Risk Devs</p>
          </div>
        </div>
      )}

      {/* Recent high-risk commits quick view */}
      {summary && summary.recent_high_risk_commits?.length > 0 && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center mb-2">
            <AlertTriangle className="w-4 h-4 text-red-600 mr-2" />
            <h3 className="text-sm font-semibold text-red-800">Recent High-Risk Commits</h3>
          </div>
          <div className="space-y-1">
            {summary.recent_high_risk_commits.map(c => (
              <div key={c.id} className="flex items-center justify-between text-xs">
                <div className="flex items-center space-x-2">
                  <code className="bg-white px-1.5 py-0.5 rounded border">{c.sha?.slice(0, 8)}</code>
                  <span className="text-red-700">{c.repo_full_name}</span>
                  <span className="text-gray-600">{c.author_name}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <RiskBadge level={c.risk_level} />
                  <span className="text-gray-500">{timeAgo(c.committed_at)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="bg-white shadow rounded-lg">
        <div className="border-b border-gray-200">
          <nav className="flex -mb-px overflow-x-auto">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center space-x-2 px-4 py-3 text-sm font-medium border-b-2 whitespace-nowrap ${
                  activeTab === tab.id
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                <span>{tab.label}</span>
                {tab.badge !== undefined && tab.badge > 0 && (
                  <span className="inline-flex items-center justify-center w-5 h-5 text-xs font-bold bg-red-500 text-white rounded-full">
                    {tab.badge}
                  </span>
                )}
              </button>
            ))}
          </nav>
        </div>

        <div className="p-6">
          {activeTab === 'commits' && <CommitFeedTab />}
          {activeTab === 'developers' && <DeveloperProfilesTab />}
          {activeTab === 'alerts' && <SensitiveFileAlertsTab unackCount={unackAlerts} onAckChange={loadSummary} />}
          {activeTab === 'repos' && <MonitoredReposTab onScanComplete={loadSummary} />}
        </div>
      </div>
    </div>
  )
}
