import { useState, useEffect, useCallback } from 'react'
import {
  GitBranch, RefreshCw, AlertTriangle, Users, FileWarning,
  ChevronDown, ChevronRight, CheckCircle, Trash2, Plus,
  Activity, TrendingUp, TrendingDown, Minus, LayoutGrid,
  CalendarDays, Settings2, Zap, ShieldAlert, Eye,
  Brain, Crosshair, ShieldCheck, BookOpen, ListChecks, Loader2
} from 'lucide-react'
import axios from 'axios'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface MonitoredRepo {
  id: number; owner: string; repo: string; full_name: string
  description?: string; default_branch: string; active: number
  last_scanned_at?: string; total_commits_scanned: number
  added_by: string; created_at: string
}

interface RepoStat {
  id: number; full_name: string; owner: string; repo: string
  last_scanned_at?: string; total_scanned: number; default_branch: string
  clean_count: number; low_count: number; medium_count: number
  high_count: number; critical_count: number
  peak_risk_score: number; avg_risk_score: number; open_alerts: number
}

interface TimelineDayData { clean: number; low: number; medium: number; high: number; critical: number }
interface TimelineResponse { days: string[]; totals_by_day: Record<string, TimelineDayData> }

interface CommitScan {
  id: number; repo_id: number; sha: string; author_name: string; author_email: string
  commit_message: string; committed_at: string; files_changed: number
  additions: number; deletions: number; risk_score: number; risk_level: string
  signals: string[]; repo_full_name: string; finding_count: number; sensitive_file_count: number
}

interface CommitFinding {
  id: number; rule_name: string; severity: string; file_path?: string
  line_number?: number; matched_text?: string
  rule_description?: string; cwe?: string; owasp?: string; remediation?: string
}

interface CommitAIAnalysis {
  threat_level: 'intentional_insider' | 'suspicious' | 'negligent' | 'false_positive'
  confidence: number
  impact_summary: string
  intent_analysis: string
  malicious_scenario?: string
  key_indicators: string[]
  recommended_actions: string[]
  analyzed_at?: string
}

interface SensitiveFileAlert {
  id: number; file_path: string; pattern_matched: string; author_email: string
  committed_at: string; acknowledged: number; sha: string; repo_full_name: string
}

interface DeveloperProfile {
  id: number; author_email: string; author_name: string; total_commits: number
  high_risk_commits: number; total_findings: number; avg_risk_score: number
  risk_trend: string; last_commit_at?: string
}

interface Summary {
  total_monitored_repos: number; total_commits_scanned: number
  high_risk_commits: number; total_findings: number
  unacknowledged_alerts: number; at_risk_developers: number
  recent_high_risk_commits: CommitScan[]
}

type Tab = 'overview' | 'commits' | 'timeline' | 'developers' | 'alerts' | 'findings' | 'repos'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const RISK_LEVELS = ['critical', 'high', 'medium', 'low', 'clean'] as const

const RISK_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-300',
  high:     'bg-orange-100 text-orange-800 border-orange-300',
  medium:   'bg-yellow-100 text-yellow-800 border-yellow-300',
  low:      'bg-blue-100 text-blue-800 border-blue-300',
  clean:    'bg-green-100 text-green-800 border-green-300',
}
const RISK_BAR: Record<string, string> = {
  critical: 'bg-red-500',
  high:     'bg-orange-400',
  medium:   'bg-yellow-400',
  low:      'bg-blue-400',
  clean:    'bg-green-400',
}
const RISK_BORDER: Record<string, string> = {
  critical: 'border-l-red-600',
  high:     'border-l-orange-500',
  medium:   'border-l-yellow-400',
  low:      'border-l-blue-400',
  clean:    'border-l-green-400',
}
const SEVERITY_PILL: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high:     'bg-orange-100 text-orange-700',
  medium:   'bg-yellow-100 text-yellow-700',
  low:      'bg-blue-100 text-blue-700',
}
const SIGNAL_ICONS: Record<string, string> = {
  off_hours: '🕐', author_committer_mismatch: '👤', unsigned_commit: '🔓',
  large_deletion: '🗑️', force_push: '⚡',
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------
function apiHeaders() { return { Authorization: `Bearer ${localStorage.getItem('token')}` } }

function repoWorstLevel(s: RepoStat): string {
  if (s.critical_count > 0) return 'critical'
  if (s.high_count > 0) return 'high'
  if (s.medium_count > 0) return 'medium'
  if (s.low_count > 0) return 'low'
  return 'clean'
}

function timeAgo(dt?: string) {
  if (!dt) return '—'
  const diff = Date.now() - new Date(dt).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function shortDate(iso: string) {
  const d = new Date(iso)
  return `${d.getMonth() + 1}/${d.getDate()}`
}

function RiskBadge({ level }: { level: string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border ${RISK_BADGE[level] ?? RISK_BADGE.clean}`}>
      {level.toUpperCase()}
    </span>
  )
}

function SignalChip({ signal }: { signal: string }) {
  if (signal.startsWith('sast_findings:')) {
    const n = signal.split(':')[1]
    return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-red-50 text-red-700 border border-red-200">🔍 {n} finding{parseInt(n) !== 1 ? 's' : ''}</span>
  }
  if (signal.startsWith('sensitive_files:')) {
    const n = signal.split(':')[1]
    return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-amber-50 text-amber-700 border border-amber-200">🗂️ {n} sensitive</span>
  }
  const icon = SIGNAL_ICONS[signal] ?? '⚠️'
  return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700 border border-gray-200">{icon} {signal.replace(/_/g, ' ')}</span>
}

// ---------------------------------------------------------------------------
// RiskDistributionBar — stacked inline bar, no library
// ---------------------------------------------------------------------------
function RiskDistributionBar({ stats, showLabels = false }: { stats: RepoStat; showLabels?: boolean }) {
  const total = stats.total_scanned || 1
  const segments = [
    { key: 'critical_count' as keyof RepoStat, bg: 'bg-red-500',    label: 'Crit' },
    { key: 'high_count'     as keyof RepoStat, bg: 'bg-orange-400', label: 'High' },
    { key: 'medium_count'   as keyof RepoStat, bg: 'bg-yellow-400', label: 'Med' },
    { key: 'low_count'      as keyof RepoStat, bg: 'bg-blue-400',   label: 'Low' },
    { key: 'clean_count'    as keyof RepoStat, bg: 'bg-green-400',  label: 'Clean' },
  ]
  return (
    <div>
      <div className="flex h-3 rounded-full overflow-hidden w-full bg-gray-100">
        {segments.map(seg => {
          const count = stats[seg.key] as number
          const pct = (count / total) * 100
          if (pct === 0) return null
          return (
            <div
              key={seg.key}
              title={`${seg.label}: ${count}`}
              className={`${seg.bg} transition-all`}
              style={{ width: `${pct}%` }}
            />
          )
        })}
      </div>
      {showLabels && (
        <div className="flex justify-between mt-1.5">
          {segments.map(seg => {
            const count = stats[seg.key] as number
            return (
              <div key={seg.key} className="text-center flex-1">
                <span className={`text-xs font-semibold ${count > 0 ? 'text-gray-800' : 'text-gray-300'}`}>{count}</span>
                <p className="text-[10px] text-gray-400">{seg.label}</p>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// RepoRiskCard (Overview tab)
// ---------------------------------------------------------------------------
function RepoRiskCard({
  stats, onScanNow, onViewCommits, scanning
}: {
  stats: RepoStat
  onScanNow: (id: number) => void
  onViewCommits: (id: number) => void
  scanning: boolean
}) {
  const worst = repoWorstLevel(stats)
  const borderClass = RISK_BORDER[worst] ?? 'border-l-gray-300'

  return (
    <div className={`bg-white border border-gray-200 border-l-4 ${borderClass} rounded-lg p-4 flex flex-col gap-3 shadow-sm hover:shadow-md transition-shadow`}>
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-gray-400 flex-shrink-0" />
            <span className="font-semibold text-gray-900 text-sm truncate">{stats.full_name}</span>
          </div>
          <p className="text-xs text-gray-400 mt-0.5 flex items-center gap-2">
            <code className="bg-gray-100 px-1 rounded">{stats.default_branch}</code>
            {stats.last_scanned_at ? `Scanned ${timeAgo(stats.last_scanned_at)}` : 'Never scanned'}
          </p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <RiskBadge level={worst} />
          {stats.open_alerts > 0 && (
            <span className="text-xs text-amber-700 bg-amber-50 border border-amber-200 px-1.5 py-0.5 rounded-full">
              ⚠️ {stats.open_alerts} alert{stats.open_alerts > 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>

      {/* Risk distribution bar */}
      {stats.total_scanned > 0 ? (
        <RiskDistributionBar stats={stats} showLabels />
      ) : (
        <div className="flex flex-col items-center py-2 text-gray-400">
          <p className="text-xs">No commits scanned yet</p>
        </div>
      )}

      {/* Stats row */}
      {stats.total_scanned > 0 && (
        <div className="flex justify-between text-xs text-gray-500 bg-gray-50 rounded-lg px-3 py-2">
          <span><strong className="text-gray-800">{stats.total_scanned}</strong> commits</span>
          <span>Peak <strong className={`${stats.peak_risk_score >= 7 ? 'text-red-600' : stats.peak_risk_score >= 4 ? 'text-orange-600' : 'text-gray-700'}`}>{stats.peak_risk_score.toFixed(1)}</strong></span>
          <span>Avg <strong className="text-gray-700">{stats.avg_risk_score.toFixed(1)}</strong></span>
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-2 mt-auto pt-1">
        <button
          onClick={() => onScanNow(stats.id)}
          disabled={scanning}
          className="flex-1 inline-flex items-center justify-center px-3 py-1.5 text-xs font-medium bg-indigo-50 text-indigo-700 border border-indigo-200 rounded-md hover:bg-indigo-100 disabled:opacity-50"
        >
          {scanning ? <RefreshCw className="w-3.5 h-3.5 mr-1 animate-spin" /> : <Activity className="w-3.5 h-3.5 mr-1" />}
          Scan Now
        </button>
        <button
          onClick={() => onViewCommits(stats.id)}
          className="flex-1 inline-flex items-center justify-center px-3 py-1.5 text-xs font-medium bg-gray-50 text-gray-700 border border-gray-200 rounded-md hover:bg-gray-100"
        >
          <Eye className="w-3.5 h-3.5 mr-1" />
          View Commits
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// OrgRiskMap — overview header
// ---------------------------------------------------------------------------
function OrgRiskMap({ repoStats }: { repoStats: RepoStat[] }) {
  const totals = repoStats.reduce(
    (acc, s) => ({
      clean: acc.clean + s.clean_count,
      low: acc.low + s.low_count,
      medium: acc.medium + s.medium_count,
      high: acc.high + s.high_count,
      critical: acc.critical + s.critical_count,
    }),
    { clean: 0, low: 0, medium: 0, high: 0, critical: 0 }
  )
  const total = Object.values(totals).reduce((a, b) => a + b, 0)

  const orgRisk = total > 0
    ? Math.min(10, ((totals.critical * 2.5 + totals.high * 1.5 + totals.medium * 0.5) / total) * 10)
    : 0

  const riskColor = orgRisk >= 7 ? 'text-red-600' : orgRisk >= 4 ? 'text-orange-500' : orgRisk >= 2 ? 'text-yellow-600' : 'text-green-600'

  return (
    <div className="bg-gradient-to-r from-gray-900 to-gray-800 text-white rounded-xl p-5 shadow-lg">
      <div className="flex flex-col md:flex-row md:items-center gap-4">
        {/* Org risk score */}
        <div className="flex items-center gap-4 md:border-r md:border-gray-600 md:pr-6">
          <div className="text-center">
            <p className="text-xs text-gray-400 uppercase tracking-widest mb-1">Org Risk Score</p>
            <p className={`text-5xl font-black ${riskColor}`}>{orgRisk.toFixed(1)}</p>
            <p className="text-xs text-gray-400 mt-1">out of 10</p>
          </div>
        </div>

        {/* Org-level stacked bar */}
        <div className="flex-1">
          <p className="text-xs text-gray-400 mb-2 uppercase tracking-widest">Commit Risk Distribution — All Repos</p>
          <div className="flex h-5 rounded-lg overflow-hidden w-full bg-gray-700">
            {RISK_LEVELS.map(level => {
              const count = totals[level]
              const pct = total > 0 ? (count / total) * 100 : 0
              if (pct === 0) return null
              return (
                <div
                  key={level}
                  title={`${level}: ${count} commits`}
                  className={`${RISK_BAR[level]} transition-all`}
                  style={{ width: `${pct}%` }}
                />
              )
            })}
          </div>
          <div className="flex gap-4 mt-2 flex-wrap">
            {RISK_LEVELS.map(level => (
              <div key={level} className="flex items-center gap-1.5">
                <div className={`w-2.5 h-2.5 rounded-full ${RISK_BAR[level]}`} />
                <span className="text-xs text-gray-300 capitalize">{level}</span>
                <span className="text-xs font-bold text-white">{totals[level as keyof typeof totals]}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Repo count */}
        <div className="flex flex-row md:flex-col items-center gap-4 md:gap-1 md:text-right md:border-l md:border-gray-600 md:pl-6">
          <div className="text-center">
            <p className="text-3xl font-bold text-white">{repoStats.length}</p>
            <p className="text-xs text-gray-400">Repos monitored</p>
          </div>
          <div className="text-center">
            <p className="text-3xl font-bold text-white">{total}</p>
            <p className="text-xs text-gray-400">Commits scanned</p>
          </div>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Risk Timeline Heatmap (pure CSS)
// ---------------------------------------------------------------------------
function RiskTimelineHeatmap({ repos }: { repos: MonitoredRepo[] }) {
  const [timeline, setTimeline] = useState<TimelineResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [selectedRepo, setSelectedRepo] = useState<string>('')
  const [hoveredDay, setHoveredDay] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: any = { days: 14 }
      if (selectedRepo) params.repo_id = parseInt(selectedRepo)
      const r = await axios.get('/api/github-monitor/timeline', { headers: apiHeaders(), params })
      setTimeline(r.data)
    } finally {
      setLoading(false)
    }
  }, [selectedRepo])

  useEffect(() => { load() }, [load])

  const rowLabels: { level: string; bg: string; label: string }[] = [
    { level: 'critical', bg: 'bg-red-500',    label: 'Critical' },
    { level: 'high',     bg: 'bg-orange-400', label: 'High' },
    { level: 'medium',   bg: 'bg-yellow-400', label: 'Med' },
    { level: 'low',      bg: 'bg-blue-400',   label: 'Low' },
    { level: 'clean',    bg: 'bg-green-400',  label: 'Clean' },
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
        <div>
          <h3 className="text-base font-semibold text-gray-900">14-Day Commit Risk Timeline</h3>
          <p className="text-xs text-gray-500">Each column is one day — color intensity shows commit volume at each risk level</p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={selectedRepo}
            onChange={e => setSelectedRepo(e.target.value)}
            className="px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="">All Repos</option>
            {repos.map(r => <option key={r.id} value={r.id}>{r.full_name}</option>)}
          </select>
          <button onClick={load} className="p-1.5 rounded-md bg-gray-100 hover:bg-gray-200">
            <RefreshCw className={`w-4 h-4 text-gray-500 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {!timeline || loading ? (
        <div className="text-center py-16 text-gray-400">
          <CalendarDays className="w-10 h-10 mx-auto mb-2 opacity-30" />
          <p>{loading ? 'Loading timeline...' : 'No data yet'}</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <div className="min-w-[600px]">
            {/* Risk level row labels + grid */}
            <div className="flex gap-2">
              {/* Y-axis labels */}
              <div className="flex flex-col gap-1 pt-0 pb-6 justify-around" style={{ width: '52px' }}>
                {rowLabels.map(row => (
                  <div key={row.level} className="flex items-center justify-end gap-1" style={{ height: '28px' }}>
                    <div className={`w-2.5 h-2.5 rounded-sm ${row.bg} flex-shrink-0`} />
                    <span className="text-[10px] text-gray-500 font-medium">{row.label}</span>
                  </div>
                ))}
              </div>

              {/* Day columns */}
              <div
                className="flex-1 grid gap-1"
                style={{ gridTemplateColumns: `repeat(${timeline.days.length}, 1fr)` }}
              >
                {timeline.days.map(day => {
                  const d = timeline.totals_by_day[day] ?? { clean: 0, low: 0, medium: 0, high: 0, critical: 0 }
                  const dayTotal = d.clean + d.low + d.medium + d.high + d.critical
                  const maxInDay = Math.max(d.clean, d.low, d.medium, d.high, d.critical, 1)

                  return (
                    <div
                      key={day}
                      className="relative flex flex-col gap-1 cursor-pointer group"
                      onMouseEnter={() => setHoveredDay(day)}
                      onMouseLeave={() => setHoveredDay(null)}
                    >
                      {rowLabels.map(row => {
                        const count = d[row.level as keyof TimelineDayData]
                        const opacity = dayTotal === 0 ? 0.07 : 0.15 + (count / maxInDay) * 0.85
                        return (
                          <div
                            key={row.level}
                            className={`rounded-sm ${row.bg}`}
                            style={{ height: '28px', opacity, transition: 'opacity 0.2s' }}
                          />
                        )
                      })}

                      {/* Date label */}
                      <p className="text-[9px] text-gray-400 text-center mt-0.5">{shortDate(day)}</p>

                      {/* Hover tooltip */}
                      {hoveredDay === day && (
                        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 z-20 bg-gray-900 text-white text-xs rounded-lg px-3 py-2 shadow-xl whitespace-nowrap pointer-events-none">
                          <p className="font-semibold mb-1">{day}</p>
                          {rowLabels.map(row => {
                            const count = d[row.level as keyof TimelineDayData]
                            return count > 0 ? (
                              <div key={row.level} className="flex items-center gap-2">
                                <div className={`w-2 h-2 rounded-sm ${row.bg}`} />
                                <span className="capitalize">{row.level}:</span>
                                <span className="font-bold">{count}</span>
                              </div>
                            ) : null
                          })}
                          {dayTotal === 0 && <p className="text-gray-400">No commits</p>}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Developer Risk Cards (replaces table)
// ---------------------------------------------------------------------------
function DeveloperCard({ dev, onDrillDown }: { dev: DeveloperProfile; onDrillDown: (email: string) => void }) {
  const barWidth = Math.min((dev.avg_risk_score / 10) * 100, 100)
  const borderColor = dev.avg_risk_score >= 7 ? 'border-l-red-600'
    : dev.avg_risk_score >= 4 ? 'border-l-orange-500'
    : dev.avg_risk_score >= 2 ? 'border-l-yellow-400'
    : 'border-l-green-400'

  const riskColor = dev.avg_risk_score >= 7 ? 'text-red-600'
    : dev.avg_risk_score >= 4 ? 'text-orange-500'
    : dev.avg_risk_score >= 2 ? 'text-yellow-600'
    : 'text-green-600'

  function TrendIcon() {
    if (dev.risk_trend === 'increasing') return <span className="text-red-500 flex items-center gap-1"><TrendingUp className="w-3.5 h-3.5" /> Increasing</span>
    if (dev.risk_trend === 'decreasing') return <span className="text-green-600 flex items-center gap-1"><TrendingDown className="w-3.5 h-3.5" /> Decreasing</span>
    return <span className="text-gray-400 flex items-center gap-1"><Minus className="w-3.5 h-3.5" /> Stable</span>
  }

  const initials = (dev.author_name || dev.author_email || '?').slice(0, 2).toUpperCase()

  return (
    <div className={`bg-white border border-gray-200 border-l-4 ${borderColor} rounded-lg p-4 shadow-sm hover:shadow-md transition-shadow flex flex-col gap-3`}>
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-full bg-indigo-100 flex items-center justify-center flex-shrink-0">
          <span className="text-indigo-700 font-bold text-sm">{initials}</span>
        </div>
        <div className="min-w-0">
          <p className="font-semibold text-gray-900 text-sm truncate">{dev.author_name || '(no name)'}</p>
          <p className="text-xs text-gray-500 truncate">{dev.author_email}</p>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-2 bg-gray-50 rounded-lg px-3 py-2">
        <div className="text-center">
          <p className="text-lg font-bold text-gray-800">{dev.total_commits}</p>
          <p className="text-[10px] text-gray-400">Commits</p>
        </div>
        <div className="text-center">
          <p className={`text-lg font-bold ${dev.high_risk_commits > 0 ? 'text-red-600' : 'text-gray-800'}`}>{dev.high_risk_commits}</p>
          <p className="text-[10px] text-gray-400">High-Risk</p>
        </div>
        <div className="text-center">
          <p className="text-lg font-bold text-gray-800">{dev.total_findings}</p>
          <p className="text-[10px] text-gray-400">Findings</p>
        </div>
      </div>

      {/* Risk score bar */}
      <div>
        <div className="flex justify-between items-center mb-1">
          <span className="text-xs text-gray-500">Avg Risk Score</span>
          <span className={`text-sm font-bold ${riskColor}`}>{dev.avg_risk_score.toFixed(1)}/10</span>
        </div>
        <div className="h-2 rounded-full bg-gray-200">
          <div
            className="h-2 rounded-full bg-gradient-to-r from-green-400 via-yellow-400 to-red-600 transition-all"
            style={{ width: `${barWidth}%` }}
          />
        </div>
      </div>

      {/* Trend + last commit */}
      <div className="flex justify-between items-center text-xs">
        <TrendIcon />
        <span className="text-gray-400">{timeAgo(dev.last_commit_at)}</span>
      </div>

      {/* Drill-down */}
      <button
        onClick={() => onDrillDown(dev.author_email)}
        className="w-full text-xs text-indigo-600 hover:text-indigo-800 font-medium py-1.5 border border-indigo-100 hover:border-indigo-300 rounded-md bg-indigo-50 hover:bg-indigo-100 transition"
      >
        View Commits →
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// CommitRow with expand
// ---------------------------------------------------------------------------
function CommitRow({ commit, expanded, onExpand, onFpChange }: {
  commit: CommitScan; expanded: boolean; onExpand: () => void
  onFpChange?: (id: number, isFp: boolean) => void
}) {
  const [fpLoading, setFpLoading] = useState(false)
  const isFp = (commit as any).false_positive === 1

  const toggleFp = async (e: React.MouseEvent) => {
    e.stopPropagation()
    setFpLoading(true)
    try {
      const endpoint = isFp
        ? `/api/github-monitor/commits/${commit.id}/unmark-false-positive`
        : `/api/github-monitor/commits/${commit.id}/mark-false-positive`
      await axios.post(endpoint, {}, { headers: apiHeaders() })
      onFpChange?.(commit.id, !isFp)
    } finally { setFpLoading(false) }
  }

  return (
    <div className={`border rounded-lg overflow-hidden mb-2 ${isFp ? 'border-gray-200 opacity-60' : 'border-gray-200'}`}>
      <div className="flex items-center justify-between p-3 cursor-pointer hover:bg-gray-50" onClick={onExpand}>
        <div className="flex items-center space-x-3 flex-1 min-w-0">
          {expanded ? <ChevronDown className="w-4 h-4 text-gray-400 flex-shrink-0" /> : <ChevronRight className="w-4 h-4 text-gray-400 flex-shrink-0" />}
          <div className="min-w-0">
            <div className="flex items-center flex-wrap gap-2 mb-1">
              <code className="text-xs bg-gray-100 px-1.5 py-0.5 rounded font-mono">{commit.sha.slice(0, 8)}</code>
              <span className="text-xs text-gray-500">{commit.repo_full_name}</span>
              <RiskBadge level={commit.risk_level} />
              <span className="text-xs font-semibold text-gray-600">Score: {commit.risk_score.toFixed(1)}</span>
              {isFp && <span className="text-xs px-1.5 py-0.5 bg-gray-100 text-gray-500 rounded border">False Positive</span>}
            </div>
            <p className="text-sm text-gray-700 truncate">{commit.commit_message?.split('\n')[0]}</p>
            <div className="flex items-center gap-3 mt-1 text-xs text-gray-500 flex-wrap">
              <span>{commit.author_name} ({commit.author_email})</span>
              <span>·</span><span>{timeAgo(commit.committed_at)}</span>
              <span>·</span><span>+{commit.additions} / -{commit.deletions}</span>
            </div>
          </div>
        </div>
        <div className="flex items-center flex-wrap gap-1 ml-3 flex-shrink-0">
          {(commit.signals || []).map((s, i) => <SignalChip key={i} signal={s} />)}
          <button
            onClick={toggleFp}
            disabled={fpLoading}
            title={isFp ? 'Remove false positive flag' : 'Mark as false positive'}
            className={`ml-1 text-xs px-2 py-1 rounded border transition ${isFp ? 'bg-gray-100 text-gray-500 border-gray-300 hover:bg-white' : 'bg-white text-gray-400 border-gray-200 hover:bg-gray-50 hover:text-gray-600'}`}
          >
            {fpLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <CheckCircle className={`w-3 h-3 ${isFp ? 'text-green-500' : ''}`} />}
          </button>
        </div>
      </div>
      {expanded && <CommitDetail scanId={commit.id} />}
    </div>
  )
}

const THREAT_LEVEL_CONFIG: Record<string, { label: string; color: string; bg: string; border: string; icon: string }> = {
  intentional_insider: { label: 'Intentional Insider Threat', color: 'text-red-700', bg: 'bg-red-50', border: 'border-red-300', icon: '🚨' },
  suspicious:          { label: 'Suspicious Activity',        color: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-300', icon: '⚠️' },
  negligent:           { label: 'Negligent / Accidental',     color: 'text-yellow-700', bg: 'bg-yellow-50', border: 'border-yellow-300', icon: '⚡' },
  false_positive:      { label: 'Likely False Positive',      color: 'text-green-700', bg: 'bg-green-50', border: 'border-green-300', icon: '✓' },
}

function CommitDetail({ scanId }: { scanId: number }) {
  const [detail, setDetail] = useState<any>(null)
  const [loadError, setLoadError] = useState('')
  const [aiAnalysis, setAiAnalysis] = useState<CommitAIAnalysis | null>(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState('')
  const [expandedFindingId, setExpandedFindingId] = useState<number | null>(null)

  useEffect(() => {
    setLoadError('')
    axios.get(`/api/github-monitor/commits/${scanId}`, { headers: apiHeaders() })
      .then(r => {
        setDetail(r.data)
        if (r.data.ai_analysis) setAiAnalysis(r.data.ai_analysis)
      })
      .catch(e => {
        setLoadError(e.response?.data?.detail || 'Failed to load commit details.')
        setDetail({})
      })
  }, [scanId])

  const runAiAnalysis = async () => {
    setAiLoading(true)
    setAiError('')
    try {
      const r = await axios.post(`/api/github-monitor/commits/${scanId}/ai-analyze`, {}, { headers: apiHeaders() })
      setAiAnalysis(r.data)
    } catch (e: any) {
      setAiError(e.response?.data?.detail || 'AI analysis failed')
    } finally {
      setAiLoading(false)
    }
  }

  if (!detail) return <div className="p-4 text-sm text-gray-400 animate-pulse flex items-center gap-2"><Loader2 className="w-3.5 h-3.5 animate-spin" /> Loading commit details...</div>
  if (loadError) return <div className="p-4 text-sm text-red-500 flex items-center gap-2"><AlertTriangle className="w-3.5 h-3.5" /> {loadError}</div>

  const findings: CommitFinding[] = detail.findings || []
  const sensitiveFiles = detail.sensitive_file_alerts || []
  const tl = aiAnalysis ? THREAT_LEVEL_CONFIG[aiAnalysis.threat_level] ?? THREAT_LEVEL_CONFIG.suspicious : null

  return (
    <div className="border-t border-gray-200 bg-gray-50">
      <div className="p-4 space-y-4">

        {/* SAST Findings */}
        {findings.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-gray-700 mb-2 flex items-center gap-1">
              <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
              SAST Findings ({findings.length})
            </p>
            <div className="space-y-2">
              {findings.map((f) => {
                const findingIsFp = (f as any).false_positive === 1
                return (
                <div key={f.id} className={`bg-white border rounded-lg overflow-hidden ${findingIsFp ? 'border-gray-100 opacity-60' : 'border-gray-200'}`}>
                  {/* Finding header */}
                  <div
                    className="flex items-start gap-2 p-2.5 cursor-pointer hover:bg-gray-50"
                    onClick={() => setExpandedFindingId(expandedFindingId === f.id ? null : f.id)}
                  >
                    <span className={`px-1.5 py-0.5 rounded text-xs font-bold flex-shrink-0 ${findingIsFp ? 'bg-gray-100 text-gray-400' : SEVERITY_PILL[f.severity] ?? ''}`}>
                      {f.severity.toUpperCase()}
                    </span>
                    <div className="flex-1 min-w-0">
                      <span className="text-xs font-semibold text-gray-800">{f.rule_name}</span>
                      {findingIsFp && <span className="ml-2 text-xs text-gray-400 italic">false positive</span>}
                      {f.file_path && (
                        <span className="ml-2 text-xs text-gray-400 font-mono">
                          {f.file_path}{f.line_number ? `:${f.line_number}` : ''}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      {f.cwe && <span className="text-xs px-1.5 py-0.5 bg-blue-50 text-blue-700 rounded font-mono">{f.cwe}</span>}
                      {f.owasp && <span className="text-xs px-1.5 py-0.5 bg-purple-50 text-purple-700 rounded font-mono">{f.owasp}</span>}
                      <button
                        onClick={async (e) => {
                          e.stopPropagation()
                          const ep = findingIsFp
                            ? `/api/github-monitor/findings/${f.id}/unmark-false-positive`
                            : `/api/github-monitor/findings/${f.id}/mark-false-positive`
                          await axios.post(ep, {}, { headers: apiHeaders() })
                          ;(f as any).false_positive = findingIsFp ? 0 : 1
                          setDetail({ ...detail })
                        }}
                        title={findingIsFp ? 'Restore finding' : 'Mark as false positive'}
                        className={`text-xs px-1.5 py-0.5 rounded border transition ${findingIsFp ? 'bg-green-50 text-green-600 border-green-200' : 'bg-white text-gray-400 border-gray-200 hover:bg-gray-50'}`}
                      >
                        {findingIsFp ? '✓ FP' : 'FP?'}
                      </button>
                      {expandedFindingId === f.id ? <ChevronDown className="w-3.5 h-3.5 text-gray-400" /> : <ChevronRight className="w-3.5 h-3.5 text-gray-400" />}
                    </div>
                  </div>

                  {/* Expanded finding detail */}
                  {expandedFindingId === f.id && (
                    <div className="border-t border-gray-100 bg-gray-50 p-3 space-y-2.5">
                      {/* Matched code */}
                      {f.matched_text && (
                        <div>
                          <p className="text-xs font-medium text-gray-500 mb-1">Matched Code</p>
                          <pre className="text-xs bg-gray-900 text-red-300 p-2.5 rounded-md overflow-x-auto font-mono leading-relaxed whitespace-pre-wrap break-all">{f.matched_text}</pre>
                        </div>
                      )}
                      {/* Rule description */}
                      {f.rule_description && (
                        <div>
                          <p className="text-xs font-medium text-gray-500 mb-1 flex items-center gap-1"><BookOpen className="w-3 h-3" /> Description</p>
                          <p className="text-xs text-gray-700">{f.rule_description}</p>
                        </div>
                      )}
                      {/* Remediation */}
                      {f.remediation && (
                        <div>
                          <p className="text-xs font-medium text-green-700 mb-1 flex items-center gap-1"><ShieldCheck className="w-3 h-3" /> Remediation</p>
                          <p className="text-xs text-gray-700">{f.remediation}</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
                )}
              )}
            </div>
          </div>
        )}

        {/* Sensitive Files */}
        {sensitiveFiles.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-amber-700 mb-2 flex items-center gap-1">
              <FileWarning className="w-3.5 h-3.5" />
              Sensitive Files Touched ({sensitiveFiles.length})
            </p>
            <div className="space-y-1">
              {sensitiveFiles.map((a: any) => (
                <div key={a.id} className="flex items-center gap-2 text-xs bg-amber-50 border border-amber-200 rounded px-2 py-1.5">
                  <FileWarning className="w-3 h-3 text-amber-500 flex-shrink-0" />
                  <code className="text-amber-800 font-mono">{a.file_path}</code>
                  <span className="text-amber-500 ml-auto">pattern: <span className="font-mono">{a.pattern_matched}</span></span>
                </div>
              ))}
            </div>
          </div>
        )}

        {!findings.length && !sensitiveFiles.length && (
          <p className="text-xs text-gray-400 italic">Risk driven by metadata signals only — no code patterns matched.</p>
        )}

        {/* AI Analysis Section */}
        <div className="border-t border-gray-200 pt-3">
          {!aiAnalysis && !aiLoading && (
            <button
              onClick={runAiAnalysis}
              className="flex items-center gap-2 px-3 py-2 bg-gradient-to-r from-indigo-600 to-purple-600 text-white text-xs font-semibold rounded-lg hover:from-indigo-700 hover:to-purple-700 transition-all shadow-sm"
            >
              <Brain className="w-3.5 h-3.5" />
              Analyze with AI — Assess Impact & Intent
            </button>
          )}
          {aiLoading && (
            <div className="flex items-center gap-2 text-xs text-indigo-600">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>AI is analyzing commit for malicious intent...</span>
            </div>
          )}
          {aiError && (
            <p className="text-xs text-red-500 mt-1">{aiError}</p>
          )}
          {aiAnalysis && tl && (
            <div className={`rounded-xl border ${tl.border} ${tl.bg} p-4 space-y-3`}>
              {/* Header */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Brain className={`w-4 h-4 ${tl.color}`} />
                  <span className={`text-sm font-bold ${tl.color}`}>
                    {tl.icon} {tl.label}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-gray-500">Confidence</span>
                  <div className="flex items-center gap-1">
                    <div className="w-20 h-1.5 bg-gray-200 rounded-full">
                      <div
                        className={`h-1.5 rounded-full ${aiAnalysis.confidence > 0.7 ? 'bg-red-500' : aiAnalysis.confidence > 0.4 ? 'bg-orange-400' : 'bg-green-500'}`}
                        style={{ width: `${Math.round(aiAnalysis.confidence * 100)}%` }}
                      />
                    </div>
                    <span className={`text-xs font-bold ${tl.color}`}>{Math.round(aiAnalysis.confidence * 100)}%</span>
                  </div>
                  <button
                    onClick={runAiAnalysis}
                    disabled={aiLoading}
                    className="ml-2 text-xs text-gray-400 hover:text-gray-600 flex items-center gap-1"
                    title="Re-analyze"
                  >
                    <RefreshCw className="w-3 h-3" />
                  </button>
                </div>
              </div>

              {/* Impact Summary */}
              <div>
                <p className="text-xs font-semibold text-gray-700 mb-1 flex items-center gap-1">
                  <Crosshair className="w-3.5 h-3.5 text-red-500" /> Real-World Impact
                </p>
                <p className="text-xs text-gray-700 leading-relaxed">{aiAnalysis.impact_summary}</p>
              </div>

              {/* Intent Analysis */}
              <div>
                <p className="text-xs font-semibold text-gray-700 mb-1 flex items-center gap-1">
                  <Eye className="w-3.5 h-3.5 text-indigo-500" /> Intent Analysis
                </p>
                <p className="text-xs text-gray-700 leading-relaxed">{aiAnalysis.intent_analysis}</p>
              </div>

              {/* Malicious Scenario */}
              {aiAnalysis.malicious_scenario && aiAnalysis.malicious_scenario !== 'null' && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-2.5">
                  <p className="text-xs font-semibold text-red-700 mb-1 flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> Possible Malicious Scenario
                  </p>
                  <p className="text-xs text-red-800 leading-relaxed">{aiAnalysis.malicious_scenario}</p>
                </div>
              )}

              {/* Key Indicators + Recommended Actions side by side */}
              <div className="grid grid-cols-2 gap-3">
                {aiAnalysis.key_indicators?.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-gray-700 mb-1.5 flex items-center gap-1">
                      <Zap className="w-3.5 h-3.5 text-orange-500" /> Key Indicators
                    </p>
                    <ul className="space-y-1">
                      {aiAnalysis.key_indicators.map((ind, i) => (
                        <li key={i} className="flex items-start gap-1.5 text-xs text-gray-700">
                          <span className="text-orange-500 font-bold flex-shrink-0">•</span>
                          {ind}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {aiAnalysis.recommended_actions?.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-gray-700 mb-1.5 flex items-center gap-1">
                      <ListChecks className="w-3.5 h-3.5 text-green-600" /> Recommended Actions
                    </p>
                    <ol className="space-y-1">
                      {aiAnalysis.recommended_actions.map((action, i) => (
                        <li key={i} className="flex items-start gap-1.5 text-xs text-gray-700">
                          <span className="text-green-600 font-bold flex-shrink-0">{i + 1}.</span>
                          {action}
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
              </div>

              {aiAnalysis.analyzed_at && (
                <p className="text-xs text-gray-400 text-right">Analyzed {new Date(aiAnalysis.analyzed_at).toLocaleString()}</p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Commit Feed tab (flat + swimlane modes)
// ---------------------------------------------------------------------------
function CommitFeedTab({
  initialRepoFilter, initialAuthor, repoStats
}: {
  initialRepoFilter?: string
  initialAuthor?: string
  repoStats: RepoStat[]
}) {
  const [viewMode, setViewMode] = useState<'flat' | 'swimlane'>('flat')
  const [commits, setCommits] = useState<CommitScan[]>([])
  const [swimlaneData, setSwimlaneData] = useState<{ repo_id: number; repo_full_name: string; commits: CommitScan[] }[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [filterRisk, setFilterRisk] = useState('')
  const [filterAuthor, setFilterAuthor] = useState(initialAuthor || '')
  const [filterRepo, setFilterRepo] = useState(initialRepoFilter || '')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [showFp, setShowFp] = useState(false)

  const loadFlat = useCallback(async () => {
    setLoading(true)
    try {
      const params: any = { page, page_size: 20, show_false_positives: showFp }
      if (filterRisk) params.risk_level = filterRisk
      if (filterAuthor) params.author = filterAuthor
      if (filterRepo) params.repo_id = parseInt(filterRepo)
      if (dateFrom) params.date_from = dateFrom
      if (dateTo) params.date_to = dateTo
      const r = await axios.get('/api/github-monitor/commits', { headers: apiHeaders(), params })
      setCommits(r.data.commits); setTotal(r.data.total)
    } finally { setLoading(false) }
  }, [page, filterRisk, filterAuthor, filterRepo, dateFrom, dateTo, showFp])

  const loadSwimlane = useCallback(async () => {
    setLoading(true)
    try {
      const params: any = {}
      if (filterRisk) params.risk_level = filterRisk
      const r = await axios.get('/api/github-monitor/commits/by-repo', { headers: apiHeaders(), params })
      setSwimlaneData(r.data.repos)
    } finally { setLoading(false) }
  }, [filterRisk])

  useEffect(() => {
    if (viewMode === 'flat') loadFlat(); else loadSwimlane()
  }, [viewMode, loadFlat, loadSwimlane])

  const filterBar = (
    <div className="space-y-2 mb-4">
      <div className="flex flex-wrap gap-2">
        {/* Mode toggle */}
        <div className="flex rounded-lg border border-gray-200 overflow-hidden text-xs font-medium">
          <button onClick={() => setViewMode('flat')} className={`px-3 py-1.5 ${viewMode === 'flat' ? 'bg-indigo-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`}>Flat</button>
          <button onClick={() => setViewMode('swimlane')} className={`px-3 py-1.5 ${viewMode === 'swimlane' ? 'bg-indigo-600 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`}>By Repo</button>
        </div>
        <select value={filterRisk} onChange={e => { setFilterRisk(e.target.value); setPage(1) }}
          className="px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500">
          <option value="">All Risk Levels</option>
          {['critical','high','medium','low','clean'].map(l => <option key={l} value={l}>{l.charAt(0).toUpperCase()+l.slice(1)}</option>)}
        </select>
        {viewMode === 'flat' && (
          <>
            <select value={filterRepo} onChange={e => { setFilterRepo(e.target.value); setPage(1) }}
              className="px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500">
              <option value="">All Repos</option>
              {repoStats.map(r => <option key={r.id} value={r.id}>{r.full_name}</option>)}
            </select>
            <input type="text" value={filterAuthor} onChange={e => { setFilterAuthor(e.target.value); setPage(1) }}
              placeholder="Filter by author..."
              className="px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 w-40" />
          </>
        )}
        <button onClick={() => viewMode === 'flat' ? loadFlat() : loadSwimlane()}
          className="inline-flex items-center px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 rounded-md">
          <RefreshCw className="w-3.5 h-3.5 mr-1" /> Refresh
        </button>
      </div>
      {/* Date range + FP toggle */}
      <div className="flex flex-wrap gap-2 items-center">
        <span className="text-xs text-gray-500 font-medium">Date:</span>
        <input type="date" value={dateFrom} onChange={e => { setDateFrom(e.target.value); setPage(1) }}
          className="px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-indigo-500" />
        <span className="text-xs text-gray-400">→</span>
        <input type="date" value={dateTo} onChange={e => { setDateTo(e.target.value); setPage(1) }}
          className="px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-indigo-500" />
        {(dateFrom || dateTo) && (
          <button onClick={() => { setDateFrom(''); setDateTo(''); setPage(1) }} className="text-xs text-gray-400 hover:text-gray-600 underline">Clear</button>
        )}
        <label className="flex items-center gap-1.5 text-xs text-gray-500 ml-2 cursor-pointer select-none">
          <input type="checkbox" checked={showFp} onChange={e => { setShowFp(e.target.checked); setPage(1) }} className="rounded" />
          Show false positives
        </label>
      </div>
    </div>
  )

  if (loading) return <div>{filterBar}<div className="text-center py-12 text-gray-400">Loading commits...</div></div>

  // Swimlane view
  if (viewMode === 'swimlane') {
    const empty = swimlaneData.length === 0
    return (
      <div>
        {filterBar}
        {empty ? (
          <div className="text-center py-12 text-gray-400">
            <GitBranch className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p>No commits found. Scan a repo to get started.</p>
          </div>
        ) : (
          <div className="space-y-5">
            {swimlaneData.map(lane => {
              const stat = repoStats.find(r => r.id === lane.repo_id)
              const worst = stat ? repoWorstLevel(stat) : 'clean'
              return (
                <div key={lane.repo_id} className="border border-gray-200 rounded-xl overflow-hidden shadow-sm">
                  {/* Swimlane header */}
                  <div className={`flex items-center justify-between px-4 py-2.5 border-b border-gray-200 ${worst === 'critical' ? 'bg-red-50' : worst === 'high' ? 'bg-orange-50' : 'bg-gray-50'}`}>
                    <div className="flex items-center gap-3">
                      <GitBranch className="w-4 h-4 text-gray-500" />
                      <span className="font-semibold text-sm text-gray-900">{lane.repo_full_name}</span>
                      <RiskBadge level={worst} />
                    </div>
                    {stat && (
                      <div className="hidden md:flex items-center gap-2" style={{ width: '160px' }}>
                        <RiskDistributionBar stats={stat} />
                      </div>
                    )}
                  </div>
                  {/* Commits in lane */}
                  <div className="p-3 space-y-0">
                    {lane.commits.map(c => (
                      <CommitRow key={c.id} commit={c} expanded={expandedId === c.id} onExpand={() => setExpandedId(prev => prev === c.id ? null : c.id)} />
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    )
  }

  // Flat view
  if (commits.length === 0) return (
    <div>
      {filterBar}
      <div className="text-center py-12 text-gray-400">
        <GitBranch className="w-12 h-12 mx-auto mb-3 opacity-30" />
        <p>No commits scanned yet. Add a repo and click Scan Now.</p>
      </div>
    </div>
  )

  return (
    <div>
      {filterBar}
      <p className="text-sm text-gray-500 mb-3">{total} commits total</p>
      {commits.map(c => (
        <CommitRow key={c.id} commit={c} expanded={expandedId === c.id} onExpand={() => setExpandedId(p => p === c.id ? null : c.id)} />
      ))}
      <div className="flex justify-center gap-2 mt-4">
        <button disabled={page === 1} onClick={() => setPage(p => p - 1)} className="px-3 py-1.5 text-sm border rounded disabled:opacity-40">Prev</button>
        <span className="px-3 py-1.5 text-sm text-gray-600">Page {page} of {Math.ceil(total / 20) || 1}</span>
        <button disabled={page >= Math.ceil(total / 20)} onClick={() => setPage(p => p + 1)} className="px-3 py-1.5 text-sm border rounded disabled:opacity-40">Next</button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Sensitive File Alerts tab
// ---------------------------------------------------------------------------
function SensitiveFileAlertsTab({ onAckChange }: { onAckChange: () => void }) {
  const [alerts, setAlerts] = useState<SensitiveFileAlert[]>([])
  const [loading, setLoading] = useState(false)
  const [filterAck, setFilterAck] = useState('false')
  const [acking, setAcking] = useState<number | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: any = {}
      if (filterAck !== '') params.acknowledged = filterAck === 'true'
      const r = await axios.get('/api/github-monitor/alerts/sensitive-files', { headers: apiHeaders(), params })
      setAlerts(r.data)
    } finally { setLoading(false) }
  }, [filterAck])

  useEffect(() => { load() }, [load])

  const handleAck = async (id: number) => {
    setAcking(id)
    await axios.post(`/api/github-monitor/alerts/sensitive-files/${id}/acknowledge`, {}, { headers: apiHeaders() })
    await load(); onAckChange(); setAcking(null)
  }

  return (
    <div>
      <div className="flex gap-3 mb-4">
        <select value={filterAck} onChange={e => setFilterAck(e.target.value)}
          className="px-3 py-1.5 text-sm border border-gray-300 rounded-md">
          <option value="false">Unacknowledged</option>
          <option value="true">Acknowledged</option>
          <option value="">All</option>
        </select>
        <button onClick={load} className="p-2 rounded-md bg-gray-100 hover:bg-gray-200"><RefreshCw className="w-4 h-4 text-gray-500" /></button>
      </div>
      {loading ? <div className="text-center py-12 text-gray-400">Loading...</div> :
        alerts.length === 0 ? (
          <div className="text-center py-12 text-gray-400">
            <FileWarning className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p>No alerts</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>{['File','Pattern','Author','Commit','Repo','Date','Action'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">{h}</th>
                ))}</tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-100">
                {alerts.map(a => (
                  <tr key={a.id} className={a.acknowledged ? 'opacity-40' : 'hover:bg-amber-50'}>
                    <td className="px-4 py-3"><code className="text-xs text-amber-700">{a.file_path}</code></td>
                    <td className="px-4 py-3 text-xs text-gray-500">{a.pattern_matched}</td>
                    <td className="px-4 py-3 text-xs text-gray-600">{a.author_email}</td>
                    <td className="px-4 py-3"><code className="text-xs bg-gray-100 px-1 rounded">{a.sha?.slice(0,8)}</code></td>
                    <td className="px-4 py-3 text-xs text-gray-600">{a.repo_full_name}</td>
                    <td className="px-4 py-3 text-xs text-gray-400">{timeAgo(a.committed_at)}</td>
                    <td className="px-4 py-3">
                      {!a.acknowledged ? (
                        <button onClick={() => handleAck(a.id)} disabled={acking === a.id}
                          className="inline-flex items-center px-2 py-1 text-xs bg-green-50 text-green-700 border border-green-200 rounded hover:bg-green-100">
                          {acking === a.id ? <RefreshCw className="w-3 h-3 animate-spin" /> : <CheckCircle className="w-3 h-3 mr-1" />}
                          Acknowledge
                        </button>
                      ) : <span className="text-xs text-gray-400">Done</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      }
    </div>
  )
}

// ---------------------------------------------------------------------------
// Monitored Repos management tab
// ---------------------------------------------------------------------------
function MonitoredReposTab({ onScanComplete, onRepoAdded }: { onScanComplete: () => void; onRepoAdded: () => void }) {
  const [repos, setRepos] = useState<MonitoredRepo[]>([])
  const [addOwner, setAddOwner] = useState(''); const [addRepo, setAddRepo] = useState('')
  const [adding, setAdding] = useState(false); const [scanning, setScanning] = useState<number | null>(null)
  const [removing, setRemoving] = useState<number | null>(null)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const load = useCallback(async () => {
    const r = await axios.get('/api/github-monitor/repos', { headers: apiHeaders() })
    setRepos(r.data)
  }, [])

  useEffect(() => { load() }, [load])

  const handleAdd = async () => {
    if (!addOwner || !addRepo) return
    setAdding(true); setMessage(null)
    try {
      await axios.post('/api/github-monitor/repos', { owner: addOwner.trim(), repo: addRepo.trim() }, { headers: apiHeaders() })
      setMessage({ type: 'success', text: `Now monitoring ${addOwner}/${addRepo}` })
      setAddOwner(''); setAddRepo(''); await load(); onRepoAdded()
    } catch (e: any) {
      setMessage({ type: 'error', text: e.response?.data?.detail || 'Failed to add repository' })
    } finally { setAdding(false) }
  }

  const handleScan = async (id: number) => {
    setScanning(id)
    try {
      await axios.post(`/api/github-monitor/scan/${id}`, {}, { headers: apiHeaders() })
      setMessage({ type: 'success', text: 'Scan queued.' }); onScanComplete()
    } catch (e: any) {
      setMessage({ type: 'error', text: e.response?.data?.detail || 'Scan failed' })
    } finally { setScanning(null) }
  }

  const handleRemove = async (id: number, name: string) => {
    if (!confirm(`Remove ${name} from monitoring?`)) return
    setRemoving(id)
    await axios.delete(`/api/github-monitor/repos/${id}`, { headers: apiHeaders() })
    await load(); setRemoving(null)
  }

  return (
    <div className="space-y-5">
      <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Add Repository</h3>
        <div className="flex flex-wrap gap-2 items-center">
          <input type="text" value={addOwner} onChange={e => setAddOwner(e.target.value)} placeholder="owner"
            className="px-3 py-2 text-sm border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 w-36" />
          <span className="text-gray-400 font-bold">/</span>
          <input type="text" value={addRepo} onChange={e => setAddRepo(e.target.value)} placeholder="repository"
            className="px-3 py-2 text-sm border border-gray-300 rounded-md focus:ring-2 focus:ring-indigo-500 w-44"
            onKeyDown={e => e.key === 'Enter' && handleAdd()} />
          <button onClick={handleAdd} disabled={adding || !addOwner || !addRepo}
            className="inline-flex items-center px-4 py-2 text-sm bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50">
            {adding ? <RefreshCw className="w-4 h-4 mr-1.5 animate-spin" /> : <Plus className="w-4 h-4 mr-1.5" />} Add
          </button>
        </div>
        {message && <div className={`mt-3 p-2 rounded text-sm ${message.type === 'success' ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'}`}>{message.text}</div>}
      </div>

      {repos.length === 0 ? (
        <div className="text-center py-12 text-gray-400">
          <GitBranch className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>No repositories added. Use the form above.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {repos.map(repo => (
            <div key={repo.id} className="bg-white border border-gray-200 rounded-lg p-4 flex items-center justify-between shadow-sm">
              <div>
                <div className="flex items-center gap-2">
                  <GitBranch className="w-4 h-4 text-gray-400" />
                  <span className="font-semibold text-gray-900">{repo.full_name}</span>
                  <code className="text-xs bg-gray-100 px-1.5 py-0.5 rounded">{repo.default_branch}</code>
                </div>
                {repo.description && <p className="text-xs text-gray-500 mt-1">{repo.description}</p>}
                <div className="flex gap-4 mt-1.5 text-xs text-gray-400">
                  <span>{repo.total_commits_scanned} scanned</span>
                  {repo.last_scanned_at && <span>Last: {timeAgo(repo.last_scanned_at)}</span>}
                </div>
              </div>
              <div className="flex gap-2">
                <button onClick={() => handleScan(repo.id)} disabled={scanning === repo.id}
                  className="inline-flex items-center px-3 py-1.5 text-xs bg-indigo-50 text-indigo-700 border border-indigo-200 rounded hover:bg-indigo-100">
                  {scanning === repo.id ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5 mr-1" />}
                  {scanning === repo.id ? '' : 'Scan Now'}
                </button>
                <button onClick={() => handleRemove(repo.id, repo.full_name)} disabled={removing === repo.id}
                  className="p-1.5 text-red-500 border border-red-200 rounded hover:bg-red-50">
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
// All Findings tab
// ---------------------------------------------------------------------------
function FindingsTab({ repoStats }: { repoStats: RepoStat[] }) {
  const [findings, setFindings] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterRepo, setFilterRepo] = useState('')
  const [filterRule, setFilterRule] = useState('')
  const [filterAuthor, setFilterAuthor] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [showFp, setShowFp] = useState(false)
  const [exporting, setExporting] = useState(false)

  const PAGE_SIZE = 50

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: any = { page, page_size: PAGE_SIZE, show_false_positives: showFp }
      if (filterSeverity) params.severity = filterSeverity
      if (filterRepo) params.repo_id = parseInt(filterRepo)
      if (filterRule) params.rule_name = filterRule
      if (filterAuthor) params.author = filterAuthor
      if (dateFrom) params.date_from = dateFrom
      if (dateTo) params.date_to = dateTo
      const r = await axios.get('/api/github-monitor/findings', { headers: apiHeaders(), params })
      setFindings(r.data.findings); setTotal(r.data.total)
    } finally { setLoading(false) }
  }, [page, filterSeverity, filterRepo, filterRule, filterAuthor, dateFrom, dateTo, showFp])

  useEffect(() => { load() }, [load])

  const handleExportCsv = async () => {
    setExporting(true)
    try {
      const params: any = { show_false_positives: showFp }
      if (filterSeverity) params.severity = filterSeverity
      if (filterRepo) params.repo_id = filterRepo
      if (filterRule) params.rule_name = filterRule
      if (filterAuthor) params.author = filterAuthor
      if (dateFrom) params.date_from = dateFrom
      if (dateTo) params.date_to = dateTo
      const qs = new URLSearchParams(params).toString()
      const token = localStorage.getItem('token')
      const resp = await fetch(`/api/github-monitor/findings/export-csv?${qs}`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      const blob = await resp.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url
      a.download = `findings_export_${new Date().toISOString().slice(0,10)}.csv`
      a.click(); URL.revokeObjectURL(url)
    } finally { setExporting(false) }
  }

  const toggleFindingFp = async (f: any) => {
    const ep = f.false_positive
      ? `/api/github-monitor/findings/${f.id}/unmark-false-positive`
      : `/api/github-monitor/findings/${f.id}/mark-false-positive`
    await axios.post(ep, {}, { headers: apiHeaders() })
    setFindings(prev => prev.map(x => x.id === f.id ? {...x, false_positive: f.false_positive ? 0 : 1} : x))
  }

  return (
    <div>
      {/* Filters */}
      <div className="space-y-2 mb-4">
        <div className="flex flex-wrap gap-2">
          <select value={filterSeverity} onChange={e => { setFilterSeverity(e.target.value); setPage(1) }}
            className="px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500">
            <option value="">All Severities</option>
            {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>)}
          </select>
          <select value={filterRepo} onChange={e => { setFilterRepo(e.target.value); setPage(1) }}
            className="px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500">
            <option value="">All Repos</option>
            {repoStats.map(r => <option key={r.id} value={r.id}>{r.full_name}</option>)}
          </select>
          <input value={filterRule} onChange={e => { setFilterRule(e.target.value); setPage(1) }}
            placeholder="Rule name..." className="px-3 py-1.5 text-sm border border-gray-300 rounded-md w-40 focus:outline-none focus:ring-2 focus:ring-indigo-500" />
          <input value={filterAuthor} onChange={e => { setFilterAuthor(e.target.value); setPage(1) }}
            placeholder="Author..." className="px-3 py-1.5 text-sm border border-gray-300 rounded-md w-36 focus:outline-none focus:ring-2 focus:ring-indigo-500" />
          <button onClick={load} className="inline-flex items-center px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 rounded-md">
            <RefreshCw className="w-3.5 h-3.5 mr-1" /> Refresh
          </button>
          <button onClick={handleExportCsv} disabled={exporting}
            className="inline-flex items-center px-3 py-1.5 text-sm bg-green-50 text-green-700 border border-green-200 hover:bg-green-100 rounded-md">
            {exporting ? <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" /> : <Activity className="w-3.5 h-3.5 mr-1" />}
            Export CSV
          </button>
        </div>
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs text-gray-500 font-medium">Date:</span>
          <input type="date" value={dateFrom} onChange={e => { setDateFrom(e.target.value); setPage(1) }}
            className="px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none" />
          <span className="text-xs text-gray-400">→</span>
          <input type="date" value={dateTo} onChange={e => { setDateTo(e.target.value); setPage(1) }}
            className="px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none" />
          {(dateFrom || dateTo) && (
            <button onClick={() => { setDateFrom(''); setDateTo(''); setPage(1) }} className="text-xs text-gray-400 hover:text-gray-600 underline">Clear</button>
          )}
          <label className="flex items-center gap-1.5 text-xs text-gray-500 ml-2 cursor-pointer">
            <input type="checkbox" checked={showFp} onChange={e => { setShowFp(e.target.checked); setPage(1) }} className="rounded" />
            Show false positives
          </label>
        </div>
      </div>

      <p className="text-sm text-gray-500 mb-3">{total.toLocaleString()} findings total</p>

      {loading ? (
        <div className="text-center py-12 text-gray-400 flex items-center justify-center gap-2">
          <Loader2 className="w-5 h-5 animate-spin" /> Loading findings...
        </div>
      ) : findings.length === 0 ? (
        <div className="text-center py-12 text-gray-400">
          <ShieldAlert className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>No findings match the current filters.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-200">
          <table className="w-full text-xs">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-3 py-2 font-semibold text-gray-600">Severity</th>
                <th className="text-left px-3 py-2 font-semibold text-gray-600">Rule</th>
                <th className="text-left px-3 py-2 font-semibold text-gray-600">File</th>
                <th className="text-left px-3 py-2 font-semibold text-gray-600">CWE / OWASP</th>
                <th className="text-left px-3 py-2 font-semibold text-gray-600">Commit</th>
                <th className="text-left px-3 py-2 font-semibold text-gray-600">Author</th>
                <th className="text-left px-3 py-2 font-semibold text-gray-600">Date</th>
                <th className="text-left px-3 py-2 font-semibold text-gray-600">Repo</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {findings.map(f => (
                <tr key={f.id} className={`hover:bg-gray-50 ${f.false_positive ? 'opacity-50' : ''}`}>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded font-bold ${SEVERITY_PILL[f.severity] ?? 'bg-gray-100 text-gray-600'}`}>{f.severity}</span>
                  </td>
                  <td className="px-3 py-2 max-w-xs">
                    <p className="font-medium text-gray-800 truncate" title={f.rule_name}>{f.rule_name}</p>
                    {f.rule_description && <p className="text-gray-400 truncate text-xs" title={f.rule_description}>{f.rule_description}</p>}
                  </td>
                  <td className="px-3 py-2 font-mono text-gray-600 max-w-xs truncate" title={f.file_path}>
                    {f.file_path || '—'}{f.line_number ? `:${f.line_number}` : ''}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex gap-1 flex-wrap">
                      {f.cwe && <span className="px-1 py-0.5 bg-blue-50 text-blue-700 rounded font-mono text-xs">{f.cwe}</span>}
                      {f.owasp && <span className="px-1 py-0.5 bg-purple-50 text-purple-700 rounded font-mono text-xs">{f.owasp}</span>}
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-1">
                      <code className="bg-gray-100 px-1 py-0.5 rounded text-xs">{f.sha?.slice(0,8)}</code>
                      <RiskBadge level={f.risk_level} />
                    </div>
                  </td>
                  <td className="px-3 py-2 text-gray-600 max-w-xs truncate">{f.author_name || f.author_email}</td>
                  <td className="px-3 py-2 text-gray-500 whitespace-nowrap">{f.committed_at?.slice(0,10)}</td>
                  <td className="px-3 py-2 text-gray-500 max-w-xs truncate">{f.repo_full_name}</td>
                  <td className="px-3 py-2">
                    <button
                      onClick={() => toggleFindingFp(f)}
                      className={`text-xs px-2 py-1 rounded border whitespace-nowrap ${f.false_positive ? 'bg-green-50 text-green-600 border-green-200' : 'bg-white text-gray-400 border-gray-200 hover:bg-gray-50'}`}
                    >
                      {f.false_positive ? '✓ FP' : 'Mark FP'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {total > PAGE_SIZE && (
        <div className="flex justify-center gap-2 mt-4">
          <button disabled={page === 1} onClick={() => setPage(p => p - 1)} className="px-3 py-1.5 text-sm border rounded disabled:opacity-40">Prev</button>
          <span className="px-3 py-1.5 text-sm text-gray-600">Page {page} of {Math.ceil(total / PAGE_SIZE)}</span>
          <button disabled={page >= Math.ceil(total / PAGE_SIZE)} onClick={() => setPage(p => p + 1)} className="px-3 py-1.5 text-sm border rounded disabled:opacity-40">Next</button>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------
export default function GitHubMonitorPage() {
  const [activeTab, setActiveTab] = useState<Tab>('overview')
  const [summary, setSummary] = useState<Summary | null>(null)
  const [repoStats, setRepoStats] = useState<RepoStat[]>([])
  const [repos, setRepos] = useState<MonitoredRepo[]>([])
  const [unackAlerts, setUnackAlerts] = useState(0)
  const [atRiskDevs, setAtRiskDevs] = useState(0)
  const [developers, setDevelopers] = useState<DeveloperProfile[]>([])
  const [scanningRepo, setScanningRepo] = useState<number | null>(null)
  // Cross-tab drill-down state
  const [drillRepoId, setDrillRepoId] = useState<string | undefined>(undefined)
  const [drillAuthor, setDrillAuthor] = useState<string | undefined>(undefined)

  const loadSummary = useCallback(async () => {
    try {
      const r = await axios.get('/api/github-monitor/summary', { headers: apiHeaders() })
      setSummary(r.data); setUnackAlerts(r.data.unacknowledged_alerts)
      setAtRiskDevs(r.data.at_risk_developers)
    } catch (e) { console.error(e) }
  }, [])

  const loadRepoStats = useCallback(async () => {
    try {
      const r = await axios.get('/api/github-monitor/repos/stats', { headers: apiHeaders() })
      setRepoStats(r.data)
    } catch (e) { console.error(e) }
  }, [])

  const loadRepos = useCallback(async () => {
    try {
      const r = await axios.get('/api/github-monitor/repos', { headers: apiHeaders() })
      setRepos(r.data)
    } catch (e) { console.error(e) }
  }, [])

  const loadDevelopers = useCallback(async () => {
    try {
      const r = await axios.get('/api/github-monitor/developers', { headers: apiHeaders() })
      setDevelopers(r.data)
    } catch (e) { console.error(e) }
  }, [])

  const refreshAll = useCallback(async () => {
    await Promise.all([loadSummary(), loadRepoStats(), loadRepos()])
  }, [loadSummary, loadRepoStats, loadRepos])

  useEffect(() => {
    refreshAll()
  }, [refreshAll])

  useEffect(() => {
    if (activeTab === 'developers') loadDevelopers()
  }, [activeTab, loadDevelopers])

  const handleScanNow = async (repoId: number) => {
    setScanningRepo(repoId)
    try {
      await axios.post(`/api/github-monitor/scan/${repoId}`, {}, { headers: apiHeaders() })
      setTimeout(refreshAll, 2000)
    } finally { setScanningRepo(null) }
  }

  const handleViewCommits = (repoId: number) => {
    setDrillRepoId(String(repoId)); setDrillAuthor(undefined)
    setActiveTab('commits')
  }

  const handleDevDrilldown = (email: string) => {
    setDrillAuthor(email); setDrillRepoId(undefined)
    setActiveTab('commits')
  }

  const tabs = [
    { id: 'overview',   label: 'Overview',         icon: LayoutGrid,   badge: (summary?.high_risk_commits ?? 0) > 0 ? summary!.high_risk_commits : undefined },
    { id: 'commits',    label: 'Commit Feed',       icon: GitBranch,    badge: undefined },
    { id: 'timeline',   label: 'Risk Timeline',     icon: CalendarDays, badge: undefined },
    { id: 'developers', label: 'Developers',        icon: Users,        badge: atRiskDevs > 0 ? atRiskDevs : undefined, badgeColor: 'bg-orange-500' },
    { id: 'findings',   label: 'All Findings',      icon: ShieldAlert,  badge: summary?.total_findings ? summary.total_findings : undefined, badgeColor: 'bg-red-500' },
    { id: 'alerts',     label: 'Sensitive Files',   icon: FileWarning,  badge: unackAlerts > 0 ? unackAlerts : undefined, badgeColor: 'bg-red-500' },
    { id: 'repos',      label: 'Repos',             icon: Settings2,    badge: undefined },
  ]

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-indigo-600" />
            GitHub Commit Monitor
          </h1>
          <p className="text-gray-500 text-sm mt-0.5">Insider threat detection across your monitored repositories</p>
        </div>
        <button onClick={refreshAll} className="inline-flex items-center gap-2 px-4 py-2 text-sm border border-gray-200 rounded-lg hover:bg-gray-50 text-gray-600">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Compact stat pills */}
      {summary && (
        <div className="flex flex-wrap gap-3">
          {[
            { label: 'Repos', value: summary.total_monitored_repos, color: 'text-gray-800' },
            { label: 'Commits Scanned', value: summary.total_commits_scanned, color: 'text-gray-800' },
            { label: 'High-Risk Commits', value: summary.high_risk_commits, color: summary.high_risk_commits > 0 ? 'text-red-600 font-bold' : 'text-gray-800' },
            { label: 'Open Alerts', value: summary.unacknowledged_alerts, color: summary.unacknowledged_alerts > 0 ? 'text-amber-600 font-bold' : 'text-gray-800' },
            { label: 'SAST Findings', value: summary.total_findings, color: 'text-gray-800' },
            { label: 'At-Risk Devs', value: summary.at_risk_developers, color: summary.at_risk_developers > 0 ? 'text-orange-600 font-bold' : 'text-gray-800' },
          ].map(pill => (
            <div key={pill.label} className="flex items-center gap-2 bg-white border border-gray-200 rounded-full px-4 py-1.5 shadow-sm text-sm">
              <span className={pill.color}>{pill.value}</span>
              <span className="text-gray-400">{pill.label}</span>
            </div>
          ))}
        </div>
      )}

      {/* High-risk alert strip */}
      {summary && summary.recent_high_risk_commits?.length > 0 && (
        <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-red-600" />
            <span className="text-sm font-semibold text-red-800">Recent High-Risk Commits</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {summary.recent_high_risk_commits.map(c => (
              <div key={c.id} className="flex items-center gap-2 bg-white border border-red-200 rounded-lg px-3 py-1.5 text-xs shadow-sm">
                <code className="font-mono">{c.sha?.slice(0,8)}</code>
                <span className="text-gray-500">{c.repo_full_name}</span>
                <RiskBadge level={c.risk_level} />
                <span className="text-gray-400">{timeAgo(c.committed_at)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Main content area */}
      <div className="bg-white shadow rounded-xl">
        {/* Tabs */}
        <div className="border-b border-gray-200">
          <nav className="flex overflow-x-auto -mb-px">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as Tab)}
                className={`flex items-center gap-2 px-4 py-3.5 text-sm font-medium border-b-2 whitespace-nowrap transition ${
                  activeTab === tab.id
                    ? 'border-indigo-500 text-indigo-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
                {tab.badge !== undefined && (
                  <span className={`inline-flex items-center justify-center min-w-[20px] h-5 px-1 text-xs font-bold text-white rounded-full ${(tab as any).badgeColor || 'bg-red-500'}`}>
                    {tab.badge}
                  </span>
                )}
              </button>
            ))}
          </nav>
        </div>

        <div className="p-6">
          {/* Overview tab */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {repoStats.length === 0 ? (
                <div className="text-center py-16 text-gray-400">
                  <Zap className="w-12 h-12 mx-auto mb-3 opacity-30" />
                  <p className="font-medium">No repositories configured</p>
                  <p className="text-sm mt-1">Go to the Repos tab to add repositories to monitor.</p>
                  <button onClick={() => setActiveTab('repos')} className="mt-4 px-4 py-2 text-sm bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
                    Add a Repository
                  </button>
                </div>
              ) : (
                <>
                  <OrgRiskMap repoStats={repoStats} />
                  <div>
                    <h3 className="text-sm font-semibold text-gray-700 mb-3">Repository Risk Cards</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                      {repoStats.map(stat => (
                        <RepoRiskCard
                          key={stat.id}
                          stats={stat}
                          scanning={scanningRepo === stat.id}
                          onScanNow={handleScanNow}
                          onViewCommits={handleViewCommits}
                        />
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>
          )}

          {/* Commit Feed tab */}
          {activeTab === 'commits' && (
            <CommitFeedTab
              key={`${drillRepoId}-${drillAuthor}`}
              initialRepoFilter={drillRepoId}
              initialAuthor={drillAuthor}
              repoStats={repoStats}
            />
          )}

          {/* Timeline tab */}
          {activeTab === 'timeline' && <RiskTimelineHeatmap repos={repos} />}

          {/* Developers tab */}
          {activeTab === 'developers' && (
            <div>
              {developers.length === 0 ? (
                <div className="text-center py-16 text-gray-400">
                  <Users className="w-12 h-12 mx-auto mb-3 opacity-30" />
                  <p>No developer profiles yet. Scan some repositories first.</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {developers.map(dev => (
                    <DeveloperCard key={dev.id} dev={dev} onDrillDown={handleDevDrilldown} />
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'findings' && <FindingsTab repoStats={repoStats} />}
          {activeTab === 'alerts' && <SensitiveFileAlertsTab onAckChange={loadSummary} />}
          {activeTab === 'repos' && <MonitoredReposTab onScanComplete={refreshAll} onRepoAdded={refreshAll} />}
        </div>
      </div>
    </div>
  )
}
