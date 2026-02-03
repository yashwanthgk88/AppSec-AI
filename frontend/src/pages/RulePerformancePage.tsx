import { useState, useEffect } from 'react'
import axios from 'axios'
import { TrendingUp, AlertTriangle, CheckCircle, Activity, BarChart3, Clock, Zap } from 'lucide-react'
import { Link } from 'react-router-dom'

interface OverallStats {
  total_rules: number
  enabled_rules: number
  total_detections: number
  total_true_positives: number
  total_false_positives: number
  avg_precision: number
  rules_needing_refinement: number
  ai_generated_rules: number
  user_created_rules: number
}

interface SeverityBreakdown {
  severity: string
  count: number
  detections: number
}

interface RuleStats {
  id: number
  name: string
  severity: string
  total_detections: number
  precision: number
  false_positives?: number
  generated_by: string
}

interface EnhancementActivity {
  id: number
  job_type: string
  status: string
  started_at: string
  completed_at: string
  rules_generated: number
  rules_refined: number
  rules_affected: number
}

interface DetectionTrend {
  date: string
  count: number
}

interface DashboardData {
  overall_stats: OverallStats
  severity_breakdown: SeverityBreakdown[]
  top_performers: RuleStats[]
  needs_attention: RuleStats[]
  recent_enhancements: EnhancementActivity[]
  detection_trend: DetectionTrend[]
  overall_precision: number
  total_rules: number
  enabled_rules: number
}

export default function RulePerformancePage() {
  const [dashboard, setDashboard] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadDashboard()
    // Refresh dashboard every 30 seconds
    const interval = setInterval(loadDashboard, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadDashboard = async () => {
    try {
      const token = localStorage.getItem('token')
      const response = await axios.get('/api/rules/performance/dashboard', {
        headers: { Authorization: `Bearer ${token}` }
      })
      setDashboard(response.data)
      setLoading(false)
    } catch (error) {
      console.error('Failed to load dashboard:', error)
      setLoading(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-700 bg-red-100'
      case 'high': return 'text-orange-700 bg-orange-100'
      case 'medium': return 'text-yellow-700 bg-yellow-100'
      case 'low': return 'text-green-700 bg-green-100'
      default: return 'text-gray-700 bg-gray-100'
    }
  }

  const getPrecisionColor = (precision: number | null) => {
    if (precision === null) return 'text-gray-500'
    if (precision >= 0.95) return 'text-green-600'
    if (precision >= 0.85) return 'text-yellow-600'
    return 'text-red-600'
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (!dashboard) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 text-yellow-500 mx-auto mb-4" />
        <p className="text-gray-600">Failed to load dashboard data</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Rule Performance Dashboard</h1>
          <p className="text-gray-600 mt-1">Monitor and analyze custom rule effectiveness</p>
        </div>
        <Link
          to="/custom-rules"
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition"
        >
          Manage Rules
        </Link>
      </div>

      {/* Overall Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Total Rules</p>
              <p className="text-3xl font-bold text-gray-900 mt-1">{dashboard.overall_stats.total_rules}</p>
              <p className="text-xs text-gray-500 mt-1">
                {dashboard.overall_stats.enabled_rules} enabled
              </p>
            </div>
            <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
              <BarChart3 className="w-6 h-6 text-blue-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Total Detections</p>
              <p className="text-3xl font-bold text-gray-900 mt-1">
                {dashboard.overall_stats.total_detections}
              </p>
              <p className="text-xs text-gray-500 mt-1">
                {dashboard.overall_stats.total_true_positives} true positives
              </p>
            </div>
            <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
              <Activity className="w-6 h-6 text-green-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Average Precision</p>
              <p className={`text-3xl font-bold mt-1 ${getPrecisionColor(dashboard.overall_stats.avg_precision)}`}>
                {dashboard.overall_stats.avg_precision
                  ? `${(dashboard.overall_stats.avg_precision * 100).toFixed(1)}%`
                  : 'N/A'}
              </p>
              <p className="text-xs text-gray-500 mt-1">
                {dashboard.overall_stats.total_false_positives} false positives
              </p>
            </div>
            <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center">
              <TrendingUp className="w-6 h-6 text-purple-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Needs Refinement</p>
              <p className="text-3xl font-bold text-orange-600 mt-1">
                {dashboard.overall_stats.rules_needing_refinement}
              </p>
              <p className="text-xs text-gray-500 mt-1">
                Precision &lt; 85%
              </p>
            </div>
            <div className="w-12 h-12 bg-orange-100 rounded-lg flex items-center justify-center">
              <AlertTriangle className="w-6 h-6 text-orange-600" />
            </div>
          </div>
        </div>
      </div>

      {/* Severity Breakdown & AI Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Breakdown */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Rules by Severity</h2>
          <div className="space-y-3">
            {dashboard.severity_breakdown.map((item) => (
              <div key={item.severity} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(item.severity)}`}>
                    {item.severity}
                  </span>
                  <span className="text-gray-600 text-sm">{item.count} rules</span>
                </div>
                <span className="text-gray-900 font-semibold">{item.detections} detections</span>
              </div>
            ))}
          </div>
        </div>

        {/* AI vs User Rules */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Rule Creation Sources</h2>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 bg-purple-50 rounded-lg">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-purple-600 rounded-lg flex items-center justify-center">
                  <Zap className="w-5 h-5 text-white" />
                </div>
                <div>
                  <p className="text-sm text-gray-600">AI Generated</p>
                  <p className="text-2xl font-bold text-gray-900">{dashboard.overall_stats.ai_generated_rules}</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-sm text-gray-600">
                  {dashboard.overall_stats.total_rules > 0
                    ? ((dashboard.overall_stats.ai_generated_rules / dashboard.overall_stats.total_rules) * 100).toFixed(0)
                    : 0}%
                </p>
              </div>
            </div>

            <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
                  <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm text-gray-600">User Created</p>
                  <p className="text-2xl font-bold text-gray-900">{dashboard.overall_stats.user_created_rules}</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-sm text-gray-600">
                  {dashboard.overall_stats.total_rules > 0
                    ? ((dashboard.overall_stats.user_created_rules / dashboard.overall_stats.total_rules) * 100).toFixed(0)
                    : 0}%
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Detection Trend */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center space-x-2">
          <Clock className="w-5 h-5" />
          <span>Detection Trend (Last 30 Days)</span>
        </h2>
        {dashboard.detection_trend.length > 0 ? (
          <div className="overflow-x-auto">
            <div className="flex items-end gap-1" style={{ height: '200px', minWidth: '600px' }}>
              {dashboard.detection_trend.slice(0, 30).reverse().map((item, index) => {
                const maxCount = Math.max(...dashboard.detection_trend.map(d => d.count), 1)
                const heightPx = Math.max((item.count / maxCount) * 160, 8)
                return (
                  <div key={index} className="flex-1 flex flex-col items-center justify-end group" style={{ minWidth: '16px' }}>
                    <div className="text-xs text-gray-500 mb-1 opacity-0 group-hover:opacity-100 transition">
                      {item.count}
                    </div>
                    <div
                      className="w-full rounded-t transition cursor-pointer"
                      style={{
                        height: `${heightPx}px`,
                        backgroundColor: '#2563eb'
                      }}
                      title={`${item.date}: ${item.count} detections`}
                      onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#1d4ed8'}
                      onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#2563eb'}
                    ></div>
                    <div className="text-xs text-gray-400 mt-1">
                      {new Date(item.date).getDate()}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        ) : (
          <p className="text-gray-500 text-center py-8">No detection data available</p>
        )}
      </div>

      {/* Top Performers & Needs Attention */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Performing Rules */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center space-x-2">
              <CheckCircle className="w-5 h-5 text-green-600" />
              <span>Top Performing Rules</span>
            </h2>
          </div>
          <div className="space-y-3">
            {dashboard.top_performers.length > 0 ? (
              dashboard.top_performers.map((rule) => (
                <div key={rule.id} className="p-3 border border-gray-200 rounded-lg hover:bg-gray-50">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <Link
                          to="/custom-rules"
                          className="text-sm font-medium text-gray-900 hover:text-primary-600"
                        >
                          {rule.name}
                        </Link>
                        <span className="text-xs">{rule.generated_by === 'ai' ? '🤖' : '👤'}</span>
                      </div>
                      <div className="flex items-center space-x-2 mt-1">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityColor(rule.severity)}`}>
                          {rule.severity}
                        </span>
                        <span className="text-xs text-gray-500">{rule.total_detections} detections</span>
                      </div>
                    </div>
                    <div className={`text-lg font-bold ${getPrecisionColor(rule.precision)}`}>
                      {rule.precision ? `${(rule.precision * 100).toFixed(0)}%` : 'N/A'}
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-gray-500 text-center py-4">No data available</p>
            )}
          </div>
        </div>

        {/* Rules Needing Attention */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center space-x-2">
              <AlertTriangle className="w-5 h-5 text-orange-600" />
              <span>Rules Needing Attention</span>
            </h2>
          </div>
          <div className="space-y-3">
            {dashboard.needs_attention.length > 0 ? (
              dashboard.needs_attention.map((rule) => (
                <div key={rule.id} className="p-3 border border-orange-200 bg-orange-50 rounded-lg">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <Link
                          to="/custom-rules"
                          className="text-sm font-medium text-gray-900 hover:text-primary-600"
                        >
                          {rule.name}
                        </Link>
                      </div>
                      <div className="flex items-center space-x-2 mt-1">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityColor(rule.severity)}`}>
                          {rule.severity}
                        </span>
                        <span className="text-xs text-red-600">{rule.false_positives} FPs</span>
                        <span className="text-xs text-gray-500">{rule.total_detections} total</span>
                      </div>
                    </div>
                    <div className={`text-lg font-bold ${getPrecisionColor(rule.precision)}`}>
                      {rule.precision ? `${(rule.precision * 100).toFixed(0)}%` : 'N/A'}
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-green-600 text-center py-4 flex items-center justify-center space-x-2">
                <CheckCircle className="w-5 h-5" />
                <span>All rules performing well!</span>
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Recent Enhancement Activity */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Recent Enhancement Activity</h2>
        {dashboard.recent_enhancements.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200">
                  <th className="text-left py-3 px-4 text-sm font-semibold text-gray-700">Job Type</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-gray-700">Status</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-gray-700">Started</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-gray-700">Completed</th>
                  <th className="text-right py-3 px-4 text-sm font-semibold text-gray-700">Results</th>
                </tr>
              </thead>
              <tbody>
                {dashboard.recent_enhancements.map((job) => (
                  <tr key={job.id} className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-3 px-4">
                      <span className="text-sm font-medium text-gray-900">
                        {job.job_type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                        job.status === 'completed' ? 'bg-green-100 text-green-700' :
                        job.status === 'failed' ? 'bg-red-100 text-red-700' :
                        'bg-yellow-100 text-yellow-700'
                      }`}>
                        {job.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-sm text-gray-600">
                      {formatDate(job.started_at)}
                    </td>
                    <td className="py-3 px-4 text-sm text-gray-600">
                      {job.completed_at ? formatDate(job.completed_at) : '-'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="text-sm">
                        {job.rules_generated > 0 && (
                          <span className="text-green-600 font-medium">{job.rules_generated} generated</span>
                        )}
                        {job.rules_refined > 0 && (
                          <span className="text-blue-600 font-medium">{job.rules_refined} refined</span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-gray-500 text-center py-8">No enhancement activity yet</p>
        )}
      </div>
    </div>
  )
}
