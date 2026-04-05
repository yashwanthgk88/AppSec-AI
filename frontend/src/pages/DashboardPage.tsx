import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Shield, AlertTriangle, FileText, TrendingUp, TrendingDown, Filter, Calendar, Activity, Clock, CheckCircle, ChevronLeft, ChevronRight, Zap, Target, ExternalLink, Users, Lock, Bug, Globe } from 'lucide-react'
import axios from 'axios'
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, AreaChart, Area,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell
} from 'recharts'

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
}

export default function DashboardPage() {
  const [analytics, setAnalytics] = useState<any>(null)
  const [threatIntel, setThreatIntel] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [selectedProject, setSelectedProject] = useState<number | null>(null)
  const [timeRange, setTimeRange] = useState(30)
  const [projectsPage, setProjectsPage] = useState(1)
  const projectsPerPage = 10

  useEffect(() => {
    fetchAnalytics()
    fetchThreatIntel()
  }, [selectedProject, timeRange])

  const fetchThreatIntel = async () => {
    try {
      const token = localStorage.getItem('token')
      const [statsRes, correlationsRes] = await Promise.allSettled([
        axios.get('/api/threat-intel/stats', {
          headers: { Authorization: `Bearer ${token}` }
        }),
        axios.get('/api/threat-intel/correlate', {
          headers: { Authorization: `Bearer ${token}` }
        })
      ])

      const stats = statsRes.status === 'fulfilled' ? statsRes.value.data : null
      const correlations = correlationsRes.status === 'fulfilled' ? correlationsRes.value.data.correlations : []

      setThreatIntel({ stats, correlations })
    } catch (error) {
      console.error('Failed to fetch threat intel:', error)
    }
  }

  const fetchAnalytics = async () => {
    try {
      setLoading(true)
      const token = localStorage.getItem('token')
      const params = new URLSearchParams()
      if (selectedProject) params.append('project_id', selectedProject.toString())
      params.append('days', timeRange.toString())

      const response = await axios.get(`/api/dashboard/analytics?${params}`, {
        headers: { Authorization: `Bearer ${token}` }
      })

      setAnalytics(response.data)
    } catch (error) {
      console.error('Failed to fetch analytics:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading dashboard analytics...</p>
        </div>
      </div>
    )
  }

  if (!analytics) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <AlertTriangle className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-600">Failed to load dashboard data</p>
          <button onClick={fetchAnalytics} className="btn btn-primary mt-4">
            Retry
          </button>
        </div>
      </div>
    )
  }

  const { summary, trends, distributions, top_types, projects } = analytics

  return (
    <div className="space-y-6">
      {/* Header with Filters */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="text-gray-600 mt-1">Comprehensive security metrics and analytics</p>
        </div>

        {/* Filters */}
        <div className="flex items-center space-x-3">
          {/* Project Filter */}
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <select
              value={selectedProject || ''}
              onChange={(e) => setSelectedProject(e.target.value ? Number(e.target.value) : null)}
              className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 bg-white"
            >
              <option value="">All Projects</option>
              {projects.map((project: any) => (
                <option key={project.id} value={project.id}>
                  {project.name}
                </option>
              ))}
            </select>
          </div>

          {/* Time Range Filter */}
          <div className="relative">
            <Calendar className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(Number(e.target.value))}
              className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 bg-white"
            >
              <option value={7}>Last 7 days</option>
              <option value={30}>Last 30 days</option>
              <option value={90}>Last 90 days</option>
            </select>
          </div>
        </div>
      </div>

      {/* Key Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard
          title="Total Vulnerabilities"
          value={summary.total_vulnerabilities}
          icon={<AlertTriangle className="w-8 h-8" />}
          color="red"
          subtitle={`${summary.critical} Critical • ${summary.high} High`}
        />
        <MetricCard
          title="False Positive Rate"
          value={`${summary.false_positive_rate}%`}
          icon={<CheckCircle className="w-8 h-8" />}
          color="yellow"
          subtitle="Lower is better"
        />
        <MetricCard
          title="Remediation Velocity"
          value={summary.remediation_velocity.toFixed(1)}
          icon={<TrendingUp className="w-8 h-8" />}
          color="green"
          subtitle="Fixes per day"
        />
        <MetricCard
          title="Avg. Time to Fix"
          value={`${summary.avg_time_to_fix} days`}
          icon={<Clock className="w-8 h-8" />}
          color="blue"
          subtitle={`${summary.total_scans} scans completed`}
        />
      </div>

      {/* Threat Intelligence Overview */}
      {threatIntel?.stats && (
        <div className="card p-6 bg-gradient-to-r from-red-50 via-orange-50 to-yellow-50 border-l-4 border-red-500">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-3">
              <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
                <Shield className="w-7 h-7 text-red-600" />
              </div>
              <div>
                <h2 className="text-xl font-semibold text-gray-900">Live Threat Intelligence</h2>
                <p className="text-sm text-gray-600">Real-time threat data from CISA KEV, NVD, and Exploit-DB</p>
              </div>
            </div>
            <Link
              to="/threat-intel"
              className="btn btn-primary inline-flex items-center space-x-2"
            >
              <TrendingUp className="w-4 h-4" />
              <span>View All Threats</span>
            </Link>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            <div className="bg-white rounded-lg p-4 border border-red-200 shadow-sm">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-600">Actively Exploited</p>
                  <p className="text-2xl font-bold text-red-600">{threatIntel.stats.actively_exploited || 0}</p>
                </div>
                <Zap className="w-6 h-6 text-red-500" />
              </div>
            </div>

            <div className="bg-white rounded-lg p-4 border border-orange-200 shadow-sm">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-600">Critical CVEs</p>
                  <p className="text-2xl font-bold text-orange-600">{threatIntel.stats.critical_threats || threatIntel.stats.by_severity?.critical || 0}</p>
                </div>
                <AlertTriangle className="w-6 h-6 text-orange-500" />
              </div>
            </div>

            <div className="bg-white rounded-lg p-4 border border-purple-200 shadow-sm">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-600">Threat Actors</p>
                  <p className="text-2xl font-bold text-purple-600">{threatIntel.stats.threat_actors || 0}</p>
                </div>
                <Users className="w-6 h-6 text-purple-500" />
              </div>
            </div>

            <div className="bg-white rounded-lg p-4 border border-pink-200 shadow-sm">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-600">Ransomware</p>
                  <p className="text-2xl font-bold text-pink-600">{threatIntel.stats.ransomware_families || 0}</p>
                </div>
                <Lock className="w-6 h-6 text-pink-500" />
              </div>
            </div>

            <div className="bg-white rounded-lg p-4 border border-indigo-200 shadow-sm">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-600">Exploit Kits</p>
                  <p className="text-2xl font-bold text-indigo-600">{threatIntel.stats.exploit_kits || 0}</p>
                </div>
                <Bug className="w-6 h-6 text-indigo-500" />
              </div>
            </div>

            <div className="bg-white rounded-lg p-4 border border-blue-200 shadow-sm">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-600">Total Threats</p>
                  <p className="text-2xl font-bold text-blue-600">{threatIntel.stats.total_threats || 0}</p>
                </div>
                <Globe className="w-6 h-6 text-blue-500" />
              </div>
            </div>
          </div>

          {/* Correlated Threats Alert */}
          {threatIntel.correlations && threatIntel.correlations.length > 0 && (
            <div className="mt-4 p-4 bg-red-100 border-2 border-red-300 rounded-lg animate-pulse">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <Zap className="w-6 h-6 text-red-600" />
                  <div>
                    <h3 className="font-semibold text-red-900">
                      {threatIntel.correlations.filter((c: any) => c.risk_elevation).length} High-Risk Correlations Found
                    </h3>
                    <p className="text-sm text-red-700">
                      Your vulnerabilities match {threatIntel.correlations.length} active threats being exploited in the wild
                    </p>
                  </div>
                </div>
                <Link
                  to="/threat-intel"
                  className="btn bg-red-600 hover:bg-red-700 text-white inline-flex items-center space-x-2"
                >
                  <Target className="w-4 h-4" />
                  <span>View Details</span>
                </Link>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Vulnerability Trend Over Time */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Vulnerability Trend</h2>
            <p className="text-sm text-gray-600 mt-1">Track vulnerability discovery over time</p>
          </div>
        </div>
        <ResponsiveContainer width="100%" height={350}>
          <AreaChart data={trends.vulnerability_trend}>
            <defs>
              <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0.1}/>
              </linearGradient>
              <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f97316" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#f97316" stopOpacity={0.1}/>
              </linearGradient>
              <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#eab308" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#eab308" stopOpacity={0.1}/>
              </linearGradient>
              <linearGradient id="colorLow" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.1}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
            <XAxis
              dataKey="date"
              tick={{ fontSize: 12 }}
              tickFormatter={(value) => {
                const date = new Date(value)
                return `${date.getMonth() + 1}/${date.getDate()}`
              }}
            />
            <YAxis tick={{ fontSize: 12 }} />
            <Tooltip
              contentStyle={{ backgroundColor: '#fff', border: '1px solid #e5e7eb', borderRadius: '8px' }}
              labelStyle={{ fontWeight: 'bold' }}
            />
            <Legend wrapperStyle={{ fontSize: '14px' }} />
            <Area
              type="monotone"
              dataKey="critical"
              stackId="1"
              stroke="#ef4444"
              fillOpacity={1}
              fill="url(#colorCritical)"
              name="Critical"
            />
            <Area
              type="monotone"
              dataKey="high"
              stackId="1"
              stroke="#f97316"
              fillOpacity={1}
              fill="url(#colorHigh)"
              name="High"
            />
            <Area
              type="monotone"
              dataKey="medium"
              stackId="1"
              stroke="#eab308"
              fillOpacity={1}
              fill="url(#colorMedium)"
              name="Medium"
            />
            <Area
              type="monotone"
              dataKey="low"
              stackId="1"
              stroke="#3b82f6"
              fillOpacity={1}
              fill="url(#colorLow)"
              name="Low"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Distributions Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="card p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-6">Severity Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={distributions.severity}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {distributions.severity.map((entry: any, index: number) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          <div className="grid grid-cols-2 gap-3 mt-6">
            {distributions.severity.map((item: any) => (
              <div key={item.name} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-2">
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-sm font-medium text-gray-700">{item.name}</span>
                </div>
                <span className="text-lg font-bold text-gray-900">{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Status Distribution */}
        <div className="card p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-6">Status Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={distributions.status} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" />
              <YAxis dataKey="name" type="category" width={80} />
              <Tooltip />
              <Bar dataKey="value" fill="#6366f1" radius={[0, 8, 8, 0]}>
                {distributions.status.map((entry: any, index: number) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={
                      entry.name === 'Fixed' ? '#10b981' :
                      entry.name === 'Open' ? '#ef4444' :
                      entry.name === 'In_progress' ? '#f59e0b' : '#6b7280'
                    }
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Vulnerabilities by Category */}
      <div className="card p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-6">Top Vulnerability Categories</h2>
        <ResponsiveContainer width="100%" height={350}>
          <BarChart data={distributions.by_category}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
            <XAxis
              dataKey="name"
              angle={-45}
              textAnchor="end"
              height={100}
              tick={{ fontSize: 11 }}
            />
            <YAxis tick={{ fontSize: 12 }} />
            <Tooltip
              contentStyle={{ backgroundColor: '#fff', border: '1px solid #e5e7eb', borderRadius: '8px' }}
            />
            <Bar dataKey="value" fill="#8b5cf6" radius={[8, 8, 0, 0]}>
              {distributions.by_category.map((entry: any, index: number) => (
                <Cell key={`cell-${index}`} fill={`hsl(${270 - index * 20}, 70%, 50%)`} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Project-wise Breakdown */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-gray-900">Vulnerabilities by Project</h2>
          <p className="text-sm text-gray-600">
            Showing {Math.min((projectsPage - 1) * projectsPerPage + 1, distributions.by_project.length)} - {Math.min(projectsPage * projectsPerPage, distributions.by_project.length)} of {distributions.by_project.length} projects
          </p>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">
                  Project
                </th>
                <th className="px-4 py-3 text-center text-xs font-semibold text-gray-600 uppercase tracking-wider">
                  Total
                </th>
                <th className="px-4 py-3 text-center text-xs font-semibold text-gray-600 uppercase tracking-wider">
                  Critical
                </th>
                <th className="px-4 py-3 text-center text-xs font-semibold text-gray-600 uppercase tracking-wider">
                  High
                </th>
                <th className="px-4 py-3 text-center text-xs font-semibold text-gray-600 uppercase tracking-wider">
                  Medium
                </th>
                <th className="px-4 py-3 text-center text-xs font-semibold text-gray-600 uppercase tracking-wider">
                  Low
                </th>
                <th className="px-4 py-3 text-center text-xs font-semibold text-gray-600 uppercase tracking-wider">
                  Chart
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {distributions.by_project
                .slice((projectsPage - 1) * projectsPerPage, projectsPage * projectsPerPage)
                .map((project: any) => (
                <tr key={project.project_id} className="hover:bg-gray-50">
                  <td className="px-4 py-4">
                    <Link
                      to={`/projects/${project.project_id}`}
                      className="font-medium text-gray-900 hover:text-primary-600"
                    >
                      {project.project_name}
                    </Link>
                  </td>
                  <td className="px-4 py-4 text-center">
                    <span className="text-lg font-bold text-gray-900">{project.total}</span>
                  </td>
                  <td className="px-4 py-4 text-center">
                    <span className="badge badge-critical">{project.critical}</span>
                  </td>
                  <td className="px-4 py-4 text-center">
                    <span className="badge badge-high">{project.high}</span>
                  </td>
                  <td className="px-4 py-4 text-center">
                    <span className="badge badge-medium">{project.medium}</span>
                  </td>
                  <td className="px-4 py-4 text-center">
                    <span className="badge badge-low">{project.low}</span>
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex space-x-1">
                      {project.critical > 0 && (
                        <div
                          className="h-6 bg-red-500 rounded"
                          style={{ width: `${(project.critical / project.total) * 100}%`, minWidth: '4px' }}
                          title={`${project.critical} Critical`}
                        />
                      )}
                      {project.high > 0 && (
                        <div
                          className="h-6 bg-orange-500 rounded"
                          style={{ width: `${(project.high / project.total) * 100}%`, minWidth: '4px' }}
                          title={`${project.high} High`}
                        />
                      )}
                      {project.medium > 0 && (
                        <div
                          className="h-6 bg-yellow-500 rounded"
                          style={{ width: `${(project.medium / project.total) * 100}%`, minWidth: '4px' }}
                          title={`${project.medium} Medium`}
                        />
                      )}
                      {project.low > 0 && (
                        <div
                          className="h-6 bg-blue-500 rounded"
                          style={{ width: `${(project.low / project.total) * 100}%`, minWidth: '4px' }}
                          title={`${project.low} Low`}
                        />
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        {distributions.by_project.length > projectsPerPage && (
          <div className="flex items-center justify-between mt-6 pt-4 border-t border-gray-200">
            <div className="text-sm text-gray-600">
              Page {projectsPage} of {Math.ceil(distributions.by_project.length / projectsPerPage)}
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setProjectsPage(Math.max(1, projectsPage - 1))}
                disabled={projectsPage === 1}
                className="px-3 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-1"
              >
                <ChevronLeft className="w-4 h-4" />
                <span>Previous</span>
              </button>

              <div className="flex items-center space-x-1">
                {Array.from({ length: Math.ceil(distributions.by_project.length / projectsPerPage) }, (_, i) => i + 1)
                  .filter(page => {
                    // Show first page, last page, current page, and pages around current
                    return page === 1 ||
                           page === Math.ceil(distributions.by_project.length / projectsPerPage) ||
                           Math.abs(page - projectsPage) <= 1
                  })
                  .map((page, index, array) => (
                    <div key={page} className="flex items-center">
                      {index > 0 && array[index - 1] !== page - 1 && (
                        <span className="px-2 text-gray-400">...</span>
                      )}
                      <button
                        onClick={() => setProjectsPage(page)}
                        className={`px-3 py-2 rounded-lg text-sm font-medium ${
                          projectsPage === page
                            ? 'bg-primary-600 text-white'
                            : 'text-gray-700 hover:bg-gray-100'
                        }`}
                      >
                        {page}
                      </button>
                    </div>
                  ))}
              </div>

              <button
                onClick={() => setProjectsPage(Math.min(Math.ceil(distributions.by_project.length / projectsPerPage), projectsPage + 1))}
                disabled={projectsPage === Math.ceil(distributions.by_project.length / projectsPerPage)}
                className="px-3 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-1"
              >
                <span>Next</span>
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Scan Activity Trend */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Scan Activity</h2>
            <p className="text-sm text-gray-600 mt-1">Number of security scans over time</p>
          </div>
        </div>
        <ResponsiveContainer width="100%" height={250}>
          <LineChart data={trends.scan_activity}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
            <XAxis
              dataKey="date"
              tick={{ fontSize: 12 }}
              tickFormatter={(value) => {
                const date = new Date(value)
                return `${date.getMonth() + 1}/${date.getDate()}`
              }}
            />
            <YAxis tick={{ fontSize: 12 }} />
            <Tooltip
              contentStyle={{ backgroundColor: '#fff', border: '1px solid #e5e7eb', borderRadius: '8px' }}
            />
            <Line
              type="monotone"
              dataKey="scans"
              stroke="#6366f1"
              strokeWidth={3}
              dot={{ fill: '#6366f1', r: 4 }}
              activeDot={{ r: 6 }}
              name="Scans"
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Top Vulnerability Types */}
      <div className="card p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-6">Top 5 Vulnerability Types</h2>
        <div className="space-y-4">
          {top_types.map((item: any, index: number) => (
            <div key={index} className="flex items-center">
              <div className="w-8 h-8 rounded-full bg-primary-100 text-primary-700 flex items-center justify-center font-bold text-sm mr-4">
                {index + 1}
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-medium text-gray-900">{item.type}</span>
                  <span className="text-sm font-bold text-gray-700">{item.count}</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-gradient-to-r from-primary-500 to-primary-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${(item.count / top_types[0].count) * 100}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function MetricCard({ title, value, icon, color, subtitle }: any) {
  const colorClasses = {
    red: 'bg-red-100 text-red-600',
    yellow: 'bg-yellow-100 text-yellow-600',
    green: 'bg-green-100 text-green-600',
    blue: 'bg-blue-100 text-blue-600',
  }

  return (
    <div className="card p-6">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-600 mb-2">{title}</p>
          <p className="text-3xl font-bold text-gray-900 mb-1">{value}</p>
          {subtitle && (
            <p className="text-xs text-gray-500">{subtitle}</p>
          )}
        </div>
        <div className={`p-3 rounded-lg ${colorClasses[color as keyof typeof colorClasses]}`}>
          {icon}
        </div>
      </div>
    </div>
  )
}
