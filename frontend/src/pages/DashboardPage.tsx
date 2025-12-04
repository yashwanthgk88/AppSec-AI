import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Shield, AlertTriangle, Package, Key, FileText, TrendingUp } from 'lucide-react'
import axios from 'axios'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, Line, Area, AreaChart } from 'recharts'

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#ef4444',
  medium: '#f97316',
  low: '#fbbf24',
  info: '#60a5fa',
}

export default function DashboardPage() {
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null)
  const [selectedScanType, setSelectedScanType] = useState<string | null>(null)
  const [drillDownView, setDrillDownView] = useState<'none' | 'severity' | 'scanType'>('none')

  useEffect(() => {
    fetchDashboardStats()
  }, [])

  const handlePieClick = (data: any) => {
    setSelectedSeverity(data.name)
    setDrillDownView('severity')
  }

  const handleBarClick = (data: any) => {
    setSelectedScanType(data.name)
    setDrillDownView('scanType')
  }

  const closeDrillDown = () => {
    setDrillDownView('none')
    setSelectedSeverity(null)
    setSelectedScanType(null)
  }

  const fetchDashboardStats = async () => {
    try {
      const token = localStorage.getItem('token')

      // Fetch projects
      const projectsRes = await axios.get('/api/projects', {
        headers: { Authorization: `Bearer ${token}` }
      })

      // Mock stats for POC demo
      const mockStats = {
        totalProjects: projectsRes.data.length || 0,
        totalVulnerabilities: 42,
        criticalIssues: 8,
        highIssues: 15,
        mediumIssues: 12,
        lowIssues: 7,
        totalScans: 15,
        averageRiskScore: 7.3,
        recentProjects: projectsRes.data.slice(0, 5),
        severityBreakdown: [
          { name: 'Critical', value: 8, color: SEVERITY_COLORS.critical },
          { name: 'High', value: 15, color: SEVERITY_COLORS.high },
          { name: 'Medium', value: 12, color: SEVERITY_COLORS.medium },
          { name: 'Low', value: 7, color: SEVERITY_COLORS.low },
        ],
        scanTypeData: [
          { name: 'SAST', critical: 5, high: 8, medium: 6, low: 3 },
          { name: 'SCA', critical: 3, high: 5, medium: 4, low: 2 },
          { name: 'Secrets', critical: 5, high: 2, medium: 2, low: 2 },
        ],
        vulnerabilityDetails: {
          Critical: [
            { id: 1, title: 'SQL Injection in login endpoint', project: 'E-commerce API', cwe: 'CWE-89' },
            { id: 2, title: 'Hardcoded AWS credentials', project: 'Mobile Backend', cwe: 'CWE-798' },
            { id: 3, title: 'Remote Code Execution vulnerability', project: 'Admin Panel', cwe: 'CWE-94' },
          ],
          High: [
            { id: 4, title: 'XSS in user profile page', project: 'User Portal', cwe: 'CWE-79' },
            { id: 5, title: 'Insecure deserialization', project: 'API Gateway', cwe: 'CWE-502' },
            { id: 6, title: 'Missing authentication check', project: 'Dashboard API', cwe: 'CWE-306' },
          ],
          Medium: [
            { id: 7, title: 'Weak password policy', project: 'Auth Service', cwe: 'CWE-521' },
            { id: 8, title: 'Missing CSRF protection', project: 'Admin Panel', cwe: 'CWE-352' },
          ],
          Low: [
            { id: 9, title: 'Information disclosure in headers', project: 'Web Server', cwe: 'CWE-200' },
            { id: 10, title: 'Outdated library version', project: 'Frontend App', cwe: 'CWE-1104' },
          ]
        },
        scanTypeDetails: {
          SAST: [
            {
              id: 1,
              finding: 'SQL Injection Vulnerability',
              file: 'src/auth.js:42',
              severity: 'Critical',
              description: 'User input is directly concatenated into SQL query without sanitization',
              cwe: 'CWE-89',
              impact: 'Attackers can read, modify, or delete database contents',
              recommendation: 'Use parameterized queries or ORM with prepared statements'
            },
            {
              id: 2,
              finding: 'Cross-Site Scripting (XSS)',
              file: 'src/components/profile.jsx:128',
              severity: 'High',
              description: 'User-controlled data rendered without HTML encoding',
              cwe: 'CWE-79',
              impact: 'Attackers can execute arbitrary JavaScript in victim browsers',
              recommendation: 'Sanitize user input and use context-aware output encoding'
            },
            {
              id: 3,
              finding: 'Insecure Random Number Generation',
              file: 'src/utils/token.js:15',
              severity: 'Medium',
              description: 'Math.random() used for security-sensitive token generation',
              cwe: 'CWE-338',
              impact: 'Tokens may be predictable, allowing session hijacking',
              recommendation: 'Use crypto.randomBytes() for cryptographically secure random values'
            },
          ],
          SCA: [
            {
              id: 3,
              finding: 'lodash Prototype Pollution',
              package: 'lodash',
              version: '4.17.15',
              installedVersion: '4.17.15',
              fixedVersion: '4.17.21',
              severity: 'High',
              cve: 'CVE-2020-8203',
              cvss: '7.4',
              description: 'Vulnerable to prototype pollution via the setWith and set functions',
              impact: 'Attackers can modify Object.prototype properties leading to RCE or DoS',
              recommendation: 'Upgrade to lodash@4.17.21 or higher',
              publishedDate: '2020-07-15',
              references: [
                'https://nvd.nist.gov/vuln/detail/CVE-2020-8203',
                'https://github.com/lodash/lodash/pull/4874'
              ]
            },
            {
              id: 4,
              finding: 'axios Server-Side Request Forgery (SSRF)',
              package: 'axios',
              version: '0.19.0',
              installedVersion: '0.19.0',
              fixedVersion: '0.21.1',
              severity: 'Medium',
              cve: 'CVE-2020-28168',
              cvss: '5.9',
              description: 'Insufficient validation of redirect URLs in axios HTTP client',
              impact: 'Attackers can make server perform requests to arbitrary internal resources',
              recommendation: 'Upgrade to axios@0.21.1 or higher',
              publishedDate: '2020-11-06',
              references: [
                'https://nvd.nist.gov/vuln/detail/CVE-2020-28168',
                'https://github.com/axios/axios/commit/5b457116e31db0e88fede6c428e969e87f290929'
              ]
            },
            {
              id: 5,
              finding: 'minimist Prototype Pollution',
              package: 'minimist',
              version: '1.2.0',
              installedVersion: '1.2.0',
              fixedVersion: '1.2.6',
              severity: 'Critical',
              cve: 'CVE-2021-44906',
              cvss: '9.8',
              description: 'Prototype pollution vulnerability in argument parsing',
              impact: 'Remote attackers can add or modify properties leading to code execution',
              recommendation: 'Upgrade to minimist@1.2.6 or higher',
              publishedDate: '2022-03-17',
              references: [
                'https://nvd.nist.gov/vuln/detail/CVE-2021-44906'
              ]
            },
          ],
          Secrets: [
            {
              id: 5,
              finding: 'AWS Access Key Exposed',
              file: 'config/config.yaml:23',
              line: 'aws_access_key_id: AKIAIOSFODNN7EXAMPLE',
              severity: 'Critical',
              secretType: 'AWS Access Key',
              entropy: 'High',
              description: 'Hardcoded AWS access key found in configuration file',
              impact: 'Full access to AWS resources under this account, potential data breach and resource abuse',
              recommendation: 'Immediately rotate credentials, use AWS Secrets Manager or environment variables',
              matchedPattern: 'AKIA[0-9A-Z]{16}',
              commitHash: 'a3f8d9e',
              author: 'developer@company.com',
              dateFound: '2024-04-15'
            },
            {
              id: 6,
              finding: 'Private RSA Key Exposed',
              file: 'deploy/deploy.sh:11',
              line: '-----BEGIN RSA PRIVATE KEY-----',
              severity: 'Critical',
              secretType: 'RSA Private Key',
              entropy: 'High',
              description: 'Private RSA key stored in deployment script',
              impact: 'Unauthorized SSH access to production servers, complete system compromise',
              recommendation: 'Remove key from repository, rotate SSH keys on all servers, use SSH agent forwarding',
              matchedPattern: 'BEGIN RSA PRIVATE KEY',
              commitHash: 'b7e2c1a',
              author: 'devops@company.com',
              dateFound: '2024-04-12'
            },
            {
              id: 7,
              finding: 'Database Password in Source Code',
              file: 'src/database/connection.js:8',
              line: 'password: "MyS3cr3tP@ssw0rd!"',
              severity: 'High',
              secretType: 'Database Password',
              entropy: 'Medium',
              description: 'Database password hardcoded in source code',
              impact: 'Unauthorized database access, data exfiltration, data manipulation',
              recommendation: 'Use environment variables or secrets management system, rotate database credentials',
              matchedPattern: 'password:\\s*["\'][^"\']+["\']',
              commitHash: 'c4a9f2d',
              author: 'backend-dev@company.com',
              dateFound: '2024-04-10'
            },
            {
              id: 8,
              finding: 'Slack Webhook URL Exposed',
              file: 'scripts/notify.py:5',
              line: 'webhook_url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXX"',
              severity: 'Medium',
              secretType: 'Slack Webhook',
              entropy: 'High',
              description: 'Slack webhook URL exposed in notification script',
              impact: 'Unauthorized messages to Slack channel, potential phishing or social engineering',
              recommendation: 'Rotate webhook URL, store in environment variables, restrict webhook permissions',
              matchedPattern: 'hooks\\.slack\\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+',
              commitHash: 'd1e7b3c',
              author: 'automation@company.com',
              dateFound: '2024-04-08'
            },
          ]
        },
        vulnerabilityTrend: [
          { date: 'Jan', total: 52, critical: 12, high: 18, medium: 15, low: 7, fixed: 5 },
          { date: 'Feb', total: 48, critical: 10, high: 17, medium: 14, low: 7, fixed: 8 },
          { date: 'Mar', total: 45, critical: 9, high: 16, medium: 13, low: 7, fixed: 12 },
          { date: 'Apr', total: 42, critical: 8, high: 15, medium: 12, low: 7, fixed: 15 },
        ]
      }

      setStats(mockStats)
    } catch (error) {
      console.error('Failed to fetch stats:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
        <p className="text-gray-600 mt-1">Overview of your application security posture</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Projects"
          value={stats.totalProjects}
          icon={<FileText className="w-8 h-8" />}
          color="blue"
        />
        <StatCard
          title="Total Vulnerabilities"
          value={stats.totalVulnerabilities}
          icon={<AlertTriangle className="w-8 h-8" />}
          color="red"
        />
        <StatCard
          title="Critical Issues"
          value={stats.criticalIssues}
          icon={<Shield className="w-8 h-8" />}
          color="red"
          trend="-12%"
          onClick={() => {
            setSelectedSeverity('Critical')
            setDrillDownView('severity')
          }}
        />
        <StatCard
          title="Risk Score"
          value={`${stats.averageRiskScore}/10`}
          icon={<TrendingUp className="w-8 h-8" />}
          color="orange"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Breakdown */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">Severity Breakdown</h2>
            <p className="text-xs text-gray-500">Click on chart to drill down</p>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={stats.severityBreakdown}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
                onClick={handlePieClick}
                cursor="pointer"
              >
                {stats.severityBreakdown.map((entry: any, index: number) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Scan Type Comparison */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">Findings by Scan Type</h2>
            <p className="text-xs text-gray-500">Click on bars to drill down</p>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={stats.scanTypeData} onClick={handleBarClick}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="critical" fill={SEVERITY_COLORS.critical} name="Critical" cursor="pointer" />
              <Bar dataKey="high" fill={SEVERITY_COLORS.high} name="High" cursor="pointer" />
              <Bar dataKey="medium" fill={SEVERITY_COLORS.medium} name="Medium" cursor="pointer" />
              <Bar dataKey="low" fill={SEVERITY_COLORS.low} name="Low" cursor="pointer" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Drill-Down Modal/Panel */}
      {drillDownView !== 'none' && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black bg-opacity-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[80vh] overflow-hidden">
            <div className="p-6 border-b border-gray-200">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-2xl font-bold text-gray-900">
                    {drillDownView === 'severity' ? `${selectedSeverity} Severity Vulnerabilities` : `${selectedScanType} Scan Findings`}
                  </h2>
                  <p className="text-sm text-gray-600 mt-1">
                    {drillDownView === 'severity'
                      ? `Showing all ${selectedSeverity?.toLowerCase()} severity issues`
                      : `Findings detected by ${selectedScanType} scan`}
                  </p>
                </div>
                <button
                  onClick={closeDrillDown}
                  className="text-gray-400 hover:text-gray-600 text-2xl font-bold"
                >
                  ×
                </button>
              </div>
            </div>

            <div className="p-6 overflow-y-auto max-h-[60vh]">
              {drillDownView === 'severity' && stats.vulnerabilityDetails[selectedSeverity!] && (
                <div className="space-y-3">
                  {stats.vulnerabilityDetails[selectedSeverity!].map((vuln: any) => (
                    <div key={vuln.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <h3 className="font-semibold text-gray-900">{vuln.title}</h3>
                          <div className="flex items-center space-x-3 mt-2">
                            <span className="text-sm text-gray-600">Project: {vuln.project}</span>
                            <span className="text-sm px-2 py-1 bg-gray-100 text-gray-700 rounded">
                              {vuln.cwe}
                            </span>
                          </div>
                        </div>
                        <AlertTriangle className="w-5 h-5 text-orange-600" />
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {drillDownView === 'scanType' && stats.scanTypeDetails[selectedScanType!] && (
                <div className="space-y-4">
                  {stats.scanTypeDetails[selectedScanType!].map((finding: any) => (
                    <div key={finding.id} className="border border-gray-200 rounded-lg overflow-hidden hover:shadow-lg transition">
                      {/* Header */}
                      <div className="bg-gradient-to-r from-gray-50 to-white p-4 border-b border-gray-200">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center space-x-3 mb-2">
                              <h3 className="text-lg font-bold text-gray-900">{finding.finding}</h3>
                              <span className={`text-xs px-3 py-1 rounded-full font-semibold ${
                                finding.severity === 'Critical' ? 'bg-red-100 text-red-800 border border-red-300' :
                                finding.severity === 'High' ? 'bg-orange-100 text-orange-800 border border-orange-300' :
                                finding.severity === 'Medium' ? 'bg-yellow-100 text-yellow-800 border border-yellow-300' :
                                'bg-blue-100 text-blue-800 border border-blue-300'
                              }`}>
                                {finding.severity}
                              </span>
                            </div>

                            {/* SAST Specific */}
                            {finding.file && !finding.package && (
                              <div className="flex items-center space-x-4 text-sm text-gray-600">
                                <div className="flex items-center space-x-1">
                                  <span className="font-medium">📄 File:</span>
                                  <code className="px-2 py-0.5 bg-gray-100 rounded text-xs">{finding.file}</code>
                                </div>
                                {finding.cwe && (
                                  <span className="px-2 py-0.5 bg-blue-50 text-blue-700 rounded text-xs font-medium">
                                    {finding.cwe}
                                  </span>
                                )}
                              </div>
                            )}

                            {/* SCA Specific */}
                            {finding.package && (
                              <div className="space-y-2">
                                <div className="flex items-center space-x-4 text-sm">
                                  <div className="flex items-center space-x-1">
                                    <span className="font-medium text-gray-600">📦 Package:</span>
                                    <code className="px-2 py-0.5 bg-purple-50 text-purple-700 rounded font-mono">{finding.package}</code>
                                  </div>
                                  <div className="flex items-center space-x-1">
                                    <span className="font-medium text-gray-600">🔖 Version:</span>
                                    <code className="px-2 py-0.5 bg-red-50 text-red-700 rounded font-mono">{finding.installedVersion}</code>
                                    <span className="text-gray-400">→</span>
                                    <code className="px-2 py-0.5 bg-green-50 text-green-700 rounded font-mono">{finding.fixedVersion}</code>
                                  </div>
                                </div>
                                <div className="flex items-center space-x-3">
                                  {finding.cve && (
                                    <span className="px-2 py-1 bg-red-100 text-red-800 rounded text-xs font-bold">
                                      {finding.cve}
                                    </span>
                                  )}
                                  {finding.cvss && (
                                    <span className="px-2 py-1 bg-orange-100 text-orange-800 rounded text-xs font-semibold">
                                      CVSS: {finding.cvss}
                                    </span>
                                  )}
                                  {finding.publishedDate && (
                                    <span className="text-xs text-gray-500">
                                      📅 Published: {finding.publishedDate}
                                    </span>
                                  )}
                                </div>
                              </div>
                            )}

                            {/* Secrets Specific */}
                            {finding.secretType && (
                              <div className="space-y-2">
                                <div className="flex items-center space-x-4 text-sm">
                                  <div className="flex items-center space-x-1">
                                    <span className="font-medium text-gray-600">🔐 Type:</span>
                                    <span className="px-2 py-0.5 bg-red-50 text-red-700 rounded font-medium">{finding.secretType}</span>
                                  </div>
                                  <div className="flex items-center space-x-1">
                                    <span className="font-medium text-gray-600">📄 File:</span>
                                    <code className="px-2 py-0.5 bg-gray-100 rounded text-xs">{finding.file}</code>
                                  </div>
                                  <div className="flex items-center space-x-1">
                                    <span className="font-medium text-gray-600">📊 Entropy:</span>
                                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                                      finding.entropy === 'High' ? 'bg-red-100 text-red-700' : 'bg-yellow-100 text-yellow-700'
                                    }`}>
                                      {finding.entropy}
                                    </span>
                                  </div>
                                </div>
                                {finding.line && (
                                  <div className="mt-2">
                                    <span className="text-xs font-medium text-gray-600">Matched Line:</span>
                                    <pre className="mt-1 p-2 bg-gray-900 text-gray-100 rounded text-xs overflow-x-auto">{finding.line}</pre>
                                  </div>
                                )}
                                <div className="flex items-center space-x-3 text-xs text-gray-500">
                                  <span>🔍 Pattern: <code className="text-xs">{finding.matchedPattern}</code></span>
                                  <span>📝 Commit: <code>{finding.commitHash}</code></span>
                                  <span>👤 {finding.author}</span>
                                </div>
                              </div>
                            )}
                          </div>
                          <Shield className={`w-6 h-6 ${
                            finding.severity === 'Critical' ? 'text-red-600' :
                            finding.severity === 'High' ? 'text-orange-600' :
                            finding.severity === 'Medium' ? 'text-yellow-600' :
                            'text-blue-600'
                          }`} />
                        </div>
                      </div>

                      {/* Details */}
                      <div className="p-4 space-y-3">
                        {/* Description */}
                        {finding.description && (
                          <div className="bg-blue-50 border-l-4 border-blue-400 p-3 rounded">
                            <p className="text-xs font-semibold text-blue-800 mb-1">📋 Description</p>
                            <p className="text-sm text-blue-900">{finding.description}</p>
                          </div>
                        )}

                        {/* Impact */}
                        {finding.impact && (
                          <div className="bg-red-50 border-l-4 border-red-400 p-3 rounded">
                            <p className="text-xs font-semibold text-red-800 mb-1">⚠️ Security Impact</p>
                            <p className="text-sm text-red-900">{finding.impact}</p>
                          </div>
                        )}

                        {/* Recommendation */}
                        {finding.recommendation && (
                          <div className="bg-green-50 border-l-4 border-green-400 p-3 rounded">
                            <p className="text-xs font-semibold text-green-800 mb-1">✅ Remediation</p>
                            <p className="text-sm text-green-900 font-medium">{finding.recommendation}</p>
                          </div>
                        )}

                        {/* References (SCA) */}
                        {finding.references && finding.references.length > 0 && (
                          <div className="bg-gray-50 border-l-4 border-gray-400 p-3 rounded">
                            <p className="text-xs font-semibold text-gray-800 mb-2">🔗 References</p>
                            <ul className="space-y-1">
                              {finding.references.map((ref: string, idx: number) => (
                                <li key={idx}>
                                  <a
                                    href={ref}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-xs text-blue-600 hover:text-blue-800 hover:underline break-all"
                                  >
                                    {ref}
                                  </a>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="p-6 border-t border-gray-200 bg-gray-50">
              <button
                onClick={closeDrillDown}
                className="w-full px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Vulnerability Trend Over Time */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Vulnerability Trend</h2>
            <p className="text-sm text-gray-600">Track vulnerabilities and fixes over time</p>
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-sm text-green-600 font-medium">↓ 19% decrease</span>
          </div>
        </div>
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={stats.vulnerabilityTrend}>
            <defs>
              <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#6366f1" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorFixed" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="date" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Area type="monotone" dataKey="critical" stackId="1" stroke="#dc2626" fill="#dc2626" name="Critical" />
            <Area type="monotone" dataKey="high" stackId="1" stroke="#ef4444" fill="#ef4444" name="High" />
            <Area type="monotone" dataKey="medium" stackId="1" stroke="#f97316" fill="#f97316" name="Medium" />
            <Area type="monotone" dataKey="low" stackId="1" stroke="#fbbf24" fill="#fbbf24" name="Low" />
            <Line type="monotone" dataKey="fixed" stroke="#10b981" strokeWidth={3} name="Fixed" />
          </AreaChart>
        </ResponsiveContainer>
        <div className="grid grid-cols-4 gap-4 mt-4">
          <div
            className="text-center p-3 bg-red-50 rounded-lg cursor-pointer hover:shadow-md transition"
            onClick={() => {
              setSelectedSeverity('Critical')
              setDrillDownView('severity')
            }}
          >
            <p className="text-2xl font-bold text-red-600">{stats.criticalIssues}</p>
            <p className="text-xs text-red-800">Critical</p>
          </div>
          <div
            className="text-center p-3 bg-orange-50 rounded-lg cursor-pointer hover:shadow-md transition"
            onClick={() => {
              setSelectedSeverity('High')
              setDrillDownView('severity')
            }}
          >
            <p className="text-2xl font-bold text-orange-600">{stats.highIssues}</p>
            <p className="text-xs text-orange-800">High</p>
          </div>
          <div
            className="text-center p-3 bg-yellow-50 rounded-lg cursor-pointer hover:shadow-md transition"
            onClick={() => {
              setSelectedSeverity('Medium')
              setDrillDownView('severity')
            }}
          >
            <p className="text-2xl font-bold text-yellow-600">{stats.mediumIssues}</p>
            <p className="text-xs text-yellow-800">Medium</p>
          </div>
          <div className="text-center p-3 bg-green-50 rounded-lg">
            <p className="text-2xl font-bold text-green-600">15</p>
            <p className="text-xs text-green-800">Fixed</p>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Projects */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">Recent Projects</h2>
            <Link to="/projects" className="text-sm text-primary-600 hover:text-primary-700">
              View all →
            </Link>
          </div>

          {stats.recentProjects.length === 0 ? (
            <div className="text-center py-8">
              <FileText className="w-12 h-12 text-gray-300 mx-auto mb-2" />
              <p className="text-gray-600">No projects yet</p>
              <Link to="/projects" className="btn btn-primary mt-4">
                Create First Project
              </Link>
            </div>
          ) : (
            <div className="space-y-3">
              {stats.recentProjects.map((project: any) => (
                <div
                  key={project.id}
                  className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition"
                >
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-primary-100 rounded-lg flex items-center justify-center">
                      <FileText className="w-5 h-5 text-primary-600" />
                    </div>
                    <div>
                      <Link
                        to={`/projects/${project.id}`}
                        className="font-medium text-gray-900 hover:text-primary-600"
                      >
                        {project.name}
                      </Link>
                      <p className="text-sm text-gray-500">{project.description || 'No description'}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-lg font-semibold text-gray-900">
                      {project.risk_score?.toFixed(1) || '0.0'}
                    </div>
                    <div className="text-xs text-gray-500">Risk Score</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Quick Actions */}
        <div className="card p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h2>
          <div className="space-y-3">
            <QuickAction
              icon={<FileText className="w-6 h-6" />}
              title="Create New Project"
              description="Upload architecture and start threat modeling"
              link="/projects"
              color="blue"
            />
            <QuickAction
              icon={<Shield className="w-6 h-6" />}
              title="Run Security Scan"
              description="SAST, SCA, and secret detection"
              link="/projects"
              color="green"
            />
            <QuickAction
              icon={<Package className="w-6 h-6" />}
              title="Review Dependencies"
              description="Check for vulnerable packages"
              link="/projects"
              color="orange"
            />
            <QuickAction
              icon={<Key className="w-6 h-6" />}
              title="AI Security Assistant"
              description="Get help from multilingual chatbot"
              link="/chat"
              color="purple"
            />
          </div>
        </div>
      </div>
    </div>
  )
}

function StatCard({ title, value, icon, color, trend, onClick }: any) {
  const colorClasses = {
    blue: 'bg-blue-100 text-blue-600',
    red: 'bg-red-100 text-red-600',
    green: 'bg-green-100 text-green-600',
    orange: 'bg-orange-100 text-orange-600',
  }

  return (
    <div
      className={`card p-6 ${onClick ? 'cursor-pointer hover:shadow-lg transition-shadow' : ''}`}
      onClick={onClick}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600 mb-1">{title}</p>
          <p className="text-3xl font-bold text-gray-900">{value}</p>
          {trend && (
            <p className="text-sm text-green-600 mt-1">
              {trend} from last week
            </p>
          )}
        </div>
        <div className={`p-3 rounded-lg ${colorClasses[color as keyof typeof colorClasses]}`}>
          {icon}
        </div>
      </div>
      {onClick && (
        <p className="text-xs text-gray-500 mt-2">Click to view details</p>
      )}
    </div>
  )
}

function QuickAction({ icon, title, description, link, color }: any) {
  const colorClasses = {
    blue: 'bg-blue-100 text-blue-600',
    green: 'bg-green-100 text-green-600',
    orange: 'bg-orange-100 text-orange-600',
    purple: 'bg-purple-100 text-purple-600',
  }

  return (
    <Link
      to={link}
      className="flex items-center space-x-4 p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition"
    >
      <div className={`p-3 rounded-lg ${colorClasses[color as keyof typeof colorClasses]}`}>
        {icon}
      </div>
      <div className="flex-1">
        <h3 className="font-medium text-gray-900">{title}</h3>
        <p className="text-sm text-gray-600">{description}</p>
      </div>
      <div className="text-gray-400">→</div>
    </Link>
  )
}
