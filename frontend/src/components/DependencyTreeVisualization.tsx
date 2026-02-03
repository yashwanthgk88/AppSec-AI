import { useState } from 'react'
import { Package, ChevronRight, ChevronDown, AlertTriangle, Shield, Github, Globe, Database, ArrowRight, Link2 } from 'lucide-react'

interface Vulnerability {
  id: number
  title: string
  severity: string
  cwe_id?: string
  cvss_score?: number
  source?: string
  isTransitive?: boolean
  introducedBy?: string
  dependencyChain?: string
}

interface DependencyNode {
  name: string
  version: string
  ecosystem: string
  vulnerabilities: Vulnerability[]
  children?: DependencyNode[]
  isTransitive?: boolean
  introducedBy?: string
  dependencyChain?: string
}

interface DependencyTreeVisualizationProps {
  dependencies: DependencyNode[]
  title?: string
  showOnlyVulnerable?: boolean
}

function SourceIcon({ source }: { source: string }) {
  const normalizedSource = source?.toLowerCase() || 'local'

  switch (normalizedSource) {
    case 'github_advisory':
    case 'github':
      return <Github className="w-3 h-3" />
    case 'osv':
      return <Globe className="w-3 h-3" />
    case 'snyk':
      return <Shield className="w-3 h-3" />
    case 'nvd':
      return <Shield className="w-3 h-3 text-red-500" />
    default:
      return <Database className="w-3 h-3" />
  }
}

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-blue-500',
  }
  return <span className={`w-2 h-2 rounded-full ${colors[severity] || 'bg-gray-400'}`} />
}

function DependencyTypeBadge({ isTransitive, introducedBy }: { isTransitive: boolean; introducedBy?: string }) {
  if (isTransitive) {
    return (
      <span className="inline-flex items-center space-x-1 text-xs px-2 py-0.5 bg-amber-100 text-amber-800 rounded-full border border-amber-300">
        <Link2 className="w-3 h-3" />
        <span>Transitive</span>
        {introducedBy && (
          <span className="text-amber-600">via {introducedBy}</span>
        )}
      </span>
    )
  }
  return (
    <span className="inline-flex items-center space-x-1 text-xs px-2 py-0.5 bg-green-100 text-green-800 rounded-full border border-green-300">
      <Package className="w-3 h-3" />
      <span>Direct</span>
    </span>
  )
}

function DependencyChain({ chain }: { chain: string }) {
  if (!chain) return null
  const parts = chain.split(' → ')

  return (
    <div className="flex items-center flex-wrap gap-1 text-xs mt-1">
      <span className="text-gray-500 font-medium">Path:</span>
      {parts.map((part, idx) => (
        <span key={idx} className="flex items-center">
          <span className={`px-1.5 py-0.5 rounded ${idx === parts.length - 1 ? 'bg-red-100 text-red-700 font-medium' : 'bg-gray-100 text-gray-600'}`}>
            {part}
          </span>
          {idx < parts.length - 1 && (
            <ArrowRight className="w-3 h-3 text-gray-400 mx-1" />
          )}
        </span>
      ))}
    </div>
  )
}

function DependencyTreeNode({ node, depth = 0 }: { node: DependencyNode; depth?: number }) {
  const [isExpanded, setIsExpanded] = useState(node.vulnerabilities.length > 0)
  const hasChildren = node.children && node.children.length > 0
  const hasVulns = node.vulnerabilities.length > 0

  const severityCounts = {
    critical: node.vulnerabilities.filter(v => v.severity === 'critical').length,
    high: node.vulnerabilities.filter(v => v.severity === 'high').length,
    medium: node.vulnerabilities.filter(v => v.severity === 'medium').length,
    low: node.vulnerabilities.filter(v => v.severity === 'low').length,
  }

  // Background color based on transitive status and vulnerability
  const getBgColor = () => {
    if (hasVulns) {
      return node.isTransitive
        ? 'bg-amber-50 hover:bg-amber-100 border-l-4 border-l-amber-400'
        : 'bg-red-50 hover:bg-red-100 border-l-4 border-l-red-400'
    }
    return 'hover:bg-gray-50'
  }

  return (
    <div className={`${depth > 0 ? 'ml-6 border-l-2 border-gray-200 pl-4' : ''}`}>
      <div
        className={`flex items-start py-2 px-3 rounded-lg transition cursor-pointer ${getBgColor()}`}
        onClick={() => setIsExpanded(!isExpanded)}
      >
        {/* Expand/Collapse Icon */}
        <div className="w-5 h-5 flex items-center justify-center mr-2">
          {hasChildren || hasVulns ? (
            isExpanded ? (
              <ChevronDown className="w-4 h-4 text-gray-500" />
            ) : (
              <ChevronRight className="w-4 h-4 text-gray-500" />
            )
          ) : (
            <span className="w-4" />
          )}
        </div>

        {/* Package Icon */}
        <Package className={`w-4 h-4 mr-2 mt-0.5 ${hasVulns ? (node.isTransitive ? 'text-amber-500' : 'text-red-500') : 'text-gray-400'}`} />

        {/* Package Name & Version */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center space-x-2 flex-wrap gap-y-1">
            <span className={`font-medium ${hasVulns ? (node.isTransitive ? 'text-amber-900' : 'text-red-900') : 'text-gray-900'}`}>
              {node.name}
            </span>
            <span className="text-sm text-gray-500 font-mono">@{node.version}</span>
            <DependencyTypeBadge isTransitive={node.isTransitive || false} introducedBy={node.introducedBy} />
            <span className="text-xs px-1.5 py-0.5 bg-gray-100 text-gray-500 rounded">
              {node.ecosystem}
            </span>
          </div>
          {node.dependencyChain && node.isTransitive && (
            <DependencyChain chain={node.dependencyChain} />
          )}
        </div>

        {/* Vulnerability Indicators */}
        {hasVulns && (
          <div className="flex items-center space-x-2 ml-2">
            <AlertTriangle className={`w-4 h-4 ${node.isTransitive ? 'text-amber-500' : 'text-red-500'}`} />
            <div className="flex items-center space-x-1">
              {severityCounts.critical > 0 && (
                <span className="px-1.5 py-0.5 text-xs bg-red-500 text-white rounded font-medium">
                  {severityCounts.critical}C
                </span>
              )}
              {severityCounts.high > 0 && (
                <span className="px-1.5 py-0.5 text-xs bg-orange-500 text-white rounded font-medium">
                  {severityCounts.high}H
                </span>
              )}
              {severityCounts.medium > 0 && (
                <span className="px-1.5 py-0.5 text-xs bg-yellow-500 text-white rounded font-medium">
                  {severityCounts.medium}M
                </span>
              )}
              {severityCounts.low > 0 && (
                <span className="px-1.5 py-0.5 text-xs bg-blue-500 text-white rounded font-medium">
                  {severityCounts.low}L
                </span>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Expanded Content */}
      {isExpanded && (
        <div className="ml-7 mt-1 space-y-2">
          {/* Vulnerabilities List */}
          {hasVulns && (
            <div className={`bg-white border rounded-lg overflow-hidden ${node.isTransitive ? 'border-amber-200' : 'border-red-200'}`}>
              <div className={`px-3 py-1.5 border-b ${node.isTransitive ? 'bg-amber-100 border-amber-200' : 'bg-red-100 border-red-200'}`}>
                <p className={`text-xs font-semibold ${node.isTransitive ? 'text-amber-800' : 'text-red-800'}`}>
                  {node.vulnerabilities.length} Vulnerabilit{node.vulnerabilities.length > 1 ? 'ies' : 'y'} Found
                  {node.isTransitive && <span className="font-normal ml-1">(in transitive dependency)</span>}
                </p>
              </div>
              <div className={`divide-y ${node.isTransitive ? 'divide-amber-100' : 'divide-red-100'}`}>
                {node.vulnerabilities.map((vuln, idx) => (
                  <div key={idx} className={`px-3 py-2 ${node.isTransitive ? 'hover:bg-amber-50' : 'hover:bg-red-50'}`}>
                    <div className="flex items-start justify-between">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center space-x-2 flex-wrap gap-1">
                          <SeverityDot severity={vuln.severity} />
                          <span className="text-sm font-medium text-gray-900 truncate">
                            {vuln.title}
                          </span>
                          <span className={`text-xs px-1.5 py-0.5 rounded ${
                            vuln.severity === 'critical' ? 'bg-red-100 text-red-800' :
                            vuln.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                            vuln.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-blue-100 text-blue-800'
                          }`}>
                            {vuln.severity.toUpperCase()}
                          </span>
                        </div>
                        <div className="flex items-center space-x-3 mt-1 text-xs text-gray-500">
                          {vuln.cwe_id && <span>{vuln.cwe_id}</span>}
                          {vuln.cvss_score && <span>CVSS: {vuln.cvss_score}</span>}
                          {vuln.source && (
                            <span className="inline-flex items-center space-x-1">
                              <SourceIcon source={vuln.source} />
                              <span>{vuln.source.replace('_', ' ')}</span>
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Child Dependencies */}
          {hasChildren && (
            <div className="space-y-1">
              {node.children!.map((child, idx) => (
                <DependencyTreeNode key={`${child.name}-${idx}`} node={child} depth={depth + 1} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function DependencyTreeVisualization({
  dependencies,
  title = 'Dependency Tree',
  showOnlyVulnerable = false,
}: DependencyTreeVisualizationProps) {
  const [filter, setFilter] = useState<'all' | 'vulnerable' | 'direct' | 'transitive'>('all')

  // Calculate stats
  const directDeps = dependencies.filter(d => !d.isTransitive)
  const transitiveDeps = dependencies.filter(d => d.isTransitive)
  const directVulnDeps = directDeps.filter(d => d.vulnerabilities.length > 0)
  const transitiveVulnDeps = transitiveDeps.filter(d => d.vulnerabilities.length > 0)

  // Apply filter
  let filteredDeps = dependencies
  if (filter === 'vulnerable' || showOnlyVulnerable) {
    filteredDeps = dependencies.filter(d => d.vulnerabilities.length > 0 || d.children?.some(c => c.vulnerabilities.length > 0))
  } else if (filter === 'direct') {
    filteredDeps = dependencies.filter(d => !d.isTransitive)
  } else if (filter === 'transitive') {
    filteredDeps = dependencies.filter(d => d.isTransitive)
  }

  const totalVulns = dependencies.reduce((acc, dep) => {
    let count = dep.vulnerabilities.length
    if (dep.children) {
      count += dep.children.reduce((childAcc, child) => childAcc + child.vulnerabilities.length, 0)
    }
    return acc + count
  }, 0)

  const vulnPackages = dependencies.filter(d => d.vulnerabilities.length > 0).length

  return (
    <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
      {/* Header */}
      <div className="bg-gradient-to-r from-purple-50 to-indigo-50 px-4 py-3 border-b border-gray-200">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center space-x-2">
            <Package className="w-5 h-5 text-purple-600" />
            <h3 className="font-semibold text-gray-900">{title}</h3>
          </div>
          <div className="flex items-center space-x-4 flex-wrap gap-y-2">
            <div className="flex items-center space-x-4 text-sm">
              <span className="text-gray-600">
                <span className="font-semibold">{dependencies.length}</span> total
              </span>
              <span className="text-green-600">
                <span className="font-semibold">{directDeps.length}</span> direct
                {directVulnDeps.length > 0 && (
                  <span className="text-red-500 ml-1">({directVulnDeps.length} vuln)</span>
                )}
              </span>
              <span className="text-amber-600">
                <span className="font-semibold">{transitiveDeps.length}</span> transitive
                {transitiveVulnDeps.length > 0 && (
                  <span className="text-amber-700 ml-1">({transitiveVulnDeps.length} vuln)</span>
                )}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="px-4 py-2 bg-gray-50 border-b border-gray-200 flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center space-x-1 bg-white rounded-lg border border-gray-200 p-0.5">
          <button
            onClick={() => setFilter('all')}
            className={`px-3 py-1 text-xs rounded transition ${
              filter === 'all'
                ? 'bg-purple-600 text-white'
                : 'text-gray-600 hover:bg-gray-100'
            }`}
          >
            All ({dependencies.length})
          </button>
          <button
            onClick={() => setFilter('direct')}
            className={`px-3 py-1 text-xs rounded transition ${
              filter === 'direct'
                ? 'bg-green-600 text-white'
                : 'text-gray-600 hover:bg-gray-100'
            }`}
          >
            Direct ({directDeps.length})
          </button>
          <button
            onClick={() => setFilter('transitive')}
            className={`px-3 py-1 text-xs rounded transition ${
              filter === 'transitive'
                ? 'bg-amber-600 text-white'
                : 'text-gray-600 hover:bg-gray-100'
            }`}
          >
            Transitive ({transitiveDeps.length})
          </button>
          <button
            onClick={() => setFilter('vulnerable')}
            className={`px-3 py-1 text-xs rounded transition ${
              filter === 'vulnerable'
                ? 'bg-red-600 text-white'
                : 'text-gray-600 hover:bg-gray-100'
            }`}
          >
            Vulnerable ({vulnPackages})
          </button>
        </div>

        {/* Legend */}
        <div className="flex items-center space-x-4 text-xs">
          <div className="flex items-center space-x-1">
            <span className="w-3 h-1 rounded bg-green-400" />
            <span className="text-gray-600">Direct</span>
          </div>
          <div className="flex items-center space-x-1">
            <span className="w-3 h-1 rounded bg-amber-400" />
            <span className="text-gray-600">Transitive</span>
          </div>
          <span className="text-gray-300">|</span>
          <div className="flex items-center space-x-1">
            <Github className="w-3 h-3 text-gray-600" />
            <span className="text-gray-500">GitHub</span>
          </div>
          <div className="flex items-center space-x-1">
            <Globe className="w-3 h-3 text-blue-600" />
            <span className="text-gray-500">OSV</span>
          </div>
          <div className="flex items-center space-x-1">
            <Shield className="w-3 h-3 text-purple-600" />
            <span className="text-gray-500">Snyk</span>
          </div>
          <div className="flex items-center space-x-1">
            <Shield className="w-3 h-3 text-red-600" />
            <span className="text-gray-500">NVD</span>
          </div>
        </div>
      </div>

      {/* Summary Alert */}
      {(directVulnDeps.length > 0 || transitiveVulnDeps.length > 0) && (
        <div className="px-4 py-2 bg-gradient-to-r from-red-50 to-amber-50 border-b border-gray-200">
          <div className="flex items-center space-x-6 text-sm">
            {directVulnDeps.length > 0 && (
              <div className="flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                <span className="text-red-700 font-medium">
                  {directVulnDeps.length} Direct {directVulnDeps.length === 1 ? 'Dependency' : 'Dependencies'} Vulnerable
                </span>
                <span className="text-red-500 text-xs">(Requires immediate attention)</span>
              </div>
            )}
            {transitiveVulnDeps.length > 0 && (
              <div className="flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-amber-500" />
                <span className="text-amber-700 font-medium">
                  {transitiveVulnDeps.length} Transitive {transitiveVulnDeps.length === 1 ? 'Dependency' : 'Dependencies'} Vulnerable
                </span>
                <span className="text-amber-600 text-xs">(Upgrade parent package)</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tree Content */}
      <div className="p-4 max-h-96 overflow-y-auto">
        {filteredDeps.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <Package className="w-12 h-12 mx-auto mb-2 text-gray-300" />
            <p>
              {filter === 'vulnerable' ? 'No vulnerable dependencies found' :
               filter === 'direct' ? 'No direct dependencies found' :
               filter === 'transitive' ? 'No transitive dependencies found' :
               'No dependencies found'}
            </p>
          </div>
        ) : (
          <div className="space-y-1">
            {filteredDeps.map((dep, idx) => (
              <DependencyTreeNode key={`${dep.name}-${idx}`} node={dep} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// Helper function to convert SCA vulnerabilities to dependency tree format
export function buildDependencyTree(vulnerabilities: any[]): DependencyNode[] {
  const scaVulns = vulnerabilities.filter(v => v.scan_type === 'sca')
  const depMap = new Map<string, DependencyNode>()

  scaVulns.forEach(vuln => {
    // Parse package info from file_path
    const filePath = vuln.file_path || ''
    const codeSnippet = vuln.code_snippet || ''

    // Extract package name from file_path like "npm dependency: lodash 4.17.15 [DIRECT] [Source: XYZ]"
    const depMatch = filePath.match(/(\w+)\s+dependency:\s*([^\s]+)\s+([^\s\[]+)/i)
    const ecosystem = depMatch ? depMatch[1] : 'npm'
    const packageName = depMatch ? depMatch[2] : vuln.title?.split(' in ')[1]?.split('@')[0]?.trim() || 'unknown'
    const version = depMatch ? depMatch[3] : 'unknown'

    // Extract direct/transitive indicator
    const isTransitive = filePath.includes('[TRANSITIVE]')

    // Extract "Via" info for transitive dependencies
    const viaMatch = filePath.match(/\[Via:\s*([^\]]+)\]/i)
    const introducedBy = viaMatch ? viaMatch[1] : undefined

    // Extract dependency chain from code snippet
    const chainMatch = codeSnippet.match(/Dependency chain:\s*(.+)/i)
    const dependencyChain = chainMatch ? chainMatch[1] : undefined

    // Extract source
    const sourceMatch = filePath.match(/\[Source:\s*([^\]]+)\]/i)
    const source = sourceMatch ? sourceMatch[1] : 'local'

    const key = `${packageName}@${version}`

    if (!depMap.has(key)) {
      depMap.set(key, {
        name: packageName,
        version,
        ecosystem,
        vulnerabilities: [],
        children: [],
        isTransitive,
        introducedBy,
        dependencyChain,
      })
    }

    const depNode = depMap.get(key)!
    depNode.vulnerabilities.push({
      id: vuln.id,
      title: vuln.title,
      severity: vuln.severity,
      cwe_id: vuln.cwe_id,
      cvss_score: vuln.cvss_score,
      source,
      isTransitive,
      introducedBy,
      dependencyChain,
    })
  })

  return Array.from(depMap.values()).sort((a, b) => {
    // Sort: Direct vulnerabilities first, then by severity
    if (a.isTransitive !== b.isTransitive) {
      return a.isTransitive ? 1 : -1  // Direct first
    }

    const aMax = Math.max(...a.vulnerabilities.map(v =>
      v.severity === 'critical' ? 4 : v.severity === 'high' ? 3 : v.severity === 'medium' ? 2 : 1
    ), 0)
    const bMax = Math.max(...b.vulnerabilities.map(v =>
      v.severity === 'critical' ? 4 : v.severity === 'high' ? 3 : v.severity === 'medium' ? 2 : 1
    ), 0)
    return bMax - aMax || b.vulnerabilities.length - a.vulnerabilities.length
  })
}
