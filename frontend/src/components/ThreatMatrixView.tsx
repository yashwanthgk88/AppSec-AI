import { useState, useMemo } from 'react'
import {
  Shield, AlertTriangle, Eye, EyeOff, Filter,
  ChevronDown, ChevronRight, Info, X, Target,
  Maximize2, Minimize2
} from 'lucide-react'

// STRIDE categories with descriptions
const STRIDE_CATEGORIES = [
  { key: 'Spoofing', short: 'S', color: 'bg-red-500', description: 'Identity spoofing attacks' },
  { key: 'Tampering', short: 'T', color: 'bg-orange-500', description: 'Data tampering attacks' },
  { key: 'Repudiation', short: 'R', color: 'bg-yellow-500', description: 'Repudiation threats' },
  { key: 'Information Disclosure', short: 'I', color: 'bg-blue-500', description: 'Information leakage' },
  { key: 'Denial of Service', short: 'D', color: 'bg-purple-500', description: 'DoS attacks' },
  { key: 'Elevation of Privilege', short: 'E', color: 'bg-pink-500', description: 'Privilege escalation' },
]

interface ThreatMatrixViewProps {
  strideAnalysis: Record<string, any[]>
  components: any[]
  onThreatClick?: (threat: any) => void
  onComponentClick?: (component: any) => void
}

interface MatrixCell {
  threats: any[]
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  totalCount: number
  maxSeverity: string
}

export default function ThreatMatrixView({
  strideAnalysis,
  components,
  onThreatClick,
  onComponentClick
}: ThreatMatrixViewProps) {
  const [selectedCell, setSelectedCell] = useState<{ component: string; category: string } | null>(null)
  const [showLowSeverity, setShowLowSeverity] = useState(true)
  const [expandedComponents, setExpandedComponents] = useState<Set<string>>(new Set())
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [isFullscreen, setIsFullscreen] = useState(false)

  // Build matrix data
  const matrixData = useMemo(() => {
    const matrix: Record<string, Record<string, MatrixCell>> = {}

    // Initialize matrix for all components
    components.forEach(comp => {
      const compName = comp.label || comp.name || comp.id
      matrix[compName] = {}
      STRIDE_CATEGORIES.forEach(cat => {
        matrix[compName][cat.key] = {
          threats: [],
          criticalCount: 0,
          highCount: 0,
          mediumCount: 0,
          lowCount: 0,
          totalCount: 0,
          maxSeverity: 'none'
        }
      })
    })

    // Populate with threats
    Object.entries(strideAnalysis || {}).forEach(([category, threats]) => {
      (threats || []).forEach(threat => {
        const compName = threat.component || threat.target_component || 'Unknown'

        // Find matching component
        const matchingComp = Object.keys(matrix).find(
          c => c.toLowerCase() === compName.toLowerCase() ||
               compName.toLowerCase().includes(c.toLowerCase()) ||
               c.toLowerCase().includes(compName.toLowerCase())
        )

        if (matchingComp && matrix[matchingComp][category]) {
          const cell = matrix[matchingComp][category]
          cell.threats.push(threat)
          cell.totalCount++

          const severity = (threat.severity || 'medium').toLowerCase()
          if (severity === 'critical') {
            cell.criticalCount++
            cell.maxSeverity = 'critical'
          } else if (severity === 'high') {
            cell.highCount++
            if (cell.maxSeverity !== 'critical') cell.maxSeverity = 'high'
          } else if (severity === 'medium') {
            cell.mediumCount++
            if (!['critical', 'high'].includes(cell.maxSeverity)) cell.maxSeverity = 'medium'
          } else {
            cell.lowCount++
            if (cell.maxSeverity === 'none') cell.maxSeverity = 'low'
          }
        }
      })
    })

    return matrix
  }, [strideAnalysis, components])

  // Get component statistics
  const componentStats = useMemo(() => {
    const stats: Record<string, { total: number; critical: number; high: number }> = {}

    Object.entries(matrixData).forEach(([compName, categories]) => {
      stats[compName] = { total: 0, critical: 0, high: 0 }
      Object.values(categories).forEach(cell => {
        stats[compName].total += cell.totalCount
        stats[compName].critical += cell.criticalCount
        stats[compName].high += cell.highCount
      })
    })

    return stats
  }, [matrixData])

  // Sort components by threat count
  const sortedComponents = useMemo(() => {
    return Object.keys(matrixData).sort((a, b) => {
      const aStats = componentStats[a]
      const bStats = componentStats[b]
      // Sort by critical first, then high, then total
      if (bStats.critical !== aStats.critical) return bStats.critical - aStats.critical
      if (bStats.high !== aStats.high) return bStats.high - aStats.high
      return bStats.total - aStats.total
    })
  }, [matrixData, componentStats])

  // Filter components based on severity filter
  const filteredComponents = useMemo(() => {
    if (filterSeverity === 'all') return sortedComponents
    return sortedComponents.filter(comp => {
      const stats = componentStats[comp]
      if (filterSeverity === 'critical') return stats.critical > 0
      if (filterSeverity === 'high') return stats.critical > 0 || stats.high > 0
      return stats.total > 0
    })
  }, [sortedComponents, componentStats, filterSeverity])

  const getCellColor = (cell: MatrixCell) => {
    if (cell.totalCount === 0) return 'bg-gray-100'
    if (cell.criticalCount > 0) return 'bg-red-500 text-white'
    if (cell.highCount > 0) return 'bg-orange-400 text-white'
    if (cell.mediumCount > 0) return 'bg-yellow-400 text-gray-900'
    return 'bg-green-200 text-gray-700'
  }

  const getCellContent = (cell: MatrixCell) => {
    if (cell.totalCount === 0) return '-'
    if (cell.criticalCount > 0) return `${cell.criticalCount}C`
    if (cell.highCount > 0) return `${cell.highCount}H`
    if (cell.mediumCount > 0) return `${cell.mediumCount}M`
    return `${cell.lowCount}L`
  }

  const handleCellClick = (component: string, category: string, cell: MatrixCell) => {
    if (cell.totalCount === 0) return
    setSelectedCell({ component, category })
  }

  const toggleComponentExpand = (compName: string) => {
    setExpandedComponents(prev => {
      const next = new Set(prev)
      if (next.has(compName)) next.delete(compName)
      else next.add(compName)
      return next
    })
  }

  return (
    <div className={`bg-white rounded-lg shadow ${isFullscreen ? 'fixed inset-4 z-50 overflow-auto' : ''}`}>
      {/* Header */}
      <div className="p-4 border-b border-gray-200 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <Target className="w-5 h-5 text-primary-600" />
          <h3 className="text-lg font-semibold text-gray-900">Threat Matrix View</h3>
          <span className="text-sm text-gray-500">
            {filteredComponents.length} components × 6 STRIDE categories
          </span>
        </div>

        <div className="flex items-center space-x-3">
          {/* Severity Filter */}
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="text-sm border border-gray-300 rounded-lg px-3 py-1.5"
          >
            <option value="all">All Components</option>
            <option value="critical">Critical Threats Only</option>
            <option value="high">High+ Threats</option>
            <option value="any">With Any Threats</option>
          </select>

          {/* Toggle Low Severity */}
          <button
            onClick={() => setShowLowSeverity(!showLowSeverity)}
            className={`inline-flex items-center px-3 py-1.5 text-sm rounded-lg border ${
              showLowSeverity
                ? 'bg-gray-100 border-gray-300 text-gray-700'
                : 'bg-gray-200 border-gray-400 text-gray-600'
            }`}
          >
            {showLowSeverity ? <Eye className="w-4 h-4 mr-1" /> : <EyeOff className="w-4 h-4 mr-1" />}
            Low Severity
          </button>

          {/* Fullscreen Toggle */}
          <button
            onClick={() => setIsFullscreen(!isFullscreen)}
            className="p-2 hover:bg-gray-100 rounded-lg"
            title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
          >
            {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="px-4 py-2 bg-gray-50 border-b border-gray-200 flex items-center space-x-4 text-xs">
        <span className="text-gray-500">Severity:</span>
        <span className="inline-flex items-center">
          <span className="w-4 h-4 rounded bg-red-500 mr-1"></span> Critical
        </span>
        <span className="inline-flex items-center">
          <span className="w-4 h-4 rounded bg-orange-400 mr-1"></span> High
        </span>
        <span className="inline-flex items-center">
          <span className="w-4 h-4 rounded bg-yellow-400 mr-1"></span> Medium
        </span>
        <span className="inline-flex items-center">
          <span className="w-4 h-4 rounded bg-green-200 mr-1"></span> Low
        </span>
        <span className="inline-flex items-center">
          <span className="w-4 h-4 rounded bg-gray-100 mr-1"></span> None
        </span>
      </div>

      {/* Matrix Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="bg-gray-50">
              <th className="sticky left-0 bg-gray-50 px-4 py-3 text-left text-sm font-semibold text-gray-900 border-b border-r border-gray-200 min-w-[200px]">
                Component
              </th>
              {STRIDE_CATEGORIES.map(cat => (
                <th
                  key={cat.key}
                  className="px-2 py-3 text-center text-sm font-semibold text-gray-900 border-b border-gray-200 min-w-[80px]"
                  title={cat.description}
                >
                  <div className="flex flex-col items-center">
                    <span className={`w-6 h-6 rounded-full ${cat.color} text-white text-xs flex items-center justify-center mb-1`}>
                      {cat.short}
                    </span>
                    <span className="text-xs text-gray-500 truncate max-w-[70px]">
                      {cat.key.split(' ')[0]}
                    </span>
                  </div>
                </th>
              ))}
              <th className="px-3 py-3 text-center text-sm font-semibold text-gray-900 border-b border-l border-gray-200 min-w-[60px]">
                Total
              </th>
            </tr>
          </thead>
          <tbody>
            {filteredComponents.map((compName, idx) => {
              const stats = componentStats[compName]
              const isExpanded = expandedComponents.has(compName)

              return (
                <tr
                  key={compName}
                  className={`${idx % 2 === 0 ? 'bg-white' : 'bg-gray-50'} hover:bg-blue-50 transition-colors`}
                >
                  <td className="sticky left-0 bg-inherit px-4 py-2 border-r border-gray-200">
                    <button
                      onClick={() => onComponentClick?.({ name: compName })}
                      className="flex items-center space-x-2 text-left hover:text-primary-600"
                    >
                      <span className="font-medium text-sm truncate max-w-[150px]" title={compName}>
                        {compName}
                      </span>
                      {stats.critical > 0 && (
                        <span className="px-1.5 py-0.5 bg-red-100 text-red-700 text-xs rounded">
                          {stats.critical}C
                        </span>
                      )}
                    </button>
                  </td>

                  {STRIDE_CATEGORIES.map(cat => {
                    const cell = matrixData[compName]?.[cat.key]
                    if (!cell) return <td key={cat.key} className="px-2 py-2 text-center">-</td>

                    const shouldShow = showLowSeverity || cell.maxSeverity !== 'low'

                    return (
                      <td key={cat.key} className="px-2 py-2 text-center">
                        {shouldShow && cell.totalCount > 0 ? (
                          <button
                            onClick={() => handleCellClick(compName, cat.key, cell)}
                            className={`w-full py-1 px-2 rounded text-xs font-medium transition-all hover:scale-105 hover:shadow ${getCellColor(cell)}`}
                            title={`${cell.totalCount} threats: ${cell.criticalCount}C, ${cell.highCount}H, ${cell.mediumCount}M, ${cell.lowCount}L`}
                          >
                            {getCellContent(cell)}
                          </button>
                        ) : (
                          <span className="text-gray-300">-</span>
                        )}
                      </td>
                    )
                  })}

                  <td className="px-3 py-2 text-center border-l border-gray-200">
                    <span className={`font-semibold text-sm ${
                      stats.critical > 0 ? 'text-red-600' :
                      stats.high > 0 ? 'text-orange-600' :
                      stats.total > 0 ? 'text-yellow-600' : 'text-gray-400'
                    }`}>
                      {stats.total}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Empty State */}
      {filteredComponents.length === 0 && (
        <div className="p-8 text-center text-gray-500">
          <Shield className="w-12 h-12 mx-auto mb-3 text-gray-300" />
          <p>No components match the current filter</p>
        </div>
      )}

      {/* Cell Detail Modal */}
      {selectedCell && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-2xl max-w-2xl w-full max-h-[80vh] overflow-hidden">
            <div className="p-4 border-b border-gray-200 flex items-center justify-between bg-gray-50">
              <div>
                <h3 className="font-semibold text-gray-900">{selectedCell.component}</h3>
                <p className="text-sm text-gray-500">{selectedCell.category} Threats</p>
              </div>
              <button
                onClick={() => setSelectedCell(null)}
                className="p-2 hover:bg-gray-200 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-4 overflow-y-auto max-h-[60vh]">
              {matrixData[selectedCell.component]?.[selectedCell.category]?.threats.map((threat, idx) => (
                <div
                  key={idx}
                  onClick={() => onThreatClick?.(threat)}
                  className="p-4 mb-3 border border-gray-200 rounded-lg hover:border-primary-300 hover:shadow cursor-pointer"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h4 className="font-medium text-gray-900">{threat.threat || threat.name}</h4>
                      <p className="text-sm text-gray-600 mt-1 line-clamp-2">
                        {threat.description}
                      </p>
                    </div>
                    <span className={`ml-3 px-2 py-1 text-xs font-medium rounded ${
                      threat.severity === 'critical' ? 'bg-red-100 text-red-700' :
                      threat.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                      threat.severity === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                      'bg-green-100 text-green-700'
                    }`}>
                      {threat.severity?.toUpperCase()}
                    </span>
                  </div>

                  <div className="mt-3 flex items-center space-x-4 text-xs text-gray-500">
                    {threat.cwe && <span>CWE: {threat.cwe}</span>}
                    {threat.mitre_techniques?.length > 0 && (
                      <span>MITRE: {threat.mitre_techniques.slice(0, 2).join(', ')}</span>
                    )}
                    {threat.risk_score && <span>Risk: {threat.risk_score}/10</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
