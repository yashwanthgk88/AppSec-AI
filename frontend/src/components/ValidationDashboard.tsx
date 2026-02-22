import { useState, useMemo } from 'react'
import {
  Shield, CheckCircle, XCircle, AlertTriangle, AlertCircle,
  Target, Activity, TrendingUp, Info, ChevronDown, ChevronRight,
  FileText, Layers, ThumbsUp, ThumbsDown, HelpCircle
} from 'lucide-react'

// STRIDE categories for coverage analysis
const STRIDE_CATEGORIES = [
  { key: 'Spoofing', description: 'Identity-related attacks', minThreats: 2 },
  { key: 'Tampering', description: 'Data integrity attacks', minThreats: 2 },
  { key: 'Repudiation', description: 'Non-repudiation issues', minThreats: 1 },
  { key: 'Information Disclosure', description: 'Confidentiality breaches', minThreats: 2 },
  { key: 'Denial of Service', description: 'Availability attacks', minThreats: 1 },
  { key: 'Elevation of Privilege', description: 'Authorization bypasses', minThreats: 2 },
]

interface ValidationDashboardProps {
  strideAnalysis: Record<string, any[]>
  components: any[]
  threatModel?: any
  onThreatFeedback?: (threatId: string, feedback: 'confirm' | 'reject', reason?: string) => void
}

interface ValidationResult {
  category: string
  status: 'pass' | 'warning' | 'fail'
  score: number
  details: string
  recommendations: string[]
}

export default function ValidationDashboard({
  strideAnalysis,
  components,
  threatModel,
  onThreatFeedback
}: ValidationDashboardProps) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['coverage', 'quality']))
  const [showLowConfidence, setShowLowConfidence] = useState(false)

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev)
      if (next.has(section)) next.delete(section)
      else next.add(section)
      return next
    })
  }

  // Calculate STRIDE coverage
  const strideCoverage = useMemo(() => {
    const coverage: Record<string, { count: number; hasCritical: boolean; hasHigh: boolean }> = {}

    STRIDE_CATEGORIES.forEach(cat => {
      const threats = strideAnalysis[cat.key] || []
      coverage[cat.key] = {
        count: threats.length,
        hasCritical: threats.some(t => t.severity?.toLowerCase() === 'critical'),
        hasHigh: threats.some(t => t.severity?.toLowerCase() === 'high')
      }
    })

    return coverage
  }, [strideAnalysis])

  // Calculate component coverage
  const componentCoverage = useMemo(() => {
    const covered = new Set<string>()
    const allThreats: any[] = []

    Object.values(strideAnalysis).forEach(threats => {
      (threats || []).forEach(threat => {
        allThreats.push(threat)
        const comp = threat.component || threat.target_component
        if (comp) {
          covered.add(comp.toLowerCase())
          // Also check for partial matches
          components.forEach(c => {
            const cName = (c.label || c.name || c.id).toLowerCase()
            if (comp.toLowerCase().includes(cName) || cName.includes(comp.toLowerCase())) {
              covered.add(cName)
            }
          })
        }
      })
    })

    const uncoveredComponents = components.filter(c => {
      const cName = (c.label || c.name || c.id).toLowerCase()
      return !covered.has(cName)
    })

    return {
      total: components.length,
      covered: covered.size,
      uncovered: uncoveredComponents,
      percentage: components.length > 0 ? Math.round((covered.size / components.length) * 100) : 0
    }
  }, [strideAnalysis, components])

  // Calculate CWE/MITRE coverage
  const standardsCoverage = useMemo(() => {
    const cweIds = new Set<string>()
    const mitreIds = new Set<string>()
    let threatsWithCWE = 0
    let threatsWithMITRE = 0
    let totalThreats = 0

    Object.values(strideAnalysis).forEach(threats => {
      (threats || []).forEach(threat => {
        totalThreats++
        if (threat.cwe) {
          cweIds.add(threat.cwe)
          threatsWithCWE++
        }
        if (threat.mitre_techniques?.length) {
          threat.mitre_techniques.forEach((t: string) => mitreIds.add(t))
          threatsWithMITRE++
        }
      })
    })

    return {
      cweCount: cweIds.size,
      mitreCount: mitreIds.size,
      cwePercentage: totalThreats > 0 ? Math.round((threatsWithCWE / totalThreats) * 100) : 0,
      mitrePercentage: totalThreats > 0 ? Math.round((threatsWithMITRE / totalThreats) * 100) : 0,
      totalThreats
    }
  }, [strideAnalysis])

  // Calculate threat quality metrics
  const threatQuality = useMemo(() => {
    let hasDescription = 0
    let hasMitigation = 0
    let hasRiskScore = 0
    let totalThreats = 0
    const lowConfidenceThreats: any[] = []

    Object.entries(strideAnalysis).forEach(([category, threats]) => {
      (threats || []).forEach(threat => {
        totalThreats++

        if (threat.description && threat.description.length > 20) hasDescription++
        if (threat.mitigation || threat.mitigations?.length) hasMitigation++
        if (threat.risk_score !== undefined) hasRiskScore++

        // Calculate confidence score
        let confidence = 0
        if (threat.description?.length > 50) confidence += 25
        if (threat.cwe) confidence += 20
        if (threat.mitre_techniques?.length) confidence += 20
        if (threat.mitigation || threat.mitigations?.length) confidence += 20
        if (threat.risk_score) confidence += 15

        if (confidence < 60) {
          lowConfidenceThreats.push({
            ...threat,
            category,
            confidence
          })
        }
      })
    })

    return {
      descriptionRate: totalThreats > 0 ? Math.round((hasDescription / totalThreats) * 100) : 0,
      mitigationRate: totalThreats > 0 ? Math.round((hasMitigation / totalThreats) * 100) : 0,
      riskScoreRate: totalThreats > 0 ? Math.round((hasRiskScore / totalThreats) * 100) : 0,
      totalThreats,
      lowConfidenceThreats
    }
  }, [strideAnalysis])

  // Overall validation score
  const overallScore = useMemo(() => {
    let score = 0
    let maxScore = 0

    // STRIDE coverage (30 points)
    maxScore += 30
    const strideCovered = STRIDE_CATEGORIES.filter(cat =>
      strideCoverage[cat.key]?.count >= cat.minThreats
    ).length
    score += Math.round((strideCovered / STRIDE_CATEGORIES.length) * 30)

    // Component coverage (25 points)
    maxScore += 25
    score += Math.round((componentCoverage.percentage / 100) * 25)

    // Standards mapping (20 points)
    maxScore += 20
    score += Math.round(((standardsCoverage.cwePercentage + standardsCoverage.mitrePercentage) / 200) * 20)

    // Threat quality (25 points)
    maxScore += 25
    const qualityAvg = (threatQuality.descriptionRate + threatQuality.mitigationRate + threatQuality.riskScoreRate) / 3
    score += Math.round((qualityAvg / 100) * 25)

    return {
      score,
      maxScore,
      percentage: Math.round((score / maxScore) * 100),
      grade: score >= 80 ? 'A' : score >= 60 ? 'B' : score >= 40 ? 'C' : 'D'
    }
  }, [strideCoverage, componentCoverage, standardsCoverage, threatQuality])

  const getScoreColor = (percentage: number) => {
    if (percentage >= 80) return 'text-green-600'
    if (percentage >= 60) return 'text-yellow-600'
    if (percentage >= 40) return 'text-orange-600'
    return 'text-red-600'
  }

  const getGradeColor = (grade: string) => {
    if (grade === 'A') return 'bg-green-100 text-green-700 border-green-300'
    if (grade === 'B') return 'bg-yellow-100 text-yellow-700 border-yellow-300'
    if (grade === 'C') return 'bg-orange-100 text-orange-700 border-orange-300'
    return 'bg-red-100 text-red-700 border-red-300'
  }

  return (
    <div className="bg-white rounded-lg shadow">
      {/* Header with Overall Score */}
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-xl font-semibold text-gray-900 flex items-center">
              <Shield className="w-6 h-6 mr-2 text-primary-600" />
              Threat Model Validation
            </h2>
            <p className="text-sm text-gray-500 mt-1">
              Comprehensive validation of threat model completeness and quality
            </p>
          </div>

          {/* Overall Score Card */}
          <div className="flex items-center space-x-4">
            <div className="text-right">
              <p className="text-sm text-gray-500">Validation Score</p>
              <p className={`text-3xl font-bold ${getScoreColor(overallScore.percentage)}`}>
                {overallScore.percentage}%
              </p>
            </div>
            <div className={`w-16 h-16 rounded-xl border-2 flex items-center justify-center text-2xl font-bold ${getGradeColor(overallScore.grade)}`}>
              {overallScore.grade}
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-4 gap-4 mt-6">
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-500">Total Threats</span>
              <Target className="w-5 h-5 text-gray-400" />
            </div>
            <p className="text-2xl font-semibold text-gray-900 mt-1">
              {threatQuality.totalThreats}
            </p>
          </div>
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-500">Components Covered</span>
              <Layers className="w-5 h-5 text-gray-400" />
            </div>
            <p className="text-2xl font-semibold text-gray-900 mt-1">
              {componentCoverage.percentage}%
            </p>
          </div>
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-500">CWE Mappings</span>
              <FileText className="w-5 h-5 text-gray-400" />
            </div>
            <p className="text-2xl font-semibold text-gray-900 mt-1">
              {standardsCoverage.cweCount}
            </p>
          </div>
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-500">Low Confidence</span>
              <AlertTriangle className="w-5 h-5 text-yellow-500" />
            </div>
            <p className="text-2xl font-semibold text-yellow-600 mt-1">
              {threatQuality.lowConfidenceThreats.length}
            </p>
          </div>
        </div>
      </div>

      {/* STRIDE Coverage Section */}
      <div className="border-b border-gray-200">
        <button
          onClick={() => toggleSection('coverage')}
          className="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-50"
        >
          <div className="flex items-center">
            {expandedSections.has('coverage') ? (
              <ChevronDown className="w-5 h-5 text-gray-400 mr-2" />
            ) : (
              <ChevronRight className="w-5 h-5 text-gray-400 mr-2" />
            )}
            <h3 className="font-medium text-gray-900">STRIDE Coverage Analysis</h3>
          </div>
          <span className={`px-3 py-1 rounded-full text-sm ${
            STRIDE_CATEGORIES.every(cat => strideCoverage[cat.key]?.count >= cat.minThreats)
              ? 'bg-green-100 text-green-700'
              : 'bg-yellow-100 text-yellow-700'
          }`}>
            {STRIDE_CATEGORIES.filter(cat => strideCoverage[cat.key]?.count >= cat.minThreats).length}/{STRIDE_CATEGORIES.length} Categories
          </span>
        </button>

        {expandedSections.has('coverage') && (
          <div className="px-6 pb-6">
            <div className="grid grid-cols-2 gap-4">
              {STRIDE_CATEGORIES.map(cat => {
                const coverage = strideCoverage[cat.key]
                const isCovered = coverage?.count >= cat.minThreats
                return (
                  <div
                    key={cat.key}
                    className={`p-4 rounded-lg border ${
                      isCovered
                        ? 'bg-green-50 border-green-200'
                        : coverage?.count > 0
                        ? 'bg-yellow-50 border-yellow-200'
                        : 'bg-red-50 border-red-200'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <h4 className="font-medium text-gray-900">{cat.key}</h4>
                        <p className="text-xs text-gray-500 mt-0.5">{cat.description}</p>
                      </div>
                      {isCovered ? (
                        <CheckCircle className="w-5 h-5 text-green-600" />
                      ) : coverage?.count > 0 ? (
                        <AlertTriangle className="w-5 h-5 text-yellow-600" />
                      ) : (
                        <XCircle className="w-5 h-5 text-red-600" />
                      )}
                    </div>
                    <div className="mt-3 flex items-center justify-between text-sm">
                      <span className="text-gray-600">
                        {coverage?.count || 0} threats
                        <span className="text-gray-400 ml-1">(min: {cat.minThreats})</span>
                      </span>
                      <div className="flex items-center space-x-2">
                        {coverage?.hasCritical && (
                          <span className="px-2 py-0.5 bg-red-100 text-red-700 text-xs rounded">Critical</span>
                        )}
                        {coverage?.hasHigh && (
                          <span className="px-2 py-0.5 bg-orange-100 text-orange-700 text-xs rounded">High</span>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Threat Quality Section */}
      <div className="border-b border-gray-200">
        <button
          onClick={() => toggleSection('quality')}
          className="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-50"
        >
          <div className="flex items-center">
            {expandedSections.has('quality') ? (
              <ChevronDown className="w-5 h-5 text-gray-400 mr-2" />
            ) : (
              <ChevronRight className="w-5 h-5 text-gray-400 mr-2" />
            )}
            <h3 className="font-medium text-gray-900">Threat Quality Metrics</h3>
          </div>
          <span className={`px-3 py-1 rounded-full text-sm ${
            threatQuality.mitigationRate >= 80 ? 'bg-green-100 text-green-700' :
            threatQuality.mitigationRate >= 50 ? 'bg-yellow-100 text-yellow-700' :
            'bg-red-100 text-red-700'
          }`}>
            {threatQuality.mitigationRate}% with mitigations
          </span>
        </button>

        {expandedSections.has('quality') && (
          <div className="px-6 pb-6">
            {/* Quality Metrics Bars */}
            <div className="space-y-4">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm text-gray-600">Detailed Descriptions</span>
                  <span className="text-sm font-medium text-gray-900">{threatQuality.descriptionRate}%</span>
                </div>
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-500 rounded-full transition-all"
                    style={{ width: `${threatQuality.descriptionRate}%` }}
                  />
                </div>
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm text-gray-600">Mitigation Plans</span>
                  <span className="text-sm font-medium text-gray-900">{threatQuality.mitigationRate}%</span>
                </div>
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-green-500 rounded-full transition-all"
                    style={{ width: `${threatQuality.mitigationRate}%` }}
                  />
                </div>
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm text-gray-600">Risk Scores Assigned</span>
                  <span className="text-sm font-medium text-gray-900">{threatQuality.riskScoreRate}%</span>
                </div>
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-purple-500 rounded-full transition-all"
                    style={{ width: `${threatQuality.riskScoreRate}%` }}
                  />
                </div>
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm text-gray-600">CWE Mapped</span>
                  <span className="text-sm font-medium text-gray-900">{standardsCoverage.cwePercentage}%</span>
                </div>
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-indigo-500 rounded-full transition-all"
                    style={{ width: `${standardsCoverage.cwePercentage}%` }}
                  />
                </div>
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm text-gray-600">MITRE ATT&CK Mapped</span>
                  <span className="text-sm font-medium text-gray-900">{standardsCoverage.mitrePercentage}%</span>
                </div>
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-red-500 rounded-full transition-all"
                    style={{ width: `${standardsCoverage.mitrePercentage}%` }}
                  />
                </div>
              </div>
            </div>

            {/* Low Confidence Threats */}
            {threatQuality.lowConfidenceThreats.length > 0 && (
              <div className="mt-6">
                <button
                  onClick={() => setShowLowConfidence(!showLowConfidence)}
                  className="flex items-center text-sm text-yellow-700 hover:text-yellow-800"
                >
                  <AlertTriangle className="w-4 h-4 mr-1" />
                  {threatQuality.lowConfidenceThreats.length} low confidence threats need review
                  {showLowConfidence ? (
                    <ChevronDown className="w-4 h-4 ml-1" />
                  ) : (
                    <ChevronRight className="w-4 h-4 ml-1" />
                  )}
                </button>

                {showLowConfidence && (
                  <div className="mt-3 space-y-2 max-h-64 overflow-y-auto">
                    {threatQuality.lowConfidenceThreats.map((threat, idx) => (
                      <div
                        key={idx}
                        className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg"
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="text-xs px-2 py-0.5 bg-yellow-100 text-yellow-700 rounded">
                                {threat.category}
                              </span>
                              <span className="text-xs text-gray-500">
                                Confidence: {threat.confidence}%
                              </span>
                            </div>
                            <p className="text-sm font-medium text-gray-900 mt-1">
                              {threat.threat || threat.name}
                            </p>
                            <p className="text-xs text-gray-500 mt-0.5">
                              Missing: {!threat.cwe && 'CWE, '}
                              {!threat.mitre_techniques?.length && 'MITRE, '}
                              {!threat.mitigation && !threat.mitigations?.length && 'Mitigation'}
                            </p>
                          </div>
                          {onThreatFeedback && (
                            <div className="flex items-center space-x-1 ml-3">
                              <button
                                onClick={() => onThreatFeedback(threat.id || idx.toString(), 'confirm')}
                                className="p-1.5 hover:bg-green-100 rounded text-green-600"
                                title="Confirm threat"
                              >
                                <ThumbsUp className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => onThreatFeedback(threat.id || idx.toString(), 'reject')}
                                className="p-1.5 hover:bg-red-100 rounded text-red-600"
                                title="Reject threat"
                              >
                                <ThumbsDown className="w-4 h-4" />
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Uncovered Components Section */}
      {componentCoverage.uncovered.length > 0 && (
        <div className="border-b border-gray-200">
          <button
            onClick={() => toggleSection('uncovered')}
            className="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-50"
          >
            <div className="flex items-center">
              {expandedSections.has('uncovered') ? (
                <ChevronDown className="w-5 h-5 text-gray-400 mr-2" />
              ) : (
                <ChevronRight className="w-5 h-5 text-gray-400 mr-2" />
              )}
              <h3 className="font-medium text-gray-900">Uncovered Components</h3>
            </div>
            <span className="px-3 py-1 bg-orange-100 text-orange-700 rounded-full text-sm">
              {componentCoverage.uncovered.length} components
            </span>
          </button>

          {expandedSections.has('uncovered') && (
            <div className="px-6 pb-6">
              <p className="text-sm text-gray-600 mb-3">
                The following components have no associated threats. Consider if they need threat analysis.
              </p>
              <div className="flex flex-wrap gap-2">
                {componentCoverage.uncovered.map((comp, idx) => (
                  <span
                    key={idx}
                    className="px-3 py-1 bg-orange-50 border border-orange-200 rounded-lg text-sm text-orange-700"
                  >
                    {comp.label || comp.name || comp.id}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Recommendations Section */}
      <div className="px-6 py-4">
        <h3 className="font-medium text-gray-900 mb-3 flex items-center">
          <Info className="w-5 h-5 mr-2 text-blue-500" />
          Recommendations
        </h3>
        <div className="space-y-2">
          {strideCoverage['Spoofing']?.count < 2 && (
            <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg text-sm text-blue-800">
              Add more Spoofing threats - consider authentication bypasses and identity impersonation risks
            </div>
          )}
          {strideCoverage['Information Disclosure']?.count < 2 && (
            <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg text-sm text-blue-800">
              Review Information Disclosure risks - check for data exposure, logging sensitive data, and insecure transmission
            </div>
          )}
          {threatQuality.mitigationRate < 80 && (
            <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg text-sm text-blue-800">
              Add mitigations for {100 - threatQuality.mitigationRate}% of threats without remediation plans
            </div>
          )}
          {standardsCoverage.cwePercentage < 50 && (
            <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg text-sm text-blue-800">
              Map threats to CWE identifiers for better vulnerability tracking and compliance reporting
            </div>
          )}
          {componentCoverage.uncovered.length > 0 && (
            <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg text-sm text-blue-800">
              Analyze {componentCoverage.uncovered.length} uncovered components for potential security risks
            </div>
          )}
          {overallScore.percentage >= 80 && (
            <div className="p-3 bg-green-50 border border-green-200 rounded-lg text-sm text-green-800 flex items-center">
              <CheckCircle className="w-4 h-4 mr-2" />
              Excellent threat model coverage! Consider periodic reviews as the architecture evolves.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
