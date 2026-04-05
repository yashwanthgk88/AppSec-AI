import { useState } from 'react'
import { Zap, AlertTriangle, Package, Shield, ChevronDown, ChevronRight, FileText, Target, ExternalLink, CheckCircle, XCircle, Activity } from 'lucide-react'

interface ImportLocation {
  file: string
  line: number
  import_statement: string
  alias: string
  style: string
}

interface FunctionUsage {
  function: string
  full_call: string
  file: string
  line: number
  code: string
  context: string
  arguments: string
  confidence: string
  data_flow?: string
}

interface CallChainNode {
  type: 'entry_point' | 'function_call' | 'vulnerable_sink'
  label: string
  file: string
  line: number
  code_snippet: string
  children: CallChainNode[]
}

interface ReachabilityData {
  exploitability: 'exploitable' | 'potentially_exploitable' | 'imported_only' | 'not_reachable'
  confidence_score: number
  attack_vector: string
  recommendation: string
  should_fix: boolean
  fix_priority: string
  import_locations: ImportLocation[]
  vulnerable_function_usages: FunctionUsage[]
  call_chain: CallChainNode[]
}

interface ReachabilityAnalysisProps {
  reachabilityData: ReachabilityData | null
  vulnerabilityTitle: string
}

const EXPLOITABILITY_CONFIG = {
  exploitable: {
    label: 'Exploitable',
    color: 'bg-red-600 text-white',
    border: 'border-red-500',
    bg: 'bg-red-50',
    text: 'text-red-900',
    icon: Zap,
    description: 'Vulnerable function is actively called with user-controlled input',
  },
  potentially_exploitable: {
    label: 'Potentially Exploitable',
    color: 'bg-orange-500 text-white',
    border: 'border-orange-500',
    bg: 'bg-orange-50',
    text: 'text-orange-900',
    icon: AlertTriangle,
    description: 'Vulnerable function is used but exploitability depends on configuration',
  },
  imported_only: {
    label: 'Imported Only',
    color: 'bg-yellow-500 text-white',
    border: 'border-yellow-500',
    bg: 'bg-yellow-50',
    text: 'text-yellow-900',
    icon: Package,
    description: 'Package is present but vulnerable functions are not directly called',
  },
  not_reachable: {
    label: 'Not Reachable',
    color: 'bg-green-600 text-white',
    border: 'border-green-500',
    bg: 'bg-green-50',
    text: 'text-green-900',
    icon: Shield,
    description: 'Vulnerable code path is not reachable in this application',
  },
}

const PRIORITY_CONFIG: Record<string, { color: string; label: string }> = {
  immediate: { color: 'bg-red-100 text-red-800 border-red-300', label: 'Immediate' },
  high: { color: 'bg-orange-100 text-orange-800 border-orange-300', label: 'High' },
  medium: { color: 'bg-yellow-100 text-yellow-800 border-yellow-300', label: 'Medium' },
  low: { color: 'bg-green-100 text-green-800 border-green-300', label: 'Low' },
}

function CallChainTree({ node, depth = 0 }: { node: CallChainNode; depth?: number }) {
  const [expanded, setExpanded] = useState(true)
  const hasChildren = node.children && node.children.length > 0

  const nodeStyles = {
    entry_point: {
      bg: 'bg-blue-50 border-blue-300',
      icon: 'bg-blue-600',
      dot: 'bg-blue-500',
      label: 'text-blue-900',
    },
    function_call: {
      bg: 'bg-orange-50 border-orange-300',
      icon: 'bg-orange-500',
      dot: 'bg-orange-500',
      label: 'text-orange-900',
    },
    vulnerable_sink: {
      bg: 'bg-red-50 border-red-400',
      icon: 'bg-red-600',
      dot: 'bg-red-600',
      label: 'text-red-900',
    },
  }

  const style = nodeStyles[node.type] || nodeStyles.function_call

  return (
    <div className={depth > 0 ? 'ml-6' : ''}>
      {/* Connector line */}
      {depth > 0 && (
        <div className="flex items-center ml-3 -mt-1 mb-1">
          <div className="w-px h-4 bg-gray-300" />
          <div className="w-3 h-px bg-gray-300" />
          <ChevronDown className="w-3 h-3 text-gray-400 -ml-0.5" />
        </div>
      )}

      <div
        className={`border rounded-lg p-3 ${style.bg} cursor-pointer hover:shadow-md transition`}
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start space-x-3">
          {/* Node type indicator */}
          <div className={`w-2.5 h-2.5 rounded-full mt-1.5 flex-shrink-0 ${style.dot}`} />

          <div className="flex-1 min-w-0">
            <div className="flex items-center space-x-2 mb-1">
              <span className={`text-xs font-semibold uppercase ${style.label}`}>
                {node.type === 'entry_point' ? 'Entry Point' :
                 node.type === 'vulnerable_sink' ? 'Vulnerable Sink' :
                 'Function Call'}
              </span>
              {hasChildren && (
                expanded ?
                  <ChevronDown className="w-3 h-3 text-gray-500" /> :
                  <ChevronRight className="w-3 h-3 text-gray-500" />
              )}
            </div>
            <p className={`text-sm font-medium ${style.label}`}>{node.label}</p>
            {node.file && (
              <p className="text-xs text-gray-600 font-mono mt-1">
                {node.file}{node.line > 0 ? `:${node.line}` : ''}
              </p>
            )}
            {expanded && node.code_snippet && (
              <div className="mt-2 bg-gray-900 rounded p-2 overflow-x-auto">
                <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap">{node.code_snippet}</pre>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Children */}
      {expanded && hasChildren && (
        <div>
          {node.children.map((child, idx) => (
            <CallChainTree key={idx} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  )
}

export default function ReachabilityAnalysis({ reachabilityData, vulnerabilityTitle }: ReachabilityAnalysisProps) {
  const [showAllUsages, setShowAllUsages] = useState(false)

  if (!reachabilityData) {
    return (
      <div className="text-center py-8 text-gray-500">
        <Target className="w-12 h-12 mx-auto mb-2 opacity-50" />
        <p>Reachability analysis data not available</p>
      </div>
    )
  }

  const config = EXPLOITABILITY_CONFIG[reachabilityData.exploitability] || EXPLOITABILITY_CONFIG.not_reachable
  const ExploitIcon = config.icon
  const priorityConfig = PRIORITY_CONFIG[reachabilityData.fix_priority] || PRIORITY_CONFIG.low

  return (
    <div className="space-y-4">
      {/* Exploitability Header */}
      <div className={`${config.bg} border-l-4 ${config.border} rounded-r-lg p-4`}>
        <div className="flex items-start justify-between">
          <div className="flex items-start space-x-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${config.color}`}>
              <ExploitIcon className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2 mb-1">
                <span className={`px-3 py-1 rounded-full text-sm font-bold ${config.color}`}>
                  {config.label}
                </span>
                <span className={`px-2 py-0.5 rounded text-xs font-medium border ${priorityConfig.color}`}>
                  Fix Priority: {priorityConfig.label}
                </span>
              </div>
              <p className={`text-sm ${config.text}`}>{config.description}</p>
            </div>
          </div>

          {/* Confidence Score */}
          <div className="text-right flex-shrink-0 ml-4">
            <p className="text-xs text-gray-500 font-medium">Confidence</p>
            <p className="text-2xl font-bold text-gray-900">
              {Math.round(reachabilityData.confidence_score * 100)}%
            </p>
            <div className="w-20 h-1.5 bg-gray-200 rounded-full mt-1">
              <div
                className={`h-1.5 rounded-full ${
                  reachabilityData.confidence_score >= 0.8 ? 'bg-green-500' :
                  reachabilityData.confidence_score >= 0.6 ? 'bg-yellow-500' : 'bg-red-500'
                }`}
                style={{ width: `${reachabilityData.confidence_score * 100}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Fix Guidance */}
      <div className={`rounded-lg p-4 ${reachabilityData.should_fix ? 'bg-red-50 border border-red-200' : 'bg-green-50 border border-green-200'}`}>
        <div className="flex items-start space-x-3">
          {reachabilityData.should_fix ? (
            <XCircle className="w-5 h-5 text-red-600 mt-0.5 flex-shrink-0" />
          ) : (
            <CheckCircle className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
          )}
          <div>
            <h4 className={`text-sm font-bold ${reachabilityData.should_fix ? 'text-red-900' : 'text-green-900'}`}>
              {reachabilityData.should_fix ? 'Fix Required' : 'No Immediate Fix Needed'}
            </h4>
            <p className={`text-sm mt-1 ${reachabilityData.should_fix ? 'text-red-800' : 'text-green-800'}`}>
              {reachabilityData.recommendation}
            </p>
          </div>
        </div>
      </div>

      {/* Call Chain Tree View */}
      {reachabilityData.call_chain.length > 0 && (
        <div className="border border-gray-200 rounded-lg overflow-hidden">
          <div className="bg-gradient-to-r from-indigo-50 to-purple-50 px-4 py-3 border-b border-gray-200">
            <div className="flex items-center space-x-2">
              <Activity className="w-5 h-5 text-indigo-600" />
              <h4 className="font-semibold text-gray-900">Reachability Call Chain</h4>
              <span className="text-xs text-gray-500">
                ({reachabilityData.call_chain.length} entry point{reachabilityData.call_chain.length > 1 ? 's' : ''})
              </span>
            </div>
            <p className="text-xs text-gray-600 mt-1">
              Trace from HTTP entry points through to vulnerable library function calls
            </p>
          </div>
          <div className="p-4 space-y-4">
            {reachabilityData.call_chain.map((chain, idx) => (
              <CallChainTree key={idx} node={chain} />
            ))}
          </div>
        </div>
      )}

      {/* Vulnerable Function Usages */}
      {reachabilityData.vulnerable_function_usages.length > 0 && (
        <div className="border border-red-200 rounded-lg overflow-hidden">
          <div className="bg-red-50 px-4 py-3 border-b border-red-200">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Zap className="w-5 h-5 text-red-600" />
                <h4 className="font-semibold text-red-900">Vulnerable Function Usages</h4>
                <span className="text-xs bg-red-100 text-red-700 px-2 py-0.5 rounded-full">
                  {reachabilityData.vulnerable_function_usages.length} found
                </span>
              </div>
              {reachabilityData.vulnerable_function_usages.length > 2 && (
                <button
                  onClick={() => setShowAllUsages(!showAllUsages)}
                  className="text-xs text-red-700 hover:text-red-900 font-medium"
                >
                  {showAllUsages ? 'Show less' : 'Show all'}
                </button>
              )}
            </div>
          </div>
          <div className="divide-y divide-red-100">
            {(showAllUsages
              ? reachabilityData.vulnerable_function_usages
              : reachabilityData.vulnerable_function_usages.slice(0, 2)
            ).map((usage, idx) => (
              <div key={idx} className="p-4">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono bg-red-100 text-red-700 px-2 py-0.5 rounded font-bold">
                      {usage.function}
                    </span>
                    <span className={`text-xs px-1.5 py-0.5 rounded ${
                      usage.confidence === 'high' ? 'bg-green-100 text-green-700' :
                      usage.confidence === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                      'bg-gray-100 text-gray-700'
                    }`}>
                      {usage.confidence} confidence
                    </span>
                  </div>
                </div>

                <p className="text-xs font-mono text-gray-600 mb-2">
                  <FileText className="w-3 h-3 inline mr-1" />
                  {usage.file}:{usage.line}
                </p>

                {/* Code context */}
                <div className="bg-gray-900 rounded p-3 overflow-x-auto mb-2">
                  <pre className="text-xs font-mono whitespace-pre-wrap">
                    {usage.context.split('\n').map((line: string, lineIdx: number) => {
                      const isVulnLine = line.includes(usage.code.trim().substring(0, 30))
                      return (
                        <span key={lineIdx} className={isVulnLine ? 'text-red-400 font-bold' : 'text-gray-400'}>
                          {line}{'\n'}
                        </span>
                      )
                    })}
                  </pre>
                </div>

                {/* Data flow */}
                {usage.data_flow && (
                  <div className="bg-orange-50 border border-orange-200 rounded p-2 mt-2">
                    <p className="text-xs text-orange-900">
                      <span className="font-semibold">Data flow: </span>
                      {usage.data_flow}
                    </p>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Import Locations */}
      {reachabilityData.import_locations.length > 0 && (
        <div className="border border-gray-200 rounded-lg overflow-hidden">
          <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
            <div className="flex items-center space-x-2">
              <Package className="w-4 h-4 text-purple-600" />
              <h4 className="text-sm font-semibold text-gray-900">Import Locations</h4>
              <span className="text-xs text-gray-500">
                ({reachabilityData.import_locations.length} file{reachabilityData.import_locations.length > 1 ? 's' : ''})
              </span>
            </div>
          </div>
          <div className="divide-y divide-gray-100">
            {reachabilityData.import_locations.map((imp, idx) => (
              <div key={idx} className="px-4 py-2 flex items-center space-x-3">
                <FileText className="w-4 h-4 text-gray-400 flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-mono text-gray-700 truncate">
                    {imp.file}{imp.line > 0 ? `:${imp.line}` : ''}
                  </p>
                  <p className="text-xs text-gray-500 font-mono truncate">{imp.import_statement}</p>
                </div>
                {imp.alias && imp.alias !== 'N/A' && (
                  <span className="text-xs bg-purple-100 text-purple-700 px-2 py-0.5 rounded flex-shrink-0">
                    as {imp.alias}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Attack Vector */}
      <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
        <div className="flex items-center space-x-2 mb-2">
          <Target className="w-4 h-4 text-gray-600" />
          <h4 className="text-sm font-semibold text-gray-900">Attack Vector</h4>
        </div>
        <p className="text-sm text-gray-700">{reachabilityData.attack_vector}</p>
      </div>
    </div>
  )
}
