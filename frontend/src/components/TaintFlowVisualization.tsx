/**
 * TaintFlowVisualization Component
 *
 * Professional interactive visualization for data flow and taint analysis.
 * Helps security testers understand how untrusted data flows through the application.
 */

import { useState } from 'react'
import {
  GitBranch,
  AlertTriangle,
  Shield,
  Target,
  ArrowDown,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Code,
  FileText,
  Zap,
  Eye,
  Copy,
  Check,
  ExternalLink,
  Info,
  Database,
  Globe,
  Terminal,
  Lock
} from 'lucide-react'

// Types for taint flow data
export interface TaintPathNode {
  id: string
  type: 'source' | 'propagator' | 'sink' | 'sanitizer'
  description: string
  location: {
    file: string
    startLine: number
    endLine: number
    startColumn: number
    endColumn: number
  }
  codeSnippet?: string
  variableName?: string
  functionName?: string
  nodeKind?: string  // e.g., 'CallExpression', 'Assignment', etc.
}

export interface TaintFlow {
  id: string
  source: TaintPathNode
  sink: TaintPathNode
  path: TaintPathNode[]
  sanitizers: Array<{
    name: string
    effective: boolean
    location: TaintPathNode['location']
  }>
  confidence: 'high' | 'medium' | 'low'
  dataType?: string  // e.g., 'user_input', 'http_request', 'database_query'
}

export interface TaintFlowVisualizationProps {
  taintFlow?: TaintFlow
  vulnerabilityType?: string
  cweId?: string
  showDataFlowDetails?: boolean
  showControlFlowDetails?: boolean
}

const nodeTypeConfig = {
  source: {
    icon: Target,
    color: 'red',
    bgColor: 'bg-red-50',
    borderColor: 'border-red-500',
    textColor: 'text-red-900',
    badgeColor: 'bg-red-600',
    label: 'TAINT SOURCE',
    description: 'Untrusted data enters the application here'
  },
  propagator: {
    icon: ArrowRight,
    color: 'yellow',
    bgColor: 'bg-amber-50',
    borderColor: 'border-amber-400',
    textColor: 'text-amber-900',
    badgeColor: 'bg-amber-500',
    label: 'PROPAGATION',
    description: 'Data flows through this point'
  },
  sink: {
    icon: AlertTriangle,
    color: 'orange',
    bgColor: 'bg-orange-50',
    borderColor: 'border-orange-500',
    textColor: 'text-orange-900',
    badgeColor: 'bg-orange-600',
    label: 'TAINT SINK',
    description: 'Dangerous operation - vulnerability occurs here'
  },
  sanitizer: {
    icon: Shield,
    color: 'green',
    bgColor: 'bg-green-50',
    borderColor: 'border-green-500',
    textColor: 'text-green-900',
    badgeColor: 'bg-green-600',
    label: 'SANITIZER',
    description: 'Data is cleaned/validated here'
  }
}

// Generate sample taint flow for demo/testing when real data isn't available
function generateSampleTaintFlow(vulnerabilityType?: string): TaintFlow {
  const type = vulnerabilityType?.toLowerCase() || 'sql-injection'

  if (type.includes('sql')) {
    return {
      id: 'sample-sql-1',
      source: {
        id: 'src-1',
        type: 'source',
        description: 'HTTP request parameter received',
        location: { file: 'controllers/UserController.js', startLine: 15, endLine: 15, startColumn: 8, endColumn: 45 },
        codeSnippet: 'const userId = req.query.userId;',
        variableName: 'userId',
        functionName: 'getUserData',
        nodeKind: 'VariableDeclaration'
      },
      sink: {
        id: 'sink-1',
        type: 'sink',
        description: 'SQL query executed with untrusted data',
        location: { file: 'controllers/UserController.js', startLine: 22, endLine: 22, startColumn: 4, endColumn: 65 },
        codeSnippet: 'const query = "SELECT * FROM users WHERE id = " + userId;',
        variableName: 'query',
        functionName: 'db.execute',
        nodeKind: 'CallExpression'
      },
      path: [
        {
          id: 'path-1',
          type: 'source',
          description: 'User input from HTTP query parameter',
          location: { file: 'controllers/UserController.js', startLine: 15, endLine: 15, startColumn: 8, endColumn: 45 },
          codeSnippet: 'const userId = req.query.userId;',
          variableName: 'userId',
          nodeKind: 'VariableDeclaration'
        },
        {
          id: 'path-2',
          type: 'propagator',
          description: 'Variable assigned to new identifier',
          location: { file: 'controllers/UserController.js', startLine: 18, endLine: 18, startColumn: 4, endColumn: 28 },
          codeSnippet: 'const id = userId;',
          variableName: 'id',
          nodeKind: 'Assignment'
        },
        {
          id: 'path-3',
          type: 'propagator',
          description: 'String concatenation with tainted data',
          location: { file: 'controllers/UserController.js', startLine: 22, endLine: 22, startColumn: 4, endColumn: 65 },
          codeSnippet: 'const query = "SELECT * FROM users WHERE id = " + userId;',
          variableName: 'query',
          nodeKind: 'BinaryExpression'
        },
        {
          id: 'path-4',
          type: 'sink',
          description: 'Database query execution with unsanitized input',
          location: { file: 'controllers/UserController.js', startLine: 23, endLine: 23, startColumn: 4, endColumn: 25 },
          codeSnippet: 'db.execute(query);',
          functionName: 'db.execute',
          nodeKind: 'CallExpression'
        }
      ],
      sanitizers: [],
      confidence: 'high',
      dataType: 'user_input'
    }
  } else if (type.includes('xss') || type.includes('cross-site')) {
    return {
      id: 'sample-xss-1',
      source: {
        id: 'src-1',
        type: 'source',
        description: 'User input from form field',
        location: { file: 'views/CommentView.jsx', startLine: 12, endLine: 12, startColumn: 4, endColumn: 42 },
        codeSnippet: 'const message = req.body.message;',
        variableName: 'message',
        nodeKind: 'VariableDeclaration'
      },
      sink: {
        id: 'sink-1',
        type: 'sink',
        description: 'innerHTML assignment allows script injection',
        location: { file: 'views/CommentView.jsx', startLine: 28, endLine: 28, startColumn: 4, endColumn: 48 },
        codeSnippet: "document.getElementById('output').innerHTML = message;",
        variableName: 'innerHTML',
        nodeKind: 'AssignmentExpression'
      },
      path: [
        {
          id: 'path-1',
          type: 'source',
          description: 'User-controlled input from POST body',
          location: { file: 'views/CommentView.jsx', startLine: 12, endLine: 12, startColumn: 4, endColumn: 42 },
          codeSnippet: 'const message = req.body.message;',
          variableName: 'message',
          nodeKind: 'VariableDeclaration'
        },
        {
          id: 'path-2',
          type: 'propagator',
          description: 'Data passed to render function',
          location: { file: 'views/CommentView.jsx', startLine: 20, endLine: 20, startColumn: 8, endColumn: 35 },
          codeSnippet: 'displayMessage(message);',
          functionName: 'displayMessage',
          nodeKind: 'CallExpression'
        },
        {
          id: 'path-3',
          type: 'sink',
          description: 'Direct DOM manipulation without encoding',
          location: { file: 'views/CommentView.jsx', startLine: 28, endLine: 28, startColumn: 4, endColumn: 48 },
          codeSnippet: "document.getElementById('output').innerHTML = message;",
          nodeKind: 'AssignmentExpression'
        }
      ],
      sanitizers: [],
      confidence: 'high',
      dataType: 'user_input'
    }
  }

  // Default generic flow
  return {
    id: 'sample-generic-1',
    source: {
      id: 'src-1',
      type: 'source',
      description: 'External input received',
      location: { file: 'app.js', startLine: 10, endLine: 10, startColumn: 0, endColumn: 30 },
      codeSnippet: 'const input = getExternalData();',
      variableName: 'input',
      nodeKind: 'VariableDeclaration'
    },
    sink: {
      id: 'sink-1',
      type: 'sink',
      description: 'Dangerous operation executed',
      location: { file: 'app.js', startLine: 25, endLine: 25, startColumn: 0, endColumn: 25 },
      codeSnippet: 'execute(input);',
      functionName: 'execute',
      nodeKind: 'CallExpression'
    },
    path: [
      {
        id: 'path-1',
        type: 'source',
        description: 'External data source',
        location: { file: 'app.js', startLine: 10, endLine: 10, startColumn: 0, endColumn: 30 },
        codeSnippet: 'const input = getExternalData();',
        variableName: 'input',
        nodeKind: 'VariableDeclaration'
      },
      {
        id: 'path-2',
        type: 'sink',
        description: 'Unsafe execution',
        location: { file: 'app.js', startLine: 25, endLine: 25, startColumn: 0, endColumn: 25 },
        codeSnippet: 'execute(input);',
        nodeKind: 'CallExpression'
      }
    ],
    sanitizers: [],
    confidence: 'medium',
    dataType: 'external_input'
  }
}

export default function TaintFlowVisualization({
  taintFlow,
  vulnerabilityType,
  cweId,
  showDataFlowDetails = true,
  showControlFlowDetails = true
}: TaintFlowVisualizationProps) {
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set())
  const [copiedCode, setCopiedCode] = useState<string | null>(null)
  const [viewMode, setViewMode] = useState<'flow' | 'list' | 'graph'>('flow')

  // Use sample data if no taint flow provided
  const flow = taintFlow || generateSampleTaintFlow(vulnerabilityType)

  const toggleNode = (nodeId: string) => {
    const newExpanded = new Set(expandedNodes)
    if (newExpanded.has(nodeId)) {
      newExpanded.delete(nodeId)
    } else {
      newExpanded.add(nodeId)
    }
    setExpandedNodes(newExpanded)
  }

  const handleCopyCode = (code: string, nodeId: string) => {
    navigator.clipboard.writeText(code)
    setCopiedCode(nodeId)
    setTimeout(() => setCopiedCode(null), 2000)
  }

  const getDataTypeIcon = (dataType?: string) => {
    switch (dataType) {
      case 'user_input': return Globe
      case 'http_request': return Globe
      case 'database_query': return Database
      case 'file_system': return FileText
      case 'command_execution': return Terminal
      default: return Zap
    }
  }

  const DataTypeIcon = getDataTypeIcon(flow.dataType)

  return (
    <div className="bg-gradient-to-br from-slate-50 to-slate-100 rounded-xl border border-slate-200 overflow-hidden">
      {/* Header */}
      <div className="bg-gradient-to-r from-slate-800 to-slate-900 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-white/10 rounded-lg">
              <GitBranch className="w-6 h-6 text-white" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">Taint Flow Analysis</h3>
              <p className="text-sm text-slate-300">Data Flow & Control Flow Visualization</p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            {/* Confidence Badge */}
            <div className={`px-3 py-1.5 rounded-full text-xs font-bold ${
              flow.confidence === 'high' ? 'bg-red-500 text-white' :
              flow.confidence === 'medium' ? 'bg-yellow-500 text-black' :
              'bg-blue-500 text-white'
            }`}>
              {flow.confidence.toUpperCase()} CONFIDENCE
            </div>

            {/* View Mode Toggle */}
            <div className="flex bg-white/10 rounded-lg p-1">
              {(['flow', 'list', 'graph'] as const).map((mode) => (
                <button
                  key={mode}
                  onClick={() => setViewMode(mode)}
                  className={`px-3 py-1 text-xs font-medium rounded transition ${
                    viewMode === mode
                      ? 'bg-white text-slate-900'
                      : 'text-white/70 hover:text-white'
                  }`}
                >
                  {mode.charAt(0).toUpperCase() + mode.slice(1)}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-4 gap-4 p-4 bg-white border-b border-slate-200">
        <div className="text-center p-3 rounded-lg bg-red-50 border border-red-200">
          <Target className="w-5 h-5 text-red-600 mx-auto mb-1" />
          <div className="text-2xl font-bold text-red-700">1</div>
          <div className="text-xs text-red-600 font-medium">Source</div>
        </div>
        <div className="text-center p-3 rounded-lg bg-amber-50 border border-amber-200">
          <ArrowRight className="w-5 h-5 text-amber-600 mx-auto mb-1" />
          <div className="text-2xl font-bold text-amber-700">{flow.path.filter(n => n.type === 'propagator').length}</div>
          <div className="text-xs text-amber-600 font-medium">Propagators</div>
        </div>
        <div className="text-center p-3 rounded-lg bg-green-50 border border-green-200">
          <Shield className="w-5 h-5 text-green-600 mx-auto mb-1" />
          <div className="text-2xl font-bold text-green-700">{flow.sanitizers.length}</div>
          <div className="text-xs text-green-600 font-medium">Sanitizers</div>
        </div>
        <div className="text-center p-3 rounded-lg bg-orange-50 border border-orange-200">
          <AlertTriangle className="w-5 h-5 text-orange-600 mx-auto mb-1" />
          <div className="text-2xl font-bold text-orange-700">1</div>
          <div className="text-xs text-orange-600 font-medium">Sink</div>
        </div>
      </div>

      {/* Data Type Info */}
      <div className="px-4 py-3 bg-blue-50 border-b border-blue-200 flex items-center space-x-3">
        <DataTypeIcon className="w-5 h-5 text-blue-600" />
        <div>
          <span className="text-sm font-medium text-blue-900">Data Type: </span>
          <span className="text-sm text-blue-700">{flow.dataType?.replace(/_/g, ' ').toUpperCase() || 'EXTERNAL INPUT'}</span>
        </div>
        {cweId && (
          <a
            href={`https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html`}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-auto text-sm text-blue-600 hover:text-blue-800 flex items-center"
          >
            {cweId} Reference <ExternalLink className="w-3 h-3 ml-1" />
          </a>
        )}
      </div>

      {/* Flow Visualization */}
      <div className="p-6">
        {viewMode === 'flow' && (
          <div className="space-y-0">
            {flow.path.map((node, index) => {
              const config = nodeTypeConfig[node.type]
              const NodeIcon = config.icon
              const isExpanded = expandedNodes.has(node.id)
              const isLast = index === flow.path.length - 1

              return (
                <div key={node.id} className="relative">
                  {/* Connector Line */}
                  {!isLast && (
                    <div className="absolute left-5 top-14 bottom-0 w-0.5 bg-gradient-to-b from-slate-300 to-slate-400 z-0" />
                  )}

                  {/* Node Card */}
                  <div className={`relative z-10 ${config.bgColor} border-l-4 ${config.borderColor} rounded-r-lg mb-4 overflow-hidden shadow-sm`}>
                    {/* Node Header */}
                    <button
                      onClick={() => toggleNode(node.id)}
                      className="w-full px-4 py-3 flex items-start space-x-3 hover:bg-white/50 transition text-left"
                    >
                      {/* Step Number & Icon */}
                      <div className={`flex-shrink-0 w-10 h-10 ${config.badgeColor} rounded-full flex items-center justify-center text-white font-bold text-sm`}>
                        {index + 1}
                      </div>

                      <div className="flex-1 min-w-0">
                        {/* Type Badge */}
                        <div className="flex items-center space-x-2 mb-1">
                          <span className={`text-xs font-bold ${config.textColor} uppercase tracking-wide`}>
                            {config.label}
                          </span>
                          <NodeIcon className={`w-4 h-4 ${config.textColor}`} />
                        </div>

                        {/* Description */}
                        <p className={`text-sm font-medium ${config.textColor}`}>
                          {node.description}
                        </p>

                        {/* Location */}
                        <div className="flex items-center space-x-2 mt-1">
                          <FileText className="w-3 h-3 text-slate-500" />
                          <span className="text-xs font-mono text-slate-600">
                            {node.location.file}:{node.location.startLine}
                          </span>
                          {node.variableName && (
                            <span className="text-xs bg-slate-200 px-1.5 py-0.5 rounded font-mono">
                              {node.variableName}
                            </span>
                          )}
                          {node.functionName && (
                            <span className="text-xs bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded font-mono">
                              {node.functionName}()
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Expand/Collapse */}
                      <div className="flex-shrink-0">
                        {isExpanded ? (
                          <ChevronUp className="w-5 h-5 text-slate-400" />
                        ) : (
                          <ChevronDown className="w-5 h-5 text-slate-400" />
                        )}
                      </div>
                    </button>

                    {/* Expanded Details */}
                    {isExpanded && (
                      <div className="px-4 pb-4 border-t border-slate-200 bg-white/80">
                        {/* Code Snippet */}
                        {node.codeSnippet && (
                          <div className="mt-3">
                            <div className="flex items-center justify-between mb-2">
                              <div className="flex items-center space-x-2">
                                <Code className="w-4 h-4 text-slate-600" />
                                <span className="text-xs font-semibold text-slate-700 uppercase">Code</span>
                              </div>
                              <button
                                onClick={() => handleCopyCode(node.codeSnippet!, node.id)}
                                className="flex items-center space-x-1 text-xs text-slate-500 hover:text-slate-700"
                              >
                                {copiedCode === node.id ? (
                                  <>
                                    <Check className="w-3 h-3" />
                                    <span>Copied</span>
                                  </>
                                ) : (
                                  <>
                                    <Copy className="w-3 h-3" />
                                    <span>Copy</span>
                                  </>
                                )}
                              </button>
                            </div>
                            <div className="bg-slate-900 rounded-lg p-3 overflow-x-auto">
                              <pre className="text-sm text-green-400 font-mono">
                                <span className="text-slate-500 select-none">{node.location.startLine} | </span>
                                {node.codeSnippet}
                              </pre>
                            </div>
                          </div>
                        )}

                        {/* Technical Details */}
                        <div className="mt-3 grid grid-cols-2 gap-3">
                          {node.nodeKind && (
                            <div className="bg-slate-100 rounded p-2">
                              <span className="text-xs text-slate-500 block">AST Node Type</span>
                              <span className="text-sm font-mono text-slate-800">{node.nodeKind}</span>
                            </div>
                          )}
                          <div className="bg-slate-100 rounded p-2">
                            <span className="text-xs text-slate-500 block">Location</span>
                            <span className="text-sm font-mono text-slate-800">
                              L{node.location.startLine}:C{node.location.startColumn}
                            </span>
                          </div>
                        </div>

                        {/* Info Box */}
                        <div className="mt-3 flex items-start space-x-2 p-3 bg-blue-50 rounded-lg border border-blue-200">
                          <Info className="w-4 h-4 text-blue-600 flex-shrink-0 mt-0.5" />
                          <p className="text-xs text-blue-800">{config.description}</p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {viewMode === 'list' && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-slate-100">
                  <th className="px-4 py-2 text-left font-semibold text-slate-700">Step</th>
                  <th className="px-4 py-2 text-left font-semibold text-slate-700">Type</th>
                  <th className="px-4 py-2 text-left font-semibold text-slate-700">Description</th>
                  <th className="px-4 py-2 text-left font-semibold text-slate-700">Location</th>
                  <th className="px-4 py-2 text-left font-semibold text-slate-700">Variable</th>
                </tr>
              </thead>
              <tbody>
                {flow.path.map((node, index) => {
                  const config = nodeTypeConfig[node.type]
                  return (
                    <tr key={node.id} className={`border-b ${config.bgColor}`}>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center justify-center w-6 h-6 ${config.badgeColor} text-white rounded-full text-xs font-bold`}>
                          {index + 1}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-bold ${config.textColor} uppercase`}>
                          {node.type}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-800">{node.description}</td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-600">
                        {node.location.file}:{node.location.startLine}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">
                        {node.variableName || '-'}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {viewMode === 'graph' && (
          <div className="flex items-center justify-center py-8">
            <div className="flex items-center space-x-4">
              {flow.path.map((node, index) => {
                const config = nodeTypeConfig[node.type]
                const NodeIcon = config.icon
                const isLast = index === flow.path.length - 1

                return (
                  <div key={node.id} className="flex items-center">
                    {/* Node */}
                    <div
                      className={`relative group cursor-pointer ${config.bgColor} border-2 ${config.borderColor} rounded-full p-4 hover:scale-110 transition-transform`}
                      title={node.description}
                    >
                      <NodeIcon className={`w-6 h-6 ${config.textColor}`} />
                      <span className={`absolute -top-2 -right-2 w-5 h-5 ${config.badgeColor} text-white rounded-full text-xs flex items-center justify-center font-bold`}>
                        {index + 1}
                      </span>

                      {/* Tooltip */}
                      <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-20">
                        <div className="bg-slate-900 text-white text-xs rounded px-3 py-2 whitespace-nowrap">
                          <div className="font-bold">{config.label}</div>
                          <div className="text-slate-300">{node.description}</div>
                        </div>
                      </div>
                    </div>

                    {/* Arrow */}
                    {!isLast && (
                      <div className="flex items-center mx-2">
                        <div className="w-8 h-0.5 bg-slate-400" />
                        <ArrowRight className="w-4 h-4 text-slate-400 -ml-1" />
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Sanitizers Section */}
      {flow.sanitizers.length > 0 && (
        <div className="p-4 border-t border-slate-200 bg-green-50">
          <h4 className="text-sm font-bold text-green-900 mb-3 flex items-center">
            <Shield className="w-4 h-4 mr-2" />
            Detected Sanitizers
          </h4>
          <div className="space-y-2">
            {flow.sanitizers.map((sanitizer, index) => (
              <div
                key={index}
                className={`p-3 rounded-lg border ${
                  sanitizer.effective
                    ? 'bg-green-100 border-green-300'
                    : 'bg-yellow-100 border-yellow-300'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    {sanitizer.effective ? (
                      <Lock className="w-4 h-4 text-green-600" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-yellow-600" />
                    )}
                    <span className="font-mono text-sm">{sanitizer.name}</span>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    sanitizer.effective
                      ? 'bg-green-600 text-white'
                      : 'bg-yellow-600 text-white'
                  }`}>
                    {sanitizer.effective ? 'EFFECTIVE' : 'INSUFFICIENT'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* No Sanitizers Warning */}
      {flow.sanitizers.length === 0 && (
        <div className="p-4 border-t border-red-200 bg-red-50">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0" />
            <div>
              <h4 className="text-sm font-bold text-red-900">No Sanitization Detected</h4>
              <p className="text-xs text-red-700 mt-1">
                The tainted data flows from source to sink without any validation or sanitization.
                This creates a direct vulnerability path that should be remediated.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="px-4 py-3 bg-slate-100 border-t border-slate-200">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center space-x-4 text-xs">
            {Object.entries(nodeTypeConfig).map(([type, config]) => {
              const Icon = config.icon
              return (
                <div key={type} className="flex items-center space-x-1.5">
                  <div className={`w-3 h-3 rounded-full ${config.badgeColor}`} />
                  <Icon className="w-3 h-3 text-slate-600" />
                  <span className="text-slate-600">{config.label}</span>
                </div>
              )
            })}
          </div>
          <div className="text-xs text-slate-500">
            Click on any node to expand details
          </div>
        </div>
      </div>
    </div>
  )
}
