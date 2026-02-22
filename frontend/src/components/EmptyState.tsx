import { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import {
  Shield, Search, Lock, Package, Bug, AlertTriangle,
  Play, LogIn, FolderOpen, FileCode, Scan
} from 'lucide-react'

interface EmptyStateProps {
  type: 'no-findings' | 'no-scans' | 'no-projects' | 'login-required' | 'filtered-empty' | 'scan-prompt'
  title?: string
  description?: string
  actionLabel?: string
  actionLink?: string
  onAction?: () => void
  icon?: ReactNode
  scanType?: 'sast' | 'sca' | 'secrets' | 'all'
}

const defaultIcons: Record<string, ReactNode> = {
  'no-findings': <Shield className="w-16 h-16 text-green-400" />,
  'no-scans': <Scan className="w-16 h-16 text-gray-300" />,
  'no-projects': <FolderOpen className="w-16 h-16 text-gray-300" />,
  'login-required': <Lock className="w-16 h-16 text-blue-400" />,
  'filtered-empty': <Search className="w-16 h-16 text-gray-300" />,
  'scan-prompt': <Play className="w-16 h-16 text-primary-400" />,
}

const scanTypeIcons: Record<string, ReactNode> = {
  'sast': <Bug className="w-16 h-16 text-blue-400" />,
  'sca': <Package className="w-16 h-16 text-purple-400" />,
  'secrets': <Lock className="w-16 h-16 text-red-400" />,
  'all': <Shield className="w-16 h-16 text-primary-400" />,
}

const defaultContent: Record<string, { title: string; description: string; actionLabel?: string }> = {
  'no-findings': {
    title: '✅ No Vulnerabilities Found',
    description: 'Great job! Your code is secure. No vulnerabilities were detected in the last scan.',
  },
  'no-scans': {
    title: '🔍 Run a Security Scan',
    description: 'No scans have been performed yet. Run a scan to detect security vulnerabilities in your code.',
    actionLabel: 'Run Scan',
  },
  'no-projects': {
    title: '📁 No Projects Yet',
    description: 'Create a project to start scanning your code for security vulnerabilities.',
    actionLabel: 'Create Project',
  },
  'login-required': {
    title: '🔐 Login Required',
    description: 'Please log in to view security findings and run scans.',
    actionLabel: 'Login',
  },
  'filtered-empty': {
    title: 'No Matching Results',
    description: 'No vulnerabilities match your current filters. Try adjusting the severity, scan type, or search query.',
    actionLabel: 'Clear Filters',
  },
  'scan-prompt': {
    title: '🔍 Ready to Scan',
    description: 'Click the button below to run a comprehensive security scan on your codebase.',
    actionLabel: 'Start Scan',
  },
}

export default function EmptyState({
  type,
  title,
  description,
  actionLabel,
  actionLink,
  onAction,
  icon,
  scanType,
}: EmptyStateProps) {
  const defaults = defaultContent[type]
  const displayIcon = icon || (scanType ? scanTypeIcons[scanType] : defaultIcons[type])
  const displayTitle = title || defaults.title
  const displayDescription = description || defaults.description
  const displayActionLabel = actionLabel || defaults.actionLabel

  return (
    <div className="card p-12 text-center">
      <div className="mx-auto mb-6">
        {displayIcon}
      </div>
      <h3 className="text-xl font-semibold text-gray-900 mb-3">{displayTitle}</h3>
      <p className="text-gray-600 max-w-md mx-auto mb-6">{displayDescription}</p>

      {displayActionLabel && (actionLink || onAction) && (
        <>
          {actionLink ? (
            <Link
              to={actionLink}
              className="inline-flex items-center px-6 py-3 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium"
            >
              {type === 'login-required' && <LogIn className="w-5 h-5 mr-2" />}
              {type === 'scan-prompt' && <Play className="w-5 h-5 mr-2" />}
              {type === 'no-projects' && <FolderOpen className="w-5 h-5 mr-2" />}
              {displayActionLabel}
            </Link>
          ) : (
            <button
              onClick={onAction}
              className="inline-flex items-center px-6 py-3 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium"
            >
              {type === 'scan-prompt' && <Play className="w-5 h-5 mr-2" />}
              {type === 'filtered-empty' && <Search className="w-5 h-5 mr-2" />}
              {displayActionLabel}
            </button>
          )}
        </>
      )}

      {type === 'no-findings' && (
        <div className="mt-6 flex items-center justify-center space-x-6 text-sm text-gray-500">
          <div className="flex items-center">
            <Bug className="w-4 h-4 mr-1 text-blue-500" />
            <span>SAST: Clean</span>
          </div>
          <div className="flex items-center">
            <Package className="w-4 h-4 mr-1 text-purple-500" />
            <span>SCA: Clean</span>
          </div>
          <div className="flex items-center">
            <Lock className="w-4 h-4 mr-1 text-red-500" />
            <span>Secrets: Clean</span>
          </div>
        </div>
      )}
    </div>
  )
}

// Specific empty states for scan types
export function SastEmptyState({ onScan }: { onScan?: () => void }) {
  return (
    <EmptyState
      type="scan-prompt"
      title="🔍 No SAST Findings"
      description="Run a Static Application Security Testing scan to detect code vulnerabilities like SQL injection, XSS, and more."
      actionLabel="Run SAST Scan"
      onAction={onScan}
      scanType="sast"
    />
  )
}

export function ScaEmptyState({ onScan }: { onScan?: () => void }) {
  return (
    <EmptyState
      type="scan-prompt"
      title="📦 No SCA Findings"
      description="Run a Software Composition Analysis scan to detect vulnerable dependencies and outdated packages."
      actionLabel="Run SCA Scan"
      onAction={onScan}
      scanType="sca"
    />
  )
}

export function SecretsEmptyState({ onScan }: { onScan?: () => void }) {
  return (
    <EmptyState
      type="scan-prompt"
      title="🔐 No Secrets Detected"
      description="Run a secrets scan to detect exposed API keys, passwords, and other sensitive credentials in your code."
      actionLabel="Run Secrets Scan"
      onAction={onScan}
      scanType="secrets"
    />
  )
}
