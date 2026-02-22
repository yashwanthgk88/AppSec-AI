import React, { useState, useEffect } from 'react';
import {
  Clock,
  GitBranch,
  ChevronDown,
  ChevronUp,
  ArrowRight,
  Activity,
  FileText,
  AlertCircle,
  CheckCircle,
  Plus,
  Minus,
  User,
  Shield,
  TrendingUp,
  Sparkles
} from 'lucide-react';
import { ThreatStatusBadge, ThreatStatus } from './ThreatStatusBadge';
import { API_URL } from '../config/api';

// Types
interface UserInfo {
  id: number;
  username: string;
  email: string;
}

interface ThreatStats {
  new: number;
  existing: number;
  modified: number;
  resolved: number;
  total: number;
}

interface ArchitectureVersion {
  id: number;
  version_number: number;
  architecture_hash: string;
  change_summary: {
    added_components: string[];
    removed_components: string[];
    modified_components: string[];
    added_flows: string[];
    removed_flows: string[];
    modified_flows: string[];
    total_changes: number;
    impact_score: number;
    has_security_relevant_changes: boolean;
  };
  change_description: string;
  impact_score: number;
  created_at: string;
  created_by?: number;
  user?: UserInfo;
  threat_stats?: ThreatStats;
  diagram_preview?: string;
}

interface ThreatTimelineEntry {
  version: number;
  status: ThreatStatus;
  timestamp: string;
  architecture_version_id: number;
  change_reason?: string;
  threat_data: any;
  previous_status?: ThreatStatus;
  transition?: string;
}

interface ThreatHistoryPanelProps {
  projectId: number;
  token: string;
  onVersionSelect?: (versionId: number) => void;
  currentVersionId?: number;
}

// API functions
const fetchVersionHistory = async (projectId: number, token: string, limit: number = 10) => {
  const response = await fetch(
    `${API_URL}/api/projects/${projectId}/threat-model/history?limit=${limit}`,
    {
      headers: { Authorization: `Bearer ${token}` }
    }
  );
  if (!response.ok) throw new Error('Failed to fetch history');
  return response.json();
};

const fetchThreatTimeline = async (projectId: number, threatId: string, token: string) => {
  const response = await fetch(
    `${API_URL}/api/projects/${projectId}/threats/${threatId}/timeline`,
    {
      headers: { Authorization: `Bearer ${token}` }
    }
  );
  if (!response.ok) throw new Error('Failed to fetch timeline');
  return response.json();
};

const fetchVersionDiff = async (projectId: number, v1: number, v2: number, token: string) => {
  const response = await fetch(
    `${API_URL}/api/projects/${projectId}/threat-model/diff/${v1}/${v2}`,
    {
      headers: { Authorization: `Bearer ${token}` }
    }
  );
  if (!response.ok) throw new Error('Failed to fetch diff');
  return response.json();
};

// Version History Panel Component
export const ThreatHistoryPanel: React.FC<ThreatHistoryPanelProps> = ({
  projectId,
  token,
  onVersionSelect,
  currentVersionId
}) => {
  const [versions, setVersions] = useState<ArchitectureVersion[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedVersion, setExpandedVersion] = useState<number | null>(null);

  useEffect(() => {
    const loadHistory = async () => {
      try {
        setLoading(true);
        const data = await fetchVersionHistory(projectId, token);
        setVersions(data.versions || []);
      } catch (e: any) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    };

    loadHistory();
  }, [projectId, token]);

  if (loading) {
    return (
      <div className="p-4 text-center text-gray-500">
        <Activity className="w-5 h-5 animate-spin mx-auto mb-2" />
        Loading history...
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 text-center text-red-500">
        <AlertCircle className="w-5 h-5 mx-auto mb-2" />
        {error}
      </div>
    );
  }

  if (versions.length === 0) {
    return (
      <div className="p-4 text-center text-gray-500">
        <FileText className="w-5 h-5 mx-auto mb-2" />
        No version history yet
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold text-gray-700 px-2 flex items-center gap-2">
        <GitBranch className="w-4 h-4" />
        Version History
      </h3>
      <div className="space-y-1">
        {versions.map((version, index) => (
          <VersionCard
            key={version.id}
            version={version}
            previousVersion={versions[index + 1]} // Previous version in the sorted list
            isExpanded={expandedVersion === version.id}
            isCurrent={currentVersionId === version.id}
            onToggle={() => setExpandedVersion(
              expandedVersion === version.id ? null : version.id
            )}
            onSelect={() => onVersionSelect?.(version.id)}
            projectId={projectId}
            token={token}
          />
        ))}
      </div>
    </div>
  );
};

interface VersionCardProps {
  version: ArchitectureVersion;
  previousVersion?: ArchitectureVersion;
  isExpanded: boolean;
  isCurrent: boolean;
  onToggle: () => void;
  onSelect: () => void;
  projectId: number;
  token: string;
}

const VersionCard: React.FC<VersionCardProps> = ({
  version,
  previousVersion,
  isExpanded,
  isCurrent,
  onToggle,
  onSelect,
  projectId,
  token
}) => {
  const [showDiff, setShowDiff] = useState(false);
  const [diffData, setDiffData] = useState<any>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getImpactColor = (score: number) => {
    if (score >= 0.7) return 'text-red-600 bg-red-50';
    if (score >= 0.4) return 'text-yellow-600 bg-yellow-50';
    return 'text-green-600 bg-green-50';
  };

  const loadDiff = async () => {
    if (!previousVersion || diffData) return;
    setLoadingDiff(true);
    try {
      const data = await fetchVersionDiff(projectId, previousVersion.id, version.id, token);
      setDiffData(data);
    } catch (e) {
      console.error('Failed to load diff:', e);
    } finally {
      setLoadingDiff(false);
    }
  };

  const handleToggleDiff = async () => {
    if (!showDiff && !diffData) {
      await loadDiff();
    }
    setShowDiff(!showDiff);
  };

  const summary = version.change_summary;
  const stats = version.threat_stats;
  const user = version.user;

  return (
    <div
      className={`border rounded-lg overflow-hidden transition-all ${
        isCurrent ? 'border-blue-300 bg-blue-50/50' : 'border-gray-200 hover:border-gray-300'
      }`}
    >
      <div
        className="p-3 cursor-pointer"
        onClick={onToggle}
      >
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-gray-900">
              Version {version.version_number}
            </span>
            {isCurrent && (
              <span className="text-xs bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded">
                Current
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {summary && summary.total_changes > 0 && (
              <span className={`text-xs px-2 py-0.5 rounded-full ${getImpactColor(version.impact_score)}`}>
                {summary.total_changes} changes
              </span>
            )}
            {isExpanded ? (
              <ChevronUp className="w-4 h-4 text-gray-400" />
            ) : (
              <ChevronDown className="w-4 h-4 text-gray-400" />
            )}
          </div>
        </div>

        {/* User and timestamp row */}
        <div className="flex items-center gap-3 text-xs text-gray-500">
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            {formatDate(version.created_at)}
          </span>
          {user && (
            <span className="flex items-center gap-1">
              <User className="w-3 h-3" />
              {user.username || user.email}
            </span>
          )}
        </div>

        {/* Threat stats badges */}
        {stats && stats.total > 0 && (
          <div className="flex items-center gap-2 mt-2">
            <Shield className="w-3 h-3 text-gray-400" />
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-xs bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded">
                {stats.total} threats
              </span>
              {stats.new > 0 && (
                <span className="text-xs bg-green-100 text-green-700 px-1.5 py-0.5 rounded flex items-center gap-0.5">
                  <Sparkles className="w-2.5 h-2.5" />
                  {stats.new} new
                </span>
              )}
              {stats.modified > 0 && (
                <span className="text-xs bg-yellow-100 text-yellow-700 px-1.5 py-0.5 rounded">
                  {stats.modified} modified
                </span>
              )}
              {stats.resolved > 0 && (
                <span className="text-xs bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded">
                  {stats.resolved} resolved
                </span>
              )}
            </div>
          </div>
        )}
      </div>

      {isExpanded && (
        <div className="px-3 pb-3 border-t border-gray-100 bg-gray-50/50">
          <p className="text-xs text-gray-600 mt-2 mb-3">
            {version.change_description || 'No description available'}
          </p>

          {summary && (
            <div className="space-y-2">
              {summary.added_components?.length > 0 && (
                <ChangeSummaryItem
                  icon={<Plus className="w-3 h-3 text-green-600" />}
                  label="Added"
                  items={summary.added_components}
                  color="green"
                />
              )}
              {summary.removed_components?.length > 0 && (
                <ChangeSummaryItem
                  icon={<Minus className="w-3 h-3 text-red-600" />}
                  label="Removed"
                  items={summary.removed_components}
                  color="red"
                />
              )}
              {summary.modified_components?.length > 0 && (
                <ChangeSummaryItem
                  icon={<AlertCircle className="w-3 h-3 text-yellow-600" />}
                  label="Modified"
                  items={summary.modified_components}
                  color="yellow"
                />
              )}
            </div>
          )}

          <div className="flex items-center gap-2 mt-3">
            <button
              onClick={(e) => {
                e.stopPropagation();
                onSelect();
              }}
              className="text-xs text-blue-600 hover:text-blue-700 font-medium"
            >
              View this version
            </button>

            {previousVersion && (
              <>
                <span className="text-gray-300">|</span>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    handleToggleDiff();
                  }}
                  className="text-xs text-purple-600 hover:text-purple-700 font-medium flex items-center gap-1"
                >
                  <GitBranch className="w-3 h-3" />
                  {showDiff ? 'Hide diff' : 'Compare with v' + previousVersion.version_number}
                </button>
              </>
            )}
          </div>

          {/* Diff Display */}
          {showDiff && previousVersion && (
            <div className="mt-3 border border-purple-200 rounded-lg bg-purple-50/50 p-3">
              <div className="flex items-center gap-2 text-xs text-purple-700 font-medium mb-2">
                <GitBranch className="w-3 h-3" />
                Changes from v{previousVersion.version_number} → v{version.version_number}
              </div>

              {loadingDiff ? (
                <div className="flex items-center gap-2 text-xs text-gray-500">
                  <Activity className="w-3 h-3 animate-spin" />
                  Loading diff...
                </div>
              ) : diffData ? (
                <div className="space-y-2">
                  {/* Security Impact */}
                  {diffData.has_security_relevant_changes && (
                    <div className="flex items-center gap-1 text-xs text-red-600 bg-red-50 px-2 py-1 rounded">
                      <AlertCircle className="w-3 h-3" />
                      Security-relevant changes detected
                    </div>
                  )}

                  {/* Impact Score */}
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-gray-600">Impact Score:</span>
                    <span className={`font-medium ${
                      diffData.impact_score >= 0.7 ? 'text-red-600' :
                      diffData.impact_score >= 0.4 ? 'text-yellow-600' : 'text-green-600'
                    }`}>
                      {(diffData.impact_score * 100).toFixed(0)}%
                    </span>
                  </div>

                  {/* Change Counts */}
                  {diffData.diff && (
                    <div className="grid grid-cols-3 gap-2 text-xs">
                      <div className="bg-green-100 text-green-700 px-2 py-1 rounded text-center">
                        +{diffData.diff.added_components?.length || 0} added
                      </div>
                      <div className="bg-red-100 text-red-700 px-2 py-1 rounded text-center">
                        -{diffData.diff.removed_components?.length || 0} removed
                      </div>
                      <div className="bg-yellow-100 text-yellow-700 px-2 py-1 rounded text-center">
                        ~{diffData.diff.modified_components?.length || 0} modified
                      </div>
                    </div>
                  )}

                  {/* Threat Changes */}
                  {diffData.threat_changes && (
                    <div className="border-t border-purple-200 pt-2 mt-2">
                      <span className="text-xs font-medium text-purple-700">Threat Changes:</span>
                      <div className="grid grid-cols-4 gap-1 mt-1 text-xs">
                        <div className="bg-green-100 text-green-700 px-1 py-0.5 rounded text-center">
                          {diffData.threat_changes.new || 0} new
                        </div>
                        <div className="bg-gray-100 text-gray-600 px-1 py-0.5 rounded text-center">
                          {diffData.threat_changes.existing || 0} same
                        </div>
                        <div className="bg-yellow-100 text-yellow-700 px-1 py-0.5 rounded text-center">
                          {diffData.threat_changes.modified || 0} mod
                        </div>
                        <div className="bg-blue-100 text-blue-700 px-1 py-0.5 rounded text-center">
                          {diffData.threat_changes.resolved || 0} fixed
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Description */}
                  {diffData.description && (
                    <p className="text-xs text-gray-600 italic mt-2">
                      {diffData.description}
                    </p>
                  )}
                </div>
              ) : (
                <p className="text-xs text-gray-500">No diff data available</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

interface ChangeSummaryItemProps {
  icon: React.ReactNode;
  label: string;
  items: string[];
  color: 'green' | 'red' | 'yellow';
}

const ChangeSummaryItem: React.FC<ChangeSummaryItemProps> = ({
  icon,
  label,
  items,
  color
}) => {
  const colorClasses = {
    green: 'bg-green-50 text-green-700',
    red: 'bg-red-50 text-red-700',
    yellow: 'bg-yellow-50 text-yellow-700'
  };

  return (
    <div className={`text-xs rounded p-2 ${colorClasses[color]}`}>
      <div className="flex items-center gap-1 font-medium mb-1">
        {icon}
        {label} ({items.length})
      </div>
      <div className="text-xs opacity-80 truncate">
        {items.slice(0, 3).join(', ')}
        {items.length > 3 && `, +${items.length - 3} more`}
      </div>
    </div>
  );
};

// Threat Timeline Component
interface ThreatTimelineProps {
  projectId: number;
  threatId: string;
  token: string;
  threatName?: string;
}

export const ThreatTimeline: React.FC<ThreatTimelineProps> = ({
  projectId,
  threatId,
  token,
  threatName
}) => {
  const [timeline, setTimeline] = useState<ThreatTimelineEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadTimeline = async () => {
      try {
        setLoading(true);
        const data = await fetchThreatTimeline(projectId, threatId, token);
        setTimeline(data.timeline || []);
      } catch (e: any) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    };

    loadTimeline();
  }, [projectId, threatId, token]);

  if (loading) {
    return (
      <div className="p-4 text-center text-gray-500">
        <Activity className="w-4 h-4 animate-spin mx-auto" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 text-center text-red-500 text-sm">
        {error}
      </div>
    );
  }

  if (timeline.length === 0) {
    return (
      <div className="p-4 text-center text-gray-500 text-sm">
        No history available
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {threatName && (
        <h4 className="text-sm font-medium text-gray-700">{threatName}</h4>
      )}
      <div className="relative">
        {/* Timeline line */}
        <div className="absolute left-3 top-0 bottom-0 w-0.5 bg-gray-200" />

        <div className="space-y-4">
          {timeline.map((entry, index) => (
            <TimelineEntry key={index} entry={entry} isLast={index === timeline.length - 1} />
          ))}
        </div>
      </div>
    </div>
  );
};

interface TimelineEntryProps {
  entry: ThreatTimelineEntry;
  isLast: boolean;
}

const TimelineEntry: React.FC<TimelineEntryProps> = ({ entry, isLast }) => {
  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className="relative pl-8">
      {/* Timeline dot */}
      <div className="absolute left-0 top-1 w-6 h-6 rounded-full bg-white border-2 border-gray-300 flex items-center justify-center">
        {entry.status === 'new' && <Plus className="w-3 h-3 text-green-600" />}
        {entry.status === 'existing' && <CheckCircle className="w-3 h-3 text-gray-400" />}
        {entry.status === 'modified' && <AlertCircle className="w-3 h-3 text-yellow-600" />}
        {entry.status === 'resolved' && <CheckCircle className="w-3 h-3 text-blue-600" />}
      </div>

      <div className="bg-gray-50 rounded-lg p-3 border border-gray-200">
        <div className="flex items-center justify-between mb-2">
          <ThreatStatusBadge status={entry.status} size="sm" />
          <span className="text-xs text-gray-500">
            v{entry.version} - {formatDate(entry.timestamp)}
          </span>
        </div>

        {entry.transition && (
          <div className="flex items-center gap-2 text-xs text-gray-600 mb-2">
            <ThreatStatusBadge status={entry.previous_status!} size="sm" showLabel={false} />
            <ArrowRight className="w-3 h-3" />
            <ThreatStatusBadge status={entry.status} size="sm" showLabel={false} />
          </div>
        )}

        {entry.change_reason && (
          <p className="text-xs text-gray-600">
            {entry.change_reason}
          </p>
        )}
      </div>
    </div>
  );
};

// Version Comparison Component
interface VersionComparisonProps {
  projectId: number;
  version1Id: number;
  version2Id: number;
  token: string;
}

export const VersionComparison: React.FC<VersionComparisonProps> = ({
  projectId,
  version1Id,
  version2Id,
  token
}) => {
  const [diff, setDiff] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadDiff = async () => {
      try {
        setLoading(true);
        const data = await fetchVersionDiff(projectId, version1Id, version2Id, token);
        setDiff(data);
      } catch (e: any) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    };

    loadDiff();
  }, [projectId, version1Id, version2Id, token]);

  if (loading) {
    return (
      <div className="p-4 text-center text-gray-500">
        <Activity className="w-5 h-5 animate-spin mx-auto mb-2" />
        Comparing versions...
      </div>
    );
  }

  if (error || !diff) {
    return (
      <div className="p-4 text-center text-red-500">
        {error || 'Failed to load comparison'}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-sm">
          <span className="font-medium">v{diff.version1.version_number}</span>
          <span className="mx-2 text-gray-400">vs</span>
          <span className="font-medium">v{diff.version2.version_number}</span>
        </div>
        <span className={`text-xs px-2 py-1 rounded-full ${
          diff.has_security_relevant_changes
            ? 'bg-red-100 text-red-700'
            : 'bg-gray-100 text-gray-600'
        }`}>
          {diff.has_security_relevant_changes ? 'Security-relevant changes' : 'No security impact'}
        </span>
      </div>

      <p className="text-sm text-gray-600">{diff.description}</p>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <h4 className="text-xs font-medium text-gray-500 mb-2">Impact Score</h4>
          <div className="text-lg font-semibold">
            {(diff.impact_score * 100).toFixed(0)}%
          </div>
        </div>
        <div>
          <h4 className="text-xs font-medium text-gray-500 mb-2">Total Changes</h4>
          <div className="text-lg font-semibold">
            {diff.diff.total_changes}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatHistoryPanel;
