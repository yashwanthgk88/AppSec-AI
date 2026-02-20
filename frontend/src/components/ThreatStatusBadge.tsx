import React from 'react';
import { Plus, Check, AlertTriangle, CheckCircle } from 'lucide-react';

export type ThreatStatus = 'new' | 'existing' | 'modified' | 'resolved';

interface ThreatStatusBadgeProps {
  status: ThreatStatus;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

const statusConfig: Record<ThreatStatus, {
  label: string;
  icon: React.ReactNode;
  bgColor: string;
  textColor: string;
  borderColor: string;
}> = {
  new: {
    label: 'New',
    icon: <Plus className="w-3 h-3" />,
    bgColor: 'bg-green-50',
    textColor: 'text-green-700',
    borderColor: 'border-green-200'
  },
  existing: {
    label: 'Existing',
    icon: <Check className="w-3 h-3" />,
    bgColor: 'bg-gray-50',
    textColor: 'text-gray-600',
    borderColor: 'border-gray-200'
  },
  modified: {
    label: 'Modified',
    icon: <AlertTriangle className="w-3 h-3" />,
    bgColor: 'bg-yellow-50',
    textColor: 'text-yellow-700',
    borderColor: 'border-yellow-200'
  },
  resolved: {
    label: 'Resolved',
    icon: <CheckCircle className="w-3 h-3" />,
    bgColor: 'bg-blue-50',
    textColor: 'text-blue-700',
    borderColor: 'border-blue-200'
  }
};

export const ThreatStatusBadge: React.FC<ThreatStatusBadgeProps> = ({
  status,
  size = 'md',
  showLabel = true
}) => {
  const config = statusConfig[status] || statusConfig.existing;

  const sizeClasses = {
    sm: 'px-1.5 py-0.5 text-xs gap-1',
    md: 'px-2 py-1 text-xs gap-1.5',
    lg: 'px-3 py-1.5 text-sm gap-2'
  };

  return (
    <span
      className={`inline-flex items-center font-medium rounded-full border ${config.bgColor} ${config.textColor} ${config.borderColor} ${sizeClasses[size]}`}
    >
      {config.icon}
      {showLabel && <span>{config.label}</span>}
    </span>
  );
};

interface ThreatLifecycleSummaryProps {
  summary: {
    new: number;
    existing: number;
    modified: number;
    resolved: number;
    total?: number;
  };
}

export const ThreatLifecycleSummary: React.FC<ThreatLifecycleSummaryProps> = ({ summary }) => {
  const items: { status: ThreatStatus; count: number }[] = [
    { status: 'new', count: summary.new },
    { status: 'modified', count: summary.modified },
    { status: 'existing', count: summary.existing },
    { status: 'resolved', count: summary.resolved }
  ];

  return (
    <div className="flex items-center gap-4 flex-wrap">
      {items.map(({ status, count }) => (
        <div key={status} className="flex items-center gap-2">
          <ThreatStatusBadge status={status} size="sm" />
          <span className="text-sm font-medium text-gray-700">{count}</span>
        </div>
      ))}
      {summary.total !== undefined && (
        <div className="text-sm text-gray-500 ml-2 pl-4 border-l border-gray-200">
          Total: <span className="font-medium">{summary.total}</span>
        </div>
      )}
    </div>
  );
};

interface ThreatChangeReasonProps {
  reason: string | null | undefined;
  status: ThreatStatus;
}

export const ThreatChangeReason: React.FC<ThreatChangeReasonProps> = ({ reason, status }) => {
  if (!reason || status === 'existing') return null;

  const bgColor = status === 'new' ? 'bg-green-50' :
                  status === 'modified' ? 'bg-yellow-50' :
                  status === 'resolved' ? 'bg-blue-50' : 'bg-gray-50';

  return (
    <div className={`text-xs ${bgColor} rounded px-2 py-1 mt-1`}>
      <span className="text-gray-500">Change reason:</span>{' '}
      <span className="text-gray-700">{reason}</span>
    </div>
  );
};

export default ThreatStatusBadge;
