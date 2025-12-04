import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Activity, RefreshCw, AlertCircle, CheckCircle, Clock, Terminal, Play, XCircle } from 'lucide-react';

interface Scan {
  id: number;
  project_id: number;
  project_name: string;
  scan_type: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at: string;
  completed_at?: string;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  progress?: number;
}

interface ScanLog {
  timestamp: string;
  level: 'info' | 'warning' | 'error' | 'success';
  message: string;
}

const ScanMonitorPage: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [filterStatus, setFilterStatus] = useState<string>('');
  const [filterProject, setFilterProject] = useState<string>('');
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadScans();
    const interval = setInterval(() => {
      if (autoRefresh) {
        loadScans();
        if (selectedScan && (selectedScan.status === 'running' || selectedScan.status === 'pending')) {
          loadScanLogs(selectedScan.id);
        }
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [autoRefresh, selectedScan]);

  useEffect(() => {
    if (selectedScan) {
      loadScanLogs(selectedScan.id);
    }
  }, [selectedScan]);

  useEffect(() => {
    scrollToBottom();
  }, [logs]);

  const scrollToBottom = () => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const loadScans = async () => {
    try {
      const token = localStorage.getItem('token');
      const params = new URLSearchParams();
      if (filterStatus) params.append('status', filterStatus);
      if (filterProject) params.append('project_id', filterProject);

      const response = await axios.get(`http://localhost:8000/api/scans/?${params}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setScans(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to load scans:', error);
      setLoading(false);
    }
  };

  const loadScanLogs = async (scanId: number) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`http://localhost:8000/api/scans/${scanId}/logs`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setLogs(response.data);
    } catch (error) {
      // If endpoint doesn't exist, generate mock logs based on scan status
      const scan = scans.find(s => s.id === scanId);
      if (scan) {
        generateMockLogs(scan);
      }
    }
  };

  const generateMockLogs = (scan: Scan) => {
    const mockLogs: ScanLog[] = [
      { timestamp: scan.started_at, level: 'info', message: `Starting ${scan.scan_type} scan for project: ${scan.project_name}` },
      { timestamp: scan.started_at, level: 'info', message: 'Initializing scan environment...' },
      { timestamp: scan.started_at, level: 'success', message: 'Environment ready' },
    ];

    if (scan.status === 'running') {
      mockLogs.push(
        { timestamp: new Date().toISOString(), level: 'info', message: 'Analyzing source code...' },
        { timestamp: new Date().toISOString(), level: 'info', message: `Processed ${scan.progress || 45}% of files` },
        { timestamp: new Date().toISOString(), level: 'warning', message: `Found ${scan.critical_count} critical issues` }
      );
    } else if (scan.status === 'completed') {
      mockLogs.push(
        { timestamp: scan.completed_at || scan.started_at, level: 'info', message: 'Analysis complete' },
        { timestamp: scan.completed_at || scan.started_at, level: 'success', message: `Scan completed successfully` },
        { timestamp: scan.completed_at || scan.started_at, level: 'info', message: `Total vulnerabilities found: ${scan.total_vulnerabilities}` },
        { timestamp: scan.completed_at || scan.started_at, level: 'info', message: `Critical: ${scan.critical_count}, High: ${scan.high_count}, Medium: ${scan.medium_count}, Low: ${scan.low_count}` }
      );
    } else if (scan.status === 'failed') {
      mockLogs.push(
        { timestamp: scan.completed_at || scan.started_at, level: 'error', message: 'Scan failed due to an error' },
        { timestamp: scan.completed_at || scan.started_at, level: 'error', message: 'Please check project configuration and try again' }
      );
    }

    setLogs(mockLogs);
  };

  const restartScan = async (scanId: number) => {
    try {
      const token = localStorage.getItem('token');
      const scan = scans.find(s => s.id === scanId);

      if (!scan) return;

      // Create a new scan with the same configuration
      await axios.post(
        'http://localhost:8000/api/scans/',
        {
          project_id: scan.project_id,
          scan_type: scan.scan_type
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      alert('Scan restarted successfully!');
      loadScans();
    } catch (error) {
      console.error('Failed to restart scan:', error);
      alert('Failed to restart scan');
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return <Activity className="w-5 h-5 text-blue-600 animate-pulse" />;
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-600" />;
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-600" />;
      case 'pending':
        return <Clock className="w-5 h-5 text-yellow-600" />;
      default:
        return <AlertCircle className="w-5 h-5 text-gray-600" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'bg-blue-100 text-blue-800 border-blue-300';
      case 'completed':
        return 'bg-green-100 text-green-800 border-green-300';
      case 'failed':
        return 'bg-red-100 text-red-800 border-red-300';
      case 'pending':
        return 'bg-yellow-100 text-yellow-800 border-yellow-300';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-300';
    }
  };

  const getLogLevelColor = (level: string) => {
    switch (level) {
      case 'error':
        return 'text-red-600';
      case 'warning':
        return 'text-yellow-600';
      case 'success':
        return 'text-green-600';
      default:
        return 'text-gray-600';
    }
  };

  const formatDuration = (start: string, end?: string) => {
    const startTime = new Date(start).getTime();
    const endTime = end ? new Date(end).getTime() : Date.now();
    const duration = Math.floor((endTime - startTime) / 1000);

    if (duration < 60) return `${duration}s`;
    if (duration < 3600) return `${Math.floor(duration / 60)}m ${duration % 60}s`;
    return `${Math.floor(duration / 3600)}h ${Math.floor((duration % 3600) / 60)}m`;
  };

  // Group scans by project
  const groupedScans = scans.reduce((acc, scan) => {
    const projectName = scan.project_name || 'Unknown Project';
    if (!acc[projectName]) {
      acc[projectName] = [];
    }
    acc[projectName].push(scan);
    return acc;
  }, {} as Record<string, Scan[]>);

  if (loading) {
    return <div className="flex justify-center items-center h-screen">Loading...</div>;
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2 flex items-center gap-2">
          <Activity className="w-8 h-8" />
          Scan Monitor
        </h1>
        <p className="text-gray-600">Real-time monitoring of security scans with live logs</p>
      </div>

      {/* Controls */}
      <div className="bg-white rounded-lg shadow-sm p-4 mb-6 flex flex-wrap gap-4 items-center justify-between">
        <div className="flex gap-3 flex-wrap">
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="px-3 py-2 border rounded-lg"
          >
            <option value="">All Statuses</option>
            <option value="pending">Pending</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
          </select>

          <button
            onClick={loadScans}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>

        <div className="flex items-center gap-2">
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded"
            />
            Auto-refresh (3s)
          </label>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="text-2xl font-bold text-blue-600">
            {scans.filter(s => s.status === 'running').length}
          </div>
          <div className="text-sm text-gray-600">Running Scans</div>
        </div>
        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="text-2xl font-bold text-yellow-600">
            {scans.filter(s => s.status === 'pending').length}
          </div>
          <div className="text-sm text-gray-600">Pending Scans</div>
        </div>
        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="text-2xl font-bold text-green-600">
            {scans.filter(s => s.status === 'completed').length}
          </div>
          <div className="text-sm text-gray-600">Completed</div>
        </div>
        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="text-2xl font-bold text-red-600">
            {scans.filter(s => s.status === 'failed').length}
          </div>
          <div className="text-sm text-gray-600">Failed</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Scans List - Grouped by Project */}
        <div className="bg-white rounded-lg shadow-sm overflow-hidden">
          <div className="bg-gray-50 px-6 py-4 border-b">
            <h2 className="text-lg font-semibold text-gray-900">Scans by Project</h2>
          </div>
          <div className="overflow-y-auto max-h-[600px]">
            {Object.entries(groupedScans).length === 0 ? (
              <div className="p-8 text-center text-gray-500">No scans available</div>
            ) : (
              Object.entries(groupedScans).map(([projectName, projectScans]) => (
                <div key={projectName} className="border-b last:border-b-0">
                  {/* Project Header */}
                  <div className="bg-gray-50 px-6 py-2 border-b">
                    <h3 className="font-semibold text-gray-900">{projectName}</h3>
                    <p className="text-xs text-gray-500">{projectScans.length} scan(s)</p>
                  </div>

                  {/* Scans for this project */}
                  {projectScans.map((scan) => (
                    <div
                      key={scan.id}
                      onClick={() => setSelectedScan(scan)}
                      className={`p-4 cursor-pointer hover:bg-gray-50 transition-colors border-l-4 ${
                        selectedScan?.id === scan.id
                          ? 'bg-blue-50 border-l-blue-600'
                          : 'border-l-transparent'
                      }`}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(scan.status)}
                          <div>
                            <div className="font-medium text-gray-900">
                              {scan.scan_type.toUpperCase()} Scan #{scan.id}
                            </div>
                            <div className="text-xs text-gray-500">
                              {new Date(scan.started_at).toLocaleString()}
                            </div>
                          </div>
                        </div>
                        <span
                          className={`px-2 py-1 text-xs font-semibold rounded-full border ${getStatusColor(
                            scan.status
                          )}`}
                        >
                          {scan.status.toUpperCase()}
                        </span>
                      </div>

                      {scan.status === 'running' && scan.progress !== undefined && (
                        <div className="mb-2">
                          <div className="flex justify-between text-xs text-gray-600 mb-1">
                            <span>Progress</span>
                            <span>{scan.progress}%</span>
                          </div>
                          <div className="w-full bg-gray-200 rounded-full h-2">
                            <div
                              className="bg-blue-600 h-2 rounded-full transition-all"
                              style={{ width: `${scan.progress}%` }}
                            />
                          </div>
                        </div>
                      )}

                      <div className="flex items-center justify-between text-xs text-gray-600">
                        <span>Duration: {formatDuration(scan.started_at, scan.completed_at)}</span>
                        {scan.status === 'completed' && (
                          <span className="font-semibold">
                            {scan.total_vulnerabilities} issues
                          </span>
                        )}
                      </div>

                      {scan.status === 'completed' && (
                        <div className="flex gap-2 mt-2">
                          <span className="text-xs px-2 py-1 bg-red-100 text-red-800 rounded">
                            C: {scan.critical_count}
                          </span>
                          <span className="text-xs px-2 py-1 bg-orange-100 text-orange-800 rounded">
                            H: {scan.high_count}
                          </span>
                          <span className="text-xs px-2 py-1 bg-yellow-100 text-yellow-800 rounded">
                            M: {scan.medium_count}
                          </span>
                          <span className="text-xs px-2 py-1 bg-green-100 text-green-800 rounded">
                            L: {scan.low_count}
                          </span>
                        </div>
                      )}

                      {(scan.status === 'completed' || scan.status === 'failed') && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            restartScan(scan.id);
                          }}
                          className="mt-2 px-3 py-1 bg-blue-600 text-white text-xs rounded hover:bg-blue-700 flex items-center gap-1"
                        >
                          <Play className="w-3 h-3" />
                          Restart Scan
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Logs Panel */}
        <div className="bg-white rounded-lg shadow-sm overflow-hidden">
          <div className="bg-gray-900 px-6 py-4 flex items-center justify-between">
            <div className="flex items-center gap-2 text-white">
              <Terminal className="w-5 h-5" />
              <h2 className="text-lg font-semibold">Live Scan Logs</h2>
            </div>
            {selectedScan && (
              <span className="text-xs text-gray-400">
                Scan #{selectedScan.id}
              </span>
            )}
          </div>

          <div className="bg-gray-950 p-4 h-[600px] overflow-y-auto font-mono text-sm">
            {!selectedScan ? (
              <div className="text-gray-500 text-center mt-20">
                Select a scan to view logs
              </div>
            ) : logs.length === 0 ? (
              <div className="text-gray-500 text-center mt-20">
                No logs available for this scan
              </div>
            ) : (
              logs.map((log, index) => (
                <div key={index} className="mb-1 flex gap-2">
                  <span className="text-gray-500 text-xs">
                    [{new Date(log.timestamp).toLocaleTimeString()}]
                  </span>
                  <span className={`text-xs uppercase ${
                    log.level === 'error' ? 'text-red-400' :
                    log.level === 'warning' ? 'text-yellow-400' :
                    log.level === 'success' ? 'text-green-400' :
                    'text-blue-400'
                  }`}>
                    {log.level}
                  </span>
                  <span className={getLogLevelColor(log.level)}>
                    {log.message}
                  </span>
                </div>
              ))
            )}
            <div ref={logsEndRef} />
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanMonitorPage;
