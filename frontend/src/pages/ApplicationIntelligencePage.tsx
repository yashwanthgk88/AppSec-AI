import React, { useState, useEffect } from 'react';
import axios from 'axios';

interface ApplicationProfile {
  id: number;
  project_id: number;
  status: 'pending' | 'profiling' | 'analyzing' | 'generating_suggestions' | 'completed' | 'failed';
  status_message: string;
  profiling_progress: number;
  languages: Record<string, number>;
  frameworks: Array<{ name: string; version?: string; type?: string }>;
  databases: string[];
  orm_libraries: string[];
  entry_points: Array<{
    method?: string;
    path?: string;
    file?: string;
    risk_indicators?: string[];
  }>;
  sensitive_data_fields: Array<{
    field?: string;
    category?: string;
    file?: string;
    line?: number;
  }>;
  auth_mechanisms: string[];
  dependencies: Record<string, string>;
  external_integrations: string[];
  cloud_services: string[];
  file_count: number;
  total_lines_of_code: number;
  security_score: number;
  risk_level: string;
  total_suggestions: number;
  critical_suggestions: number;
  high_suggestions: number;
  last_profiled_at: string;
  created_at: string;
}

interface SuggestedRule {
  id: number;
  name: string;
  description: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  reason: string;
  detected_patterns: Array<Record<string, unknown>>;
  framework_context: string;
  rule_type: string;
  semgrep_rule: string;
  codeql_rule: string;
  checkmarx_rule: string;
  fortify_rule: string;
  cwe_ids: string[];
  owasp_categories: string[];
  mitre_techniques: string[];
  status: 'pending' | 'accepted' | 'dismissed' | 'implemented';
  confidence_score: number;
  user_feedback: string;
  created_at: string;
}

interface Project {
  id: number;
  name: string;
  description: string;
}

interface ProfilingStatus {
  status: string;
  progress: number;
  message: string;
  timestamp?: string;
}

const ApplicationIntelligencePage: React.FC = () => {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [profile, setProfile] = useState<ApplicationProfile | null>(null);
  const [suggestions, setSuggestions] = useState<SuggestedRule[]>([]);
  const [profilingStatus, setProfilingStatus] = useState<ProfilingStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [isPolling, setIsPolling] = useState(false);
  const [selectedSuggestion, setSelectedSuggestion] = useState<SuggestedRule | null>(null);
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [exportFormat, setExportFormat] = useState<string>('semgrep');
  const [activeTab, setActiveTab] = useState<'overview' | 'suggestions' | 'techstack' | 'security'>('overview');
  const [filterSeverity, setFilterSeverity] = useState<string>('');
  const [filterCategory, setFilterCategory] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('');

  const token = localStorage.getItem('token');
  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    loadProjects();
  }, []);

  useEffect(() => {
    if (selectedProjectId) {
      loadProfile();
      loadSuggestions();
    }
  }, [selectedProjectId, filterSeverity, filterCategory, filterStatus]);

  // Poll for profiling status when profiling is in progress
  useEffect(() => {
    let intervalId: ReturnType<typeof setInterval>;

    if (isPolling && selectedProjectId) {
      intervalId = setInterval(async () => {
        try {
          const response = await axios.get(
            `http://localhost:8000/api/application-intelligence/profile/${selectedProjectId}/status`,
            { headers }
          );
          setProfilingStatus(response.data);

          if (response.data.status === 'completed' || response.data.status === 'failed') {
            setIsPolling(false);
            loadProfile();
            loadSuggestions();
          }
        } catch (error) {
          console.error('Failed to get profiling status:', error);
        }
      }, 2000);
    }

    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [isPolling, selectedProjectId]);

  const loadProjects = async () => {
    try {
      const response = await axios.get('http://localhost:8000/api/projects', { headers });
      setProjects(response.data);
      if (response.data.length > 0) {
        setSelectedProjectId(response.data[0].id);
      }
    } catch (error) {
      console.error('Failed to load projects:', error);
    }
  };

  const loadProfile = async () => {
    if (!selectedProjectId) return;

    try {
      const response = await axios.get(
        `http://localhost:8000/api/application-intelligence/profile/${selectedProjectId}`,
        { headers }
      );
      setProfile(response.data);
    } catch (error: any) {
      if (error.response?.status !== 404) {
        console.error('Failed to load profile:', error);
      }
      setProfile(null);
    }
  };

  const loadSuggestions = async () => {
    if (!selectedProjectId) return;

    try {
      const params = new URLSearchParams();
      if (filterSeverity) params.append('severity', filterSeverity);
      if (filterCategory) params.append('category', filterCategory);
      if (filterStatus) params.append('status', filterStatus);

      const response = await axios.get(
        `http://localhost:8000/api/application-intelligence/suggestions/${selectedProjectId}?${params}`,
        { headers }
      );
      setSuggestions(response.data);
    } catch (error: any) {
      if (error.response?.status !== 404) {
        console.error('Failed to load suggestions:', error);
      }
      setSuggestions([]);
    }
  };

  const startProfiling = async () => {
    if (!selectedProjectId) return;

    setLoading(true);
    try {
      const response = await axios.post(
        `http://localhost:8000/api/application-intelligence/profile/${selectedProjectId}`,
        {},
        { headers }
      );
      setProfile(response.data);
      setIsPolling(true);
      setProfilingStatus({ status: 'pending', progress: 0, message: 'Starting profiling...' });
    } catch (error: any) {
      console.error('Failed to start profiling:', error);
      alert(error.response?.data?.detail || 'Failed to start profiling');
    } finally {
      setLoading(false);
    }
  };

  const acceptSuggestion = async (suggestionId: number) => {
    try {
      await axios.put(
        `http://localhost:8000/api/application-intelligence/suggestion/${suggestionId}/accept`,
        {},
        { headers }
      );
      loadSuggestions();
    } catch (error) {
      console.error('Failed to accept suggestion:', error);
    }
  };

  const dismissSuggestion = async (suggestionId: number) => {
    try {
      await axios.put(
        `http://localhost:8000/api/application-intelligence/suggestion/${suggestionId}/dismiss`,
        {},
        { headers }
      );
      loadSuggestions();
    } catch (error) {
      console.error('Failed to dismiss suggestion:', error);
    }
  };

  const exportRule = async (suggestionId: number, format: string) => {
    try {
      const response = await axios.get(
        `http://localhost:8000/api/application-intelligence/suggestion/${suggestionId}/export/${format}`,
        { headers, responseType: 'blob' }
      );

      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `rule_${suggestionId}.${format === 'semgrep' ? 'yaml' : format === 'fortify' ? 'xml' : format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Failed to export rule:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-600 text-white';
      case 'high': return 'bg-orange-500 text-white';
      case 'medium': return 'bg-yellow-500 text-black';
      case 'low': return 'bg-blue-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-400';
      case 'profiling': return 'text-blue-400';
      case 'analyzing': return 'text-yellow-400';
      case 'generating_suggestions': return 'text-purple-400';
      case 'failed': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk?.toLowerCase()) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const renderProgressBar = () => {
    const progress = profilingStatus?.progress || profile?.profiling_progress || 0;
    const status = profilingStatus?.status || profile?.status || 'pending';
    const message = profilingStatus?.message || profile?.status_message || '';

    if (!isPolling && status === 'completed') return null;

    return (
      <div className="mb-6 bg-gray-800 rounded-lg p-4">
        <div className="flex justify-between items-center mb-2">
          <span className={`font-medium ${getStatusColor(status)}`}>
            {status.replace('_', ' ').toUpperCase()}
          </span>
          <span className="text-gray-400">{progress}%</span>
        </div>
        <div className="w-full bg-gray-700 rounded-full h-3 mb-2">
          <div
            className={`h-3 rounded-full transition-all duration-500 ${
              status === 'failed' ? 'bg-red-500' : 'bg-gradient-to-r from-blue-500 to-purple-500'
            }`}
            style={{ width: `${progress}%` }}
          />
        </div>
        <p className="text-sm text-gray-400">{message}</p>
      </div>
    );
  };

  const renderOverview = () => (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {/* Security Score Card */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-gray-400 text-sm mb-2">Security Score</h3>
        <div className="flex items-center">
          <span className={`text-4xl font-bold ${
            (profile?.security_score || 0) >= 80 ? 'text-green-400' :
            (profile?.security_score || 0) >= 60 ? 'text-yellow-400' :
            (profile?.security_score || 0) >= 40 ? 'text-orange-400' : 'text-red-400'
          }`}>
            {profile?.security_score?.toFixed(0) || '--'}
          </span>
          <span className="text-gray-400 text-xl ml-1">/100</span>
        </div>
        <div className={`text-sm mt-2 ${getRiskColor(profile?.risk_level || '')}`}>
          Risk Level: {profile?.risk_level?.toUpperCase() || 'N/A'}
        </div>
      </div>

      {/* Codebase Stats */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-gray-400 text-sm mb-2">Codebase Size</h3>
        <div className="text-3xl font-bold text-blue-400">
          {profile?.total_lines_of_code?.toLocaleString() || '--'}
        </div>
        <div className="text-sm text-gray-400 mt-1">
          Lines of Code
        </div>
        <div className="text-sm text-gray-500 mt-1">
          {profile?.file_count?.toLocaleString() || '--'} files analyzed
        </div>
      </div>

      {/* Suggestions Stats */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-gray-400 text-sm mb-2">Rule Suggestions</h3>
        <div className="text-3xl font-bold text-purple-400">
          {profile?.total_suggestions || suggestions.length || 0}
        </div>
        <div className="flex gap-2 mt-2 text-sm">
          <span className="text-red-400">
            {profile?.critical_suggestions || 0} Critical
          </span>
          <span className="text-orange-400">
            {profile?.high_suggestions || 0} High
          </span>
        </div>
      </div>

      {/* Last Profiled */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-gray-400 text-sm mb-2">Last Profiled</h3>
        <div className="text-lg font-medium text-gray-200">
          {profile?.last_profiled_at ? formatDate(profile.last_profiled_at) : 'Never'}
        </div>
        <button
          onClick={startProfiling}
          disabled={loading || isPolling}
          className={`mt-3 w-full py-2 px-4 rounded-lg font-medium transition-colors ${
            loading || isPolling
              ? 'bg-gray-600 cursor-not-allowed'
              : 'bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600'
          }`}
        >
          {loading || isPolling ? 'Profiling...' : profile ? 'Re-Profile' : 'Start Profiling'}
        </button>
      </div>
    </div>
  );

  const renderTechStack = () => (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Languages */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <span className="mr-2">Languages</span>
          <span className="text-sm bg-gray-700 px-2 py-0.5 rounded">
            {Object.keys(profile?.languages || {}).length}
          </span>
        </h3>
        <div className="space-y-3">
          {Object.entries(profile?.languages || {}).sort((a, b) => b[1] - a[1]).map(([lang, percentage]) => (
            <div key={lang}>
              <div className="flex justify-between text-sm mb-1">
                <span className="capitalize">{lang}</span>
                <span className="text-gray-400">{percentage.toFixed(1)}%</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div
                  className="h-2 rounded-full bg-gradient-to-r from-blue-500 to-cyan-500"
                  style={{ width: `${percentage}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Frameworks */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <span className="mr-2">Frameworks & Libraries</span>
          <span className="text-sm bg-gray-700 px-2 py-0.5 rounded">
            {profile?.frameworks?.length || 0}
          </span>
        </h3>
        <div className="flex flex-wrap gap-2">
          {profile?.frameworks?.map((fw, idx) => (
            <span key={idx} className="px-3 py-1.5 bg-gray-700 rounded-lg text-sm flex items-center gap-2">
              <span className="font-medium">{fw.name}</span>
              {fw.version && <span className="text-gray-400 text-xs">{fw.version}</span>}
              {fw.type && (
                <span className={`text-xs px-1.5 py-0.5 rounded ${
                  fw.type === 'backend' ? 'bg-blue-500/20 text-blue-400' :
                  fw.type === 'frontend' ? 'bg-green-500/20 text-green-400' : 'bg-gray-600 text-gray-400'
                }`}>
                  {fw.type}
                </span>
              )}
            </span>
          ))}
        </div>
      </div>

      {/* Databases & ORMs */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold mb-4">Databases & ORMs</h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <h4 className="text-sm text-gray-400 mb-2">Databases</h4>
            <div className="flex flex-wrap gap-2">
              {profile?.databases?.map((db, idx) => (
                <span key={idx} className="px-3 py-1 bg-purple-500/20 text-purple-400 rounded-lg text-sm">
                  {db}
                </span>
              ))}
              {(!profile?.databases || profile.databases.length === 0) && (
                <span className="text-gray-500 text-sm">None detected</span>
              )}
            </div>
          </div>
          <div>
            <h4 className="text-sm text-gray-400 mb-2">ORM Libraries</h4>
            <div className="flex flex-wrap gap-2">
              {profile?.orm_libraries?.map((orm, idx) => (
                <span key={idx} className="px-3 py-1 bg-cyan-500/20 text-cyan-400 rounded-lg text-sm">
                  {orm}
                </span>
              ))}
              {(!profile?.orm_libraries || profile.orm_libraries.length === 0) && (
                <span className="text-gray-500 text-sm">None detected</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* External Integrations */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold mb-4">External Integrations</h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <h4 className="text-sm text-gray-400 mb-2">Services</h4>
            <div className="flex flex-wrap gap-2">
              {profile?.external_integrations?.map((int, idx) => (
                <span key={idx} className="px-3 py-1 bg-orange-500/20 text-orange-400 rounded-lg text-sm">
                  {int}
                </span>
              ))}
              {(!profile?.external_integrations || profile.external_integrations.length === 0) && (
                <span className="text-gray-500 text-sm">None detected</span>
              )}
            </div>
          </div>
          <div>
            <h4 className="text-sm text-gray-400 mb-2">Cloud Providers</h4>
            <div className="flex flex-wrap gap-2">
              {profile?.cloud_services?.map((cloud, idx) => (
                <span key={idx} className="px-3 py-1 bg-blue-500/20 text-blue-400 rounded-lg text-sm">
                  {cloud}
                </span>
              ))}
              {(!profile?.cloud_services || profile.cloud_services.length === 0) && (
                <span className="text-gray-500 text-sm">None detected</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Authentication */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold mb-4">Authentication Mechanisms</h3>
        <div className="flex flex-wrap gap-2">
          {profile?.auth_mechanisms?.map((auth, idx) => (
            <span key={idx} className="px-3 py-1.5 bg-green-500/20 text-green-400 rounded-lg text-sm font-medium">
              {auth}
            </span>
          ))}
          {(!profile?.auth_mechanisms || profile.auth_mechanisms.length === 0) && (
            <span className="text-gray-500 text-sm">None detected</span>
          )}
        </div>
      </div>

      {/* Dependencies Count */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold mb-4">Dependencies</h3>
        <div className="text-3xl font-bold text-yellow-400">
          {Object.keys(profile?.dependencies || {}).length}
        </div>
        <div className="text-sm text-gray-400 mt-1">Total packages</div>
      </div>
    </div>
  );

  const renderSecurityAnalysis = () => (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Entry Points */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <span className="mr-2">API Entry Points</span>
          <span className="text-sm bg-gray-700 px-2 py-0.5 rounded">
            {profile?.entry_points?.length || 0}
          </span>
        </h3>
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {profile?.entry_points?.slice(0, 20).map((ep, idx) => (
            <div key={idx} className="bg-gray-700/50 rounded-lg p-3">
              <div className="flex items-center gap-2 mb-1">
                <span className={`px-2 py-0.5 rounded text-xs font-mono ${
                  ep.method === 'GET' ? 'bg-green-500/20 text-green-400' :
                  ep.method === 'POST' ? 'bg-blue-500/20 text-blue-400' :
                  ep.method === 'PUT' ? 'bg-yellow-500/20 text-yellow-400' :
                  ep.method === 'DELETE' ? 'bg-red-500/20 text-red-400' :
                  'bg-gray-600 text-gray-400'
                }`}>
                  {ep.method || 'GET'}
                </span>
                <span className="font-mono text-sm text-gray-200">{ep.path}</span>
              </div>
              <div className="text-xs text-gray-500">{ep.file}</div>
              {ep.risk_indicators && ep.risk_indicators.length > 0 && (
                <div className="flex gap-1 mt-2">
                  {ep.risk_indicators.map((ri, i) => (
                    <span key={i} className="text-xs px-2 py-0.5 bg-red-500/20 text-red-400 rounded">
                      {ri}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
          {(!profile?.entry_points || profile.entry_points.length === 0) && (
            <p className="text-gray-500">No entry points detected</p>
          )}
        </div>
      </div>

      {/* Sensitive Data Fields */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <span className="mr-2">Sensitive Data Fields</span>
          <span className="text-sm bg-red-500/20 text-red-400 px-2 py-0.5 rounded">
            {profile?.sensitive_data_fields?.length || 0}
          </span>
        </h3>
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {profile?.sensitive_data_fields?.slice(0, 20).map((field, idx) => (
            <div key={idx} className="bg-gray-700/50 rounded-lg p-3 flex justify-between items-start">
              <div>
                <div className="font-mono text-sm text-gray-200">{field.field}</div>
                <div className="text-xs text-gray-500">{field.file}:{field.line}</div>
              </div>
              <span className={`text-xs px-2 py-0.5 rounded ${
                field.category === 'credential' ? 'bg-red-500/20 text-red-400' :
                field.category === 'pii' ? 'bg-orange-500/20 text-orange-400' :
                field.category === 'financial' ? 'bg-yellow-500/20 text-yellow-400' :
                'bg-gray-600 text-gray-400'
              }`}>
                {field.category}
              </span>
            </div>
          ))}
          {(!profile?.sensitive_data_fields || profile.sensitive_data_fields.length === 0) && (
            <p className="text-gray-500">No sensitive data fields detected</p>
          )}
        </div>
      </div>
    </div>
  );

  const renderSuggestions = () => (
    <div>
      {/* Filters */}
      <div className="flex gap-4 mb-6">
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          className="bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-sm"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <select
          value={filterCategory}
          onChange={(e) => setFilterCategory(e.target.value)}
          className="bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-sm"
        >
          <option value="">All Categories</option>
          <option value="sql_injection">SQL Injection</option>
          <option value="xss">XSS</option>
          <option value="auth_bypass">Auth Bypass</option>
          <option value="crypto">Cryptography</option>
          <option value="hardcoded_secrets">Hardcoded Secrets</option>
        </select>

        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-sm"
        >
          <option value="">All Statuses</option>
          <option value="pending">Pending</option>
          <option value="accepted">Accepted</option>
          <option value="dismissed">Dismissed</option>
        </select>
      </div>

      {/* Suggestions List */}
      <div className="space-y-4">
        {suggestions.map((suggestion) => (
          <div key={suggestion.id} className="bg-gray-800 rounded-lg p-6 hover:bg-gray-750 transition-colors">
            <div className="flex justify-between items-start mb-4">
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <span className={`px-2.5 py-1 rounded-md text-xs font-medium ${getSeverityColor(suggestion.severity)}`}>
                    {suggestion.severity.toUpperCase()}
                  </span>
                  <span className="text-xs bg-gray-700 px-2 py-1 rounded">
                    {suggestion.category?.replace('_', ' ').toUpperCase()}
                  </span>
                  {suggestion.framework_context && (
                    <span className="text-xs bg-blue-500/20 text-blue-400 px-2 py-1 rounded">
                      {suggestion.framework_context}
                    </span>
                  )}
                  <span className={`text-xs px-2 py-1 rounded ${
                    suggestion.status === 'accepted' ? 'bg-green-500/20 text-green-400' :
                    suggestion.status === 'dismissed' ? 'bg-gray-600 text-gray-400' :
                    'bg-yellow-500/20 text-yellow-400'
                  }`}>
                    {suggestion.status}
                  </span>
                </div>
                <h3 className="text-lg font-semibold text-gray-200">{suggestion.name}</h3>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-sm text-gray-400">
                  Confidence: {(suggestion.confidence_score * 100).toFixed(0)}%
                </span>
              </div>
            </div>

            <p className="text-gray-400 text-sm mb-4">{suggestion.description}</p>

            <div className="bg-gray-700/50 rounded-lg p-3 mb-4">
              <h4 className="text-sm font-medium text-gray-300 mb-1">Why this rule?</h4>
              <p className="text-sm text-gray-400">{suggestion.reason}</p>
            </div>

            {/* CWE and OWASP Tags */}
            <div className="flex flex-wrap gap-2 mb-4">
              {suggestion.cwe_ids?.map((cwe, idx) => (
                <span key={idx} className="text-xs bg-purple-500/20 text-purple-400 px-2 py-1 rounded">
                  {cwe}
                </span>
              ))}
              {suggestion.owasp_categories?.map((owasp, idx) => (
                <span key={idx} className="text-xs bg-orange-500/20 text-orange-400 px-2 py-1 rounded">
                  {owasp}
                </span>
              ))}
            </div>

            {/* Actions */}
            <div className="flex gap-3 pt-4 border-t border-gray-700">
              {suggestion.status === 'pending' && (
                <>
                  <button
                    onClick={() => acceptSuggestion(suggestion.id)}
                    className="px-4 py-2 bg-green-500 hover:bg-green-600 rounded-lg text-sm font-medium transition-colors"
                  >
                    Accept
                  </button>
                  <button
                    onClick={() => dismissSuggestion(suggestion.id)}
                    className="px-4 py-2 bg-gray-600 hover:bg-gray-500 rounded-lg text-sm font-medium transition-colors"
                  >
                    Dismiss
                  </button>
                </>
              )}
              <button
                onClick={() => {
                  setSelectedSuggestion(suggestion);
                  setShowRuleModal(true);
                }}
                className="px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg text-sm font-medium transition-colors"
              >
                View Rule
              </button>
              <div className="flex items-center gap-2 ml-auto">
                <select
                  value={exportFormat}
                  onChange={(e) => setExportFormat(e.target.value)}
                  className="bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-sm"
                >
                  <option value="semgrep">Semgrep</option>
                  <option value="codeql">CodeQL</option>
                  <option value="checkmarx">Checkmarx</option>
                  <option value="fortify">Fortify</option>
                </select>
                <button
                  onClick={() => exportRule(suggestion.id, exportFormat)}
                  className="px-4 py-2 bg-purple-500 hover:bg-purple-600 rounded-lg text-sm font-medium transition-colors"
                >
                  Export
                </button>
              </div>
            </div>
          </div>
        ))}

        {suggestions.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            {profile ? 'No rule suggestions yet. Start profiling to generate suggestions.' : 'No profile found. Start profiling first.'}
          </div>
        )}
      </div>
    </div>
  );

  const renderRuleModal = () => {
    if (!selectedSuggestion || !showRuleModal) return null;

    return (
      <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
        <div className="bg-gray-800 rounded-xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
          <div className="p-6 border-b border-gray-700">
            <div className="flex justify-between items-start">
              <div>
                <h2 className="text-xl font-semibold">{selectedSuggestion.name}</h2>
                <p className="text-gray-400 text-sm mt-1">{selectedSuggestion.description}</p>
              </div>
              <button
                onClick={() => setShowRuleModal(false)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                &times;
              </button>
            </div>
          </div>

          <div className="p-6 overflow-y-auto max-h-[70vh]">
            {/* Rule Tabs */}
            <div className="flex gap-2 mb-4 border-b border-gray-700">
              {['semgrep', 'codeql', 'checkmarx', 'fortify'].map((format) => (
                <button
                  key={format}
                  onClick={() => setExportFormat(format)}
                  className={`px-4 py-2 -mb-px ${
                    exportFormat === format
                      ? 'border-b-2 border-blue-500 text-blue-400'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  {format.charAt(0).toUpperCase() + format.slice(1)}
                </button>
              ))}
            </div>

            {/* Rule Content */}
            <div className="bg-gray-900 rounded-lg p-4">
              <pre className="text-sm text-gray-300 overflow-x-auto whitespace-pre-wrap">
                {exportFormat === 'semgrep' && selectedSuggestion.semgrep_rule}
                {exportFormat === 'codeql' && selectedSuggestion.codeql_rule}
                {exportFormat === 'checkmarx' && selectedSuggestion.checkmarx_rule}
                {exportFormat === 'fortify' && selectedSuggestion.fortify_rule}
              </pre>
            </div>

            <div className="mt-4 flex justify-end gap-3">
              <button
                onClick={() => exportRule(selectedSuggestion.id, exportFormat)}
                className="px-4 py-2 bg-purple-500 hover:bg-purple-600 rounded-lg text-sm font-medium transition-colors"
              >
                Download {exportFormat.charAt(0).toUpperCase() + exportFormat.slice(1)} Rule
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
              Application Intelligence
            </h1>
            <p className="text-gray-400 mt-1">
              AI-powered application profiling and security rule suggestions
            </p>
          </div>

          <select
            value={selectedProjectId || ''}
            onChange={(e) => setSelectedProjectId(Number(e.target.value))}
            className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 min-w-[200px]"
          >
            {projects.map((project) => (
              <option key={project.id} value={project.id}>
                {project.name}
              </option>
            ))}
          </select>
        </div>

        {/* Progress Bar */}
        {(isPolling || (profile?.status && profile.status !== 'completed')) && renderProgressBar()}

        {/* Tabs */}
        <div className="flex gap-1 mb-6 bg-gray-800 p-1 rounded-lg w-fit">
          {['overview', 'techstack', 'security', 'suggestions'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab as any)}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === tab
                  ? 'bg-gradient-to-r from-blue-500 to-purple-500 text-white'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {tab === 'techstack' ? 'Tech Stack' : tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        {/* Content */}
        {!profile && !isPolling ? (
          <div className="text-center py-16 bg-gray-800 rounded-xl">
            <div className="text-6xl mb-4">&#128269;</div>
            <h2 className="text-xl font-semibold mb-2">No Profile Found</h2>
            <p className="text-gray-400 mb-6">
              Start profiling to analyze your application and get AI-powered security rule suggestions.
            </p>
            <button
              onClick={startProfiling}
              disabled={loading}
              className="px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600 rounded-lg font-medium transition-colors"
            >
              Start Application Profiling
            </button>
          </div>
        ) : (
          <>
            {activeTab === 'overview' && renderOverview()}
            {activeTab === 'techstack' && renderTechStack()}
            {activeTab === 'security' && renderSecurityAnalysis()}
            {activeTab === 'suggestions' && renderSuggestions()}
          </>
        )}
      </div>

      {renderRuleModal()}
    </div>
  );
};

export default ApplicationIntelligencePage;
