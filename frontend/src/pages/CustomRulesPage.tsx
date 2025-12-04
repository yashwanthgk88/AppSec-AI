import React, { useState, useEffect } from 'react';
import axios from 'axios';

interface CustomRule {
  id: number;
  name: string;
  pattern: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  language: string;
  cwe?: string;
  owasp?: string;
  remediation?: string;
  remediation_code?: string;
  enabled: number;
  created_by: string;
  created_at: string;
  generated_by: string;
  total_detections: number;
  false_positives: number;
  true_positives: number;
  precision?: number;
}

interface EnhancementJob {
  id: number;
  job_type: string;
  status: string;
  progress: number;
  triggered_by: string;
  rules_generated: number;
  rules_refined: number;
  started_at?: string;
  completed_at?: string;
}

const CustomRulesPage: React.FC = () => {
  const [rules, setRules] = useState<CustomRule[]>([]);
  const [jobs, setJobs] = useState<EnhancementJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showAIGenerateModal, setShowAIGenerateModal] = useState(false);
  const [selectedRule, setSelectedRule] = useState<CustomRule | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('');
  const [filterLanguage, setFilterLanguage] = useState<string>('');

  const [newRule, setNewRule] = useState({
    name: '',
    pattern: '',
    severity: 'medium' as 'critical' | 'high' | 'medium' | 'low',
    description: '',
    language: '*',
    cwe: '',
    owasp: '',
    remediation: '',
    enabled: true
  });

  const [aiGenerate, setAiGenerate] = useState({
    rule_name: '',
    vulnerability_description: '',
    severity: 'medium' as 'critical' | 'high' | 'medium' | 'low',
    languages: ['*']
  });

  useEffect(() => {
    loadRules();
    loadJobs();
    const interval = setInterval(loadJobs, 5000); // Poll jobs every 5s
    return () => clearInterval(interval);
  }, [filterSeverity, filterLanguage]);

  const loadRules = async () => {
    try {
      const token = localStorage.getItem('token');
      const params = new URLSearchParams();
      if (filterSeverity) params.append('severity', filterSeverity);
      if (filterLanguage) params.append('language', filterLanguage);

      const response = await axios.get(`http://localhost:8000/api/rules/?${params}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setRules(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to load rules:', error);
      setLoading(false);
    }
  };

  const loadJobs = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:8000/api/rules/jobs/?limit=10', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setJobs(response.data);
    } catch (error) {
      console.error('Failed to load jobs:', error);
    }
  };

  const createRule = async () => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('http://localhost:8000/api/rules/', newRule, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setShowCreateModal(false);
      setNewRule({
        name: '', pattern: '', severity: 'medium', description: '',
        language: '*', cwe: '', owasp: '', remediation: '', enabled: true
      });
      loadRules();
    } catch (error: any) {
      alert(`Failed to create rule: ${error.response?.data?.detail || error.message}`);
    }
  };

  const generateRuleWithAI = async () => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('http://localhost:8000/api/rules/generate', aiGenerate, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setShowAIGenerateModal(false);
      setAiGenerate({
        rule_name: '', vulnerability_description: '', severity: 'medium', languages: ['*']
      });
      alert('AI rule generation started! Check the Enhancement Jobs section for progress.');
      loadJobs();
    } catch (error: any) {
      alert(`Failed to generate rule: ${error.response?.data?.detail || error.message}`);
    }
  };

  const toggleRuleEnabled = async (ruleId: number, currentEnabled: number) => {
    try {
      const token = localStorage.getItem('token');
      await axios.put(`http://localhost:8000/api/rules/${ruleId}`,
        { enabled: !currentEnabled },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      loadRules();
    } catch (error) {
      alert('Failed to update rule');
    }
  };

  const deleteRule = async (ruleId: number) => {
    if (!confirm('Are you sure you want to delete this rule?')) return;

    try {
      const token = localStorage.getItem('token');
      await axios.delete(`http://localhost:8000/api/rules/${ruleId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      loadRules();
    } catch (error) {
      alert('Failed to delete rule');
    }
  };

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: 'bg-red-100 text-red-800 border-red-300',
      high: 'bg-orange-100 text-orange-800 border-orange-300',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-300',
      low: 'bg-green-100 text-green-800 border-green-300'
    };
    return colors[severity as keyof typeof colors] || colors.medium;
  };

  const getJobStatusColor = (status: string) => {
    const colors = {
      pending: 'bg-gray-100 text-gray-800',
      running: 'bg-blue-100 text-blue-800',
      completed: 'bg-green-100 text-green-800',
      failed: 'bg-red-100 text-red-800'
    };
    return colors[status as keyof typeof colors] || colors.pending;
  };

  if (loading) {
    return <div className="flex justify-center items-center h-screen">Loading...</div>;
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Custom Security Rules</h1>
        <p className="text-gray-600">Manage user-defined and AI-generated vulnerability detection rules</p>
      </div>

      {/* Actions Bar */}
      <div className="bg-white rounded-lg shadow-sm p-4 mb-6 flex flex-wrap gap-4 items-center justify-between">
        <div className="flex gap-3">
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2"
          >
            <span>➕</span> Create Rule
          </button>
          <button
            onClick={() => setShowAIGenerateModal(true)}
            className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 flex items-center gap-2"
          >
            <span>🤖</span> Generate with AI
          </button>
        </div>

        {/* Filters */}
        <div className="flex gap-3">
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="px-3 py-2 border rounded-lg"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            value={filterLanguage}
            onChange={(e) => setFilterLanguage(e.target.value)}
            className="px-3 py-2 border rounded-lg"
          >
            <option value="">All Languages</option>
            <option value="*">All (*)</option>
            <option value="python">Python</option>
            <option value="javascript">JavaScript</option>
            <option value="java">Java</option>
            <option value="php">PHP</option>
            <option value="go">Go</option>
          </select>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="text-2xl font-bold text-blue-600">{rules.length}</div>
          <div className="text-sm text-gray-600">Total Rules</div>
        </div>
        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="text-2xl font-bold text-green-600">
            {rules.filter(r => r.enabled).length}
          </div>
          <div className="text-sm text-gray-600">Enabled Rules</div>
        </div>
        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="text-2xl font-bold text-purple-600">
            {rules.filter(r => r.generated_by === 'ai').length}
          </div>
          <div className="text-sm text-gray-600">AI Generated</div>
        </div>
        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="text-2xl font-bold text-orange-600">
            {rules.reduce((sum, r) => sum + r.total_detections, 0)}
          </div>
          <div className="text-sm text-gray-600">Total Detections</div>
        </div>
      </div>

      {/* Rules Table */}
      <div className="bg-white rounded-lg shadow-sm overflow-hidden mb-6">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rule Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Language</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Detections</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Precision</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {rules.map((rule) => (
                <tr key={rule.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div className="font-medium text-gray-900">{rule.name}</div>
                    <div className="text-sm text-gray-500 truncate max-w-xs" title={rule.pattern}>
                      {rule.pattern}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(rule.severity)}`}>
                      {rule.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-900">{rule.language}</td>
                  <td className="px-6 py-4 text-sm text-gray-900">
                    {rule.total_detections}
                    {rule.false_positives > 0 && (
                      <span className="text-red-600 ml-1">({rule.false_positives} FP)</span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-sm">
                    {rule.precision !== null && rule.precision !== undefined ? (
                      <span className={(rule.precision ?? 0) < 0.85 ? 'text-orange-600 font-semibold' : 'text-green-600'}>
                        {((rule.precision ?? 0) * 100).toFixed(1)}%
                      </span>
                    ) : (
                      <span className="text-gray-400">N/A</span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-900">
                    {rule.generated_by === 'ai' ? '🤖 AI' : '👤 User'}
                  </td>
                  <td className="px-6 py-4">
                    <button
                      onClick={() => toggleRuleEnabled(rule.id, rule.enabled)}
                      className={`px-3 py-1 rounded-full text-xs font-semibold ${
                        rule.enabled
                          ? 'bg-green-100 text-green-800 hover:bg-green-200'
                          : 'bg-gray-100 text-gray-800 hover:bg-gray-200'
                      }`}
                    >
                      {rule.enabled ? '✓ Enabled' : '✗ Disabled'}
                    </button>
                  </td>
                  <td className="px-6 py-4 text-sm">
                    <button
                      onClick={() => setSelectedRule(rule)}
                      className="text-blue-600 hover:text-blue-800 mr-3"
                    >
                      View
                    </button>
                    <button
                      onClick={() => deleteRule(rule.id)}
                      className="text-red-600 hover:text-red-800"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Enhancement Jobs */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <h2 className="text-xl font-bold text-gray-900 mb-4">Recent Enhancement Jobs</h2>
        <div className="space-y-3">
          {jobs.slice(0, 5).map((job) => (
            <div key={job.id} className="border rounded-lg p-4 flex items-center justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-1 text-xs font-semibold rounded ${getJobStatusColor(job.status)}`}>
                    {job.status.toUpperCase()}
                  </span>
                  <span className="font-medium text-gray-900">
                    {job.job_type.replace('_', ' ').toUpperCase()}
                  </span>
                  <span className="text-sm text-gray-600">by {job.triggered_by}</span>
                </div>
                <div className="text-sm text-gray-600 mt-1">
                  {job.status === 'completed' && (
                    <span>✓ Generated {job.rules_generated} rules, Refined {job.rules_refined} rules</span>
                  )}
                  {job.status === 'running' && (
                    <div className="flex items-center gap-2">
                      <div className="w-48 bg-gray-200 rounded-full h-2">
                        <div
                          className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                          style={{ width: `${job.progress}%` }}
                        />
                      </div>
                      <span>{job.progress}%</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Create Rule Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6">
            <h2 className="text-2xl font-bold mb-4">Create Custom Rule</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Rule Name *</label>
                <input
                  type="text"
                  value={newRule.name}
                  onChange={(e) => setNewRule({...newRule, name: e.target.value})}
                  className="w-full px-3 py-2 border rounded-lg"
                  placeholder="e.g., SQL Injection via String Concatenation"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Pattern (Regex) *</label>
                <input
                  type="text"
                  value={newRule.pattern}
                  onChange={(e) => setNewRule({...newRule, pattern: e.target.value})}
                  className="w-full px-3 py-2 border rounded-lg font-mono text-sm"
                  placeholder="e.g., (execute|query).*\+"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Severity *</label>
                  <select
                    value={newRule.severity}
                    onChange={(e) => setNewRule({...newRule, severity: e.target.value as any})}
                    className="w-full px-3 py-2 border rounded-lg"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Language</label>
                  <select
                    value={newRule.language}
                    onChange={(e) => setNewRule({...newRule, language: e.target.value})}
                    className="w-full px-3 py-2 border rounded-lg"
                  >
                    <option value="*">All Languages</option>
                    <option value="python">Python</option>
                    <option value="javascript">JavaScript</option>
                    <option value="java">Java</option>
                    <option value="php">PHP</option>
                    <option value="go">Go</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Description *</label>
                <textarea
                  value={newRule.description}
                  onChange={(e) => setNewRule({...newRule, description: e.target.value})}
                  className="w-full px-3 py-2 border rounded-lg"
                  rows={3}
                  placeholder="Describe what this rule detects..."
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">CWE</label>
                  <input
                    type="text"
                    value={newRule.cwe}
                    onChange={(e) => setNewRule({...newRule, cwe: e.target.value})}
                    className="w-full px-3 py-2 border rounded-lg"
                    placeholder="e.g., CWE-89"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">OWASP</label>
                  <input
                    type="text"
                    value={newRule.owasp}
                    onChange={(e) => setNewRule({...newRule, owasp: e.target.value})}
                    className="w-full px-3 py-2 border rounded-lg"
                    placeholder="e.g., A03:2021 - Injection"
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Remediation</label>
                <textarea
                  value={newRule.remediation}
                  onChange={(e) => setNewRule({...newRule, remediation: e.target.value})}
                  className="w-full px-3 py-2 border rounded-lg"
                  rows={2}
                  placeholder="How to fix this vulnerability..."
                />
              </div>
              <div className="flex justify-end gap-3 mt-6">
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={createRule}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                  disabled={!newRule.name || !newRule.pattern || !newRule.description}
                >
                  Create Rule
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* AI Generate Modal */}
      {showAIGenerateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg max-w-2xl w-full p-6">
            <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
              <span>🤖</span> Generate Rule with AI
            </h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Rule Name *</label>
                <input
                  type="text"
                  value={aiGenerate.rule_name}
                  onChange={(e) => setAiGenerate({...aiGenerate, rule_name: e.target.value})}
                  className="w-full px-3 py-2 border rounded-lg"
                  placeholder="e.g., Prototype Pollution in JavaScript"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Vulnerability Description *
                </label>
                <textarea
                  value={aiGenerate.vulnerability_description}
                  onChange={(e) => setAiGenerate({...aiGenerate, vulnerability_description: e.target.value})}
                  className="w-full px-3 py-2 border rounded-lg"
                  rows={4}
                  placeholder="Describe what vulnerability the rule should detect. Be specific about the attack pattern, vulnerable code constructs, and programming languages..."
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Severity *</label>
                <select
                  value={aiGenerate.severity}
                  onChange={(e) => setAiGenerate({...aiGenerate, severity: e.target.value as any})}
                  className="w-full px-3 py-2 border rounded-lg"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div className="flex justify-end gap-3 mt-6">
                <button
                  onClick={() => setShowAIGenerateModal(false)}
                  className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={generateRuleWithAI}
                  className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
                  disabled={!aiGenerate.rule_name || !aiGenerate.vulnerability_description}
                >
                  Generate with AI
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Rule Details Modal */}
      {selectedRule && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg max-w-3xl w-full max-h-[90vh] overflow-y-auto p-6">
            <div className="flex justify-between items-start mb-4">
              <h2 className="text-2xl font-bold">{selectedRule.name}</h2>
              <button onClick={() => setSelectedRule(null)} className="text-gray-500 hover:text-gray-700 text-2xl">
                ×
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <span className={`px-3 py-1 text-sm font-semibold rounded-full ${getSeverityColor(selectedRule.severity)}`}>
                  {selectedRule.severity.toUpperCase()}
                </span>
                <span className="ml-3 text-gray-600">Language: {selectedRule.language}</span>
              </div>
              <div>
                <h3 className="font-semibold text-gray-700 mb-1">Pattern:</h3>
                <code className="block bg-gray-100 p-3 rounded text-sm font-mono break-all">
                  {selectedRule.pattern}
                </code>
              </div>
              <div>
                <h3 className="font-semibold text-gray-700 mb-1">Description:</h3>
                <p className="text-gray-600">{selectedRule.description}</p>
              </div>
              {selectedRule.remediation && (
                <div>
                  <h3 className="font-semibold text-gray-700 mb-1">Remediation:</h3>
                  <p className="text-gray-600">{selectedRule.remediation}</p>
                </div>
              )}
              <div className="grid grid-cols-2 gap-4">
                {selectedRule.cwe && (
                  <div>
                    <h3 className="font-semibold text-gray-700 mb-1">CWE:</h3>
                    <p className="text-gray-600">{selectedRule.cwe}</p>
                  </div>
                )}
                {selectedRule.owasp && (
                  <div>
                    <h3 className="font-semibold text-gray-700 mb-1">OWASP:</h3>
                    <p className="text-gray-600">{selectedRule.owasp}</p>
                  </div>
                )}
              </div>
              <div className="border-t pt-4">
                <h3 className="font-semibold text-gray-700 mb-2">Performance Metrics:</h3>
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-blue-50 p-3 rounded">
                    <div className="text-2xl font-bold text-blue-600">{selectedRule.total_detections}</div>
                    <div className="text-sm text-gray-600">Total Detections</div>
                  </div>
                  <div className="bg-green-50 p-3 rounded">
                    <div className="text-2xl font-bold text-green-600">{selectedRule.true_positives}</div>
                    <div className="text-sm text-gray-600">True Positives</div>
                  </div>
                  <div className="bg-red-50 p-3 rounded">
                    <div className="text-2xl font-bold text-red-600">{selectedRule.false_positives}</div>
                    <div className="text-sm text-gray-600">False Positives</div>
                  </div>
                </div>
                {selectedRule.precision !== null && (
                  <div className="mt-3 text-center">
                    <span className="text-lg font-semibold">
                      Precision:
                      <span className={(selectedRule.precision ?? 0) < 0.85 ? 'text-orange-600' : 'text-green-600'}>
                        {' '}{((selectedRule.precision ?? 0) * 100).toFixed(1)}%
                      </span>
                    </span>
                  </div>
                )}
              </div>
              <div className="text-sm text-gray-500">
                Created by {selectedRule.created_by} on {new Date(selectedRule.created_at).toLocaleString()}
                {selectedRule.generated_by === 'ai' && <span className="ml-2">🤖 AI Generated</span>}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CustomRulesPage;
