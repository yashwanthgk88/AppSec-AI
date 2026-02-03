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

// Enterprise Rules Types
interface Tool {
  id: string;
  name: string;
  extension: string;
  description: string;
  mime_type: string;
}

interface VulnerabilityType {
  id: string;
  name: string;
  category: string;
}

interface RuleTemplate {
  id: string;
  name: string;
  description: string;
  vulnerability_type: string;
  severity: string;
  cwe_id: string;
  owasp_category: string;
  languages: string[];
}

interface GeneratedRule {
  tool: string;
  tool_info: Tool;
  rule_name: string;
  rule_content: string;
  severity: string;
  language: string;
  vulnerability_type: string;
  cwe_id: string;
  owasp_category: string;
  generated_at: string;
}

interface GeneratedRules {
  rule_name: string;
  description: string;
  vulnerability_type: string;
  severity: string;
  language: string;
  cwe_id: string;
  owasp_category: string;
  generated_at: string;
  rules: Record<string, GeneratedRule | { error: string }>;
}

const CustomRulesPage: React.FC = () => {
  // Main tab state
  const [mainTab, setMainTab] = useState<'custom' | 'enterprise'>('custom');

  // Custom Rules State
  const [rules, setRules] = useState<CustomRule[]>([]);
  const [jobs, setJobs] = useState<EnhancementJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showAIGenerateModal, setShowAIGenerateModal] = useState(false);
  const [selectedRule, setSelectedRule] = useState<CustomRule | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('');
  const [filterLanguage, setFilterLanguage] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

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

  // Enterprise Rules State
  const [tools, setTools] = useState<Tool[]>([]);
  const [vulnerabilityTypes, setVulnerabilityTypes] = useState<VulnerabilityType[]>([]);
  const [enterpriseLanguages, setEnterpriseLanguages] = useState<string[]>([]);
  const [templates, setTemplates] = useState<RuleTemplate[]>([]);
  const [generatedRules, setGeneratedRules] = useState<GeneratedRules | null>(null);
  const [enterpriseLoading, setEnterpriseLoading] = useState(false);
  const [enterpriseTab, setEnterpriseTab] = useState<'generator' | 'templates'>('generator');
  const [selectedTool, setSelectedTool] = useState<string>('');
  const [copySuccess, setCopySuccess] = useState<string>('');

  const [enterpriseFormData, setEnterpriseFormData] = useState({
    rule_name: '',
    description: '',
    vulnerability_type: '',
    severity: 'high',
    language: 'python',
    pattern: '',
    cwe_id: '',
    owasp_category: '',
    remediation: '',
    selectedTools: [] as string[],
  });

  const token = localStorage.getItem('token');
  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    loadRules();
    loadJobs();
    loadEnterpriseData();
    const interval = setInterval(loadJobs, 5000);
    return () => clearInterval(interval);
  }, [filterSeverity, filterLanguage]);

  // Custom Rules Functions
  const loadRules = async () => {
    try {
      const params = new URLSearchParams();
      if (filterSeverity) params.append('severity', filterSeverity);
      if (filterLanguage) params.append('language', filterLanguage);

      const response = await axios.get(`http://localhost:8000/api/rules?${params}`, { headers });
      setRules(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to load rules:', error);
      setLoading(false);
    }
  };

  const loadJobs = async () => {
    try {
      const response = await axios.get('http://localhost:8000/api/rules/jobs?limit=10', { headers });
      setJobs(response.data);
    } catch (error) {
      console.error('Failed to load jobs:', error);
    }
  };

  const createRule = async () => {
    try {
      await axios.post('http://localhost:8000/api/rules', newRule, { headers });
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
      await axios.post('http://localhost:8000/api/rules/generate', aiGenerate, { headers });
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
      await axios.put(`http://localhost:8000/api/rules/${ruleId}`,
        { enabled: !currentEnabled },
        { headers }
      );
      loadRules();
    } catch (error) {
      alert('Failed to update rule');
    }
  };

  const deleteRule = async (ruleId: number) => {
    if (!confirm('Are you sure you want to delete this rule?')) return;
    try {
      await axios.delete(`http://localhost:8000/api/rules/${ruleId}`, { headers });
      loadRules();
    } catch (error) {
      alert('Failed to delete rule');
    }
  };

  // Enterprise Rules Functions
  const loadEnterpriseData = async () => {
    try {
      const [toolsRes, vulnTypesRes, langsRes, templatesRes] = await Promise.all([
        axios.get('http://localhost:8000/api/enterprise-rules/tools', { headers }),
        axios.get('http://localhost:8000/api/enterprise-rules/vulnerability-types', { headers }),
        axios.get('http://localhost:8000/api/enterprise-rules/languages', { headers }),
        axios.get('http://localhost:8000/api/enterprise-rules/templates', { headers }),
      ]);

      setTools(toolsRes.data);
      setVulnerabilityTypes(vulnTypesRes.data);
      setEnterpriseLanguages(langsRes.data);
      setTemplates(templatesRes.data);

      setEnterpriseFormData(prev => ({
        ...prev,
        selectedTools: toolsRes.data.map((t: Tool) => t.id)
      }));
    } catch (error) {
      console.error('Failed to load enterprise data:', error);
    }
  };

  const handleEnterpriseInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setEnterpriseFormData(prev => ({ ...prev, [name]: value }));

    if (name === 'vulnerability_type') {
      const vulnType = vulnerabilityTypes.find(v => v.id === value);
      if (vulnType) {
        setEnterpriseFormData(prev => ({
          ...prev,
          vulnerability_type: value,
          cwe_id: value,
          owasp_category: getOwaspForCwe(value),
        }));
      }
    }
  };

  const getOwaspForCwe = (cweId: string): string => {
    const mapping: Record<string, string> = {
      'CWE-89': 'A03:2021', 'CWE-79': 'A03:2021', 'CWE-78': 'A03:2021',
      'CWE-22': 'A01:2021', 'CWE-434': 'A04:2021', 'CWE-611': 'A05:2021',
      'CWE-918': 'A10:2021', 'CWE-352': 'A01:2021', 'CWE-287': 'A07:2021',
      'CWE-798': 'A07:2021', 'CWE-502': 'A08:2021', 'CWE-327': 'A02:2021',
    };
    return mapping[cweId] || '';
  };

  const toggleTool = (toolId: string) => {
    setEnterpriseFormData(prev => ({
      ...prev,
      selectedTools: prev.selectedTools.includes(toolId)
        ? prev.selectedTools.filter(t => t !== toolId)
        : [...prev.selectedTools, toolId]
    }));
  };

  const selectAllTools = () => {
    setEnterpriseFormData(prev => ({ ...prev, selectedTools: tools.map(t => t.id) }));
  };

  const deselectAllTools = () => {
    setEnterpriseFormData(prev => ({ ...prev, selectedTools: [] }));
  };

  const generateEnterpriseRules = async () => {
    if (!enterpriseFormData.rule_name || !enterpriseFormData.description || !enterpriseFormData.vulnerability_type) {
      alert('Please fill in required fields: Rule Name, Description, and Vulnerability Type');
      return;
    }
    if (enterpriseFormData.selectedTools.length === 0) {
      alert('Please select at least one tool');
      return;
    }

    setEnterpriseLoading(true);
    try {
      const response = await axios.post(
        'http://localhost:8000/api/enterprise-rules/generate-all',
        {
          rule_name: enterpriseFormData.rule_name,
          description: enterpriseFormData.description,
          vulnerability_type: enterpriseFormData.vulnerability_type.replace('CWE-', '').toLowerCase().replace(/[^a-z_]/g, '_'),
          severity: enterpriseFormData.severity,
          language: enterpriseFormData.language,
          pattern: enterpriseFormData.pattern || null,
          cwe_id: enterpriseFormData.cwe_id,
          owasp_category: enterpriseFormData.owasp_category,
          remediation: enterpriseFormData.remediation,
          tools: enterpriseFormData.selectedTools,
        },
        { headers }
      );

      setGeneratedRules(response.data);
      setSelectedTool(enterpriseFormData.selectedTools[0]);
    } catch (error: any) {
      console.error('Failed to generate rules:', error);
      alert(error.response?.data?.detail || 'Failed to generate rules');
    } finally {
      setEnterpriseLoading(false);
    }
  };

  const generateFromTemplate = async (template: RuleTemplate) => {
    setEnterpriseLoading(true);
    try {
      const response = await axios.post(
        `http://localhost:8000/api/enterprise-rules/generate-from-template/${template.id}`,
        null,
        {
          headers,
          params: {
            language: enterpriseFormData.language,
            tools: enterpriseFormData.selectedTools.length > 0 ? enterpriseFormData.selectedTools : null
          }
        }
      );

      setGeneratedRules(response.data);
      setSelectedTool(enterpriseFormData.selectedTools[0] || tools[0]?.id);
      setEnterpriseTab('generator');
    } catch (error: any) {
      console.error('Failed to generate from template:', error);
      alert(error.response?.data?.detail || 'Failed to generate from template');
    } finally {
      setEnterpriseLoading(false);
    }
  };

  const copyToClipboard = async (content: string, toolId: string) => {
    try {
      await navigator.clipboard.writeText(content);
      setCopySuccess(toolId);
      setTimeout(() => setCopySuccess(''), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const downloadRule = async (toolId: string) => {
    if (!generatedRules) return;
    const rule = generatedRules.rules[toolId];
    if (!rule || 'error' in rule) return;

    const tool = tools.find(t => t.id === toolId);
    const blob = new Blob([rule.rule_content], { type: tool?.mime_type || 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${enterpriseFormData.rule_name.replace(/\s+/g, '_').toLowerCase()}_${toolId}.${tool?.extension || 'txt'}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const downloadAllRules = async () => {
    if (!generatedRules) return;
    try {
      const response = await axios.post(
        'http://localhost:8000/api/enterprise-rules/export-all',
        {
          rule_name: generatedRules.rule_name,
          description: generatedRules.description,
          vulnerability_type: generatedRules.vulnerability_type,
          severity: generatedRules.severity,
          language: generatedRules.language,
          cwe_id: generatedRules.cwe_id,
          owasp_category: generatedRules.owasp_category,
          tools: Object.keys(generatedRules.rules).filter(k => !('error' in generatedRules.rules[k])),
        },
        { headers, responseType: 'blob' }
      );

      const blob = new Blob([response.data], { type: 'application/zip' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${generatedRules.rule_name.replace(/\s+/g, '_').toLowerCase()}_rules.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to download all rules:', error);
    }
  };

  // Utility Functions
  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: 'bg-red-100 text-red-800 border-red-300',
      high: 'bg-orange-100 text-orange-800 border-orange-300',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-300',
      low: 'bg-green-100 text-green-800 border-green-300'
    };
    return colors[severity] || colors.medium;
  };

  const getJobStatusColor = (status: string) => {
    const colors: Record<string, string> = {
      pending: 'bg-gray-100 text-gray-800',
      running: 'bg-blue-100 text-blue-800',
      completed: 'bg-green-100 text-green-800',
      failed: 'bg-red-100 text-red-800'
    };
    return colors[status] || colors.pending;
  };

  const getToolIcon = (toolId: string) => {
    const icons: Record<string, string> = {
      checkmarx: 'CX', fortify: 'FT', appscan: 'AS', acunetix: 'AC',
      webinspect: 'WI', semgrep: 'SG', codeql: 'QL',
    };
    return icons[toolId] || toolId.substring(0, 2).toUpperCase();
  };

  const getToolColor = (toolId: string) => {
    const colors: Record<string, string> = {
      checkmarx: 'from-purple-500 to-purple-700',
      fortify: 'from-blue-500 to-blue-700',
      appscan: 'from-cyan-500 to-cyan-700',
      acunetix: 'from-orange-500 to-orange-700',
      webinspect: 'from-green-500 to-green-700',
      semgrep: 'from-pink-500 to-pink-700',
      codeql: 'from-yellow-500 to-yellow-700',
    };
    return colors[toolId] || 'from-gray-500 to-gray-700';
  };

  const filteredRules = rules.filter(rule => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      rule.name.toLowerCase().includes(query) ||
      rule.description.toLowerCase().includes(query) ||
      rule.pattern.toLowerCase().includes(query) ||
      (rule.cwe && rule.cwe.toLowerCase().includes(query)) ||
      (rule.owasp && rule.owasp.toLowerCase().includes(query))
    );
  });

  if (loading) {
    return <div className="flex justify-center items-center h-screen">Loading...</div>;
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Security Rules</h1>
        <p className="text-gray-600">Create custom rules or generate enterprise-grade rules for leading security tools</p>
      </div>

      {/* Main Tabs */}
      <div className="flex gap-1 mb-6 bg-gray-100 p-1 rounded-lg w-fit">
        <button
          onClick={() => setMainTab('custom')}
          className={`px-6 py-2.5 rounded-md text-sm font-medium transition-colors ${
            mainTab === 'custom'
              ? 'bg-white text-blue-600 shadow-sm'
              : 'text-gray-600 hover:text-gray-900'
          }`}
        >
          Custom Rules
        </button>
        <button
          onClick={() => setMainTab('enterprise')}
          className={`px-6 py-2.5 rounded-md text-sm font-medium transition-colors ${
            mainTab === 'enterprise'
              ? 'bg-white text-purple-600 shadow-sm'
              : 'text-gray-600 hover:text-gray-900'
          }`}
        >
          Enterprise Rules Generator
        </button>
      </div>

      {/* Custom Rules Tab Content */}
      {mainTab === 'custom' && (
        <>
          {/* Actions Bar */}
          <div className="bg-white rounded-lg shadow-sm p-4 mb-6 flex flex-wrap gap-4 items-center justify-between">
            <div className="flex gap-3">
              <button
                onClick={() => setShowCreateModal(true)}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2"
              >
                <span>+</span> Create Rule
              </button>
              <button
                onClick={() => setShowAIGenerateModal(true)}
                className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 flex items-center gap-2"
              >
                <span>AI</span> Generate with AI
              </button>
            </div>

            {/* Filters */}
            <div className="flex gap-3 flex-wrap">
              <input
                type="text"
                placeholder="Search rules by name, description, or pattern..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="flex-1 min-w-[300px] px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
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

          {/* Search Results Info */}
          {searchQuery && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 mb-4">
              <p className="text-sm text-blue-800">
                Showing <span className="font-bold">{filteredRules.length}</span> of <span className="font-bold">{rules.length}</span> rules matching "{searchQuery}"
                {filteredRules.length !== rules.length && (
                  <button
                    onClick={() => setSearchQuery('')}
                    className="ml-2 text-blue-600 hover:text-blue-800 underline"
                  >
                    Clear search
                  </button>
                )}
              </p>
            </div>
          )}

          {/* Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-white rounded-lg shadow-sm p-4">
              <div className="text-2xl font-bold text-blue-600">
                {searchQuery ? filteredRules.length : rules.length}
              </div>
              <div className="text-sm text-gray-600">{searchQuery ? 'Filtered Rules' : 'Total Rules'}</div>
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
                  {filteredRules.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="px-6 py-8 text-center text-gray-500">
                        {searchQuery ? `No rules found matching "${searchQuery}"` : 'No rules available'}
                      </td>
                    </tr>
                  ) : (
                    filteredRules.map((rule) => (
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
                          {rule.generated_by === 'ai' ? 'AI' : 'User'}
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
                            {rule.enabled ? 'Enabled' : 'Disabled'}
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
                    ))
                  )}
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
                        <span>Generated {job.rules_generated} rules, Refined {job.rules_refined} rules</span>
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
        </>
      )}

      {/* Enterprise Rules Tab Content */}
      {mainTab === 'enterprise' && (
        <>
          {/* Enterprise Sub-tabs */}
          <div className="flex gap-1 mb-6 bg-gray-100 p-1 rounded-lg w-fit">
            {['generator', 'templates'].map((tab) => (
              <button
                key={tab}
                onClick={() => setEnterpriseTab(tab as any)}
                className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                  enterpriseTab === tab
                    ? 'bg-white text-purple-600 shadow-sm'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>

          {/* Generator Tab */}
          {enterpriseTab === 'generator' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Form Section */}
              <div className="bg-white rounded-lg shadow-sm p-6">
                <h3 className="text-xl font-semibold text-gray-900 mb-6">Rule Configuration</h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Rule Name *</label>
                    <input
                      type="text"
                      name="rule_name"
                      value={enterpriseFormData.rule_name}
                      onChange={handleEnterpriseInputChange}
                      placeholder="e.g., SQL Injection in User Input"
                      className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Description *</label>
                    <textarea
                      name="description"
                      value={enterpriseFormData.description}
                      onChange={handleEnterpriseInputChange}
                      placeholder="Describe the vulnerability this rule detects..."
                      rows={3}
                      className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Vulnerability Type *</label>
                      <select
                        name="vulnerability_type"
                        value={enterpriseFormData.vulnerability_type}
                        onChange={handleEnterpriseInputChange}
                        className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                      >
                        <option value="">Select type...</option>
                        {vulnerabilityTypes.map((vt) => (
                          <option key={vt.id} value={vt.id}>
                            {vt.name} ({vt.id})
                          </option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                      <select
                        name="severity"
                        value={enterpriseFormData.severity}
                        onChange={handleEnterpriseInputChange}
                        className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                      >
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Language</label>
                      <select
                        name="language"
                        value={enterpriseFormData.language}
                        onChange={handleEnterpriseInputChange}
                        className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                      >
                        {enterpriseLanguages.map((lang) => (
                          <option key={lang} value={lang}>
                            {lang.charAt(0).toUpperCase() + lang.slice(1)}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">CWE ID</label>
                      <input
                        type="text"
                        name="cwe_id"
                        value={enterpriseFormData.cwe_id}
                        onChange={handleEnterpriseInputChange}
                        placeholder="e.g., CWE-89"
                        className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">OWASP Category</label>
                      <input
                        type="text"
                        name="owasp_category"
                        value={enterpriseFormData.owasp_category}
                        onChange={handleEnterpriseInputChange}
                        placeholder="e.g., A03:2021"
                        className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Custom Pattern</label>
                      <input
                        type="text"
                        name="pattern"
                        value={enterpriseFormData.pattern}
                        onChange={handleEnterpriseInputChange}
                        placeholder="Regex pattern"
                        className="w-full border border-gray-300 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Remediation Guidance</label>
                    <textarea
                      name="remediation"
                      value={enterpriseFormData.remediation}
                      onChange={handleEnterpriseInputChange}
                      placeholder="How to fix this vulnerability..."
                      rows={2}
                      className="w-full border border-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    />
                  </div>

                  {/* Tool Selection */}
                  <div>
                    <div className="flex justify-between items-center mb-2">
                      <label className="text-sm font-medium text-gray-700">Target Tools</label>
                      <div className="flex gap-2">
                        <button onClick={selectAllTools} className="text-xs text-purple-600 hover:text-purple-700">
                          Select All
                        </button>
                        <span className="text-gray-400">|</span>
                        <button onClick={deselectAllTools} className="text-xs text-gray-500 hover:text-gray-700">
                          Deselect All
                        </button>
                      </div>
                    </div>
                    <div className="grid grid-cols-4 gap-2">
                      {tools.map((tool) => (
                        <button
                          key={tool.id}
                          onClick={() => toggleTool(tool.id)}
                          className={`p-3 rounded-lg border-2 transition-all ${
                            enterpriseFormData.selectedTools.includes(tool.id)
                              ? 'border-purple-500 bg-purple-50'
                              : 'border-gray-200 hover:border-gray-300 bg-white'
                          }`}
                        >
                          <div className={`w-8 h-8 mx-auto rounded-md bg-gradient-to-br ${getToolColor(tool.id)} flex items-center justify-center text-white font-bold text-xs mb-1`}>
                            {getToolIcon(tool.id)}
                          </div>
                          <div className="text-xs text-center truncate text-gray-700">{tool.name}</div>
                        </button>
                      ))}
                    </div>
                  </div>

                  <button
                    onClick={generateEnterpriseRules}
                    disabled={enterpriseLoading}
                    className={`w-full py-3 rounded-lg font-medium transition-all text-white ${
                      enterpriseLoading
                        ? 'bg-gray-400 cursor-not-allowed'
                        : 'bg-purple-600 hover:bg-purple-700'
                    }`}
                  >
                    {enterpriseLoading ? (
                      <span className="flex items-center justify-center gap-2">
                        <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                        Generating Rules...
                      </span>
                    ) : (
                      `Generate Rules for ${enterpriseFormData.selectedTools.length} Tool${enterpriseFormData.selectedTools.length !== 1 ? 's' : ''}`
                    )}
                  </button>
                </div>
              </div>

              {/* Generated Rules Section */}
              <div className="bg-white rounded-lg shadow-sm p-6">
                <div className="flex justify-between items-center mb-6">
                  <h3 className="text-xl font-semibold text-gray-900">Generated Rules</h3>
                  {generatedRules && (
                    <button
                      onClick={downloadAllRules}
                      className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-sm font-medium text-white transition-colors flex items-center gap-2"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                      </svg>
                      Download All (ZIP)
                    </button>
                  )}
                </div>

                {generatedRules ? (
                  <>
                    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 mb-4">
                      <div className="flex items-center gap-3 mb-2">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(generatedRules.severity)}`}>
                          {generatedRules.severity.toUpperCase()}
                        </span>
                        <span className="text-xs bg-gray-200 text-gray-700 px-2 py-1 rounded">{generatedRules.cwe_id}</span>
                        <span className="text-xs bg-gray-200 text-gray-700 px-2 py-1 rounded">{generatedRules.owasp_category}</span>
                      </div>
                      <h4 className="font-medium text-gray-900">{generatedRules.rule_name}</h4>
                      <p className="text-sm text-gray-600 mt-1">{generatedRules.description}</p>
                    </div>

                    <div className="flex gap-1 mb-4 overflow-x-auto pb-2">
                      {Object.keys(generatedRules.rules).map((toolId) => {
                        const hasError = 'error' in generatedRules.rules[toolId];
                        const tool = tools.find(t => t.id === toolId);
                        return (
                          <button
                            key={toolId}
                            onClick={() => setSelectedTool(toolId)}
                            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${
                              selectedTool === toolId
                                ? 'bg-purple-100 text-purple-700 border border-purple-300'
                                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                            } ${hasError ? 'opacity-50' : ''}`}
                          >
                            <div className={`w-6 h-6 rounded bg-gradient-to-br ${getToolColor(toolId)} flex items-center justify-center text-white text-xs font-bold`}>
                              {getToolIcon(toolId)}
                            </div>
                            {tool?.name || toolId}
                            {hasError && <span className="text-red-500">!</span>}
                          </button>
                        );
                      })}
                    </div>

                    {selectedTool && generatedRules.rules[selectedTool] && (
                      <div className="relative">
                        {'error' in generatedRules.rules[selectedTool] ? (
                          <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">
                            Error: {(generatedRules.rules[selectedTool] as { error: string }).error}
                          </div>
                        ) : (
                          <>
                            <div className="absolute top-2 right-2 flex gap-2 z-10">
                              <button
                                onClick={() => copyToClipboard((generatedRules.rules[selectedTool] as GeneratedRule).rule_content, selectedTool)}
                                className={`p-2 rounded-lg transition-colors ${
                                  copySuccess === selectedTool
                                    ? 'bg-green-500 text-white'
                                    : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                                }`}
                                title="Copy to clipboard"
                              >
                                {copySuccess === selectedTool ? (
                                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                  </svg>
                                ) : (
                                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                  </svg>
                                )}
                              </button>
                              <button
                                onClick={() => downloadRule(selectedTool)}
                                className="p-2 bg-gray-200 hover:bg-gray-300 rounded-lg text-gray-700 transition-colors"
                                title="Download file"
                              >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                                </svg>
                              </button>
                            </div>
                            <pre className="bg-gray-900 rounded-lg p-4 overflow-auto max-h-96 text-sm font-mono text-gray-300">
                              {(generatedRules.rules[selectedTool] as GeneratedRule).rule_content}
                            </pre>
                          </>
                        )}
                      </div>
                    )}
                  </>
                ) : (
                  <div className="text-center py-16 text-gray-400">
                    <div className="text-5xl mb-4">&#128221;</div>
                    <p>Configure your rule and click Generate to create rules for your selected tools.</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Templates Tab */}
          {enterpriseTab === 'templates' && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {templates.map((template) => (
                <div key={template.id} className="bg-white rounded-lg shadow-sm p-6 hover:shadow-md transition-shadow border border-gray-100">
                  <div className="flex items-center gap-3 mb-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(template.severity)}`}>
                      {template.severity.toUpperCase()}
                    </span>
                    <span className="text-xs bg-purple-100 text-purple-700 px-2 py-1 rounded">
                      {template.cwe_id}
                    </span>
                  </div>

                  <h4 className="text-lg font-semibold text-gray-900 mb-2">{template.name}</h4>
                  <p className="text-sm text-gray-600 mb-4">{template.description}</p>

                  <div className="flex flex-wrap gap-1 mb-4">
                    {template.languages.map((lang) => (
                      <span key={lang} className="text-xs bg-gray-100 text-gray-700 px-2 py-1 rounded">
                        {lang}
                      </span>
                    ))}
                  </div>

                  <div className="flex gap-2">
                    <select
                      value={enterpriseFormData.language}
                      onChange={(e) => setEnterpriseFormData(prev => ({ ...prev, language: e.target.value }))}
                      className="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
                    >
                      {template.languages.map((lang) => (
                        <option key={lang} value={lang}>
                          {lang.charAt(0).toUpperCase() + lang.slice(1)}
                        </option>
                      ))}
                    </select>
                    <button
                      onClick={() => generateFromTemplate(template)}
                      disabled={enterpriseLoading}
                      className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg text-sm font-medium text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Generate
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

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
              Generate Rule with AI
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
                x
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
                {selectedRule.generated_by === 'ai' && <span className="ml-2">AI Generated</span>}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CustomRulesPage;
