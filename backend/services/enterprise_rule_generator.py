"""
Enterprise Security Rule Generator Service

Generates custom security rules for enterprise SAST/DAST tools:
- Checkmarx (CxQL)
- Fortify (Fortify Rule Pack XML)
- HCL AppScan (XML patterns)
- Acunetix (Custom checks)
- Micro Focus WebInspect (SecureBase rules)
- Semgrep (YAML)
- CodeQL (QL)
"""

import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class EnterpriseRuleGenerator:
    """Generates security rules for multiple enterprise scanning tools"""

    # Supported tools and their configurations
    SUPPORTED_TOOLS = {
        "checkmarx": {
            "name": "Checkmarx",
            "extension": "cxql",
            "description": "Checkmarx CxQL (Custom Query Language)",
            "mime_type": "text/plain"
        },
        "fortify": {
            "name": "Fortify",
            "extension": "xml",
            "description": "Fortify Rule Pack XML",
            "mime_type": "application/xml"
        },
        "appscan": {
            "name": "HCL AppScan",
            "extension": "xml",
            "description": "HCL AppScan Custom Rules XML",
            "mime_type": "application/xml"
        },
        "acunetix": {
            "name": "Acunetix",
            "extension": "script",
            "description": "Acunetix Custom Script Check",
            "mime_type": "text/plain"
        },
        "webinspect": {
            "name": "Micro Focus WebInspect",
            "extension": "xml",
            "description": "WebInspect SecureBase Rule",
            "mime_type": "application/xml"
        },
        "semgrep": {
            "name": "Semgrep",
            "extension": "yaml",
            "description": "Semgrep YAML Rule",
            "mime_type": "application/x-yaml"
        },
        "codeql": {
            "name": "CodeQL",
            "extension": "ql",
            "description": "CodeQL Query",
            "mime_type": "text/plain"
        }
    }

    # CWE to vulnerability category mapping
    CWE_CATEGORIES = {
        "CWE-89": {"name": "SQL Injection", "category": "injection"},
        "CWE-79": {"name": "Cross-Site Scripting (XSS)", "category": "injection"},
        "CWE-78": {"name": "OS Command Injection", "category": "injection"},
        "CWE-94": {"name": "Code Injection", "category": "injection"},
        "CWE-22": {"name": "Path Traversal", "category": "file"},
        "CWE-434": {"name": "Unrestricted File Upload", "category": "file"},
        "CWE-611": {"name": "XXE Injection", "category": "injection"},
        "CWE-918": {"name": "SSRF", "category": "injection"},
        "CWE-352": {"name": "CSRF", "category": "auth"},
        "CWE-287": {"name": "Improper Authentication", "category": "auth"},
        "CWE-306": {"name": "Missing Authentication", "category": "auth"},
        "CWE-798": {"name": "Hardcoded Credentials", "category": "secret"},
        "CWE-321": {"name": "Hardcoded Cryptographic Key", "category": "secret"},
        "CWE-327": {"name": "Broken Crypto Algorithm", "category": "crypto"},
        "CWE-328": {"name": "Weak Hash", "category": "crypto"},
        "CWE-502": {"name": "Deserialization", "category": "injection"},
        "CWE-601": {"name": "Open Redirect", "category": "injection"},
        "CWE-200": {"name": "Information Exposure", "category": "info"},
        "CWE-532": {"name": "Sensitive Log Data", "category": "info"},
        "CWE-209": {"name": "Error Message Information Leak", "category": "info"},
    }

    # Language-specific patterns
    LANGUAGE_PATTERNS = {
        "python": {
            "sql_injection": [
                r'execute\s*\(\s*f["\']',
                r'execute\s*\(\s*["\'].*%s',
                r'cursor\.execute\s*\(\s*[^,]+\+',
                r'\.format\s*\([^)]*\).*execute',
            ],
            "command_injection": [
                r'os\.system\s*\(',
                r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True',
                r'eval\s*\(',
                r'exec\s*\(',
            ],
            "xss": [
                r'render_template_string\s*\(',
                r'Markup\s*\([^)]*\+',
            ],
            "path_traversal": [
                r'open\s*\([^)]*\+',
                r'os\.path\.join\s*\([^)]*request\.',
            ],
        },
        "java": {
            "sql_injection": [
                r'createStatement\s*\(\)',
                r'executeQuery\s*\([^)]*\+',
                r'PreparedStatement.*\+.*execute',
            ],
            "command_injection": [
                r'Runtime\.getRuntime\(\)\.exec\s*\(',
                r'ProcessBuilder\s*\([^)]*\+',
            ],
            "xss": [
                r'\.getWriter\(\)\.print(?:ln)?\s*\([^)]*request\.',
            ],
            "deserialization": [
                r'ObjectInputStream\s*\(',
                r'\.readObject\s*\(\)',
            ],
        },
        "javascript": {
            "sql_injection": [
                r'query\s*\(\s*`[^`]*\$\{',
                r'\.raw\s*\(\s*`',
            ],
            "xss": [
                r'\.innerHTML\s*=',
                r'document\.write\s*\(',
                r'eval\s*\(',
            ],
            "command_injection": [
                r'child_process\.exec\s*\(',
                r'execSync\s*\(',
            ],
            "prototype_pollution": [
                r'Object\.assign\s*\([^,]*,\s*req\.',
                r'\[req\.(?:body|query|params)',
            ],
        },
        "csharp": {
            "sql_injection": [
                r'SqlCommand\s*\([^)]*\+',
                r'ExecuteReader\s*\([^)]*\+',
            ],
            "command_injection": [
                r'Process\.Start\s*\([^)]*\+',
            ],
            "xss": [
                r'Response\.Write\s*\([^)]*Request\.',
            ],
            "deserialization": [
                r'BinaryFormatter\s*\(',
                r'\.Deserialize\s*\(',
            ],
        },
        "php": {
            "sql_injection": [
                r'mysql_query\s*\(\s*["\'].*\.\s*\$',
                r'mysqli_query\s*\([^,]*,\s*["\'].*\$',
            ],
            "command_injection": [
                r'exec\s*\([^)]*\$',
                r'system\s*\([^)]*\$',
                r'passthru\s*\([^)]*\$',
                r'shell_exec\s*\([^)]*\$',
            ],
            "xss": [
                r'echo\s+\$_(?:GET|POST|REQUEST)',
            ],
            "file_inclusion": [
                r'include\s*\([^)]*\$',
                r'require\s*\([^)]*\$',
            ],
        },
        "go": {
            "sql_injection": [
                r'db\.Query\s*\([^)]*\+',
                r'fmt\.Sprintf.*db\.(?:Query|Exec)',
            ],
            "command_injection": [
                r'exec\.Command\s*\([^)]*\+',
            ],
            "path_traversal": [
                r'filepath\.Join\s*\([^)]*r\.URL',
            ],
        },
    }

    def __init__(self):
        pass

    def get_supported_tools(self) -> List[Dict[str, Any]]:
        """Get list of supported tools with their configurations"""
        return [
            {"id": tool_id, **config}
            for tool_id, config in self.SUPPORTED_TOOLS.items()
        ]

    def generate_rule(
        self,
        tool: str,
        rule_name: str,
        description: str,
        vulnerability_type: str,
        severity: str,
        language: str,
        pattern: Optional[str] = None,
        cwe_id: Optional[str] = None,
        owasp_category: Optional[str] = None,
        custom_message: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a security rule for the specified tool.

        Args:
            tool: Target tool (checkmarx, fortify, appscan, etc.)
            rule_name: Name of the rule
            description: Description of what the rule detects
            vulnerability_type: Type of vulnerability (sql_injection, xss, etc.)
            severity: Severity level (critical, high, medium, low)
            language: Target programming language
            pattern: Optional custom regex pattern
            cwe_id: CWE identifier
            owasp_category: OWASP category
            custom_message: Custom message for findings
            remediation: Remediation guidance

        Returns:
            Dictionary containing the generated rule and metadata
        """
        if tool not in self.SUPPORTED_TOOLS:
            raise ValueError(f"Unsupported tool: {tool}. Supported: {list(self.SUPPORTED_TOOLS.keys())}")

        # Get or generate pattern
        if not pattern:
            pattern = self._get_default_pattern(language, vulnerability_type)

        # Generate rule based on tool
        generators = {
            "checkmarx": self._generate_checkmarx_rule,
            "fortify": self._generate_fortify_rule,
            "appscan": self._generate_appscan_rule,
            "acunetix": self._generate_acunetix_rule,
            "webinspect": self._generate_webinspect_rule,
            "semgrep": self._generate_semgrep_rule,
            "codeql": self._generate_codeql_rule,
        }

        generator = generators.get(tool)
        if not generator:
            raise ValueError(f"No generator for tool: {tool}")

        rule_content = generator(
            rule_name=rule_name,
            description=description,
            vulnerability_type=vulnerability_type,
            severity=severity,
            language=language,
            pattern=pattern,
            cwe_id=cwe_id,
            owasp_category=owasp_category,
            custom_message=custom_message,
            remediation=remediation,
        )

        return {
            "tool": tool,
            "tool_info": self.SUPPORTED_TOOLS[tool],
            "rule_name": rule_name,
            "rule_content": rule_content,
            "severity": severity,
            "language": language,
            "vulnerability_type": vulnerability_type,
            "cwe_id": cwe_id,
            "owasp_category": owasp_category,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def generate_all_formats(
        self,
        rule_name: str,
        description: str,
        vulnerability_type: str,
        severity: str,
        language: str,
        pattern: Optional[str] = None,
        cwe_id: Optional[str] = None,
        owasp_category: Optional[str] = None,
        custom_message: Optional[str] = None,
        remediation: Optional[str] = None,
        tools: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate rules for multiple tools at once.

        Args:
            tools: List of tools to generate for, or None for all tools

        Returns:
            Dictionary with rules for each tool
        """
        if tools is None:
            tools = list(self.SUPPORTED_TOOLS.keys())

        results = {
            "rule_name": rule_name,
            "description": description,
            "vulnerability_type": vulnerability_type,
            "severity": severity,
            "language": language,
            "cwe_id": cwe_id,
            "owasp_category": owasp_category,
            "generated_at": datetime.utcnow().isoformat(),
            "rules": {}
        }

        for tool in tools:
            try:
                rule = self.generate_rule(
                    tool=tool,
                    rule_name=rule_name,
                    description=description,
                    vulnerability_type=vulnerability_type,
                    severity=severity,
                    language=language,
                    pattern=pattern,
                    cwe_id=cwe_id,
                    owasp_category=owasp_category,
                    custom_message=custom_message,
                    remediation=remediation,
                )
                results["rules"][tool] = rule
            except Exception as e:
                logger.error(f"Failed to generate {tool} rule: {e}")
                results["rules"][tool] = {"error": str(e)}

        return results

    def _get_default_pattern(self, language: str, vulnerability_type: str) -> str:
        """Get default pattern for a vulnerability type and language"""
        lang_patterns = self.LANGUAGE_PATTERNS.get(language.lower(), {})
        patterns = lang_patterns.get(vulnerability_type, [])

        if patterns:
            return patterns[0]

        # Generic fallback patterns
        generic_patterns = {
            "sql_injection": r'(?:execute|query)\s*\([^)]*[\+\$]',
            "xss": r'(?:innerHTML|document\.write|eval)\s*[\(=]',
            "command_injection": r'(?:exec|system|popen)\s*\([^)]*[\+\$]',
            "path_traversal": r'(?:open|read|include)\s*\([^)]*[\+\$]',
            "hardcoded_secret": r'(?:password|secret|api_key)\s*=\s*["\'][^"\']+["\']',
        }

        return generic_patterns.get(vulnerability_type, r'PATTERN_PLACEHOLDER')

    def _generate_checkmarx_rule(self, **kwargs) -> str:
        """Generate Checkmarx CxQL rule"""
        rule_name = kwargs["rule_name"]
        description = kwargs["description"]
        severity = kwargs["severity"]
        language = kwargs["language"]
        pattern = kwargs["pattern"]
        cwe_id = kwargs.get("cwe_id", "CWE-0")
        remediation = kwargs.get("remediation", "Review and fix the vulnerable code pattern.")

        severity_map = {"critical": "High", "high": "High", "medium": "Medium", "low": "Low"}
        cx_severity = severity_map.get(severity.lower(), "Medium")

        return f'''// Checkmarx CxQL Custom Query
// Rule: {rule_name}
// Description: {description}
// Severity: {cx_severity}
// CWE: {cwe_id}
// Language: {language}

CxList sources = Find_Sources();
CxList sanitizers = Find_Sanitizers();
CxList sinks = Find_Sinks();

// Find vulnerable pattern
CxList vulnerablePattern = All.FindByRegex(@"{pattern}");

// Find data flow from source to sink
CxList dataFlow = sources.InfluencingOnAndNotSanitized(sinks, sanitizers);

// Combine with pattern matching
CxList results = dataFlow.FindByShortName(vulnerablePattern);

// Add results with custom message
foreach (CxList r in results)
{{
    r.data.Severity = CxQuerySeverity.{cx_severity};
    r.data.Description = @"{description}";
    r.data.Remediation = @"{remediation}";
}}

result = results;
'''

    def _generate_fortify_rule(self, **kwargs) -> str:
        """Generate Fortify Rule Pack XML"""
        rule_name = kwargs["rule_name"]
        description = kwargs["description"]
        severity = kwargs["severity"]
        language = kwargs["language"]
        pattern = kwargs["pattern"]
        cwe_id = kwargs.get("cwe_id", "0")
        owasp = kwargs.get("owasp_category", "")
        remediation = kwargs.get("remediation", "Review and fix the vulnerable code pattern.")

        severity_map = {"critical": "4.0", "high": "3.0", "medium": "2.0", "low": "1.0"}
        fortify_severity = severity_map.get(severity.lower(), "2.0")

        cwe_num = cwe_id.replace("CWE-", "") if cwe_id else "0"

        return f'''<?xml version="1.0" encoding="UTF-8"?>
<RulePack xmlns="xmlns://www.fortifysoftware.com/schema/rules"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="xmlns://www.fortifysoftware.com/schema/rules">

    <RulePackID>{rule_name.replace(" ", "_").upper()}_PACK_001</RulePackID>
    <SKU>SKU-CUSTOM-{rule_name.replace(" ", "-").upper()}</SKU>
    <Name>{rule_name} Rule Pack</Name>
    <Version>1.0</Version>
    <Description>{description}</Description>
    <Language>{language}</Language>

    <Rules>
        <RuleDefinitions>
            <DataflowSinkRule
                formatVersion="21.1"
                language="{language}">

                <RuleID>{rule_name.replace(" ", "_").upper()}_001</RuleID>
                <VulnKingdom>Input Validation and Representation</VulnKingdom>
                <VulnCategory>{rule_name}</VulnCategory>
                <VulnSubcategory>Custom Detection</VulnSubcategory>

                <DefaultSeverity>{fortify_severity}</DefaultSeverity>

                <Description>
                    <Abstract>{description}</Abstract>
                    <Explanation>
                        This rule detects potential security vulnerabilities matching the pattern: {pattern}
                    </Explanation>
                    <Recommendations>
                        {remediation}
                    </Recommendations>
                </Description>

                <Sink>
                    <InArguments>true</InArguments>
                    <TaintFlags>+VALIDATED</TaintFlags>
                </Sink>

                <FunctionIdentifier>
                    <Pattern>{pattern}</Pattern>
                </FunctionIdentifier>

                <MetaInfo>
                    <Group name="Standards">
                        <Item name="CWE">{cwe_num}</Item>
                        <Item name="OWASP">{owasp}</Item>
                    </Group>
                </MetaInfo>
            </DataflowSinkRule>
        </RuleDefinitions>
    </Rules>
</RulePack>
'''

    def _generate_appscan_rule(self, **kwargs) -> str:
        """Generate HCL AppScan custom rule XML"""
        rule_name = kwargs["rule_name"]
        description = kwargs["description"]
        severity = kwargs["severity"]
        language = kwargs["language"]
        pattern = kwargs["pattern"]
        cwe_id = kwargs.get("cwe_id", "CWE-0")
        remediation = kwargs.get("remediation", "Review and fix the vulnerable code pattern.")

        severity_map = {"critical": "High", "high": "High", "medium": "Medium", "low": "Low"}
        appscan_severity = severity_map.get(severity.lower(), "Medium")

        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!-- HCL AppScan Custom Rule -->
<!-- Rule: {rule_name} -->

<CustomRules xmlns="http://www.hcl.com/appscan/rules">
    <Rule id="{rule_name.replace(" ", "_").lower()}_001">
        <Name>{rule_name}</Name>
        <Description>{description}</Description>
        <Severity>{appscan_severity}</Severity>
        <Category>Custom Security Check</Category>
        <Language>{language}</Language>

        <CWE id="{cwe_id.replace('CWE-', '')}" />

        <PatternMatch>
            <Type>Regex</Type>
            <Pattern><![CDATA[{pattern}]]></Pattern>
            <Scope>SourceCode</Scope>
        </PatternMatch>

        <DataFlow>
            <Source>
                <Type>UserInput</Type>
            </Source>
            <Sink>
                <Pattern><![CDATA[{pattern}]]></Pattern>
            </Sink>
        </DataFlow>

        <Remediation>
            <Description>{remediation}</Description>
            <References>
                <Reference>
                    <Name>CWE Reference</Name>
                    <URL>https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html</URL>
                </Reference>
            </References>
        </Remediation>

        <Metadata>
            <Author>SecureDev AI</Author>
            <CreatedDate>{datetime.utcnow().strftime('%Y-%m-%d')}</CreatedDate>
            <Version>1.0</Version>
        </Metadata>
    </Rule>
</CustomRules>
'''

    def _generate_acunetix_rule(self, **kwargs) -> str:
        """Generate Acunetix custom script check"""
        rule_name = kwargs["rule_name"]
        description = kwargs["description"]
        severity = kwargs["severity"]
        pattern = kwargs["pattern"]
        cwe_id = kwargs.get("cwe_id", "CWE-0")
        remediation = kwargs.get("remediation", "Review and fix the vulnerable code pattern.")

        severity_map = {"critical": 3, "high": 3, "medium": 2, "low": 1}
        acunetix_severity = severity_map.get(severity.lower(), 2)

        return f'''// Acunetix Custom Script Check
// Rule: {rule_name}
// Description: {description}
// Severity: {severity}
// CWE: {cwe_id}

class {rule_name.replace(" ", "_").replace("-", "_")}Check extends CustomCheck {{

    // Check metadata
    name = "{rule_name}";
    description = "{description}";
    severity = {acunetix_severity}; // 1=Low, 2=Medium, 3=High
    cwe = "{cwe_id}";

    // Detection pattern
    pattern = /{pattern}/gi;

    function init() {{
        // Initialize the check
        this.addRequestCheck(this.checkRequest);
        this.addResponseCheck(this.checkResponse);
    }}

    function checkRequest(request) {{
        // Check request for vulnerable patterns
        var matches = request.body.match(this.pattern);
        if (matches) {{
            this.alert({{
                parameter: "request_body",
                value: matches[0],
                evidence: matches[0]
            }});
        }}
    }}

    function checkResponse(response) {{
        // Check response for vulnerable patterns
        var matches = response.body.match(this.pattern);
        if (matches) {{
            this.alert({{
                parameter: "response_body",
                value: matches[0],
                evidence: matches[0]
            }});
        }}
    }}

    function getRemediation() {{
        return "{remediation}";
    }}

    function getReferences() {{
        return [
            "https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html"
        ];
    }}
}}

// Register the check
registerCheck(new {rule_name.replace(" ", "_").replace("-", "_")}Check());
'''

    def _generate_webinspect_rule(self, **kwargs) -> str:
        """Generate Micro Focus WebInspect SecureBase rule"""
        rule_name = kwargs["rule_name"]
        description = kwargs["description"]
        severity = kwargs["severity"]
        pattern = kwargs["pattern"]
        cwe_id = kwargs.get("cwe_id", "CWE-0")
        remediation = kwargs.get("remediation", "Review and fix the vulnerable code pattern.")

        severity_map = {"critical": "4", "high": "3", "medium": "2", "low": "1"}
        wi_severity = severity_map.get(severity.lower(), "2")

        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!-- Micro Focus WebInspect SecureBase Rule -->
<!-- Rule: {rule_name} -->

<SecureBase>
    <Policy name="{rule_name}_Policy" version="1.0">
        <Description>{description}</Description>

        <Check id="{rule_name.replace(" ", "_").lower()}_001">
            <Name>{rule_name}</Name>
            <Enabled>true</Enabled>
            <Severity>{wi_severity}</Severity>

            <Description><![CDATA[{description}]]></Description>

            <Vulnerability>
                <CWEID>{cwe_id.replace('CWE-', '')}</CWEID>
                <Type>Custom Security Check</Type>
            </Vulnerability>

            <Detection>
                <RequestCheck>
                    <Pattern type="regex"><![CDATA[{pattern}]]></Pattern>
                    <Location>Body</Location>
                </RequestCheck>
                <ResponseCheck>
                    <Pattern type="regex"><![CDATA[{pattern}]]></Pattern>
                    <Location>Body</Location>
                </ResponseCheck>
            </Detection>

            <Attack>
                <PayloadGeneration>
                    <Type>PatternBased</Type>
                    <Pattern>{pattern}</Pattern>
                </PayloadGeneration>
            </Attack>

            <Remediation>
                <Recommendation><![CDATA[{remediation}]]></Recommendation>
                <Reference type="URL">https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html</Reference>
            </Remediation>

            <Metadata>
                <Author>SecureDev AI</Author>
                <DateCreated>{datetime.utcnow().strftime('%Y-%m-%d')}</DateCreated>
                <Version>1.0</Version>
            </Metadata>
        </Check>
    </Policy>
</SecureBase>
'''

    def _generate_semgrep_rule(self, **kwargs) -> str:
        """Generate Semgrep YAML rule"""
        rule_name = kwargs["rule_name"]
        description = kwargs["description"]
        severity = kwargs["severity"]
        language = kwargs["language"]
        pattern = kwargs["pattern"]
        cwe_id = kwargs.get("cwe_id", "CWE-0")
        owasp = kwargs.get("owasp_category", "")
        remediation = kwargs.get("remediation", "Review and fix the vulnerable code pattern.")

        severity_map = {"critical": "ERROR", "high": "WARNING", "medium": "WARNING", "low": "INFO"}
        semgrep_severity = severity_map.get(severity.lower(), "WARNING")

        lang_map = {
            "python": "python",
            "javascript": "javascript",
            "typescript": "typescript",
            "java": "java",
            "csharp": "csharp",
            "go": "go",
            "php": "php",
            "ruby": "ruby",
        }
        semgrep_lang = lang_map.get(language.lower(), "generic")

        rule_id = rule_name.lower().replace(" ", "-").replace("_", "-")

        return f'''rules:
  - id: {rule_id}
    message: |
      {description}

      Remediation: {remediation}
    severity: {semgrep_severity}
    languages:
      - {semgrep_lang}
    metadata:
      cwe: "{cwe_id}"
      owasp: "{owasp}"
      category: security
      technology:
        - {language}
      confidence: HIGH
      likelihood: MEDIUM
      impact: HIGH
      subcategory:
        - vuln
      author: SecureDev AI
      created: "{datetime.utcnow().strftime('%Y-%m-%d')}"
    patterns:
      - pattern-regex: '{pattern}'
    fix-regex:
      regex: '{pattern}'
      replacement: '# SECURITY: Review this code - {rule_name}'
'''

    def _generate_codeql_rule(self, **kwargs) -> str:
        """Generate CodeQL query"""
        rule_name = kwargs["rule_name"]
        description = kwargs["description"]
        severity = kwargs["severity"]
        language = kwargs["language"]
        pattern = kwargs["pattern"]
        cwe_id = kwargs.get("cwe_id", "CWE-0")
        remediation = kwargs.get("remediation", "Review and fix the vulnerable code pattern.")

        severity_map = {"critical": "error", "high": "error", "medium": "warning", "low": "recommendation"}
        codeql_severity = severity_map.get(severity.lower(), "warning")

        class_name = rule_name.replace(" ", "").replace("-", "").replace("_", "")
        cwe_num = cwe_id.replace("CWE-", "")

        # Language-specific CodeQL imports
        lang_imports = {
            "python": "import python\nimport semmle.python.dataflow.new.TaintTracking",
            "javascript": "import javascript\nimport semmle.javascript.security.dataflow.TaintedPath",
            "java": "import java\nimport semmle.java.dataflow.TaintTracking",
            "csharp": "import csharp\nimport semmle.code.csharp.dataflow.TaintTracking",
            "go": "import go\nimport semmle.go.dataflow.TaintTracking",
        }
        imports = lang_imports.get(language.lower(), f"import {language.lower()}")

        return f'''/**
 * @name {rule_name}
 * @description {description}
 * @kind problem
 * @problem.severity {codeql_severity}
 * @security-severity 7.5
 * @precision medium
 * @id custom/{rule_name.lower().replace(" ", "-")}
 * @tags security
 *       external/cwe/cwe-{cwe_num}
 *       custom
 */

{imports}

/**
 * Taint tracking configuration for {rule_name}
 */
class {class_name}Config extends TaintTracking::Configuration {{
    {class_name}Config() {{ this = "{rule_name} Config" }}

    override predicate isSource(DataFlow::Node source) {{
        // Define sources of tainted data (user input, external data, etc.)
        source instanceof RemoteFlowSource
    }}

    override predicate isSink(DataFlow::Node sink) {{
        // Define sinks where tainted data should not reach
        // Pattern: {pattern}
        exists(MethodAccess call |
            call.getMethod().hasName("execute") or
            call.getMethod().hasName("query") or
            call.getMethod().hasName("eval")
            |
            sink.asExpr() = call.getAnArgument()
        )
    }}

    override predicate isSanitizer(DataFlow::Node node) {{
        // Define sanitization methods that make data safe
        exists(MethodAccess sanitize |
            sanitize.getMethod().hasName("escape") or
            sanitize.getMethod().hasName("sanitize") or
            sanitize.getMethod().hasName("encode")
            |
            node.asExpr() = sanitize
        )
    }}
}}

from {class_name}Config config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
    "Potential {rule_name} vulnerability. " +
    "Tainted data from $@ flows to a dangerous sink. " +
    "{remediation}",
    source.getNode(), "user input"
'''

    def validate_pattern(self, pattern: str) -> Dict[str, Any]:
        """Validate a regex pattern"""
        import re
        try:
            re.compile(pattern)
            return {"valid": True, "pattern": pattern}
        except re.error as e:
            return {"valid": False, "error": str(e), "pattern": pattern}
