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

    # Comprehensive language-specific sources, sinks, and sanitizers
    TAINT_TRACKING = {
        "python": {
            "sources": {
                "web": ["request.args", "request.form", "request.data", "request.json", "request.files", "request.cookies", "request.headers"],
                "django": ["request.GET", "request.POST", "request.body", "request.FILES", "request.COOKIES"],
                "fastapi": ["request.query_params", "request.body()", "request.form()", "request.json()"],
            },
            "sinks": {
                "sql_injection": ["cursor.execute", "connection.execute", "engine.execute", "db.execute", "session.execute", "raw", "text"],
                "command_injection": ["os.system", "os.popen", "subprocess.call", "subprocess.run", "subprocess.Popen", "commands.getoutput"],
                "xss": ["render_template_string", "Markup", "mark_safe", "Response"],
                "path_traversal": ["open", "os.path.join", "send_file", "send_from_directory"],
                "ssrf": ["requests.get", "requests.post", "urllib.request.urlopen", "httpx.get"],
                "deserialization": ["pickle.loads", "yaml.load", "marshal.loads"],
            },
            "sanitizers": {
                "sql_injection": ["parameterized query", "prepared statement", "escape_string"],
                "xss": ["escape", "html.escape", "bleach.clean", "markupsafe.escape"],
                "path_traversal": ["os.path.basename", "secure_filename"],
            }
        },
        "java": {
            "sources": {
                "servlet": ["request.getParameter", "request.getParameterValues", "request.getHeader", "request.getCookies", "request.getInputStream"],
                "spring": ["@RequestParam", "@PathVariable", "@RequestBody", "@RequestHeader", "@CookieValue"],
            },
            "sinks": {
                "sql_injection": ["createStatement", "executeQuery", "executeUpdate", "execute", "prepareStatement + string concat"],
                "command_injection": ["Runtime.getRuntime().exec", "ProcessBuilder", "new ProcessBuilder"],
                "xss": ["getWriter().print", "getWriter().write", "response.getOutputStream"],
                "path_traversal": ["new File", "new FileInputStream", "new FileReader", "Files.readAllBytes"],
                "xxe": ["DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory"],
                "deserialization": ["ObjectInputStream", "readObject", "XMLDecoder"],
                "ldap_injection": ["search", "DirContext.search"],
            },
            "sanitizers": {
                "sql_injection": ["PreparedStatement with ?", "setString", "setInt"],
                "xss": ["StringEscapeUtils.escapeHtml", "ESAPI.encoder().encodeForHTML"],
                "xxe": ["setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)"],
            }
        },
        "javascript": {
            "sources": {
                "express": ["req.params", "req.query", "req.body", "req.headers", "req.cookies"],
                "browser": ["document.location", "window.location", "document.URL", "document.referrer"],
            },
            "sinks": {
                "sql_injection": ["query", "execute", "raw", "sequelize.query", "knex.raw"],
                "command_injection": ["exec", "execSync", "spawn", "execFile", "child_process"],
                "xss": ["innerHTML", "outerHTML", "document.write", "document.writeln", "eval", "setTimeout", "setInterval"],
                "path_traversal": ["fs.readFile", "fs.readFileSync", "fs.createReadStream", "path.join"],
                "ssrf": ["fetch", "axios", "request", "http.get", "https.get"],
                "prototype_pollution": ["Object.assign", "_.merge", "_.extend", "$.extend"],
            },
            "sanitizers": {
                "sql_injection": ["parameterized query", "prepared statement", "escape"],
                "xss": ["DOMPurify.sanitize", "textContent", "encodeURIComponent", "escapeHtml"],
            }
        },
        "csharp": {
            "sources": {
                "aspnet": ["Request.QueryString", "Request.Form", "Request.Params", "Request.Headers", "Request.Cookies"],
                "aspnetcore": ["HttpContext.Request.Query", "HttpContext.Request.Form", "[FromQuery]", "[FromBody]", "[FromRoute]"],
            },
            "sinks": {
                "sql_injection": ["SqlCommand", "ExecuteReader", "ExecuteNonQuery", "ExecuteScalar", "FromSqlRaw"],
                "command_injection": ["Process.Start", "ProcessStartInfo"],
                "xss": ["Response.Write", "HtmlString", "@Html.Raw"],
                "path_traversal": ["File.ReadAllText", "File.Open", "FileStream", "StreamReader"],
                "deserialization": ["BinaryFormatter.Deserialize", "XmlSerializer.Deserialize", "JsonConvert.DeserializeObject"],
            },
            "sanitizers": {
                "sql_injection": ["SqlParameter", "AddWithValue", "Parameters.Add"],
                "xss": ["HtmlEncoder.Encode", "HttpUtility.HtmlEncode", "AntiXssEncoder"],
            }
        },
        "php": {
            "sources": {
                "superglobals": ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER"],
            },
            "sinks": {
                "sql_injection": ["mysql_query", "mysqli_query", "pg_query", "PDO::query", "->query"],
                "command_injection": ["exec", "system", "passthru", "shell_exec", "popen", "proc_open", "pcntl_exec"],
                "xss": ["echo", "print", "printf"],
                "path_traversal": ["file_get_contents", "fopen", "include", "require", "include_once", "require_once"],
                "file_upload": ["move_uploaded_file"],
            },
            "sanitizers": {
                "sql_injection": ["mysqli_real_escape_string", "PDO::quote", "prepared statements"],
                "xss": ["htmlspecialchars", "htmlentities", "strip_tags"],
                "path_traversal": ["basename", "realpath"],
            }
        },
        "go": {
            "sources": {
                "http": ["r.URL.Query()", "r.FormValue", "r.PostFormValue", "r.Header.Get", "r.Body"],
                "gin": ["c.Query", "c.Param", "c.PostForm", "c.GetHeader"],
            },
            "sinks": {
                "sql_injection": ["db.Query", "db.Exec", "db.QueryRow", "tx.Query", "tx.Exec"],
                "command_injection": ["exec.Command", "os/exec.Command"],
                "path_traversal": ["os.Open", "ioutil.ReadFile", "filepath.Join"],
                "ssrf": ["http.Get", "http.Post", "client.Do"],
            },
            "sanitizers": {
                "sql_injection": ["prepared statement with ?", "db.Prepare"],
                "path_traversal": ["filepath.Clean", "filepath.Base"],
            }
        },
    }

    # Language-specific patterns (regex)
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
        """Generate Checkmarx CxQL rule with real source/sink definitions"""
        rule_name = kwargs["rule_name"]
        description = kwargs["description"]
        severity = kwargs["severity"]
        language = kwargs["language"]
        pattern = kwargs["pattern"]
        vuln_type = kwargs.get("vulnerability_type", "sql_injection")
        cwe_id = kwargs.get("cwe_id", "CWE-0")
        remediation = kwargs.get("remediation", "Review and fix the vulnerable code pattern.")

        severity_map = {"critical": "High", "high": "High", "medium": "Medium", "low": "Low"}
        cx_severity = severity_map.get(severity.lower(), "Medium")

        # Get language-specific sources and sinks
        taint_info = self.TAINT_TRACKING.get(language.lower(), {})
        sources_dict = taint_info.get("sources", {})
        sinks_dict = taint_info.get("sinks", {})
        sanitizers_dict = taint_info.get("sanitizers", {})

        # Flatten sources
        all_sources = []
        for src_list in sources_dict.values():
            all_sources.extend(src_list)

        # Get vulnerability-specific sinks and sanitizers
        vuln_sinks = sinks_dict.get(vuln_type, ["execute", "query", "eval"])
        vuln_sanitizers = sanitizers_dict.get(vuln_type, ["escape", "sanitize", "encode"])

        return f'''// Checkmarx CxQL Custom Query
// Rule: {rule_name}
// Description: {description}
// Severity: {cx_severity}
// CWE: {cwe_id}
// Language: {language}
// Vulnerability Type: {vuln_type}

// ============================================
// SOURCES - User controllable input points
// ============================================
CxList sources = All.FindByType(typeof(MethodInvokeExpr)).FindByShortNames(new List<string> {{
    {", ".join([f'"{s.split(".")[-1]}"' for s in all_sources[:8]])}
}});

// Add parameter sources
sources.Add(All.FindByType(typeof(Param)));

// Add direct user input patterns for {language}
CxList userInput = All.FindByRegex(@"{pattern}");
sources.Add(userInput);

// ============================================
// SINKS - Dangerous execution points
// ============================================
CxList sinks = All.FindByType(typeof(MethodInvokeExpr)).FindByShortNames(new List<string> {{
    {", ".join([f'"{s.split(".")[-1]}"' for s in vuln_sinks])}
}});

// Add regex pattern matching for additional sinks
CxList patternSinks = All.FindByRegex(@"{pattern}");
sinks.Add(patternSinks);

// ============================================
// SANITIZERS - Functions that neutralize threats
// ============================================
CxList sanitizers = All.FindByType(typeof(MethodInvokeExpr)).FindByShortNames(new List<string> {{
    {", ".join([f'"{s}"' for s in vuln_sanitizers])}
}});

// ============================================
// TAINT ANALYSIS - Track data flow
// ============================================
// Find all paths where tainted data reaches sinks without sanitization
CxList taintedFlow = sources.InfluencingOnAndNotSanitized(sinks, sanitizers);

// Additional: Find direct string concatenation in sink arguments
CxList stringConcat = All.FindByType(typeof(BinaryExpr)).FindByOperator(Operator.Plus);
CxList unsafeConcat = stringConcat.DataInfluencedBy(sources);
CxList concatInSinks = sinks.DataInfluencedBy(unsafeConcat);

// Combine results
CxList results = taintedFlow;
results.Add(concatInSinks);

// Remove duplicates
results = results.ReduceFlow(CxList.ReduceFlowType.ReduceBigFlow);

// ============================================
// OUTPUT - Format results with metadata
// ============================================
foreach (CxList r in results)
{{
    r.data.Severity = CxQuerySeverity.{cx_severity};
    r.data.Description = @"{description}

Detected Pattern: {vuln_type}
This vulnerability occurs when user-controlled input reaches a dangerous sink without proper sanitization.";
    r.data.Remediation = @"{remediation}

Recommended fixes:
1. Use parameterized queries/prepared statements
2. Apply input validation and sanitization
3. Use allowlist validation for expected input formats
4. Implement proper encoding for the output context";
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
        """Generate Semgrep YAML rule with proper code patterns"""
        rule_name = kwargs["rule_name"]
        description = kwargs["description"]
        severity = kwargs["severity"]
        language = kwargs["language"]
        pattern = kwargs["pattern"]
        vuln_type = kwargs.get("vulnerability_type", "sql_injection")
        cwe_id = kwargs.get("cwe_id", "CWE-0")
        owasp = kwargs.get("owasp_category", "")
        remediation = kwargs.get("remediation", "Review and fix the vulnerable code pattern.")

        severity_map = {"critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO"}
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

        # Generate language and vulnerability specific patterns
        patterns_section = self._get_semgrep_patterns(semgrep_lang, vuln_type, pattern)

        return f'''rules:
  - id: {rule_id}
    message: |
      {description}

      Vulnerability: {vuln_type.replace("_", " ").title()}
      CWE: {cwe_id}

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
      references:
        - https://cwe.mitre.org/data/definitions/{cwe_id.replace("CWE-", "")}.html
        - https://owasp.org/Top10/
      author: SecureDev AI
{patterns_section}
'''

    def _get_semgrep_patterns(self, language: str, vuln_type: str, fallback_pattern: str) -> str:
        """Generate language-specific Semgrep patterns for vulnerability types"""

        # Python SQL Injection patterns
        python_sql_patterns = '''    patterns:
      - pattern-either:
          # f-string in execute
          - pattern: $CURSOR.execute(f"...", ...)
          - pattern: $CURSOR.execute(f'...', ...)
          # String concatenation in execute
          - pattern: $CURSOR.execute($X + $Y, ...)
          - pattern: $CURSOR.execute("..." + $VAR + "...", ...)
          # Format string in execute
          - pattern: $CURSOR.execute("...".format(...), ...)
          - pattern: $CURSOR.execute("..." % $VAR, ...)
          # Raw SQL with variables
          - pattern: $DB.execute(text($QUERY))
          - pattern: session.execute(text($QUERY))
      - pattern-not: $CURSOR.execute($SQL, $PARAMS)
      - pattern-not: $CURSOR.execute($SQL, ($PARAMS,))'''

        python_cmd_patterns = '''    patterns:
      - pattern-either:
          - pattern: os.system($CMD)
          - pattern: os.popen($CMD)
          - pattern: subprocess.call($CMD, shell=True, ...)
          - pattern: subprocess.run($CMD, shell=True, ...)
          - pattern: subprocess.Popen($CMD, shell=True, ...)
          - pattern: commands.getoutput($CMD)
      - metavariable-pattern:
          metavariable: $CMD
          patterns:
            - pattern-not: "..."'''

        python_xss_patterns = '''    patterns:
      - pattern-either:
          - pattern: flask.render_template_string($TEMPLATE)
          - pattern: jinja2.Template($TEMPLATE).render(...)
          - pattern: Markup($DATA)
          - pattern: mark_safe($DATA)
      - pattern-not: flask.render_template_string("...")'''

        # Java SQL Injection patterns
        java_sql_patterns = '''    patterns:
      - pattern-either:
          # Statement with string concatenation
          - pattern: |
              $STMT = $CONN.createStatement(...);
              ...
              $STMT.executeQuery($QUERY);
          - pattern: $STMT.executeQuery($X + $Y)
          - pattern: $STMT.executeUpdate($X + $Y)
          # PreparedStatement with string concat (wrong usage)
          - pattern: $CONN.prepareStatement($X + $Y)
      - pattern-not: $CONN.prepareStatement("...?...")'''

        java_cmd_patterns = '''    patterns:
      - pattern-either:
          - pattern: Runtime.getRuntime().exec($CMD)
          - pattern: new ProcessBuilder($CMD).start()
          - pattern: new ProcessBuilder(...).command($CMD).start()
      - metavariable-pattern:
          metavariable: $CMD
          patterns:
            - pattern-not: "..."'''

        java_deser_patterns = '''    patterns:
      - pattern-either:
          - pattern: new ObjectInputStream($INPUT).readObject()
          - pattern: |
              $OIS = new ObjectInputStream($INPUT);
              ...
              $OIS.readObject();
          - pattern: new XMLDecoder($INPUT).readObject()'''

        # JavaScript patterns
        js_sql_patterns = '''    patterns:
      - pattern-either:
          # Template literals in queries
          - pattern: $DB.query(`...${$VAR}...`)
          - pattern: $CONN.execute(`...${$VAR}...`)
          - pattern: sequelize.query(`...${$VAR}...`)
          - pattern: knex.raw(`...${$VAR}...`)
          # String concatenation
          - pattern: $DB.query($X + $Y)
      - pattern-not: $DB.query("...", [...])
      - pattern-not: $DB.query("...", $PARAMS)'''

        js_xss_patterns = '''    patterns:
      - pattern-either:
          - pattern: $EL.innerHTML = $DATA
          - pattern: $EL.outerHTML = $DATA
          - pattern: document.write($DATA)
          - pattern: document.writeln($DATA)
          - pattern: eval($CODE)
          - pattern: new Function($CODE)
      - pattern-not: $EL.innerHTML = "..."
      - pattern-not: $EL.textContent = $DATA'''

        js_cmd_patterns = '''    patterns:
      - pattern-either:
          - pattern: child_process.exec($CMD, ...)
          - pattern: child_process.execSync($CMD, ...)
          - pattern: require("child_process").exec($CMD, ...)
      - pattern-not: child_process.execFile("...", [...], ...)'''

        # Go patterns
        go_sql_patterns = '''    patterns:
      - pattern-either:
          - pattern: $DB.Query(fmt.Sprintf($FMT, $ARGS))
          - pattern: $DB.Exec(fmt.Sprintf($FMT, $ARGS))
          - pattern: $DB.QueryRow(fmt.Sprintf($FMT, $ARGS))
          - pattern: $DB.Query($X + $Y)
      - pattern-not: $DB.Query("...", $ARGS)
      - pattern-not: $DB.Prepare("...")'''

        go_cmd_patterns = '''    patterns:
      - pattern-either:
          - pattern: exec.Command($CMD, $ARGS...)
          - pattern: exec.CommandContext($CTX, $CMD, $ARGS...)
      - metavariable-pattern:
          metavariable: $CMD
          patterns:
            - pattern-not: "..."'''

        # PHP patterns
        php_sql_patterns = '''    patterns:
      - pattern-either:
          - pattern: mysqli_query($CONN, $QUERY . $VAR)
          - pattern: mysql_query($QUERY . $VAR)
          - pattern: $PDO->query($QUERY . $VAR)
          - pattern: pg_query($CONN, $QUERY . $VAR)
      - pattern-not: $PDO->prepare("...")'''

        php_cmd_patterns = '''    patterns:
      - pattern-either:
          - pattern: exec($CMD . $VAR)
          - pattern: system($CMD . $VAR)
          - pattern: passthru($CMD . $VAR)
          - pattern: shell_exec($CMD . $VAR)
          - pattern: popen($CMD . $VAR, ...)'''

        # C# patterns
        csharp_sql_patterns = '''    patterns:
      - pattern-either:
          - pattern: new SqlCommand($QUERY + $VAR, ...)
          - pattern: $CMD.CommandText = $QUERY + $VAR
          - pattern: $CTX.Database.ExecuteSqlRaw($QUERY + $VAR)
      - pattern-not: new SqlCommand("...", ...)
      - pattern-not: $CMD.Parameters.AddWithValue(...)'''

        # Pattern mapping
        pattern_map = {
            "python": {
                "sql_injection": python_sql_patterns,
                "command_injection": python_cmd_patterns,
                "xss": python_xss_patterns,
            },
            "java": {
                "sql_injection": java_sql_patterns,
                "command_injection": java_cmd_patterns,
                "deserialization": java_deser_patterns,
            },
            "javascript": {
                "sql_injection": js_sql_patterns,
                "xss": js_xss_patterns,
                "command_injection": js_cmd_patterns,
            },
            "go": {
                "sql_injection": go_sql_patterns,
                "command_injection": go_cmd_patterns,
            },
            "php": {
                "sql_injection": php_sql_patterns,
                "command_injection": php_cmd_patterns,
            },
            "csharp": {
                "sql_injection": csharp_sql_patterns,
            },
        }

        # Get language-specific pattern or fallback to regex
        lang_patterns = pattern_map.get(language, {})
        if vuln_type in lang_patterns:
            return lang_patterns[vuln_type]

        # Fallback to regex pattern
        return f'''    patterns:
      - pattern-regex: '{fallback_pattern}' '''

    def _generate_codeql_rule(self, **kwargs) -> str:
        """Generate CodeQL query with language-specific data flow analysis"""
        rule_name = kwargs["rule_name"]
        description = kwargs["description"]
        severity = kwargs["severity"]
        language = kwargs["language"]
        vuln_type = kwargs.get("vulnerability_type", "sql_injection")
        cwe_id = kwargs.get("cwe_id", "CWE-0")
        remediation = kwargs.get("remediation", "Review and fix the vulnerable code pattern.")

        severity_map = {"critical": "error", "high": "error", "medium": "warning", "low": "recommendation"}
        codeql_severity = severity_map.get(severity.lower(), "warning")

        class_name = rule_name.replace(" ", "").replace("-", "").replace("_", "")
        cwe_num = cwe_id.replace("CWE-", "")

        # Get language-specific CodeQL query
        query = self._get_codeql_query(language.lower(), vuln_type, class_name, rule_name, description, cwe_num, codeql_severity, remediation)
        return query

    def _get_codeql_query(self, language: str, vuln_type: str, class_name: str, rule_name: str, description: str, cwe_num: str, severity: str, remediation: str) -> str:
        """Generate language-specific CodeQL queries"""

        # Python SQL Injection
        python_sql = f'''/**
 * @name {rule_name}
 * @description {description}
 * @kind path-problem
 * @problem.severity {severity}
 * @security-severity 9.8
 * @precision high
 * @id py/custom-sql-injection
 * @tags security
 *       external/cwe/cwe-{cwe_num}
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.ApiGraphs
import DataFlow::PathGraph

/** A SQL sink - methods that execute SQL queries */
class SqlSink extends DataFlow::Node {{
  SqlSink() {{
    exists(DataFlow::CallCfgNode call |
      // cursor.execute(), connection.execute()
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = ["execute", "executemany", "executescript"] and
      this = call.getArg(0)
    )
    or
    exists(DataFlow::CallCfgNode call |
      // SQLAlchemy text(), raw queries
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = ["text", "raw"] and
      this = call.getArg(0)
    )
  }}
}}

/** Sanitizers that prevent SQL injection */
class SqlSanitizer extends DataFlow::Node {{
  SqlSanitizer() {{
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = ["escape", "quote", "escape_string"] and
      this = call
    )
  }}
}}

class {class_name}Config extends TaintTracking::Configuration {{
  {class_name}Config() {{ this = "{rule_name}" }}

  override predicate isSource(DataFlow::Node source) {{
    source instanceof RemoteFlowSource
  }}

  override predicate isSink(DataFlow::Node sink) {{
    sink instanceof SqlSink
  }}

  override predicate isSanitizer(DataFlow::Node node) {{
    node instanceof SqlSanitizer
  }}
}}

from {class_name}Config config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection vulnerability: user input from $@ flows to SQL query without sanitization. {remediation}",
  source.getNode(), "user-controlled input"
'''

        # Java SQL Injection
        java_sql = f'''/**
 * @name {rule_name}
 * @description {description}
 * @kind path-problem
 * @problem.severity {severity}
 * @security-severity 9.8
 * @precision high
 * @id java/custom-sql-injection
 * @tags security
 *       external/cwe/cwe-{cwe_num}
 */

import java
import semmle.java.dataflow.TaintTracking
import semmle.java.dataflow.FlowSources
import semmle.java.security.QueryInjection
import DataFlow::PathGraph

/** SQL execution methods */
class SqlExecutionMethod extends Method {{
  SqlExecutionMethod() {{
    this.getDeclaringType().hasQualifiedName("java.sql", ["Statement", "PreparedStatement", "Connection"]) and
    this.hasName(["executeQuery", "executeUpdate", "execute", "executeBatch"])
    or
    this.getDeclaringType().hasQualifiedName("java.sql", "Connection") and
    this.hasName(["prepareStatement", "prepareCall", "nativeSQL"])
    or
    // JPA/Hibernate
    this.getDeclaringType().hasQualifiedName("javax.persistence", "EntityManager") and
    this.hasName(["createQuery", "createNativeQuery"])
  }}
}}

class {class_name}Config extends TaintTracking::Configuration {{
  {class_name}Config() {{ this = "{rule_name}" }}

  override predicate isSource(DataFlow::Node source) {{
    source instanceof RemoteFlowSource
  }}

  override predicate isSink(DataFlow::Node sink) {{
    exists(MethodAccess ma |
      ma.getMethod() instanceof SqlExecutionMethod and
      sink.asExpr() = ma.getAnArgument()
    )
  }}

  override predicate isSanitizer(DataFlow::Node node) {{
    // PreparedStatement with parameter binding
    exists(MethodAccess ma |
      ma.getMethod().hasName(["setString", "setInt", "setLong", "setObject"]) and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") and
      node.asExpr() = ma.getArgument(1)
    )
  }}
}}

from {class_name}Config config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection: user input from $@ reaches SQL execution. {remediation}",
  source.getNode(), "user input"
'''

        # JavaScript SQL Injection
        js_sql = f'''/**
 * @name {rule_name}
 * @description {description}
 * @kind path-problem
 * @problem.severity {severity}
 * @security-severity 9.8
 * @precision high
 * @id js/custom-sql-injection
 * @tags security
 *       external/cwe/cwe-{cwe_num}
 */

import javascript
import semmle.javascript.security.dataflow.SqlInjectionCustomizations
import semmle.javascript.security.dataflow.NosqlInjectionCustomizations
import DataFlow::PathGraph

class {class_name}Config extends TaintTracking::Configuration {{
  {class_name}Config() {{ this = "{rule_name}" }}

  override predicate isSource(DataFlow::Node source) {{
    source instanceof RemoteFlowSource
  }}

  override predicate isSink(DataFlow::Node sink) {{
    sink instanceof SqlInjection::Sink
    or
    // Raw query methods
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["query", "raw", "execute"] and
      sink = call.getArgument(0)
    )
    or
    // Template literal in query
    exists(DataFlow::CallNode call, TemplateLiteral tl |
      call.getCalleeName() = ["query", "raw"] and
      tl = call.getArgument(0).asExpr() and
      sink.asExpr() = tl.getAnElement()
    )
  }}

  override predicate isSanitizer(DataFlow::Node node) {{
    // Parameterized query usage
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["escape", "escapeId", "format"] and
      node = call
    )
  }}
}}

from {class_name}Config config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection: user input from $@ flows to database query. {remediation}",
  source.getNode(), "user input"
'''

        # Go SQL Injection
        go_sql = f'''/**
 * @name {rule_name}
 * @description {description}
 * @kind path-problem
 * @problem.severity {severity}
 * @security-severity 9.8
 * @precision high
 * @id go/custom-sql-injection
 * @tags security
 *       external/cwe/cwe-{cwe_num}
 */

import go
import semmle.go.dataflow.TaintTracking
import semmle.go.security.SqlInjection
import DataFlow::PathGraph

class {class_name}Config extends TaintTracking::Configuration {{
  {class_name}Config() {{ this = "{rule_name}" }}

  override predicate isSource(DataFlow::Node source) {{
    // HTTP request parameters
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("net/http", "Request", ["FormValue", "PostFormValue"]) and
      source = call.getResult()
    )
    or
    // Gin framework
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("github.com/gin-gonic/gin", "Context", ["Query", "Param", "PostForm"]) and
      source = call.getResult()
    )
  }}

  override predicate isSink(DataFlow::Node sink) {{
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("database/sql", ["DB", "Tx"], ["Query", "QueryRow", "Exec"]) and
      sink = call.getArgument(0)
    )
  }}

  override predicate isSanitizer(DataFlow::Node node) {{
    // Prepared statement usage
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("database/sql", "DB", "Prepare") and
      node = call.getResult()
    )
  }}
}}

from {class_name}Config config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection: user input from $@ flows to SQL query. {remediation}",
  source.getNode(), "user input"
'''

        # Command injection queries
        python_cmd = f'''/**
 * @name {rule_name}
 * @description {description}
 * @kind path-problem
 * @problem.severity {severity}
 * @security-severity 9.8
 * @precision high
 * @id py/custom-command-injection
 * @tags security
 *       external/cwe/cwe-{cwe_num}
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

class CommandSink extends DataFlow::Node {{
  CommandSink() {{
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = ["system", "popen"] and
      call.getFunction().(DataFlow::AttrRead).getObject().asCfgNode().(NameNode).getId() = "os" and
      this = call.getArg(0)
    )
    or
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = ["call", "run", "Popen", "check_output"] and
      this = call.getArg(0)
    )
  }}
}}

class {class_name}Config extends TaintTracking::Configuration {{
  {class_name}Config() {{ this = "{rule_name}" }}

  override predicate isSource(DataFlow::Node source) {{
    source instanceof RemoteFlowSource
  }}

  override predicate isSink(DataFlow::Node sink) {{
    sink instanceof CommandSink
  }}
}}

from {class_name}Config config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Command injection: user input from $@ flows to shell command. {remediation}",
  source.getNode(), "user input"
'''

        # Query mapping
        queries = {
            "python": {
                "sql_injection": python_sql,
                "command_injection": python_cmd,
            },
            "java": {
                "sql_injection": java_sql,
            },
            "javascript": {
                "sql_injection": js_sql,
            },
            "go": {
                "sql_injection": go_sql,
            },
        }

        # Get specific query or generate generic one
        lang_queries = queries.get(language, {})
        if vuln_type in lang_queries:
            return lang_queries[vuln_type]

        # Generic fallback
        return self._generate_generic_codeql(language, class_name, rule_name, description, cwe_num, severity, remediation)

    def _generate_generic_codeql(self, language: str, class_name: str, rule_name: str, description: str, cwe_num: str, severity: str, remediation: str) -> str:
        """Generate a generic CodeQL query when no specific template exists"""
        lang_imports = {
            "python": "import python\\nimport semmle.python.dataflow.new.TaintTracking\\nimport semmle.python.dataflow.new.RemoteFlowSources",
            "java": "import java\\nimport semmle.java.dataflow.TaintTracking\\nimport semmle.java.dataflow.FlowSources",
            "javascript": "import javascript\\nimport semmle.javascript.security.dataflow.RemoteFlowSources",
            "csharp": "import csharp\\nimport semmle.code.csharp.dataflow.TaintTracking\\nimport semmle.code.csharp.security.dataflow.flowsources.Remote",
            "go": "import go\\nimport semmle.go.dataflow.TaintTracking",
        }
        imports = lang_imports.get(language, f"import {language}")

        return f'''/**
 * @name {rule_name}
 * @description {description}
 * @kind path-problem
 * @problem.severity {severity}
 * @security-severity 7.5
 * @precision medium
 * @id {language}/custom-{rule_name.lower().replace(" ", "-")}
 * @tags security
 *       external/cwe/cwe-{cwe_num}
 */

{imports}
import DataFlow::PathGraph

class {class_name}Config extends TaintTracking::Configuration {{
  {class_name}Config() {{ this = "{rule_name}" }}

  override predicate isSource(DataFlow::Node source) {{
    source instanceof RemoteFlowSource
  }}

  override predicate isSink(DataFlow::Node sink) {{
    // Define sinks based on vulnerability type
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i)(execute|query|eval|system|exec|open|read|write|send|render)") and
      sink = call.getAnArgument()
    )
  }}

  override predicate isSanitizer(DataFlow::Node node) {{
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i)(escape|sanitize|encode|validate|clean|filter)") and
      node = call
    )
  }}
}}

from {class_name}Config config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "{rule_name}: tainted data from $@ reaches a sensitive sink. {remediation}",
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
