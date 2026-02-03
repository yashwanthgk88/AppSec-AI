"""
Enhanced SAST Scanner with Multi-Language AST Parsing
Supports: Java, PHP, .NET (C#), Node.js, JavaScript, Python, Go
"""
import re
import os
import ast
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class Language(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    PHP = "php"
    CSHARP = "csharp"
    GO = "go"
    RUBY = "ruby"
    UNKNOWN = "unknown"


@dataclass
class SecurityFinding:
    """Represents a security vulnerability finding"""
    title: str
    description: str
    severity: str
    cwe_id: str
    owasp_category: str
    file_path: str
    line_number: int
    code_snippet: str
    remediation: str
    remediation_code: str = ""
    cvss_score: float = 0.0
    confidence: str = "high"
    language: str = ""
    rule_id: str = ""


class EnhancedSASTScanner:
    """
    Multi-language SAST scanner with comprehensive vulnerability detection
    """

    # File extensions to language mapping
    LANG_EXTENSIONS = {
        '.py': Language.PYTHON,
        '.js': Language.JAVASCRIPT,
        '.jsx': Language.JAVASCRIPT,
        '.ts': Language.TYPESCRIPT,
        '.tsx': Language.TYPESCRIPT,
        '.java': Language.JAVA,
        '.php': Language.PHP,
        '.cs': Language.CSHARP,
        '.go': Language.GO,
        '.rb': Language.RUBY,
    }

    # Skip directories
    SKIP_DIRS = {
        'node_modules', 'venv', '.venv', '__pycache__', '.git',
        'dist', 'build', 'target', 'vendor', 'packages', 'bin', 'obj'
    }

    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.scanned_files = 0
        self.errors: List[str] = []

        # Initialize vulnerability patterns for each language
        self._init_patterns()

    def _init_patterns(self):
        """Initialize comprehensive vulnerability patterns for all languages"""

        # ============== SQL Injection Patterns ==============
        self.sql_injection_patterns = {
            Language.PYTHON: [
                (r'execute\s*\(\s*[f"\'].*?{.*?}.*?["\']', "F-string SQL query"),
                (r'execute\s*\(\s*["\'].*?%s.*?["\'].*?%', "Format string SQL"),
                (r'execute\s*\(\s*["\'].*?\+', "Concatenated SQL query"),
                (r'cursor\.execute\s*\([^,)]*\+', "Cursor execute with concatenation"),
                (r'\.raw\s*\(\s*[f"\']', "Django raw SQL with f-string"),
                (r'\.extra\s*\(.*?where\s*=.*?\+', "Django extra with concatenation"),
            ],
            Language.JAVA: [
                (r'createQuery\s*\(\s*["\'].*?\+', "JPA createQuery concatenation"),
                (r'executeQuery\s*\(\s*["\'].*?\+', "JDBC executeQuery concatenation"),
                (r'prepareStatement\s*\(\s*["\'].*?\+', "PreparedStatement concatenation"),
                (r'Statement.*?execute.*?\+', "Statement execute concatenation"),
                (r'createNativeQuery\s*\(\s*["\'].*?\+', "Native query concatenation"),
                (r'jdbcTemplate\.query\s*\(\s*["\'].*?\+', "JdbcTemplate concatenation"),
            ],
            Language.PHP: [
                (r'mysqli_query\s*\([^,]+,\s*["\'].*?\$', "mysqli_query with variable"),
                (r'\$.*?->query\s*\(\s*["\'].*?\$', "PDO query with variable"),
                (r'mysql_query\s*\(\s*["\'].*?\$', "mysql_query with variable"),
                (r'pg_query\s*\([^,]*,\s*["\'].*?\$', "pg_query with variable"),
                (r'\$wpdb->query\s*\(\s*["\'].*?\$', "WordPress query with variable"),
            ],
            Language.CSHARP: [
                (r'SqlCommand\s*\(\s*["\'].*?\+', "SqlCommand concatenation"),
                (r'ExecuteReader\s*\(\s*["\'].*?\+', "ExecuteReader concatenation"),
                (r'ExecuteNonQuery.*?["\'].*?\+', "ExecuteNonQuery concatenation"),
                (r'FromSqlRaw\s*\(\s*\$', "EF Core FromSqlRaw interpolation"),
                (r'ExecuteSqlRaw\s*\(\s*\$', "EF Core ExecuteSqlRaw interpolation"),
            ],
            Language.JAVASCRIPT: [
                (r'\.query\s*\(\s*`.*?\$\{', "Template literal SQL"),
                (r'\.query\s*\(\s*["\'].*?\+', "Concatenated SQL"),
                (r'sequelize\.query\s*\(\s*`.*?\$\{', "Sequelize raw query"),
                (r'knex\.raw\s*\(\s*`.*?\$\{', "Knex raw query"),
            ],
            Language.GO: [
                (r'db\.Query\s*\(\s*["`].*?\+', "db.Query concatenation"),
                (r'db\.Exec\s*\(\s*["`].*?\+', "db.Exec concatenation"),
                (r'fmt\.Sprintf.*?SELECT|INSERT|UPDATE|DELETE', "Sprintf SQL"),
            ],
        }

        # ============== XSS Patterns ==============
        self.xss_patterns = {
            Language.PYTHON: [
                (r'render_template_string\s*\(.*?request\.', "Template string with request data"),
                (r'Markup\s*\(.*?request\.', "Markup with request data"),
                (r'\.format\s*\(.*?request\.', "Format with request data in template"),
            ],
            Language.JAVA: [
                (r'response\.getWriter\s*\(\s*\)\.print.*?request\.getParameter', "Direct output of request param"),
                (r'out\.print.*?request\.getParameter', "JSP out.print with request param"),
                (r'setAttribute.*?request\.getParameter', "setAttribute with request param"),
            ],
            Language.PHP: [
                (r'echo\s+\$_(?:GET|POST|REQUEST)', "Echo with superglobal"),
                (r'print\s+\$_(?:GET|POST|REQUEST)', "Print with superglobal"),
                (r'<\?=\s*\$_(?:GET|POST|REQUEST)', "Short echo with superglobal"),
            ],
            Language.CSHARP: [
                (r'Response\.Write\s*\(\s*Request', "Response.Write with Request"),
                (r'@Html\.Raw\s*\(.*?Model\.', "Html.Raw with model data"),
                (r'innerHTML\s*=.*?Request', "innerHTML with Request data"),
            ],
            Language.JAVASCRIPT: [
                (r'\.innerHTML\s*=.*?(?:location|document\.URL|window\.location)', "innerHTML with location"),
                (r'document\.write\s*\(.*?(?:location|document\.URL)', "document.write with location"),
                (r'\.html\s*\(.*?(?:req\.|request\.)', "jQuery html with request data"),
                (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
            ],
            Language.GO: [
                (r'template\.HTML\s*\(.*?r\.(?:Form|URL)', "template.HTML with request"),
                (r'fmt\.Fprintf\s*\(.*?r\.(?:Form|URL)', "Fprintf with request data"),
            ],
        }

        # ============== Command Injection Patterns ==============
        self.cmd_injection_patterns = {
            Language.PYTHON: [
                (r'os\.system\s*\(.*?(?:request\.|input\(|sys\.argv)', "os.system with user input"),
                (r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True', "subprocess with shell=True"),
                (r'eval\s*\(.*?(?:request\.|input\()', "eval with user input"),
                (r'exec\s*\(.*?(?:request\.|input\()', "exec with user input"),
            ],
            Language.JAVA: [
                (r'Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(.*?\+', "Runtime.exec with concatenation"),
                (r'ProcessBuilder.*?(?:request\.getParameter|userInput)', "ProcessBuilder with user input"),
            ],
            Language.PHP: [
                (r'(?:exec|system|passthru|shell_exec)\s*\(\s*\$', "Command execution with variable"),
                (r'`\$', "Backtick execution with variable"),
                (r'proc_open\s*\(\s*\$', "proc_open with variable"),
            ],
            Language.CSHARP: [
                (r'Process\.Start\s*\(.*?(?:Request|input)', "Process.Start with user input"),
                (r'ProcessStartInfo.*?(?:Request|input)', "ProcessStartInfo with user input"),
            ],
            Language.JAVASCRIPT: [
                (r'child_process\.exec\s*\(.*?(?:req\.|request\.)', "child_process.exec with request"),
                (r'eval\s*\(.*?(?:req\.|request\.)', "eval with request data"),
            ],
            Language.GO: [
                (r'exec\.Command\s*\(.*?(?:r\.Form|r\.URL)', "exec.Command with request"),
            ],
        }

        # ============== Path Traversal Patterns ==============
        self.path_traversal_patterns = {
            Language.PYTHON: [
                (r'open\s*\(.*?(?:request\.|input\()', "open with user input"),
                (r'send_file\s*\(.*?(?:request\.|args\.)', "send_file with user input"),
                (r'os\.path\.join\s*\([^)]*(?:request\.|input\()', "path.join with user input"),
            ],
            Language.JAVA: [
                (r'new\s+File\s*\(.*?request\.getParameter', "File constructor with request param"),
                (r'FileInputStream\s*\(.*?request\.getParameter', "FileInputStream with request param"),
                (r'Paths\.get\s*\(.*?request\.getParameter', "Paths.get with request param"),
            ],
            Language.PHP: [
                (r'(?:include|require|include_once|require_once)\s*\(\s*\$', "Include with variable"),
                (r'file_get_contents\s*\(\s*\$', "file_get_contents with variable"),
                (r'fopen\s*\(\s*\$', "fopen with variable"),
            ],
            Language.CSHARP: [
                (r'File\.(?:Read|Open|Write).*?Request', "File operation with Request"),
                (r'Path\.Combine\s*\(.*?Request', "Path.Combine with Request"),
            ],
            Language.JAVASCRIPT: [
                (r'fs\.(?:readFile|writeFile|readdir)\s*\(.*?(?:req\.|request\.)', "fs operation with request"),
                (r'path\.join\s*\(.*?(?:req\.|request\.)', "path.join with request"),
            ],
            Language.GO: [
                (r'os\.Open\s*\(.*?r\.(?:Form|URL)', "os.Open with request"),
                (r'ioutil\.ReadFile\s*\(.*?r\.(?:Form|URL)', "ioutil.ReadFile with request"),
            ],
        }

        # ============== Hardcoded Secrets Patterns ==============
        self.hardcoded_secrets_patterns = [
            (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
            (r'(?:api_key|apikey|api-key)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded API key"),
            (r'(?:secret|secret_key)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret"),
            (r'(?:token|auth_token|access_token)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded token"),
            (r'(?:aws_access_key_id)\s*=\s*["\']AKIA[A-Z0-9]{16}["\']', "AWS Access Key"),
            (r'(?:aws_secret_access_key)\s*=\s*["\'][A-Za-z0-9/+=]{40}["\']', "AWS Secret Key"),
            (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Private key in code"),
            (r'(?:jdbc|mysql|postgresql|mongodb)://[^:]+:[^@]+@', "Database connection with credentials"),
        ]

        # ============== Insecure Deserialization Patterns ==============
        self.deserialization_patterns = {
            Language.PYTHON: [
                (r'pickle\.loads?\s*\(', "Pickle deserialization"),
                (r'yaml\.(?:load|unsafe_load)\s*\(', "Unsafe YAML load"),
                (r'marshal\.loads?\s*\(', "Marshal deserialization"),
            ],
            Language.JAVA: [
                (r'ObjectInputStream.*?readObject', "Java deserialization"),
                (r'XMLDecoder', "XMLDecoder usage"),
                (r'XStream.*?fromXML', "XStream deserialization"),
            ],
            Language.PHP: [
                (r'unserialize\s*\(\s*\$', "unserialize with variable"),
            ],
            Language.CSHARP: [
                (r'BinaryFormatter.*?Deserialize', "BinaryFormatter deserialization"),
                (r'XmlSerializer.*?Deserialize', "XmlSerializer deserialization"),
            ],
            Language.JAVASCRIPT: [
                (r'JSON\.parse\s*\(.*?(?:req\.|request\.)', "JSON.parse with request data"),
                (r'deserialize\s*\(.*?(?:req\.|request\.)', "Custom deserialize with request"),
            ],
        }

        # ============== Weak Cryptography Patterns ==============
        self.weak_crypto_patterns = [
            (r'(?:MD5|md5)\s*\(', "MD5 hash usage"),
            (r'(?:SHA1|sha1)\s*\(', "SHA1 hash usage"),
            (r'DES(?:ede)?(?:Cipher|\.)?', "DES encryption"),
            (r'RC4', "RC4 encryption"),
            (r'(?:ECB|ecb)', "ECB mode encryption"),
            (r'random\s*\(\s*\)', "Weak random number generator"),
            (r'Math\.random\s*\(\s*\)', "JavaScript Math.random for security"),
        ]

        # ============== SSRF Patterns ==============
        self.ssrf_patterns = {
            Language.PYTHON: [
                (r'requests\.(?:get|post|put)\s*\(.*?(?:request\.|input\()', "requests with user input URL"),
                (r'urllib\.(?:request\.)?urlopen\s*\(.*?(?:request\.|input\()', "urllib with user input"),
            ],
            Language.JAVA: [
                (r'new\s+URL\s*\(.*?request\.getParameter', "URL with request param"),
                (r'HttpURLConnection.*?request\.getParameter', "HttpURLConnection with request param"),
            ],
            Language.PHP: [
                (r'file_get_contents\s*\(\s*\$(?!_SERVER)', "file_get_contents with URL variable"),
                (r'curl_setopt.*?CURLOPT_URL.*?\$', "cURL with variable URL"),
            ],
            Language.JAVASCRIPT: [
                (r'fetch\s*\(.*?(?:req\.|request\.)', "fetch with request data"),
                (r'axios\.(?:get|post)\s*\(.*?(?:req\.|request\.)', "axios with request data"),
            ],
            Language.GO: [
                (r'http\.Get\s*\(.*?r\.(?:Form|URL)', "http.Get with request"),
            ],
        }

    def detect_language(self, file_path: str) -> Language:
        """Detect programming language from file extension"""
        ext = os.path.splitext(file_path)[1].lower()
        return self.LANG_EXTENSIONS.get(ext, Language.UNKNOWN)

    def scan_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Scan a single file for vulnerabilities"""
        findings = []
        language = self.detect_language(file_path)

        if language == Language.UNKNOWN:
            return findings

        lines = content.split('\n')

        # Scan for SQL Injection
        findings.extend(self._scan_patterns(
            file_path, content, lines, language,
            self.sql_injection_patterns.get(language, []),
            "SQL Injection", "CWE-89", "A03:2021 - Injection", "critical",
            "SQL query constructed with user input can lead to data breach.",
            "Use parameterized queries or prepared statements."
        ))

        # Scan for XSS
        findings.extend(self._scan_patterns(
            file_path, content, lines, language,
            self.xss_patterns.get(language, []),
            "Cross-Site Scripting (XSS)", "CWE-79", "A03:2021 - Injection", "high",
            "User input rendered without encoding can execute malicious scripts.",
            "Encode all user input before rendering in HTML context."
        ))

        # Scan for Command Injection
        findings.extend(self._scan_patterns(
            file_path, content, lines, language,
            self.cmd_injection_patterns.get(language, []),
            "Command Injection", "CWE-78", "A03:2021 - Injection", "critical",
            "User input passed to system commands can execute arbitrary code.",
            "Avoid shell commands with user input. Use safe APIs."
        ))

        # Scan for Path Traversal
        findings.extend(self._scan_patterns(
            file_path, content, lines, language,
            self.path_traversal_patterns.get(language, []),
            "Path Traversal", "CWE-22", "A01:2021 - Broken Access Control", "high",
            "User input in file paths can access unauthorized files.",
            "Validate and sanitize file paths. Use allowlists."
        ))

        # Scan for Hardcoded Secrets (all languages)
        findings.extend(self._scan_patterns(
            file_path, content, lines, language,
            self.hardcoded_secrets_patterns,
            "Hardcoded Secret", "CWE-798", "A07:2021 - Identification Failures", "high",
            "Secrets in source code can be extracted from repositories.",
            "Use environment variables or secret management systems."
        ))

        # Scan for Insecure Deserialization
        findings.extend(self._scan_patterns(
            file_path, content, lines, language,
            self.deserialization_patterns.get(language, []),
            "Insecure Deserialization", "CWE-502", "A08:2021 - Integrity Failures", "high",
            "Deserializing untrusted data can lead to remote code execution.",
            "Avoid deserializing untrusted data. Use safe formats like JSON."
        ))

        # Scan for Weak Cryptography (all languages)
        findings.extend(self._scan_patterns(
            file_path, content, lines, language,
            self.weak_crypto_patterns,
            "Weak Cryptography", "CWE-327", "A02:2021 - Cryptographic Failures", "medium",
            "Weak cryptographic algorithms can be broken.",
            "Use strong algorithms: AES-256, SHA-256, bcrypt for passwords."
        ))

        # Scan for SSRF
        findings.extend(self._scan_patterns(
            file_path, content, lines, language,
            self.ssrf_patterns.get(language, []),
            "Server-Side Request Forgery (SSRF)", "CWE-918", "A10:2021 - SSRF", "high",
            "User-controlled URLs can access internal resources.",
            "Validate URLs against allowlist. Block internal IPs."
        ))

        # Python-specific AST analysis
        if language == Language.PYTHON:
            findings.extend(self._analyze_python_ast(file_path, content))

        return findings

    def _scan_patterns(
        self, file_path: str, content: str, lines: List[str],
        language: Language, patterns: List[Tuple[str, str]],
        vuln_type: str, cwe_id: str, owasp: str, severity: str,
        description: str, remediation: str
    ) -> List[Dict[str, Any]]:
        """Scan content against a list of regex patterns"""
        findings = []

        for pattern, pattern_name in patterns:
            try:
                regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for match in regex.finditer(content):
                    line_num = content[:match.start()].count('\n') + 1

                    # Get code snippet (3 lines context)
                    start_line = max(0, line_num - 2)
                    end_line = min(len(lines), line_num + 2)
                    snippet = '\n'.join(lines[start_line:end_line])

                    findings.append({
                        'title': f"{vuln_type}: {pattern_name}",
                        'description': description,
                        'severity': severity,
                        'cwe_id': cwe_id,
                        'owasp_category': owasp,
                        'file_path': file_path,
                        'line_number': line_num,
                        'code_snippet': snippet,
                        'remediation': remediation,
                        'cvss_score': self._severity_to_cvss(severity),
                        'language': language.value,
                        'confidence': 'high' if 'request' in match.group().lower() else 'medium'
                    })
            except re.error as e:
                logger.warning(f"Invalid regex pattern: {pattern} - {e}")

        return findings

    def _analyze_python_ast(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Deep AST analysis for Python files"""
        findings = []

        try:
            tree = ast.parse(content)

            for node in ast.walk(tree):
                # Check for dangerous function calls
                if isinstance(node, ast.Call):
                    func_name = self._get_func_name(node)

                    # eval/exec detection
                    if func_name in ('eval', 'exec'):
                        findings.append({
                            'title': f"Dangerous function: {func_name}()",
                            'description': f"Use of {func_name}() can execute arbitrary code if input is not trusted.",
                            'severity': 'critical',
                            'cwe_id': 'CWE-95',
                            'owasp_category': 'A03:2021 - Injection',
                            'file_path': file_path,
                            'line_number': node.lineno,
                            'code_snippet': ast.get_source_segment(content, node) or '',
                            'remediation': f"Avoid {func_name}(). Use safe alternatives like ast.literal_eval() for eval.",
                            'cvss_score': 9.8,
                            'language': 'python',
                            'confidence': 'high'
                        })

                    # assert in production code
                    if isinstance(node, ast.Assert):
                        findings.append({
                            'title': "Assert statement in code",
                            'description': "Assert statements can be disabled with -O flag, bypassing security checks.",
                            'severity': 'low',
                            'cwe_id': 'CWE-617',
                            'owasp_category': 'A04:2021 - Insecure Design',
                            'file_path': file_path,
                            'line_number': node.lineno,
                            'code_snippet': ast.get_source_segment(content, node) or '',
                            'remediation': "Use explicit if statements with proper error handling instead of assert.",
                            'cvss_score': 3.0,
                            'language': 'python',
                            'confidence': 'medium'
                        })

        except SyntaxError:
            pass  # File has syntax errors, skip AST analysis

        return findings

    def _get_func_name(self, node: ast.Call) -> str:
        """Extract function name from AST Call node"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ''

    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity to CVSS score"""
        mapping = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.5,
            'low': 3.0
        }
        return mapping.get(severity.lower(), 5.0)

    def scan_directory(self, directory: str) -> Dict[str, Any]:
        """Scan an entire directory for vulnerabilities"""
        findings = []
        self.scanned_files = 0
        self.errors = []

        logger.info(f"[EnhancedSAST] Starting scan of: {directory}")

        for root, dirs, files in os.walk(directory):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            for file in files:
                file_path = os.path.join(root, file)
                ext = os.path.splitext(file)[1].lower()

                if ext not in self.LANG_EXTENSIONS:
                    continue

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Skip very large files (>1MB)
                    if len(content) > 1024 * 1024:
                        continue

                    file_findings = self.scan_file(file_path, content)
                    findings.extend(file_findings)
                    self.scanned_files += 1

                except Exception as e:
                    self.errors.append(f"Error scanning {file_path}: {e}")

        logger.info(f"[EnhancedSAST] Scan complete: {self.scanned_files} files, {len(findings)} findings")

        return {
            'findings': findings,
            'stats': {
                'files_scanned': self.scanned_files,
                'total_findings': len(findings),
                'critical': len([f for f in findings if f['severity'] == 'critical']),
                'high': len([f for f in findings if f['severity'] == 'high']),
                'medium': len([f for f in findings if f['severity'] == 'medium']),
                'low': len([f for f in findings if f['severity'] == 'low']),
            },
            'errors': self.errors
        }

    def generate_sample_findings(self) -> List[Dict[str, Any]]:
        """Generate sample findings for demo purposes"""
        return [
            {
                'title': 'SQL Injection in login function',
                'description': 'User input directly concatenated into SQL query',
                'severity': 'critical',
                'cwe_id': 'CWE-89',
                'owasp_category': 'A03:2021 - Injection',
                'file_path': 'src/auth/login.py',
                'line_number': 42,
                'code_snippet': 'query = f"SELECT * FROM users WHERE username=\'{username}\'"',
                'remediation': 'Use parameterized queries',
                'cvss_score': 9.8,
            },
            {
                'title': 'Hardcoded API Key',
                'description': 'API key found in source code',
                'severity': 'high',
                'cwe_id': 'CWE-798',
                'owasp_category': 'A07:2021 - Identification Failures',
                'file_path': 'config/settings.py',
                'line_number': 15,
                'code_snippet': 'API_KEY = "sk-1234567890abcdef"',
                'remediation': 'Use environment variables',
                'cvss_score': 7.5,
            }
        ]


# Singleton instance
enhanced_sast_scanner = EnhancedSASTScanner()
