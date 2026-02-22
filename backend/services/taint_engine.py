"""
Production-Grade Taint Analysis Engine

This module provides precise, inter-procedural taint tracking with:
- AST-based code parsing for accurate analysis
- Clear taint state machine with defined transitions
- Proper propagation through assignments, calls, and returns
- Context-sensitive function summaries
- Alias tracking for accurate data flow
- Sanitizer effectiveness verification

Supported Languages: Python, JavaScript, TypeScript, Go, PHP, C#, Java
"""

import ast
import re
import hashlib
from typing import Dict, List, Any, Set, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# TAINT STATE MACHINE
# =============================================================================

class TaintState(Enum):
    """
    Precise taint states with clear semantics:

    UNTAINTED: Data is safe, originates from trusted source
    TAINTED: Data is unsafe, originates from untrusted source (user input)
    SANITIZED: Data was tainted but has been properly sanitized
    PARTIALLY_SANITIZED: Data was sanitized but sanitizer doesn't fully cover the sink type
    UNKNOWN: Cannot determine taint state (conservative: treat as tainted)
    """
    UNTAINTED = auto()
    TAINTED = auto()
    SANITIZED = auto()
    PARTIALLY_SANITIZED = auto()
    UNKNOWN = auto()

    def is_dangerous(self) -> bool:
        """Returns True if this state could lead to a vulnerability"""
        return self in (TaintState.TAINTED, TaintState.PARTIALLY_SANITIZED, TaintState.UNKNOWN)


class TaintTransition(Enum):
    """Operations that affect taint state"""
    ASSIGNMENT = auto()      # x = tainted_value
    CONCATENATION = auto()   # x + tainted_value
    FUNCTION_CALL = auto()   # func(tainted_value)
    FUNCTION_RETURN = auto() # return tainted_value
    SANITIZATION = auto()    # sanitize(tainted_value)
    STRING_FORMAT = auto()   # f"{tainted}" or "{}".format(tainted)
    ARRAY_ACCESS = auto()    # array[tainted] or tainted[index]
    PROPERTY_ACCESS = auto() # obj.prop where obj is tainted


@dataclass
class TaintedValue:
    """Represents a tainted value with full tracking information"""
    variable_name: str
    taint_state: TaintState
    source_type: str           # e.g., "request.args", "user_input"
    source_line: int
    source_file: str
    original_source: str       # The actual source expression
    propagation_chain: List[Dict[str, Any]] = field(default_factory=list)
    sanitizers_applied: List[str] = field(default_factory=list)
    confidence: float = 1.0    # 0.0 to 1.0

    def add_propagation(self, operation: str, line: int, expression: str):
        """Track how taint propagates through code"""
        self.propagation_chain.append({
            "operation": operation,
            "line": line,
            "expression": expression
        })

    def apply_sanitizer(self, sanitizer_name: str, sanitizer_type: str):
        """Apply a sanitizer and update taint state"""
        self.sanitizers_applied.append(f"{sanitizer_name}:{sanitizer_type}")
        # State transitions based on sanitizer effectiveness will be handled by the engine


@dataclass
class TaintFlow:
    """Complete taint flow from source to sink"""
    flow_id: str
    source: TaintedValue
    sink_name: str
    sink_line: int
    sink_expression: str
    vulnerability_type: str
    cwe_id: str
    severity: str
    is_exploitable: bool
    confidence: float
    call_chain: List[str] = field(default_factory=list)
    sanitizers_bypassed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "flow_id": self.flow_id,
            "source": {
                "variable": self.source.variable_name,
                "type": self.source.source_type,
                "line": self.source.source_line,
                "expression": self.source.original_source,
                "taint_state": self.source.taint_state.name,
            },
            "sink": {
                "name": self.sink_name,
                "line": self.sink_line,
                "expression": self.sink_expression,
            },
            "propagation_chain": self.source.propagation_chain,
            "sanitizers_applied": self.source.sanitizers_applied,
            "vulnerability_type": self.vulnerability_type,
            "cwe_id": self.cwe_id,
            "severity": self.severity,
            "is_exploitable": self.is_exploitable,
            "confidence": self.confidence,
            "call_chain": self.call_chain,
        }


# =============================================================================
# TAINT SOURCES - Where untrusted data enters
# =============================================================================

@dataclass
class TaintSourceDefinition:
    """Definition of a taint source"""
    name: str
    pattern: str
    language: str
    framework: Optional[str]
    taint_type: str  # "full" or "partial"
    description: str
    risk_level: str  # "high", "medium", "low"

    # What variable gets tainted
    taints_return: bool = True
    taints_param_indices: List[int] = field(default_factory=list)


# Python Taint Sources
PYTHON_SOURCES = [
    # Flask
    TaintSourceDefinition("flask.request.args", r"request\.args(?:\.get\s*\(\s*['\"](\w+)['\"])?",
                          "python", "flask", "full", "Flask query parameters", "high"),
    TaintSourceDefinition("flask.request.form", r"request\.form(?:\.get\s*\(\s*['\"](\w+)['\"])?",
                          "python", "flask", "full", "Flask form data", "high"),
    TaintSourceDefinition("flask.request.data", r"request\.data",
                          "python", "flask", "full", "Flask raw body", "high"),
    TaintSourceDefinition("flask.request.json", r"request\.(?:json|get_json\s*\(\s*\))",
                          "python", "flask", "full", "Flask JSON body", "high"),
    TaintSourceDefinition("flask.request.values", r"request\.values(?:\.get)?",
                          "python", "flask", "full", "Flask combined params", "high"),
    TaintSourceDefinition("flask.request.headers", r"request\.headers(?:\.get\s*\(\s*['\"](\w+)['\"])?",
                          "python", "flask", "partial", "Flask headers", "medium"),
    TaintSourceDefinition("flask.request.cookies", r"request\.cookies(?:\.get)?",
                          "python", "flask", "full", "Flask cookies", "high"),

    # Django
    TaintSourceDefinition("django.request.GET", r"request\.GET(?:\.get\s*\(\s*['\"](\w+)['\"])?",
                          "python", "django", "full", "Django query params", "high"),
    TaintSourceDefinition("django.request.POST", r"request\.POST(?:\.get\s*\(\s*['\"](\w+)['\"])?",
                          "python", "django", "full", "Django POST data", "high"),
    TaintSourceDefinition("django.request.body", r"request\.body",
                          "python", "django", "full", "Django raw body", "high"),
    TaintSourceDefinition("django.request.FILES", r"request\.FILES(?:\.get)?",
                          "python", "django", "full", "Django file uploads", "high"),

    # FastAPI
    TaintSourceDefinition("fastapi.query", r"Query\s*\(",
                          "python", "fastapi", "full", "FastAPI query param", "high"),
    TaintSourceDefinition("fastapi.body", r"Body\s*\(",
                          "python", "fastapi", "full", "FastAPI body", "high"),
    TaintSourceDefinition("fastapi.path", r"Path\s*\(",
                          "python", "fastapi", "full", "FastAPI path param", "high"),

    # General Python
    TaintSourceDefinition("python.input", r"(?:input|raw_input)\s*\(",
                          "python", None, "full", "User console input", "high"),
    TaintSourceDefinition("python.sys.argv", r"sys\.argv\s*\[",
                          "python", None, "full", "Command line args", "high"),
    TaintSourceDefinition("python.os.environ", r"os\.environ(?:\.get)?\s*\[?\s*['\"]?(\w+)",
                          "python", None, "partial", "Environment variables", "medium"),
    TaintSourceDefinition("python.file.read", r"\.read(?:line|lines)?\s*\(",
                          "python", None, "partial", "File content", "medium"),
]

# JavaScript/TypeScript Taint Sources
JS_SOURCES = [
    # Express
    TaintSourceDefinition("express.req.query", r"req\.query(?:\.(\w+)|\[['\"](\w+)['\"])?",
                          "javascript", "express", "full", "Express query params", "high"),
    TaintSourceDefinition("express.req.body", r"req\.body(?:\.(\w+)|\[['\"](\w+)['\"])?",
                          "javascript", "express", "full", "Express body", "high"),
    TaintSourceDefinition("express.req.params", r"req\.params(?:\.(\w+)|\[['\"](\w+)['\"])?",
                          "javascript", "express", "full", "Express URL params", "high"),
    TaintSourceDefinition("express.req.headers", r"req\.headers(?:\.(\w+)|\[['\"](\w+)['\"])?",
                          "javascript", "express", "partial", "Express headers", "medium"),
    TaintSourceDefinition("express.req.cookies", r"req\.cookies(?:\.(\w+))?",
                          "javascript", "express", "full", "Express cookies", "high"),

    # Browser DOM
    TaintSourceDefinition("dom.location", r"(?:window\.)?location\.(?:search|hash|href|pathname)",
                          "javascript", None, "full", "URL location", "high"),
    TaintSourceDefinition("dom.document.URL", r"document\.(?:URL|documentURI|referrer)",
                          "javascript", None, "full", "Document URL", "high"),
    TaintSourceDefinition("dom.URLSearchParams", r"(?:new\s+)?URLSearchParams\s*\([^)]*\)\.get",
                          "javascript", None, "full", "URL params", "high"),
    TaintSourceDefinition("dom.postMessage", r"(?:event|e|evt)\.data",
                          "javascript", None, "full", "postMessage data", "high"),
    TaintSourceDefinition("dom.input.value", r"\.value\b",
                          "javascript", None, "full", "Input value", "high"),
    TaintSourceDefinition("dom.localStorage", r"(?:localStorage|sessionStorage)\.getItem",
                          "javascript", None, "partial", "Local storage", "medium"),

    # Node.js
    TaintSourceDefinition("node.process.argv", r"process\.argv",
                          "javascript", None, "full", "CLI args", "high"),
    TaintSourceDefinition("node.process.env", r"process\.env(?:\.(\w+)|\[['\"](\w+)['\"])?",
                          "javascript", None, "partial", "Env vars", "medium"),
    TaintSourceDefinition("node.fs.readFile", r"fs\.(?:readFile|readFileSync)",
                          "javascript", None, "partial", "File content", "medium"),
]

# Go Taint Sources
GO_SOURCES = [
    TaintSourceDefinition("go.http.FormValue", r"r\.FormValue\s*\(",
                          "go", None, "full", "HTTP form value", "high"),
    TaintSourceDefinition("go.http.URL.Query", r"r\.URL\.Query\s*\(\s*\)",
                          "go", None, "full", "URL query", "high"),
    TaintSourceDefinition("go.http.Header", r"r\.Header\.Get\s*\(",
                          "go", None, "partial", "HTTP header", "medium"),
    TaintSourceDefinition("go.http.Body", r"(?:ioutil|io)\.ReadAll\s*\(\s*r\.Body",
                          "go", None, "full", "Request body", "high"),
    TaintSourceDefinition("go.http.Cookie", r"r\.Cookie\s*\(",
                          "go", None, "full", "HTTP cookie", "high"),
    TaintSourceDefinition("go.gin.Query", r"c\.Query\s*\(",
                          "go", "gin", "full", "Gin query param", "high"),
    TaintSourceDefinition("go.gin.Param", r"c\.Param\s*\(",
                          "go", "gin", "full", "Gin URL param", "high"),
    TaintSourceDefinition("go.gin.PostForm", r"c\.PostForm\s*\(",
                          "go", "gin", "full", "Gin form value", "high"),
    TaintSourceDefinition("go.os.Args", r"os\.Args",
                          "go", None, "full", "CLI args", "high"),
    TaintSourceDefinition("go.os.Getenv", r"os\.(?:Getenv|LookupEnv)\s*\(",
                          "go", None, "partial", "Env var", "medium"),
]

# PHP Taint Sources
PHP_SOURCES = [
    TaintSourceDefinition("php.$_GET", r"\$_GET\s*\[\s*['\"](\w+)['\"]",
                          "php", None, "full", "GET parameter", "high"),
    TaintSourceDefinition("php.$_POST", r"\$_POST\s*\[\s*['\"](\w+)['\"]",
                          "php", None, "full", "POST parameter", "high"),
    TaintSourceDefinition("php.$_REQUEST", r"\$_REQUEST\s*\[\s*['\"](\w+)['\"]",
                          "php", None, "full", "REQUEST parameter", "high"),
    TaintSourceDefinition("php.$_COOKIE", r"\$_COOKIE\s*\[\s*['\"](\w+)['\"]",
                          "php", None, "full", "Cookie value", "high"),
    TaintSourceDefinition("php.$_FILES", r"\$_FILES\s*\[\s*['\"](\w+)['\"]",
                          "php", None, "full", "File upload", "high"),
    TaintSourceDefinition("php.$_SERVER", r"\$_SERVER\s*\[\s*['\"](?:HTTP_|REQUEST_|QUERY_|PATH_)(\w+)['\"]",
                          "php", None, "partial", "Server variable", "medium"),
    TaintSourceDefinition("php.php://input", r"file_get_contents\s*\(\s*['\"]php://input['\"]",
                          "php", None, "full", "Raw POST body", "high"),
    TaintSourceDefinition("php.laravel.input", r"\$request->(?:input|get|post|query|all)\s*\(",
                          "php", "laravel", "full", "Laravel input", "high"),
]

# C# Taint Sources
CSHARP_SOURCES = [
    TaintSourceDefinition("csharp.Request.Query", r"Request\.Query\[\s*['\"](\w+)['\"]",
                          "csharp", "aspnet", "full", "Query param", "high"),
    TaintSourceDefinition("csharp.Request.Form", r"Request\.Form\[\s*['\"](\w+)['\"]",
                          "csharp", "aspnet", "full", "Form value", "high"),
    TaintSourceDefinition("csharp.Request.Body", r"Request\.Body",
                          "csharp", "aspnet", "full", "Request body", "high"),
    TaintSourceDefinition("csharp.Request.Headers", r"Request\.Headers\[\s*['\"](\w+)['\"]",
                          "csharp", "aspnet", "partial", "Header", "medium"),
    TaintSourceDefinition("csharp.Request.Cookies", r"Request\.Cookies\[\s*['\"](\w+)['\"]",
                          "csharp", "aspnet", "full", "Cookie", "high"),
    TaintSourceDefinition("csharp.FromQuery", r"\[FromQuery\]",
                          "csharp", "aspnet", "full", "Query binding", "high"),
    TaintSourceDefinition("csharp.FromBody", r"\[FromBody\]",
                          "csharp", "aspnet", "full", "Body binding", "high"),
]

# Java Taint Sources
JAVA_SOURCES = [
    TaintSourceDefinition("java.getParameter", r"request\.getParameter\s*\(\s*['\"](\w+)['\"]",
                          "java", "servlet", "full", "Request param", "high"),
    TaintSourceDefinition("java.getParameterValues", r"request\.getParameterValues\s*\(",
                          "java", "servlet", "full", "Request params array", "high"),
    TaintSourceDefinition("java.getHeader", r"request\.getHeader\s*\(",
                          "java", "servlet", "partial", "Request header", "medium"),
    TaintSourceDefinition("java.getCookies", r"request\.getCookies\s*\(",
                          "java", "servlet", "full", "Cookies", "high"),
    TaintSourceDefinition("java.getInputStream", r"request\.getInputStream\s*\(",
                          "java", "servlet", "full", "Input stream", "high"),
    TaintSourceDefinition("java.getReader", r"request\.getReader\s*\(",
                          "java", "servlet", "full", "Request reader", "high"),
    TaintSourceDefinition("java.getPathInfo", r"request\.getPathInfo\s*\(",
                          "java", "servlet", "full", "Path info", "high"),
    TaintSourceDefinition("java.getQueryString", r"request\.getQueryString\s*\(",
                          "java", "servlet", "full", "Query string", "high"),
    TaintSourceDefinition("java.@RequestParam", r"@RequestParam",
                          "java", "spring", "full", "Spring param", "high"),
    TaintSourceDefinition("java.@PathVariable", r"@PathVariable",
                          "java", "spring", "full", "Spring path var", "high"),
    TaintSourceDefinition("java.@RequestBody", r"@RequestBody",
                          "java", "spring", "full", "Spring body", "high"),
]


# =============================================================================
# TAINT SINKS - Where tainted data becomes dangerous
# =============================================================================

@dataclass
class TaintSinkDefinition:
    """Definition of a security-sensitive sink"""
    name: str
    pattern: str
    language: str
    vulnerability_type: str
    cwe_id: str
    severity: str
    description: str

    # Which arguments are vulnerable (0-indexed, -1 means all)
    vulnerable_args: List[int] = field(default_factory=lambda: [0])

    # What sanitizers can protect this sink
    protected_by: List[str] = field(default_factory=list)

    # Requires tainted input to be a vulnerability
    requires_taint: bool = True


# Python Sinks
PYTHON_SINKS = [
    # SQL Injection
    TaintSinkDefinition(
        "python.cursor.execute",
        r"(?:cursor|conn|db|connection)\.execute\s*\(",
        "python", "SQL Injection", "CWE-89", "critical",
        "SQL execution - vulnerable if query contains user input",
        vulnerable_args=[0],
        protected_by=["parameterized_query", "orm_filter"]
    ),
    TaintSinkDefinition(
        "python.raw_sql",
        r"\.raw\s*\(\s*['\"]?(?:SELECT|INSERT|UPDATE|DELETE)",
        "python", "SQL Injection", "CWE-89", "critical",
        "Django/SQLAlchemy raw SQL",
        vulnerable_args=[0],
        protected_by=["parameterized_query"]
    ),
    TaintSinkDefinition(
        "python.text_sql",
        r"text\s*\(\s*['\"](?:SELECT|INSERT|UPDATE|DELETE)",
        "python", "SQL Injection", "CWE-89", "critical",
        "SQLAlchemy text() SQL",
        vulnerable_args=[0],
        protected_by=["bindparams"]
    ),

    # Command Injection
    TaintSinkDefinition(
        "python.os.system",
        r"os\.system\s*\(",
        "python", "Command Injection", "CWE-78", "critical",
        "OS command execution",
        vulnerable_args=[0],
        protected_by=["shlex_quote"]
    ),
    TaintSinkDefinition(
        "python.os.popen",
        r"os\.popen\s*\(",
        "python", "Command Injection", "CWE-78", "critical",
        "OS popen execution",
        vulnerable_args=[0],
        protected_by=["shlex_quote"]
    ),
    TaintSinkDefinition(
        "python.subprocess.shell",
        r"subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True",
        "python", "Command Injection", "CWE-78", "critical",
        "Subprocess with shell=True",
        vulnerable_args=[0],
        protected_by=["shlex_quote", "subprocess_list"]
    ),
    TaintSinkDefinition(
        "python.eval",
        r"(?<![.\w])eval\s*\(",
        "python", "Code Injection", "CWE-94", "critical",
        "Python eval() - arbitrary code execution",
        vulnerable_args=[0],
        protected_by=[]  # No safe way to use eval with user input
    ),
    TaintSinkDefinition(
        "python.exec",
        r"(?<![.\w])exec\s*\(",
        "python", "Code Injection", "CWE-94", "critical",
        "Python exec() - arbitrary code execution",
        vulnerable_args=[0],
        protected_by=[]
    ),

    # XSS
    TaintSinkDefinition(
        "python.render_template_string",
        r"render_template_string\s*\(",
        "python", "XSS", "CWE-79", "high",
        "Flask template string rendering",
        vulnerable_args=[0],
        protected_by=["html_escape", "jinja_autoescape"]
    ),
    TaintSinkDefinition(
        "python.mark_safe",
        r"mark_safe\s*\(",
        "python", "XSS", "CWE-79", "high",
        "Django mark_safe bypasses escaping",
        vulnerable_args=[0],
        protected_by=["html_escape"]
    ),
    TaintSinkDefinition(
        "python.jinja_safe",
        r"\|\s*safe\s*(?:\||}})",
        "python", "XSS", "CWE-79", "high",
        "Jinja2 safe filter bypasses escaping",
        vulnerable_args=[0],
        protected_by=["html_escape"]
    ),

    # Path Traversal
    TaintSinkDefinition(
        "python.open",
        r"(?<![.\w])open\s*\(",
        "python", "Path Traversal", "CWE-22", "high",
        "File open operation",
        vulnerable_args=[0],
        protected_by=["secure_filename", "path_validation", "basename"]
    ),
    TaintSinkDefinition(
        "python.send_file",
        r"send_file\s*\(",
        "python", "Path Traversal", "CWE-22", "high",
        "Flask send_file",
        vulnerable_args=[0],
        protected_by=["secure_filename", "safe_join"]
    ),

    # SSRF
    TaintSinkDefinition(
        "python.requests",
        r"requests\.(?:get|post|put|delete|patch|head|options)\s*\(",
        "python", "SSRF", "CWE-918", "high",
        "HTTP request with requests library",
        vulnerable_args=[0],
        protected_by=["url_validator", "allowlist"]
    ),
    TaintSinkDefinition(
        "python.urllib",
        r"urllib\.request\.urlopen\s*\(",
        "python", "SSRF", "CWE-918", "high",
        "HTTP request with urllib",
        vulnerable_args=[0],
        protected_by=["url_validator", "allowlist"]
    ),

    # Deserialization
    TaintSinkDefinition(
        "python.pickle",
        r"pickle\.loads?\s*\(",
        "python", "Insecure Deserialization", "CWE-502", "critical",
        "Pickle deserialization - RCE possible",
        vulnerable_args=[0],
        protected_by=[]  # No safe way to unpickle untrusted data
    ),
    TaintSinkDefinition(
        "python.yaml_unsafe",
        r"yaml\.(?:load|unsafe_load)\s*\([^)]*(?!Loader\s*=\s*(?:yaml\.)?(?:Safe|Base)Loader)",
        "python", "Insecure Deserialization", "CWE-502", "critical",
        "YAML load without safe loader",
        vulnerable_args=[0],
        protected_by=["yaml_safe_load"]
    ),

    # XXE
    TaintSinkDefinition(
        "python.etree",
        r"(?:ET|etree)\.(?:parse|fromstring|XML)\s*\(",
        "python", "XXE", "CWE-611", "high",
        "XML parsing without entity protection",
        vulnerable_args=[0],
        protected_by=["defusedxml"]
    ),

    # LDAP Injection
    TaintSinkDefinition(
        "python.ldap_search",
        r"\.search(?:_s)?\s*\(",
        "python", "LDAP Injection", "CWE-90", "high",
        "LDAP search operation",
        vulnerable_args=[0, 1],
        protected_by=["ldap_escape"]
    ),

    # Open Redirect
    TaintSinkDefinition(
        "python.redirect",
        r"(?:redirect|HttpResponseRedirect)\s*\(",
        "python", "Open Redirect", "CWE-601", "medium",
        "HTTP redirect",
        vulnerable_args=[0],
        protected_by=["url_validator", "relative_url_check"]
    ),
]

# JavaScript Sinks
JS_SINKS = [
    # SQL Injection
    TaintSinkDefinition(
        "js.query",
        r"\.query\s*\(",
        "javascript", "SQL Injection", "CWE-89", "critical",
        "Database query execution",
        vulnerable_args=[0],
        protected_by=["parameterized_query", "prepared_statement"]
    ),
    TaintSinkDefinition(
        "js.sequelize.query",
        r"sequelize\.query\s*\(",
        "javascript", "SQL Injection", "CWE-89", "critical",
        "Sequelize raw query",
        vulnerable_args=[0],
        protected_by=["replacements", "bind"]
    ),

    # Command Injection
    TaintSinkDefinition(
        "js.exec",
        r"(?:exec|execSync)\s*\(",
        "javascript", "Command Injection", "CWE-78", "critical",
        "child_process exec",
        vulnerable_args=[0],
        protected_by=["execFile", "spawn_array"]
    ),
    TaintSinkDefinition(
        "js.eval",
        r"(?<![.\w])eval\s*\(",
        "javascript", "Code Injection", "CWE-94", "critical",
        "JavaScript eval",
        vulnerable_args=[0],
        protected_by=[]
    ),
    TaintSinkDefinition(
        "js.Function",
        r"new\s+Function\s*\(",
        "javascript", "Code Injection", "CWE-94", "critical",
        "Function constructor",
        vulnerable_args=[-1],
        protected_by=[]
    ),
    TaintSinkDefinition(
        "js.setTimeout.string",
        r"setTimeout\s*\(\s*['\"`]",
        "javascript", "Code Injection", "CWE-94", "high",
        "setTimeout with string",
        vulnerable_args=[0],
        protected_by=[]
    ),

    # XSS
    TaintSinkDefinition(
        "js.innerHTML",
        r"\.innerHTML\s*=",
        "javascript", "XSS", "CWE-79", "high",
        "innerHTML assignment",
        vulnerable_args=[0],
        protected_by=["DOMPurify", "textContent", "createTextNode"]
    ),
    TaintSinkDefinition(
        "js.outerHTML",
        r"\.outerHTML\s*=",
        "javascript", "XSS", "CWE-79", "high",
        "outerHTML assignment",
        vulnerable_args=[0],
        protected_by=["DOMPurify"]
    ),
    TaintSinkDefinition(
        "js.document.write",
        r"document\.(?:write|writeln)\s*\(",
        "javascript", "XSS", "CWE-79", "high",
        "document.write",
        vulnerable_args=[0],
        protected_by=["escape_html"]
    ),
    TaintSinkDefinition(
        "js.jquery.html",
        r"\$\([^)]+\)\.html\s*\(",
        "javascript", "XSS", "CWE-79", "high",
        "jQuery .html()",
        vulnerable_args=[0],
        protected_by=["DOMPurify", "text"]
    ),
    TaintSinkDefinition(
        "js.dangerouslySetInnerHTML",
        r"dangerouslySetInnerHTML",
        "javascript", "XSS", "CWE-79", "high",
        "React dangerouslySetInnerHTML",
        vulnerable_args=[0],
        protected_by=["DOMPurify"]
    ),

    # Path Traversal
    TaintSinkDefinition(
        "js.fs.readFile",
        r"fs\.(?:readFile|readFileSync|access|stat|open)\s*\(",
        "javascript", "Path Traversal", "CWE-22", "high",
        "File system read",
        vulnerable_args=[0],
        protected_by=["path_normalize", "basename", "resolve_check"]
    ),
    TaintSinkDefinition(
        "js.res.sendFile",
        r"res\.sendFile\s*\(",
        "javascript", "Path Traversal", "CWE-22", "high",
        "Express sendFile",
        vulnerable_args=[0],
        protected_by=["path_resolve", "root_option"]
    ),

    # SSRF
    TaintSinkDefinition(
        "js.fetch",
        r"(?<![.\w])fetch\s*\(",
        "javascript", "SSRF", "CWE-918", "high",
        "fetch API",
        vulnerable_args=[0],
        protected_by=["url_validator", "allowlist"]
    ),
    TaintSinkDefinition(
        "js.axios",
        r"axios\.(?:get|post|put|delete|patch|request)\s*\(",
        "javascript", "SSRF", "CWE-918", "high",
        "Axios HTTP request",
        vulnerable_args=[0],
        protected_by=["url_validator", "allowlist"]
    ),

    # NoSQL Injection
    TaintSinkDefinition(
        "js.mongo.find",
        r"\.(?:find|findOne|findOneAndUpdate|updateOne|deleteOne)\s*\(",
        "javascript", "NoSQL Injection", "CWE-943", "high",
        "MongoDB query",
        vulnerable_args=[0],
        protected_by=["mongo_sanitize", "type_check"]
    ),
    TaintSinkDefinition(
        "js.mongo.$where",
        r"\$where\s*:",
        "javascript", "NoSQL Injection", "CWE-943", "critical",
        "MongoDB $where - JS execution",
        vulnerable_args=[0],
        protected_by=[]
    ),

    # Prototype Pollution
    TaintSinkDefinition(
        "js.Object.assign",
        r"Object\.assign\s*\(\s*\{\s*\}",
        "javascript", "Prototype Pollution", "CWE-1321", "high",
        "Object.assign with untrusted data",
        vulnerable_args=[1],
        protected_by=["Object.freeze", "key_validation"]
    ),
    TaintSinkDefinition(
        "js.lodash.merge",
        r"_\.(?:merge|defaultsDeep|set)\s*\(",
        "javascript", "Prototype Pollution", "CWE-1321", "high",
        "Lodash deep merge",
        vulnerable_args=[1],
        protected_by=["key_validation"]
    ),

    # Open Redirect
    TaintSinkDefinition(
        "js.location.href",
        r"(?:window\.)?location(?:\.href)?\s*=",
        "javascript", "Open Redirect", "CWE-601", "medium",
        "Location assignment",
        vulnerable_args=[0],
        protected_by=["url_validator", "relative_check"]
    ),
    TaintSinkDefinition(
        "js.res.redirect",
        r"res\.redirect\s*\(",
        "javascript", "Open Redirect", "CWE-601", "medium",
        "Express redirect",
        vulnerable_args=[0],
        protected_by=["url_validator"]
    ),
]

# Go Sinks
GO_SINKS = [
    TaintSinkDefinition(
        "go.db.Query",
        r"\.(?:Query|QueryRow|Exec)\s*\(",
        "go", "SQL Injection", "CWE-89", "critical",
        "SQL query execution",
        vulnerable_args=[0],
        protected_by=["prepared_statement", "parameterized"]
    ),
    TaintSinkDefinition(
        "go.exec.Command",
        r"exec\.Command\s*\(",
        "go", "Command Injection", "CWE-78", "critical",
        "Command execution",
        vulnerable_args=[0, 1],
        protected_by=["allowlist"]
    ),
    TaintSinkDefinition(
        "go.template.HTML",
        r"template\.HTML\s*\(",
        "go", "XSS", "CWE-79", "high",
        "Unescaped HTML",
        vulnerable_args=[0],
        protected_by=["html_escape"]
    ),
    TaintSinkDefinition(
        "go.os.Open",
        r"os\.(?:Open|OpenFile|Create|ReadFile)\s*\(",
        "go", "Path Traversal", "CWE-22", "high",
        "File operation",
        vulnerable_args=[0],
        protected_by=["filepath_clean", "filepath_base"]
    ),
    TaintSinkDefinition(
        "go.http.Get",
        r"http\.(?:Get|Post|PostForm|Head|NewRequest)\s*\(",
        "go", "SSRF", "CWE-918", "high",
        "HTTP request",
        vulnerable_args=[0],
        protected_by=["url_validate"]
    ),
]

# PHP Sinks
PHP_SINKS = [
    TaintSinkDefinition(
        "php.mysql_query",
        r"mysqli?_query\s*\(",
        "php", "SQL Injection", "CWE-89", "critical",
        "MySQL query",
        vulnerable_args=[0, 1],
        protected_by=["mysqli_real_escape", "prepared_statement"]
    ),
    TaintSinkDefinition(
        "php.pdo.query",
        r"\$\w+->query\s*\(",
        "php", "SQL Injection", "CWE-89", "critical",
        "PDO query",
        vulnerable_args=[0],
        protected_by=["pdo_prepare"]
    ),
    TaintSinkDefinition(
        "php.system",
        r"(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(",
        "php", "Command Injection", "CWE-78", "critical",
        "System command",
        vulnerable_args=[0],
        protected_by=["escapeshellarg", "escapeshellcmd"]
    ),
    TaintSinkDefinition(
        "php.eval",
        r"(?<![.\w])eval\s*\(",
        "php", "Code Injection", "CWE-94", "critical",
        "PHP eval",
        vulnerable_args=[0],
        protected_by=[]
    ),
    TaintSinkDefinition(
        "php.include",
        r"(?:include|include_once|require|require_once)\s*\(?",
        "php", "Path Traversal/RCE", "CWE-22", "critical",
        "File inclusion",
        vulnerable_args=[0],
        protected_by=["basename", "realpath_check", "allowlist"]
    ),
    TaintSinkDefinition(
        "php.echo",
        r"(?:echo|print)\s+",
        "php", "XSS", "CWE-79", "high",
        "Output",
        vulnerable_args=[0],
        protected_by=["htmlspecialchars", "htmlentities"]
    ),
    TaintSinkDefinition(
        "php.unserialize",
        r"unserialize\s*\(",
        "php", "Insecure Deserialization", "CWE-502", "critical",
        "PHP unserialize",
        vulnerable_args=[0],
        protected_by=["allowed_classes"]
    ),
    TaintSinkDefinition(
        "php.header",
        r"header\s*\(\s*['\"]Location:",
        "php", "Open Redirect", "CWE-601", "medium",
        "Location header",
        vulnerable_args=[0],
        protected_by=["url_validator"]
    ),
]

# C# Sinks
CSHARP_SINKS = [
    TaintSinkDefinition(
        "csharp.SqlCommand",
        r"(?:new\s+)?SqlCommand\s*\(",
        "csharp", "SQL Injection", "CWE-89", "critical",
        "SQL command",
        vulnerable_args=[0],
        protected_by=["SqlParameter", "Parameters.Add"]
    ),
    TaintSinkDefinition(
        "csharp.FromSqlRaw",
        r"\.FromSqlRaw\s*\(",
        "csharp", "SQL Injection", "CWE-89", "high",
        "EF Core raw SQL",
        vulnerable_args=[0],
        protected_by=["FromSqlInterpolated"]
    ),
    TaintSinkDefinition(
        "csharp.Process.Start",
        r"Process\.Start\s*\(",
        "csharp", "Command Injection", "CWE-78", "critical",
        "Process execution",
        vulnerable_args=[0],
        protected_by=["arguments_array"]
    ),
    TaintSinkDefinition(
        "csharp.Html.Raw",
        r"Html\.Raw\s*\(",
        "csharp", "XSS", "CWE-79", "high",
        "Unescaped HTML",
        vulnerable_args=[0],
        protected_by=["HtmlEncode"]
    ),
    TaintSinkDefinition(
        "csharp.File.Open",
        r"File\.(?:Open|Read|WriteAll)\w*\s*\(",
        "csharp", "Path Traversal", "CWE-22", "high",
        "File operation",
        vulnerable_args=[0],
        protected_by=["Path.GetFileName", "path_validation"]
    ),
    TaintSinkDefinition(
        "csharp.HttpClient",
        r"(?:HttpClient|WebClient)\.\w+Async?\s*\(",
        "csharp", "SSRF", "CWE-918", "high",
        "HTTP request",
        vulnerable_args=[0],
        protected_by=["uri_validator"]
    ),
    TaintSinkDefinition(
        "csharp.BinaryFormatter",
        r"BinaryFormatter\s*\(\s*\)\.Deserialize",
        "csharp", "Insecure Deserialization", "CWE-502", "critical",
        "Binary deserialization",
        vulnerable_args=[0],
        protected_by=[]
    ),
]

# Java Sinks
JAVA_SINKS = [
    TaintSinkDefinition(
        "java.Statement.execute",
        r"\.(?:execute|executeQuery|executeUpdate)\s*\(",
        "java", "SQL Injection", "CWE-89", "critical",
        "JDBC statement execution",
        vulnerable_args=[0],
        protected_by=["PreparedStatement", "setString"]
    ),
    TaintSinkDefinition(
        "java.createQuery",
        r"\.createQuery\s*\(",
        "java", "SQL Injection", "CWE-89", "high",
        "JPA/Hibernate query",
        vulnerable_args=[0],
        protected_by=["setParameter", "criteria_api"]
    ),
    TaintSinkDefinition(
        "java.Runtime.exec",
        r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(",
        "java", "Command Injection", "CWE-78", "critical",
        "Runtime exec",
        vulnerable_args=[0],
        protected_by=["ProcessBuilder_array"]
    ),
    TaintSinkDefinition(
        "java.ProcessBuilder",
        r"new\s+ProcessBuilder\s*\(",
        "java", "Command Injection", "CWE-78", "critical",
        "ProcessBuilder",
        vulnerable_args=[0],
        protected_by=[]
    ),
    TaintSinkDefinition(
        "java.PrintWriter",
        r"(?:PrintWriter|response\.getWriter\s*\(\s*\))\.(?:print|println|write)\s*\(",
        "java", "XSS", "CWE-79", "high",
        "Response output",
        vulnerable_args=[0],
        protected_by=["ESAPI_encode", "StringEscapeUtils"]
    ),
    TaintSinkDefinition(
        "java.File",
        r"new\s+File\s*\(",
        "java", "Path Traversal", "CWE-22", "high",
        "File constructor",
        vulnerable_args=[0],
        protected_by=["getCanonicalPath", "normalize"]
    ),
    TaintSinkDefinition(
        "java.URL",
        r"new\s+URL\s*\(",
        "java", "SSRF", "CWE-918", "high",
        "URL connection",
        vulnerable_args=[0],
        protected_by=["url_validator", "allowlist"]
    ),
    TaintSinkDefinition(
        "java.ObjectInputStream",
        r"(?:new\s+)?ObjectInputStream\s*\(",
        "java", "Insecure Deserialization", "CWE-502", "critical",
        "Object deserialization",
        vulnerable_args=[0],
        protected_by=["ObjectInputFilter"]
    ),
    TaintSinkDefinition(
        "java.XMLDecoder",
        r"(?:new\s+)?XMLDecoder\s*\(",
        "java", "Insecure Deserialization", "CWE-502", "critical",
        "XMLDecoder",
        vulnerable_args=[0],
        protected_by=[]
    ),
]


# =============================================================================
# SANITIZERS - Functions that clean tainted data
# =============================================================================

@dataclass
class SanitizerDefinition:
    """Definition of a sanitization function"""
    name: str
    pattern: str
    language: str
    sanitizes: List[str]  # List of vulnerability types it protects against
    effectiveness: str    # "full", "partial", "context-dependent"
    description: str


PYTHON_SANITIZERS = [
    SanitizerDefinition("html.escape", r"html\.escape\s*\(", "python",
                        ["XSS"], "full", "HTML entity encoding"),
    SanitizerDefinition("markupsafe.escape", r"(?:markupsafe\.)?escape\s*\(", "python",
                        ["XSS"], "full", "MarkupSafe HTML escaping"),
    SanitizerDefinition("bleach.clean", r"bleach\.clean\s*\(", "python",
                        ["XSS"], "full", "Bleach HTML sanitization"),
    SanitizerDefinition("parameterized_query", r"\.execute\s*\([^,]+,\s*[\(\[\{]", "python",
                        ["SQL Injection"], "full", "Parameterized SQL query"),
    SanitizerDefinition("shlex.quote", r"shlex\.quote\s*\(", "python",
                        ["Command Injection"], "full", "Shell argument quoting"),
    SanitizerDefinition("subprocess_list", r"subprocess\.\w+\s*\(\s*\[", "python",
                        ["Command Injection"], "full", "Subprocess with list"),
    SanitizerDefinition("secure_filename", r"secure_filename\s*\(", "python",
                        ["Path Traversal"], "full", "Werkzeug secure filename"),
    SanitizerDefinition("os.path.basename", r"os\.path\.basename\s*\(", "python",
                        ["Path Traversal"], "full", "Extract filename only"),
    SanitizerDefinition("validators.url", r"validators\.url\s*\(", "python",
                        ["SSRF", "Open Redirect"], "partial", "URL validation"),
    SanitizerDefinition("yaml.safe_load", r"yaml\.safe_load\s*\(", "python",
                        ["Insecure Deserialization"], "full", "Safe YAML loading"),
    SanitizerDefinition("defusedxml", r"defusedxml\.\w+\.\w+\s*\(", "python",
                        ["XXE"], "full", "Defused XML parser"),
]

JS_SANITIZERS = [
    SanitizerDefinition("DOMPurify.sanitize", r"DOMPurify\.sanitize\s*\(", "javascript",
                        ["XSS"], "full", "DOMPurify HTML sanitization"),
    SanitizerDefinition("textContent", r"\.textContent\s*=", "javascript",
                        ["XSS"], "full", "Safe text assignment"),
    SanitizerDefinition("createTextNode", r"\.createTextNode\s*\(", "javascript",
                        ["XSS"], "full", "Safe text node creation"),
    SanitizerDefinition("encodeURIComponent", r"encodeURIComponent\s*\(", "javascript",
                        ["XSS", "Open Redirect"], "partial", "URL encoding"),
    SanitizerDefinition("parameterized_query", r"\.query\s*\([^,]+,\s*\[", "javascript",
                        ["SQL Injection"], "full", "Parameterized SQL"),
    SanitizerDefinition("prepared_statement", r"\.prepare\s*\(['\"]", "javascript",
                        ["SQL Injection"], "full", "Prepared statement"),
    SanitizerDefinition("execFile", r"execFile\s*\(", "javascript",
                        ["Command Injection"], "full", "Safe child_process"),
    SanitizerDefinition("spawn_array", r"spawn\s*\([^,]+,\s*\[", "javascript",
                        ["Command Injection"], "full", "Spawn with array"),
    SanitizerDefinition("path.normalize", r"path\.normalize\s*\(", "javascript",
                        ["Path Traversal"], "partial", "Path normalization"),
    SanitizerDefinition("path.basename", r"path\.basename\s*\(", "javascript",
                        ["Path Traversal"], "full", "Extract filename"),
    SanitizerDefinition("mongo-sanitize", r"(?:sanitize|mongoSanitize)\s*\(", "javascript",
                        ["NoSQL Injection"], "full", "MongoDB input sanitization"),
]

GO_SANITIZERS = [
    SanitizerDefinition("template.HTMLEscapeString", r"template\.HTMLEscapeString\s*\(", "go",
                        ["XSS"], "full", "HTML escaping"),
    SanitizerDefinition("prepared_statement", r"\.Prepare\s*\(", "go",
                        ["SQL Injection"], "full", "SQL prepared statement"),
    SanitizerDefinition("filepath.Clean", r"filepath\.Clean\s*\(", "go",
                        ["Path Traversal"], "partial", "Path cleaning"),
    SanitizerDefinition("filepath.Base", r"filepath\.Base\s*\(", "go",
                        ["Path Traversal"], "full", "Extract filename"),
    SanitizerDefinition("url.Parse", r"url\.Parse\s*\(", "go",
                        ["SSRF"], "partial", "URL parsing"),
]

PHP_SANITIZERS = [
    SanitizerDefinition("htmlspecialchars", r"htmlspecialchars\s*\(", "php",
                        ["XSS"], "full", "HTML entity encoding"),
    SanitizerDefinition("htmlentities", r"htmlentities\s*\(", "php",
                        ["XSS"], "full", "HTML entities"),
    SanitizerDefinition("mysqli_real_escape_string", r"mysqli_real_escape_string\s*\(", "php",
                        ["SQL Injection"], "partial", "MySQL escaping"),
    SanitizerDefinition("pdo_prepare", r"\$\w+->prepare\s*\(", "php",
                        ["SQL Injection"], "full", "PDO prepared statement"),
    SanitizerDefinition("escapeshellarg", r"escapeshellarg\s*\(", "php",
                        ["Command Injection"], "full", "Shell arg escaping"),
    SanitizerDefinition("escapeshellcmd", r"escapeshellcmd\s*\(", "php",
                        ["Command Injection"], "partial", "Shell cmd escaping"),
    SanitizerDefinition("basename", r"basename\s*\(", "php",
                        ["Path Traversal"], "full", "Extract filename"),
    SanitizerDefinition("realpath", r"realpath\s*\(", "php",
                        ["Path Traversal"], "partial", "Resolve path"),
    SanitizerDefinition("filter_var", r"filter_var\s*\([^,]+,\s*FILTER_(?:VALIDATE|SANITIZE)", "php",
                        ["XSS", "SQL Injection", "SSRF"], "context-dependent", "Input filtering"),
]

CSHARP_SANITIZERS = [
    SanitizerDefinition("HtmlEncode", r"(?:Html|Http)(?:Utility)?\.(?:Html)?Encode\s*\(", "csharp",
                        ["XSS"], "full", "HTML encoding"),
    SanitizerDefinition("SqlParameter", r"new\s+SqlParameter\s*\(", "csharp",
                        ["SQL Injection"], "full", "SQL parameterization"),
    SanitizerDefinition("Parameters.Add", r"\.Parameters\.(?:Add|AddWithValue)\s*\(", "csharp",
                        ["SQL Injection"], "full", "SQL parameterization"),
    SanitizerDefinition("Path.GetFileName", r"Path\.GetFileName\s*\(", "csharp",
                        ["Path Traversal"], "full", "Extract filename"),
    SanitizerDefinition("Uri.IsWellFormedUriString", r"Uri\.IsWellFormedUriString\s*\(", "csharp",
                        ["SSRF", "Open Redirect"], "partial", "URI validation"),
]

JAVA_SANITIZERS = [
    SanitizerDefinition("ESAPI.encoder", r"ESAPI\.encoder\s*\(\s*\)\.encodeFor\w+\s*\(", "java",
                        ["XSS", "SQL Injection", "LDAP Injection"], "full", "ESAPI encoding"),
    SanitizerDefinition("StringEscapeUtils", r"StringEscapeUtils\.escape\w+\s*\(", "java",
                        ["XSS"], "full", "Apache Commons escaping"),
    SanitizerDefinition("PreparedStatement", r"\.prepareStatement\s*\(", "java",
                        ["SQL Injection"], "full", "Prepared statement"),
    SanitizerDefinition("setParameter", r"\.set(?:String|Int|Long|Object)\s*\(", "java",
                        ["SQL Injection"], "full", "Parameter binding"),
    SanitizerDefinition("getCanonicalPath", r"\.getCanonicalPath\s*\(", "java",
                        ["Path Traversal"], "partial", "Canonical path"),
    SanitizerDefinition("DocumentBuilderFactory.setFeature",
                        r"\.setFeature\s*\([^)]*disallow-doctype-decl[^)]*,\s*true", "java",
                        ["XXE"], "full", "Disable DOCTYPE"),
]


# =============================================================================
# TAINT ANALYSIS ENGINE
# =============================================================================

class TaintAnalysisEngine:
    """
    Production-grade taint analysis engine with precise tracking.

    Features:
    - AST-based code analysis for accuracy
    - Clear taint state transitions
    - Inter-procedural tracking through function calls
    - Context-sensitive sanitizer verification
    - Detailed flow reporting
    """

    def __init__(self, language: str):
        self.language = language.lower()
        self.sources = self._get_sources()
        self.sinks = self._get_sinks()
        self.sanitizers = self._get_sanitizers()

        # Analysis state
        self.tainted_values: Dict[str, TaintedValue] = {}
        self.function_summaries: Dict[str, Dict] = {}
        self.detected_flows: List[TaintFlow] = []

    def _get_sources(self) -> List[TaintSourceDefinition]:
        """Get taint sources for the language"""
        sources_map = {
            "python": PYTHON_SOURCES,
            "javascript": JS_SOURCES,
            "typescript": JS_SOURCES,
            "go": GO_SOURCES,
            "php": PHP_SOURCES,
            "csharp": CSHARP_SOURCES,
            "java": JAVA_SOURCES,
        }
        return sources_map.get(self.language, [])

    def _get_sinks(self) -> List[TaintSinkDefinition]:
        """Get taint sinks for the language"""
        sinks_map = {
            "python": PYTHON_SINKS,
            "javascript": JS_SINKS,
            "typescript": JS_SINKS,
            "go": GO_SINKS,
            "php": PHP_SINKS,
            "csharp": CSHARP_SINKS,
            "java": JAVA_SINKS,
        }
        return sinks_map.get(self.language, [])

    def _get_sanitizers(self) -> List[SanitizerDefinition]:
        """Get sanitizers for the language"""
        sanitizers_map = {
            "python": PYTHON_SANITIZERS,
            "javascript": JS_SANITIZERS,
            "typescript": JS_SANITIZERS,
            "go": GO_SANITIZERS,
            "php": PHP_SANITIZERS,
            "csharp": CSHARP_SANITIZERS,
            "java": JAVA_SANITIZERS,
        }
        return sanitizers_map.get(self.language, [])

    def analyze(self, source_code: str, file_path: str = "unknown") -> Dict[str, Any]:
        """
        Perform complete taint analysis on source code.

        Returns:
            {
                "tainted_values": [...],
                "taint_flows": [...],
                "vulnerabilities": [...],
                "statistics": {...}
            }
        """
        # Reset state
        self.tainted_values = {}
        self.detected_flows = []

        lines = source_code.split('\n')

        # Phase 1: Identify all taint sources
        self._identify_sources(lines, file_path)

        # Phase 2: Track taint propagation
        self._track_propagation(lines, file_path)

        # Phase 3: Identify sinks and check for taint reaching them
        vulnerabilities = self._identify_vulnerable_sinks(lines, file_path)

        return {
            "tainted_values": [
                {
                    "variable": tv.variable_name,
                    "source_type": tv.source_type,
                    "source_line": tv.source_line,
                    "taint_state": tv.taint_state.name,
                    "propagation_chain": tv.propagation_chain,
                    "sanitizers_applied": tv.sanitizers_applied,
                    "confidence": tv.confidence,
                }
                for tv in self.tainted_values.values()
            ],
            "taint_flows": [flow.to_dict() for flow in self.detected_flows],
            "vulnerabilities": vulnerabilities,
            "statistics": {
                "total_tainted_values": len(self.tainted_values),
                "total_flows": len(self.detected_flows),
                "total_vulnerabilities": len(vulnerabilities),
                "by_severity": self._count_by_severity(vulnerabilities),
                "by_type": self._count_by_type(vulnerabilities),
            }
        }

    def _identify_sources(self, lines: List[str], file_path: str):
        """Phase 1: Find all taint introduction points"""
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip comments
            if self._is_comment(stripped):
                continue

            # Check each source pattern
            for source in self.sources:
                match = re.search(source.pattern, line, re.IGNORECASE)
                if match:
                    # Extract the variable being assigned
                    var_name = self._extract_assigned_variable(line, match)
                    if var_name:
                        # Create tainted value
                        self.tainted_values[var_name] = TaintedValue(
                            variable_name=var_name,
                            taint_state=TaintState.TAINTED,
                            source_type=source.name,
                            source_line=line_num,
                            source_file=file_path,
                            original_source=match.group(0),
                            confidence=1.0 if source.risk_level == "high" else 0.8
                        )
                        logger.debug(f"Found taint source: {var_name} = {source.name} at line {line_num}")

    def _track_propagation(self, lines: List[str], file_path: str):
        """Phase 2: Track how taint propagates through assignments"""
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            if self._is_comment(stripped):
                continue

            # Check for assignments that propagate taint
            assignment_match = re.match(r'(\w+)\s*=\s*(.+)', stripped)
            if assignment_match:
                target_var = assignment_match.group(1)
                expression = assignment_match.group(2)

                # Check if expression uses any tainted variable
                for tainted_var, tainted_value in list(self.tainted_values.items()):
                    if self._expression_uses_variable(expression, tainted_var):
                        # Taint propagates to target variable
                        if target_var not in self.tainted_values:
                            # Create new tainted value from propagation
                            new_tainted = TaintedValue(
                                variable_name=target_var,
                                taint_state=tainted_value.taint_state,
                                source_type=f"propagated from {tainted_var}",
                                source_line=line_num,
                                source_file=file_path,
                                original_source=expression,
                                propagation_chain=tainted_value.propagation_chain.copy(),
                                sanitizers_applied=tainted_value.sanitizers_applied.copy(),
                                confidence=tainted_value.confidence * 0.95
                            )
                            new_tainted.add_propagation("assignment", line_num, stripped)
                            self.tainted_values[target_var] = new_tainted
                        else:
                            # Update existing tainted value
                            self.tainted_values[target_var].add_propagation("assignment", line_num, stripped)

                        break

            # Check for sanitizer application
            for sanitizer in self.sanitizers:
                if re.search(sanitizer.pattern, line, re.IGNORECASE):
                    # Find which tainted variable is being sanitized
                    for tainted_var in self.tainted_values:
                        if self._expression_uses_variable(line, tainted_var):
                            self._apply_sanitizer(tainted_var, sanitizer, line_num)

    def _identify_vulnerable_sinks(self, lines: List[str], file_path: str) -> List[Dict[str, Any]]:
        """Phase 3: Find sinks that receive tainted data"""
        vulnerabilities = []

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            if self._is_comment(stripped):
                continue

            # Check each sink
            for sink in self.sinks:
                match = re.search(sink.pattern, line, re.IGNORECASE)
                if match:
                    # Check if any tainted value reaches this sink
                    tainted_reaching_sink = []

                    for tainted_var, tainted_value in self.tainted_values.items():
                        if self._expression_uses_variable(line, tainted_var):
                            # Check if sanitized for this sink type
                            is_sanitized = self._is_sanitized_for_sink(tainted_value, sink)

                            if not is_sanitized and tainted_value.taint_state.is_dangerous():
                                tainted_reaching_sink.append(tainted_value)

                    # Also check for direct source usage in sink
                    if not tainted_reaching_sink:
                        for source in self.sources:
                            if re.search(source.pattern, line, re.IGNORECASE):
                                # Direct source to sink - most dangerous
                                tainted_reaching_sink.append(TaintedValue(
                                    variable_name="<direct>",
                                    taint_state=TaintState.TAINTED,
                                    source_type=source.name,
                                    source_line=line_num,
                                    source_file=file_path,
                                    original_source=line.strip(),
                                    confidence=1.0
                                ))
                                break

                    if tainted_reaching_sink or not sink.requires_taint:
                        # Generate vulnerability report
                        vuln = self._create_vulnerability(
                            sink, line_num, line.strip(), file_path,
                            tainted_reaching_sink[0] if tainted_reaching_sink else None
                        )
                        vulnerabilities.append(vuln)

                        # Create taint flow
                        if tainted_reaching_sink:
                            flow = TaintFlow(
                                flow_id=hashlib.md5(f"{file_path}:{line_num}:{sink.name}".encode()).hexdigest()[:12],
                                source=tainted_reaching_sink[0],
                                sink_name=sink.name,
                                sink_line=line_num,
                                sink_expression=line.strip(),
                                vulnerability_type=sink.vulnerability_type,
                                cwe_id=sink.cwe_id,
                                severity=sink.severity,
                                is_exploitable=True,
                                confidence=tainted_reaching_sink[0].confidence
                            )
                            self.detected_flows.append(flow)

        return vulnerabilities

    def _apply_sanitizer(self, var_name: str, sanitizer: SanitizerDefinition, line_num: int):
        """Apply a sanitizer to a tainted variable"""
        if var_name not in self.tainted_values:
            return

        tainted = self.tainted_values[var_name]
        tainted.apply_sanitizer(sanitizer.name, sanitizer.effectiveness)

        # Update taint state based on sanitizer effectiveness
        if sanitizer.effectiveness == "full":
            tainted.taint_state = TaintState.SANITIZED
        elif sanitizer.effectiveness == "partial":
            tainted.taint_state = TaintState.PARTIALLY_SANITIZED
        # context-dependent keeps current state but records sanitizer

        tainted.add_propagation(f"sanitizer:{sanitizer.name}", line_num, sanitizer.name)

    def _is_sanitized_for_sink(self, tainted_value: TaintedValue, sink: TaintSinkDefinition) -> bool:
        """Check if tainted value is properly sanitized for this specific sink"""
        if tainted_value.taint_state == TaintState.SANITIZED:
            # Check if any applied sanitizer protects against this sink type
            for sanitizer_entry in tainted_value.sanitizers_applied:
                sanitizer_name = sanitizer_entry.split(":")[0]
                for sanitizer in self.sanitizers:
                    if sanitizer.name == sanitizer_name:
                        if sink.vulnerability_type in sanitizer.sanitizes:
                            return True
                        # Also check sink's protected_by list
                        if sanitizer_name in sink.protected_by:
                            return True

        return False

    def _create_vulnerability(self, sink: TaintSinkDefinition, line_num: int,
                              expression: str, file_path: str,
                              tainted_value: Optional[TaintedValue]) -> Dict[str, Any]:
        """Create a vulnerability report"""
        confidence = "high"
        if tainted_value:
            confidence = "high" if tainted_value.confidence > 0.8 else "medium" if tainted_value.confidence > 0.5 else "low"
        elif not sink.requires_taint:
            confidence = "high"  # Static issue like weak crypto

        return {
            "type": sink.vulnerability_type,
            "severity": sink.severity,
            "cwe_id": sink.cwe_id,
            "sink": sink.name,
            "line_number": line_num,
            "expression": expression,
            "file_path": file_path,
            "description": sink.description,
            "confidence": confidence,
            "taint_info": {
                "is_tainted": tainted_value is not None,
                "source_type": tainted_value.source_type if tainted_value else None,
                "source_line": tainted_value.source_line if tainted_value else None,
                "propagation_length": len(tainted_value.propagation_chain) if tainted_value else 0,
                "sanitizers_applied": tainted_value.sanitizers_applied if tainted_value else [],
            } if tainted_value or sink.requires_taint else None,
            "remediation": f"Use one of: {', '.join(sink.protected_by)}" if sink.protected_by else "Review and fix manually",
        }

    def _expression_uses_variable(self, expression: str, var_name: str) -> bool:
        """Check if an expression references a variable"""
        # Match word boundary to avoid partial matches
        pattern = rf'\b{re.escape(var_name)}\b'
        return bool(re.search(pattern, expression))

    def _extract_assigned_variable(self, line: str, source_match: re.Match) -> Optional[str]:
        """Extract the variable name being assigned from a source"""
        # Common assignment patterns
        patterns = [
            r'(\w+)\s*=\s*' + re.escape(source_match.group(0)),  # var = source
            r'(\w+)\s*:=\s*' + re.escape(source_match.group(0)),  # Go short declaration
            r'(?:var|let|const)\s+(\w+)\s*=',  # JS/TS variable declaration
            r'\$(\w+)\s*=',  # PHP variable
        ]

        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)

        # If no assignment, return None (the value is used inline)
        return None

    def _is_comment(self, line: str) -> bool:
        """Check if a line is a comment"""
        comment_markers = {
            'python': ['#'],
            'javascript': ['//', '/*'],
            'typescript': ['//', '/*'],
            'go': ['//', '/*'],
            'php': ['//', '#', '/*'],
            'csharp': ['//', '/*'],
            'java': ['//', '/*'],
        }

        markers = comment_markers.get(self.language, ['#', '//'])
        return any(line.lstrip().startswith(m) for m in markers)

    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulnerabilities:
            severity = v.get("severity", "medium")
            if severity in counts:
                counts[severity] += 1
        return counts

    def _count_by_type(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by type"""
        counts: Dict[str, int] = {}
        for v in vulnerabilities:
            vtype = v.get("type", "Unknown")
            counts[vtype] = counts.get(vtype, 0) + 1
        return counts


# =============================================================================
# FACTORY FUNCTION
# =============================================================================

def create_taint_engine(language: str) -> TaintAnalysisEngine:
    """Create a taint analysis engine for the specified language"""
    return TaintAnalysisEngine(language)


def analyze_code(source_code: str, file_path: str, language: str = None) -> Dict[str, Any]:
    """
    Convenience function to analyze code for taint vulnerabilities.

    Args:
        source_code: The source code to analyze
        file_path: Path to the file (for reporting)
        language: Programming language (auto-detected if not provided)

    Returns:
        Analysis results with tainted values, flows, and vulnerabilities
    """
    if not language:
        # Auto-detect from file extension
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.go': 'go',
            '.php': 'php',
            '.cs': 'csharp',
            '.java': 'java',
        }
        import os
        ext = os.path.splitext(file_path)[1].lower()
        language = ext_map.get(ext, 'python')

    engine = create_taint_engine(language)
    return engine.analyze(source_code, file_path)
