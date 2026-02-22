"""
Comprehensive SAST Rules Engine - Inter-Procedural Analysis

This module provides accurate, language-specific security rules that go beyond
simple regex matching to include:
- Inter-procedural data flow tracking
- Taint source/sink/propagator definitions
- Framework-specific vulnerability patterns
- Context-aware false positive reduction
- Semantic analysis patterns

Supported Languages:
- Python (Django, Flask, FastAPI, SQLAlchemy)
- JavaScript/TypeScript (Express, React, Next.js, Node.js)
- Go (Gin, Echo, net/http)
- PHP (Laravel, Symfony, WordPress)
- C#/.NET (ASP.NET Core, Entity Framework)
- Java (Spring, Hibernate, Servlet)

Author: SecureDev AI Platform
"""

from typing import Dict, List, Any, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(Enum):
    INJECTION = "injection"
    XSS = "xss"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    DESERIALIZATION = "deserialization"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"
    LOGGING = "logging"
    INFORMATION_DISCLOSURE = "information_disclosure"
    RACE_CONDITION = "race_condition"
    MEMORY = "memory"
    CONFIGURATION = "configuration"


@dataclass
class TaintSource:
    """Definition of a taint source - where untrusted data enters"""
    name: str
    pattern: str
    language: str
    framework: Optional[str] = None
    tainted_return: bool = True
    tainted_params: List[int] = field(default_factory=list)
    description: str = ""
    confidence: str = "high"


@dataclass
class TaintSink:
    """Definition of a security-sensitive sink"""
    name: str
    pattern: str
    language: str
    framework: Optional[str] = None
    vulnerable_params: List[int] = field(default_factory=list)
    vulnerability_type: str = ""
    cwe: str = ""
    severity: Severity = Severity.HIGH
    description: str = ""
    requires_taint: bool = True  # Only flag if tainted data reaches sink


@dataclass
class Sanitizer:
    """Definition of a sanitization function"""
    name: str
    pattern: str
    language: str
    framework: Optional[str] = None
    sanitizes: List[str] = field(default_factory=list)  # Types of vulnerabilities it prevents
    description: str = ""


@dataclass
class Propagator:
    """Definition of taint propagator - functions that pass taint through"""
    name: str
    pattern: str
    language: str
    from_params: List[int] = field(default_factory=list)
    to_return: bool = True
    description: str = ""


# =============================================================================
# PYTHON RULES
# =============================================================================

PYTHON_TAINT_SOURCES = [
    # Flask Sources
    TaintSource("flask_request_args", r"request\.args(?:\.get)?", "python", "flask",
                description="Flask query string parameters - user controlled"),
    TaintSource("flask_request_form", r"request\.form(?:\.get)?", "python", "flask",
                description="Flask form data - user controlled"),
    TaintSource("flask_request_data", r"request\.data", "python", "flask",
                description="Flask raw request body"),
    TaintSource("flask_request_json", r"request\.(?:json|get_json)", "python", "flask",
                description="Flask JSON body - user controlled"),
    TaintSource("flask_request_headers", r"request\.headers(?:\.get)?", "python", "flask",
                description="Flask request headers"),
    TaintSource("flask_request_cookies", r"request\.cookies(?:\.get)?", "python", "flask",
                description="Flask cookies - user controlled"),
    TaintSource("flask_request_files", r"request\.files(?:\.get)?", "python", "flask",
                description="Flask file uploads"),
    TaintSource("flask_request_values", r"request\.values(?:\.get)?", "python", "flask",
                description="Flask combined args and form"),
    TaintSource("flask_view_args", r"request\.view_args", "python", "flask",
                description="Flask URL path parameters"),

    # Django Sources
    TaintSource("django_request_get", r"request\.GET(?:\.get)?", "python", "django",
                description="Django query parameters"),
    TaintSource("django_request_post", r"request\.POST(?:\.get)?", "python", "django",
                description="Django form data"),
    TaintSource("django_request_body", r"request\.body", "python", "django",
                description="Django raw request body"),
    TaintSource("django_request_files", r"request\.FILES(?:\.get)?", "python", "django",
                description="Django file uploads"),
    TaintSource("django_request_meta", r"request\.META(?:\.get)?", "python", "django",
                description="Django request metadata including headers"),
    TaintSource("django_path_kwargs", r"kwargs\[", "python", "django",
                description="Django URL path parameters"),

    # FastAPI Sources
    TaintSource("fastapi_query_param", r"(?:Query|Path|Body|Form|Header|Cookie)\s*\(", "python", "fastapi",
                description="FastAPI parameter injection points"),
    TaintSource("fastapi_request", r"request\.(query_params|path_params|headers|cookies|body)", "python", "fastapi",
                description="FastAPI raw request access"),

    # General Python Sources
    TaintSource("stdin_input", r"(?:input|raw_input)\s*\(", "python", None,
                description="Standard input - user controlled"),
    TaintSource("sys_argv", r"sys\.argv", "python", None,
                description="Command line arguments"),
    TaintSource("environ", r"os\.environ(?:\.get)?", "python", None,
                description="Environment variables - potentially controlled"),
    TaintSource("file_read", r"(?:open|read|readline|readlines)\s*\(", "python", None,
                description="File content - potentially untrusted", confidence="medium"),
    TaintSource("url_fetch", r"(?:urlopen|requests\.get|requests\.post|httpx\.get|aiohttp)", "python", None,
                description="External URL content"),
    TaintSource("socket_recv", r"\.recv(?:from)?\s*\(", "python", None,
                description="Network socket data"),
]

PYTHON_TAINT_SINKS = [
    # SQL Injection Sinks
    TaintSink("cursor_execute", r"cursor\.execute\s*\(\s*[^\),]*\+", "python", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="SQL execution with string concatenation"),
    TaintSink("execute_format", r"\.execute\s*\([^)]*\.format\s*\(", "python", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="SQL execution with string formatting"),
    TaintSink("execute_fstring", r"\.execute\s*\(\s*f['\"]", "python", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="SQL execution with f-string"),
    TaintSink("execute_percent", r"\.execute\s*\([^)]*%\s*\(", "python", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="SQL execution with % formatting"),
    TaintSink("raw_query", r"\.raw\s*\([^)]*\+", "python", "django",
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="Django raw SQL with concatenation"),
    TaintSink("extra_where", r"\.extra\s*\(\s*where\s*=", "python", "django",
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.HIGH,
              description="Django extra() with raw SQL"),

    # Command Injection Sinks
    TaintSink("os_system", r"os\.system\s*\(", "python", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="OS command execution"),
    TaintSink("os_popen", r"os\.popen\s*\(", "python", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="OS popen command execution"),
    TaintSink("subprocess_shell", r"subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True", "python", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="Subprocess with shell=True"),
    TaintSink("subprocess_string", r"subprocess\.(?:call|run|Popen)\s*\(\s*['\"]", "python", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.HIGH,
              description="Subprocess with string command"),
    TaintSink("eval", r"(?<!import\s)eval\s*\(", "python", None,
              vulnerable_params=[0], vulnerability_type="Code Injection", cwe="CWE-94",
              severity=Severity.CRITICAL,
              description="Python eval() execution"),
    TaintSink("exec", r"(?<!import\s)exec\s*\(", "python", None,
              vulnerable_params=[0], vulnerability_type="Code Injection", cwe="CWE-94",
              severity=Severity.CRITICAL,
              description="Python exec() execution"),
    TaintSink("compile", r"compile\s*\([^)]*,\s*['\"]exec['\"]", "python", None,
              vulnerable_params=[0], vulnerability_type="Code Injection", cwe="CWE-94",
              severity=Severity.HIGH,
              description="Python compile() for execution"),

    # XSS Sinks
    TaintSink("flask_render", r"render_template_string\s*\(", "python", "flask",
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="Flask render_template_string with user data"),
    TaintSink("jinja_raw", r"\|\s*safe\b", "python", "flask",
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="Jinja2 safe filter bypassing escaping"),
    TaintSink("mark_safe", r"mark_safe\s*\(", "python", "django",
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="Django mark_safe with user data"),
    TaintSink("response_write", r"(?:HttpResponse|Response)\s*\([^)]*\+", "python", None,
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.MEDIUM,
              description="Direct response with concatenated user data"),

    # Path Traversal Sinks
    TaintSink("open_file", r"open\s*\([^)]*\+", "python", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="File open with user-controlled path"),
    TaintSink("send_file", r"send_file\s*\(", "python", "flask",
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="Flask send_file with user path"),
    TaintSink("send_from_directory", r"send_from_directory\s*\([^,]+,\s*[^)]+\+", "python", "flask",
              vulnerable_params=[1], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="Flask send_from_directory with user filename"),
    TaintSink("os_path_join", r"os\.path\.join\s*\([^)]*request\.", "python", None,
              vulnerable_params=[1], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.MEDIUM,
              description="os.path.join with request data"),

    # SSRF Sinks
    TaintSink("requests_get", r"requests\.(?:get|post|put|delete|patch|head)\s*\([^)]*\+", "python", None,
              vulnerable_params=[0], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="HTTP request with user-controlled URL"),
    TaintSink("urllib_open", r"urllib\.request\.urlopen\s*\(", "python", None,
              vulnerable_params=[0], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="URL open with user-controlled URL"),
    TaintSink("httpx_request", r"httpx\.(?:get|post|put|delete)\s*\(", "python", None,
              vulnerable_params=[0], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="HTTPX request with user-controlled URL"),

    # Deserialization Sinks
    TaintSink("pickle_loads", r"pickle\.loads?\s*\(", "python", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.CRITICAL,
              description="Pickle deserialization - RCE risk"),
    TaintSink("yaml_load", r"yaml\.load\s*\([^)]*(?!Loader\s*=\s*(?:Safe|Base)Loader)", "python", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.CRITICAL,
              description="YAML load without safe loader"),
    TaintSink("marshal_loads", r"marshal\.loads?\s*\(", "python", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.HIGH,
              description="Marshal deserialization"),
    TaintSink("shelve_open", r"shelve\.open\s*\(", "python", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.HIGH,
              description="Shelve uses pickle internally"),

    # Cryptography Sinks (Weak)
    TaintSink("md5_hash", r"(?:hashlib\.)?md5\s*\(", "python", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.MEDIUM, requires_taint=False,
              description="MD5 is cryptographically broken"),
    TaintSink("sha1_hash", r"(?:hashlib\.)?sha1\s*\(", "python", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.LOW, requires_taint=False,
              description="SHA1 is deprecated for security use"),
    TaintSink("des_cipher", r"DES\s*\(|DES\.new\s*\(", "python", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.HIGH, requires_taint=False,
              description="DES is broken - use AES"),

    # Open Redirect Sinks
    TaintSink("redirect", r"redirect\s*\([^)]*\+", "python", None,
              vulnerable_params=[0], vulnerability_type="Open Redirect", cwe="CWE-601",
              severity=Severity.MEDIUM,
              description="Redirect with user-controlled URL"),
    TaintSink("flask_redirect", r"redirect\s*\(\s*request\.", "python", "flask",
              vulnerable_params=[0], vulnerability_type="Open Redirect", cwe="CWE-601",
              severity=Severity.MEDIUM,
              description="Flask redirect with request data"),

    # XXE Sinks
    TaintSink("etree_parse", r"etree\.(?:parse|fromstring)\s*\(", "python", None,
              vulnerable_params=[0], vulnerability_type="XXE", cwe="CWE-611",
              severity=Severity.HIGH,
              description="XML parsing without disabling entities"),
    TaintSink("xml_parse", r"xml\.(?:dom|sax)\..*parse", "python", None,
              vulnerable_params=[0], vulnerability_type="XXE", cwe="CWE-611",
              severity=Severity.HIGH,
              description="XML parsing vulnerable to XXE"),

    # LDAP Injection Sinks
    TaintSink("ldap_search", r"\.search(?:_s)?\s*\([^)]*\+", "python", None,
              vulnerable_params=[0, 1], vulnerability_type="LDAP Injection", cwe="CWE-90",
              severity=Severity.HIGH,
              description="LDAP search with user input"),

    # Template Injection Sinks
    TaintSink("jinja_from_string", r"(?:Template|Environment)\s*\([^)]*\+", "python", None,
              vulnerable_params=[0], vulnerability_type="SSTI", cwe="CWE-94",
              severity=Severity.CRITICAL,
              description="Template construction from user input"),
]

PYTHON_SANITIZERS = [
    Sanitizer("escape_html", r"(?:html\.escape|escape|markupsafe\.escape|bleach\.clean)", "python",
              sanitizes=["XSS"], description="HTML escaping"),
    Sanitizer("parameterized_query", r"\.execute\s*\([^,]+,\s*[\(\[\{]", "python",
              sanitizes=["SQL Injection"], description="Parameterized SQL query"),
    Sanitizer("secure_filename", r"secure_filename\s*\(", "python", "flask",
              sanitizes=["Path Traversal"], description="Werkzeug secure filename"),
    Sanitizer("shlex_quote", r"shlex\.quote\s*\(", "python",
              sanitizes=["Command Injection"], description="Shell argument quoting"),
    Sanitizer("subprocess_list", r"subprocess\.\w+\s*\(\s*\[", "python",
              sanitizes=["Command Injection"], description="Subprocess with list args"),
    Sanitizer("url_validator", r"(?:validators\.url|URLValidator)", "python",
              sanitizes=["SSRF", "Open Redirect"], description="URL validation"),
    Sanitizer("defused_xml", r"defusedxml\.", "python",
              sanitizes=["XXE"], description="Defused XML parser"),
    Sanitizer("yaml_safe_load", r"yaml\.safe_load", "python",
              sanitizes=["Insecure Deserialization"], description="Safe YAML loading"),
]


# =============================================================================
# JAVASCRIPT/TYPESCRIPT RULES
# =============================================================================

JS_TAINT_SOURCES = [
    # Express.js Sources
    TaintSource("express_req_query", r"req\.query(?:\.\w+|\[['\"])", "javascript", "express",
                description="Express query string parameters"),
    TaintSource("express_req_body", r"req\.body(?:\.\w+|\[['\"])?", "javascript", "express",
                description="Express request body"),
    TaintSource("express_req_params", r"req\.params(?:\.\w+|\[['\"])?", "javascript", "express",
                description="Express URL parameters"),
    TaintSource("express_req_headers", r"req\.headers(?:\.\w+|\[['\"])?", "javascript", "express",
                description="Express request headers"),
    TaintSource("express_req_cookies", r"req\.cookies(?:\.\w+|\[['\"])?", "javascript", "express",
                description="Express cookies"),
    TaintSource("express_req_files", r"req\.files?(?:\.\w+|\[['\"])?", "javascript", "express",
                description="Express file uploads"),

    # Browser DOM Sources
    TaintSource("location_search", r"(?:window\.)?location\.(?:search|hash|href|pathname)", "javascript", None,
                description="URL components - user controlled"),
    TaintSource("document_url", r"document\.(?:URL|documentURI|referrer)", "javascript", None,
                description="Document URL properties"),
    TaintSource("window_name", r"window\.name", "javascript", None,
                description="Window name - can be set by opener"),
    TaintSource("local_storage", r"(?:localStorage|sessionStorage)\.getItem", "javascript", None,
                description="Local storage - potentially tainted"),
    TaintSource("url_params", r"(?:URLSearchParams|new URL)\([^)]*\)\.get", "javascript", None,
                description="URL parameter extraction"),
    TaintSource("postmessage_data", r"(?:event|e|evt)\.data", "javascript", None,
                description="postMessage data - cross-origin"),
    TaintSource("user_input", r"(?:document|getElementById|querySelector).*\.(?:value|innerHTML|innerText|textContent)", "javascript", None,
                description="Form input values"),

    # Node.js Sources
    TaintSource("process_argv", r"process\.argv", "javascript", None,
                description="Command line arguments"),
    TaintSource("process_env", r"process\.env(?:\.\w+|\[['\"])?", "javascript", None,
                description="Environment variables"),
    TaintSource("fs_read", r"fs\.(?:readFile|readFileSync|read)", "javascript", None,
                description="File system reads"),
    TaintSource("socket_data", r"socket\.on\s*\(['\"]data['\"]", "javascript", None,
                description="Socket data events"),
]

JS_TAINT_SINKS = [
    # SQL Injection Sinks
    TaintSink("query_concat", r"\.query\s*\(\s*[`'\"].*?\$\{", "javascript", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="SQL query with template literal interpolation"),
    TaintSink("query_plus", r"\.query\s*\([^)]*\+", "javascript", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="SQL query with string concatenation"),
    TaintSink("sequelize_raw", r"sequelize\.query\s*\([^,]+,\s*\{[^}]*type:\s*['\"]RAW", "javascript", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.HIGH,
              description="Sequelize raw query"),
    TaintSink("knex_raw", r"knex\.raw\s*\([^)]*\+", "javascript", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="Knex raw query with concatenation"),

    # NoSQL Injection Sinks
    TaintSink("mongo_find", r"\.(?:find|findOne|findOneAndUpdate|updateOne|deleteOne)\s*\(\s*\{[^}]*\$", "javascript", None,
              vulnerable_params=[0], vulnerability_type="NoSQL Injection", cwe="CWE-943",
              severity=Severity.HIGH,
              description="MongoDB query with operators from user input"),
    TaintSink("mongo_where", r"\$where\s*:", "javascript", None,
              vulnerable_params=[0], vulnerability_type="NoSQL Injection", cwe="CWE-943",
              severity=Severity.CRITICAL,
              description="MongoDB $where allows JS execution"),

    # Command Injection Sinks
    TaintSink("child_exec", r"(?:exec|execSync)\s*\([^)]*\+", "javascript", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="child_process exec with concatenation"),
    TaintSink("child_exec_template", r"(?:exec|execSync)\s*\(\s*`", "javascript", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="child_process exec with template literal"),
    TaintSink("eval_js", r"(?<!import\s)eval\s*\(", "javascript", None,
              vulnerable_params=[0], vulnerability_type="Code Injection", cwe="CWE-94",
              severity=Severity.CRITICAL,
              description="eval() execution"),
    TaintSink("function_constructor", r"new\s+Function\s*\(", "javascript", None,
              vulnerable_params=[-1], vulnerability_type="Code Injection", cwe="CWE-94",
              severity=Severity.CRITICAL,
              description="Function constructor - eval equivalent"),
    TaintSink("settimeout_string", r"setTimeout\s*\(\s*['\"`]", "javascript", None,
              vulnerable_params=[0], vulnerability_type="Code Injection", cwe="CWE-94",
              severity=Severity.HIGH,
              description="setTimeout with string - implicit eval"),

    # XSS Sinks
    TaintSink("innerHTML", r"\.innerHTML\s*=", "javascript", None,
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="innerHTML assignment - DOM XSS"),
    TaintSink("outerHTML", r"\.outerHTML\s*=", "javascript", None,
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="outerHTML assignment - DOM XSS"),
    TaintSink("document_write", r"document\.(?:write|writeln)\s*\(", "javascript", None,
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="document.write - DOM XSS"),
    TaintSink("insertAdjacentHTML", r"\.insertAdjacentHTML\s*\(", "javascript", None,
              vulnerable_params=[1], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="insertAdjacentHTML - DOM XSS"),
    TaintSink("jquery_html", r"\$\([^)]+\)\.html\s*\(", "javascript", None,
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="jQuery .html() - DOM XSS"),
    TaintSink("jquery_append", r"\$\([^)]+\)\.(?:append|prepend|after|before)\s*\([^)]*\+", "javascript", None,
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.MEDIUM,
              description="jQuery DOM manipulation with concatenation"),
    TaintSink("react_dangerously", r"dangerouslySetInnerHTML\s*=\s*\{\s*\{", "javascript", "react",
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="React dangerouslySetInnerHTML"),
    TaintSink("res_send", r"res\.send\s*\([^)]*\+", "javascript", "express",
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.MEDIUM,
              description="Express response with concatenation"),

    # Path Traversal Sinks
    TaintSink("fs_readfile", r"fs\.(?:readFile|readFileSync|access|stat|open)\s*\([^)]*\+", "javascript", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="File system access with concatenation"),
    TaintSink("path_join", r"path\.join\s*\([^)]*req\.", "javascript", None,
              vulnerable_params=[1], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.MEDIUM,
              description="path.join with request data"),
    TaintSink("res_sendfile", r"res\.sendFile\s*\([^)]*\+", "javascript", "express",
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="Express sendFile with concatenation"),

    # SSRF Sinks
    TaintSink("fetch_url", r"fetch\s*\([^)]*\+", "javascript", None,
              vulnerable_params=[0], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="fetch with user-controlled URL"),
    TaintSink("axios_request", r"axios\.(?:get|post|put|delete|request)\s*\([^)]*\+", "javascript", None,
              vulnerable_params=[0], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="axios request with user-controlled URL"),
    TaintSink("http_request", r"(?:http|https)\.(?:request|get)\s*\(\s*[^)]*\+", "javascript", None,
              vulnerable_params=[0], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="Node.js HTTP request with user URL"),

    # Deserialization Sinks
    TaintSink("unserialize", r"(?:unserialize|deserialize)\s*\(", "javascript", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.CRITICAL,
              description="Deserialization of user data"),
    TaintSink("node_serialize", r"(?:serialize|node-serialize)\.unserialize", "javascript", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.CRITICAL,
              description="node-serialize RCE vulnerability"),

    # Prototype Pollution Sinks
    TaintSink("object_assign", r"Object\.assign\s*\(\s*\{\s*\}\s*,\s*[^)]*req\.", "javascript", None,
              vulnerable_params=[1], vulnerability_type="Prototype Pollution", cwe="CWE-1321",
              severity=Severity.HIGH,
              description="Object.assign with request data"),
    TaintSink("lodash_merge", r"_\.(?:merge|defaultsDeep|set)\s*\([^)]*req\.", "javascript", None,
              vulnerable_params=[1], vulnerability_type="Prototype Pollution", cwe="CWE-1321",
              severity=Severity.HIGH,
              description="Lodash deep merge with request data"),

    # Open Redirect Sinks
    TaintSink("res_redirect", r"res\.redirect\s*\([^)]*\+", "javascript", "express",
              vulnerable_params=[0], vulnerability_type="Open Redirect", cwe="CWE-601",
              severity=Severity.MEDIUM,
              description="Express redirect with user input"),
    TaintSink("location_href", r"(?:window\.)?location(?:\.href)?\s*=", "javascript", None,
              vulnerable_params=[0], vulnerability_type="Open Redirect", cwe="CWE-601",
              severity=Severity.MEDIUM,
              description="Location assignment - open redirect"),
]

JS_SANITIZERS = [
    Sanitizer("dompurify", r"DOMPurify\.sanitize\s*\(", "javascript",
              sanitizes=["XSS"], description="DOMPurify HTML sanitization"),
    Sanitizer("escape_html", r"(?:escapeHtml|escape|sanitize)\s*\(", "javascript",
              sanitizes=["XSS"], description="HTML escaping function"),
    Sanitizer("textContent", r"\.textContent\s*=", "javascript",
              sanitizes=["XSS"], description="textContent is safe"),
    Sanitizer("parameterized_sql", r"\.query\s*\([^,]+,\s*\[", "javascript",
              sanitizes=["SQL Injection"], description="Parameterized query"),
    Sanitizer("prepared_statement", r"\.prepare\s*\(['\"]", "javascript",
              sanitizes=["SQL Injection"], description="Prepared statement"),
    Sanitizer("path_normalize", r"path\.(?:normalize|resolve|basename)\s*\(", "javascript",
              sanitizes=["Path Traversal"], description="Path normalization"),
    Sanitizer("execFile", r"execFile\s*\(", "javascript",
              sanitizes=["Command Injection"], description="execFile with arguments array"),
    Sanitizer("spawn_array", r"spawn\s*\([^,]+,\s*\[", "javascript",
              sanitizes=["Command Injection"], description="spawn with arguments array"),
    Sanitizer("url_validator", r"(?:validator\.isURL|URL\.canParse)", "javascript",
              sanitizes=["SSRF", "Open Redirect"], description="URL validation"),
]


# =============================================================================
# GO RULES
# =============================================================================

GO_TAINT_SOURCES = [
    # HTTP Sources
    TaintSource("http_request_form", r"r\.Form(?:Value)?\[", "go", None,
                description="HTTP form values"),
    TaintSource("http_request_url", r"r\.URL\.(?:Query|Path|RawQuery)", "go", None,
                description="HTTP URL components"),
    TaintSource("http_request_header", r"r\.Header\.(?:Get|Values)", "go", None,
                description="HTTP headers"),
    TaintSource("http_request_body", r"(?:ioutil\.ReadAll|io\.ReadAll)\s*\(\s*r\.Body", "go", None,
                description="HTTP request body"),
    TaintSource("http_request_cookie", r"r\.Cookie\s*\(", "go", None,
                description="HTTP cookies"),
    TaintSource("http_path_value", r"r\.PathValue\s*\(", "go", None,
                description="HTTP path parameters"),

    # Gin Framework Sources
    TaintSource("gin_query", r"c\.Query\s*\(", "go", "gin",
                description="Gin query parameter"),
    TaintSource("gin_param", r"c\.Param\s*\(", "go", "gin",
                description="Gin URL parameter"),
    TaintSource("gin_postform", r"c\.PostForm\s*\(", "go", "gin",
                description="Gin form value"),
    TaintSource("gin_bind", r"c\.(?:Bind|ShouldBind|BindJSON)", "go", "gin",
                description="Gin request binding"),
    TaintSource("gin_getrawdata", r"c\.GetRawData\s*\(", "go", "gin",
                description="Gin raw body"),

    # Echo Framework Sources
    TaintSource("echo_queryparam", r"c\.QueryParam\s*\(", "go", "echo",
                description="Echo query parameter"),
    TaintSource("echo_pathparam", r"c\.Param\s*\(", "go", "echo",
                description="Echo path parameter"),
    TaintSource("echo_formvalue", r"c\.FormValue\s*\(", "go", "echo",
                description="Echo form value"),
    TaintSource("echo_bind", r"c\.Bind\s*\(", "go", "echo",
                description="Echo request binding"),

    # General Sources
    TaintSource("os_args", r"os\.Args", "go", None,
                description="Command line arguments"),
    TaintSource("os_getenv", r"os\.(?:Getenv|LookupEnv)\s*\(", "go", None,
                description="Environment variables"),
    TaintSource("file_read", r"(?:ioutil|os)\.ReadFile\s*\(", "go", None,
                description="File content"),
]

GO_TAINT_SINKS = [
    # SQL Injection Sinks
    TaintSink("db_query_concat", r"\.(?:Query|QueryRow|Exec)\s*\([^)]*\+", "go", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="SQL query with string concatenation"),
    TaintSink("db_query_fmt", r"\.(?:Query|QueryRow|Exec)\s*\(\s*fmt\.Sprintf", "go", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="SQL query with fmt.Sprintf"),
    TaintSink("gorm_raw", r"\.Raw\s*\([^)]*\+", "go", "gorm",
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.HIGH,
              description="GORM raw query with concatenation"),

    # Command Injection Sinks
    TaintSink("exec_command", r"exec\.Command\s*\([^)]*\+", "go", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="exec.Command with concatenation"),
    TaintSink("exec_commandcontext", r"exec\.CommandContext\s*\([^,]+,[^)]*\+", "go", None,
              vulnerable_params=[1], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="exec.CommandContext with concatenation"),
    TaintSink("os_exec", r"os\.(?:StartProcess|Exec)\s*\([^)]*\+", "go", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="os process execution with concatenation"),

    # Path Traversal Sinks
    TaintSink("os_open", r"os\.(?:Open|OpenFile|Create)\s*\([^)]*\+", "go", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="File open with concatenation"),
    TaintSink("filepath_join", r"filepath\.Join\s*\([^)]*r\.", "go", None,
              vulnerable_params=[1], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.MEDIUM,
              description="filepath.Join with request data"),
    TaintSink("ioutil_readfile", r"(?:ioutil|os)\.ReadFile\s*\([^)]*\+", "go", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="ReadFile with concatenation"),

    # SSRF Sinks
    TaintSink("http_get", r"http\.(?:Get|Post|PostForm|Head)\s*\([^)]*\+", "go", None,
              vulnerable_params=[0], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="HTTP request with user URL"),
    TaintSink("http_newrequest", r"http\.NewRequest\s*\([^,]+,[^)]*\+", "go", None,
              vulnerable_params=[1], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="HTTP NewRequest with user URL"),

    # XSS Sinks (Template)
    TaintSink("template_html", r"template\.HTML\s*\(", "go", None,
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="template.HTML bypasses escaping"),
    TaintSink("template_htmlattr", r"template\.HTMLAttr\s*\(", "go", None,
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="template.HTMLAttr bypasses escaping"),
    TaintSink("fmt_fprintf_response", r"fmt\.Fprintf\s*\(\s*w\s*,", "go", None,
              vulnerable_params=[1], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.MEDIUM,
              description="Direct response write without encoding"),

    # Deserialization Sinks
    TaintSink("gob_decode", r"gob\.(?:NewDecoder|Decode)\s*\(", "go", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.HIGH,
              description="Gob decoding of untrusted data"),
    TaintSink("json_unmarshal", r"json\.Unmarshal\s*\([^,]+,\s*&?interface\{", "go", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.MEDIUM,
              description="JSON unmarshaling to interface"),

    # Redirect Sinks
    TaintSink("http_redirect", r"http\.Redirect\s*\([^)]+,\s*[^,]+,\s*[^)]*\+", "go", None,
              vulnerable_params=[2], vulnerability_type="Open Redirect", cwe="CWE-601",
              severity=Severity.MEDIUM,
              description="HTTP redirect with user URL"),

    # Weak Crypto
    TaintSink("md5_new", r"md5\.(?:New|Sum)\s*\(", "go", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.MEDIUM, requires_taint=False,
              description="MD5 is cryptographically broken"),
    TaintSink("sha1_new", r"sha1\.(?:New|Sum)\s*\(", "go", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.LOW, requires_taint=False,
              description="SHA1 is deprecated"),
    TaintSink("des_cipher", r"des\.NewCipher\s*\(", "go", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.HIGH, requires_taint=False,
              description="DES is broken"),
]

GO_SANITIZERS = [
    Sanitizer("prepared_stmt", r"\.(?:Prepare|PrepareContext)\s*\(", "go",
              sanitizes=["SQL Injection"], description="Prepared statement"),
    Sanitizer("parameterized_query", r"\.(?:Query|Exec)\s*\([^,]+,\s*[^)]+\)", "go",
              sanitizes=["SQL Injection"], description="Query with parameters"),
    Sanitizer("filepath_clean", r"filepath\.Clean\s*\(", "go",
              sanitizes=["Path Traversal"], description="Path cleaning"),
    Sanitizer("filepath_base", r"filepath\.Base\s*\(", "go",
              sanitizes=["Path Traversal"], description="Get base filename"),
    Sanitizer("template_escapestring", r"template\.(?:HTMLEscapeString|JSEscapeString)", "go",
              sanitizes=["XSS"], description="Template escaping"),
    Sanitizer("url_parse", r"url\.(?:Parse|ParseRequestURI)\s*\(", "go",
              sanitizes=["SSRF"], description="URL parsing and validation"),
]


# =============================================================================
# PHP RULES
# =============================================================================

PHP_TAINT_SOURCES = [
    # Superglobals
    TaintSource("get_param", r"\$_GET\s*\[", "php", None,
                description="GET parameter - user controlled"),
    TaintSource("post_param", r"\$_POST\s*\[", "php", None,
                description="POST parameter - user controlled"),
    TaintSource("request_param", r"\$_REQUEST\s*\[", "php", None,
                description="REQUEST parameter - user controlled"),
    TaintSource("cookie_param", r"\$_COOKIE\s*\[", "php", None,
                description="Cookie - user controlled"),
    TaintSource("server_param", r"\$_SERVER\s*\[['\"](?:HTTP_|REQUEST_|QUERY_|PATH_)", "php", None,
                description="Server variables - some user controlled"),
    TaintSource("files_param", r"\$_FILES\s*\[", "php", None,
                description="File upload - user controlled"),
    TaintSource("env_param", r"\$_ENV\s*\[", "php", None,
                description="Environment variables"),

    # Laravel Sources
    TaintSource("laravel_input", r"\$request->(?:input|get|post|query|all)\s*\(", "php", "laravel",
                description="Laravel request input"),
    TaintSource("laravel_route_param", r"\$request->route\s*\(", "php", "laravel",
                description="Laravel route parameter"),
    TaintSource("laravel_file", r"\$request->file\s*\(", "php", "laravel",
                description="Laravel file upload"),

    # Symfony Sources
    TaintSource("symfony_request", r"\$request->(?:get|query|request|cookies|headers)->get\s*\(", "php", "symfony",
                description="Symfony request bag"),

    # General Sources
    TaintSource("file_get_contents", r"file_get_contents\s*\(", "php", None,
                description="File content - potentially tainted"),
    TaintSource("php_input", r"file_get_contents\s*\(\s*['\"]php://input['\"]", "php", None,
                description="Raw POST body"),
    TaintSource("fgets", r"fgets\s*\(\s*STDIN", "php", None,
                description="Standard input"),
]

PHP_TAINT_SINKS = [
    # SQL Injection Sinks
    TaintSink("mysql_query", r"mysql(?:i)?_query\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="mysql_query with variable"),
    TaintSink("mysqli_query", r"\$\w+->query\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="mysqli query with variable"),
    TaintSink("pdo_query", r"\$\w+->query\s*\([^)]*\.\s*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="PDO query with concatenation"),
    TaintSink("pdo_exec", r"\$\w+->exec\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="PDO exec with variable"),
    TaintSink("laravel_raw", r"DB::(?:raw|statement|select|insert|update|delete)\s*\([^)]*\$", "php", "laravel",
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.HIGH,
              description="Laravel raw SQL with variable"),
    TaintSink("laravel_whereraw", r"->whereRaw\s*\([^)]*\$", "php", "laravel",
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.HIGH,
              description="Laravel whereRaw with variable"),

    # Command Injection Sinks
    TaintSink("system", r"(?<!\\)system\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="system() with variable"),
    TaintSink("exec", r"(?<!\\)exec\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="exec() with variable"),
    TaintSink("shell_exec", r"shell_exec\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="shell_exec() with variable"),
    TaintSink("passthru", r"passthru\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="passthru() with variable"),
    TaintSink("popen", r"popen\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="popen() with variable"),
    TaintSink("proc_open", r"proc_open\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="proc_open() with variable"),
    TaintSink("backtick", r"`[^`]*\$[^`]*`", "php", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="Backtick operator with variable"),
    TaintSink("eval", r"(?<!\\)eval\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Code Injection", cwe="CWE-94",
              severity=Severity.CRITICAL,
              description="eval() with variable"),
    TaintSink("create_function", r"create_function\s*\([^)]*\$", "php", None,
              vulnerable_params=[0, 1], vulnerability_type="Code Injection", cwe="CWE-94",
              severity=Severity.CRITICAL,
              description="create_function() with variable"),
    TaintSink("preg_replace_e", r"preg_replace\s*\(\s*['\"][^'\"]*e[^'\"]*['\"]", "php", None,
              vulnerable_params=[1, 2], vulnerability_type="Code Injection", cwe="CWE-94",
              severity=Severity.CRITICAL,
              description="preg_replace with /e modifier"),

    # XSS Sinks
    TaintSink("echo", r"echo\s+[^;]*\$_(?:GET|POST|REQUEST|COOKIE)", "php", None,
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="echo with superglobal"),
    TaintSink("print", r"print\s+[^;]*\$_(?:GET|POST|REQUEST|COOKIE)", "php", None,
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="print with superglobal"),
    TaintSink("printf", r"(?:printf|vprintf)\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.MEDIUM,
              description="printf with variable"),

    # Path Traversal Sinks
    TaintSink("include", r"(?:include|include_once|require|require_once)\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal/RCE", cwe="CWE-22",
              severity=Severity.CRITICAL,
              description="File inclusion with variable"),
    TaintSink("fopen", r"fopen\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="fopen() with variable"),
    TaintSink("file_get_contents_path", r"file_get_contents\s*\([^)]*\$_(?:GET|POST|REQUEST)", "php", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="file_get_contents with superglobal"),
    TaintSink("readfile", r"readfile\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="readfile() with variable"),
    TaintSink("file", r"(?<!_)file\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="file() with variable"),
    TaintSink("unlink", r"unlink\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="unlink() with variable - file deletion"),
    TaintSink("copy", r"copy\s*\([^)]*\$", "php", None,
              vulnerable_params=[0, 1], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="copy() with variable"),

    # SSRF Sinks
    TaintSink("curl_setopt_url", r"curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$", "php", None,
              vulnerable_params=[2], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="cURL with user URL"),
    TaintSink("file_get_contents_url", r"file_get_contents\s*\(\s*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="file_get_contents with user URL"),

    # Deserialization Sinks
    TaintSink("unserialize", r"unserialize\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.CRITICAL,
              description="unserialize() with user data - RCE risk"),

    # XXE Sinks
    TaintSink("simplexml_load", r"simplexml_load_(?:string|file)\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="XXE", cwe="CWE-611",
              severity=Severity.HIGH,
              description="SimpleXML loading user data"),
    TaintSink("domdocument_load", r"\$\w+->load(?:XML|HTML)\s*\([^)]*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="XXE", cwe="CWE-611",
              severity=Severity.HIGH,
              description="DOMDocument loading user data"),

    # Open Redirect Sinks
    TaintSink("header_location", r"header\s*\(\s*['\"]Location:\s*['\"]?\s*\.\s*\$", "php", None,
              vulnerable_params=[0], vulnerability_type="Open Redirect", cwe="CWE-601",
              severity=Severity.MEDIUM,
              description="Location header with user data"),
    TaintSink("laravel_redirect", r"redirect\s*\([^)]*\$", "php", "laravel",
              vulnerable_params=[0], vulnerability_type="Open Redirect", cwe="CWE-601",
              severity=Severity.MEDIUM,
              description="Laravel redirect with user data"),

    # Weak Crypto
    TaintSink("md5", r"(?<!\\)md5\s*\(", "php", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.MEDIUM, requires_taint=False,
              description="MD5 is cryptographically broken"),
    TaintSink("sha1", r"(?<!\\)sha1\s*\(", "php", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.LOW, requires_taint=False,
              description="SHA1 is deprecated"),
]

PHP_SANITIZERS = [
    Sanitizer("mysqli_real_escape", r"mysqli_real_escape_string\s*\(", "php",
              sanitizes=["SQL Injection"], description="mysqli escaping"),
    Sanitizer("pdo_prepare", r"\$\w+->prepare\s*\(", "php",
              sanitizes=["SQL Injection"], description="PDO prepared statement"),
    Sanitizer("htmlspecialchars", r"htmlspecialchars\s*\(", "php",
              sanitizes=["XSS"], description="HTML special chars escaping"),
    Sanitizer("htmlentities", r"htmlentities\s*\(", "php",
              sanitizes=["XSS"], description="HTML entities escaping"),
    Sanitizer("strip_tags", r"strip_tags\s*\(", "php",
              sanitizes=["XSS"], description="Strip HTML tags"),
    Sanitizer("escapeshellarg", r"escapeshellarg\s*\(", "php",
              sanitizes=["Command Injection"], description="Shell argument escaping"),
    Sanitizer("escapeshellcmd", r"escapeshellcmd\s*\(", "php",
              sanitizes=["Command Injection"], description="Shell command escaping"),
    Sanitizer("basename", r"basename\s*\(", "php",
              sanitizes=["Path Traversal"], description="Get base filename"),
    Sanitizer("realpath", r"realpath\s*\(", "php",
              sanitizes=["Path Traversal"], description="Resolve real path"),
    Sanitizer("filter_var", r"filter_var\s*\([^,]+,\s*FILTER_(?:VALIDATE|SANITIZE)_", "php",
              sanitizes=["XSS", "SQL Injection"], description="Input filtering"),
    Sanitizer("libxml_disable", r"libxml_disable_entity_loader\s*\(\s*true\s*\)", "php",
              sanitizes=["XXE"], description="Disable XML external entities"),
]


# =============================================================================
# C#/.NET RULES
# =============================================================================

CSHARP_TAINT_SOURCES = [
    # ASP.NET Core Sources
    TaintSource("request_query", r"Request\.Query\[", "csharp", "aspnet",
                description="ASP.NET query string"),
    TaintSource("request_form", r"Request\.Form\[", "csharp", "aspnet",
                description="ASP.NET form data"),
    TaintSource("request_body", r"Request\.Body", "csharp", "aspnet",
                description="ASP.NET request body"),
    TaintSource("request_headers", r"Request\.Headers\[", "csharp", "aspnet",
                description="ASP.NET request headers"),
    TaintSource("request_cookies", r"Request\.Cookies\[", "csharp", "aspnet",
                description="ASP.NET cookies"),
    TaintSource("request_routevalues", r"Request\.RouteValues\[", "csharp", "aspnet",
                description="ASP.NET route values"),
    TaintSource("httpcontext_request", r"HttpContext\.Request\.", "csharp", "aspnet",
                description="ASP.NET HttpContext request"),
    TaintSource("model_binding", r"\[From(?:Query|Body|Route|Header|Form)\]", "csharp", "aspnet",
                description="ASP.NET model binding", confidence="medium"),

    # General Sources
    TaintSource("console_readline", r"Console\.ReadLine\s*\(", "csharp", None,
                description="Console input"),
    TaintSource("environment_var", r"Environment\.GetEnvironmentVariable\s*\(", "csharp", None,
                description="Environment variables"),
    TaintSource("file_read", r"File\.(?:ReadAllText|ReadAllLines|ReadAllBytes)\s*\(", "csharp", None,
                description="File content"),
    TaintSource("stream_reader", r"StreamReader\s*\([^)]+\)\.Read", "csharp", None,
                description="Stream reading"),
]

CSHARP_TAINT_SINKS = [
    # SQL Injection Sinks
    TaintSink("sqlcommand_concat", r"new\s+SqlCommand\s*\([^)]*\+", "csharp", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="SqlCommand with concatenation"),
    TaintSink("sqlcommand_format", r"new\s+SqlCommand\s*\(\s*(?:\$\"|string\.Format)", "csharp", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="SqlCommand with string interpolation"),
    TaintSink("executenonquery", r"\.CommandText\s*=\s*[^;]+\+", "csharp", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="CommandText with concatenation"),
    TaintSink("fromsqlraw", r"\.FromSqlRaw\s*\(\s*\$", "csharp", "efcore",
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.HIGH,
              description="EF Core FromSqlRaw with interpolation"),
    TaintSink("executesqlraw", r"\.ExecuteSqlRaw\s*\(\s*\$", "csharp", "efcore",
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.HIGH,
              description="EF Core ExecuteSqlRaw with interpolation"),

    # Command Injection Sinks
    TaintSink("process_start", r"Process\.Start\s*\([^)]*\+", "csharp", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="Process.Start with concatenation"),
    TaintSink("process_startinfo", r"new\s+ProcessStartInfo\s*\([^)]*\+", "csharp", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="ProcessStartInfo with concatenation"),
    TaintSink("process_arguments", r"\.Arguments\s*=\s*[^;]+\+", "csharp", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.HIGH,
              description="Process arguments with concatenation"),

    # XSS Sinks
    TaintSink("htmlraw", r"Html\.Raw\s*\(", "csharp", "aspnet",
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="Html.Raw bypasses encoding"),
    TaintSink("response_write", r"Response\.Write\s*\([^)]*\+", "csharp", "aspnet",
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.MEDIUM,
              description="Response.Write with concatenation"),
    TaintSink("content_result", r"Content\s*\([^)]*\+", "csharp", "aspnet",
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.MEDIUM,
              description="Content result with concatenation"),

    # Path Traversal Sinks
    TaintSink("file_read_path", r"File\.(?:ReadAllText|ReadAllLines|Open|OpenRead)\s*\([^)]*\+", "csharp", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="File access with concatenation"),
    TaintSink("path_combine", r"Path\.Combine\s*\([^)]*Request\.", "csharp", None,
              vulnerable_params=[1], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.MEDIUM,
              description="Path.Combine with request data"),
    TaintSink("streamwriter", r"new\s+StreamWriter\s*\([^)]*\+", "csharp", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="StreamWriter with concatenation"),

    # SSRF Sinks
    TaintSink("httpclient_getstring", r"HttpClient\.GetStringAsync\s*\([^)]*\+", "csharp", None,
              vulnerable_params=[0], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="HttpClient with user URL"),
    TaintSink("webclient_download", r"WebClient\.Download\w+\s*\([^)]*\+", "csharp", None,
              vulnerable_params=[0], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="WebClient with user URL"),

    # Deserialization Sinks
    TaintSink("binaryformatter", r"BinaryFormatter\s*\(\s*\)\.Deserialize", "csharp", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.CRITICAL,
              description="BinaryFormatter deserialization - RCE risk"),
    TaintSink("javascriptserializer", r"JavaScriptSerializer\s*\(\s*\)\.Deserialize", "csharp", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.HIGH,
              description="JavaScriptSerializer deserialization"),
    TaintSink("xmlserializer", r"XmlSerializer\s*\([^)]*\)\.Deserialize", "csharp", None,
              vulnerable_params=[0], vulnerability_type="XXE/Deserialization", cwe="CWE-502",
              severity=Severity.HIGH,
              description="XmlSerializer deserialization"),
    TaintSink("newtonsoft_deserialize", r"JsonConvert\.DeserializeObject<\w+>\s*\([^)]*\+", "csharp", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.MEDIUM,
              description="JSON deserialization with type"),

    # XXE Sinks
    TaintSink("xmldocument_load", r"XmlDocument\s*\(\s*\)\.(?:Load|LoadXml)\s*\(", "csharp", None,
              vulnerable_params=[0], vulnerability_type="XXE", cwe="CWE-611",
              severity=Severity.HIGH,
              description="XmlDocument loading - XXE risk"),
    TaintSink("xmlreader_create", r"XmlReader\.Create\s*\([^)]*\+", "csharp", None,
              vulnerable_params=[0], vulnerability_type="XXE", cwe="CWE-611",
              severity=Severity.HIGH,
              description="XmlReader with user data"),

    # Open Redirect Sinks
    TaintSink("redirect", r"Redirect\s*\([^)]*\+", "csharp", "aspnet",
              vulnerable_params=[0], vulnerability_type="Open Redirect", cwe="CWE-601",
              severity=Severity.MEDIUM,
              description="Redirect with user URL"),
    TaintSink("redirecttoaction", r"RedirectToAction\s*\([^)]*Request\.", "csharp", "aspnet",
              vulnerable_params=[0], vulnerability_type="Open Redirect", cwe="CWE-601",
              severity=Severity.MEDIUM,
              description="RedirectToAction with request data"),

    # LDAP Injection
    TaintSink("directoryentry", r"new\s+DirectoryEntry\s*\([^)]*\+", "csharp", None,
              vulnerable_params=[0], vulnerability_type="LDAP Injection", cwe="CWE-90",
              severity=Severity.HIGH,
              description="DirectoryEntry with concatenation"),
    TaintSink("ldap_search", r"DirectorySearcher\s*\([^)]*\)\.Filter\s*=\s*[^;]+\+", "csharp", None,
              vulnerable_params=[0], vulnerability_type="LDAP Injection", cwe="CWE-90",
              severity=Severity.HIGH,
              description="LDAP filter with concatenation"),

    # Weak Crypto
    TaintSink("md5_create", r"MD5\.Create\s*\(", "csharp", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.MEDIUM, requires_taint=False,
              description="MD5 is cryptographically broken"),
    TaintSink("sha1_create", r"SHA1\.Create\s*\(", "csharp", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.LOW, requires_taint=False,
              description="SHA1 is deprecated"),
    TaintSink("des_create", r"DES\.Create\s*\(", "csharp", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.HIGH, requires_taint=False,
              description="DES is broken"),
]

CSHARP_SANITIZERS = [
    Sanitizer("sqlparameter", r"new\s+SqlParameter\s*\(", "csharp",
              sanitizes=["SQL Injection"], description="SQL parameterization"),
    Sanitizer("parameters_add", r"\.Parameters\.(?:Add|AddWithValue)\s*\(", "csharp",
              sanitizes=["SQL Injection"], description="SQL parameterization"),
    Sanitizer("fromsqlinterpolated", r"\.FromSqlInterpolated\s*\(", "csharp", "efcore",
              sanitizes=["SQL Injection"], description="EF Core safe interpolation"),
    Sanitizer("htmlencode", r"(?:Html|Http)(?:Utility)?\.(?:Html)?Encode\s*\(", "csharp",
              sanitizes=["XSS"], description="HTML encoding"),
    Sanitizer("antixss", r"(?:AntiXss|Encoder)\.\w+Encode\s*\(", "csharp",
              sanitizes=["XSS"], description="AntiXSS encoding"),
    Sanitizer("path_getfilename", r"Path\.GetFileName\s*\(", "csharp",
              sanitizes=["Path Traversal"], description="Get filename only"),
    Sanitizer("uri_isabsoluteuri", r"Uri\.IsWellFormed|\.IsAbsoluteUri", "csharp",
              sanitizes=["SSRF", "Open Redirect"], description="URI validation"),
    Sanitizer("xmlreadersettings", r"XmlReaderSettings\s*\{[^}]*DtdProcessing\s*=\s*DtdProcessing\.Prohibit", "csharp",
              sanitizes=["XXE"], description="Disable DTD processing"),
]


# =============================================================================
# JAVA RULES
# =============================================================================

JAVA_TAINT_SOURCES = [
    # Servlet Sources
    TaintSource("servlet_parameter", r"request\.getParameter\s*\(", "java", "servlet",
                description="HTTP request parameter"),
    TaintSource("servlet_parametermap", r"request\.getParameterMap\s*\(", "java", "servlet",
                description="All request parameters"),
    TaintSource("servlet_header", r"request\.getHeader\s*\(", "java", "servlet",
                description="HTTP request header"),
    TaintSource("servlet_cookie", r"request\.getCookies\s*\(", "java", "servlet",
                description="HTTP cookies"),
    TaintSource("servlet_pathinfo", r"request\.getPathInfo\s*\(", "java", "servlet",
                description="URL path info"),
    TaintSource("servlet_querystring", r"request\.getQueryString\s*\(", "java", "servlet",
                description="Query string"),
    TaintSource("servlet_inputstream", r"request\.getInputStream\s*\(", "java", "servlet",
                description="Request body stream"),
    TaintSource("servlet_reader", r"request\.getReader\s*\(", "java", "servlet",
                description="Request body reader"),

    # Spring Sources
    TaintSource("spring_requestparam", r"@RequestParam", "java", "spring",
                description="Spring request parameter", confidence="medium"),
    TaintSource("spring_pathvariable", r"@PathVariable", "java", "spring",
                description="Spring path variable", confidence="medium"),
    TaintSource("spring_requestbody", r"@RequestBody", "java", "spring",
                description="Spring request body", confidence="medium"),
    TaintSource("spring_requestheader", r"@RequestHeader", "java", "spring",
                description="Spring request header", confidence="medium"),
    TaintSource("spring_cookievalue", r"@CookieValue", "java", "spring",
                description="Spring cookie value", confidence="medium"),

    # General Sources
    TaintSource("scanner_next", r"scanner\.next\w*\s*\(", "java", None,
                description="Scanner input"),
    TaintSource("bufferedreader_readline", r"bufferedReader\.readLine\s*\(", "java", None,
                description="Reader input"),
    TaintSource("system_getenv", r"System\.getenv\s*\(", "java", None,
                description="Environment variable"),
    TaintSource("system_getproperty", r"System\.getProperty\s*\(", "java", None,
                description="System property"),
]

JAVA_TAINT_SINKS = [
    # SQL Injection Sinks
    TaintSink("statement_execute", r"(?:Statement|PreparedStatement)\s+\w+.*?\.(?:execute|executeQuery|executeUpdate)\s*\([^)]*\+", "java", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="SQL execution with concatenation"),
    TaintSink("createstatement", r"connection\.createStatement\s*\(\s*\).*?\.execute\w*\s*\([^)]*\+", "java", None,
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.CRITICAL,
              description="Statement with concatenation"),
    TaintSink("createquery", r"\.createQuery\s*\([^)]*\+", "java", "hibernate",
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.HIGH,
              description="Hibernate createQuery with concatenation"),
    TaintSink("createnativequery", r"\.createNativeQuery\s*\([^)]*\+", "java", "jpa",
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.HIGH,
              description="JPA native query with concatenation"),
    TaintSink("jdbctemplate_query", r"jdbcTemplate\.(?:query|update|execute)\s*\([^)]*\+", "java", "spring",
              vulnerable_params=[0], vulnerability_type="SQL Injection", cwe="CWE-89",
              severity=Severity.HIGH,
              description="JdbcTemplate with concatenation"),

    # Command Injection Sinks
    TaintSink("runtime_exec", r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\([^)]*\+", "java", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="Runtime.exec with concatenation"),
    TaintSink("processbuilder", r"new\s+ProcessBuilder\s*\([^)]*\+", "java", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.CRITICAL,
              description="ProcessBuilder with concatenation"),
    TaintSink("processbuilder_command", r"processBuilder\.command\s*\([^)]*\+", "java", None,
              vulnerable_params=[0], vulnerability_type="Command Injection", cwe="CWE-78",
              severity=Severity.HIGH,
              description="ProcessBuilder.command with concatenation"),

    # XSS Sinks
    TaintSink("printwriter_print", r"(?:PrintWriter|response\.getWriter\s*\(\s*\))\.(?:print|println|write)\s*\([^)]*\+", "java", "servlet",
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.MEDIUM,
              description="Response write with concatenation"),
    TaintSink("jsp_expression", r"<%=.*?request\.getParameter", "java", "jsp",
              vulnerable_params=[0], vulnerability_type="XSS", cwe="CWE-79",
              severity=Severity.HIGH,
              description="JSP expression with request parameter"),

    # Path Traversal Sinks
    TaintSink("file_constructor", r"new\s+File\s*\([^)]*\+", "java", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="File with concatenation"),
    TaintSink("fileinputstream", r"new\s+FileInputStream\s*\([^)]*\+", "java", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="FileInputStream with concatenation"),
    TaintSink("paths_get", r"Paths\.get\s*\([^)]*\+", "java", None,
              vulnerable_params=[0], vulnerability_type="Path Traversal", cwe="CWE-22",
              severity=Severity.HIGH,
              description="Paths.get with concatenation"),

    # SSRF Sinks
    TaintSink("url_constructor", r"new\s+URL\s*\([^)]*\+", "java", None,
              vulnerable_params=[0], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="URL with concatenation"),
    TaintSink("httpclient_execute", r"httpClient\.execute\s*\(\s*new\s+Http\w+\s*\([^)]*\+", "java", None,
              vulnerable_params=[0], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="HttpClient with user URL"),
    TaintSink("resttemplate", r"restTemplate\.(?:getForObject|postForObject|exchange)\s*\([^)]*\+", "java", "spring",
              vulnerable_params=[0], vulnerability_type="SSRF", cwe="CWE-918",
              severity=Severity.HIGH,
              description="RestTemplate with concatenation"),

    # Deserialization Sinks
    TaintSink("objectinputstream", r"new\s+ObjectInputStream\s*\(", "java", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.CRITICAL,
              description="ObjectInputStream deserialization - RCE risk"),
    TaintSink("xmldecoder", r"new\s+XMLDecoder\s*\(", "java", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.CRITICAL,
              description="XMLDecoder deserialization - RCE risk"),
    TaintSink("jackson_readvalue", r"objectMapper\.readValue\s*\([^,]+,\s*Object\.class", "java", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.HIGH,
              description="Jackson deserialization to Object"),
    TaintSink("xstream_fromxml", r"xStream\.fromXML\s*\(", "java", None,
              vulnerable_params=[0], vulnerability_type="Insecure Deserialization", cwe="CWE-502",
              severity=Severity.CRITICAL,
              description="XStream deserialization - RCE risk"),

    # XXE Sinks
    TaintSink("documentbuilder_parse", r"documentBuilder\.parse\s*\(", "java", None,
              vulnerable_params=[0], vulnerability_type="XXE", cwe="CWE-611",
              severity=Severity.HIGH,
              description="XML parsing without disabling external entities"),
    TaintSink("saxparser_parse", r"saxParser\.parse\s*\(", "java", None,
              vulnerable_params=[0], vulnerability_type="XXE", cwe="CWE-611",
              severity=Severity.HIGH,
              description="SAX parsing without disabling external entities"),
    TaintSink("xmlinputfactory", r"XMLInputFactory\.newInstance\s*\(\s*\)\.createXML", "java", None,
              vulnerable_params=[0], vulnerability_type="XXE", cwe="CWE-611",
              severity=Severity.HIGH,
              description="StAX parsing without disabling external entities"),

    # LDAP Injection
    TaintSink("ldap_search", r"(?:dirContext|ctx)\.search\s*\([^)]*\+", "java", None,
              vulnerable_params=[1], vulnerability_type="LDAP Injection", cwe="CWE-90",
              severity=Severity.HIGH,
              description="LDAP search with concatenation"),

    # Expression Language Injection
    TaintSink("expression_language", r"(?:expressionFactory|elProcessor)\.eval\s*\([^)]*\+", "java", None,
              vulnerable_params=[0], vulnerability_type="Expression Language Injection", cwe="CWE-917",
              severity=Severity.CRITICAL,
              description="EL injection - RCE risk"),
    TaintSink("spel_parse", r"spelExpressionParser\.parseExpression\s*\([^)]*\+", "java", "spring",
              vulnerable_params=[0], vulnerability_type="SpEL Injection", cwe="CWE-917",
              severity=Severity.CRITICAL,
              description="Spring Expression Language injection"),

    # Open Redirect
    TaintSink("sendredirect", r"response\.sendRedirect\s*\([^)]*\+", "java", "servlet",
              vulnerable_params=[0], vulnerability_type="Open Redirect", cwe="CWE-601",
              severity=Severity.MEDIUM,
              description="Redirect with concatenation"),

    # Weak Crypto
    TaintSink("md5_digest", r"MessageDigest\.getInstance\s*\(\s*['\"]MD5['\"]", "java", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.MEDIUM, requires_taint=False,
              description="MD5 is cryptographically broken"),
    TaintSink("sha1_digest", r"MessageDigest\.getInstance\s*\(\s*['\"]SHA-?1['\"]", "java", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.LOW, requires_taint=False,
              description="SHA1 is deprecated"),
    TaintSink("des_cipher", r"Cipher\.getInstance\s*\(\s*['\"]DES", "java", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.HIGH, requires_taint=False,
              description="DES is broken"),
    TaintSink("ecb_mode", r"Cipher\.getInstance\s*\(\s*['\"][^'\"]+/ECB/", "java", None,
              vulnerable_params=[], vulnerability_type="Weak Cryptography", cwe="CWE-327",
              severity=Severity.MEDIUM, requires_taint=False,
              description="ECB mode is insecure"),
]

JAVA_SANITIZERS = [
    Sanitizer("preparedstatement", r"connection\.prepareStatement\s*\(", "java",
              sanitizes=["SQL Injection"], description="Prepared statement"),
    Sanitizer("setstring", r"preparedStatement\.setString\s*\(", "java",
              sanitizes=["SQL Injection"], description="Parameter binding"),
    Sanitizer("esapi_encode", r"ESAPI\.encoder\s*\(\s*\)\.encodeFor", "java",
              sanitizes=["XSS", "SQL Injection", "LDAP Injection"], description="ESAPI encoding"),
    Sanitizer("stringescapeutils", r"StringEscapeUtils\.escape\w+\s*\(", "java",
              sanitizes=["XSS"], description="Apache Commons escaping"),
    Sanitizer("htmlutils_escape", r"HtmlUtils\.htmlEscape\s*\(", "java", "spring",
              sanitizes=["XSS"], description="Spring HTML escaping"),
    Sanitizer("file_canonicalpath", r"\.getCanonicalPath\s*\(", "java",
              sanitizes=["Path Traversal"], description="Canonical path resolution"),
    Sanitizer("paths_normalize", r"\.normalize\s*\(", "java",
              sanitizes=["Path Traversal"], description="Path normalization"),
    Sanitizer("url_validation", r"new\s+URL\s*\([^)]+\)\.getHost\s*\(\s*\)\.(?:equals|endsWith)", "java",
              sanitizes=["SSRF"], description="URL host validation"),
    Sanitizer("dbf_secure", r"DocumentBuilderFactory[^;]+setFeature\s*\([^)]*http://apache\.org/xml/features/disallow-doctype-decl", "java",
              sanitizes=["XXE"], description="Disable DOCTYPE"),
    Sanitizer("objectinputfilter", r"ObjectInputFilter", "java",
              sanitizes=["Insecure Deserialization"], description="Deserialization filtering"),
]


# =============================================================================
# INTER-PROCEDURAL ANALYSIS PATTERNS
# =============================================================================

@dataclass
class InterproceduralPattern:
    """Pattern for tracking data flow across function boundaries"""
    name: str
    language: str
    source_pattern: str  # Pattern that introduces taint
    propagation_pattern: str  # Pattern that passes taint through
    sink_pattern: str  # Pattern where taint is dangerous
    vulnerability_type: str
    cwe: str
    severity: Severity
    description: str
    call_depth: int = 3  # How many function calls to track


INTERPROCEDURAL_PATTERNS = [
    # Python: Request -> Helper Function -> SQL
    InterproceduralPattern(
        name="python_request_to_sql_via_helper",
        language="python",
        source_pattern=r"request\.(args|form|data|json|GET|POST)\.",
        propagation_pattern=r"def\s+\w+\s*\([^)]*\w+[^)]*\):",
        sink_pattern=r"\.execute\s*\(",
        vulnerability_type="SQL Injection",
        cwe="CWE-89",
        severity=Severity.CRITICAL,
        description="Request data flows through helper function to SQL execution"
    ),

    # JavaScript: req.body -> sanitize? -> database
    InterproceduralPattern(
        name="js_body_to_nosql_via_function",
        language="javascript",
        source_pattern=r"req\.(body|query|params)\.",
        propagation_pattern=r"(?:function\s+\w+|const\s+\w+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)",
        sink_pattern=r"\.(?:find|findOne|update|delete)\s*\(",
        vulnerability_type="NoSQL Injection",
        cwe="CWE-943",
        severity=Severity.HIGH,
        description="Request data flows through function to MongoDB query"
    ),

    # Go: HTTP handler -> helper -> exec
    InterproceduralPattern(
        name="go_http_to_command_via_helper",
        language="go",
        source_pattern=r"r\.(?:Form|URL\.Query|Header|Body)\.",
        propagation_pattern=r"func\s+\w+\s*\([^)]+\)",
        sink_pattern=r"exec\.Command\s*\(",
        vulnerability_type="Command Injection",
        cwe="CWE-78",
        severity=Severity.CRITICAL,
        description="HTTP request data flows through function to command execution"
    ),

    # PHP: $_GET -> process function -> query
    InterproceduralPattern(
        name="php_get_to_sql_via_function",
        language="php",
        source_pattern=r"\$_(?:GET|POST|REQUEST)\[",
        propagation_pattern=r"function\s+\w+\s*\([^)]*\$",
        sink_pattern=r"(?:mysql_query|mysqli_query|\$\w+->query)\s*\(",
        vulnerability_type="SQL Injection",
        cwe="CWE-89",
        severity=Severity.CRITICAL,
        description="Superglobal flows through function to SQL query"
    ),

    # C#: Request -> Service -> Database
    InterproceduralPattern(
        name="csharp_request_to_sql_via_service",
        language="csharp",
        source_pattern=r"Request\.(?:Query|Form|Body|Headers)\[",
        propagation_pattern=r"(?:public|private|internal)\s+(?:async\s+)?\w+\s+\w+\s*\([^)]*\)",
        sink_pattern=r"\.(?:ExecuteReader|ExecuteNonQuery|FromSqlRaw)\s*\(",
        vulnerability_type="SQL Injection",
        cwe="CWE-89",
        severity=Severity.CRITICAL,
        description="Request data flows through service method to SQL execution"
    ),

    # Java: HttpServletRequest -> DAO -> JDBC
    InterproceduralPattern(
        name="java_request_to_jdbc_via_dao",
        language="java",
        source_pattern=r"request\.getParameter\s*\(",
        propagation_pattern=r"(?:public|private|protected)\s+\w+\s+\w+\s*\([^)]*\)",
        sink_pattern=r"\.(?:executeQuery|executeUpdate|execute)\s*\(",
        vulnerability_type="SQL Injection",
        cwe="CWE-89",
        severity=Severity.CRITICAL,
        description="Servlet request flows through DAO to JDBC execution"
    ),
]


# =============================================================================
# FRAMEWORK-SPECIFIC RULES
# =============================================================================

FRAMEWORK_RULES = {
    "django": {
        "security_headers": {
            "pattern": r"SECURE_(?:BROWSER_XSS_FILTER|CONTENT_TYPE_NOSNIFF|SSL_REDIRECT)\s*=\s*False",
            "cwe": "CWE-16",
            "severity": Severity.MEDIUM,
            "description": "Django security header disabled"
        },
        "debug_mode": {
            "pattern": r"DEBUG\s*=\s*True",
            "cwe": "CWE-489",
            "severity": Severity.HIGH,
            "description": "Django debug mode enabled in production"
        },
        "csrf_exempt": {
            "pattern": r"@csrf_exempt",
            "cwe": "CWE-352",
            "severity": Severity.HIGH,
            "description": "CSRF protection disabled"
        },
        "unsafe_redirect": {
            "pattern": r"HttpResponseRedirect\s*\(\s*request\.",
            "cwe": "CWE-601",
            "severity": Severity.MEDIUM,
            "description": "Redirect with unvalidated request data"
        },
    },
    "flask": {
        "debug_mode": {
            "pattern": r"app\.run\s*\([^)]*debug\s*=\s*True",
            "cwe": "CWE-489",
            "severity": Severity.HIGH,
            "description": "Flask debug mode enabled"
        },
        "secret_key_hardcoded": {
            "pattern": r"(?:SECRET_KEY|secret_key)\s*=\s*['\"][^'\"]{8,}['\"]",
            "cwe": "CWE-798",
            "severity": Severity.HIGH,
            "description": "Flask secret key hardcoded"
        },
    },
    "express": {
        "helmet_missing": {
            "pattern": r"app\.use\s*\(\s*(?!.*helmet)",
            "cwe": "CWE-16",
            "severity": Severity.MEDIUM,
            "description": "Helmet security middleware not detected"
        },
        "cors_wildcard": {
            "pattern": r"cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]?\*['\"]?",
            "cwe": "CWE-942",
            "severity": Severity.MEDIUM,
            "description": "CORS allows all origins"
        },
    },
    "spring": {
        "csrf_disabled": {
            "pattern": r"\.csrf\s*\(\s*\)\s*\.disable\s*\(",
            "cwe": "CWE-352",
            "severity": Severity.HIGH,
            "description": "Spring Security CSRF disabled"
        },
        "permit_all": {
            "pattern": r"\.permitAll\s*\(\s*\)",
            "cwe": "CWE-862",
            "severity": Severity.MEDIUM,
            "description": "Endpoint allows unauthenticated access"
        },
    },
    "laravel": {
        "debug_mode": {
            "pattern": r"APP_DEBUG\s*=\s*true",
            "cwe": "CWE-489",
            "severity": Severity.HIGH,
            "description": "Laravel debug mode enabled"
        },
        "mass_assignment": {
            "pattern": r"\$guarded\s*=\s*\[\s*\]",
            "cwe": "CWE-915",
            "severity": Severity.HIGH,
            "description": "Laravel mass assignment unprotected"
        },
    },
    "aspnet": {
        "custom_errors_off": {
            "pattern": r"<customErrors\s+mode\s*=\s*['\"]Off['\"]",
            "cwe": "CWE-209",
            "severity": Severity.MEDIUM,
            "description": "ASP.NET custom errors disabled"
        },
        "request_validation_off": {
            "pattern": r"validateRequest\s*=\s*['\"]false['\"]",
            "cwe": "CWE-79",
            "severity": Severity.HIGH,
            "description": "ASP.NET request validation disabled"
        },
    },
    "gin": {
        "debug_mode": {
            "pattern": r"gin\.SetMode\s*\(\s*gin\.DebugMode\s*\)",
            "cwe": "CWE-489",
            "severity": Severity.MEDIUM,
            "description": "Gin debug mode enabled"
        },
    },
}


# =============================================================================
# RULE ENGINE
# =============================================================================

class ComprehensiveSASTEngine:
    """
    Comprehensive SAST Engine with inter-procedural analysis support
    """

    def __init__(self):
        self.sources = {
            "python": PYTHON_TAINT_SOURCES,
            "javascript": JS_TAINT_SOURCES,
            "typescript": JS_TAINT_SOURCES,
            "go": GO_TAINT_SOURCES,
            "php": PHP_TAINT_SOURCES,
            "csharp": CSHARP_TAINT_SOURCES,
            "java": JAVA_TAINT_SOURCES,
        }

        self.sinks = {
            "python": PYTHON_TAINT_SINKS,
            "javascript": JS_TAINT_SINKS,
            "typescript": JS_TAINT_SINKS,
            "go": GO_TAINT_SINKS,
            "php": PHP_TAINT_SINKS,
            "csharp": CSHARP_TAINT_SINKS,
            "java": JAVA_TAINT_SINKS,
        }

        self.sanitizers = {
            "python": PYTHON_SANITIZERS,
            "javascript": JS_SANITIZERS,
            "typescript": JS_SANITIZERS,
            "go": GO_SANITIZERS,
            "php": PHP_SANITIZERS,
            "csharp": CSHARP_SANITIZERS,
            "java": JAVA_SANITIZERS,
        }

        self.interprocedural_patterns = INTERPROCEDURAL_PATTERNS
        self.framework_rules = FRAMEWORK_RULES

    def get_sources_for_language(self, language: str) -> List[TaintSource]:
        """Get all taint sources for a language"""
        return self.sources.get(language.lower(), [])

    def get_sinks_for_language(self, language: str) -> List[TaintSink]:
        """Get all taint sinks for a language"""
        return self.sinks.get(language.lower(), [])

    def get_sanitizers_for_language(self, language: str) -> List[Sanitizer]:
        """Get all sanitizers for a language"""
        return self.sanitizers.get(language.lower(), [])

    def get_framework_rules(self, framework: str) -> Dict[str, Any]:
        """Get framework-specific rules"""
        return self.framework_rules.get(framework.lower(), {})

    def get_interprocedural_patterns(self, language: str) -> List[InterproceduralPattern]:
        """Get inter-procedural patterns for a language"""
        return [p for p in self.interprocedural_patterns if p.language == language.lower()]

    def check_line_for_source(self, line: str, language: str) -> List[TaintSource]:
        """Check if a line contains any taint sources"""
        sources = self.get_sources_for_language(language)
        found = []
        for source in sources:
            if re.search(source.pattern, line, re.IGNORECASE):
                found.append(source)
        return found

    def check_line_for_sink(self, line: str, language: str) -> List[TaintSink]:
        """Check if a line contains any taint sinks"""
        sinks = self.get_sinks_for_language(language)
        found = []
        for sink in sinks:
            if re.search(sink.pattern, line, re.IGNORECASE):
                found.append(sink)
        return found

    def check_line_for_sanitizer(self, line: str, language: str) -> List[Sanitizer]:
        """Check if a line contains any sanitizers"""
        sanitizers = self.get_sanitizers_for_language(language)
        found = []
        for sanitizer in sanitizers:
            if re.search(sanitizer.pattern, line, re.IGNORECASE):
                found.append(sanitizer)
        return found

    def is_line_sanitized(self, line: str, context_lines: List[str],
                          language: str, vulnerability_type: str) -> bool:
        """Check if a line is protected by a sanitizer"""
        sanitizers = self.get_sanitizers_for_language(language)

        # Check current line
        for sanitizer in sanitizers:
            if vulnerability_type in sanitizer.sanitizes:
                if re.search(sanitizer.pattern, line, re.IGNORECASE):
                    return True

        # Check surrounding context (previous 5 lines)
        for context_line in context_lines[-5:]:
            for sanitizer in sanitizers:
                if vulnerability_type in sanitizer.sanitizes:
                    if re.search(sanitizer.pattern, context_line, re.IGNORECASE):
                        return True

        return False

    def analyze_file(self, content: str, file_path: str,
                     language: str) -> List[Dict[str, Any]]:
        """
        Analyze a file for security vulnerabilities using comprehensive rules
        """
        findings = []
        lines = content.split('\n')

        # Track tainted variables for inter-procedural analysis
        tainted_vars: Set[str] = set()

        # Track function definitions for call analysis
        function_defs: Dict[str, int] = {}

        for line_num, line in enumerate(lines, 1):
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or self._is_comment(stripped, language):
                continue

            # Check for taint sources
            sources = self.check_line_for_source(line, language)
            for source in sources:
                # Extract variable assignment if any
                var_match = re.match(r'(\w+)\s*=', line)
                if var_match:
                    tainted_vars.add(var_match.group(1))

            # Check for sinks
            sinks = self.check_line_for_sink(line, language)
            for sink in sinks:
                # Check if line uses tainted data
                has_taint = sink.requires_taint and self._line_uses_tainted_data(
                    line, tainted_vars, sources
                )

                # Check for sanitization
                context = lines[max(0, line_num - 6):line_num]
                is_sanitized = self.is_line_sanitized(
                    line, context, language, sink.vulnerability_type
                )

                if (not sink.requires_taint) or (has_taint and not is_sanitized):
                    findings.append({
                        "type": sink.vulnerability_type,
                        "severity": sink.severity.value,
                        "cwe": sink.cwe,
                        "line_number": line_num,
                        "line_content": line.strip(),
                        "file_path": file_path,
                        "description": sink.description,
                        "confidence": "high" if has_taint else "medium",
                        "sink_name": sink.name,
                        "is_tainted": has_taint,
                        "is_sanitized": is_sanitized,
                    })

        # Check framework-specific rules
        framework = self._detect_framework(content, language)
        if framework:
            framework_findings = self._check_framework_rules(
                content, file_path, framework
            )
            findings.extend(framework_findings)

        return findings

    def _is_comment(self, line: str, language: str) -> bool:
        """Check if line is a comment"""
        comment_prefixes = {
            'python': ['#'],
            'javascript': ['//', '/*'],
            'typescript': ['//', '/*'],
            'go': ['//', '/*'],
            'php': ['//', '#', '/*'],
            'csharp': ['//', '/*'],
            'java': ['//', '/*'],
        }
        prefixes = comment_prefixes.get(language.lower(), ['#', '//'])
        return any(line.startswith(p) for p in prefixes)

    def _line_uses_tainted_data(self, line: str, tainted_vars: Set[str],
                                 sources: List[TaintSource]) -> bool:
        """Check if a line uses tainted data"""
        # Direct source usage
        if sources:
            return True

        # Tainted variable usage
        for var in tainted_vars:
            if re.search(rf'\b{re.escape(var)}\b', line):
                return True

        return False

    def _detect_framework(self, content: str, language: str) -> Optional[str]:
        """Detect the framework being used"""
        framework_patterns = {
            'django': r'from\s+django|import\s+django',
            'flask': r'from\s+flask|import\s+flask',
            'fastapi': r'from\s+fastapi|import\s+fastapi',
            'express': r"require\s*\(\s*['\"]express['\"]|from\s+['\"]express['\"]",
            'react': r"from\s+['\"]react['\"]|import\s+React",
            'spring': r'import\s+org\.springframework|@SpringBootApplication',
            'laravel': r'use\s+Illuminate|Laravel',
            'symfony': r'use\s+Symfony',
            'gin': r'import\s+["\"]github\.com/gin-gonic/gin["\"]',
            'echo': r'import\s+["\"]github\.com/labstack/echo["\"]',
            'aspnet': r'using\s+Microsoft\.AspNetCore|using\s+System\.Web\.Mvc',
        }

        for framework, pattern in framework_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                return framework

        return None

    def _check_framework_rules(self, content: str, file_path: str,
                                framework: str) -> List[Dict[str, Any]]:
        """Check framework-specific security rules"""
        findings = []
        rules = self.get_framework_rules(framework)

        for rule_name, rule in rules.items():
            matches = list(re.finditer(rule['pattern'], content, re.IGNORECASE | re.MULTILINE))
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    "type": f"Framework Security ({framework})",
                    "severity": rule['severity'].value,
                    "cwe": rule['cwe'],
                    "line_number": line_num,
                    "line_content": match.group(0).strip(),
                    "file_path": file_path,
                    "description": rule['description'],
                    "confidence": "high",
                    "rule_name": rule_name,
                    "framework": framework,
                })

        return findings


# Export the engine for use in other modules
sast_engine = ComprehensiveSASTEngine()
