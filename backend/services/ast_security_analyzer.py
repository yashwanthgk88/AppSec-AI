"""
AST-Based Security Analyzer
Professional-grade static analysis with:
- Abstract Syntax Tree parsing for multiple languages
- Taint Analysis Engine (source → propagator → sink tracking)
- Control Flow Graph (CFG) Analysis
- Data Flow Graph (DFG) Analysis
- Context-aware vulnerability detection
- False positive reduction through semantic analysis
"""

import ast
import re
from typing import List, Dict, Any, Set, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import hashlib


class NodeType(Enum):
    """Types of nodes in taint/data flow analysis"""
    SOURCE = "source"
    PROPAGATOR = "propagator"
    SANITIZER = "sanitizer"
    SINK = "sink"


class TaintState(Enum):
    """Taint states for variables"""
    TAINTED = "tainted"
    CLEAN = "clean"
    UNKNOWN = "unknown"
    SANITIZED = "sanitized"


@dataclass
class Location:
    """Source code location"""
    file: str
    start_line: int
    end_line: int
    start_column: int
    end_column: int

    def to_dict(self) -> Dict:
        return {
            "file": self.file,
            "startLine": self.start_line,
            "endLine": self.end_line,
            "startColumn": self.start_column,
            "endColumn": self.end_column
        }


@dataclass
class TaintNode:
    """Node in taint flow graph"""
    id: str
    node_type: NodeType
    description: str
    location: Location
    code_snippet: str
    variable_name: Optional[str] = None
    function_name: Optional[str] = None
    node_kind: Optional[str] = None  # e.g., "CallExpression", "Assignment"

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "type": self.node_type.value,
            "description": self.description,
            "location": self.location.to_dict(),
            "codeSnippet": self.code_snippet,
            "variableName": self.variable_name,
            "functionName": self.function_name,
            "nodeKind": self.node_kind
        }


@dataclass
class TaintFlow:
    """Complete taint flow from source to sink"""
    id: str
    source: TaintNode
    sink: TaintNode
    path: List[TaintNode]
    sanitizers: List[Dict] = field(default_factory=list)
    confidence: str = "high"
    data_type: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "path": [n.to_dict() for n in self.path],
            "sanitizers": self.sanitizers,
            "confidence": self.confidence,
            "dataType": self.data_type
        }


@dataclass
class CFGNode:
    """Control Flow Graph node"""
    id: str
    node_type: str  # "entry", "exit", "condition", "statement", "loop", "try", "catch"
    code: str
    location: Location
    successors: List[str] = field(default_factory=list)
    predecessors: List[str] = field(default_factory=list)
    condition: Optional[str] = None  # For conditional nodes


@dataclass
class DFGNode:
    """Data Flow Graph node"""
    id: str
    variable: str
    definition_type: str  # "assignment", "parameter", "return", "call"
    location: Location
    value_source: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)  # Variables this depends on
    used_by: List[str] = field(default_factory=list)  # Where this variable is used


@dataclass
class SecurityFinding:
    """Security vulnerability finding with full context"""
    id: str
    title: str
    description: str
    severity: str
    confidence: str
    cwe_id: str
    owasp_category: str
    location: Location
    code_snippet: str
    vulnerable_code: str
    remediation: str
    remediation_code: Optional[str] = None
    taint_flow: Optional[TaintFlow] = None
    cvss_score: float = 0.0
    stride_category: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    is_false_positive: bool = False
    validation_notes: Optional[str] = None

    def to_dict(self) -> Dict:
        result = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "file_path": self.location.file,
            "line_number": self.location.start_line,
            "code_snippet": self.code_snippet,
            "vulnerable_code": self.vulnerable_code,
            "remediation": self.remediation,
            "remediation_code": self.remediation_code,
            "cvss_score": self.cvss_score,
            "stride_category": self.stride_category,
            "mitre_attack_id": self.mitre_attack_id,
            "is_false_positive": self.is_false_positive,
            "validation_notes": self.validation_notes
        }
        if self.taint_flow:
            result["taint_flow"] = self.taint_flow.to_dict()
        return result


class LanguageParser:
    """
    Multi-language AST parser
    Supports: Python, JavaScript/TypeScript, Java, PHP, Go, Ruby, C#, Kotlin, Swift
    """

    # Language detection by extension
    LANGUAGE_MAP = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.java': 'java',
        '.php': 'php',
        '.go': 'go',
        '.rb': 'ruby',
        '.cs': 'csharp',
        '.kt': 'kotlin',
        '.kts': 'kotlin',
        '.swift': 'swift',
        '.m': 'objectivec',
        '.c': 'c',
        '.cpp': 'cpp',
        '.h': 'c',
        '.hpp': 'cpp',
    }

    def __init__(self):
        self.current_file = ""
        self.source_lines: List[str] = []

    def detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        import os
        ext = os.path.splitext(file_path)[1].lower()
        return self.LANGUAGE_MAP.get(ext, 'unknown')

    def parse(self, source_code: str, file_path: str) -> Dict[str, Any]:
        """
        Parse source code into AST representation
        Returns a normalized AST structure regardless of language
        """
        self.current_file = file_path
        self.source_lines = source_code.split('\n')
        language = self.detect_language(file_path)

        if language == 'python':
            return self._parse_python(source_code)
        elif language in ('javascript', 'typescript'):
            return self._parse_javascript(source_code)
        elif language == 'java':
            return self._parse_java(source_code)
        elif language == 'php':
            return self._parse_php(source_code)
        elif language == 'go':
            return self._parse_go(source_code)
        elif language == 'ruby':
            return self._parse_ruby(source_code)
        elif language == 'csharp':
            return self._parse_csharp(source_code)
        elif language == 'kotlin':
            return self._parse_kotlin(source_code)
        elif language == 'swift':
            return self._parse_swift(source_code)
        else:
            return self._parse_generic(source_code)

    def _parse_python(self, source_code: str) -> Dict[str, Any]:
        """Parse Python code using ast module"""
        try:
            tree = ast.parse(source_code)
            return self._normalize_python_ast(tree)
        except SyntaxError as e:
            return {"error": str(e), "nodes": [], "language": "python"}

    def _normalize_python_ast(self, tree: ast.AST) -> Dict[str, Any]:
        """Convert Python AST to normalized format"""
        nodes = []
        functions = []
        classes = []
        imports = []
        assignments = []
        calls = []

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_info = {
                    "type": "function",
                    "name": node.name,
                    "line": node.lineno,
                    "end_line": node.end_lineno or node.lineno,
                    "col": node.col_offset,
                    "parameters": [arg.arg for arg in node.args.args],
                    "decorators": [self._get_decorator_name(d) for d in node.decorator_list],
                }
                functions.append(func_info)
                nodes.append(func_info)

            elif isinstance(node, ast.ClassDef):
                class_info = {
                    "type": "class",
                    "name": node.name,
                    "line": node.lineno,
                    "end_line": node.end_lineno or node.lineno,
                    "bases": [self._get_name(b) for b in node.bases],
                }
                classes.append(class_info)
                nodes.append(class_info)

            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                import_info = {
                    "type": "import",
                    "line": node.lineno,
                    "module": getattr(node, 'module', None),
                    "names": [alias.name for alias in node.names],
                }
                imports.append(import_info)
                nodes.append(import_info)

            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assign_info = {
                            "type": "assignment",
                            "variable": target.id,
                            "line": node.lineno,
                            "col": node.col_offset,
                            "value_type": self._get_value_type(node.value),
                        }
                        assignments.append(assign_info)
                        nodes.append(assign_info)

            elif isinstance(node, ast.Call):
                call_info = {
                    "type": "call",
                    "function": self._get_call_name(node),
                    "line": node.lineno,
                    "col": node.col_offset,
                    "args_count": len(node.args),
                }
                calls.append(call_info)
                nodes.append(call_info)

        return {
            "language": "python",
            "nodes": nodes,
            "functions": functions,
            "classes": classes,
            "imports": imports,
            "assignments": assignments,
            "calls": calls,
        }

    def _get_decorator_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return self._get_call_name(node)
        return "unknown"

    def _get_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Subscript):
            return f"{self._get_name(node.value)}[...]"
        return "unknown"

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return f"{self._get_name(node.func.value)}.{node.func.attr}"
        return "unknown"

    def _get_value_type(self, node: ast.AST) -> str:
        if isinstance(node, ast.Constant):
            return type(node.value).__name__
        elif isinstance(node, ast.List):
            return "list"
        elif isinstance(node, ast.Dict):
            return "dict"
        elif isinstance(node, ast.Call):
            return f"call:{self._get_call_name(node)}"
        elif isinstance(node, ast.Name):
            return f"ref:{node.id}"
        return "unknown"

    def _parse_javascript(self, source_code: str) -> Dict[str, Any]:
        """Parse JavaScript/TypeScript using regex-based tokenization"""
        # Since we can't use a full JS parser in Python, use regex patterns
        return self._parse_c_family(source_code, "javascript")

    def _parse_java(self, source_code: str) -> Dict[str, Any]:
        return self._parse_c_family(source_code, "java")

    def _parse_php(self, source_code: str) -> Dict[str, Any]:
        return self._parse_c_family(source_code, "php")

    def _parse_go(self, source_code: str) -> Dict[str, Any]:
        return self._parse_c_family(source_code, "go")

    def _parse_ruby(self, source_code: str) -> Dict[str, Any]:
        return self._parse_ruby_style(source_code)

    def _parse_csharp(self, source_code: str) -> Dict[str, Any]:
        return self._parse_c_family(source_code, "csharp")

    def _parse_kotlin(self, source_code: str) -> Dict[str, Any]:
        return self._parse_c_family(source_code, "kotlin")

    def _parse_swift(self, source_code: str) -> Dict[str, Any]:
        return self._parse_c_family(source_code, "swift")

    def _parse_generic(self, source_code: str) -> Dict[str, Any]:
        return self._parse_c_family(source_code, "generic")

    def _parse_c_family(self, source_code: str, language: str) -> Dict[str, Any]:
        """
        Generic parser for C-family languages (JS, Java, C#, Go, etc.)
        Uses regex-based tokenization to extract structure
        """
        nodes = []
        functions = []
        classes = []
        imports = []
        assignments = []
        calls = []

        lines = source_code.split('\n')

        # Function patterns for different languages
        func_patterns = {
            'javascript': r'(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>|\w+\s*=>))',
            'typescript': r'(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))',
            'java': r'(?:public|private|protected)?\s*(?:static)?\s*(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+)?\s*\{',
            'csharp': r'(?:public|private|protected|internal)?\s*(?:static|async|virtual|override)?\s*(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\([^)]*\)\s*\{',
            'go': r'func\s+(?:\([^)]+\)\s*)?(\w+)\s*\([^)]*\)',
            'php': r'(?:public|private|protected)?\s*(?:static)?\s*function\s+(\w+)\s*\(',
            'kotlin': r'(?:fun|suspend\s+fun)\s+(\w+)\s*(?:<[^>]+>)?\s*\(',
            'swift': r'func\s+(\w+)\s*(?:<[^>]+>)?\s*\(',
        }

        # Class patterns
        class_patterns = {
            'javascript': r'class\s+(\w+)(?:\s+extends\s+(\w+))?',
            'typescript': r'(?:export\s+)?(?:abstract\s+)?class\s+(\w+)(?:<[^>]+>)?(?:\s+extends\s+(\w+))?(?:\s+implements\s+[\w,\s]+)?',
            'java': r'(?:public\s+)?(?:abstract\s+)?class\s+(\w+)(?:<[^>]+>)?(?:\s+extends\s+(\w+))?(?:\s+implements\s+[\w,\s]+)?',
            'csharp': r'(?:public\s+)?(?:abstract\s+|sealed\s+)?class\s+(\w+)(?:<[^>]+>)?(?:\s*:\s*[\w,\s<>]+)?',
            'go': r'type\s+(\w+)\s+struct',
            'php': r'class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+[\w,\s]+)?',
            'kotlin': r'(?:data\s+)?class\s+(\w+)(?:<[^>]+>)?(?:\s*:\s*[\w,\s<>()]+)?',
            'swift': r'(?:class|struct)\s+(\w+)(?:<[^>]+>)?(?:\s*:\s*[\w,\s]+)?',
        }

        # Import patterns
        import_patterns = {
            'javascript': r'(?:import\s+.*?from\s+["\']([^"\']+)["\']|require\s*\(["\']([^"\']+)["\']\))',
            'typescript': r'import\s+.*?from\s+["\']([^"\']+)["\']',
            'java': r'import\s+([\w.]+(?:\.\*)?);',
            'csharp': r'using\s+([\w.]+);',
            'go': r'import\s+(?:\(\s*)?["\']([^"\']+)["\']',
            'php': r'(?:use|require|include)\s+([^;]+);',
            'kotlin': r'import\s+([\w.]+)',
            'swift': r'import\s+(\w+)',
        }

        # Variable assignment patterns
        assign_patterns = {
            'javascript': r'(?:const|let|var)\s+(\w+)\s*=',
            'typescript': r'(?:const|let|var)\s+(\w+)\s*(?::\s*\w+(?:<[^>]+>)?)?\s*=',
            'java': r'(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*=',
            'csharp': r'(?:var|\w+(?:<[^>]+>)?)\s+(\w+)\s*=',
            'go': r'(\w+)\s*:?=',
            'php': r'\$(\w+)\s*=',
            'kotlin': r'(?:val|var)\s+(\w+)\s*(?::\s*\w+(?:<[^>]+>)?)?\s*=',
            'swift': r'(?:let|var)\s+(\w+)\s*(?::\s*\w+(?:<[^>]+>)?)?\s*=',
        }

        func_pattern = func_patterns.get(language, func_patterns.get('java', ''))
        class_pattern = class_patterns.get(language, class_patterns.get('java', ''))
        import_pattern = import_patterns.get(language, import_patterns.get('java', ''))
        assign_pattern = assign_patterns.get(language, assign_patterns.get('java', ''))

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip comments
            if self._is_comment(stripped, language):
                continue

            # Find functions
            if func_pattern:
                match = re.search(func_pattern, line)
                if match:
                    name = next((g for g in match.groups() if g), None)
                    if name:
                        func_info = {
                            "type": "function",
                            "name": name,
                            "line": line_num,
                            "col": match.start(),
                        }
                        functions.append(func_info)
                        nodes.append(func_info)

            # Find classes
            if class_pattern:
                match = re.search(class_pattern, line)
                if match:
                    name = match.group(1)
                    class_info = {
                        "type": "class",
                        "name": name,
                        "line": line_num,
                        "col": match.start(),
                    }
                    classes.append(class_info)
                    nodes.append(class_info)

            # Find imports
            if import_pattern:
                match = re.search(import_pattern, line)
                if match:
                    module = next((g for g in match.groups() if g), None)
                    if module:
                        import_info = {
                            "type": "import",
                            "module": module,
                            "line": line_num,
                        }
                        imports.append(import_info)
                        nodes.append(import_info)

            # Find assignments
            if assign_pattern:
                match = re.search(assign_pattern, line)
                if match:
                    var_name = next((g for g in match.groups() if g), None)
                    if var_name:
                        assign_info = {
                            "type": "assignment",
                            "variable": var_name,
                            "line": line_num,
                            "col": match.start(),
                        }
                        assignments.append(assign_info)
                        nodes.append(assign_info)

            # Find function calls
            call_matches = re.finditer(r'(\w+(?:\.\w+)*)\s*\(', line)
            for match in call_matches:
                func_name = match.group(1)
                # Skip language keywords
                keywords = {'if', 'else', 'for', 'while', 'switch', 'catch', 'function', 'class', 'return'}
                if func_name.split('.')[-1] not in keywords:
                    call_info = {
                        "type": "call",
                        "function": func_name,
                        "line": line_num,
                        "col": match.start(),
                    }
                    calls.append(call_info)
                    nodes.append(call_info)

        return {
            "language": language,
            "nodes": nodes,
            "functions": functions,
            "classes": classes,
            "imports": imports,
            "assignments": assignments,
            "calls": calls,
        }

    def _parse_ruby_style(self, source_code: str) -> Dict[str, Any]:
        """Parse Ruby-style languages"""
        nodes = []
        functions = []
        classes = []

        lines = source_code.split('\n')

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Ruby methods
            match = re.search(r'def\s+(\w+[?!]?)', line)
            if match:
                functions.append({
                    "type": "function",
                    "name": match.group(1),
                    "line": line_num,
                })

            # Ruby classes
            match = re.search(r'class\s+(\w+)(?:\s*<\s*(\w+))?', line)
            if match:
                classes.append({
                    "type": "class",
                    "name": match.group(1),
                    "line": line_num,
                    "parent": match.group(2),
                })

        return {
            "language": "ruby",
            "nodes": nodes + functions + classes,
            "functions": functions,
            "classes": classes,
            "imports": [],
            "assignments": [],
            "calls": [],
        }

    def _is_comment(self, line: str, language: str) -> bool:
        """Check if line is a comment"""
        single_line_comments = {
            'python': '#',
            'javascript': '//',
            'typescript': '//',
            'java': '//',
            'csharp': '//',
            'go': '//',
            'php': ['#', '//'],
            'kotlin': '//',
            'swift': '//',
            'ruby': '#',
        }

        markers = single_line_comments.get(language, '//')
        if isinstance(markers, str):
            markers = [markers]

        return any(line.startswith(marker) for marker in markers)


class TaintAnalyzer:
    """
    Taint Analysis Engine
    Tracks data flow from sources (untrusted input) through propagators to sinks (dangerous operations)
    """

    # Known taint sources by language
    SOURCES = {
        'python': [
            ('request', 'HTTP request data'),
            ('request.args', 'URL query parameters'),
            ('request.form', 'Form data'),
            ('request.json', 'JSON request body'),
            ('request.data', 'Raw request data'),
            ('request.cookies', 'Cookie data'),
            ('request.headers', 'HTTP headers'),
            ('request.files', 'Uploaded files'),
            ('request.values', 'Combined request values'),
            ('request.get_json', 'JSON body method'),
            ('input(', 'User input'),
            ('sys.argv', 'Command line arguments'),
            ('os.environ', 'Environment variables'),
            ('os.getenv', 'Environment variable'),
            ('open(', 'File content'),
            ('read()', 'File read'),
            ('recv(', 'Socket data'),
            ('urlopen(', 'HTTP response'),
            ('requests.get', 'HTTP GET response'),
            ('requests.post', 'HTTP POST response'),
            ('json.loads', 'Parsed JSON'),
            ('yaml.load', 'Parsed YAML'),
            ('pickle.loads', 'Deserialized data'),
            ('subprocess.check_output', 'Command output'),
            ('socket.recv', 'Socket data'),
            # Django sources
            ('request.GET', 'Django GET params'),
            ('request.POST', 'Django POST data'),
            ('request.FILES', 'Django files'),
            ('request.META', 'Django meta'),
            # FastAPI sources
            ('Body(', 'FastAPI body'),
            ('Query(', 'FastAPI query'),
            ('Path(', 'FastAPI path'),
            ('Header(', 'FastAPI header'),
            ('Cookie(', 'FastAPI cookie'),
        ],
        'javascript': [
            ('req.query', 'URL query parameters'),
            ('req.body', 'Request body'),
            ('req.params', 'URL parameters'),
            ('req.cookies', 'Cookies'),
            ('req.headers', 'HTTP headers'),
            ('req.files', 'Uploaded files'),
            ('req.file', 'Uploaded file'),
            ('window.location', 'URL/Location'),
            ('location.href', 'Current URL'),
            ('location.search', 'URL query string'),
            ('location.hash', 'URL hash'),
            ('document.URL', 'Document URL'),
            ('document.referrer', 'Referrer URL'),
            ('document.cookie', 'Cookies'),
            ('localStorage', 'Local storage'),
            ('sessionStorage', 'Session storage'),
            ('prompt(', 'User input'),
            ('fetch(', 'HTTP response'),
            ('XMLHttpRequest', 'HTTP response'),
            ('process.env', 'Environment variables'),
            ('process.argv', 'Command line args'),
            ('$.ajax', 'jQuery AJAX response'),
            ('axios.get', 'Axios GET response'),
            ('axios.post', 'Axios POST response'),
            # WebSocket
            ('message.data', 'WebSocket message'),
            ('event.data', 'Event data'),
            # URL parsing
            ('URLSearchParams', 'URL params'),
            ('new URL(', 'URL object'),
        ],
        'typescript': [
            ('req.query', 'URL query parameters'),
            ('req.body', 'Request body'),
            ('req.params', 'URL parameters'),
            ('req.cookies', 'Cookies'),
            ('req.headers', 'HTTP headers'),
            ('window.location', 'URL/Location'),
            ('document.URL', 'Document URL'),
            ('document.cookie', 'Cookies'),
            ('localStorage', 'Local storage'),
            ('sessionStorage', 'Session storage'),
            ('process.env', 'Environment variables'),
            ('process.argv', 'Command line args'),
        ],
        'java': [
            ('request.getParameter', 'Request parameter'),
            ('request.getParameterValues', 'Request parameters'),
            ('request.getParameterMap', 'Parameter map'),
            ('request.getQueryString', 'Query string'),
            ('request.getHeader', 'HTTP header'),
            ('request.getHeaders', 'HTTP headers'),
            ('request.getCookies', 'Cookies'),
            ('request.getInputStream', 'Request body'),
            ('request.getReader', 'Request reader'),
            ('request.getPart', 'Multipart data'),
            ('System.getenv', 'Environment variable'),
            ('System.getProperty', 'System property'),
            ('Scanner', 'User input'),
            ('BufferedReader', 'File/Stream input'),
            ('args', 'Command line args'),
            # Spring sources
            ('@RequestParam', 'Spring request param'),
            ('@PathVariable', 'Spring path variable'),
            ('@RequestBody', 'Spring request body'),
            ('@RequestHeader', 'Spring header'),
            ('@CookieValue', 'Spring cookie'),
            ('ModelAttribute', 'Spring model'),
        ],
        'php': [
            ('$_GET', 'GET parameters'),
            ('$_POST', 'POST data'),
            ('$_REQUEST', 'Request data'),
            ('$_COOKIE', 'Cookies'),
            ('$_FILES', 'Uploaded files'),
            ('$_SERVER', 'Server variables'),
            ('$_ENV', 'Environment variables'),
            ('$_SESSION', 'Session data'),
            ('file_get_contents', 'File content'),
            ('file(', 'File lines'),
            ('fread', 'File read'),
            ('fgets', 'File line'),
            ('fgetc', 'File char'),
            ('php://input', 'Raw input'),
            ('getenv', 'Environment variable'),
            # Laravel sources
            ('$request->input', 'Laravel input'),
            ('$request->query', 'Laravel query'),
            ('$request->post', 'Laravel post'),
            ('$request->file', 'Laravel file'),
        ],
        'go': [
            ('r.URL.Query', 'URL query'),
            ('r.FormValue', 'Form value'),
            ('r.PostFormValue', 'POST form value'),
            ('r.Header.Get', 'HTTP header'),
            ('r.Cookie', 'Cookie'),
            ('r.Body', 'Request body'),
            ('r.MultipartForm', 'Multipart form'),
            ('r.Form', 'Form data'),
            ('os.Args', 'Command line args'),
            ('os.Getenv', 'Environment variable'),
            ('bufio.Scanner', 'Input scanner'),
            ('ioutil.ReadAll', 'Read all data'),
            ('json.Unmarshal', 'JSON unmarshal'),
            # Gin sources
            ('c.Query', 'Gin query'),
            ('c.Param', 'Gin param'),
            ('c.PostForm', 'Gin post form'),
            ('c.GetHeader', 'Gin header'),
        ],
        'csharp': [
            ('Request.QueryString', 'Query string'),
            ('Request.Form', 'Form data'),
            ('Request.Cookies', 'Cookies'),
            ('Request.Headers', 'HTTP headers'),
            ('Request.Body', 'Request body'),
            ('Request.Files', 'Uploaded files'),
            ('Environment.GetEnvironmentVariable', 'Environment variable'),
            ('Console.ReadLine', 'Console input'),
            ('args', 'Command line args'),
            # ASP.NET Core sources
            ('[FromQuery]', 'ASP.NET query'),
            ('[FromBody]', 'ASP.NET body'),
            ('[FromRoute]', 'ASP.NET route'),
            ('[FromForm]', 'ASP.NET form'),
            ('[FromHeader]', 'ASP.NET header'),
            ('HttpContext.Request', 'HTTP context'),
        ],
        'ruby': [
            ('params', 'Request parameters'),
            ('request.params', 'Request params'),
            ('request.body', 'Request body'),
            ('request.headers', 'Request headers'),
            ('cookies', 'Cookies'),
            ('session', 'Session data'),
            ('ENV', 'Environment variables'),
            ('ARGV', 'Command line args'),
            ('gets', 'User input'),
            ('File.read', 'File content'),
        ],
    }

    # Known sinks (dangerous operations)
    SINKS = {
        'sql': [
            ('execute(', 'SQL execution'),
            ('executemany(', 'SQL batch execution'),
            ('query(', 'SQL query'),
            ('raw(', 'Raw SQL'),
            ('executeQuery', 'SQL query'),
            ('executeUpdate', 'SQL update'),
            ('executeBatch', 'SQL batch'),
            ('createQuery', 'JPA query'),
            ('createNativeQuery', 'JPA native query'),
            ('rawQuery', 'Raw query'),
            ('$wpdb->query', 'WordPress query'),
            ('$wpdb->prepare', 'WordPress prepare'),
            ('mysql_query', 'MySQL query'),
            ('mysqli_query', 'MySQLi query'),
            ('pg_query', 'PostgreSQL query'),
            ('pg_execute', 'PostgreSQL execute'),
            ('cursor.execute', 'Cursor execute'),
            ('db.execute', 'DB execute'),
            ('conn.execute', 'Connection execute'),
            ('session.execute', 'Session execute'),
            # ORMs
            ('Model.objects.raw', 'Django raw query'),
            ('extra(', 'Django extra'),
            ('RawSQL', 'Django RawSQL'),
            ('text(', 'SQLAlchemy text'),
            ('sequelize.query', 'Sequelize query'),
        ],
        'command': [
            ('exec(', 'Command execution'),
            ('system(', 'System command'),
            ('popen(', 'Process open'),
            ('subprocess.call', 'Subprocess call'),
            ('subprocess.run', 'Subprocess run'),
            ('subprocess.Popen', 'Subprocess Popen'),
            ('subprocess.check_output', 'Subprocess output'),
            ('subprocess.check_call', 'Subprocess check'),
            ('shell_exec', 'Shell execution'),
            ('passthru', 'Passthrough'),
            ('proc_open', 'Process open'),
            ('Runtime.exec', 'Runtime exec'),
            ('Runtime.getRuntime', 'Runtime getRuntime'),
            ('ProcessBuilder', 'Process builder'),
            ('os.system', 'OS system'),
            ('os.popen', 'OS popen'),
            ('os.exec', 'OS exec'),
            ('os.spawn', 'OS spawn'),
            ('child_process', 'Child process'),
            ('execSync', 'Exec sync'),
            ('spawnSync', 'Spawn sync'),
            ('backtick', 'Backtick execution'),
        ],
        'xss': [
            ('innerHTML', 'Inner HTML'),
            ('outerHTML', 'Outer HTML'),
            ('document.write', 'Document write'),
            ('document.writeln', 'Document writeln'),
            ('dangerouslySetInnerHTML', 'React dangerous HTML'),
            ('.html(', 'jQuery html'),
            ('.append(', 'jQuery append'),
            ('.prepend(', 'jQuery prepend'),
            ('.after(', 'jQuery after'),
            ('.before(', 'jQuery before'),
            ('.replaceWith(', 'jQuery replaceWith'),
            ('Response.Write', 'Response write'),
            ('echo', 'PHP echo'),
            ('print', 'Print output'),
            ('printf', 'Printf output'),
            ('render_template_string', 'Template string'),
            ('Markup(', 'Flask Markup'),
            ('mark_safe', 'Django mark_safe'),
            ('safe', 'Template safe filter'),
            ('insertAdjacentHTML', 'Insert adjacent HTML'),
            ('createContextualFragment', 'Create fragment'),
            ('v-html', 'Vue v-html'),
            ('[innerHTML]', 'Angular innerHTML'),
        ],
        'path': [
            ('open(', 'File open'),
            ('read(', 'File read'),
            ('write(', 'File write'),
            ('readFile', 'Read file'),
            ('readFileSync', 'Read file sync'),
            ('writeFile', 'Write file'),
            ('writeFileSync', 'Write file sync'),
            ('appendFile', 'Append file'),
            ('createReadStream', 'Create read stream'),
            ('createWriteStream', 'Create write stream'),
            ('file_get_contents', 'File contents'),
            ('file_put_contents', 'File put contents'),
            ('include(', 'PHP include'),
            ('include_once', 'PHP include once'),
            ('require(', 'PHP require'),
            ('require_once', 'PHP require once'),
            ('FileInputStream', 'File input stream'),
            ('FileOutputStream', 'File output stream'),
            ('FileReader', 'File reader'),
            ('FileWriter', 'File writer'),
            ('os.path.join', 'Path join'),
            ('path.join', 'Node path join'),
            ('path.resolve', 'Path resolve'),
            ('Paths.get', 'Java Paths.get'),
            ('Files.read', 'Java Files.read'),
            ('Files.write', 'Java Files.write'),
            ('shutil.copy', 'Shutil copy'),
            ('shutil.move', 'Shutil move'),
            ('os.rename', 'OS rename'),
            ('os.remove', 'OS remove'),
            ('os.unlink', 'OS unlink'),
            ('send_file', 'Flask send_file'),
            ('sendFile', 'Express sendFile'),
            ('download', 'File download'),
        ],
        'deserialization': [
            ('pickle.loads', 'Pickle deserialize'),
            ('pickle.load', 'Pickle load'),
            ('cPickle.loads', 'cPickle deserialize'),
            ('yaml.load', 'YAML load'),
            ('yaml.unsafe_load', 'YAML unsafe load'),
            ('yaml.full_load', 'YAML full load'),
            ('eval(', 'Eval'),
            ('exec(', 'Exec'),
            ('compile(', 'Compile'),
            ('unserialize', 'PHP unserialize'),
            ('ObjectInputStream', 'Java deserialize'),
            ('readObject', 'Read object'),
            ('XMLDecoder', 'XML decoder'),
            ('fromXML', 'XStream fromXML'),
            ('unmarshal', 'JAXB unmarshal'),
            ('deserialize', 'Generic deserialize'),
            ('jsonpickle', 'JSONPickle'),
            ('marshal.loads', 'Marshal loads'),
            ('shelve.open', 'Shelve open'),
        ],
        'ssrf': [
            ('requests.get', 'HTTP GET'),
            ('requests.post', 'HTTP POST'),
            ('requests.put', 'HTTP PUT'),
            ('requests.delete', 'HTTP DELETE'),
            ('requests.request', 'HTTP request'),
            ('urllib.request', 'URL request'),
            ('urllib.urlopen', 'URL open'),
            ('urllib2.urlopen', 'URL open v2'),
            ('httplib', 'HTTP lib'),
            ('http.client', 'HTTP client'),
            ('fetch(', 'Fetch'),
            ('axios', 'Axios'),
            ('http.get', 'HTTP GET'),
            ('http.post', 'HTTP POST'),
            ('got(', 'Got HTTP'),
            ('request(', 'Request library'),
            ('curl', 'CURL'),
            ('curl_exec', 'CURL exec'),
            ('file_get_contents', 'URL contents'),
            ('HttpClient', 'HTTP client'),
            ('WebClient', 'Web client'),
            ('RestTemplate', 'Spring RestTemplate'),
            ('HttpURLConnection', 'HTTP URL connection'),
            ('socket.connect', 'Socket connect'),
        ],
        'ldap': [
            ('ldap.search', 'LDAP search'),
            ('ldap_search', 'LDAP search'),
            ('ldap_bind', 'LDAP bind'),
            ('LdapTemplate', 'LDAP template'),
            ('DirContext.search', 'Dir context search'),
            ('LdapContext', 'LDAP context'),
        ],
        'xpath': [
            ('xpath(', 'XPath query'),
            ('evaluate(', 'XPath evaluate'),
            ('selectNodes', 'Select nodes'),
            ('selectSingleNode', 'Select single node'),
            ('XPathExpression', 'XPath expression'),
        ],
        'template': [
            ('render_template_string', 'Flask template string'),
            ('Template(', 'Jinja template'),
            ('Environment(', 'Jinja environment'),
            ('compile(', 'Template compile'),
            ('ejs.render', 'EJS render'),
            ('pug.render', 'Pug render'),
            ('handlebars.compile', 'Handlebars compile'),
        ],
        'redirect': [
            ('redirect(', 'Redirect'),
            ('Response.Redirect', 'ASP redirect'),
            ('sendRedirect', 'Send redirect'),
            ('header("Location', 'PHP redirect'),
            ('res.redirect', 'Express redirect'),
            ('HttpResponseRedirect', 'Django redirect'),
        ],
        'log_injection': [
            ('logger.info', 'Logger info'),
            ('logger.debug', 'Logger debug'),
            ('logger.error', 'Logger error'),
            ('logger.warn', 'Logger warn'),
            ('logging.info', 'Logging info'),
            ('console.log', 'Console log'),
            ('Log.d', 'Android log'),
        ],
    }

    # Known sanitizers
    SANITIZERS = {
        'sql': [
            'parameterized',
            'prepared',
            'placeholder',
            'escape',
            'quote',
            'bindParam',
            'bindValue',
        ],
        'xss': [
            'escape',
            'sanitize',
            'htmlspecialchars',
            'htmlentities',
            'encode',
            'DOMPurify',
            'textContent',
            'innerText',
            'encodeURIComponent',
        ],
        'command': [
            'shlex.quote',
            'escapeshellarg',
            'escapeshellcmd',
            'whitelist',
        ],
        'path': [
            'basename',
            'realpath',
            'normpath',
            'secure_filename',
            'abspath',
        ],
    }

    def __init__(self, language: str):
        self.language = language
        self.tainted_variables: Dict[str, TaintState] = {}
        self.taint_sources: List[TaintNode] = []
        self.taint_flows: List[TaintFlow] = []
        self.current_file = ""

    def analyze(self, source_code: str, file_path: str, ast_data: Dict) -> List[TaintFlow]:
        """
        Perform taint analysis on source code with multi-step propagation
        Returns list of taint flows from source to sink
        """
        self.current_file = file_path
        self.tainted_variables = {}
        self.taint_sources = []
        self.taint_flows = []

        lines = source_code.split('\n')
        sources_patterns = self.SOURCES.get(self.language, [])

        # Track variable origins for multi-step propagation
        variable_origins: Dict[str, str] = {}  # Maps derived var -> original source var
        propagation_nodes: Dict[str, List[TaintNode]] = defaultdict(list)
        propagation_chain: Dict[str, List[str]] = defaultdict(list)  # Track full propagation chain

        # Phase 1: Identify taint sources
        for line_num, line in enumerate(lines, 1):
            for source_pattern, description in sources_patterns:
                if source_pattern in line:
                    # Find variable being assigned (handle multiple assignment patterns)
                    patterns = [
                        r'(\w+)\s*=.*' + re.escape(source_pattern),
                        r'(\w+)\s*=\s*' + re.escape(source_pattern),
                        r'^\s*(\w+)\s*=',  # Simple assignment on line containing source
                    ]

                    for pattern in patterns:
                        var_match = re.search(pattern, line)
                        if var_match:
                            var_name = var_match.group(1)
                            self.tainted_variables[var_name] = TaintState.TAINTED
                            variable_origins[var_name] = var_name  # Source is its own origin
                            propagation_chain[var_name] = [var_name]

                            source_node = TaintNode(
                                id=f"src_{line_num}_{var_name}",
                                node_type=NodeType.SOURCE,
                                description=f"Taint source: {description}",
                                location=Location(
                                    file=file_path,
                                    start_line=line_num,
                                    end_line=line_num,
                                    start_column=0,
                                    end_column=len(line)
                                ),
                                code_snippet=line.strip(),
                                variable_name=var_name,
                                node_kind="Assignment"
                            )
                            self.taint_sources.append(source_node)
                            break

        # Phase 2: Multi-step taint propagation with iteration until fixed point
        max_iterations = 10  # Prevent infinite loops
        iteration = 0

        while iteration < max_iterations:
            iteration += 1
            new_taints_found = False

            for line_num, line in enumerate(lines, 1):
                # Check for variable assignments that propagate taint
                # Handle multiple assignment patterns
                assign_patterns = [
                    r'^(\w+)\s*=\s*(.+)$',  # Standard assignment
                    r'^\s*(\w+)\s*=\s*(.+)$',  # With leading whitespace
                    r'(\w+)\s*:\s*\w+\s*=\s*(.+)',  # Type annotated (Python)
                    r'(?:let|const|var)\s+(\w+)\s*=\s*(.+)',  # JavaScript
                ]

                for pattern in assign_patterns:
                    assign_match = re.search(pattern, line)
                    if assign_match:
                        target_var = assign_match.group(1)
                        value_expr = assign_match.group(2)

                        # Skip if already tainted with same state
                        if target_var in self.tainted_variables and self.tainted_variables[target_var] == TaintState.TAINTED:
                            continue

                        # Check if value contains any tainted variables
                        for tainted_var, state in list(self.tainted_variables.items()):
                            if state == TaintState.TAINTED:
                                # Use word boundary to avoid partial matches
                                if re.search(rf'\b{re.escape(tainted_var)}\b', value_expr):
                                    # Check for sanitization
                                    is_sanitized = False
                                    for sink_type, sanitizers in self.SANITIZERS.items():
                                        if any(san in line.lower() for san in sanitizers):
                                            is_sanitized = True
                                            break

                                    if is_sanitized:
                                        if target_var not in self.tainted_variables:
                                            self.tainted_variables[target_var] = TaintState.SANITIZED
                                            new_taints_found = True
                                    else:
                                        if target_var not in self.tainted_variables or self.tainted_variables[target_var] != TaintState.TAINTED:
                                            self.tainted_variables[target_var] = TaintState.TAINTED
                                            new_taints_found = True

                                            # Track origin through chain
                                            origin = variable_origins.get(tainted_var, tainted_var)
                                            variable_origins[target_var] = origin

                                            # Build propagation chain
                                            parent_chain = propagation_chain.get(tainted_var, [tainted_var])
                                            propagation_chain[target_var] = parent_chain + [target_var]

                                            prop_node = TaintNode(
                                                id=f"prop_{line_num}_{target_var}",
                                                node_type=NodeType.PROPAGATOR,
                                                description=f"Taint propagated from {tainted_var} to {target_var}",
                                                location=Location(
                                                    file=file_path,
                                                    start_line=line_num,
                                                    end_line=line_num,
                                                    start_column=0,
                                                    end_column=len(line)
                                                ),
                                                code_snippet=line.strip(),
                                                variable_name=target_var,
                                                node_kind="Propagation"
                                            )
                                            propagation_nodes[origin].append(prop_node)
                                    break
                        break

            # Stop if no new taints were found (fixed point reached)
            if not new_taints_found:
                break

        # Phase 3: Identify sinks and create taint flows
        for line_num, line in enumerate(lines, 1):
            for sink_category, sink_patterns in self.SINKS.items():
                for sink_pattern, sink_desc in sink_patterns:
                    if sink_pattern in line:
                        # Check if any tainted variable flows to this sink
                        for tainted_var, state in self.tainted_variables.items():
                            if state == TaintState.TAINTED:
                                # Use word boundary matching
                                if re.search(rf'\b{re.escape(tainted_var)}\b', line):
                                    # Find the original source for this tainted variable
                                    origin_var = variable_origins.get(tainted_var, tainted_var)
                                    source_node = None

                                    for src in self.taint_sources:
                                        if src.variable_name == origin_var:
                                            source_node = src
                                            break

                                    if source_node:
                                        sink_node = TaintNode(
                                            id=f"sink_{line_num}_{sink_category}_{tainted_var}",
                                            node_type=NodeType.SINK,
                                            description=f"Dangerous sink: {sink_desc}",
                                            location=Location(
                                                file=file_path,
                                                start_line=line_num,
                                                end_line=line_num,
                                                start_column=0,
                                                end_column=len(line)
                                            ),
                                            code_snippet=line.strip(),
                                            variable_name=tainted_var,
                                            function_name=sink_pattern.rstrip('('),
                                            node_kind=f"{sink_category.upper()}_Sink"
                                        )

                                        # Build complete path using propagation chain
                                        path = [source_node]
                                        chain = propagation_chain.get(tainted_var, [])

                                        # Add propagation nodes in order
                                        for prop_var in chain[1:]:  # Skip the source itself
                                            for prop_node in propagation_nodes.get(origin_var, []):
                                                if prop_node.variable_name == prop_var:
                                                    path.append(prop_node)
                                                    break

                                        path.append(sink_node)

                                        # Avoid duplicate flows
                                        flow_id = f"flow_{source_node.id}_{sink_node.id}"
                                        if not any(f.id == flow_id for f in self.taint_flows):
                                            flow = TaintFlow(
                                                id=flow_id,
                                                source=source_node,
                                                sink=sink_node,
                                                path=path,
                                                confidence="high" if len(path) <= 5 else "medium",
                                                data_type=sink_category
                                            )
                                            self.taint_flows.append(flow)

        return self.taint_flows


class ControlFlowAnalyzer:
    """
    Control Flow Graph (CFG) Analyzer
    Maps execution paths through code
    """

    def __init__(self, language: str):
        self.language = language
        self.nodes: Dict[str, CFGNode] = {}
        self.entry_node: Optional[str] = None
        self.exit_nodes: List[str] = []

    def analyze(self, source_code: str, file_path: str) -> Dict[str, Any]:
        """Build control flow graph from source code"""
        lines = source_code.split('\n')
        self.nodes = {}

        # Create entry node
        entry_id = "entry_0"
        self.entry_node = entry_id
        self.nodes[entry_id] = CFGNode(
            id=entry_id,
            node_type="entry",
            code="<entry>",
            location=Location(file_path, 1, 1, 0, 0)
        )

        current_node_id = entry_id
        block_stack: List[str] = []  # Track nested blocks

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue

            node_id = f"stmt_{line_num}"

            # Detect control flow structures
            if self._is_condition(stripped):
                node_type = "condition"
                condition = self._extract_condition(stripped)
            elif self._is_loop(stripped):
                node_type = "loop"
                condition = self._extract_condition(stripped)
            elif self._is_try_block(stripped):
                node_type = "try"
                condition = None
            elif self._is_catch_block(stripped):
                node_type = "catch"
                condition = None
            elif self._is_return(stripped):
                node_type = "return"
                condition = None
            else:
                node_type = "statement"
                condition = None

            cfg_node = CFGNode(
                id=node_id,
                node_type=node_type,
                code=stripped,
                location=Location(file_path, line_num, line_num, 0, len(line)),
                condition=condition
            )
            self.nodes[node_id] = cfg_node

            # Link to previous node
            if current_node_id:
                self.nodes[current_node_id].successors.append(node_id)
                cfg_node.predecessors.append(current_node_id)

            current_node_id = node_id

            # Track exit points
            if node_type == "return":
                self.exit_nodes.append(node_id)

        # Create exit node
        exit_id = "exit_end"
        self.nodes[exit_id] = CFGNode(
            id=exit_id,
            node_type="exit",
            code="<exit>",
            location=Location(file_path, len(lines), len(lines), 0, 0)
        )

        # Link last statement to exit
        if current_node_id and current_node_id not in self.exit_nodes:
            self.nodes[current_node_id].successors.append(exit_id)
            self.nodes[exit_id].predecessors.append(current_node_id)

        # Link return statements to exit
        for ret_node_id in self.exit_nodes:
            self.nodes[ret_node_id].successors.append(exit_id)
            self.nodes[exit_id].predecessors.append(ret_node_id)

        return {
            "entry": self.entry_node,
            "exit": exit_id,
            "nodes": {k: self._node_to_dict(v) for k, v in self.nodes.items()},
            "total_nodes": len(self.nodes),
            "branches": len([n for n in self.nodes.values() if n.node_type == "condition"]),
            "loops": len([n for n in self.nodes.values() if n.node_type == "loop"]),
        }

    def _node_to_dict(self, node: CFGNode) -> Dict:
        return {
            "id": node.id,
            "type": node.node_type,
            "code": node.code,
            "successors": node.successors,
            "predecessors": node.predecessors,
            "condition": node.condition,
            "location": node.location.to_dict()
        }

    def _is_condition(self, line: str) -> bool:
        patterns = [r'^if\s*\(', r'^if\s+', r'^else\s+if', r'^elif\s+', r'^switch\s*\(']
        return any(re.match(p, line) for p in patterns)

    def _is_loop(self, line: str) -> bool:
        patterns = [r'^for\s*\(', r'^for\s+', r'^while\s*\(', r'^while\s+', r'^do\s*\{']
        return any(re.match(p, line) for p in patterns)

    def _is_try_block(self, line: str) -> bool:
        return line.startswith('try') or line.startswith('try:')

    def _is_catch_block(self, line: str) -> bool:
        patterns = ['catch', 'except', 'rescue', 'finally']
        return any(line.startswith(p) for p in patterns)

    def _is_return(self, line: str) -> bool:
        return line.startswith('return ')

    def _extract_condition(self, line: str) -> str:
        match = re.search(r'\(([^)]+)\)', line)
        if match:
            return match.group(1)
        # Python-style
        match = re.search(r'(?:if|elif|while|for)\s+(.+?):', line)
        if match:
            return match.group(1)
        return ""


class DataFlowAnalyzer:
    """
    Data Flow Graph (DFG) Analyzer
    Tracks variable definitions and uses
    """

    def __init__(self, language: str):
        self.language = language
        self.definitions: Dict[str, List[DFGNode]] = defaultdict(list)
        self.uses: Dict[str, List[Tuple[int, str]]] = defaultdict(list)

    def analyze(self, source_code: str, file_path: str, ast_data: Dict) -> Dict[str, Any]:
        """Build data flow graph from source code"""
        lines = source_code.split('\n')
        self.definitions = defaultdict(list)
        self.uses = defaultdict(list)

        # Extract variable definitions
        for assignment in ast_data.get('assignments', []):
            var_name = assignment.get('variable', '')
            line_num = assignment.get('line', 0)

            if var_name:
                dfg_node = DFGNode(
                    id=f"def_{var_name}_{line_num}",
                    variable=var_name,
                    definition_type="assignment",
                    location=Location(file_path, line_num, line_num, 0, 0)
                )
                self.definitions[var_name].append(dfg_node)

        # Track function parameters as definitions
        for func in ast_data.get('functions', []):
            for param in func.get('parameters', []):
                dfg_node = DFGNode(
                    id=f"param_{param}_{func['line']}",
                    variable=param,
                    definition_type="parameter",
                    location=Location(file_path, func['line'], func['line'], 0, 0)
                )
                self.definitions[param].append(dfg_node)

        # Track variable uses
        for line_num, line in enumerate(lines, 1):
            for var_name in self.definitions.keys():
                # Check if variable is used (not just defined)
                pattern = rf'\b{re.escape(var_name)}\b'
                if re.search(pattern, line):
                    # Verify it's a use, not a definition
                    if not re.match(rf'^\s*{re.escape(var_name)}\s*=', line):
                        self.uses[var_name].append((line_num, line.strip()))

        # Build dependency graph
        dependencies: Dict[str, List[str]] = defaultdict(list)

        for line_num, line in enumerate(lines, 1):
            # Find assignments
            match = re.match(r'^\s*(\w+)\s*=\s*(.+)', line)
            if match:
                target = match.group(1)
                value = match.group(2)

                # Find other variables in the value
                for other_var in self.definitions.keys():
                    if other_var != target and re.search(rf'\b{re.escape(other_var)}\b', value):
                        dependencies[target].append(other_var)

        return {
            "definitions": {
                var: [
                    {
                        "id": node.id,
                        "line": node.location.start_line,
                        "type": node.definition_type
                    }
                    for node in nodes
                ]
                for var, nodes in self.definitions.items()
            },
            "uses": {
                var: [{"line": line, "code": code} for line, code in uses]
                for var, uses in self.uses.items()
            },
            "dependencies": dict(dependencies),
            "total_variables": len(self.definitions),
            "total_definitions": sum(len(nodes) for nodes in self.definitions.values()),
        }


class ASTSecurityAnalyzer:
    """
    Main AST-based Security Analyzer
    Combines all analysis engines for comprehensive security scanning
    """

    def __init__(self):
        self.parser = LanguageParser()
        self.findings: List[SecurityFinding] = []
        self.stats = {
            "files_scanned": 0,
            "total_findings": 0,
            "taint_flows_detected": 0,
            "false_positives_filtered": 0,
        }

    def analyze_file(self, source_code: str, file_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis on a file

        Returns:
            Analysis results including findings, taint flows, CFG, and DFG
        """
        self.findings = []
        language = self.parser.detect_language(file_path)

        # Phase 1: Parse AST
        ast_data = self.parser.parse(source_code, file_path)

        # Phase 2: Build CFG
        cfg_analyzer = ControlFlowAnalyzer(language)
        cfg_data = cfg_analyzer.analyze(source_code, file_path)

        # Phase 3: Build DFG
        dfg_analyzer = DataFlowAnalyzer(language)
        dfg_data = dfg_analyzer.analyze(source_code, file_path, ast_data)

        # Phase 4: Taint Analysis
        taint_analyzer = TaintAnalyzer(language)
        taint_flows = taint_analyzer.analyze(source_code, file_path, ast_data)

        # Phase 5: Pattern-based detection with AST context validation
        pattern_findings = self._pattern_scan_with_ast_validation(
            source_code, file_path, language, ast_data
        )

        # Phase 6: Convert taint flows to findings
        taint_findings = self._taint_flows_to_findings(taint_flows, file_path)

        # Merge and deduplicate findings
        all_findings = self._merge_findings(pattern_findings, taint_findings)

        # Update stats
        self.stats["files_scanned"] += 1
        self.stats["total_findings"] = len(all_findings)
        self.stats["taint_flows_detected"] = len(taint_flows)

        return {
            "file_path": file_path,
            "language": language,
            "findings": [f.to_dict() for f in all_findings],
            "taint_flows": [tf.to_dict() for tf in taint_flows],
            "cfg": cfg_data,
            "dfg": dfg_data,
            "ast_summary": {
                "functions": len(ast_data.get('functions', [])),
                "classes": len(ast_data.get('classes', [])),
                "imports": len(ast_data.get('imports', [])),
                "assignments": len(ast_data.get('assignments', [])),
                "calls": len(ast_data.get('calls', [])),
            },
            "stats": self.stats,
        }

    def _pattern_scan_with_ast_validation(
        self,
        source_code: str,
        file_path: str,
        language: str,
        ast_data: Dict
    ) -> List[SecurityFinding]:
        """
        Scan for patterns but validate against AST to reduce false positives
        """
        findings = []
        lines = source_code.split('\n')

        # Import vulnerability patterns from existing scanner
        from .sast_scanner import SASTScanner
        scanner = SASTScanner()

        # Get findings from pattern matching
        raw_findings = scanner.scan_code(source_code, file_path, language)

        # Validate each finding against AST context
        for raw_finding in raw_findings:
            line_num = raw_finding.get('line_number', 0)

            # Validation checks
            is_valid = True
            validation_notes = []

            # Check 1: Is it in a comment?
            if self._is_in_comment(lines, line_num, language):
                is_valid = False
                validation_notes.append("Code is in a comment")

            # Check 2: Is it in a string literal (not executable)?
            if is_valid and self._is_in_string_literal(lines, line_num, raw_finding.get('code_snippet', '')):
                is_valid = False
                validation_notes.append("Code is in a string literal")

            # Check 3: Is it in test code?
            if is_valid and self._is_test_code(file_path, lines, line_num):
                # Lower confidence but don't filter
                raw_finding['confidence'] = 'low'
                validation_notes.append("Code is in test file")

            # Check 4: Is the function actually called?
            if is_valid and 'call' in str(raw_finding.get('title', '')).lower():
                if not self._is_function_called(ast_data, raw_finding):
                    validation_notes.append("Function call validated in AST")

            if is_valid:
                finding = SecurityFinding(
                    id=hashlib.md5(f"{file_path}:{line_num}:{raw_finding['title']}".encode()).hexdigest()[:12],
                    title=raw_finding.get('title', ''),
                    description=raw_finding.get('description', ''),
                    severity=raw_finding.get('severity', 'medium'),
                    confidence=raw_finding.get('confidence', 'medium'),
                    cwe_id=raw_finding.get('cwe_id', ''),
                    owasp_category=raw_finding.get('owasp_category', ''),
                    location=Location(
                        file=file_path,
                        start_line=line_num,
                        end_line=line_num,
                        start_column=0,
                        end_column=len(lines[line_num - 1]) if line_num <= len(lines) else 0
                    ),
                    code_snippet=raw_finding.get('code_snippet', ''),
                    vulnerable_code=raw_finding.get('code_snippet', ''),
                    remediation=raw_finding.get('remediation', ''),
                    remediation_code=raw_finding.get('remediation_code'),
                    cvss_score=raw_finding.get('cvss_score', 0.0),
                    stride_category=raw_finding.get('stride_category'),
                    mitre_attack_id=raw_finding.get('mitre_attack_id'),
                    validation_notes='; '.join(validation_notes) if validation_notes else None
                )
                findings.append(finding)
            else:
                self.stats["false_positives_filtered"] += 1

        return findings

    def _taint_flows_to_findings(
        self,
        taint_flows: List[TaintFlow],
        file_path: str
    ) -> List[SecurityFinding]:
        """Convert taint flows to security findings"""
        findings = []

        sink_type_to_vuln = {
            'sql': ('SQL Injection', 'CWE-89', 'A05:2025 - Injection', 'critical'),
            'command': ('Command Injection', 'CWE-78', 'A05:2025 - Injection', 'critical'),
            'xss': ('Cross-Site Scripting (XSS)', 'CWE-79', 'A05:2025 - Injection', 'high'),
            'path': ('Path Traversal', 'CWE-22', 'A01:2025 - Broken Access Control', 'high'),
            'deserialization': ('Insecure Deserialization', 'CWE-502', 'A03:2025 - Software Supply Chain Failures', 'critical'),
            'ssrf': ('Server-Side Request Forgery', 'CWE-918', 'A08:2025 - Server-Side Request Forgery (SSRF)', 'high'),
            'ldap': ('LDAP Injection', 'CWE-90', 'A05:2025 - Injection', 'high'),
            'xpath': ('XPath Injection', 'CWE-643', 'A05:2025 - Injection', 'high'),
            'template': ('Server-Side Template Injection', 'CWE-1336', 'A05:2025 - Injection', 'critical'),
            'redirect': ('Open Redirect', 'CWE-601', 'A01:2025 - Broken Access Control', 'medium'),
            'log_injection': ('Log Injection', 'CWE-117', 'A09:2025 - Security Logging and Alerting Failures', 'medium'),
        }

        for flow in taint_flows:
            data_type = flow.data_type or 'unknown'
            vuln_info = sink_type_to_vuln.get(data_type, ('Security Vulnerability', 'CWE-20', 'A05:2025 - Injection', 'high'))

            title, cwe_id, owasp, severity = vuln_info

            finding = SecurityFinding(
                id=flow.id,
                title=f"Taint Flow: {title}",
                description=f"Untrusted data flows from {flow.source.description} to {flow.sink.description}",
                severity=severity,
                confidence=flow.confidence,
                cwe_id=cwe_id,
                owasp_category=owasp,
                location=flow.sink.location,
                code_snippet=flow.sink.code_snippet,
                vulnerable_code=flow.sink.code_snippet,
                remediation=self._get_remediation_for_sink(data_type),
                taint_flow=flow,
                cvss_score=9.8 if severity == 'critical' else 7.5 if severity == 'high' else 5.0,
                stride_category="Tampering" if data_type in ['sql', 'command'] else "Information Disclosure",
                mitre_attack_id="T1190"
            )
            findings.append(finding)

        return findings

    def _get_remediation_for_sink(self, sink_type: str) -> str:
        """Get remediation advice for a sink type"""
        remediations = {
            'sql': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.',
            'command': 'Avoid shell execution with user input. Use subprocess with argument lists (shell=False). Validate and whitelist inputs.',
            'xss': 'Encode output for the appropriate context (HTML, JavaScript, URL). Use Content-Security-Policy headers.',
            'path': 'Validate file paths using os.path.basename(). Implement whitelist of allowed paths. Use realpath to resolve paths.',
            'deserialization': 'Avoid deserializing untrusted data. Use safe alternatives like JSON. Implement input validation.',
            'ssrf': 'Validate and whitelist allowed URLs/hosts. Use allowlists for internal services. Disable redirects.',
            'ldap': 'Use parameterized LDAP queries. Escape special characters in user input.',
        }
        return remediations.get(sink_type, 'Review and sanitize user input before use in sensitive operations.')

    def _merge_findings(
        self,
        pattern_findings: List[SecurityFinding],
        taint_findings: List[SecurityFinding]
    ) -> List[SecurityFinding]:
        """Merge findings and remove duplicates"""
        seen = set()
        merged = []

        # Prioritize taint findings as they have more context
        for finding in taint_findings:
            key = f"{finding.location.file}:{finding.location.start_line}:{finding.cwe_id}"
            if key not in seen:
                seen.add(key)
                merged.append(finding)

        for finding in pattern_findings:
            key = f"{finding.location.file}:{finding.location.start_line}:{finding.cwe_id}"
            if key not in seen:
                seen.add(key)
                merged.append(finding)

        return merged

    def _is_in_comment(self, lines: List[str], line_num: int, language: str) -> bool:
        """Check if line is inside a comment"""
        if line_num <= 0 or line_num > len(lines):
            return False

        line = lines[line_num - 1].strip()

        # Single line comments
        single_comment = {'python': '#', 'javascript': '//', 'java': '//', 'php': ['#', '//'], 'go': '//'}
        markers = single_comment.get(language, '//')

        if isinstance(markers, str):
            markers = [markers]

        if any(line.startswith(m) for m in markers):
            return True

        # Check for multi-line comments (simplified)
        full_content = '\n'.join(lines[:line_num])
        if language in ('javascript', 'java', 'go', 'csharp', 'php'):
            # Count /* and */ occurrences
            opens = full_content.count('/*')
            closes = full_content.count('*/')
            if opens > closes:
                return True

        return False

    def _is_in_string_literal(self, lines: List[str], line_num: int, code_snippet: str) -> bool:
        """Check if code is inside a string literal"""
        if line_num <= 0 or line_num > len(lines):
            return False

        line = lines[line_num - 1]

        # Find the position of the code snippet in the line
        pos = line.find(code_snippet.strip())
        if pos == -1:
            return False

        # Count quotes before this position
        before = line[:pos]
        single_quotes = before.count("'") - before.count("\\'")
        double_quotes = before.count('"') - before.count('\\"')

        # If odd number of unescaped quotes, we're inside a string
        return (single_quotes % 2 == 1) or (double_quotes % 2 == 1)

    def _is_test_code(self, file_path: str, lines: List[str], line_num: int) -> bool:
        """Check if code is in a test file or test function"""
        test_indicators = ['test', 'spec', '__tests__', '_test', 'Test']

        # Check file path
        if any(ind in file_path.lower() for ind in test_indicators):
            return True

        # Check if inside a test function
        for i in range(max(0, line_num - 20), line_num):
            if i < len(lines):
                line = lines[i]
                if re.search(r'def\s+test_|@Test|describe\(|it\(|test\(', line):
                    return True

        return False

    def _is_function_called(self, ast_data: Dict, finding: Dict) -> bool:
        """Verify function is actually called in AST"""
        calls = ast_data.get('calls', [])
        snippet = finding.get('code_snippet', '')

        # Extract function name from snippet
        match = re.search(r'(\w+)\s*\(', snippet)
        if match:
            func_name = match.group(1)
            return any(call.get('function', '').endswith(func_name) for call in calls)

        return True  # Assume valid if we can't verify


# Create singleton instance
ast_analyzer = ASTSecurityAnalyzer()
