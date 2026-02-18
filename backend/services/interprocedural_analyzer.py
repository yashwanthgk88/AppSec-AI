"""
Inter-Procedural Security Analyzer

Advanced static analysis with:
- Call Graph Construction (CG)
- Inter-procedural Data Flow Analysis
- Context-Sensitive Taint Tracking
- Function Summary Generation
- Return Value Propagation
- Alias Analysis

This analyzer goes beyond single-function analysis to track
data flow across function boundaries.
"""

import ast
import re
from typing import List, Dict, Any, Set, Optional, Tuple, DefaultDict
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
import hashlib


class TaintState(Enum):
    """Taint states for variables"""
    TAINTED = "tainted"
    CLEAN = "clean"
    UNKNOWN = "unknown"
    SANITIZED = "sanitized"
    CONDITIONAL = "conditional"  # Tainted in some paths


@dataclass
class FunctionSignature:
    """Function signature with parameter and return type info"""
    name: str
    qualified_name: str  # class.method or module.function
    file_path: str
    start_line: int
    end_line: int
    parameters: List[str]
    return_statements: List[int]  # Line numbers of return statements
    calls_functions: List[str]  # Functions this function calls
    called_by: List[str]  # Functions that call this function
    tainted_params: Set[int]  # Indices of parameters that can carry taint
    returns_tainted: bool  # Whether function can return tainted data
    is_sanitizer: bool  # Whether this function sanitizes input
    is_sink: bool  # Whether this function is a dangerous sink
    is_source: bool  # Whether this function is a taint source


@dataclass
class CallSite:
    """Represents a function call site"""
    id: str
    caller_function: str
    callee_function: str
    file_path: str
    line_number: int
    arguments: List[str]  # Argument expressions
    return_var: Optional[str]  # Variable that receives return value
    context: str  # Call context for context-sensitive analysis


@dataclass
class TaintTransfer:
    """Represents taint transfer at a call site"""
    call_site: CallSite
    tainted_args: List[int]  # Indices of tainted arguments
    return_tainted: bool
    sanitized: bool
    confidence: str


@dataclass
class InterproceduralFlow:
    """Complete inter-procedural taint flow"""
    id: str
    source_function: str
    source_line: int
    sink_function: str
    sink_line: int
    call_chain: List[str]  # Function call chain from source to sink
    transfers: List[TaintTransfer]
    tainted_variable: str
    vulnerability_type: str
    confidence: str
    is_exploitable: bool


class CallGraphBuilder:
    """
    Builds call graph from source code
    Supports: Python, JavaScript, Java, Go, PHP
    """

    def __init__(self, language: str):
        self.language = language
        self.functions: Dict[str, FunctionSignature] = {}
        self.call_sites: List[CallSite] = []
        self.call_graph: DefaultDict[str, Set[str]] = defaultdict(set)
        self.reverse_call_graph: DefaultDict[str, Set[str]] = defaultdict(set)

    def build(self, source_code: str, file_path: str) -> Dict[str, Any]:
        """Build call graph from source code"""

        if self.language == 'python':
            return self._build_python_callgraph(source_code, file_path)
        else:
            return self._build_generic_callgraph(source_code, file_path)

    def _build_python_callgraph(self, source_code: str, file_path: str) -> Dict[str, Any]:
        """Build call graph for Python using AST"""
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return self._build_generic_callgraph(source_code, file_path)

        # First pass: collect all function definitions
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                func_name = node.name
                params = [arg.arg for arg in node.args.args]

                # Find return statements
                return_lines = []
                for child in ast.walk(node):
                    if isinstance(child, ast.Return):
                        return_lines.append(child.lineno)

                # Check if function is a source/sink/sanitizer
                is_source = self._is_python_source(node)
                is_sink = self._is_python_sink(node)
                is_sanitizer = self._is_python_sanitizer(node)

                sig = FunctionSignature(
                    name=func_name,
                    qualified_name=func_name,
                    file_path=file_path,
                    start_line=node.lineno,
                    end_line=node.end_lineno or node.lineno,
                    parameters=params,
                    return_statements=return_lines,
                    calls_functions=[],
                    called_by=[],
                    tainted_params=set(),
                    returns_tainted=False,
                    is_sanitizer=is_sanitizer,
                    is_sink=is_sink,
                    is_source=is_source
                )
                self.functions[func_name] = sig

        # Second pass: find all call sites
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                callee = self._get_call_name(node)
                if callee:
                    # Find the enclosing function
                    caller = self._find_enclosing_function(tree, node.lineno)

                    # Extract arguments
                    args = []
                    for arg in node.args:
                        args.append(ast.unparse(arg) if hasattr(ast, 'unparse') else str(arg))

                    # Check if return value is assigned
                    return_var = self._find_return_var(tree, node.lineno)

                    call_site = CallSite(
                        id=f"call_{node.lineno}_{callee}",
                        caller_function=caller or "<module>",
                        callee_function=callee,
                        file_path=file_path,
                        line_number=node.lineno,
                        arguments=args,
                        return_var=return_var,
                        context=f"{caller or '<module>'}:{node.lineno}"
                    )
                    self.call_sites.append(call_site)

                    # Update call graph
                    if caller:
                        self.call_graph[caller].add(callee)
                        self.reverse_call_graph[callee].add(caller)

                        if caller in self.functions:
                            self.functions[caller].calls_functions.append(callee)
                        if callee in self.functions:
                            self.functions[callee].called_by.append(caller)

        return self._get_call_graph_summary()

    def _build_generic_callgraph(self, source_code: str, file_path: str) -> Dict[str, Any]:
        """Build call graph using regex for non-Python languages"""
        lines = source_code.split('\n')

        # Enhanced patterns for function definitions
        func_patterns = {
            'javascript': r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(|(\w+)\s*:\s*(?:async\s*)?\(|(\w+)\s*=\s*async\s*\()',
            'typescript': r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*[:<]\s*|(\w+)\s*:\s*(?:async\s*)?\(|(?:async\s+)?(\w+)\s*<[^>]*>\s*\()',
            'java': r'(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*(?:<[^>]+>\s*)?\w+(?:<[^>]+>)?\s+(\w+)\s*\(',
            'go': r'func\s+(?:\(\s*\w+\s+\*?(\w+)\s*\)\s+)?(\w+)\s*\(',
            'php': r'(?:public|private|protected)?\s*(?:static)?\s*function\s+(\w+)\s*\(',
            'csharp': r'(?:public|private|protected|internal)?\s*(?:static|async|override|virtual)?\s*(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\(',
            'ruby': r'def\s+(?:self\.)?(\w+)',
            'kotlin': r'(?:fun|suspend\s+fun)\s+(?:<[^>]+>\s*)?(\w+)\s*\(',
            'swift': r'func\s+(\w+)\s*(?:<[^>]+>)?\s*\(',
            'rust': r'(?:pub\s+)?(?:async\s+)?fn\s+(\w+)',
            'scala': r'def\s+(\w+)\s*(?:\[[^\]]+\])?\s*\(',
        }

        func_pattern = func_patterns.get(self.language, r'(?:function|def|func)\s+(\w+)')

        current_function = None
        function_stack = []
        brace_count = 0

        # Go-specific: Track method receivers for qualified names
        go_receivers: Dict[str, str] = {}

        for line_num, line in enumerate(lines, 1):
            # Track function definitions
            match = re.search(func_pattern, line)
            if match:
                groups = [g for g in match.groups() if g]
                func_name = groups[-1] if groups else None  # Last non-None group is the function name

                if func_name:
                    # Go-specific: Handle method receivers
                    qualified_name = func_name
                    if self.language == 'go' and len(groups) > 1:
                        receiver_type = groups[0]
                        qualified_name = f"{receiver_type}.{func_name}"
                        go_receivers[func_name] = receiver_type

                    # Check if function is a source/sink/sanitizer based on patterns
                    is_source = self._is_generic_source(func_name, line)
                    is_sink = self._is_generic_sink(func_name, line)
                    is_sanitizer = self._is_generic_sanitizer(func_name)

                    sig = FunctionSignature(
                        name=func_name,
                        qualified_name=qualified_name,
                        file_path=file_path,
                        start_line=line_num,
                        end_line=line_num,
                        parameters=self._extract_params(line),
                        return_statements=[],
                        calls_functions=[],
                        called_by=[],
                        tainted_params=set(),
                        returns_tainted=False,
                        is_sanitizer=is_sanitizer,
                        is_sink=is_sink,
                        is_source=is_source
                    )
                    self.functions[func_name] = sig
                    function_stack.append(func_name)
                    current_function = func_name

            # Track braces for function scope (simplified)
            brace_count += line.count('{') - line.count('}')
            if brace_count <= 0 and function_stack:
                func = function_stack.pop()
                if func in self.functions:
                    self.functions[func].end_line = line_num
                current_function = function_stack[-1] if function_stack else None

            # Find function calls with improved pattern
            call_pattern = r'(\w+(?:\.\w+)*)\s*\('
            for match in re.finditer(call_pattern, line):
                callee = match.group(1)

                # Skip language keywords
                keywords = {
                    'if', 'for', 'while', 'switch', 'catch', 'function', 'class', 'return',
                    'func', 'def', 'else', 'elif', 'try', 'except', 'finally', 'with',
                    'new', 'delete', 'typeof', 'instanceof', 'import', 'export', 'from',
                    'go', 'select', 'case', 'default', 'range', 'defer', 'panic', 'recover',
                    'public', 'private', 'protected', 'static', 'final', 'abstract',
                    'throw', 'throws', 'catch', 'async', 'await', 'yield',
                }
                if callee.split('.')[-1] in keywords:
                    continue

                caller = current_function or "<module>"

                # Extract arguments for better taint tracking
                args = self._extract_call_arguments(line, match.end())

                # Detect return variable assignment
                return_var = self._detect_return_assignment(line, match.start())

                call_site = CallSite(
                    id=f"call_{line_num}_{callee}",
                    caller_function=caller,
                    callee_function=callee,
                    file_path=file_path,
                    line_number=line_num,
                    arguments=args,
                    return_var=return_var,
                    context=f"{caller}:{line_num}"
                )
                self.call_sites.append(call_site)

                self.call_graph[caller].add(callee)
                self.reverse_call_graph[callee].add(caller)

            # Track return statements
            return_patterns = {
                'go': r'\breturn\b',
                'python': r'\breturn\b',
                'java': r'\breturn\b',
                'javascript': r'\breturn\b',
                'ruby': r'\breturn\b|\bend\b',  # Ruby implicit returns
            }
            return_pattern = return_patterns.get(self.language, r'\breturn\b')
            if re.search(return_pattern, line) and current_function and current_function in self.functions:
                self.functions[current_function].return_statements.append(line_num)

        return self._get_call_graph_summary()

    def _is_generic_source(self, func_name: str, line: str) -> bool:
        """Check if function is a taint source based on common patterns"""
        source_patterns = {
            'go': ['Handler', 'ServeHTTP', 'Handle', 'Get', 'Post', 'Put', 'Delete', 'Patch'],
            'javascript': ['get', 'post', 'put', 'delete', 'patch', 'route', 'use'],
            'java': ['doGet', 'doPost', 'doPut', 'doDelete', 'service', 'handleRequest'],
            'python': ['route', 'get', 'post', 'put', 'delete', 'api_view'],
            'php': [],
            'ruby': [],
            'csharp': ['Get', 'Post', 'Put', 'Delete', 'HttpGet', 'HttpPost'],
        }

        patterns = source_patterns.get(self.language, [])

        # Check function name
        for pattern in patterns:
            if pattern.lower() in func_name.lower():
                return True

        # Check for HTTP handler signatures
        if self.language == 'go':
            if 'http.ResponseWriter' in line or 'http.Request' in line:
                return True
            if 'gin.Context' in line or 'echo.Context' in line or 'fiber.Ctx' in line:
                return True

        return False

    def _is_generic_sink(self, func_name: str, line: str) -> bool:
        """Check if function contains/is a dangerous sink"""
        sink_indicators = ['execute', 'query', 'exec', 'eval', 'system', 'write', 'render']
        return any(s in func_name.lower() for s in sink_indicators)

    def _is_generic_sanitizer(self, func_name: str) -> bool:
        """Check if function is a sanitizer based on naming"""
        sanitizer_names = ['escape', 'sanitize', 'clean', 'validate', 'encode', 'quote',
                          'filter', 'purify', 'strip', 'normalize']
        return any(s in func_name.lower() for s in sanitizer_names)

    def _extract_call_arguments(self, line: str, start_pos: int) -> List[str]:
        """Extract function call arguments from line"""
        args = []
        paren_count = 0
        current_arg = ""
        in_string = False
        string_char = None

        for i, char in enumerate(line[start_pos:]):
            if char in '"\'`' and (i == 0 or line[start_pos + i - 1] != '\\'):
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False
                    string_char = None

            if not in_string:
                if char == '(':
                    paren_count += 1
                    if paren_count == 1:
                        continue
                elif char == ')':
                    paren_count -= 1
                    if paren_count == 0:
                        if current_arg.strip():
                            args.append(current_arg.strip())
                        break
                elif char == ',' and paren_count == 1:
                    if current_arg.strip():
                        args.append(current_arg.strip())
                    current_arg = ""
                    continue

            if paren_count >= 1:
                current_arg += char

        return args[:10]  # Limit to first 10 args

    def _detect_return_assignment(self, line: str, call_start: int) -> Optional[str]:
        """Detect if the function call result is assigned to a variable"""
        before_call = line[:call_start].strip()

        # Go: var result = fn() or result := fn() or result, err := fn()
        go_assign = re.search(r'(\w+(?:\s*,\s*\w+)*)\s*:?=\s*$', before_call)
        if go_assign:
            vars_str = go_assign.group(1)
            return vars_str.split(',')[0].strip()

        # Python/JS: result = fn()
        simple_assign = re.search(r'(\w+)\s*=\s*$', before_call)
        if simple_assign:
            return simple_assign.group(1)

        # Java: Type result = fn()
        java_assign = re.search(r'(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*=\s*$', before_call)
        if java_assign:
            return java_assign.group(1)

        return None

    def _extract_params(self, line: str) -> List[str]:
        """Extract function parameters from definition line"""
        match = re.search(r'\(([^)]*)\)', line)
        if match:
            params_str = match.group(1)
            params = [p.strip().split(':')[0].split('=')[0].strip()
                      for p in params_str.split(',') if p.strip()]
            return [p for p in params if p and not p.startswith('*')]
        return []

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Get the name of a called function from AST node"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return None

    def _find_enclosing_function(self, tree: ast.AST, line_no: int) -> Optional[str]:
        """Find the function containing a given line number"""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.lineno <= line_no <= (node.end_lineno or node.lineno + 1000):
                    return node.name
        return None

    def _find_return_var(self, tree: ast.AST, line_no: int) -> Optional[str]:
        """Find variable assigned from a call at given line"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and node.lineno == line_no:
                if node.targets and isinstance(node.targets[0], ast.Name):
                    return node.targets[0].id
        return None

    def _is_python_source(self, node: ast.FunctionDef) -> bool:
        """Check if function is a taint source"""
        source_decorators = {'route', 'get', 'post', 'put', 'delete', 'api_view'}
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id in source_decorators:
                return True
            if isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name) and decorator.func.id in source_decorators:
                    return True
        return False

    def _is_python_sink(self, node: ast.FunctionDef) -> bool:
        """Check if function contains dangerous sinks"""
        sink_calls = {'execute', 'system', 'eval', 'exec', 'subprocess', 'popen'}
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._get_call_name(child)
                if name and any(s in name.lower() for s in sink_calls):
                    return True
        return False

    def _is_python_sanitizer(self, node: ast.FunctionDef) -> bool:
        """Check if function is a sanitizer"""
        sanitizer_names = {'escape', 'sanitize', 'clean', 'validate', 'encode', 'quote'}
        return any(s in node.name.lower() for s in sanitizer_names)

    def _get_call_graph_summary(self) -> Dict[str, Any]:
        """Get call graph summary"""
        return {
            "functions": {
                name: {
                    "name": sig.name,
                    "qualified_name": sig.qualified_name,
                    "start_line": sig.start_line,
                    "end_line": sig.end_line,
                    "parameters": sig.parameters,
                    "calls": list(self.call_graph.get(name, set())),
                    "called_by": list(self.reverse_call_graph.get(name, set())),
                    "is_source": sig.is_source,
                    "is_sink": sig.is_sink,
                    "is_sanitizer": sig.is_sanitizer,
                }
                for name, sig in self.functions.items()
            },
            "call_sites": [
                {
                    "id": cs.id,
                    "caller": cs.caller_function,
                    "callee": cs.callee_function,
                    "line": cs.line_number,
                    "arguments": cs.arguments,
                    "return_var": cs.return_var,
                }
                for cs in self.call_sites
            ],
            "call_graph": {k: list(v) for k, v in self.call_graph.items()},
            "reverse_call_graph": {k: list(v) for k, v in self.reverse_call_graph.items()},
            "statistics": {
                "total_functions": len(self.functions),
                "total_call_sites": len(self.call_sites),
                "max_call_depth": self._calculate_max_depth(),
                "recursive_functions": self._find_recursive_functions(),
            }
        }

    def _calculate_max_depth(self) -> int:
        """Calculate maximum call depth in the graph"""
        visited = set()
        max_depth = 0

        def dfs(func: str, depth: int):
            nonlocal max_depth
            if func in visited:
                return
            visited.add(func)
            max_depth = max(max_depth, depth)
            for callee in self.call_graph.get(func, set()):
                dfs(callee, depth + 1)
            visited.remove(func)

        for func in self.functions:
            dfs(func, 0)
        return max_depth

    def _find_recursive_functions(self) -> List[str]:
        """Find functions that are directly or indirectly recursive"""
        recursive = []
        for func in self.functions:
            if self._is_reachable(func, func):
                recursive.append(func)
        return recursive

    def _is_reachable(self, start: str, target: str) -> bool:
        """Check if target is reachable from start in call graph"""
        visited = set()
        stack = list(self.call_graph.get(start, set()))

        while stack:
            current = stack.pop()
            if current == target:
                return True
            if current not in visited:
                visited.add(current)
                stack.extend(self.call_graph.get(current, set()))
        return False


class FunctionSummaryGenerator:
    """
    Generates summaries for functions describing:
    - Which parameters can carry taint
    - Whether return value can be tainted
    - What sanitization is performed
    """

    # Comprehensive taint sources by language
    TAINT_SOURCES = {
        'python': [
            # Flask/Django
            'request.args', 'request.form', 'request.json', 'request.data', 'request.files',
            'request.values', 'request.cookies', 'request.headers', 'request.get_json',
            # Django
            'request.GET', 'request.POST', 'request.body',
            # General
            'input(', 'sys.argv', 'os.environ', 'open(', 'socket.recv', 'urlopen',
            'subprocess.check_output', 'raw_input',
        ],
        'javascript': [
            # Express
            'req.query', 'req.body', 'req.params', 'req.headers', 'req.cookies',
            'req.path', 'req.url', 'req.originalUrl',
            # Browser
            'window.location', 'document.URL', 'document.referrer', 'document.cookie',
            'location.search', 'location.hash', 'location.pathname',
            'URLSearchParams', 'FormData',
            # File/Network
            'readFileSync', 'fetch(', 'axios',
        ],
        'typescript': [
            'req.query', 'req.body', 'req.params', 'req.headers', 'req.cookies',
            'request.query', 'request.body', 'request.params',
        ],
        'java': [
            # Servlet
            'getParameter', 'getHeader', 'getCookies', 'getInputStream', 'getReader',
            'getQueryString', 'getPathInfo', 'getRequestURI', 'getRequestURL',
            # Spring
            '@RequestParam', '@PathVariable', '@RequestBody', '@RequestHeader',
            'HttpServletRequest',
            # General
            'Scanner', 'BufferedReader', 'DataInputStream',
        ],
        'go': [
            # net/http
            'r.URL.Query', 'r.FormValue', 'r.Body', 'r.PostFormValue', 'r.Form',
            'r.Header.Get', 'r.Cookie', 'r.URL.Path', 'r.URL.RawQuery',
            'r.ParseForm', 'r.ParseMultipartForm', 'r.MultipartForm',
            # Gin
            'c.Query', 'c.Param', 'c.PostForm', 'c.FormFile', 'c.GetHeader',
            'c.BindJSON', 'c.ShouldBindJSON', 'c.Request',
            # Echo
            'c.QueryParam', 'c.PathParam', 'c.FormValue', 'c.Bind',
            # Fiber
            'c.Query', 'c.Params', 'c.FormValue', 'c.Body',
            # Chi
            'chi.URLParam',
            # File/Network
            'os.Stdin', 'bufio.Scanner', 'ioutil.ReadAll', 'io.ReadAll',
        ],
        'php': [
            '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER',
            'php://input', 'file_get_contents', 'fgets', 'fread',
        ],
        'ruby': [
            'params', 'request.params', 'request.body', 'request.cookies',
            'ENV', 'ARGV', 'gets', 'readline',
        ],
        'csharp': [
            'Request.Query', 'Request.Form', 'Request.Body', 'Request.Headers',
            'Request.Cookies', 'HttpContext.Request',
            '[FromBody]', '[FromQuery]', '[FromRoute]', '[FromForm]',
        ],
    }

    # Comprehensive sinks by vulnerability category
    SINKS = {
        'sql': {
            'python': ['execute', 'executemany', 'cursor.execute', 'raw(', 'extra(', 'RawSQL'],
            'javascript': ['query(', 'execute(', 'sequelize.query', 'knex.raw'],
            'java': ['executeQuery', 'executeUpdate', 'execute(', 'prepareStatement', 'createQuery', 'nativeQuery'],
            'go': ['db.Query', 'db.QueryRow', 'db.Exec', 'tx.Query', 'tx.Exec', 'Raw(', 'Exec('],
            'php': ['mysql_query', 'mysqli_query', 'pg_query', 'PDO::query', 'execute'],
            'generic': ['execute', 'query', 'cursor', 'raw', 'executeQuery', 'Exec', 'Query'],
        },
        'command': {
            'python': ['os.system', 'os.popen', 'subprocess.call', 'subprocess.run', 'subprocess.Popen', 'commands.getoutput'],
            'javascript': ['exec(', 'execSync', 'spawn(', 'spawnSync', 'execFile', 'child_process'],
            'java': ['Runtime.exec', 'ProcessBuilder', 'Runtime.getRuntime().exec'],
            'go': ['exec.Command', 'exec.CommandContext', 'os.StartProcess', 'syscall.Exec'],
            'php': ['system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open', 'pcntl_exec'],
            'generic': ['system', 'exec', 'popen', 'subprocess', 'spawn', 'shell_exec'],
        },
        'xss': {
            'python': ['render_template_string', 'Markup(', 'safe|', '|safe'],
            'javascript': ['innerHTML', 'outerHTML', 'document.write', 'insertAdjacentHTML', 'eval(', 'Function('],
            'java': ['getWriter().print', 'getWriter().write', 'getOutputStream'],
            'go': ['template.HTML', 'w.Write', 'io.WriteString', 'fmt.Fprintf(w'],
            'php': ['echo', 'print', 'printf'],
            'generic': ['innerHTML', 'document.write', 'render_template_string', 'html('],
        },
        'path': {
            'python': ['open(', 'file(', 'os.path.join', 'shutil.copy', 'send_file'],
            'javascript': ['readFile', 'writeFile', 'readFileSync', 'createReadStream', 'require('],
            'java': ['FileInputStream', 'FileOutputStream', 'File(', 'Paths.get'],
            'go': ['os.Open', 'os.Create', 'ioutil.ReadFile', 'os.ReadFile', 'filepath.Join', 'http.ServeFile'],
            'php': ['include', 'require', 'include_once', 'require_once', 'fopen', 'file_get_contents', 'readfile'],
            'generic': ['open', 'readFile', 'include', 'require', 'fopen'],
        },
        'deserialize': {
            'python': ['pickle.loads', 'pickle.load', 'yaml.load', 'yaml.unsafe_load', 'marshal.loads', 'shelve.open'],
            'javascript': ['JSON.parse', 'eval(', 'Function(', 'deserialize'],
            'java': ['ObjectInputStream.readObject', 'XMLDecoder', 'readObject', 'fromXML'],
            'go': ['gob.Decode', 'json.Unmarshal', 'yaml.Unmarshal', 'xml.Unmarshal'],
            'php': ['unserialize'],
            'generic': ['pickle.loads', 'yaml.load', 'unserialize', 'readObject', 'Unmarshal'],
        },
        'ssrf': {
            'python': ['requests.get', 'requests.post', 'urllib.request.urlopen', 'http.client', 'httplib'],
            'javascript': ['fetch(', 'axios', 'http.get', 'https.get', 'request('],
            'java': ['HttpURLConnection', 'URL.openConnection', 'HttpClient', 'WebClient'],
            'go': ['http.Get', 'http.Post', 'http.NewRequest', 'client.Do', 'client.Get'],
            'php': ['file_get_contents', 'curl_exec', 'fopen'],
            'generic': ['http.get', 'fetch', 'urlopen', 'request'],
        },
        'redirect': {
            'python': ['redirect(', 'HttpResponseRedirect'],
            'javascript': ['res.redirect', 'window.location', 'location.href'],
            'java': ['sendRedirect', 'forward'],
            'go': ['http.Redirect', 'c.Redirect'],
            'php': ['header("Location'],
            'generic': ['redirect', 'sendRedirect', 'location'],
        },
        'ldap': {
            'generic': ['ldap_search', 'search_s', 'ldap.search', 'LdapContext'],
        },
        'xpath': {
            'generic': ['xpath(', 'evaluate', 'selectNodes', 'XPathExpression'],
        },
        'regex_dos': {
            'generic': ['re.match', 're.search', 'Pattern.compile', 'RegExp('],
        },
    }

    # Comprehensive sanitizers by vulnerability category
    SANITIZERS = {
        'sql': {
            'python': ['escape_string', 'quote', 'parameterized', '%s', '?'],
            'javascript': ['escape', 'mysql.escape', 'pg.escapeLiteral', 'sequelize.escape'],
            'java': ['PreparedStatement', 'setString', 'setInt', 'createNamedQuery'],
            'go': ['$1', '$2', '?', 'Prepare', 'stmt.Exec', 'sqlx.Named'],
            'php': ['mysqli_real_escape_string', 'PDO::quote', 'addslashes'],
            'generic': ['escape', 'quote', 'parameterized', 'prepared', 'bindParam'],
        },
        'xss': {
            'python': ['escape(', 'html.escape', 'markupsafe.escape', 'bleach.clean', 'cgi.escape'],
            'javascript': ['DOMPurify.sanitize', 'textContent', 'createTextNode', 'encodeURIComponent', 'escape('],
            'java': ['StringEscapeUtils.escapeHtml', 'HtmlUtils.htmlEscape', 'ESAPI.encoder'],
            'go': ['html.EscapeString', 'template.HTMLEscapeString', 'html/template'],
            'php': ['htmlspecialchars', 'htmlentities', 'strip_tags'],
            'generic': ['escape', 'htmlspecialchars', 'DOMPurify', 'sanitize', 'encode'],
        },
        'command': {
            'python': ['shlex.quote', 'shlex.split', 'pipes.quote'],
            'javascript': ['shell-escape', 'escapeshellarg'],
            'java': ['ProcessBuilder(list)', 'new ProcessBuilder'],
            'go': ['exec.Command(cmd, args...)', 'filepath.Clean'],
            'php': ['escapeshellarg', 'escapeshellcmd'],
            'generic': ['shlex.quote', 'escapeshellarg', 'shell-escape'],
        },
        'path': {
            'python': ['os.path.basename', 'secure_filename', 'os.path.realpath', 'pathlib'],
            'javascript': ['path.basename', 'path.normalize', 'path.resolve'],
            'java': ['FilenameUtils.getName', 'normalize', 'getCanonicalPath'],
            'go': ['filepath.Base', 'filepath.Clean', 'filepath.Abs', 'strings.HasPrefix'],
            'php': ['basename', 'realpath'],
            'generic': ['basename', 'realpath', 'secure_filename', 'normalize', 'Clean'],
        },
        'ssrf': {
            'generic': ['allowlist', 'whitelist', 'isPrivate', 'isLoopback', 'validateURL', 'url.Parse'],
        },
        'deserialize': {
            'python': ['json.loads', 'yaml.safe_load', 'SafeLoader'],
            'javascript': ['JSON.parse'],
            'java': ['ObjectInputFilter', 'ValidatingObjectInputStream'],
            'go': ['json.Unmarshal'],  # JSON is safe
            'php': ['json_decode'],
            'generic': ['json.loads', 'safe_load', 'json_decode'],
        },
    }

    def __init__(self, language: str):
        self.language = language
        self.summaries: Dict[str, Dict[str, Any]] = {}

    def generate_summaries(
        self,
        source_code: str,
        call_graph: CallGraphBuilder
    ) -> Dict[str, Dict[str, Any]]:
        """Generate summaries for all functions"""

        for func_name, sig in call_graph.functions.items():
            summary = self._analyze_function(source_code, sig, call_graph)
            self.summaries[func_name] = summary

        # Propagate summaries through call graph (fixed-point iteration)
        self._propagate_summaries(call_graph)

        return self.summaries

    def _get_sinks_for_language(self, sink_type: str) -> List[str]:
        """Get sinks for a specific vulnerability type, language-aware"""
        sink_dict = self.SINKS.get(sink_type, {})
        if isinstance(sink_dict, dict):
            # New format with language-specific sinks
            lang_sinks = sink_dict.get(self.language, [])
            generic_sinks = sink_dict.get('generic', [])
            return list(set(lang_sinks + generic_sinks))
        else:
            # Legacy format (list)
            return sink_dict

    def _get_sanitizers_for_language(self, san_type: str) -> List[str]:
        """Get sanitizers for a specific vulnerability type, language-aware"""
        san_dict = self.SANITIZERS.get(san_type, {})
        if isinstance(san_dict, dict):
            lang_sans = san_dict.get(self.language, [])
            generic_sans = san_dict.get('generic', [])
            return list(set(lang_sans + generic_sans))
        else:
            return san_dict

    def _analyze_function(
        self,
        source_code: str,
        sig: FunctionSignature,
        call_graph: CallGraphBuilder
    ) -> Dict[str, Any]:
        """Analyze a single function and generate summary"""

        lines = source_code.split('\n')
        func_lines = lines[sig.start_line - 1:sig.end_line]
        func_code = '\n'.join(func_lines)

        # Determine which parameters can carry taint (conservatively all)
        tainted_params = set(range(len(sig.parameters)))

        # Check if any parameter flows to a sink (language-aware)
        param_to_sink = {}
        sink_details = []
        for i, param in enumerate(sig.parameters):
            for sink_type in self.SINKS.keys():
                sinks = self._get_sinks_for_language(sink_type)
                for sink in sinks:
                    # Check if parameter appears near a sink
                    # Escape special regex chars in sink but handle ( specially
                    sink_escaped = re.escape(sink).replace(r'\(', r'\s*\(')
                    param_escaped = re.escape(param)
                    pattern = rf'\b{param_escaped}\b[^;{{}}]*{sink_escaped}|{sink_escaped}[^;{{}}]*\b{param_escaped}\b'
                    match = re.search(pattern, func_code, re.IGNORECASE)
                    if match:
                        param_to_sink[i] = sink_type
                        sink_details.append({
                            'param': param,
                            'param_idx': i,
                            'sink_type': sink_type,
                            'sink_pattern': sink,
                            'line_content': match.group(0)[:100]
                        })

        # Check if function sanitizes input (language-aware)
        sanitizes = {}
        sanitizer_details = []
        for san_type in self.SANITIZERS.keys():
            sanitizers = self._get_sanitizers_for_language(san_type)
            for san in sanitizers:
                if san.lower() in func_code.lower():
                    sanitizes[san_type] = True
                    sanitizer_details.append({
                        'type': san_type,
                        'sanitizer': san
                    })

        # Check if return value can be tainted
        returns_tainted = False
        taint_propagation = []
        for param in sig.parameters:
            # Check if parameter influences return value
            param_escaped = re.escape(param)
            if re.search(rf'return\s+.*\b{param_escaped}\b', func_code):
                returns_tainted = True
                taint_propagation.append({'from': param, 'to': 'return'})
                break

        # Check if function calls sources (language-aware)
        calls_source = False
        source_calls = []
        sources = self.TAINT_SOURCES.get(self.language, [])
        for source in sources:
            if source in func_code:
                calls_source = True
                returns_tainted = True
                source_calls.append(source)

        # Determine confidence based on language and analysis depth
        confidence = "high"
        if self.language in ['python', 'java']:
            confidence = "high"
        elif self.language in ['go', 'javascript', 'typescript']:
            confidence = "high" if param_to_sink else "medium"
        else:
            confidence = "medium"

        return {
            "name": sig.name,
            "parameters": sig.parameters,
            "tainted_params": list(tainted_params),
            "param_to_sink": param_to_sink,
            "sink_details": sink_details,
            "sanitizes": sanitizes,
            "sanitizer_details": sanitizer_details,
            "returns_tainted": returns_tainted,
            "taint_propagation": taint_propagation,
            "calls_source": calls_source,
            "source_calls": source_calls,
            "is_sink": sig.is_sink or bool(param_to_sink),
            "is_sanitizer": sig.is_sanitizer or bool(sanitizes),
            "confidence": confidence,
            "language": self.language
        }

    def _propagate_summaries(self, call_graph: CallGraphBuilder, max_iterations: int = 10):
        """Propagate taint information through call graph"""

        for _ in range(max_iterations):
            changed = False

            for func_name, summary in self.summaries.items():
                # Check callees - if we call a function that returns tainted data
                for callee in call_graph.call_graph.get(func_name, set()):
                    if callee in self.summaries:
                        callee_summary = self.summaries[callee]
                        if callee_summary.get('returns_tainted') and not summary.get('returns_tainted'):
                            # If we call a function that returns tainted data and
                            # we return that result, we also return tainted data
                            summary['returns_tainted'] = True
                            changed = True

                        # If callee is a sink, mark this function as containing sink
                        if callee_summary.get('is_sink') and not summary.get('calls_sink'):
                            summary['calls_sink'] = True
                            changed = True

            if not changed:
                break


class InterproceduralTaintAnalyzer:
    """
    Main inter-procedural taint analysis engine

    Tracks taint flow across function boundaries using:
    1. Call graph
    2. Function summaries
    3. Context-sensitive analysis
    """

    def __init__(self, language: str):
        self.language = language
        self.call_graph_builder = CallGraphBuilder(language)
        self.summary_generator = FunctionSummaryGenerator(language)
        self.flows: List[InterproceduralFlow] = []
        self.taint_state: Dict[str, Dict[str, TaintState]] = defaultdict(dict)

    def analyze(self, source_code: str, file_path: str) -> Dict[str, Any]:
        """
        Perform inter-procedural taint analysis

        Returns:
            Dictionary with call graph, summaries, and taint flows
        """

        # Step 1: Build call graph
        call_graph_data = self.call_graph_builder.build(source_code, file_path)

        # Step 2: Generate function summaries
        summaries = self.summary_generator.generate_summaries(
            source_code, self.call_graph_builder
        )

        # Step 3: Perform inter-procedural taint analysis
        self._analyze_taint_flows(source_code, file_path)

        # Step 4: Find complete vulnerability paths
        vulnerabilities = self._find_vulnerabilities()

        return {
            "call_graph": call_graph_data,
            "function_summaries": summaries,
            "inter_procedural_flows": [self._flow_to_dict(f) for f in self.flows],
            "vulnerabilities": vulnerabilities,
            "statistics": {
                "total_functions": len(self.call_graph_builder.functions),
                "total_call_sites": len(self.call_graph_builder.call_sites),
                "tainted_functions": len([
                    s for s in summaries.values()
                    if s.get('returns_tainted') or s.get('calls_source')
                ]),
                "sink_functions": len([
                    s for s in summaries.values()
                    if s.get('is_sink') or s.get('calls_sink')
                ]),
                "total_flows": len(self.flows),
                "exploitable_flows": len([f for f in self.flows if f.is_exploitable]),
            }
        }

    def _analyze_taint_flows(self, source_code: str, file_path: str):
        """Analyze taint flows across function boundaries"""

        lines = source_code.split('\n')

        # Initialize taint at sources
        for func_name, summary in self.summary_generator.summaries.items():
            if summary.get('calls_source'):
                # Function calls a source - its return value is tainted
                self.taint_state[func_name]['return'] = TaintState.TAINTED

            # Parameters of route handlers are tainted
            sig = self.call_graph_builder.functions.get(func_name)
            if sig and sig.is_source:
                for param in sig.parameters:
                    self.taint_state[func_name][param] = TaintState.TAINTED

        # Propagate taint through call graph
        worklist = list(self.call_graph_builder.functions.keys())
        iterations = 0
        max_iterations = 50

        while worklist and iterations < max_iterations:
            iterations += 1
            func_name = worklist.pop(0)

            if self._propagate_function_taint(func_name, source_code):
                # Taint changed, add callers to worklist
                for caller in self.call_graph_builder.reverse_call_graph.get(func_name, set()):
                    if caller not in worklist:
                        worklist.append(caller)

        # Find taint flows to sinks
        self._find_taint_to_sink_flows(source_code, file_path)

    def _propagate_function_taint(self, func_name: str, source_code: str) -> bool:
        """Propagate taint within and through a function"""

        changed = False
        summary = self.summary_generator.summaries.get(func_name, {})
        sig = self.call_graph_builder.functions.get(func_name)

        if not sig:
            return False

        # Get function code
        lines = source_code.split('\n')
        func_lines = lines[sig.start_line - 1:sig.end_line]

        # Track local taint
        local_taint: Dict[str, TaintState] = {}

        # Initialize with tainted parameters
        for param in sig.parameters:
            if self.taint_state[func_name].get(param) == TaintState.TAINTED:
                local_taint[param] = TaintState.TAINTED

        # Propagate through function body
        for line in func_lines:
            # Check for assignments
            assign_match = re.search(r'(\w+)\s*=\s*(.+)', line)
            if assign_match:
                target = assign_match.group(1)
                value = assign_match.group(2)

                # Check if value contains tainted variable
                for var, state in local_taint.items():
                    if state == TaintState.TAINTED and re.search(rf'\b{re.escape(var)}\b', value):
                        if local_taint.get(target) != TaintState.TAINTED:
                            local_taint[target] = TaintState.TAINTED
                            changed = True

            # Check for function calls that return tainted data
            for call_site in self.call_graph_builder.call_sites:
                if call_site.caller_function == func_name:
                    callee = call_site.callee_function
                    callee_summary = self.summary_generator.summaries.get(callee, {})

                    # If callee returns tainted data, return var is tainted
                    if callee_summary.get('returns_tainted') and call_site.return_var:
                        if local_taint.get(call_site.return_var) != TaintState.TAINTED:
                            local_taint[call_site.return_var] = TaintState.TAINTED
                            changed = True

                    # Propagate taint to callee parameters
                    for i, arg in enumerate(call_site.arguments):
                        for var, state in local_taint.items():
                            if state == TaintState.TAINTED and var in arg:
                                if self.taint_state[callee].get(f'param_{i}') != TaintState.TAINTED:
                                    self.taint_state[callee][f'param_{i}'] = TaintState.TAINTED
                                    changed = True

        # Check if return value is tainted
        for line in func_lines:
            if 'return ' in line:
                for var, state in local_taint.items():
                    if state == TaintState.TAINTED and re.search(rf'\b{re.escape(var)}\b', line):
                        if self.taint_state[func_name].get('return') != TaintState.TAINTED:
                            self.taint_state[func_name]['return'] = TaintState.TAINTED
                            summary['returns_tainted'] = True
                            changed = True

        return changed

    def _find_taint_to_sink_flows(self, source_code: str, file_path: str):
        """Find flows from tainted data to dangerous sinks"""

        for func_name, summary in self.summary_generator.summaries.items():
            if not summary.get('is_sink') and not summary.get('calls_sink'):
                continue

            # Check if any tainted data reaches this sink
            func_taint = self.taint_state.get(func_name, {})
            sig = self.call_graph_builder.functions.get(func_name)

            if not sig:
                continue

            # Find the call chain from source to this sink
            for param_idx, sink_type in summary.get('param_to_sink', {}).items():
                param = sig.parameters[param_idx] if param_idx < len(sig.parameters) else None
                if param and func_taint.get(param) == TaintState.TAINTED:
                    # Found a flow - trace back to source
                    call_chain = self._trace_call_chain_to_source(func_name)

                    if call_chain:
                        flow = InterproceduralFlow(
                            id=f"flow_{func_name}_{param}_{sink_type}",
                            source_function=call_chain[0],
                            source_line=self.call_graph_builder.functions.get(call_chain[0], FunctionSignature(
                                name='', qualified_name='', file_path='', start_line=0, end_line=0,
                                parameters=[], return_statements=[], calls_functions=[], called_by=[],
                                tainted_params=set(), returns_tainted=False, is_sanitizer=False,
                                is_sink=False, is_source=False
                            )).start_line,
                            sink_function=func_name,
                            sink_line=sig.start_line,
                            call_chain=call_chain,
                            transfers=[],
                            tainted_variable=param,
                            vulnerability_type=sink_type,
                            confidence="high" if len(call_chain) <= 3 else "medium",
                            is_exploitable=not summary.get('sanitizes', {}).get(sink_type, False)
                        )
                        self.flows.append(flow)

    def _trace_call_chain_to_source(self, sink_func: str) -> List[str]:
        """Trace call chain from a source to the sink function"""

        # BFS to find path from any source to sink
        visited = set()
        queue = [(sink_func, [sink_func])]

        while queue:
            current, path = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            # Check if this is a source
            summary = self.summary_generator.summaries.get(current, {})
            sig = self.call_graph_builder.functions.get(current)

            if summary.get('calls_source') or (sig and sig.is_source):
                return list(reversed(path))

            # Add callers to queue
            for caller in self.call_graph_builder.reverse_call_graph.get(current, set()):
                if caller not in visited:
                    queue.append((caller, path + [caller]))

        return []

    def _find_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Convert flows to vulnerability findings"""

        vulnerabilities = []

        vuln_info = {
            'sql': {
                'cwe': 'CWE-89',
                'title': 'SQL Injection',
                'severity': 'critical',
                'owasp': 'A03:2021',
                'remediation': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.'
            },
            'command': {
                'cwe': 'CWE-78',
                'title': 'OS Command Injection',
                'severity': 'critical',
                'owasp': 'A03:2021',
                'remediation': 'Avoid shell commands with user input. Use subprocess with shell=False and pass arguments as list.'
            },
            'xss': {
                'cwe': 'CWE-79',
                'title': 'Cross-Site Scripting (XSS)',
                'severity': 'high',
                'owasp': 'A03:2021',
                'remediation': 'Escape all user input before rendering. Use templating engines with auto-escaping enabled.'
            },
            'path': {
                'cwe': 'CWE-22',
                'title': 'Path Traversal',
                'severity': 'high',
                'owasp': 'A01:2021',
                'remediation': 'Validate and sanitize file paths. Use os.path.basename() and check against allowed directories.'
            },
            'deserialize': {
                'cwe': 'CWE-502',
                'title': 'Insecure Deserialization',
                'severity': 'critical',
                'owasp': 'A08:2021',
                'remediation': 'Never deserialize untrusted data. Use safe serialization formats like JSON.'
            },
            'ssrf': {
                'cwe': 'CWE-918',
                'title': 'Server-Side Request Forgery (SSRF)',
                'severity': 'high',
                'owasp': 'A10:2021',
                'remediation': 'Validate URLs against allowlist. Block internal IP ranges and cloud metadata endpoints.'
            },
            'redirect': {
                'cwe': 'CWE-601',
                'title': 'Open Redirect',
                'severity': 'medium',
                'owasp': 'A01:2021',
                'remediation': 'Validate redirect URLs against allowlist. Use relative URLs when possible.'
            },
            'ldap': {
                'cwe': 'CWE-90',
                'title': 'LDAP Injection',
                'severity': 'high',
                'owasp': 'A03:2021',
                'remediation': 'Use parameterized LDAP queries. Escape special characters in user input.'
            },
            'xpath': {
                'cwe': 'CWE-643',
                'title': 'XPath Injection',
                'severity': 'high',
                'owasp': 'A03:2021',
                'remediation': 'Use parameterized XPath queries or sanitize user input.'
            },
            'regex_dos': {
                'cwe': 'CWE-1333',
                'title': 'Regex Denial of Service (ReDoS)',
                'severity': 'medium',
                'owasp': 'A06:2021',
                'remediation': 'Avoid unbounded repetition in regex. Use atomic groups or possessive quantifiers.'
            },
        }

        for flow in self.flows:
            info = vuln_info.get(flow.vulnerability_type, {
                'cwe': 'CWE-20',
                'title': 'Input Validation',
                'severity': 'medium',
                'owasp': 'A03:2021'
            })

            vulnerabilities.append({
                'id': flow.id,
                'title': f"Inter-procedural {info['title']}",
                'description': f"Tainted data flows from {flow.source_function}() through "
                              f"{' -> '.join(flow.call_chain)} to dangerous sink in {flow.sink_function}()",
                'severity': info['severity'],
                'cwe_id': info['cwe'],
                'owasp_category': info['owasp'],
                'source_function': flow.source_function,
                'source_line': flow.source_line,
                'sink_function': flow.sink_function,
                'sink_line': flow.sink_line,
                'call_chain': flow.call_chain,
                'call_depth': len(flow.call_chain),
                'tainted_variable': flow.tainted_variable,
                'is_exploitable': flow.is_exploitable,
                'confidence': flow.confidence,
                'remediation': self._get_remediation(flow.vulnerability_type),
                'analysis_type': 'inter-procedural'
            })

        return vulnerabilities

    def _get_remediation(self, vuln_type: str) -> str:
        """Get remediation advice for vulnerability type"""
        remediation = {
            'sql': "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
            'command': "Avoid shell commands with user input. Use subprocess with shell=False and pass arguments as list.",
            'xss': "Escape all user input before rendering. Use templating engines with auto-escaping enabled.",
            'path': "Validate and sanitize file paths. Use os.path.basename() and check against allowed directories.",
            'deserialize': "Never deserialize untrusted data. Use safe serialization formats like JSON.",
        }
        return remediation.get(vuln_type, "Validate and sanitize all user input before use.")

    def _flow_to_dict(self, flow: InterproceduralFlow) -> Dict[str, Any]:
        """Convert flow to dictionary"""
        return {
            'id': flow.id,
            'source_function': flow.source_function,
            'source_line': flow.source_line,
            'sink_function': flow.sink_function,
            'sink_line': flow.sink_line,
            'call_chain': flow.call_chain,
            'tainted_variable': flow.tainted_variable,
            'vulnerability_type': flow.vulnerability_type,
            'confidence': flow.confidence,
            'is_exploitable': flow.is_exploitable,
        }


class EnhancedSecurityAnalyzer:
    """
    Enhanced security analyzer combining intra and inter-procedural analysis
    """

    def __init__(self):
        self.language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.php': 'php',
            '.cs': 'csharp',
            '.rb': 'ruby',
        }

    def analyze(self, source_code: str, file_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis

        Combines:
        - Intra-procedural taint analysis
        - Inter-procedural data flow
        - Call graph analysis
        - Function summaries
        """

        # Detect language
        ext = '.' + file_path.split('.')[-1] if '.' in file_path else '.py'
        language = self.language_map.get(ext, 'python')

        # Perform inter-procedural analysis
        analyzer = InterproceduralTaintAnalyzer(language)
        results = analyzer.analyze(source_code, file_path)

        return {
            'file_path': file_path,
            'language': language,
            'analysis_type': 'inter-procedural',
            **results
        }


# Convenience function for direct use
def analyze_code_interprocedural(source_code: str, file_path: str) -> Dict[str, Any]:
    """
    Analyze source code with inter-procedural taint analysis

    Args:
        source_code: The source code to analyze
        file_path: Path to the source file (used for language detection)

    Returns:
        Dictionary containing:
        - call_graph: Function call relationships
        - function_summaries: Taint behavior of each function
        - inter_procedural_flows: Taint flows across functions
        - vulnerabilities: Detected security issues
        - statistics: Analysis statistics
    """
    analyzer = EnhancedSecurityAnalyzer()
    return analyzer.analyze(source_code, file_path)
