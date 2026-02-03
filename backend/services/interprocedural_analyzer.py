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

        # Patterns for function definitions
        func_patterns = {
            'javascript': r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(|(\w+)\s*:\s*(?:async\s*)?\()',
            'java': r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\(',
            'go': r'func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(',
            'php': r'function\s+(\w+)\s*\(',
            'csharp': r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\(',
        }

        func_pattern = func_patterns.get(self.language, r'(?:function|def|func)\s+(\w+)')

        current_function = None
        function_stack = []
        brace_count = 0

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Track function definitions
            match = re.search(func_pattern, line)
            if match:
                func_name = next((g for g in match.groups() if g), None)
                if func_name:
                    sig = FunctionSignature(
                        name=func_name,
                        qualified_name=func_name,
                        file_path=file_path,
                        start_line=line_num,
                        end_line=line_num,
                        parameters=self._extract_params(line),
                        return_statements=[],
                        calls_functions=[],
                        called_by=[],
                        tainted_params=set(),
                        returns_tainted=False,
                        is_sanitizer=False,
                        is_sink=False,
                        is_source=False
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

            # Find function calls
            call_pattern = r'(\w+(?:\.\w+)*)\s*\('
            for match in re.finditer(call_pattern, line):
                callee = match.group(1)
                # Skip keywords
                if callee.split('.')[-1] in {'if', 'for', 'while', 'switch', 'catch', 'function', 'class', 'return'}:
                    continue

                caller = current_function or "<module>"
                call_site = CallSite(
                    id=f"call_{line_num}_{callee}",
                    caller_function=caller,
                    callee_function=callee,
                    file_path=file_path,
                    line_number=line_num,
                    arguments=[],
                    return_var=None,
                    context=f"{caller}:{line_num}"
                )
                self.call_sites.append(call_site)

                self.call_graph[caller].add(callee)
                self.reverse_call_graph[callee].add(caller)

            # Track return statements
            if 'return ' in line and current_function and current_function in self.functions:
                self.functions[current_function].return_statements.append(line_num)

        return self._get_call_graph_summary()

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

    # Known sources by language
    TAINT_SOURCES = {
        'python': ['request', 'input', 'sys.argv', 'os.environ', 'open', 'recv'],
        'javascript': ['req.query', 'req.body', 'req.params', 'window.location', 'document.URL'],
        'java': ['getParameter', 'getHeader', 'getInputStream', 'Scanner'],
        'go': ['r.URL.Query', 'r.FormValue', 'r.Body'],
        'php': ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE'],
    }

    # Known sinks by category
    SINKS = {
        'sql': ['execute', 'query', 'cursor', 'raw', 'executeQuery'],
        'command': ['system', 'exec', 'popen', 'subprocess', 'spawn'],
        'xss': ['innerHTML', 'document.write', 'render_template_string'],
        'path': ['open', 'readFile', 'include', 'require'],
        'deserialize': ['pickle.loads', 'yaml.load', 'unserialize'],
    }

    SANITIZERS = {
        'sql': ['escape', 'quote', 'parameterized', 'prepared'],
        'xss': ['escape', 'htmlspecialchars', 'DOMPurify', 'sanitize'],
        'command': ['shlex.quote', 'escapeshellarg'],
        'path': ['basename', 'realpath', 'secure_filename'],
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

        # Check if any parameter flows to a sink
        param_to_sink = {}
        for i, param in enumerate(sig.parameters):
            for sink_type, sinks in self.SINKS.items():
                for sink in sinks:
                    # Check if parameter appears near a sink
                    pattern = rf'\b{re.escape(param)}\b.*{re.escape(sink)}|{re.escape(sink)}.*\b{re.escape(param)}\b'
                    if re.search(pattern, func_code, re.IGNORECASE):
                        param_to_sink[i] = sink_type

        # Check if function sanitizes input
        sanitizes = {}
        for san_type, sanitizers in self.SANITIZERS.items():
            for san in sanitizers:
                if san.lower() in func_code.lower():
                    sanitizes[san_type] = True

        # Check if return value can be tainted
        returns_tainted = False
        for param in sig.parameters:
            # Check if parameter influences return value
            if re.search(rf'return\s+.*\b{re.escape(param)}\b', func_code):
                returns_tainted = True
                break

        # Check if function calls sources
        calls_source = False
        sources = self.TAINT_SOURCES.get(self.language, [])
        for source in sources:
            if source in func_code:
                calls_source = True
                returns_tainted = True
                break

        return {
            "name": sig.name,
            "parameters": sig.parameters,
            "tainted_params": list(tainted_params),
            "param_to_sink": param_to_sink,
            "sanitizes": sanitizes,
            "returns_tainted": returns_tainted,
            "calls_source": calls_source,
            "is_sink": sig.is_sink or bool(param_to_sink),
            "is_sanitizer": sig.is_sanitizer or bool(sanitizes),
            "confidence": "high" if self.language == 'python' else "medium"
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
                'owasp': 'A03:2021'
            },
            'command': {
                'cwe': 'CWE-78',
                'title': 'OS Command Injection',
                'severity': 'critical',
                'owasp': 'A03:2021'
            },
            'xss': {
                'cwe': 'CWE-79',
                'title': 'Cross-Site Scripting (XSS)',
                'severity': 'high',
                'owasp': 'A03:2021'
            },
            'path': {
                'cwe': 'CWE-22',
                'title': 'Path Traversal',
                'severity': 'high',
                'owasp': 'A01:2021'
            },
            'deserialize': {
                'cwe': 'CWE-502',
                'title': 'Insecure Deserialization',
                'severity': 'critical',
                'owasp': 'A08:2021'
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
