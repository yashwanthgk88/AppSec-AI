"""
CVE Reachability Analyzer
Analyzes whether vulnerable functions identified by CVEs are actually used in target code.
Provides exploitability assessment based on actual code usage patterns.

This analyzer:
1. Tracks import aliases precisely (e.g., `const _ = require('lodash')`)
2. Only matches vulnerable function calls using the actual imported alias
3. Provides exact line numbers and code snippets
4. Reports high-confidence matches only
"""
import re
import os
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ExploitabilityLevel(Enum):
    """Levels of exploitability based on code reachability analysis"""
    EXPLOITABLE = "exploitable"      # Vulnerable function is actively called
    POTENTIALLY_EXPLOITABLE = "potentially_exploitable"  # Package imported, function may be called dynamically
    IMPORTED_ONLY = "imported_only"  # Package imported but vulnerable functions not used
    NOT_REACHABLE = "not_reachable"  # Package/vulnerable code not found in codebase


@dataclass
class ImportInfo:
    """Detailed information about a package import"""
    file_path: str
    line_number: int
    import_statement: str
    alias: str  # The variable name used (e.g., '_' for lodash, 'axios' for axios)
    import_style: str  # 'default', 'named', 'namespace', 'require'
    named_imports: List[str] = field(default_factory=list)  # For destructured imports


@dataclass
class VulnerableFunctionUsage:
    """Precise information about a vulnerable function usage"""
    function_name: str
    full_call: str  # e.g., "_.defaultsDeep" or "axios.get"
    file_path: str
    line_number: int
    code_line: str  # The exact line of code
    code_context: str  # Surrounding lines for context
    arguments: str  # The arguments passed to the function
    confidence: str  # high, medium, low
    import_info: Optional[ImportInfo] = None


@dataclass
class ReachabilityResult:
    """Result of reachability analysis for a CVE"""
    cve_id: str
    package: str
    exploitability: ExploitabilityLevel
    vulnerable_functions_used: List[VulnerableFunctionUsage]
    import_locations: List[ImportInfo]
    attack_vector: str
    recommendation: str
    confidence_score: float  # 0.0 to 1.0


class CVEVulnerableFunctionsDB:
    """
    Database of vulnerable functions per CVE.
    Maps CVEs to their specific vulnerable function signatures.
    """

    CVE_FUNCTIONS: Dict[str, Dict[str, Any]] = {
        # ==================== LODASH CVEs ====================
        "CVE-2020-8203": {
            "package": "lodash",
            "ecosystem": "npm",
            "common_aliases": ["_", "lodash", "lo"],
            "vulnerable_functions": [
                "defaultsDeep", "merge", "mergeWith", "zipObjectDeep",
                "set", "setWith", "update", "updateWith"
            ],
            "attack_vector": "Prototype pollution via __proto__ property manipulation in nested object merging",
            "exploit_indicators": ["__proto__", "constructor.prototype", "Object.prototype"],
            "severity": "high",
            "fixed_version": "4.17.21"
        },
        "CVE-2019-10744": {
            "package": "lodash",
            "ecosystem": "npm",
            "common_aliases": ["_", "lodash", "lo"],
            "vulnerable_functions": ["defaultsDeep"],
            "attack_vector": "Prototype pollution via defaultsDeep function",
            "exploit_indicators": ["__proto__", "constructor"],
            "severity": "critical",
            "fixed_version": "4.17.12"
        },

        # ==================== EXPRESS CVEs ====================
        "CVE-2022-24999": {
            "package": "express",
            "ecosystem": "npm",
            "common_aliases": ["express", "app"],
            "vulnerable_functions": [],  # Express itself isn't called, it's the qs parser
            "middleware_indicators": ["urlencoded", "bodyParser"],
            "attack_vector": "DoS via deeply nested query string parsing (qs library)",
            "exploit_indicators": ["urlencoded", "extended: true"],
            "severity": "high",
            "fixed_version": "4.17.3",
            "note": "Vulnerability is in qs transitive dependency, triggered by urlencoded middleware"
        },

        # ==================== AXIOS CVEs ====================
        "CVE-2021-3749": {
            "package": "axios",
            "ecosystem": "npm",
            "common_aliases": ["axios", "http", "api", "client"],
            "vulnerable_functions": ["get", "post", "put", "delete", "patch", "request", "create"],
            "attack_vector": "SSRF via improper redirect handling - follows redirects to internal IPs",
            "exploit_indicators": ["maxRedirects", "http://", "https://"],
            "severity": "medium",
            "fixed_version": "0.21.2"
        },
        "CVE-2023-45857": {
            "package": "axios",
            "ecosystem": "npm",
            "common_aliases": ["axios", "http", "api", "client"],
            "vulnerable_functions": ["get", "post", "put", "delete", "patch", "request"],
            "attack_vector": "CSRF vulnerability in browser environments",
            "exploit_indicators": ["withCredentials"],
            "severity": "medium",
            "fixed_version": "1.6.0"
        },

        # ==================== JSONWEBTOKEN CVEs ====================
        "CVE-2022-23529": {
            "package": "jsonwebtoken",
            "ecosystem": "npm",
            "common_aliases": ["jwt", "jsonwebtoken", "token"],
            "vulnerable_functions": ["verify", "decode"],
            "attack_vector": "JWT signature verification bypass via algorithm confusion",
            "exploit_indicators": ["algorithms", "secretOrPublicKey", "none"],
            "severity": "high",
            "fixed_version": "9.0.0"
        },

        # ==================== MINIMIST CVEs ====================
        "CVE-2021-44906": {
            "package": "minimist",
            "ecosystem": "npm",
            "common_aliases": ["minimist", "argv", "args", "parseArgs"],
            "vulnerable_functions": ["parse"],  # Usually called as minimist(args)
            "call_patterns": [r"\bminimist\s*\(", r"parseArgs\s*\("],
            "attack_vector": "Prototype pollution via command-line argument parsing",
            "exploit_indicators": ["__proto__", "prototype"],
            "severity": "critical",
            "fixed_version": "1.2.6"
        },

        # ==================== QS CVEs ====================
        "CVE-2022-24999-qs": {
            "package": "qs",
            "ecosystem": "npm",
            "common_aliases": ["qs", "querystring"],
            "vulnerable_functions": ["parse", "stringify"],
            "attack_vector": "Prototype pollution via deep object parsing",
            "exploit_indicators": ["allowPrototypes", "depth", "__proto__"],
            "severity": "high",
            "fixed_version": "6.5.3"
        },

        # ==================== FOLLOW-REDIRECTS CVEs ====================
        "CVE-2022-0155": {
            "package": "follow-redirects",
            "ecosystem": "npm",
            "common_aliases": ["follow-redirects", "followRedirects"],
            "vulnerable_functions": ["http.request", "https.request"],
            "attack_vector": "Cookie exposure via cross-origin redirects",
            "exploit_indicators": ["maxRedirects", "beforeRedirect"],
            "severity": "medium",
            "fixed_version": "1.14.7"
        },

        # ==================== PYTHON PACKAGE CVEs ====================
        "CVE-2021-28363": {
            "package": "urllib3",
            "ecosystem": "pip",
            "common_aliases": ["urllib3"],
            "vulnerable_functions": ["request", "urlopen", "HTTPConnectionPool", "PoolManager"],
            "attack_vector": "HTTPS certificate validation bypass",
            "exploit_indicators": ["cert_reqs", "CERT_NONE", "assert_hostname=False"],
            "severity": "medium",
            "fixed_version": "1.26.5"
        },
        "CVE-2023-32681": {
            "package": "requests",
            "ecosystem": "pip",
            "common_aliases": ["requests", "req", "r"],
            "vulnerable_functions": ["get", "post", "put", "delete", "patch", "request", "Session"],
            "attack_vector": "Sensitive header leakage on cross-origin redirect",
            "exploit_indicators": ["allow_redirects", "auth", "headers"],
            "severity": "medium",
            "fixed_version": "2.31.0"
        },
        "CVE-2019-19844": {
            "package": "django",
            "ecosystem": "pip",
            "common_aliases": ["django"],
            "vulnerable_functions": ["PasswordResetForm"],
            "attack_vector": "Account takeover via password reset email hijacking",
            "exploit_indicators": ["PasswordResetForm", "email"],
            "severity": "critical",
            "fixed_version": "3.0.1"
        },

        # ==================== JAVA PACKAGE CVEs ====================
        "CVE-2021-44228": {
            "package": "log4j-core",
            "ecosystem": "maven",
            "common_aliases": ["logger", "log", "LOG"],
            "vulnerable_functions": ["info", "error", "warn", "debug", "fatal", "trace", "log"],
            "attack_vector": "Remote code execution via JNDI lookup in log messages",
            "exploit_indicators": ["${jndi:", "ldap://", "rmi://", "${env:"],
            "severity": "critical",
            "fixed_version": "2.17.0"
        },
        "CVE-2022-22965": {
            "package": "spring-beans",
            "ecosystem": "maven",
            "common_aliases": [],
            "vulnerable_functions": [],
            "annotation_indicators": ["@RequestMapping", "@GetMapping", "@PostMapping", "@ModelAttribute"],
            "attack_vector": "Spring4Shell - RCE via data binding",
            "exploit_indicators": ["class.module.classLoader"],
            "severity": "critical",
            "fixed_version": "5.3.18"
        },

        # ==================== GO PACKAGE CVEs ====================
        "CVE-2022-27664": {
            "package": "golang.org/x/net",
            "ecosystem": "go",
            "common_aliases": ["http2"],
            "vulnerable_functions": ["Server", "Transport", "ConfigureServer"],
            "attack_vector": "DoS via HTTP/2 RST_STREAM flood",
            "exploit_indicators": ["http2.Server", "http2.Transport"],
            "severity": "high",
            "fixed_version": "0.0.0-20220906165146-f3363e06e74c"
        },
    }

    @classmethod
    def get_cve_info(cls, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get vulnerable function info for a CVE"""
        return cls.CVE_FUNCTIONS.get(cve_id)

    @classmethod
    def get_package_cves(cls, package_name: str) -> List[str]:
        """Get all CVEs for a package"""
        return [
            cve_id for cve_id, info in cls.CVE_FUNCTIONS.items()
            if info["package"].lower() == package_name.lower()
        ]


class PreciseReachabilityAnalyzer:
    """
    Precise reachability analyzer that tracks exact import aliases
    and only matches vulnerable function calls using those aliases.
    """

    SCANNABLE_EXTENSIONS = {
        "npm": [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
        "pip": [".py"],
        "maven": [".java", ".kt", ".scala"],
        "gradle": [".java", ".kt", ".scala"],
        "go": [".go"],
        "cargo": [".rs"],
        "composer": [".php"],
        "bundler": [".rb"],
        "nuget": [".cs", ".vb", ".fs"],
    }

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self._file_cache: Dict[str, str] = {}
        self._import_cache: Dict[str, List[ImportInfo]] = {}

    def analyze_cve(self, cve_id: str, ecosystem: str = "npm") -> Optional[ReachabilityResult]:
        """
        Analyze code reachability for a specific CVE with precise matching.
        """
        cve_info = CVEVulnerableFunctionsDB.get_cve_info(cve_id)
        if not cve_info:
            logger.warning(f"[Reachability] No CVE info for {cve_id}")
            return None

        package = cve_info["package"]
        extensions = self.SCANNABLE_EXTENSIONS.get(ecosystem, [".js", ".ts", ".py"])

        # Step 1: Find all imports of this package and track aliases
        imports = self._find_package_imports(package, extensions, ecosystem)

        if not imports:
            return ReachabilityResult(
                cve_id=cve_id,
                package=package,
                exploitability=ExploitabilityLevel.NOT_REACHABLE,
                vulnerable_functions_used=[],
                import_locations=[],
                attack_vector=cve_info["attack_vector"],
                recommendation=f"Package '{package}' is not imported. No immediate risk, but update for defense in depth.",
                confidence_score=0.95
            )

        # Step 2: Find vulnerable function usages using the exact aliases
        vulnerable_usages = self._find_vulnerable_function_usages(
            imports,
            cve_info.get("vulnerable_functions", []),
            cve_info.get("call_patterns", []),
            cve_info.get("middleware_indicators", []),
            extensions,
            ecosystem
        )

        # Step 3: Check for exploit indicators
        exploit_indicators = cve_info.get("exploit_indicators", [])
        has_exploit_indicators = self._check_exploit_indicators(exploit_indicators, extensions)

        # Step 4: Determine exploitability level
        if vulnerable_usages:
            if has_exploit_indicators:
                exploitability = ExploitabilityLevel.EXPLOITABLE
                confidence = 0.95
                recommendation = (
                    f"CRITICAL: Vulnerable functions from '{package}' are actively used with "
                    f"exploit indicators detected. Immediate upgrade to {cve_info.get('fixed_version', 'latest')} required. "
                    f"Attack vector: {cve_info['attack_vector']}"
                )
            else:
                exploitability = ExploitabilityLevel.POTENTIALLY_EXPLOITABLE
                confidence = 0.85
                recommendation = (
                    f"HIGH RISK: Vulnerable functions from '{package}' are used in code. "
                    f"Upgrade to {cve_info.get('fixed_version', 'latest')} immediately. "
                    f"Attack vector: {cve_info['attack_vector']}"
                )
        else:
            exploitability = ExploitabilityLevel.IMPORTED_ONLY
            confidence = 0.75
            recommendation = (
                f"MEDIUM: Package '{package}' is imported but specific vulnerable functions "
                f"are not directly called. Still recommended to upgrade to {cve_info.get('fixed_version', 'latest')}. "
                f"Attack vector: {cve_info['attack_vector']}"
            )

        return ReachabilityResult(
            cve_id=cve_id,
            package=package,
            exploitability=exploitability,
            vulnerable_functions_used=vulnerable_usages,
            import_locations=imports,
            attack_vector=cve_info["attack_vector"],
            recommendation=recommendation,
            confidence_score=confidence
        )

    def _find_package_imports(
        self,
        package: str,
        extensions: List[str],
        ecosystem: str
    ) -> List[ImportInfo]:
        """Find all imports of a package and extract the alias used."""
        imports = []
        package_lower = package.lower()

        for file_path in self._get_scannable_files(extensions):
            content = self._read_file(file_path)
            if not content:
                continue

            lines = content.split('\n')
            rel_path = str(file_path.relative_to(self.project_path))

            for line_num, line in enumerate(lines, 1):
                # JavaScript/TypeScript imports
                if ecosystem in ["npm"]:
                    import_info = self._parse_js_import(line, package_lower, rel_path, line_num)
                    if import_info:
                        imports.append(import_info)

                # Python imports
                elif ecosystem in ["pip"]:
                    import_info = self._parse_python_import(line, package_lower, rel_path, line_num)
                    if import_info:
                        imports.append(import_info)

                # Go imports
                elif ecosystem in ["go"]:
                    import_info = self._parse_go_import(line, package_lower, rel_path, line_num)
                    if import_info:
                        imports.append(import_info)

                # Java imports
                elif ecosystem in ["maven", "gradle"]:
                    import_info = self._parse_java_import(line, package_lower, rel_path, line_num)
                    if import_info:
                        imports.append(import_info)

        return imports

    def _parse_js_import(self, line: str, package: str, file_path: str, line_num: int) -> Optional[ImportInfo]:
        """Parse JavaScript/TypeScript import statement."""
        line_stripped = line.strip()

        # require() style: const _ = require('lodash')
        require_match = re.search(
            rf"(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['\"]({re.escape(package)})['\"]",
            line_stripped, re.IGNORECASE
        )
        if require_match:
            return ImportInfo(
                file_path=file_path,
                line_number=line_num,
                import_statement=line_stripped,
                alias=require_match.group(1),
                import_style="require"
            )

        # ES6 default import: import axios from 'axios'
        default_import_match = re.search(
            rf"import\s+(\w+)\s+from\s+['\"]({re.escape(package)})['\"]",
            line_stripped, re.IGNORECASE
        )
        if default_import_match:
            return ImportInfo(
                file_path=file_path,
                line_number=line_num,
                import_statement=line_stripped,
                alias=default_import_match.group(1),
                import_style="default"
            )

        # ES6 namespace import: import * as _ from 'lodash'
        namespace_import_match = re.search(
            rf"import\s+\*\s+as\s+(\w+)\s+from\s+['\"]({re.escape(package)})['\"]",
            line_stripped, re.IGNORECASE
        )
        if namespace_import_match:
            return ImportInfo(
                file_path=file_path,
                line_number=line_num,
                import_statement=line_stripped,
                alias=namespace_import_match.group(1),
                import_style="namespace"
            )

        # ES6 named import: import { merge, defaultsDeep } from 'lodash'
        named_import_match = re.search(
            rf"import\s+\{{\s*([^}}]+)\s*\}}\s+from\s+['\"]({re.escape(package)})['\"]",
            line_stripped, re.IGNORECASE
        )
        if named_import_match:
            named_imports = [n.strip().split(' as ')[-1].strip()
                           for n in named_import_match.group(1).split(',')]
            return ImportInfo(
                file_path=file_path,
                line_number=line_num,
                import_statement=line_stripped,
                alias="",  # No single alias for named imports
                import_style="named",
                named_imports=named_imports
            )

        return None

    def _parse_python_import(self, line: str, package: str, file_path: str, line_num: int) -> Optional[ImportInfo]:
        """Parse Python import statement."""
        line_stripped = line.strip()

        # import requests as req
        alias_import = re.search(
            rf"import\s+({re.escape(package)})\s+as\s+(\w+)",
            line_stripped, re.IGNORECASE
        )
        if alias_import:
            return ImportInfo(
                file_path=file_path,
                line_number=line_num,
                import_statement=line_stripped,
                alias=alias_import.group(2),
                import_style="alias"
            )

        # import requests
        simple_import = re.search(
            rf"^import\s+({re.escape(package)})(?:\s|$|,)",
            line_stripped, re.IGNORECASE
        )
        if simple_import:
            return ImportInfo(
                file_path=file_path,
                line_number=line_num,
                import_statement=line_stripped,
                alias=simple_import.group(1),
                import_style="simple"
            )

        # from requests import get, post
        from_import = re.search(
            rf"from\s+({re.escape(package)})\s+import\s+(.+)",
            line_stripped, re.IGNORECASE
        )
        if from_import:
            named_imports = [n.strip().split(' as ')[-1].strip()
                           for n in from_import.group(2).split(',')]
            return ImportInfo(
                file_path=file_path,
                line_number=line_num,
                import_statement=line_stripped,
                alias="",
                import_style="from",
                named_imports=named_imports
            )

        return None

    def _parse_go_import(self, line: str, package: str, file_path: str, line_num: int) -> Optional[ImportInfo]:
        """Parse Go import statement."""
        line_stripped = line.strip()

        # import "package" or alias "package"
        go_import = re.search(
            rf'(?:(\w+)\s+)?["\']([^"\']*{re.escape(package)}[^"\']*)["\']',
            line_stripped, re.IGNORECASE
        )
        if go_import:
            alias = go_import.group(1) or go_import.group(2).split('/')[-1]
            return ImportInfo(
                file_path=file_path,
                line_number=line_num,
                import_statement=line_stripped,
                alias=alias,
                import_style="go"
            )

        return None

    def _parse_java_import(self, line: str, package: str, file_path: str, line_num: int) -> Optional[ImportInfo]:
        """Parse Java import statement."""
        line_stripped = line.strip()

        if package.lower() in line_stripped.lower() and line_stripped.startswith("import"):
            # Extract class name as alias
            parts = line_stripped.rstrip(';').split('.')
            alias = parts[-1] if parts else ""
            return ImportInfo(
                file_path=file_path,
                line_number=line_num,
                import_statement=line_stripped,
                alias=alias,
                import_style="java"
            )

        return None

    def _find_vulnerable_function_usages(
        self,
        imports: List[ImportInfo],
        vulnerable_functions: List[str],
        call_patterns: List[str],
        middleware_indicators: List[str],
        extensions: List[str],
        ecosystem: str
    ) -> List[VulnerableFunctionUsage]:
        """Find usages of vulnerable functions using the tracked import aliases."""
        usages = []

        # Build alias-to-file mapping
        file_aliases: Dict[str, List[ImportInfo]] = {}
        for imp in imports:
            if imp.file_path not in file_aliases:
                file_aliases[imp.file_path] = []
            file_aliases[imp.file_path].append(imp)

        for file_path in self._get_scannable_files(extensions):
            rel_path = str(file_path.relative_to(self.project_path))

            if rel_path not in file_aliases:
                continue

            content = self._read_file(file_path)
            if not content:
                continue

            lines = content.split('\n')
            file_imports = file_aliases[rel_path]

            for imp in file_imports:
                # Search for vulnerable function calls using this import's alias
                for line_num, line in enumerate(lines, 1):
                    # Skip the import line itself
                    if line_num == imp.line_number:
                        continue

                    # For named imports, check if any of the imported names are called
                    if imp.import_style in ["named", "from"]:
                        for func in imp.named_imports:
                            if func in vulnerable_functions:
                                # Pattern: functionName( - must be the function being called
                                pattern = rf'\b{re.escape(func)}\s*\('
                                match = re.search(pattern, line)
                                if match:
                                    usage = self._create_usage(
                                        func, func, rel_path, line_num,
                                        line, lines, match, imp
                                    )
                                    usages.append(usage)

                    # For aliased imports (require/default/namespace)
                    elif imp.alias:
                        for func in vulnerable_functions:
                            # Pattern: alias.functionName( - exact match required
                            pattern = rf'\b{re.escape(imp.alias)}\.{re.escape(func)}\s*\('
                            match = re.search(pattern, line)
                            if match:
                                usage = self._create_usage(
                                    func, f"{imp.alias}.{func}", rel_path, line_num,
                                    line, lines, match, imp
                                )
                                usages.append(usage)

                # Check for custom call patterns (e.g., minimist(args))
                for pattern in call_patterns:
                    for line_num, line in enumerate(lines, 1):
                        if re.search(pattern, line):
                            match = re.search(pattern, line)
                            if match:
                                usage = self._create_usage(
                                    pattern, match.group(0), rel_path, line_num,
                                    line, lines, match, imp
                                )
                                usages.append(usage)

            # Check for middleware indicators (for express-like packages)
            for indicator in middleware_indicators:
                for line_num, line in enumerate(lines, 1):
                    if indicator.lower() in line.lower():
                        # More specific pattern for middleware
                        pattern = rf'\.use\s*\([^)]*{re.escape(indicator)}|{re.escape(indicator)}\s*\('
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            usage = self._create_usage(
                                indicator, match.group(0), rel_path, line_num,
                                line, lines, match, file_imports[0] if file_imports else None
                            )
                            usages.append(usage)

        return usages

    def _create_usage(
        self,
        func_name: str,
        full_call: str,
        file_path: str,
        line_num: int,
        line: str,
        lines: List[str],
        match: re.Match,
        import_info: Optional[ImportInfo]
    ) -> VulnerableFunctionUsage:
        """Create a VulnerableFunctionUsage object with context."""
        # Get surrounding context (2 lines before and after)
        start_ctx = max(0, line_num - 3)
        end_ctx = min(len(lines), line_num + 2)
        context_lines = lines[start_ctx:end_ctx]
        context = '\n'.join(f"{start_ctx + i + 1}: {l}" for i, l in enumerate(context_lines))

        # Extract arguments
        args = self._extract_arguments(line, match.end() - 1)

        return VulnerableFunctionUsage(
            function_name=func_name,
            full_call=full_call.strip(),
            file_path=file_path,
            line_number=line_num,
            code_line=line.strip(),
            code_context=context,
            arguments=args,
            confidence="high" if import_info else "medium",
            import_info=import_info
        )

    def _extract_arguments(self, line: str, start_pos: int) -> str:
        """Extract function call arguments."""
        paren_start = line.find('(', start_pos)
        if paren_start == -1:
            return ""

        depth = 0
        end_pos = paren_start
        for i, char in enumerate(line[paren_start:]):
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    end_pos = paren_start + i + 1
                    break

        args = line[paren_start + 1:end_pos - 1].strip()
        return args[:100] + "..." if len(args) > 100 else args

    def _check_exploit_indicators(self, indicators: List[str], extensions: List[str]) -> bool:
        """Check if any exploit indicators are present in the code."""
        for file_path in self._get_scannable_files(extensions):
            content = self._read_file(file_path)
            if not content:
                continue

            for indicator in indicators:
                if indicator.lower() in content.lower():
                    return True
        return False

    def _get_scannable_files(self, extensions: List[str]) -> List[Path]:
        """Get all scannable files, excluding common non-source directories."""
        exclude_dirs = {
            'node_modules', 'vendor', 'venv', '.venv', 'env',
            '.git', '__pycache__', 'dist', 'build', 'target',
            '.next', '.nuxt', 'coverage', '.pytest_cache', 'test',
            'tests', '__tests__', 'spec', 'specs'
        }

        files = []
        for ext in extensions:
            for file_path in self.project_path.rglob(f"*{ext}"):
                if any(exc in file_path.parts for exc in exclude_dirs):
                    continue
                files.append(file_path)

        return files

    def _read_file(self, file_path: Path) -> Optional[str]:
        """Read file content with caching."""
        path_str = str(file_path)
        if path_str not in self._file_cache:
            try:
                self._file_cache[path_str] = file_path.read_text(encoding='utf-8', errors='ignore')
            except Exception as e:
                logger.debug(f"[Reachability] Error reading {file_path}: {e}")
                return None
        return self._file_cache[path_str]

    def analyze_findings(
        self,
        sca_findings: List[Dict[str, Any]],
        ecosystem: str = "npm"
    ) -> List[Dict[str, Any]]:
        """Analyze reachability for SCA findings and enhance them."""
        enhanced = []

        for finding in sca_findings:
            cve = finding.get("cve", "")
            enhanced_finding = finding.copy()

            if cve:
                result = self.analyze_cve(cve, ecosystem)
                if result:
                    enhanced_finding["reachability"] = {
                        "exploitability": result.exploitability.value,
                        "confidence_score": result.confidence_score,
                        "attack_vector": result.attack_vector,
                        "recommendation": result.recommendation,
                        "vulnerable_functions_used": [
                            {
                                "function": vu.function_name,
                                "full_call": vu.full_call,
                                "file": vu.file_path,
                                "line": vu.line_number,
                                "code": vu.code_line,
                                "context": vu.code_context,
                                "arguments": vu.arguments,
                                "confidence": vu.confidence
                            }
                            for vu in result.vulnerable_functions_used
                        ],
                        "import_locations": [
                            {
                                "file": imp.file_path,
                                "line": imp.line_number,
                                "import": imp.import_statement,
                                "alias": imp.alias,
                                "style": imp.import_style
                            }
                            for imp in result.import_locations
                        ],
                        "is_exploitable": result.exploitability in [
                            ExploitabilityLevel.EXPLOITABLE,
                            ExploitabilityLevel.POTENTIALLY_EXPLOITABLE
                        ]
                    }
                else:
                    enhanced_finding["reachability"] = {
                        "exploitability": "unknown",
                        "confidence_score": 0.0,
                        "attack_vector": "CVE not in reachability database",
                        "recommendation": "Manual review required",
                        "vulnerable_functions_used": [],
                        "import_locations": [],
                        "is_exploitable": None
                    }
            else:
                enhanced_finding["reachability"] = {
                    "exploitability": "unknown",
                    "confidence_score": 0.0,
                    "attack_vector": "No CVE available",
                    "recommendation": "Manual review required",
                    "vulnerable_functions_used": [],
                    "import_locations": [],
                    "is_exploitable": None
                }

            enhanced.append(enhanced_finding)

        return enhanced


# Backwards-compatible aliases
ReachabilityAnalyzer = PreciseReachabilityAnalyzer


def analyze_code_reachability(
    project_path: str,
    sca_findings: List[Dict[str, Any]],
    ecosystem: str = "npm"
) -> Dict[str, Any]:
    """
    Main entry point for reachability analysis.
    """
    analyzer = PreciseReachabilityAnalyzer(project_path)

    # Analyze all findings
    enhanced_findings = analyzer.analyze_findings(sca_findings, ecosystem)

    # Generate summary
    summary = {
        "total_analyzed": len(enhanced_findings),
        "exploitable": 0,
        "potentially_exploitable": 0,
        "imported_only": 0,
        "not_reachable": 0,
        "critical_findings": []
    }

    for finding in enhanced_findings:
        reach = finding.get("reachability", {})
        level = reach.get("exploitability", "unknown")

        if level == "exploitable":
            summary["exploitable"] += 1
            summary["critical_findings"].append({
                "cve": finding.get("cve"),
                "package": finding.get("package"),
                "attack_vector": reach.get("attack_vector"),
                "functions_used": len(reach.get("vulnerable_functions_used", []))
            })
        elif level == "potentially_exploitable":
            summary["potentially_exploitable"] += 1
        elif level == "imported_only":
            summary["imported_only"] += 1
        elif level == "not_reachable":
            summary["not_reachable"] += 1

    return {
        "findings": enhanced_findings,
        "summary": summary,
        "total_cves_analyzed": len(enhanced_findings),
        "reachability_coverage": f"{len([f for f in enhanced_findings if f.get('reachability', {}).get('exploitability') != 'unknown']) / max(len(enhanced_findings), 1) * 100:.1f}%"
    }
