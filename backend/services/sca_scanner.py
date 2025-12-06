"""
SCA (Software Composition Analysis) Scanner - Optimized Version
Professional-grade dependency vulnerability scanner with:
- Pre-indexed vulnerability database for O(1) lookups
- Pre-compiled version constraints
- Version caching to avoid repeated parsing
- Async batch processing for parallel scanning
- NVD API integration for real-time data
- Support for npm, pip, Maven, Gradle, Composer, RubyGems, Go modules, Cargo, NuGet
"""
from typing import List, Dict, Any, Tuple, Callable
import json
import re
import os
import asyncio
import httpx
from datetime import datetime, timedelta
from functools import lru_cache
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor


@dataclass
class ParsedVersion:
    """Pre-parsed version for efficient comparison"""
    original: str
    parts: Tuple[Any, ...]
    is_prerelease: bool


@dataclass
class CompiledConstraint:
    """Pre-compiled version constraint"""
    operator: str
    version: ParsedVersion
    check_func: Callable[[ParsedVersion, ParsedVersion], bool]


class SCAScanner:
    """
    Enhanced SCA scanner with O(1) lookups and async capabilities
    """

    # Comprehensive vulnerability database with real CVEs
    VULNERABLE_PACKAGES = {
        # ==================== JAVASCRIPT/NODE.JS PACKAGES ====================
        "lodash": [
            {
                "versions": ["<4.17.21"],
                "vulnerability": "Prototype Pollution",
                "cve": ["CVE-2020-8203", "CVE-2019-10744", "CVE-2018-16487"],
                "severity": "high",
                "cvss": 7.4,
                "description": "Lodash allows attackers to cause prototype pollution via various methods.",
                "remediation": "Upgrade to lodash >= 4.17.21",
                "cwe": "CWE-1321",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "published": "2020-07-15",
                "ecosystem": "npm"
            },
        ],
        "axios": [
            {
                "versions": ["<0.21.2"],
                "vulnerability": "Server-Side Request Forgery (SSRF)",
                "cve": ["CVE-2021-3749"],
                "severity": "medium",
                "cvss": 5.9,
                "description": "Axios improperly handles redirects, allowing SSRF attacks.",
                "remediation": "Upgrade to axios >= 0.21.2",
                "cwe": "CWE-918",
                "owasp": "A10:2021 - Server-Side Request Forgery",
                "published": "2021-08-31",
                "ecosystem": "npm"
            },
            {
                "versions": ["<1.6.0"],
                "vulnerability": "Cross-Site Request Forgery (CSRF)",
                "cve": ["CVE-2023-45857"],
                "severity": "medium",
                "cvss": 6.5,
                "description": "Axios CSRF vulnerability in browser environment.",
                "remediation": "Upgrade to axios >= 1.6.0",
                "cwe": "CWE-352",
                "owasp": "A01:2021 - Broken Access Control",
                "published": "2023-11-08",
                "ecosystem": "npm"
            },
        ],
        "express": [
            {
                "versions": ["<4.17.3"],
                "vulnerability": "Denial of Service via Body Parsing",
                "cve": ["CVE-2022-24999"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Express.js vulnerable to DoS through qs library.",
                "remediation": "Upgrade to express >= 4.17.3",
                "cwe": "CWE-400",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "published": "2022-11-26",
                "ecosystem": "npm"
            },
        ],
        "jsonwebtoken": [
            {
                "versions": ["<9.0.0"],
                "vulnerability": "Improper Signature Validation",
                "cve": ["CVE-2022-23529"],
                "severity": "high",
                "cvss": 7.6,
                "description": "JWT signature verification bypass vulnerability.",
                "remediation": "Upgrade to jsonwebtoken >= 9.0.0",
                "cwe": "CWE-347",
                "owasp": "A02:2021 - Cryptographic Failures",
                "published": "2022-12-22",
                "ecosystem": "npm"
            },
        ],
        "minimist": [
            {
                "versions": ["<1.2.6"],
                "vulnerability": "Prototype Pollution",
                "cve": ["CVE-2021-44906"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "Prototype pollution vulnerability in argument parsing.",
                "remediation": "Upgrade to minimist >= 1.2.6",
                "cwe": "CWE-1321",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "published": "2022-03-17",
                "ecosystem": "npm"
            },
        ],
        "node-fetch": [
            {
                "versions": ["<2.6.7", ">=3.0.0,<3.2.1"],
                "vulnerability": "Information Exposure",
                "cve": ["CVE-2022-0235"],
                "severity": "medium",
                "cvss": 6.1,
                "description": "Exposure of sensitive information to unauthorized actor.",
                "remediation": "Upgrade to node-fetch >= 2.6.7 or >= 3.2.1",
                "cwe": "CWE-200",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2022-01-16",
                "ecosystem": "npm"
            },
        ],
        "ws": [
            {
                "versions": ["<7.5.10", ">=8.0.0,<8.17.1"],
                "vulnerability": "Regular Expression Denial of Service (ReDoS)",
                "cve": ["CVE-2024-37890"],
                "severity": "high",
                "cvss": 7.5,
                "description": "WebSocket server vulnerable to ReDoS.",
                "remediation": "Upgrade to ws >= 7.5.10 or >= 8.17.1",
                "cwe": "CWE-1333",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2024-06-17",
                "ecosystem": "npm"
            },
        ],
        "ansi-regex": [
            {
                "versions": ["<5.0.1"],
                "vulnerability": "Regular Expression Denial of Service (ReDoS)",
                "cve": ["CVE-2021-3807"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Inefficient regular expression allows ReDoS attacks.",
                "remediation": "Upgrade to ansi-regex >= 5.0.1",
                "cwe": "CWE-1333",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2021-09-17",
                "ecosystem": "npm"
            },
        ],
        "ejs": [
            {
                "versions": ["<3.1.7"],
                "vulnerability": "Server-Side Template Injection (SSTI)",
                "cve": ["CVE-2022-29078"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "Template injection leading to RCE.",
                "remediation": "Upgrade to ejs >= 3.1.7",
                "cwe": "CWE-94",
                "owasp": "A03:2021 - Injection",
                "published": "2022-04-25",
                "ecosystem": "npm"
            },
        ],

        # ==================== PYTHON PACKAGES ====================
        "django": [
            {
                "versions": ["<3.2.13", ">=4.0.0,<4.0.4"],
                "vulnerability": "SQL Injection via QuerySet.order_by()",
                "cve": ["CVE-2022-28346"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "SQL injection vulnerability in QuerySet ordering.",
                "remediation": "Upgrade to django >= 3.2.13 or >= 4.0.4",
                "cwe": "CWE-89",
                "owasp": "A03:2021 - Injection",
                "published": "2022-04-11",
                "ecosystem": "pip"
            },
            {
                "versions": ["<3.2.15", ">=4.0.0,<4.0.7"],
                "vulnerability": "Potential SQL Injection via Trunc/Extract",
                "cve": ["CVE-2022-34265"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "SQL injection in Trunc() and Extract() database functions.",
                "remediation": "Upgrade to django >= 3.2.15 or >= 4.0.7",
                "cwe": "CWE-89",
                "owasp": "A03:2021 - Injection",
                "published": "2022-07-04",
                "ecosystem": "pip"
            },
        ],
        "flask": [
            {
                "versions": ["<2.2.5", ">=2.3.0,<2.3.2"],
                "vulnerability": "Path Traversal in send_file()",
                "cve": ["CVE-2023-30861"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Path traversal vulnerability allows reading arbitrary files.",
                "remediation": "Upgrade to flask >= 2.2.5 or >= 2.3.2",
                "cwe": "CWE-22",
                "owasp": "A01:2021 - Broken Access Control",
                "published": "2023-05-02",
                "ecosystem": "pip"
            },
        ],
        "requests": [
            {
                "versions": ["<2.31.0"],
                "vulnerability": "SSL Certificate Validation Bypass",
                "cve": ["CVE-2023-32681"],
                "severity": "medium",
                "cvss": 6.1,
                "description": "Proxy-Authorization header sent to proxy in plaintext.",
                "remediation": "Upgrade to requests >= 2.31.0",
                "cwe": "CWE-295",
                "owasp": "A02:2021 - Cryptographic Failures",
                "published": "2023-05-26",
                "ecosystem": "pip"
            },
        ],
        "pillow": [
            {
                "versions": ["<9.3.0"],
                "vulnerability": "Denial of Service via Malicious Image",
                "cve": ["CVE-2022-45198"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Uncontrolled Resource Consumption in image processing.",
                "remediation": "Upgrade to pillow >= 9.3.0",
                "cwe": "CWE-400",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2022-11-14",
                "ecosystem": "pip"
            },
        ],
        "pyyaml": [
            {
                "versions": ["<5.4"],
                "vulnerability": "Arbitrary Code Execution",
                "cve": ["CVE-2020-14343"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "Unsafe yaml.load() allows arbitrary code execution.",
                "remediation": "Upgrade to pyyaml >= 5.4 and use yaml.safe_load()",
                "cwe": "CWE-502",
                "owasp": "A08:2021 - Software and Data Integrity Failures",
                "published": "2020-07-30",
                "ecosystem": "pip"
            },
        ],
        "werkzeug": [
            {
                "versions": ["<2.2.3"],
                "vulnerability": "High Resource Consumption",
                "cve": ["CVE-2023-25577"],
                "severity": "high",
                "cvss": 7.5,
                "description": "DoS via specially crafted multipart data.",
                "remediation": "Upgrade to werkzeug >= 2.2.3",
                "cwe": "CWE-400",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2023-02-14",
                "ecosystem": "pip"
            },
        ],
        "cryptography": [
            {
                "versions": ["<39.0.1"],
                "vulnerability": "NULL Pointer Dereference",
                "cve": ["CVE-2023-23931"],
                "severity": "medium",
                "cvss": 6.5,
                "description": "Memory corruption in cipher decryption.",
                "remediation": "Upgrade to cryptography >= 39.0.1",
                "cwe": "CWE-476",
                "owasp": "A02:2021 - Cryptographic Failures",
                "published": "2023-02-07",
                "ecosystem": "pip"
            },
        ],
        "jinja2": [
            {
                "versions": ["<3.1.3"],
                "vulnerability": "Sandbox Escape via Globals",
                "cve": ["CVE-2024-22195"],
                "severity": "medium",
                "cvss": 6.1,
                "description": "XSS vulnerability via template rendering.",
                "remediation": "Upgrade to jinja2 >= 3.1.3",
                "cwe": "CWE-79",
                "owasp": "A03:2021 - Injection",
                "published": "2024-01-11",
                "ecosystem": "pip"
            },
        ],

        # ==================== JAVA PACKAGES ====================
        "log4j-core": [
            {
                "versions": [">=2.0-beta9,<2.17.1"],
                "vulnerability": "Remote Code Execution (Log4Shell)",
                "cve": ["CVE-2021-44228"],
                "severity": "critical",
                "cvss": 10.0,
                "description": "JNDI injection vulnerability allowing remote code execution.",
                "remediation": "Upgrade to log4j-core >= 2.17.1",
                "cwe": "CWE-502",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "published": "2021-12-10",
                "ecosystem": "maven"
            },
        ],
        "spring-core": [
            {
                "versions": [">=5.3.0,<5.3.18", ">=5.2.0,<5.2.20"],
                "vulnerability": "Remote Code Execution (Spring4Shell)",
                "cve": ["CVE-2022-22965"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "RCE vulnerability via data binding on JDK 9+.",
                "remediation": "Upgrade to spring-core >= 5.3.18 or >= 5.2.20",
                "cwe": "CWE-94",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "published": "2022-04-01",
                "ecosystem": "maven"
            },
        ],
        "jackson-databind": [
            {
                "versions": ["<2.13.4"],
                "vulnerability": "Deserialization of Untrusted Data",
                "cve": ["CVE-2022-42003", "CVE-2022-42004"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Unsafe deserialization can lead to RCE.",
                "remediation": "Upgrade to jackson-databind >= 2.13.4",
                "cwe": "CWE-502",
                "owasp": "A08:2021 - Software and Data Integrity Failures",
                "published": "2022-10-02",
                "ecosystem": "maven"
            },
        ],
        "commons-collections": [
            {
                "versions": ["<3.2.2"],
                "vulnerability": "Remote Code Execution via Deserialization",
                "cve": ["CVE-2015-6420"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "Java deserialization vulnerability enabling RCE.",
                "remediation": "Upgrade to commons-collections >= 3.2.2",
                "cwe": "CWE-502",
                "owasp": "A08:2021 - Software and Data Integrity Failures",
                "published": "2015-11-18",
                "ecosystem": "maven"
            },
        ],
        "struts": [
            {
                "versions": [">=2.0.0,<2.5.33"],
                "vulnerability": "Remote Code Execution",
                "cve": ["CVE-2023-50164"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "Path traversal and RCE via file upload.",
                "remediation": "Upgrade to struts >= 2.5.33 or >= 6.3.0",
                "cwe": "CWE-22",
                "owasp": "A01:2021 - Broken Access Control",
                "published": "2023-12-07",
                "ecosystem": "maven"
            },
        ],

        # ==================== PHP PACKAGES ====================
        "symfony/http-kernel": [
            {
                "versions": ["<4.4.50", ">=5.0.0,<5.4.20", ">=6.0.0,<6.2.6"],
                "vulnerability": "HTTP Cache Poisoning",
                "cve": ["CVE-2023-21267"],
                "severity": "medium",
                "cvss": 5.3,
                "description": "HTTP cache poisoning vulnerability.",
                "remediation": "Upgrade to symfony/http-kernel >= 4.4.50, >= 5.4.20, or >= 6.2.6",
                "cwe": "CWE-444",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2023-02-03",
                "ecosystem": "composer"
            },
        ],
        "laravel/framework": [
            {
                "versions": ["<6.20.42", ">=7.0.0,<7.30.6", ">=8.0.0,<8.75.0"],
                "vulnerability": "Mass Assignment Vulnerability",
                "cve": ["CVE-2022-36067"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Unauthorized mass assignment in query builder.",
                "remediation": "Upgrade to laravel/framework >= 6.20.42, >= 7.30.6, or >= 8.75.0",
                "cwe": "CWE-915",
                "owasp": "A01:2021 - Broken Access Control",
                "published": "2022-08-24",
                "ecosystem": "composer"
            },
        ],
        "monolog/monolog": [
            {
                "versions": ["<2.8.0"],
                "vulnerability": "Remote Code Execution via Log Injection",
                "cve": ["CVE-2022-41343"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Log injection can lead to RCE.",
                "remediation": "Upgrade to monolog/monolog >= 2.8.0",
                "cwe": "CWE-94",
                "owasp": "A03:2021 - Injection",
                "published": "2022-09-30",
                "ecosystem": "composer"
            },
        ],

        # ==================== RUBY PACKAGES ====================
        "rails": [
            {
                "versions": ["<5.2.8.1", ">=6.0.0,<6.0.5.1", ">=6.1.0,<6.1.6.1"],
                "vulnerability": "Path Traversal and RCE",
                "cve": ["CVE-2022-32224"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "Possible RCE vulnerability with Action Pack.",
                "remediation": "Upgrade to rails >= 5.2.8.1, >= 6.0.5.1, or >= 6.1.6.1",
                "cwe": "CWE-22",
                "owasp": "A03:2021 - Injection",
                "published": "2022-07-12",
                "ecosystem": "bundler"
            },
        ],
        "rack": [
            {
                "versions": ["<2.2.6.3", ">=3.0.0,<3.0.4.2"],
                "vulnerability": "Denial of Service via Multipart Parsing",
                "cve": ["CVE-2023-27530"],
                "severity": "high",
                "cvss": 7.5,
                "description": "DoS via crafted multipart/form-data.",
                "remediation": "Upgrade to rack >= 2.2.6.3 or >= 3.0.4.2",
                "cwe": "CWE-400",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2023-03-10",
                "ecosystem": "bundler"
            },
        ],

        # ==================== GO PACKAGES ====================
        "golang.org/x/crypto": [
            {
                "versions": ["<0.0.0-20220314234659-1baeb1ce4c0b"],
                "vulnerability": "Empty Plaintext Packet Causes Panic",
                "cve": ["CVE-2022-27191"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Panic in golang crypto SSH implementation.",
                "remediation": "Upgrade to golang.org/x/crypto >= v0.0.0-20220314234659-1baeb1ce4c0b",
                "cwe": "CWE-476",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2022-03-18",
                "ecosystem": "go"
            },
        ],
        "github.com/gin-gonic/gin": [
            {
                "versions": ["<1.9.1"],
                "vulnerability": "Path Traversal",
                "cve": ["CVE-2023-29401"],
                "severity": "medium",
                "cvss": 6.5,
                "description": "Directory traversal in file serving.",
                "remediation": "Upgrade to gin >= v1.9.1",
                "cwe": "CWE-22",
                "owasp": "A01:2021 - Broken Access Control",
                "published": "2023-07-05",
                "ecosystem": "go"
            },
        ],
        "github.com/dgrijalva/jwt-go": [
            {
                "versions": ["<4.0.0-preview1"],
                "vulnerability": "Improper Token Verification",
                "cve": ["CVE-2020-26160"],
                "severity": "high",
                "cvss": 7.5,
                "description": "JWT token verification can be bypassed.",
                "remediation": "Migrate to github.com/golang-jwt/jwt",
                "cwe": "CWE-347",
                "owasp": "A02:2021 - Cryptographic Failures",
                "published": "2020-09-30",
                "ecosystem": "go"
            },
        ],

        # ==================== RUST PACKAGES ====================
        "serde": [
            {
                "versions": ["<1.0.171"],
                "vulnerability": "Incorrect Encoding/Decoding",
                "cve": ["RUSTSEC-2023-0048"],
                "severity": "medium",
                "cvss": 5.3,
                "description": "Possible denial of service via malformed input.",
                "remediation": "Upgrade to serde >= 1.0.171",
                "cwe": "CWE-20",
                "owasp": "A03:2021 - Injection",
                "published": "2023-07-14",
                "ecosystem": "cargo"
            },
        ],
        "regex": [
            {
                "versions": ["<1.5.5"],
                "vulnerability": "ReDoS Vulnerability",
                "cve": ["RUSTSEC-2022-0013"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Regex can hang on malicious input.",
                "remediation": "Upgrade to regex >= 1.5.5",
                "cwe": "CWE-1333",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2022-03-08",
                "ecosystem": "cargo"
            },
        ],

        # ==================== .NET PACKAGES ====================
        "Newtonsoft.Json": [
            {
                "versions": ["<13.0.1"],
                "vulnerability": "Insecure Deserialization",
                "cve": ["CVE-2024-21907"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Potential RCE via TypeNameHandling.",
                "remediation": "Upgrade and avoid TypeNameHandling.Auto",
                "cwe": "CWE-502",
                "owasp": "A08:2021 - Software and Data Integrity Failures",
                "published": "2024-01-09",
                "ecosystem": "nuget"
            },
        ],
        "System.Text.Json": [
            {
                "versions": ["<7.0.3", ">=8.0.0,<8.0.1"],
                "vulnerability": "Stack Overflow DoS",
                "cve": ["CVE-2024-21319"],
                "severity": "high",
                "cvss": 7.5,
                "description": "DoS via deeply nested JSON.",
                "remediation": "Upgrade to System.Text.Json >= 7.0.3 or >= 8.0.1",
                "cwe": "CWE-400",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2024-01-09",
                "ecosystem": "nuget"
            },
        ],
    }

    # Comprehensive license database
    LICENSE_INFO = {
        "MIT": {"risk": "low", "commercial_use": True, "category": "Permissive"},
        "Apache-2.0": {"risk": "low", "commercial_use": True, "category": "Permissive"},
        "GPL-2.0": {"risk": "high", "commercial_use": False, "category": "Copyleft", "warning": "Strong copyleft"},
        "GPL-3.0": {"risk": "high", "commercial_use": False, "category": "Copyleft", "warning": "Strong copyleft"},
        "LGPL-2.1": {"risk": "medium", "commercial_use": True, "category": "Weak Copyleft"},
        "LGPL-3.0": {"risk": "medium", "commercial_use": True, "category": "Weak Copyleft"},
        "AGPL-3.0": {"risk": "high", "commercial_use": False, "category": "Network Copyleft", "warning": "Network copyleft"},
        "BSD-2-Clause": {"risk": "low", "commercial_use": True, "category": "Permissive"},
        "BSD-3-Clause": {"risk": "low", "commercial_use": True, "category": "Permissive"},
        "ISC": {"risk": "low", "commercial_use": True, "category": "Permissive"},
        "MPL-2.0": {"risk": "medium", "commercial_use": True, "category": "Weak Copyleft"},
        "CC0-1.0": {"risk": "low", "commercial_use": True, "category": "Public Domain"},
        "Unlicense": {"risk": "low", "commercial_use": True, "category": "Public Domain"},
    }

    def __init__(self):
        """Initialize with pre-indexed database and compiled constraints"""
        self.scanned_packages = 0
        self.errors = []

        # Pre-index vulnerabilities by ecosystem for O(1) lookup
        self._vuln_by_ecosystem: Dict[str, Dict[str, List[Dict]]] = {}

        # Cache for compiled version constraints
        self._compiled_constraints: Dict[str, List[CompiledConstraint]] = {}

        # Version comparison cache (LRU-style)
        self._version_cache: Dict[str, ParsedVersion] = {}
        self._cache_max_size = 10000

        # NVD API configuration
        self._nvd_api_key = os.getenv("NVD_API_KEY", "")
        self._nvd_cache: Dict[str, Any] = {}
        self._nvd_cache_time: Dict[str, datetime] = {}
        self._nvd_cache_duration = timedelta(hours=6)

        # Build indices on initialization
        self._build_indices()

        # Thread pool for parallel operations
        self._executor = ThreadPoolExecutor(max_workers=4)

    def _build_indices(self):
        """Build optimized indices for O(1) vulnerability lookup"""
        ecosystems = ['npm', 'pip', 'maven', 'gradle', 'composer', 'bundler', 'go', 'cargo', 'nuget']

        for ecosystem in ecosystems:
            self._vuln_by_ecosystem[ecosystem] = {}

        for package_name, vuln_list in self.VULNERABLE_PACKAGES.items():
            for vuln_info in vuln_list:
                ecosystem = vuln_info.get('ecosystem', 'npm')

                if package_name not in self._vuln_by_ecosystem[ecosystem]:
                    self._vuln_by_ecosystem[ecosystem][package_name] = []

                self._vuln_by_ecosystem[ecosystem][package_name].append(vuln_info)

                # Pre-compile version constraints for this vulnerability
                constraint_key = f"{package_name}:{','.join(vuln_info['versions'])}"
                if constraint_key not in self._compiled_constraints:
                    self._compiled_constraints[constraint_key] = [
                        self._compile_constraint(v) for v in vuln_info['versions']
                    ]

    def _compile_constraint(self, constraint: str) -> CompiledConstraint:
        """Pre-compile a version constraint for efficient repeated use"""
        operators = {
            '>=': lambda v, c: self._compare_parsed_versions(v, c) >= 0,
            '<=': lambda v, c: self._compare_parsed_versions(v, c) <= 0,
            '>': lambda v, c: self._compare_parsed_versions(v, c) > 0,
            '<': lambda v, c: self._compare_parsed_versions(v, c) < 0,
            '==': lambda v, c: self._compare_parsed_versions(v, c) == 0,
            '!=': lambda v, c: self._compare_parsed_versions(v, c) != 0,
        }

        # Handle range constraints like ">=1.0.0,<2.0.0"
        if ',' in constraint:
            # Return just the first part for now, ranges handled separately
            constraint = constraint.split(',')[0]

        for op_str in ['>=', '<=', '!=', '>', '<', '==']:
            if constraint.startswith(op_str):
                version_str = constraint[len(op_str):].strip()
                return CompiledConstraint(
                    operator=op_str,
                    version=self._parse_version(version_str),
                    check_func=operators[op_str]
                )

        # Default to exact match
        return CompiledConstraint(
            operator='==',
            version=self._parse_version(constraint),
            check_func=operators['==']
        )

    @lru_cache(maxsize=10000)
    def _parse_version(self, version: str) -> ParsedVersion:
        """Parse and cache a version string for efficient comparison"""
        original = version
        v = version.lstrip('v').strip()

        # Check for pre-release identifiers
        is_prerelease = any(x in v.lower() for x in ['alpha', 'beta', 'rc', 'dev', 'preview'])

        # Split version into parts
        parts = []
        for part in re.split(r'[.\-+]', v):
            if part.isdigit():
                parts.append(int(part))
            else:
                # Try to extract leading number from parts like "20220314234659"
                match = re.match(r'^(\d+)', part)
                if match:
                    parts.append(int(match.group(1)))
                else:
                    parts.append(part.lower())

        return ParsedVersion(
            original=original,
            parts=tuple(parts),
            is_prerelease=is_prerelease
        )

    def _compare_parsed_versions(self, v1: ParsedVersion, v2: ParsedVersion) -> int:
        """Compare two pre-parsed versions efficiently"""
        parts1, parts2 = v1.parts, v2.parts

        for i in range(max(len(parts1), len(parts2))):
            p1 = parts1[i] if i < len(parts1) else 0
            p2 = parts2[i] if i < len(parts2) else 0

            # Both numeric
            if isinstance(p1, int) and isinstance(p2, int):
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1
            # Mixed or both strings
            else:
                s1, s2 = str(p1), str(p2)
                if s1 < s2:
                    return -1
                elif s1 > s2:
                    return 1

        return 0

    def _is_version_vulnerable_fast(self, installed: ParsedVersion, constraint_key: str) -> bool:
        """Fast vulnerability check using pre-compiled constraints"""
        compiled = self._compiled_constraints.get(constraint_key, [])

        for constraint in compiled:
            if constraint.check_func(installed, constraint.version):
                return True

        return False

    def _check_range_constraint(self, version: str, constraint: str) -> bool:
        """Check if version matches a range constraint like '>=1.0.0,<2.0.0'"""
        parsed_version = self._parse_version(version)

        if ',' in constraint:
            # Handle range: all parts must match
            parts = constraint.split(',')
            for part in parts:
                part = part.strip()
                compiled = self._compile_constraint(part)
                if not compiled.check_func(parsed_version, compiled.version):
                    return False
            return True
        else:
            compiled = self._compile_constraint(constraint)
            return compiled.check_func(parsed_version, compiled.version)

    def scan_dependencies(self, dependencies: Dict[str, str], ecosystem: str = "npm") -> Dict[str, Any]:
        """
        Optimized dependency scanning with O(1) lookups

        Args:
            dependencies: {"package_name": "version"}
            ecosystem: Package ecosystem (npm, pip, maven, etc.)

        Returns:
            Scan results with vulnerabilities and statistics
        """
        findings = []
        total_packages = len(dependencies)
        vulnerable_count = 0
        self.scanned_packages = total_packages

        # Get ecosystem-specific vulnerability index
        ecosystem_vulns = self._vuln_by_ecosystem.get(ecosystem, {})

        for package, version in dependencies.items():
            # O(1) lookup for package vulnerabilities
            if package not in ecosystem_vulns:
                continue

            vuln_list = ecosystem_vulns[package]
            parsed_version = self._parse_version(version)

            for vuln_info in vuln_list:
                # Check all version constraints
                is_vulnerable = False
                for v_constraint in vuln_info['versions']:
                    if self._check_range_constraint(version, v_constraint):
                        is_vulnerable = True
                        break

                if is_vulnerable:
                    vulnerable_count += 1
                    cves = vuln_info['cve'] if isinstance(vuln_info['cve'], list) else [vuln_info['cve']]

                    findings.append({
                        "package": package,
                        "installed_version": version,
                        "vulnerability": vuln_info['vulnerability'],
                        "cve": cves[0],
                        "all_cves": cves,
                        "severity": vuln_info['severity'],
                        "cvss_score": vuln_info['cvss'],
                        "cwe_id": vuln_info['cwe'],
                        "owasp_category": vuln_info['owasp'],
                        "description": vuln_info['description'],
                        "remediation": vuln_info['remediation'],
                        "published_date": vuln_info.get('published', 'N/A'),
                        "stride_category": self._map_to_stride(vuln_info['vulnerability']),
                        "mitre_attack_id": "T1195.001",
                        "ecosystem": ecosystem
                    })
                    break  # Found vulnerability, move to next package

        # Calculate severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f['severity']
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "total_packages": total_packages,
            "vulnerable_packages": vulnerable_count,
            "total_vulnerabilities": len(findings),
            "severity_counts": severity_counts,
            "findings": findings,
            "scan_date": datetime.now().isoformat(),
            "ecosystem": ecosystem
        }

    async def scan_dependencies_async(self, dependencies: Dict[str, str], ecosystem: str = "npm") -> Dict[str, Any]:
        """Async version of scan_dependencies with NVD enrichment"""
        # First run local scan
        results = self.scan_dependencies(dependencies, ecosystem)

        # Enrich with NVD data if we have findings
        if results['findings'] and self._nvd_api_key:
            try:
                cve_ids = [f['cve'] for f in results['findings'] if f['cve'].startswith('CVE-')]
                if cve_ids:
                    nvd_data = await self._fetch_nvd_batch(cve_ids[:20])  # Limit to 20
                    results = self._enrich_with_nvd(results, nvd_data)
            except Exception as e:
                self.errors.append(f"NVD enrichment failed: {e}")

        return results

    async def scan_multiple_files_async(self, files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Scan multiple dependency files in parallel

        Args:
            files: [{"content": "...", "type": "npm|pip|maven|..."}]

        Returns:
            Combined scan results from all files
        """
        tasks = []

        for file_info in files:
            content = file_info.get('content', '')
            file_type = file_info.get('type', 'npm')

            # Parse dependencies based on file type
            dependencies = self._parse_file_by_type(content, file_type)

            if dependencies:
                tasks.append(self.scan_dependencies_async(dependencies, file_type))

        if not tasks:
            return {"total_files": 0, "results": []}

        # Run all scans in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate results
        combined = {
            "total_files": len(files),
            "total_packages": 0,
            "vulnerable_packages": 0,
            "total_vulnerabilities": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "findings": [],
            "scan_date": datetime.now().isoformat(),
            "file_results": []
        }

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.errors.append(f"File {i} scan failed: {result}")
                continue

            combined["total_packages"] += result.get("total_packages", 0)
            combined["vulnerable_packages"] += result.get("vulnerable_packages", 0)
            combined["total_vulnerabilities"] += result.get("total_vulnerabilities", 0)
            combined["findings"].extend(result.get("findings", []))

            for sev in ["critical", "high", "medium", "low"]:
                combined["severity_counts"][sev] += result.get("severity_counts", {}).get(sev, 0)

            combined["file_results"].append({
                "file_index": i,
                "ecosystem": result.get("ecosystem"),
                "packages": result.get("total_packages"),
                "vulnerabilities": result.get("total_vulnerabilities")
            })

        return combined

    def _parse_file_by_type(self, content: str, file_type: str) -> Dict[str, str]:
        """Parse dependency file based on type"""
        parsers = {
            'npm': self.parse_package_json,
            'pip': self.parse_requirements_txt,
            'maven': self.parse_pom_xml,
            'gradle': self.parse_gradle_build,
            'composer': self.parse_composer_json,
            'bundler': self.parse_gemfile_lock,
            'go': self.parse_go_mod,
            'cargo': self.parse_cargo_toml,
            'nuget': self.parse_csproj,
        }

        parser = parsers.get(file_type)
        if parser:
            return parser(content)
        return {}

    async def _fetch_nvd_batch(self, cve_ids: List[str]) -> Dict[str, Any]:
        """Fetch CVE details from NVD API in batch"""
        results = {}

        async with httpx.AsyncClient(timeout=30.0) as client:
            for cve_id in cve_ids:
                # Check cache first
                if cve_id in self._nvd_cache:
                    cache_time = self._nvd_cache_time.get(cve_id)
                    if cache_time and datetime.now() - cache_time < self._nvd_cache_duration:
                        results[cve_id] = self._nvd_cache[cve_id]
                        continue

                try:
                    headers = {"apiKey": self._nvd_api_key} if self._nvd_api_key else {}
                    response = await client.get(
                        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                        headers=headers
                    )

                    if response.status_code == 200:
                        data = response.json()
                        vulns = data.get('vulnerabilities', [])
                        if vulns:
                            cve_data = vulns[0].get('cve', {})
                            results[cve_id] = cve_data
                            self._nvd_cache[cve_id] = cve_data
                            self._nvd_cache_time[cve_id] = datetime.now()

                    # Rate limiting - NVD allows 5 requests/30s without key, 50/30s with key
                    await asyncio.sleep(0.1 if self._nvd_api_key else 0.6)

                except Exception as e:
                    self.errors.append(f"NVD fetch failed for {cve_id}: {e}")

        return results

    def _enrich_with_nvd(self, results: Dict[str, Any], nvd_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich scan results with NVD data"""
        for finding in results['findings']:
            cve_id = finding.get('cve')
            if cve_id in nvd_data:
                nvd_cve = nvd_data[cve_id]

                # Extract CVSS v3.1 score if available
                metrics = nvd_cve.get('metrics', {})
                cvss_v31 = metrics.get('cvssMetricV31', [])
                if cvss_v31:
                    finding['nvd_cvss'] = cvss_v31[0].get('cvssData', {}).get('baseScore')
                    finding['nvd_vector'] = cvss_v31[0].get('cvssData', {}).get('vectorString')

                # Get references
                refs = nvd_cve.get('references', [])
                finding['nvd_references'] = [r.get('url') for r in refs[:5]]

                # Get CWEs
                weaknesses = nvd_cve.get('weaknesses', [])
                for w in weaknesses:
                    for desc in w.get('description', []):
                        if desc.get('value', '').startswith('CWE-'):
                            finding['nvd_cwe'] = desc['value']
                            break

        return results

    def _map_to_stride(self, vulnerability_name: str) -> str:
        """Map vulnerability to STRIDE threat category"""
        vuln_lower = vulnerability_name.lower()

        mapping = [
            (["injection", "xss", "sqli", "template"], "Tampering"),
            (["rce", "execution", "deseriali"], "Elevation of Privilege"),
            (["dos", "denial", "redos", "resource"], "Denial of Service"),
            (["disclosure", "exposure", "information", "traversal"], "Information Disclosure"),
            (["bypass", "authentication", "ssrf"], "Spoofing"),
            (["forgery", "csrf"], "Repudiation"),
        ]

        for keywords, stride in mapping:
            if any(kw in vuln_lower for kw in keywords):
                return stride

        return "Tampering"

    # ==================== DEPENDENCY PARSERS ====================

    def parse_package_json(self, content: str) -> Dict[str, str]:
        """Parse package.json (npm/yarn)"""
        try:
            data = json.loads(content)
            deps = {}
            deps.update(data.get("dependencies", {}))
            deps.update(data.get("devDependencies", {}))

            # Clean version strings (remove ^, ~, etc.)
            cleaned = {}
            for pkg, ver in deps.items():
                if isinstance(ver, str):
                    cleaned[pkg] = ver.lstrip('^~>=<')

            return cleaned
        except Exception as e:
            self.errors.append(f"Error parsing package.json: {e}")
            return {}

    def parse_requirements_txt(self, content: str) -> Dict[str, str]:
        """Parse requirements.txt (pip)"""
        deps = {}

        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue

            # Handle extras like package[extra]==version
            line = re.sub(r'\[.*?\]', '', line)

            try:
                for sep in ['==', '>=', '<=', '~=', '!=', '<', '>']:
                    if sep in line:
                        parts = line.split(sep, 1)
                        deps[parts[0].strip()] = parts[1].strip().split(',')[0].strip()
                        break
                else:
                    # Package without version
                    deps[line.strip()] = "latest"
            except Exception as e:
                self.errors.append(f"Error parsing line '{line}': {e}")

        return deps

    def parse_pom_xml(self, content: str) -> Dict[str, str]:
        """Parse Maven pom.xml"""
        deps = {}

        # More robust XML parsing with regex
        dep_pattern = re.compile(
            r'<dependency>\s*'
            r'<groupId>([^<]+)</groupId>\s*'
            r'<artifactId>([^<]+)</artifactId>\s*'
            r'(?:<version>([^<]+)</version>)?',
            re.DOTALL
        )

        for match in dep_pattern.finditer(content):
            group_id = match.group(1).strip()
            artifact_id = match.group(2).strip()
            version = match.group(3).strip() if match.group(3) else "latest"

            # Use artifact_id as primary key (most vuln DBs use this)
            deps[artifact_id] = version
            # Also store full coordinate
            deps[f"{group_id}:{artifact_id}"] = version

        return deps

    def parse_gradle_build(self, content: str) -> Dict[str, str]:
        """Parse Gradle build.gradle or build.gradle.kts"""
        deps = {}

        # Match various Gradle dependency formats
        patterns = [
            # implementation 'group:artifact:version'
            r"(?:implementation|api|compile|testImplementation)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
            # implementation("group:artifact:version")
            r"(?:implementation|api|compile|testImplementation)\s*\(\s*['\"]([^:]+):([^:]+):([^'\"]+)['\"]\s*\)",
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, content):
                artifact_id = match.group(2).strip()
                version = match.group(3).strip()
                deps[artifact_id] = version

        return deps

    def parse_composer_json(self, content: str) -> Dict[str, str]:
        """Parse PHP composer.json"""
        try:
            data = json.loads(content)
            deps = {}
            deps.update(data.get("require", {}))
            deps.update(data.get("require-dev", {}))

            # Clean version constraints
            cleaned = {}
            for pkg, ver in deps.items():
                if pkg == "php":  # Skip PHP version requirement
                    continue
                if isinstance(ver, str):
                    # Remove ^, ~, >=, etc.
                    cleaned[pkg] = re.sub(r'^[\^~>=<|*]+', '', ver).split(',')[0].strip()

            return cleaned
        except Exception as e:
            self.errors.append(f"Error parsing composer.json: {e}")
            return {}

    def parse_gemfile_lock(self, content: str) -> Dict[str, str]:
        """Parse Ruby Gemfile.lock"""
        deps = {}
        in_specs = False

        for line in content.split('\n'):
            if line.strip() == 'specs:':
                in_specs = True
                continue

            if in_specs:
                if line and not line.startswith(' '):
                    in_specs = False
                    continue

                # Match gem name and version
                match = re.match(r'\s{4}(\S+)\s+\(([^)]+)\)', line)
                if match:
                    deps[match.group(1)] = match.group(2)

        return deps

    def parse_go_mod(self, content: str) -> Dict[str, str]:
        """Parse Go go.mod file"""
        deps = {}

        # Match require blocks and single requires
        require_pattern = re.compile(r'require\s+\(\s*(.*?)\s*\)', re.DOTALL)
        single_require = re.compile(r'require\s+(\S+)\s+(\S+)')
        dep_line = re.compile(r'^\s*(\S+)\s+(\S+)')

        # Check for require block
        block_match = require_pattern.search(content)
        if block_match:
            for line in block_match.group(1).split('\n'):
                match = dep_line.match(line.strip())
                if match and not match.group(1).startswith('//'):
                    deps[match.group(1)] = match.group(2).lstrip('v')

        # Check for single-line requires
        for match in single_require.finditer(content):
            deps[match.group(1)] = match.group(2).lstrip('v')

        return deps

    def parse_cargo_toml(self, content: str) -> Dict[str, str]:
        """Parse Rust Cargo.toml"""
        deps = {}
        in_deps = False

        for line in content.split('\n'):
            line = line.strip()

            # Check for dependencies section
            if line in ['[dependencies]', '[dev-dependencies]', '[build-dependencies]']:
                in_deps = True
                continue
            elif line.startswith('[') and in_deps:
                in_deps = False
                continue

            if in_deps and '=' in line:
                # Handle: package = "version" or package = { version = "x" }
                parts = line.split('=', 1)
                pkg = parts[0].strip()
                value = parts[1].strip()

                if value.startswith('"'):
                    # Simple version string
                    version = value.strip('"\'')
                    deps[pkg] = version
                elif value.startswith('{'):
                    # Inline table
                    ver_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', value)
                    if ver_match:
                        deps[pkg] = ver_match.group(1)

        return deps

    def parse_csproj(self, content: str) -> Dict[str, str]:
        """Parse .NET .csproj file"""
        deps = {}

        # Match PackageReference elements
        pattern = re.compile(
            r'<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?',
            re.IGNORECASE
        )

        for match in pattern.finditer(content):
            pkg = match.group(1)
            version = match.group(2) or "latest"
            deps[pkg] = version

        return deps

    def scan_licenses(self, dependencies: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
        """Scan dependency licenses for compliance issues"""
        findings = []
        high_risk_count = 0
        license_stats = {}

        for package, info in dependencies.items():
            license_name = info.get("license", "Unknown")
            version = info.get("version", "unknown")

            license_stats[license_name] = license_stats.get(license_name, 0) + 1

            license_info = self.LICENSE_INFO.get(license_name)

            if license_info and license_info['risk'] in ['high', 'medium']:
                high_risk_count += 1
                findings.append({
                    "package": package,
                    "version": version,
                    "license": license_name,
                    "risk_level": license_info['risk'],
                    "category": license_info.get('category', 'Unknown'),
                    "commercial_use": license_info.get('commercial_use', True),
                    "warning": license_info.get('warning', ''),
                })
            elif not license_info and license_name != "Unknown":
                findings.append({
                    "package": package,
                    "version": version,
                    "license": license_name,
                    "risk_level": "unknown",
                    "warning": "Unrecognized license",
                })

        return {
            "total_packages": len(dependencies),
            "high_risk_licenses": high_risk_count,
            "license_distribution": license_stats,
            "findings": findings
        }

    def generate_sample_findings(self) -> Dict[str, Any]:
        """Generate sample SCA findings for demo"""
        sample_deps = {
            "lodash": "4.17.15",
            "express": "4.16.0",
            "django": "3.1.12",
            "axios": "0.21.1",
            "requests": "2.26.0",
            "log4j-core": "2.14.1",
            "spring-core": "5.3.10",
            "jsonwebtoken": "8.5.1",
            "minimist": "1.2.5",
        }

        # Scan with appropriate ecosystems
        npm_deps = {k: v for k, v in sample_deps.items() if k in ['lodash', 'express', 'axios', 'jsonwebtoken', 'minimist']}
        pip_deps = {k: v for k, v in sample_deps.items() if k in ['django', 'requests']}
        maven_deps = {k: v for k, v in sample_deps.items() if k in ['log4j-core', 'spring-core']}

        npm_results = self.scan_dependencies(npm_deps, "npm")
        pip_results = self.scan_dependencies(pip_deps, "pip")
        maven_results = self.scan_dependencies(maven_deps, "maven")

        # Combine results
        all_findings = npm_results['findings'] + pip_results['findings'] + maven_results['findings']

        return {
            "vulnerabilities": {
                "total_packages": len(sample_deps),
                "vulnerable_packages": len(set(f['package'] for f in all_findings)),
                "total_vulnerabilities": len(all_findings),
                "severity_counts": {
                    "critical": len([f for f in all_findings if f['severity'] == 'critical']),
                    "high": len([f for f in all_findings if f['severity'] == 'high']),
                    "medium": len([f for f in all_findings if f['severity'] == 'medium']),
                    "low": len([f for f in all_findings if f['severity'] == 'low']),
                },
                "findings": all_findings,
                "scan_date": datetime.now().isoformat(),
            },
            "licenses": self.scan_licenses({
                "lodash": {"version": "4.17.21", "license": "MIT"},
                "express": {"version": "4.17.3", "license": "MIT"},
                "django": {"version": "3.2.13", "license": "BSD-3-Clause"},
            })
        }


# Global instance with pre-built indices
sca_scanner = SCAScanner()
