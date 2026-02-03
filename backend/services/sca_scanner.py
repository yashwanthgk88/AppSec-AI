"""
SCA (Software Composition Analysis) Scanner - Optimized Version
Professional-grade dependency vulnerability scanner with:
- Pre-indexed vulnerability database for O(1) lookups
- Pre-compiled version constraints
- Version caching to avoid repeated parsing
- Async batch processing for parallel scanning
- NVD API integration for real-time data
- Live vulnerability feeds from GitHub Advisory, OSV, and Snyk
- Transitive dependency analysis
- Support for npm, pip, Maven, Gradle, Composer, RubyGems, Go modules, Cargo, NuGet
"""
from typing import List, Dict, Any, Tuple, Callable, Optional
import json
import re
import os
import asyncio
import httpx
import logging
from datetime import datetime, timedelta
from functools import lru_cache
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# Import vulnerability feeds and transitive analyzer
try:
    from .vulnerability_feeds import (
        UnifiedVulnerabilityFeed,
        batch_check_vulnerabilities,
        VulnerabilitySource
    )
    from .transitive_analyzer import (
        TransitiveDependencyAnalyzer,
        TransitiveVulnerabilityScanner,
        DependencyTree
    )
    FEEDS_AVAILABLE = True
except ImportError:
    FEEDS_AVAILABLE = False


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
        "moment": [
            {
                "versions": ["<2.29.4"],
                "vulnerability": "Path Traversal",
                "cve": ["CVE-2022-31129"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Moment.js has path traversal vulnerability through moment.locale().",
                "remediation": "Upgrade to moment >= 2.29.4 or migrate to date-fns/dayjs",
                "cwe": "CWE-22",
                "owasp": "A01:2021 - Broken Access Control",
                "published": "2022-07-06",
                "ecosystem": "npm"
            },
        ],
        "shell-quote": [
            {
                "versions": ["<1.7.3"],
                "vulnerability": "Command Injection",
                "cve": ["CVE-2021-42740"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "Shell-quote allows command injection via quote method.",
                "remediation": "Upgrade to shell-quote >= 1.7.3",
                "cwe": "CWE-78",
                "owasp": "A03:2021 - Injection",
                "published": "2021-10-21",
                "ecosystem": "npm"
            },
        ],
        "ua-parser-js": [
            {
                "versions": ["<0.7.33", ">=1.0.0,<1.0.33"],
                "vulnerability": "Regular Expression Denial of Service (ReDoS)",
                "cve": ["CVE-2022-25927"],
                "severity": "high",
                "cvss": 7.5,
                "description": "UA-Parser-JS vulnerable to ReDoS via malicious user-agent string.",
                "remediation": "Upgrade to ua-parser-js >= 0.7.33 or >= 1.0.33",
                "cwe": "CWE-1333",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2022-01-25",
                "ecosystem": "npm"
            },
        ],
        "glob-parent": [
            {
                "versions": ["<5.1.2"],
                "vulnerability": "Regular Expression Denial of Service (ReDoS)",
                "cve": ["CVE-2020-28469"],
                "severity": "high",
                "cvss": 7.5,
                "description": "ReDoS vulnerability in glob-parent.",
                "remediation": "Upgrade to glob-parent >= 5.1.2",
                "cwe": "CWE-1333",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2021-01-12",
                "ecosystem": "npm"
            },
        ],
        "trim-newlines": [
            {
                "versions": ["<3.0.1", ">=4.0.0,<4.0.1"],
                "vulnerability": "Regular Expression Denial of Service (ReDoS)",
                "cve": ["CVE-2021-33623"],
                "severity": "high",
                "cvss": 7.5,
                "description": "ReDoS vulnerability in trim-newlines.",
                "remediation": "Upgrade to trim-newlines >= 3.0.1 or >= 4.0.1",
                "cwe": "CWE-1333",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2021-05-28",
                "ecosystem": "npm"
            },
        ],
        "path-parse": [
            {
                "versions": ["<1.0.7"],
                "vulnerability": "Regular Expression Denial of Service (ReDoS)",
                "cve": ["CVE-2021-23343"],
                "severity": "medium",
                "cvss": 5.3,
                "description": "ReDoS vulnerability in path-parse.",
                "remediation": "Upgrade to path-parse >= 1.0.7",
                "cwe": "CWE-1333",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2021-05-04",
                "ecosystem": "npm"
            },
        ],
        "tar": [
            {
                "versions": ["<6.1.11"],
                "vulnerability": "Arbitrary File Overwrite",
                "cve": ["CVE-2021-37713", "CVE-2021-37701", "CVE-2021-37712"],
                "severity": "high",
                "cvss": 8.1,
                "description": "Tar allows arbitrary file creation/overwrite via symlink.",
                "remediation": "Upgrade to tar >= 6.1.11",
                "cwe": "CWE-22",
                "owasp": "A01:2021 - Broken Access Control",
                "published": "2021-08-31",
                "ecosystem": "npm"
            },
        ],
        "semver": [
            {
                "versions": ["<5.7.2", ">=6.0.0,<6.3.1", ">=7.0.0,<7.5.2"],
                "vulnerability": "Regular Expression Denial of Service (ReDoS)",
                "cve": ["CVE-2022-25883"],
                "severity": "medium",
                "cvss": 5.3,
                "description": "Semver vulnerable to ReDoS via malformed version string.",
                "remediation": "Upgrade to semver >= 5.7.2, >= 6.3.1, or >= 7.5.2",
                "cwe": "CWE-1333",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2022-06-23",
                "ecosystem": "npm"
            },
        ],
        "decode-uri-component": [
            {
                "versions": ["<0.2.1"],
                "vulnerability": "Denial of Service via malformed URI",
                "cve": ["CVE-2022-38900"],
                "severity": "high",
                "cvss": 7.5,
                "description": "DoS via malformed URI component.",
                "remediation": "Upgrade to decode-uri-component >= 0.2.1",
                "cwe": "CWE-400",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2022-11-28",
                "ecosystem": "npm"
            },
        ],
        "json5": [
            {
                "versions": ["<2.2.2"],
                "vulnerability": "Prototype Pollution",
                "cve": ["CVE-2022-46175"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Prototype pollution in JSON5 parse method.",
                "remediation": "Upgrade to json5 >= 2.2.2",
                "cwe": "CWE-1321",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "published": "2022-12-24",
                "ecosystem": "npm"
            },
        ],
        "qs": [
            {
                "versions": ["<6.10.3"],
                "vulnerability": "Prototype Pollution",
                "cve": ["CVE-2022-24999"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Prototype pollution via the __proto__ key.",
                "remediation": "Upgrade to qs >= 6.10.3",
                "cwe": "CWE-1321",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "published": "2022-11-26",
                "ecosystem": "npm"
            },
        ],
        "nanoid": [
            {
                "versions": ["<3.1.31"],
                "vulnerability": "Security Bypass",
                "cve": ["CVE-2021-23566"],
                "severity": "medium",
                "cvss": 5.5,
                "description": "Predictable ID generation in certain conditions.",
                "remediation": "Upgrade to nanoid >= 3.1.31",
                "cwe": "CWE-330",
                "owasp": "A02:2021 - Cryptographic Failures",
                "published": "2022-01-14",
                "ecosystem": "npm"
            },
        ],
        "nth-check": [
            {
                "versions": ["<2.0.1"],
                "vulnerability": "Regular Expression Denial of Service (ReDoS)",
                "cve": ["CVE-2021-3803"],
                "severity": "medium",
                "cvss": 5.3,
                "description": "ReDoS vulnerability in nth-check.",
                "remediation": "Upgrade to nth-check >= 2.0.1",
                "cwe": "CWE-1333",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2021-09-17",
                "ecosystem": "npm"
            },
        ],
        "cached-path-relative": [
            {
                "versions": ["<1.1.0"],
                "vulnerability": "Prototype Pollution",
                "cve": ["CVE-2021-23518"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Prototype pollution vulnerability.",
                "remediation": "Upgrade to cached-path-relative >= 1.1.0",
                "cwe": "CWE-1321",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "published": "2022-01-21",
                "ecosystem": "npm"
            },
        ],
        "immer": [
            {
                "versions": ["<9.0.6"],
                "vulnerability": "Prototype Pollution",
                "cve": ["CVE-2021-23436"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "Prototype pollution in Immer library.",
                "remediation": "Upgrade to immer >= 9.0.6",
                "cwe": "CWE-1321",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "published": "2021-09-01",
                "ecosystem": "npm"
            },
        ],
        "follow-redirects": [
            {
                "versions": ["<1.14.8"],
                "vulnerability": "Information Disclosure",
                "cve": ["CVE-2022-0155"],
                "severity": "medium",
                "cvss": 6.5,
                "description": "Sensitive headers exposed on cross-origin redirect.",
                "remediation": "Upgrade to follow-redirects >= 1.14.8",
                "cwe": "CWE-200",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2022-01-10",
                "ecosystem": "npm"
            },
        ],
        "postcss": [
            {
                "versions": ["<8.4.31"],
                "vulnerability": "Line Return Parsing Error",
                "cve": ["CVE-2023-44270"],
                "severity": "medium",
                "cvss": 5.3,
                "description": "Parsing error in external source maps.",
                "remediation": "Upgrade to postcss >= 8.4.31",
                "cwe": "CWE-74",
                "owasp": "A03:2021 - Injection",
                "published": "2023-09-29",
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
        "urllib3": [
            {
                "versions": ["<1.26.18", ">=2.0.0,<2.0.7"],
                "vulnerability": "Request Smuggling",
                "cve": ["CVE-2023-45803"],
                "severity": "medium",
                "cvss": 5.9,
                "description": "HTTP request smuggling vulnerability.",
                "remediation": "Upgrade to urllib3 >= 1.26.18 or >= 2.0.7",
                "cwe": "CWE-444",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2023-10-17",
                "ecosystem": "pip"
            },
        ],
        "certifi": [
            {
                "versions": ["<2023.7.22"],
                "vulnerability": "Removal of e-Tugra Root Certificate",
                "cve": ["CVE-2023-37920"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Certifi includes revoked root certificate.",
                "remediation": "Upgrade to certifi >= 2023.7.22",
                "cwe": "CWE-295",
                "owasp": "A02:2021 - Cryptographic Failures",
                "published": "2023-07-25",
                "ecosystem": "pip"
            },
        ],
        "aiohttp": [
            {
                "versions": ["<3.9.0"],
                "vulnerability": "HTTP Header Injection",
                "cve": ["CVE-2023-49081"],
                "severity": "medium",
                "cvss": 6.5,
                "description": "CRLF injection via improper validation.",
                "remediation": "Upgrade to aiohttp >= 3.9.0",
                "cwe": "CWE-113",
                "owasp": "A03:2021 - Injection",
                "published": "2023-11-28",
                "ecosystem": "pip"
            },
        ],
        "sqlalchemy": [
            {
                "versions": ["<1.4.49", ">=2.0.0,<2.0.21"],
                "vulnerability": "SQL Injection",
                "cve": ["CVE-2023-38325"],
                "severity": "high",
                "cvss": 7.5,
                "description": "SQL injection in text() function.",
                "remediation": "Upgrade to sqlalchemy >= 1.4.49 or >= 2.0.21",
                "cwe": "CWE-89",
                "owasp": "A03:2021 - Injection",
                "published": "2023-08-01",
                "ecosystem": "pip"
            },
        ],
        "setuptools": [
            {
                "versions": ["<65.5.1"],
                "vulnerability": "Regular Expression Denial of Service (ReDoS)",
                "cve": ["CVE-2022-40897"],
                "severity": "medium",
                "cvss": 5.9,
                "description": "ReDoS vulnerability in package_index.",
                "remediation": "Upgrade to setuptools >= 65.5.1",
                "cwe": "CWE-1333",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2022-12-23",
                "ecosystem": "pip"
            },
        ],
        "starlette": [
            {
                "versions": ["<0.36.2"],
                "vulnerability": "Path Traversal",
                "cve": ["CVE-2024-24762"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Path traversal vulnerability in StaticFiles.",
                "remediation": "Upgrade to starlette >= 0.36.2",
                "cwe": "CWE-22",
                "owasp": "A01:2021 - Broken Access Control",
                "published": "2024-02-05",
                "ecosystem": "pip"
            },
        ],
        "fastapi": [
            {
                "versions": ["<0.109.1"],
                "vulnerability": "Denial of Service via Multipart",
                "cve": ["CVE-2024-24763"],
                "severity": "high",
                "cvss": 7.5,
                "description": "DoS via malformed multipart form data.",
                "remediation": "Upgrade to fastapi >= 0.109.1",
                "cwe": "CWE-400",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2024-02-05",
                "ecosystem": "pip"
            },
        ],
        "paramiko": [
            {
                "versions": ["<3.4.0"],
                "vulnerability": "Authentication Bypass",
                "cve": ["CVE-2023-48795"],
                "severity": "medium",
                "cvss": 5.9,
                "description": "Terrapin attack - SSH prefix truncation.",
                "remediation": "Upgrade to paramiko >= 3.4.0",
                "cwe": "CWE-354",
                "owasp": "A02:2021 - Cryptographic Failures",
                "published": "2023-12-18",
                "ecosystem": "pip"
            },
        ],
        "lxml": [
            {
                "versions": ["<4.9.1"],
                "vulnerability": "NULL Pointer Dereference",
                "cve": ["CVE-2022-2309"],
                "severity": "medium",
                "cvss": 5.3,
                "description": "NULL pointer dereference in iterparse.",
                "remediation": "Upgrade to lxml >= 4.9.1",
                "cwe": "CWE-476",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2022-07-05",
                "ecosystem": "pip"
            },
        ],
        "numpy": [
            {
                "versions": ["<1.22.0"],
                "vulnerability": "Buffer Overflow",
                "cve": ["CVE-2021-41496"],
                "severity": "medium",
                "cvss": 5.5,
                "description": "Buffer overflow in array_from_pyobj.",
                "remediation": "Upgrade to numpy >= 1.22.0",
                "cwe": "CWE-120",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2021-12-17",
                "ecosystem": "pip"
            },
        ],
        "tornado": [
            {
                "versions": ["<6.3.3"],
                "vulnerability": "HTTP Response Splitting",
                "cve": ["CVE-2023-28370"],
                "severity": "medium",
                "cvss": 6.1,
                "description": "CRLF injection in set_header.",
                "remediation": "Upgrade to tornado >= 6.3.3",
                "cwe": "CWE-113",
                "owasp": "A03:2021 - Injection",
                "published": "2023-05-25",
                "ecosystem": "pip"
            },
        ],
        "gunicorn": [
            {
                "versions": ["<22.0.0"],
                "vulnerability": "HTTP Request Smuggling",
                "cve": ["CVE-2024-1135"],
                "severity": "high",
                "cvss": 7.5,
                "description": "HTTP request smuggling via improper parsing.",
                "remediation": "Upgrade to gunicorn >= 22.0.0",
                "cwe": "CWE-444",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2024-04-16",
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
        "commons-fileupload": [
            {
                "versions": ["<1.5"],
                "vulnerability": "Denial of Service via FileUpload",
                "cve": ["CVE-2023-24998"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Apache Commons FileUpload DoS via malicious upload.",
                "remediation": "Upgrade to commons-fileupload >= 1.5",
                "cwe": "CWE-400",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2023-02-20",
                "ecosystem": "maven"
            },
        ],
        "commons-io": [
            {
                "versions": ["<2.7"],
                "vulnerability": "Path Traversal",
                "cve": ["CVE-2021-29425"],
                "severity": "medium",
                "cvss": 5.3,
                "description": "Limited path traversal vulnerability.",
                "remediation": "Upgrade to commons-io >= 2.7",
                "cwe": "CWE-22",
                "owasp": "A01:2021 - Broken Access Control",
                "published": "2021-04-13",
                "ecosystem": "maven"
            },
        ],
        "commons-collections4": [
            {
                "versions": ["<4.1"],
                "vulnerability": "Deserialization of Untrusted Data",
                "cve": ["CVE-2015-7501"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "Java deserialization vulnerability enabling RCE.",
                "remediation": "Upgrade to commons-collections4 >= 4.1",
                "cwe": "CWE-502",
                "owasp": "A08:2021 - Software and Data Integrity Failures",
                "published": "2015-11-06",
                "ecosystem": "maven"
            },
        ],
        "mysql-connector-java": [
            {
                "versions": ["<8.0.28"],
                "vulnerability": "Improper Access Control",
                "cve": ["CVE-2022-21363"],
                "severity": "medium",
                "cvss": 6.6,
                "description": "Connector/J vulnerability allowing unauthorized access.",
                "remediation": "Upgrade to mysql-connector-java >= 8.0.28",
                "cwe": "CWE-284",
                "owasp": "A01:2021 - Broken Access Control",
                "published": "2022-01-18",
                "ecosystem": "maven"
            },
        ],
        "spring-boot-starter-web": [
            {
                "versions": ["<2.5.12", ">=2.6.0,<2.6.6"],
                "vulnerability": "Spring4Shell RCE",
                "cve": ["CVE-2022-22965"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "RCE via data binding on JDK 9+.",
                "remediation": "Upgrade to spring-boot >= 2.5.12 or >= 2.6.6",
                "cwe": "CWE-94",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "published": "2022-04-01",
                "ecosystem": "maven"
            },
        ],
        "keycloak-saml-core": [
            {
                "versions": ["<20.0.0"],
                "vulnerability": "SAML Signature Validation Bypass",
                "cve": ["CVE-2023-0091"],
                "severity": "high",
                "cvss": 8.1,
                "description": "SAML signature validation can be bypassed.",
                "remediation": "Upgrade to keycloak >= 20.0.0",
                "cwe": "CWE-347",
                "owasp": "A02:2021 - Cryptographic Failures",
                "published": "2023-01-13",
                "ecosystem": "maven"
            },
        ],
        "slf4j-log4j12": [
            {
                "versions": ["<1.7.35"],
                "vulnerability": "Log4j Dependency Vulnerability",
                "cve": ["CVE-2021-44228"],
                "severity": "critical",
                "cvss": 10.0,
                "description": "Transitive Log4j vulnerability via SLF4J binding.",
                "remediation": "Upgrade to slf4j-log4j12 >= 1.7.35 or use slf4j-reload4j",
                "cwe": "CWE-502",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "published": "2021-12-10",
                "ecosystem": "maven"
            },
        ],
        "spring-webmvc": [
            {
                "versions": ["<5.3.18", ">=5.2.0,<5.2.20"],
                "vulnerability": "Remote Code Execution (Spring4Shell)",
                "cve": ["CVE-2022-22965"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "RCE via data binding on JDK 9+.",
                "remediation": "Upgrade to spring-webmvc >= 5.3.18",
                "cwe": "CWE-94",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "published": "2022-04-01",
                "ecosystem": "maven"
            },
        ],
        "hibernate-core": [
            {
                "versions": ["<5.4.24", ">=5.5.0,<5.6.1"],
                "vulnerability": "SQL Injection",
                "cve": ["CVE-2020-25638"],
                "severity": "high",
                "cvss": 7.4,
                "description": "SQL injection via DML statements.",
                "remediation": "Upgrade to hibernate-core >= 5.4.24 or >= 5.6.1",
                "cwe": "CWE-89",
                "owasp": "A03:2021 - Injection",
                "published": "2020-12-02",
                "ecosystem": "maven"
            },
        ],
        "gson": [
            {
                "versions": ["<2.8.9"],
                "vulnerability": "Deserialization of Untrusted Data",
                "cve": ["CVE-2022-25647"],
                "severity": "high",
                "cvss": 7.5,
                "description": "Unsafe deserialization can lead to DoS.",
                "remediation": "Upgrade to gson >= 2.8.9",
                "cwe": "CWE-502",
                "owasp": "A08:2021 - Software and Data Integrity Failures",
                "published": "2022-05-01",
                "ecosystem": "maven"
            },
        ],
        "tomcat-embed-core": [
            {
                "versions": ["<9.0.43", ">=10.0.0,<10.0.2"],
                "vulnerability": "HTTP Request Smuggling",
                "cve": ["CVE-2021-25122"],
                "severity": "high",
                "cvss": 7.5,
                "description": "HTTP request smuggling vulnerability.",
                "remediation": "Upgrade to tomcat >= 9.0.43 or >= 10.0.2",
                "cwe": "CWE-444",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2021-03-01",
                "ecosystem": "maven"
            },
        ],
        "snakeyaml": [
            {
                "versions": ["<1.32"],
                "vulnerability": "Denial of Service via YAML Parsing",
                "cve": ["CVE-2022-25857"],
                "severity": "high",
                "cvss": 7.5,
                "description": "DoS via deeply nested YAML documents.",
                "remediation": "Upgrade to snakeyaml >= 1.32",
                "cwe": "CWE-400",
                "owasp": "A04:2021 - Insecure Design",
                "published": "2022-08-30",
                "ecosystem": "maven"
            },
        ],
        "h2": [
            {
                "versions": ["<2.1.210"],
                "vulnerability": "Remote Code Execution",
                "cve": ["CVE-2021-42392"],
                "severity": "critical",
                "cvss": 9.8,
                "description": "JNDI injection via H2 Console.",
                "remediation": "Upgrade to h2 >= 2.1.210",
                "cwe": "CWE-502",
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "published": "2022-01-06",
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

    def __init__(self, ai_impact_service=None, ai_impact_enabled: bool = True):
        """
        Initialize with pre-indexed database and compiled constraints

        Args:
            ai_impact_service: Optional AI impact service for dynamic impact generation
            ai_impact_enabled: Whether to use AI for impact generation (default True)
        """
        self.scanned_packages = 0
        self.errors = []

        # AI Impact Service configuration
        self.ai_impact_service = ai_impact_service
        self.ai_impact_enabled = ai_impact_enabled

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
            # Normalize package name to lowercase for consistent matching
            package_name_normalized = package_name.lower()

            for vuln_info in vuln_list:
                ecosystem = vuln_info.get('ecosystem', 'npm')

                if package_name_normalized not in self._vuln_by_ecosystem[ecosystem]:
                    self._vuln_by_ecosystem[ecosystem][package_name_normalized] = []

                self._vuln_by_ecosystem[ecosystem][package_name_normalized].append(vuln_info)

                # Pre-compile version constraints for this vulnerability
                constraint_key = f"{package_name_normalized}:{','.join(vuln_info['versions'])}"
                if constraint_key not in self._compiled_constraints:
                    self._compiled_constraints[constraint_key] = [
                        self._compile_constraint(v) for v in vuln_info['versions']
                    ]

        logger.info(f"[SCA] Built vulnerability indices for {len(self.VULNERABLE_PACKAGES)} packages")

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

    def _generate_sca_impact(self, vuln_type: str, severity: str, cve: str, package: str,
                              installed_version: str = "", ecosystem: str = "npm",
                              cvss_score: float = 0.0) -> Dict[str, str]:
        """
        Generate detailed impact statement and recommendation for SCA findings.
        Uses AI when available, falls back to static templates otherwise.

        Args:
            vuln_type: Type of vulnerability
            severity: Severity level
            cve: CVE identifier
            package: Package name
            installed_version: Installed version of the package
            ecosystem: Package ecosystem (npm, pip, etc.)
            cvss_score: CVSS score

        Returns:
            Dictionary with 'impact', 'recommendation', and 'generated_by' keys
        """
        # Try AI generation if enabled
        if self.ai_impact_enabled and self.ai_impact_service:
            try:
                vuln_info = {
                    "vulnerability": vuln_type,
                    "package": package,
                    "installed_version": installed_version,
                    "cve": cve,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "ecosystem": ecosystem
                }

                ai_result = self.ai_impact_service.generate_impact_statement(
                    finding_type="sca",
                    vulnerability_info=vuln_info
                )

                return {
                    "business_impact": ai_result.get('business_impact', 'Impact assessment unavailable'),
                    "technical_impact": ai_result.get('technical_impact', 'Technical impact unavailable'),
                    "recommendations": ai_result.get('recommendations', ''),
                    "generated_by": ai_result.get('generated_by', 'ai')
                }

            except Exception as e:
                logger.warning(f"[SCAScanner] AI impact generation failed: {e}")
                # Fall through to static generation

        # Static fallback generation
        return self._generate_static_sca_impact(vuln_type, severity, cve, package)

    def _generate_static_sca_impact(self, vuln_type: str, severity: str, cve: str, package: str) -> Dict[str, str]:
        """Generate static impact statement when AI is unavailable."""
        # Severity-based business impact
        severity_impacts = {
            "critical": """**Business Impact:**
- Immediate risk of exploitation with publicly available exploits
- Potential for complete system compromise and data breach
- Regulatory compliance violations (PCI-DSS, HIPAA, GDPR)
- Emergency patching required within 24-48 hours
- High probability of being targeted by automated attack tools""",
            "high": """**Business Impact:**
- Significant security risk requiring urgent attention
- Potential for unauthorized access or data exposure
- May enable attack chains when combined with other vulnerabilities
- Should be remediated within 1-2 weeks
- Increased risk of targeted attacks""",
            "medium": """**Business Impact:**
- Moderate security risk with limited exploitation potential
- May require specific conditions to exploit
- Should be remediated within 30 days
- Lower priority but still important for defense in depth""",
            "low": """**Business Impact:**
- Low security risk with minimal exploitation potential
- Typically requires significant access or unlikely conditions
- Should be tracked and remediated during regular maintenance cycles
- Important for overall security hygiene"""
        }

        # Vulnerability type-based technical impact
        vuln_type_lower = vuln_type.lower()
        if "rce" in vuln_type_lower or "remote code" in vuln_type_lower or "arbitrary code" in vuln_type_lower:
            tech_impact = """**Technical Impact:**
- Remote Code Execution (RCE) allowing attackers to run arbitrary commands
- Complete server compromise with application privileges
- Potential for backdoor installation and persistent access
- Risk of lateral movement within the network
- Data exfiltration and system manipulation"""
        elif "sql injection" in vuln_type_lower:
            tech_impact = """**Technical Impact:**
- Database compromise and unauthorized data access
- Authentication bypass and privilege escalation
- Data manipulation, deletion, or encryption (ransomware)
- Potential for operating system command execution via database features"""
        elif "prototype pollution" in vuln_type_lower:
            tech_impact = """**Technical Impact:**
- Object prototype manipulation affecting all objects in the application
- Potential for denial of service through property collisions
- Possible Remote Code Execution depending on application logic
- Authentication bypass through modified object properties"""
        elif "xss" in vuln_type_lower or "cross-site scripting" in vuln_type_lower:
            tech_impact = """**Technical Impact:**
- Client-side code execution in user browsers
- Session hijacking through cookie theft
- Credential harvesting via phishing within the application
- Malware distribution to application users"""
        elif "ssrf" in vuln_type_lower or "request forgery" in vuln_type_lower:
            tech_impact = """**Technical Impact:**
- Internal network scanning and service discovery
- Access to cloud metadata APIs exposing credentials
- Bypass of firewall and network access controls
- Potential for further exploitation of internal services"""
        elif "denial of service" in vuln_type_lower or "dos" in vuln_type_lower or "redos" in vuln_type_lower:
            tech_impact = """**Technical Impact:**
- Application unavailability affecting business operations
- Resource exhaustion (CPU, memory, network)
- Potential for cascading failures in dependent services
- Customer impact and SLA violations"""
        elif "path traversal" in vuln_type_lower or "directory traversal" in vuln_type_lower:
            tech_impact = """**Technical Impact:**
- Arbitrary file read exposing sensitive configuration
- Access to source code and credentials
- Potential for file write leading to code execution"""
        elif "deserialization" in vuln_type_lower:
            tech_impact = """**Technical Impact:**
- Remote Code Execution through malicious serialized objects
- Application logic bypass through object manipulation
- Potential for complete server compromise"""
        else:
            tech_impact = """**Technical Impact:**
- Security weakness in third-party dependency
- Attack surface expansion through vulnerable code paths
- Risk increases if vulnerability is publicly known ({})""".format(cve)

        impact = severity_impacts.get(severity, severity_impacts["medium"]) + "\n\n" + tech_impact

        recommendation = """**Immediate Actions:**
1. Upgrade {} to the latest patched version immediately
2. Review application logs for signs of exploitation
3. If upgrade not possible, evaluate workarounds or mitigating controls
4. Check if vulnerability is being actively exploited (check CVE references)

**Long-term Remediation:**
1. Implement automated dependency scanning in CI/CD pipeline
2. Configure alerts for new vulnerabilities in project dependencies
3. Establish a regular dependency update schedule
4. Consider using dependency lock files to ensure reproducible builds
5. Evaluate alternative packages if the maintainer is unresponsive""".format(package)

        # Extract business and technical impact separately (strip the headers)
        business_impact = severity_impacts.get(severity, severity_impacts["medium"]).replace("**Business Impact:**\n", "").strip()
        technical_impact_text = tech_impact.replace("**Technical Impact:**\n", "").strip()

        return {
            "business_impact": business_impact,
            "technical_impact": technical_impact_text,
            "recommendations": recommendation,
            "generated_by": "static"
        }

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

        logger.info(f"[SCA] Scanning {total_packages} {ecosystem} dependencies against {len(ecosystem_vulns)} known vulnerable packages")

        # Debug: Log first few dependencies being scanned
        sample_deps = list(dependencies.items())[:5]
        logger.debug(f"[SCA] Sample dependencies: {sample_deps}")

        for package, version in dependencies.items():
            # Normalize package name for consistent matching
            package_normalized = package.lower()

            # O(1) lookup for package vulnerabilities
            if package_normalized not in ecosystem_vulns:
                continue

            logger.info(f"[SCA] Found potentially vulnerable package: {package} v{version}")

            vuln_list = ecosystem_vulns[package_normalized]
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

                    # Generate detailed impact and recommendation (with AI if enabled)
                    impact_info = self._generate_sca_impact(
                        vuln_type=vuln_info['vulnerability'],
                        severity=vuln_info['severity'],
                        cve=cves[0],
                        package=package,
                        installed_version=version,
                        ecosystem=ecosystem,
                        cvss_score=vuln_info['cvss']
                    )

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
                        "business_impact": impact_info.get('business_impact', ''),
                        "technical_impact": impact_info.get('technical_impact', ''),
                        "recommendations": impact_info.get('recommendations', ''),
                        "published_date": vuln_info.get('published', 'N/A'),
                        "stride_category": self._map_to_stride(vuln_info['vulnerability']),
                        "mitre_attack_id": "T1195.001",
                        "ecosystem": ecosystem,
                        "impact_generated_by": impact_info.get('generated_by', 'static')
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

            # Clean version strings (remove ^, ~, etc.) and normalize package names
            cleaned = {}
            for pkg, ver in deps.items():
                if isinstance(ver, str):
                    # Normalize package name (lowercase for consistent matching)
                    pkg_normalized = pkg.lower()
                    # Clean version string
                    cleaned[pkg_normalized] = ver.lstrip('^~>=<').split(' ')[0]

            logger.info(f"[SCA] Parsed package.json: {len(cleaned)} dependencies")
            return cleaned
        except Exception as e:
            self.errors.append(f"Error parsing package.json: {e}")
            logger.error(f"[SCA] Error parsing package.json: {e}")
            return {}

    def parse_package_lock_json(self, content: str) -> Dict[str, str]:
        """Parse package-lock.json (npm v2/v3 format)"""
        try:
            data = json.loads(content)
            deps = {}

            # NPM v3 format uses "packages" key
            packages = data.get("packages", {})
            if packages:
                for pkg_path, pkg_info in packages.items():
                    if pkg_path and "node_modules/" in pkg_path:
                        # Extract package name from path
                        pkg_name = pkg_path.split("node_modules/")[-1]
                        # Handle scoped packages
                        if "/" in pkg_name and not pkg_name.startswith("@"):
                            pkg_name = pkg_name.split("/")[0]
                        version = pkg_info.get("version", "")
                        if version:
                            deps[pkg_name.lower()] = version

            # NPM v1/v2 format uses "dependencies" key
            if not deps:
                dependencies = data.get("dependencies", {})
                for pkg_name, pkg_info in dependencies.items():
                    if isinstance(pkg_info, dict):
                        version = pkg_info.get("version", "")
                        if version:
                            deps[pkg_name.lower()] = version
                    elif isinstance(pkg_info, str):
                        deps[pkg_name.lower()] = pkg_info

            logger.info(f"[SCA] Parsed package-lock.json: {len(deps)} dependencies")
            return deps
        except Exception as e:
            self.errors.append(f"Error parsing package-lock.json: {e}")
            logger.error(f"[SCA] Error parsing package-lock.json: {e}")
            return {}

    def parse_yarn_lock(self, content: str) -> Dict[str, str]:
        """Parse yarn.lock format"""
        deps = {}
        try:
            current_pkg = None

            for line in content.split('\n'):
                line = line.rstrip()

                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Package definition line (e.g., "lodash@^4.17.0:")
                if not line.startswith(' ') and line.endswith(':'):
                    # Extract package name from definition
                    pkg_def = line.rstrip(':').strip('"')
                    # Handle multiple version specs (e.g., "lodash@^4.17.0, lodash@~4.17.0:")
                    first_spec = pkg_def.split(',')[0].strip()
                    # Extract package name (before the @version)
                    if '@' in first_spec:
                        # Handle scoped packages (@scope/name@version)
                        if first_spec.startswith('@'):
                            parts = first_spec.rsplit('@', 1)
                            current_pkg = parts[0].lower()
                        else:
                            current_pkg = first_spec.split('@')[0].lower()
                    else:
                        current_pkg = first_spec.lower()

                # Version line (e.g., "  version "4.17.21"")
                elif current_pkg and '  version' in line:
                    match = re.search(r'version\s+"?([^"]+)"?', line)
                    if match:
                        version = match.group(1).strip()
                        deps[current_pkg] = version
                        current_pkg = None

            logger.info(f"[SCA] Parsed yarn.lock: {len(deps)} dependencies")
            return deps
        except Exception as e:
            self.errors.append(f"Error parsing yarn.lock: {e}")
            logger.error(f"[SCA] Error parsing yarn.lock: {e}")
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
        """Parse Maven pom.xml with property resolution"""
        deps = {}

        # First extract Maven properties for version resolution
        properties = {}

        # Extract properties from <properties> section
        props_pattern = re.compile(r'<properties>(.*?)</properties>', re.DOTALL)
        props_match = props_pattern.search(content)
        if props_match:
            props_content = props_match.group(1)
            # Extract each property
            prop_pattern = re.compile(r'<([^>]+)>([^<]+)</\1>')
            for prop_match in prop_pattern.finditer(props_content):
                prop_name = prop_match.group(1).strip()
                prop_value = prop_match.group(2).strip()
                properties[prop_name] = prop_value

        # Also check for parent version
        parent_pattern = re.compile(
            r'<parent>\s*.*?<version>([^<]+)</version>.*?</parent>',
            re.DOTALL
        )
        parent_match = parent_pattern.search(content)
        if parent_match:
            properties['project.parent.version'] = parent_match.group(1).strip()

        logger.debug(f"[SCA] Parsed Maven properties: {properties}")

        def resolve_version(version_str: str) -> str:
            """Resolve Maven property references like ${property.name}"""
            if not version_str or not version_str.startswith('$'):
                return version_str

            # Extract property name from ${property.name}
            prop_match = re.match(r'\$\{([^}]+)\}', version_str)
            if prop_match:
                prop_name = prop_match.group(1)
                # Try direct match
                if prop_name in properties:
                    return properties[prop_name]
                # Try with dots replaced (e.g., springboot.version)
                for key, value in properties.items():
                    if key.replace('.', '').lower() == prop_name.replace('.', '').lower():
                        return value
                    # Also try partial matches
                    if prop_name.endswith('.version') and key.endswith('.version'):
                        base_name = prop_name.replace('.version', '')
                        if base_name in key.lower():
                            return value

            return version_str  # Return original if not resolved

        # Parse dependencies
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
            version_raw = match.group(3).strip() if match.group(3) else "latest"

            # Resolve version if it's a property reference
            version = resolve_version(version_raw)

            # Use artifact_id as primary key (most vuln DBs use this)
            deps[artifact_id] = version
            # Also store full coordinate
            deps[f"{group_id}:{artifact_id}"] = version

        logger.info(f"[SCA] Parsed pom.xml: {len(deps)} dependencies")
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

    # ==================== LIVE VULNERABILITY FEEDS ====================

    async def scan_with_live_feeds(
        self,
        dependencies: Dict[str, str],
        ecosystem: str = "npm",
        use_local_db: bool = True,
        use_live_feeds: bool = True
    ) -> Dict[str, Any]:
        """
        Scan dependencies using both local database and live vulnerability feeds.

        Args:
            dependencies: {"package_name": "version"}
            ecosystem: Package ecosystem
            use_local_db: Whether to use local vulnerability database
            use_live_feeds: Whether to query live feeds (GitHub Advisory, OSV, Snyk)

        Returns:
            Combined scan results from all sources
        """
        all_findings = []
        sources_used = []

        # Scan with local database
        if use_local_db:
            local_results = self.scan_dependencies(dependencies, ecosystem)
            all_findings.extend(local_results.get("findings", []))
            sources_used.append("local")

        # Scan with live feeds
        if use_live_feeds and FEEDS_AVAILABLE:
            try:
                live_results = await batch_check_vulnerabilities(dependencies, ecosystem)
                live_findings = live_results.get("findings", [])

                # Build comprehensive deduplication keys from existing findings
                # Use package+CVE and package+title as keys to catch all duplicates
                existing_keys = set()
                for f in all_findings:
                    pkg = f.get("package", "").lower()
                    cve = f.get("cve", "")
                    title = f.get("vulnerability", "").lower()
                    # Add multiple keys for robust deduplication
                    if cve:
                        existing_keys.add(f"{pkg}:{cve}")
                        existing_keys.add(cve)  # Also track CVE alone
                    if title:
                        existing_keys.add(f"{pkg}:{title[:50]}")  # First 50 chars of title

                for finding in live_findings:
                    pkg = finding.get("package", "").lower()
                    cve = finding.get("cve", "")
                    title = finding.get("vulnerability", "").lower()

                    # Check all possible duplicate keys
                    is_duplicate = False
                    if cve and (cve in existing_keys or f"{pkg}:{cve}" in existing_keys):
                        is_duplicate = True
                    if title and f"{pkg}:{title[:50]}" in existing_keys:
                        is_duplicate = True

                    if not is_duplicate:
                        all_findings.append(finding)
                        # Add keys for this finding
                        if cve:
                            existing_keys.add(f"{pkg}:{cve}")
                            existing_keys.add(cve)
                        if title:
                            existing_keys.add(f"{pkg}:{title[:50]}")

                sources_used.extend(live_results.get("sources", []))
            except Exception as e:
                self.errors.append(f"Live feed scan failed: {e}")

        # Calculate severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            sev = f.get('severity', 'medium')
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "total_packages": len(dependencies),
            "vulnerable_packages": len(set(f['package'] for f in all_findings)),
            "total_vulnerabilities": len(all_findings),
            "severity_counts": severity_counts,
            "findings": all_findings,
            "scan_date": datetime.now().isoformat(),
            "ecosystem": ecosystem,
            "sources": list(set(sources_used))
        }

    # ==================== TRANSITIVE DEPENDENCY ANALYSIS ====================

    def scan_lockfile_with_transitives(
        self,
        lockfile_content: str,
        lockfile_type: str,
        project_name: str = "project"
    ) -> Dict[str, Any]:
        """
        Scan a lockfile and analyze both direct and transitive dependencies.

        Args:
            lockfile_content: Contents of the lockfile
            lockfile_type: Type of lockfile (npm, yarn, pip, maven, go, cargo)
            project_name: Name of the project

        Returns:
            Scan results with transitive dependency information
        """
        if not FEEDS_AVAILABLE:
            # Fall back to basic scanning
            ecosystem_map = {
                'npm': 'npm', 'yarn': 'npm', 'pip': 'pip',
                'maven': 'maven', 'gradle': 'maven',
                'go': 'go', 'cargo': 'cargo'
            }
            ecosystem = ecosystem_map.get(lockfile_type.lower(), 'npm')
            deps = self._parse_file_by_type(lockfile_content, lockfile_type)
            return self.scan_dependencies(deps, ecosystem)

        scanner = TransitiveVulnerabilityScanner(sca_scanner=self)
        return scanner.scan_with_tree(lockfile_content, lockfile_type, project_name)

    def get_dependency_tree(
        self,
        lockfile_content: str,
        lockfile_type: str,
        project_name: str = "project"
    ) -> Dict[str, Any]:
        """
        Extract and return the dependency tree without vulnerability scanning.

        Args:
            lockfile_content: Contents of the lockfile
            lockfile_type: Type of lockfile
            project_name: Name of the project

        Returns:
            Dependency tree structure
        """
        if not FEEDS_AVAILABLE:
            return {"error": "Transitive analysis not available"}

        analyzer = TransitiveDependencyAnalyzer()
        tree = analyzer.analyze_lockfile(lockfile_content, lockfile_type, project_name)

        return {
            "root": project_name,
            "ecosystem": tree.ecosystem,
            "total_packages": len(tree.all_deps),
            "direct_packages": len(tree.direct_deps),
            "transitive_packages": len(tree.all_deps) - len(tree.direct_deps),
            "packages": tree.get_all_packages(),
            "nodes": {
                k: {
                    "name": v.name,
                    "version": v.version,
                    "is_direct": v.is_direct,
                    "depth": v.depth,
                    "parent": v.parent,
                    "children": v.children,
                    "dev_dependency": v.dev_dependency
                }
                for k, v in tree.nodes.items()
            }
        }

    async def full_scan(
        self,
        lockfile_content: str,
        lockfile_type: str,
        project_name: str = "project",
        use_live_feeds: bool = True
    ) -> Dict[str, Any]:
        """
        Perform a comprehensive scan with:
        - Local vulnerability database
        - Live vulnerability feeds
        - Transitive dependency analysis

        Args:
            lockfile_content: Contents of the lockfile
            lockfile_type: Type of lockfile
            project_name: Name of the project
            use_live_feeds: Whether to query live feeds

        Returns:
            Comprehensive scan results
        """
        # First get the transitive analysis
        transitive_results = self.scan_lockfile_with_transitives(
            lockfile_content, lockfile_type, project_name
        )

        # If live feeds requested, enhance with live data
        if use_live_feeds and FEEDS_AVAILABLE:
            all_packages = {
                node["name"]: node["version"]
                for node in transitive_results.get("dependency_tree", {}).get("nodes", {}).values()
            }

            if all_packages:
                ecosystem = transitive_results.get("ecosystem", "npm")
                try:
                    live_results = await batch_check_vulnerabilities(all_packages, ecosystem)

                    # Build comprehensive deduplication keys
                    existing_keys = set()
                    for f in transitive_results.get("findings", []):
                        pkg = f.get("package", "").lower()
                        cve = f.get("cve", "")
                        title = f.get("vulnerability", "").lower()
                        if cve:
                            existing_keys.add(f"{pkg}:{cve}")
                            existing_keys.add(cve)
                        if title:
                            existing_keys.add(f"{pkg}:{title[:50]}")

                    for finding in live_results.get("findings", []):
                        pkg = finding.get("package", "").lower()
                        cve = finding.get("cve", "")
                        title = finding.get("vulnerability", "").lower()

                        # Check for duplicates
                        is_duplicate = False
                        if cve and (cve in existing_keys or f"{pkg}:{cve}" in existing_keys):
                            is_duplicate = True
                        if title and f"{pkg}:{title[:50]}" in existing_keys:
                            is_duplicate = True

                        if not is_duplicate:
                            # Add transitive info
                            pkg_name = finding.get("package", "")

                            for key, node in transitive_results.get("dependency_tree", {}).get("nodes", {}).items():
                                if node["name"] == pkg_name:
                                    finding["is_direct_dependency"] = node["is_direct"]
                                    finding["dependency_depth"] = node["depth"]
                                    finding["introduced_by"] = node["parent"]
                                    break

                            transitive_results["findings"].append(finding)
                            # Add keys for deduplication
                            if cve:
                                existing_keys.add(f"{pkg}:{cve}")
                                existing_keys.add(cve)
                            if title:
                                existing_keys.add(f"{pkg}:{title[:50]}")

                    transitive_results["sources"] = list(set(
                        transitive_results.get("sources", ["local"]) +
                        live_results.get("sources", [])
                    ))

                except Exception as e:
                    self.errors.append(f"Live feed enhancement failed: {e}")

        # Recalculate statistics
        findings = transitive_results.get("findings", [])
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get('severity', 'medium')
            if sev in severity_counts:
                severity_counts[sev] += 1

        transitive_results["severity_counts"] = severity_counts
        transitive_results["total_vulnerabilities"] = len(findings)
        transitive_results["vulnerable_packages"] = len(set(f.get("package") for f in findings))

        # Separate direct vs transitive
        transitive_results["direct_findings"] = [
            f for f in findings if f.get("is_direct_dependency", True)
        ]
        transitive_results["transitive_findings"] = [
            f for f in findings if not f.get("is_direct_dependency", True)
        ]
        transitive_results["direct_vulnerabilities"] = len(transitive_results["direct_findings"])
        transitive_results["transitive_vulnerabilities"] = len(transitive_results["transitive_findings"])

        return transitive_results


# Global instance with pre-built indices
sca_scanner = SCAScanner()
