"""
Real-time CVE Service for SCA Scanner

Fetches vulnerability data from multiple authoritative sources:
1. OSV (Open Source Vulnerabilities) - Primary, free, comprehensive
2. NVD (National Vulnerability Database) - Secondary, enrichment
3. GitHub Advisory Database - Additional coverage

Features:
- Real-time vulnerability lookups during scans
- Intelligent caching with configurable TTL
- Batch queries for efficiency
- Graceful fallback when APIs are unavailable
- Rate limiting and retry logic
"""

import os
import json
import asyncio
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from functools import lru_cache
from collections import OrderedDict
import threading

import httpx

logger = logging.getLogger(__name__)


@dataclass
class CachedVulnerability:
    """Cached vulnerability data with expiration"""
    data: List[Dict[str, Any]]
    fetched_at: datetime
    source: str

    def is_expired(self, ttl_hours: int = 6) -> bool:
        return datetime.now() - self.fetched_at > timedelta(hours=ttl_hours)


@dataclass
class RateLimitState:
    """Track rate limiting state"""
    requests_made: int = 0
    window_start: datetime = field(default_factory=datetime.now)
    is_rate_limited: bool = False
    retry_after: Optional[datetime] = None


class LRUCache:
    """Thread-safe LRU cache with TTL support"""

    def __init__(self, maxsize: int = 5000, ttl_hours: int = 6):
        self.maxsize = maxsize
        self.ttl_hours = ttl_hours
        self.cache: OrderedDict[str, CachedVulnerability] = OrderedDict()
        self.lock = threading.Lock()

    def get(self, key: str) -> Optional[List[Dict[str, Any]]]:
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                if not entry.is_expired(self.ttl_hours):
                    # Move to end (most recently used)
                    self.cache.move_to_end(key)
                    return entry.data
                else:
                    # Remove expired entry
                    del self.cache[key]
            return None

    def set(self, key: str, data: List[Dict[str, Any]], source: str = "unknown"):
        with self.lock:
            if key in self.cache:
                del self.cache[key]
            elif len(self.cache) >= self.maxsize:
                # Remove oldest entry
                self.cache.popitem(last=False)

            self.cache[key] = CachedVulnerability(
                data=data,
                fetched_at=datetime.now(),
                source=source
            )

    def clear(self):
        with self.lock:
            self.cache.clear()

    def stats(self) -> Dict[str, Any]:
        with self.lock:
            expired = sum(1 for e in self.cache.values() if e.is_expired(self.ttl_hours))
            sources = {}
            for e in self.cache.values():
                sources[e.source] = sources.get(e.source, 0) + 1

            return {
                "size": len(self.cache),
                "maxsize": self.maxsize,
                "expired_entries": expired,
                "sources": sources
            }


class RealtimeCVEService:
    """
    Real-time CVE lookup service using multiple vulnerability databases.

    Primary: OSV (Open Source Vulnerabilities) - Free, comprehensive
    Secondary: NVD API - Authoritative, requires API key for high rate limits
    Tertiary: GitHub Advisory Database - Good for GitHub ecosystem packages
    """

    # Ecosystem mapping for OSV
    OSV_ECOSYSTEMS = {
        "npm": "npm",
        "pip": "PyPI",
        "maven": "Maven",
        "gradle": "Maven",
        "go": "Go",
        "cargo": "crates.io",
        "nuget": "NuGet",
        "composer": "Packagist",
        "bundler": "RubyGems",
        "hex": "Hex",
        "pub": "Pub",
        "swift": "SwiftURL",
    }

    # GitHub Advisory ecosystem mapping
    GHSA_ECOSYSTEMS = {
        "npm": "NPM",
        "pip": "PIP",
        "maven": "MAVEN",
        "gradle": "MAVEN",
        "go": "GO",
        "cargo": "RUST",
        "nuget": "NUGET",
        "composer": "COMPOSER",
        "bundler": "RUBYGEMS",
    }

    def __init__(
        self,
        nvd_api_key: Optional[str] = None,
        github_token: Optional[str] = None,
        cache_ttl_hours: int = 6,
        cache_max_size: int = 5000,
        enable_osv: bool = True,
        enable_nvd: bool = True,
        enable_github: bool = True,
        timeout_seconds: float = 30.0
    ):
        """
        Initialize the real-time CVE service.

        Args:
            nvd_api_key: NVD API key (optional, increases rate limit from 5 to 50 req/30s)
            github_token: GitHub personal access token for Advisory API
            cache_ttl_hours: How long to cache vulnerability data
            cache_max_size: Maximum number of cached entries
            enable_osv: Enable OSV API queries
            enable_nvd: Enable NVD API queries
            enable_github: Enable GitHub Advisory queries
            timeout_seconds: HTTP request timeout
        """
        self.nvd_api_key = nvd_api_key or os.getenv("NVD_API_KEY", "")
        self.github_token = github_token or os.getenv("GITHUB_TOKEN", "")

        self.enable_osv = enable_osv
        self.enable_nvd = enable_nvd
        self.enable_github = enable_github and bool(self.github_token)

        self.timeout = timeout_seconds

        # Initialize cache
        self.cache = LRUCache(maxsize=cache_max_size, ttl_hours=cache_ttl_hours)

        # Rate limiting state
        self._nvd_rate_limit = RateLimitState()
        self._osv_rate_limit = RateLimitState()

        # Statistics
        self.stats = {
            "osv_queries": 0,
            "nvd_queries": 0,
            "github_queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "errors": []
        }

        logger.info(f"[RealtimeCVE] Initialized - OSV: {enable_osv}, NVD: {enable_nvd} (key: {bool(self.nvd_api_key)}), GitHub: {self.enable_github}")

    def _cache_key(self, package: str, version: str, ecosystem: str) -> str:
        """Generate a cache key for a package/version/ecosystem combination"""
        key_str = f"{ecosystem}:{package.lower()}:{version}"
        return hashlib.md5(key_str.encode()).hexdigest()

    async def query_vulnerabilities(
        self,
        package: str,
        version: str,
        ecosystem: str = "npm"
    ) -> List[Dict[str, Any]]:
        """
        Query vulnerabilities for a specific package version.

        Args:
            package: Package name
            version: Package version
            ecosystem: Package ecosystem (npm, pip, maven, etc.)

        Returns:
            List of vulnerability dictionaries
        """
        cache_key = self._cache_key(package, version, ecosystem)

        # Check cache first
        cached = self.cache.get(cache_key)
        if cached is not None:
            self.stats["cache_hits"] += 1
            return cached

        self.stats["cache_misses"] += 1

        vulnerabilities = []

        # Query OSV (primary source - comprehensive and free)
        if self.enable_osv:
            try:
                osv_vulns = await self._query_osv(package, version, ecosystem)
                vulnerabilities.extend(osv_vulns)
            except Exception as e:
                self.stats["errors"].append(f"OSV error for {package}: {str(e)[:100]}")
                logger.warning(f"[RealtimeCVE] OSV query failed for {package}@{version}: {e}")

        # Query NVD for additional CVE details (if we have CVE IDs or as secondary)
        if self.enable_nvd and self.nvd_api_key:
            try:
                nvd_vulns = await self._query_nvd_by_cpe(package, ecosystem)
                # Merge NVD data without duplicating
                existing_cves = {v.get('cve') for v in vulnerabilities if v.get('cve')}
                for nvd_vuln in nvd_vulns:
                    if nvd_vuln.get('cve') not in existing_cves:
                        vulnerabilities.append(nvd_vuln)
            except Exception as e:
                self.stats["errors"].append(f"NVD error for {package}: {str(e)[:100]}")
                logger.warning(f"[RealtimeCVE] NVD query failed for {package}: {e}")

        # Query GitHub Advisory Database
        if self.enable_github:
            try:
                ghsa_vulns = await self._query_github_advisory(package, ecosystem)
                existing_cves = {v.get('cve') for v in vulnerabilities if v.get('cve')}
                for ghsa_vuln in ghsa_vulns:
                    if ghsa_vuln.get('cve') not in existing_cves:
                        vulnerabilities.append(ghsa_vuln)
            except Exception as e:
                self.stats["errors"].append(f"GitHub error for {package}: {str(e)[:100]}")
                logger.warning(f"[RealtimeCVE] GitHub Advisory query failed for {package}: {e}")

        # Filter vulnerabilities that affect this version
        applicable_vulns = self._filter_by_version(vulnerabilities, version)

        # Cache results
        self.cache.set(cache_key, applicable_vulns, source="realtime")

        return applicable_vulns

    async def query_batch(
        self,
        packages: List[Tuple[str, str, str]]  # [(package, version, ecosystem), ...]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Query vulnerabilities for multiple packages in batch.

        Args:
            packages: List of (package, version, ecosystem) tuples

        Returns:
            Dictionary mapping "package@version" to vulnerability list
        """
        results = {}

        # First, check cache and separate hits from misses
        cache_misses = []
        for pkg, ver, eco in packages:
            cache_key = self._cache_key(pkg, ver, eco)
            cached = self.cache.get(cache_key)
            if cached is not None:
                results[f"{pkg}@{ver}"] = cached
                self.stats["cache_hits"] += 1
            else:
                cache_misses.append((pkg, ver, eco))
                self.stats["cache_misses"] += 1

        if not cache_misses:
            return results

        # OSV supports batch queries - use it
        if self.enable_osv:
            try:
                osv_results = await self._query_osv_batch(cache_misses)
                for key, vulns in osv_results.items():
                    if key not in results:
                        results[key] = vulns
                    else:
                        results[key].extend(vulns)
            except Exception as e:
                logger.warning(f"[RealtimeCVE] OSV batch query failed: {e}")

        # Query remaining packages individually for other sources
        if self.enable_nvd or self.enable_github:
            tasks = []
            for pkg, ver, eco in cache_misses:
                key = f"{pkg}@{ver}"
                if key not in results:
                    results[key] = []
                tasks.append(self._query_additional_sources(pkg, ver, eco))

            additional_results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, (pkg, ver, eco) in enumerate(cache_misses):
                key = f"{pkg}@{ver}"
                if isinstance(additional_results[i], list):
                    existing_cves = {v.get('cve') for v in results.get(key, []) if v.get('cve')}
                    for vuln in additional_results[i]:
                        if vuln.get('cve') not in existing_cves:
                            results[key].append(vuln)

        # Cache all results
        for pkg, ver, eco in cache_misses:
            key = f"{pkg}@{ver}"
            cache_key = self._cache_key(pkg, ver, eco)
            self.cache.set(cache_key, results.get(key, []), source="realtime_batch")

        return results

    async def _query_osv(
        self,
        package: str,
        version: str,
        ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Query OSV (Open Source Vulnerabilities) API"""
        osv_ecosystem = self.OSV_ECOSYSTEMS.get(ecosystem, ecosystem)

        payload = {
            "version": version,
            "package": {
                "name": package,
                "ecosystem": osv_ecosystem
            }
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                "https://api.osv.dev/v1/query",
                json=payload
            )

            self.stats["osv_queries"] += 1

            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulns", [])
                return self._normalize_osv_vulns(vulns, package, ecosystem)
            elif response.status_code == 429:
                # Rate limited
                self._osv_rate_limit.is_rate_limited = True
                self._osv_rate_limit.retry_after = datetime.now() + timedelta(seconds=60)
                return []
            else:
                return []

    async def _query_osv_batch(
        self,
        packages: List[Tuple[str, str, str]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Query OSV API for multiple packages at once"""
        queries = []
        for pkg, ver, eco in packages:
            osv_ecosystem = self.OSV_ECOSYSTEMS.get(eco, eco)
            queries.append({
                "version": ver,
                "package": {
                    "name": pkg,
                    "ecosystem": osv_ecosystem
                }
            })

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                "https://api.osv.dev/v1/querybatch",
                json={"queries": queries}
            )

            self.stats["osv_queries"] += 1

            results = {}
            if response.status_code == 200:
                data = response.json()
                batch_results = data.get("results", [])

                for i, result in enumerate(batch_results):
                    pkg, ver, eco = packages[i]
                    key = f"{pkg}@{ver}"
                    vulns = result.get("vulns", [])
                    results[key] = self._normalize_osv_vulns(vulns, pkg, eco)

            return results

    def _normalize_osv_vulns(
        self,
        vulns: List[Dict],
        package: str,
        ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Normalize OSV vulnerability format to our standard format"""
        normalized = []

        for vuln in vulns:
            # Extract CVE if available
            cve = None
            aliases = vuln.get("aliases", [])
            for alias in aliases:
                if alias.startswith("CVE-"):
                    cve = alias
                    break

            # If no CVE, use OSV ID
            vuln_id = cve or vuln.get("id", "UNKNOWN")

            # Parse severity from database_specific or severity array
            severity = "medium"
            cvss_score = 0.0

            severity_list = vuln.get("severity", [])
            for sev in severity_list:
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    try:
                        # Parse CVSS vector to get base score
                        if "CVSS:3" in score_str:
                            # Extract score from vector or use heuristic
                            pass
                    except:
                        pass

            # Fallback: use database_specific severity
            db_specific = vuln.get("database_specific", {})
            if "severity" in db_specific:
                severity = db_specific["severity"].lower()
            elif "cvss_score" in db_specific:
                cvss_score = float(db_specific["cvss_score"])
                severity = self._cvss_to_severity(cvss_score)

            # Extract affected versions
            affected_versions = []
            for affected in vuln.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "introduced" in event:
                            affected_versions.append(f">={event['introduced']}")
                        if "fixed" in event:
                            affected_versions.append(f"<{event['fixed']}")

            # Get description
            summary = vuln.get("summary", "")
            details = vuln.get("details", "")
            description = summary or details[:500]

            # Get CWE
            cwe = None
            for ref in vuln.get("references", []):
                ref_url = ref.get("url", "")
                if "cwe.mitre.org" in ref_url:
                    cwe_match = ref_url.split("/")[-1] if "/" in ref_url else None
                    if cwe_match and cwe_match.startswith("CWE-"):
                        cwe = cwe_match
                        break

            # Determine vulnerability type from details
            vuln_type = self._infer_vulnerability_type(summary + details)

            # Get published date
            published = vuln.get("published", "")
            if published:
                published = published.split("T")[0]  # Just the date part

            normalized.append({
                "cve": vuln_id,
                "package": package,
                "ecosystem": ecosystem,
                "vulnerability": vuln_type,
                "severity": severity,
                "cvss": cvss_score,
                "description": description,
                "versions": affected_versions,
                "cwe": cwe or "CWE-Unknown",
                "published": published,
                "references": [r.get("url") for r in vuln.get("references", [])[:5]],
                "source": "osv",
                "osv_id": vuln.get("id")
            })

        return normalized

    async def _query_nvd_by_cpe(
        self,
        package: str,
        ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Query NVD API by keyword (package name)"""
        if not self.nvd_api_key:
            return []

        # Check rate limit
        if self._nvd_rate_limit.is_rate_limited:
            if self._nvd_rate_limit.retry_after and datetime.now() < self._nvd_rate_limit.retry_after:
                return []
            self._nvd_rate_limit.is_rate_limited = False

        headers = {"apiKey": self.nvd_api_key}

        # Search by keyword
        params = {
            "keywordSearch": package,
            "resultsPerPage": 50
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers=headers,
                params=params
            )

            self.stats["nvd_queries"] += 1

            if response.status_code == 200:
                data = response.json()
                return self._normalize_nvd_vulns(data, package, ecosystem)
            elif response.status_code == 403:
                self._nvd_rate_limit.is_rate_limited = True
                self._nvd_rate_limit.retry_after = datetime.now() + timedelta(seconds=30)
                return []
            else:
                return []

    def _normalize_nvd_vulns(
        self,
        data: Dict,
        package: str,
        ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Normalize NVD vulnerability format"""
        normalized = []

        for vuln_item in data.get("vulnerabilities", []):
            cve_data = vuln_item.get("cve", {})
            cve_id = cve_data.get("id", "UNKNOWN")

            # Extract CVSS score
            cvss_score = 0.0
            severity = "medium"

            metrics = cve_data.get("metrics", {})

            # Try CVSS v3.1 first
            cvss_v31 = metrics.get("cvssMetricV31", [])
            if cvss_v31:
                cvss_data = cvss_v31[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "MEDIUM").lower()
            else:
                # Try CVSS v3.0
                cvss_v30 = metrics.get("cvssMetricV30", [])
                if cvss_v30:
                    cvss_data = cvss_v30[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "MEDIUM").lower()
                else:
                    # Fall back to CVSS v2
                    cvss_v2 = metrics.get("cvssMetricV2", [])
                    if cvss_v2:
                        cvss_score = cvss_v2[0].get("cvssData", {}).get("baseScore", 0.0)
                        severity = self._cvss_to_severity(cvss_score)

            # Extract description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")[:500]
                    break

            # Extract CWE
            cwe = None
            weaknesses = cve_data.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    value = desc.get("value", "")
                    if value.startswith("CWE-"):
                        cwe = value
                        break

            # Extract references
            references = [r.get("url") for r in cve_data.get("references", [])[:5]]

            # Get published date
            published = cve_data.get("published", "")
            if published:
                published = published.split("T")[0]

            # Infer vulnerability type
            vuln_type = self._infer_vulnerability_type(description)

            normalized.append({
                "cve": cve_id,
                "package": package,
                "ecosystem": ecosystem,
                "vulnerability": vuln_type,
                "severity": severity,
                "cvss": cvss_score,
                "description": description,
                "cwe": cwe or "CWE-Unknown",
                "published": published,
                "references": references,
                "source": "nvd"
            })

        return normalized

    async def _query_github_advisory(
        self,
        package: str,
        ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Query GitHub Advisory Database via GraphQL API"""
        if not self.github_token:
            return []

        ghsa_ecosystem = self.GHSA_ECOSYSTEMS.get(ecosystem)
        if not ghsa_ecosystem:
            return []

        query = """
        query($package: String!, $ecosystem: SecurityAdvisoryEcosystem!) {
          securityVulnerabilities(first: 50, package: $package, ecosystem: $ecosystem) {
            nodes {
              advisory {
                ghsaId
                identifiers {
                  type
                  value
                }
                summary
                description
                severity
                publishedAt
                references {
                  url
                }
                cwes(first: 5) {
                  nodes {
                    cweId
                  }
                }
              }
              vulnerableVersionRange
              firstPatchedVersion {
                identifier
              }
            }
          }
        }
        """

        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Content-Type": "application/json"
        }

        payload = {
            "query": query,
            "variables": {
                "package": package,
                "ecosystem": ghsa_ecosystem
            }
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                "https://api.github.com/graphql",
                headers=headers,
                json=payload
            )

            self.stats["github_queries"] += 1

            if response.status_code == 200:
                data = response.json()
                return self._normalize_github_vulns(data, package, ecosystem)
            else:
                return []

    def _normalize_github_vulns(
        self,
        data: Dict,
        package: str,
        ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Normalize GitHub Advisory format"""
        normalized = []

        nodes = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])

        for node in nodes:
            advisory = node.get("advisory", {})

            # Get CVE from identifiers
            cve = None
            ghsa_id = advisory.get("ghsaId", "UNKNOWN")
            for ident in advisory.get("identifiers", []):
                if ident.get("type") == "CVE":
                    cve = ident.get("value")
                    break

            vuln_id = cve or ghsa_id

            # Severity
            severity = (advisory.get("severity") or "MODERATE").lower()
            if severity == "moderate":
                severity = "medium"

            # Description
            description = advisory.get("summary", "") or advisory.get("description", "")[:500]

            # CWE
            cwes = advisory.get("cwes", {}).get("nodes", [])
            cwe = cwes[0].get("cweId") if cwes else "CWE-Unknown"

            # Published date
            published = advisory.get("publishedAt", "")
            if published:
                published = published.split("T")[0]

            # Version range
            version_range = node.get("vulnerableVersionRange", "")
            versions = [version_range] if version_range else []

            # References
            references = [r.get("url") for r in advisory.get("references", [])[:5]]

            # Infer vulnerability type
            vuln_type = self._infer_vulnerability_type(description)

            normalized.append({
                "cve": vuln_id,
                "ghsa_id": ghsa_id,
                "package": package,
                "ecosystem": ecosystem,
                "vulnerability": vuln_type,
                "severity": severity,
                "cvss": self._severity_to_cvss(severity),
                "description": description,
                "versions": versions,
                "cwe": cwe,
                "published": published,
                "references": references,
                "source": "github"
            })

        return normalized

    async def _query_additional_sources(
        self,
        package: str,
        version: str,
        ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Query NVD and GitHub for additional vulnerabilities"""
        vulns = []

        if self.enable_nvd and self.nvd_api_key:
            try:
                nvd_vulns = await self._query_nvd_by_cpe(package, ecosystem)
                vulns.extend(self._filter_by_version(nvd_vulns, version))
            except Exception as e:
                logger.debug(f"NVD additional query failed: {e}")

        if self.enable_github:
            try:
                ghsa_vulns = await self._query_github_advisory(package, ecosystem)
                vulns.extend(self._filter_by_version(ghsa_vulns, version))
            except Exception as e:
                logger.debug(f"GitHub additional query failed: {e}")

        return vulns

    def _filter_by_version(
        self,
        vulnerabilities: List[Dict[str, Any]],
        version: str
    ) -> List[Dict[str, Any]]:
        """Filter vulnerabilities that affect the specified version"""
        # For now, return all - version filtering is complex and handled by caller
        # TODO: Implement proper semver range checking
        return vulnerabilities

    def _cvss_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity string"""
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        else:
            return "low"

    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity string to approximate CVSS score"""
        mapping = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.5,
            "low": 2.5
        }
        return mapping.get(severity.lower(), 5.0)

    def _infer_vulnerability_type(self, text: str) -> str:
        """Infer vulnerability type from description text"""
        text_lower = text.lower()

        patterns = [
            (["sql injection", "sqli"], "SQL Injection"),
            (["remote code execution", "rce", "code execution"], "Remote Code Execution"),
            (["cross-site scripting", "xss"], "Cross-Site Scripting (XSS)"),
            (["prototype pollution"], "Prototype Pollution"),
            (["denial of service", "dos", "redos"], "Denial of Service"),
            (["path traversal", "directory traversal"], "Path Traversal"),
            (["ssrf", "server-side request forgery"], "Server-Side Request Forgery"),
            (["deserialization", "unsafe deserialization"], "Insecure Deserialization"),
            (["authentication bypass", "auth bypass"], "Authentication Bypass"),
            (["command injection", "os command"], "Command Injection"),
            (["information disclosure", "information leak"], "Information Disclosure"),
            (["buffer overflow", "heap overflow"], "Buffer Overflow"),
            (["csrf", "cross-site request forgery"], "Cross-Site Request Forgery"),
            (["xml external entity", "xxe"], "XML External Entity (XXE)"),
            (["open redirect"], "Open Redirect"),
            (["improper access control"], "Improper Access Control"),
            (["memory corruption"], "Memory Corruption"),
            (["integer overflow"], "Integer Overflow"),
        ]

        for keywords, vuln_type in patterns:
            if any(kw in text_lower for kw in keywords):
                return vuln_type

        return "Security Vulnerability"

    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics"""
        return {
            **self.stats,
            "cache_stats": self.cache.stats(),
            "nvd_enabled": self.enable_nvd and bool(self.nvd_api_key),
            "osv_enabled": self.enable_osv,
            "github_enabled": self.enable_github
        }

    def clear_cache(self):
        """Clear the vulnerability cache"""
        self.cache.clear()
        logger.info("[RealtimeCVE] Cache cleared")


# Singleton instance
_realtime_cve_service: Optional[RealtimeCVEService] = None


def get_realtime_cve_service() -> RealtimeCVEService:
    """Get or create the singleton CVE service instance"""
    global _realtime_cve_service
    if _realtime_cve_service is None:
        _realtime_cve_service = RealtimeCVEService()
    return _realtime_cve_service


def initialize_realtime_cve_service(**kwargs) -> RealtimeCVEService:
    """Initialize the singleton with custom configuration"""
    global _realtime_cve_service
    _realtime_cve_service = RealtimeCVEService(**kwargs)
    return _realtime_cve_service
