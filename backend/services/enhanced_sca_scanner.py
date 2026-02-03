"""
Enhanced SCA Scanner with Live NVD/OSV Database Integration
Supports: Maven (Java), npm (Node.js), pip (Python), NuGet (.NET), Composer (PHP), Go modules
"""
import re
import os
import json
import logging
import asyncio
import httpx
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """Represents a vulnerability in a dependency"""
    package: str
    version: str
    vulnerability_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cwe_id: str
    fixed_versions: List[str]
    source: str
    published_date: str
    ecosystem: str


class EnhancedSCAScanner:
    """
    Comprehensive SCA scanner with live vulnerability database queries
    """

    # OSV API endpoint (free, no auth required)
    OSV_API = "https://api.osv.dev/v1"

    # NVD API endpoint
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Ecosystem mappings for OSV
    OSV_ECOSYSTEMS = {
        'npm': 'npm',
        'pip': 'PyPI',
        'maven': 'Maven',
        'nuget': 'NuGet',
        'composer': 'Packagist',
        'go': 'Go',
        'cargo': 'crates.io',
        'rubygems': 'RubyGems',
    }

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.nvd_api_key = os.getenv('NVD_API_KEY', '')

    # ============== DEPENDENCY PARSERS ==============

    def parse_package_json(self, content: str) -> Dict[str, str]:
        """Parse npm package.json"""
        deps = {}
        try:
            data = json.loads(content)
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        # Clean version string
                        version = re.sub(r'^[\^~>=<]', '', version)
                        version = version.split(' ')[0]  # Take first part if range
                        deps[name] = version
            logger.info(f"[SCA] Parsed package.json: {len(deps)} dependencies")
        except json.JSONDecodeError as e:
            logger.error(f"[SCA] Failed to parse package.json: {e}")
        return deps

    def parse_package_lock_json(self, content: str) -> Dict[str, str]:
        """Parse npm package-lock.json for exact versions"""
        deps = {}
        try:
            data = json.loads(content)

            # Handle both v1 and v2/v3 lockfile formats
            if 'packages' in data:
                # v2/v3 format
                for pkg_path, pkg_info in data['packages'].items():
                    if pkg_path and pkg_path.startswith('node_modules/'):
                        name = pkg_path.replace('node_modules/', '').split('node_modules/')[-1]
                        version = pkg_info.get('version', '')
                        if name and version:
                            deps[name] = version
            elif 'dependencies' in data:
                # v1 format
                def extract_deps(deps_dict, prefix=''):
                    for name, info in deps_dict.items():
                        version = info.get('version', '')
                        if version:
                            deps[name] = version
                        if 'dependencies' in info:
                            extract_deps(info['dependencies'], name + '/')

                extract_deps(data['dependencies'])

            logger.info(f"[SCA] Parsed package-lock.json: {len(deps)} dependencies")
        except json.JSONDecodeError as e:
            logger.error(f"[SCA] Failed to parse package-lock.json: {e}")
        return deps

    def parse_requirements_txt(self, content: str) -> Dict[str, str]:
        """Parse Python requirements.txt"""
        deps = {}
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue

            # Handle different formats: pkg==1.0, pkg>=1.0, pkg~=1.0
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*(?:[=<>~!]+\s*)?([0-9][a-zA-Z0-9._-]*)?', line)
            if match:
                name = match.group(1)
                version = match.group(2) or 'latest'
                deps[name.lower()] = version

        logger.info(f"[SCA] Parsed requirements.txt: {len(deps)} dependencies")
        return deps

    def parse_pipfile_lock(self, content: str) -> Dict[str, str]:
        """Parse Pipfile.lock"""
        deps = {}
        try:
            data = json.loads(content)
            for section in ['default', 'develop']:
                if section in data:
                    for name, info in data[section].items():
                        version = info.get('version', '').lstrip('=')
                        if version:
                            deps[name.lower()] = version
            logger.info(f"[SCA] Parsed Pipfile.lock: {len(deps)} dependencies")
        except json.JSONDecodeError as e:
            logger.error(f"[SCA] Failed to parse Pipfile.lock: {e}")
        return deps

    def parse_pom_xml(self, content: str) -> Dict[str, str]:
        """Parse Maven pom.xml with property resolution"""
        deps = {}

        # Extract properties for version resolution
        properties = {}
        props_match = re.search(r'<properties>(.*?)</properties>', content, re.DOTALL)
        if props_match:
            for prop in re.finditer(r'<([^>]+)>([^<]+)</\1>', props_match.group(1)):
                properties[prop.group(1)] = prop.group(2).strip()

        # Extract parent version
        parent_match = re.search(r'<parent>.*?<version>([^<]+)</version>.*?</parent>', content, re.DOTALL)
        if parent_match:
            properties['project.parent.version'] = parent_match.group(1).strip()
            properties['project.version'] = parent_match.group(1).strip()

        def resolve_version(ver: str) -> str:
            """Resolve Maven property references"""
            if not ver or not ver.startswith('$'):
                return ver
            prop_match = re.match(r'\$\{([^}]+)\}', ver)
            if prop_match:
                prop_name = prop_match.group(1)
                return properties.get(prop_name, ver)
            return ver

        # Extract dependencies
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
            version = resolve_version(match.group(3).strip() if match.group(3) else 'latest')

            # Store both formats for better matching
            deps[artifact_id] = version
            deps[f"{group_id}:{artifact_id}"] = version

        logger.info(f"[SCA] Parsed pom.xml: {len(deps)} dependencies")
        return deps

    def parse_build_gradle(self, content: str) -> Dict[str, str]:
        """Parse Gradle build.gradle"""
        deps = {}

        # Match various dependency declaration formats
        patterns = [
            # implementation 'group:artifact:version'
            r"(?:implementation|compile|api|testImplementation)\s*['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
            # implementation group: 'x', name: 'y', version: 'z'
            r"(?:implementation|compile|api)\s*group:\s*['\"]([^'\"]+)['\"],\s*name:\s*['\"]([^'\"]+)['\"],\s*version:\s*['\"]([^'\"]+)['\"]",
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, content):
                group_id = match.group(1)
                artifact_id = match.group(2)
                version = match.group(3)
                deps[artifact_id] = version
                deps[f"{group_id}:{artifact_id}"] = version

        logger.info(f"[SCA] Parsed build.gradle: {len(deps)} dependencies")
        return deps

    def parse_csproj(self, content: str) -> Dict[str, str]:
        """Parse .NET .csproj file"""
        deps = {}

        # PackageReference format
        for match in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', content):
            deps[match.group(1)] = match.group(2)

        # Alternate format
        for match in re.finditer(r'<PackageReference\s+Include="([^"]+)"[^>]*>\s*<Version>([^<]+)</Version>', content, re.DOTALL):
            deps[match.group(1)] = match.group(2)

        logger.info(f"[SCA] Parsed .csproj: {len(deps)} dependencies")
        return deps

    def parse_packages_config(self, content: str) -> Dict[str, str]:
        """Parse .NET packages.config"""
        deps = {}
        for match in re.finditer(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', content):
            deps[match.group(1)] = match.group(2)

        logger.info(f"[SCA] Parsed packages.config: {len(deps)} dependencies")
        return deps

    def parse_composer_json(self, content: str) -> Dict[str, str]:
        """Parse PHP composer.json"""
        deps = {}
        try:
            data = json.loads(content)
            for dep_type in ['require', 'require-dev']:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        if name == 'php' or name.startswith('ext-'):
                            continue
                        version = re.sub(r'^[\^~>=<*]', '', version)
                        deps[name] = version.split(' ')[0]
            logger.info(f"[SCA] Parsed composer.json: {len(deps)} dependencies")
        except json.JSONDecodeError as e:
            logger.error(f"[SCA] Failed to parse composer.json: {e}")
        return deps

    def parse_composer_lock(self, content: str) -> Dict[str, str]:
        """Parse PHP composer.lock"""
        deps = {}
        try:
            data = json.loads(content)
            for pkg in data.get('packages', []) + data.get('packages-dev', []):
                name = pkg.get('name', '')
                version = pkg.get('version', '').lstrip('v')
                if name and version:
                    deps[name] = version
            logger.info(f"[SCA] Parsed composer.lock: {len(deps)} dependencies")
        except json.JSONDecodeError as e:
            logger.error(f"[SCA] Failed to parse composer.lock: {e}")
        return deps

    def parse_go_mod(self, content: str) -> Dict[str, str]:
        """Parse Go go.mod"""
        deps = {}
        in_require = False

        for line in content.split('\n'):
            line = line.strip()

            if line.startswith('require ('):
                in_require = True
                continue
            elif line == ')':
                in_require = False
                continue

            if in_require or line.startswith('require '):
                # Match: module/path v1.2.3
                match = re.match(r'^(?:require\s+)?([^\s]+)\s+v?([^\s]+)', line)
                if match:
                    module = match.group(1)
                    version = match.group(2)
                    deps[module] = version

        logger.info(f"[SCA] Parsed go.mod: {len(deps)} dependencies")
        return deps

    def parse_go_sum(self, content: str) -> Dict[str, str]:
        """Parse Go go.sum for exact versions"""
        deps = {}
        for line in content.split('\n'):
            match = re.match(r'^([^\s]+)\s+v?([^\s/]+)', line)
            if match:
                module = match.group(1)
                version = match.group(2)
                if '/go.mod' not in line:
                    deps[module] = version

        logger.info(f"[SCA] Parsed go.sum: {len(deps)} dependencies")
        return deps

    # ============== VULNERABILITY QUERIES ==============

    async def query_osv(self, package: str, version: str, ecosystem: str) -> List[Dict[str, Any]]:
        """Query OSV database for vulnerabilities"""
        vulnerabilities = []

        osv_ecosystem = self.OSV_ECOSYSTEMS.get(ecosystem)
        if not osv_ecosystem:
            return vulnerabilities

        # Handle Maven package format (groupId:artifactId)
        query_package = package
        if osv_ecosystem == 'Maven' and ':' not in package:
            # Common Maven packages mapping
            maven_mapping = {
                'log4j-core': 'org.apache.logging.log4j:log4j-core',
                'spring-core': 'org.springframework:spring-core',
                'spring-webmvc': 'org.springframework:spring-webmvc',
                'jackson-databind': 'com.fasterxml.jackson.core:jackson-databind',
                'commons-collections': 'commons-collections:commons-collections',
                'struts2-core': 'org.apache.struts:struts2-core',
            }
            query_package = maven_mapping.get(package.lower(), f"{package}:{package}")

        query = {
            "package": {
                "name": query_package,
                "ecosystem": osv_ecosystem
            },
            "version": version
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(f"{self.OSV_API}/query", json=query)

                if response.status_code == 200:
                    data = response.json()
                    for vuln in data.get('vulns', []):
                        severity = self._extract_osv_severity(vuln)
                        cvss = self._extract_osv_cvss(vuln)

                        vulnerabilities.append({
                            'package': package,
                            'version': version,
                            'vulnerability_id': vuln.get('id', ''),
                            'title': vuln.get('summary', vuln.get('id', '')),
                            'description': vuln.get('details', '')[:500],
                            'severity': severity,
                            'cvss_score': cvss,
                            'cwe_id': self._extract_cwe(vuln),
                            'fixed_versions': self._extract_fixed_versions(vuln),
                            'source': 'OSV',
                            'published_date': vuln.get('published', ''),
                            'ecosystem': ecosystem,
                            'references': [ref.get('url') for ref in vuln.get('references', [])[:3]]
                        })

        except Exception as e:
            logger.error(f"[SCA] OSV query failed for {package}: {e}")

        return vulnerabilities

    async def query_osv_batch(self, packages: Dict[str, str], ecosystem: str) -> List[Dict[str, Any]]:
        """Query OSV for multiple packages in parallel"""
        tasks = []
        for package, version in packages.items():
            tasks.append(self.query_osv(package, version, ecosystem))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_vulns = []
        for result in results:
            if isinstance(result, list):
                all_vulns.extend(result)

        return all_vulns

    def _extract_osv_severity(self, vuln: Dict) -> str:
        """Extract severity from OSV vulnerability"""
        # Check severity array first
        for severity in vuln.get('severity', []):
            score = severity.get('score', '')
            if 'CVSS' in severity.get('type', ''):
                try:
                    cvss = float(score.split('/')[0]) if '/' in score else float(score)
                    if cvss >= 9.0:
                        return 'critical'
                    elif cvss >= 7.0:
                        return 'high'
                    elif cvss >= 4.0:
                        return 'medium'
                    else:
                        return 'low'
                except:
                    pass

        # Check database_specific
        db_specific = vuln.get('database_specific', {})
        severity = db_specific.get('severity', '').lower()
        if severity in ['critical', 'high', 'medium', 'low']:
            return severity

        # Default based on keywords
        summary = (vuln.get('summary', '') + vuln.get('details', '')).lower()
        if 'critical' in summary or 'rce' in summary or 'remote code' in summary:
            return 'critical'
        elif 'high' in summary:
            return 'high'

        return 'medium'

    def _extract_osv_cvss(self, vuln: Dict) -> float:
        """Extract CVSS score from OSV vulnerability"""
        for severity in vuln.get('severity', []):
            if 'CVSS' in severity.get('type', ''):
                try:
                    score = severity.get('score', '')
                    return float(score.split('/')[0]) if '/' in score else float(score)
                except:
                    pass

        # Default based on severity
        severity = self._extract_osv_severity(vuln)
        defaults = {'critical': 9.5, 'high': 7.5, 'medium': 5.0, 'low': 2.5}
        return defaults.get(severity, 5.0)

    def _extract_cwe(self, vuln: Dict) -> str:
        """Extract CWE ID from vulnerability"""
        # Check aliases for CWE
        for alias in vuln.get('aliases', []):
            if alias.startswith('CWE-'):
                return alias

        # Check references
        for ref in vuln.get('references', []):
            url = ref.get('url', '')
            if 'cwe.mitre.org' in url:
                match = re.search(r'CWE-(\d+)', url)
                if match:
                    return f"CWE-{match.group(1)}"

        return 'CWE-1035'  # Default: Vulnerable Components

    def _extract_fixed_versions(self, vuln: Dict) -> List[str]:
        """Extract fixed versions from vulnerability"""
        fixed = []
        for affected in vuln.get('affected', []):
            for range_info in affected.get('ranges', []):
                for event in range_info.get('events', []):
                    if 'fixed' in event:
                        fixed.append(event['fixed'])
        return fixed[:3]  # Return up to 3 fixed versions

    # ============== MAIN SCAN METHODS ==============

    async def scan_dependencies_async(
        self,
        dependencies: Dict[str, str],
        ecosystem: str
    ) -> Dict[str, Any]:
        """Scan dependencies for vulnerabilities using live feeds"""
        logger.info(f"[SCA] Scanning {len(dependencies)} {ecosystem} dependencies")

        # Query OSV for all packages
        vulnerabilities = await self.query_osv_batch(dependencies, ecosystem)

        # Deduplicate
        seen = set()
        unique_vulns = []
        for v in vulnerabilities:
            key = f"{v['package']}:{v['vulnerability_id']}"
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)

        # Convert to findings format
        findings = []
        for vuln in unique_vulns:
            fixed_str = ', '.join(vuln['fixed_versions']) if vuln['fixed_versions'] else 'No fix available'

            findings.append({
                'package': vuln['package'],
                'installed_version': vuln['version'],
                'vulnerability': vuln['title'],
                'cve': vuln['vulnerability_id'],
                'severity': vuln['severity'],
                'cvss_score': vuln['cvss_score'],
                'cwe_id': vuln['cwe_id'],
                'description': vuln['description'],
                'remediation': f"Upgrade to: {fixed_str}" if vuln['fixed_versions'] else "No fix available yet",
                'fixed_versions': vuln['fixed_versions'],
                'source': vuln['source'],
                'ecosystem': ecosystem,
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components'
            })

        severity_counts = {
            'critical': len([f for f in findings if f['severity'] == 'critical']),
            'high': len([f for f in findings if f['severity'] == 'high']),
            'medium': len([f for f in findings if f['severity'] == 'medium']),
            'low': len([f for f in findings if f['severity'] == 'low']),
        }

        logger.info(f"[SCA] Found {len(findings)} vulnerabilities: {severity_counts}")

        return {
            'findings': findings,
            'total_packages': len(dependencies),
            'vulnerable_packages': len(set(f['package'] for f in findings)),
            'total_vulnerabilities': len(findings),
            'severity_counts': severity_counts,
            'ecosystem': ecosystem,
            'scan_date': datetime.now().isoformat()
        }

    def scan_dependencies(self, dependencies: Dict[str, str], ecosystem: str) -> Dict[str, Any]:
        """Synchronous wrapper for scanning dependencies"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.scan_dependencies_async(dependencies, ecosystem))
            loop.close()
            return result
        except Exception as e:
            logger.error(f"[SCA] Scan failed: {e}")
            return {
                'findings': [],
                'total_packages': len(dependencies),
                'vulnerable_packages': 0,
                'total_vulnerabilities': 0,
                'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'ecosystem': ecosystem,
                'error': str(e)
            }

    def generate_sample_findings(self) -> List[Dict[str, Any]]:
        """Generate sample findings for demo"""
        return [
            {
                'package': 'lodash',
                'installed_version': '4.17.15',
                'vulnerability': 'Prototype Pollution',
                'cve': 'CVE-2020-8203',
                'severity': 'high',
                'cvss_score': 7.4,
                'cwe_id': 'CWE-1321',
                'description': 'Prototype pollution vulnerability in lodash',
                'remediation': 'Upgrade to 4.17.21 or later',
                'fixed_versions': ['4.17.21'],
                'ecosystem': 'npm',
                'owasp_category': 'A06:2021 - Vulnerable Components'
            }
        ]


# Singleton instance
enhanced_sca_scanner = EnhancedSCAScanner()
