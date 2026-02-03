"""
Transitive Dependency Analyzer

Analyzes dependency trees to identify vulnerabilities in both direct
and transitive (nested) dependencies.

Supports:
- npm (package-lock.json, yarn.lock)
- pip (with pipdeptree output)
- Maven (with dependency:tree output)
- Go (go.sum)
- Cargo (Cargo.lock)
"""

import re
import json
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import asyncio
import logging

logger = logging.getLogger(__name__)


@dataclass
class DependencyNode:
    """Represents a single dependency in the tree"""
    name: str
    version: str
    ecosystem: str
    is_direct: bool = True
    depth: int = 0
    parent: Optional[str] = None
    children: List[str] = field(default_factory=list)
    dev_dependency: bool = False


@dataclass
class DependencyTree:
    """Complete dependency tree for a project"""
    root_name: str
    ecosystem: str
    nodes: Dict[str, DependencyNode] = field(default_factory=dict)
    direct_deps: Set[str] = field(default_factory=set)
    all_deps: Set[str] = field(default_factory=set)

    def add_node(self, node: DependencyNode) -> None:
        key = f"{node.name}@{node.version}"
        self.nodes[key] = node
        self.all_deps.add(key)
        if node.is_direct:
            self.direct_deps.add(key)

    def get_all_packages(self) -> Dict[str, str]:
        """Get all packages as name -> version mapping"""
        return {
            node.name: node.version
            for node in self.nodes.values()
        }

    def get_dependency_path(self, package_key: str) -> List[str]:
        """Get the path from root to a specific package"""
        if package_key not in self.nodes:
            return []

        path = [package_key]
        current = self.nodes[package_key]

        while current.parent:
            parent_node = None
            for key, node in self.nodes.items():
                if node.name == current.parent:
                    parent_node = node
                    path.insert(0, key)
                    break
            if parent_node:
                current = parent_node
            else:
                break

        return path


class TransitiveDependencyAnalyzer:
    """
    Analyzes transitive dependencies and identifies vulnerable packages
    throughout the dependency tree.
    """

    def __init__(self):
        self.parsers = {
            'npm': self._parse_npm_lockfile,
            'yarn': self._parse_yarn_lock,
            'pip': self._parse_pip_tree,
            'maven': self._parse_maven_tree,
            'gradle': self._parse_gradle_deps,
            'go': self._parse_go_sum,
            'cargo': self._parse_cargo_lock,
        }

    def analyze_lockfile(
        self,
        content: str,
        lockfile_type: str,
        project_name: str = "project"
    ) -> DependencyTree:
        """
        Analyze a lockfile to build the complete dependency tree.

        Args:
            content: Contents of the lockfile
            lockfile_type: Type of lockfile (npm, yarn, pip, maven, etc.)
            project_name: Name of the root project

        Returns:
            DependencyTree with all direct and transitive dependencies
        """
        parser = self.parsers.get(lockfile_type.lower())
        if not parser:
            raise ValueError(f"Unsupported lockfile type: {lockfile_type}")

        return parser(content, project_name)

    def _parse_npm_lockfile(self, content: str, project_name: str) -> DependencyTree:
        """Parse npm package-lock.json"""
        tree = DependencyTree(root_name=project_name, ecosystem="npm")

        try:
            data = json.loads(content)
            lockfile_version = data.get("lockfileVersion", 1)

            if lockfile_version >= 2:
                # package-lock.json v2/v3 format
                packages = data.get("packages", {})

                for pkg_path, pkg_info in packages.items():
                    if not pkg_path:  # Root package
                        continue

                    # Extract package name from path
                    # node_modules/pkg or node_modules/@scope/pkg
                    name_match = re.search(r'node_modules/(.+)$', pkg_path)
                    if not name_match:
                        continue

                    name = name_match.group(1)
                    version = pkg_info.get("version", "unknown")
                    is_dev = pkg_info.get("dev", False)

                    # Determine depth by counting node_modules segments
                    depth = pkg_path.count("node_modules/") - 1
                    is_direct = depth == 0

                    node = DependencyNode(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        is_direct=is_direct,
                        depth=depth,
                        dev_dependency=is_dev
                    )
                    tree.add_node(node)

                    # Track dependencies
                    deps = pkg_info.get("dependencies", {})
                    node.children = list(deps.keys())

            else:
                # package-lock.json v1 format
                dependencies = data.get("dependencies", {})
                self._parse_npm_deps_recursive(tree, dependencies, depth=0)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse npm lockfile: {e}")

        return tree

    def _parse_npm_deps_recursive(
        self,
        tree: DependencyTree,
        deps: Dict[str, Any],
        depth: int,
        parent: Optional[str] = None
    ) -> None:
        """Recursively parse npm dependencies (v1 format)"""
        for name, info in deps.items():
            version = info.get("version", "unknown")
            is_dev = info.get("dev", False)

            node = DependencyNode(
                name=name,
                version=version,
                ecosystem="npm",
                is_direct=(depth == 0),
                depth=depth,
                parent=parent,
                dev_dependency=is_dev
            )
            tree.add_node(node)

            # Process nested dependencies
            nested_deps = info.get("dependencies", {})
            if nested_deps:
                self._parse_npm_deps_recursive(tree, nested_deps, depth + 1, name)
                node.children = list(nested_deps.keys())

    def _parse_yarn_lock(self, content: str, project_name: str) -> DependencyTree:
        """Parse yarn.lock file"""
        tree = DependencyTree(root_name=project_name, ecosystem="npm")

        # Yarn.lock format:
        # "package@version":
        #   version "x.y.z"
        #   dependencies:
        #     dep "^version"

        current_packages = []
        current_version = None
        current_deps = []
        in_deps = False

        for line in content.split('\n'):
            stripped = line.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith('#'):
                continue

            # New package block
            if not line.startswith(' ') and stripped.endswith(':'):
                # Save previous package
                if current_packages and current_version:
                    for pkg in current_packages:
                        # Extract package name
                        name_match = re.match(r'^"?(@?[^@"]+)@', pkg)
                        if name_match:
                            name = name_match.group(1)
                            node = DependencyNode(
                                name=name,
                                version=current_version,
                                ecosystem="npm",
                                is_direct=True,  # Will be corrected later
                                depth=0
                            )
                            node.children = current_deps.copy()
                            tree.add_node(node)

                # Parse new package names
                current_packages = [p.strip().rstrip(':') for p in stripped.rstrip(':').split(',')]
                current_version = None
                current_deps = []
                in_deps = False

            elif line.startswith('  version'):
                version_match = re.search(r'"([^"]+)"', line)
                if version_match:
                    current_version = version_match.group(1)

            elif line.startswith('  dependencies:'):
                in_deps = True

            elif in_deps and line.startswith('    '):
                dep_match = re.match(r'\s+"?([^"\s]+)"?\s', line)
                if dep_match:
                    current_deps.append(dep_match.group(1))

            elif not line.startswith('    '):
                in_deps = False

        # Don't forget the last package
        if current_packages and current_version:
            for pkg in current_packages:
                name_match = re.match(r'^"?(@?[^@"]+)@', pkg)
                if name_match:
                    name = name_match.group(1)
                    node = DependencyNode(
                        name=name,
                        version=current_version,
                        ecosystem="npm",
                        is_direct=True,
                        depth=0
                    )
                    node.children = current_deps.copy()
                    tree.add_node(node)

        return tree

    def _parse_pip_tree(self, content: str, project_name: str) -> DependencyTree:
        """
        Parse pipdeptree output or requirements.txt with markers.

        Expected format from pipdeptree --json:
        [{"package": {"key": "pkg", "package_name": "pkg", "installed_version": "1.0"},
          "dependencies": [{"key": "dep", ...}]}]
        """
        tree = DependencyTree(root_name=project_name, ecosystem="pip")

        try:
            # Try JSON format first (pipdeptree --json)
            data = json.loads(content)

            for pkg in data:
                pkg_info = pkg.get("package", {})
                name = pkg_info.get("package_name") or pkg_info.get("key", "")
                version = pkg_info.get("installed_version", "unknown")

                node = DependencyNode(
                    name=name,
                    version=version,
                    ecosystem="pip",
                    is_direct=True,
                    depth=0
                )

                deps = pkg.get("dependencies", [])
                for dep in deps:
                    dep_name = dep.get("package_name") or dep.get("key", "")
                    dep_version = dep.get("installed_version", "unknown")
                    node.children.append(dep_name)

                    # Add transitive dependency
                    dep_node = DependencyNode(
                        name=dep_name,
                        version=dep_version,
                        ecosystem="pip",
                        is_direct=False,
                        depth=1,
                        parent=name
                    )
                    tree.add_node(dep_node)

                tree.add_node(node)

        except json.JSONDecodeError:
            # Fall back to text format (pipdeptree output)
            current_parent = None
            current_depth = 0

            for line in content.split('\n'):
                if not line.strip():
                    continue

                # Count leading spaces/dashes to determine depth
                stripped = line.lstrip()
                indent = len(line) - len(stripped)
                depth = indent // 2  # Assume 2-space indent

                # Parse package name and version
                # Format: "package==version" or "- package [required: >=x, installed: y]"
                pkg_match = re.match(r'^-?\s*([a-zA-Z0-9_-]+)(?:\[.+\])?\s*(?:==|>=|<=|~=)?([0-9.]+)?', stripped)
                if pkg_match:
                    name = pkg_match.group(1)
                    version = pkg_match.group(2) or "unknown"

                    node = DependencyNode(
                        name=name,
                        version=version,
                        ecosystem="pip",
                        is_direct=(depth == 0),
                        depth=depth,
                        parent=current_parent if depth > 0 else None
                    )
                    tree.add_node(node)

                    if depth == 0:
                        current_parent = name
                    current_depth = depth

        return tree

    def _parse_maven_tree(self, content: str, project_name: str) -> DependencyTree:
        """
        Parse Maven dependency:tree output.

        Expected format:
        [INFO] +- groupId:artifactId:type:version:scope
        [INFO] |  \- nested:dependency:jar:1.0:compile
        """
        tree = DependencyTree(root_name=project_name, ecosystem="maven")

        parent_stack: List[str] = []

        for line in content.split('\n'):
            # Skip non-dependency lines
            if '[INFO]' not in line:
                continue

            # Extract the tree part
            tree_part = line.split('[INFO]', 1)[-1]

            # Count depth by tree characters
            depth = 0
            for char in tree_part:
                if char in '|+\\- ':
                    depth += 1
                else:
                    break
            depth = depth // 3  # Normalize

            # Parse GAV (groupId:artifactId:packaging:version:scope)
            gav_match = re.search(r'([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+)(?::([a-zA-Z0-9._-]+))?', tree_part)
            if not gav_match:
                continue

            group_id = gav_match.group(1)
            artifact_id = gav_match.group(2)
            version = gav_match.group(4)
            scope = gav_match.group(5) or "compile"

            # Full name
            name = f"{group_id}:{artifact_id}"

            # Update parent stack
            while len(parent_stack) > depth:
                parent_stack.pop()

            parent = parent_stack[-1] if parent_stack else None

            node = DependencyNode(
                name=name,
                version=version,
                ecosystem="maven",
                is_direct=(depth == 0),
                depth=depth,
                parent=parent,
                dev_dependency=(scope == "test")
            )
            tree.add_node(node)

            parent_stack.append(name)
            while len(parent_stack) > depth + 1:
                parent_stack.pop()

        return tree

    def _parse_gradle_deps(self, content: str, project_name: str) -> DependencyTree:
        """
        Parse Gradle dependencies output.

        Expected format from `gradle dependencies`:
        +--- group:name:version
        |    \--- nested:dep:version
        """
        tree = DependencyTree(root_name=project_name, ecosystem="gradle")

        parent_stack: List[str] = []

        for line in content.split('\n'):
            # Skip non-dependency lines
            if '---' not in line:
                continue

            # Count depth
            depth = 0
            for char in line:
                if char in '|+\\- ':
                    depth += 1
                else:
                    break
            depth = depth // 5  # Normalize for Gradle's format

            # Parse GAV
            gav_match = re.search(r'([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+)', line)
            if not gav_match:
                continue

            group_id = gav_match.group(1)
            artifact_id = gav_match.group(2)
            version = gav_match.group(3)

            # Remove version modifiers like " -> 1.2.3" or " (*)"
            version = re.sub(r'\s*->.*$', '', version)
            version = re.sub(r'\s*\(\*\)$', '', version)

            name = f"{group_id}:{artifact_id}"

            # Update parent stack
            while len(parent_stack) > depth:
                parent_stack.pop()

            parent = parent_stack[-1] if parent_stack else None

            node = DependencyNode(
                name=name,
                version=version.strip(),
                ecosystem="maven",  # Gradle uses Maven repos
                is_direct=(depth == 0),
                depth=depth,
                parent=parent
            )
            tree.add_node(node)

            parent_stack.append(name)
            while len(parent_stack) > depth + 1:
                parent_stack.pop()

        return tree

    def _parse_go_sum(self, content: str, project_name: str) -> DependencyTree:
        """
        Parse go.sum file.

        Format: module/path vX.Y.Z h1:hash=
        """
        tree = DependencyTree(root_name=project_name, ecosystem="go")

        seen = set()

        for line in content.split('\n'):
            if not line.strip():
                continue

            # Parse: module/path vX.Y.Z ...
            match = re.match(r'^(\S+)\s+(v[0-9][^\s/]+)', line)
            if match:
                name = match.group(1)
                version = match.group(2)

                # Skip /go.mod entries
                if '/go.mod' in name:
                    name = name.replace('/go.mod', '')

                key = f"{name}@{version}"
                if key in seen:
                    continue
                seen.add(key)

                node = DependencyNode(
                    name=name,
                    version=version.lstrip('v'),
                    ecosystem="go",
                    is_direct=True,  # go.sum doesn't distinguish
                    depth=0
                )
                tree.add_node(node)

        return tree

    def _parse_cargo_lock(self, content: str, project_name: str) -> DependencyTree:
        """
        Parse Cargo.lock file.

        Format:
        [[package]]
        name = "pkg"
        version = "1.0.0"
        dependencies = ["dep1", "dep2 1.0"]
        """
        tree = DependencyTree(root_name=project_name, ecosystem="cargo")

        current_name = None
        current_version = None
        current_deps = []
        is_root = True

        for line in content.split('\n'):
            stripped = line.strip()

            if stripped == '[[package]]':
                # Save previous package
                if current_name and current_version:
                    node = DependencyNode(
                        name=current_name,
                        version=current_version,
                        ecosystem="cargo",
                        is_direct=is_root,
                        depth=0 if is_root else 1
                    )
                    node.children = current_deps.copy()
                    tree.add_node(node)

                current_name = None
                current_version = None
                current_deps = []
                is_root = False

            elif stripped.startswith('name = '):
                current_name = stripped.split('"')[1] if '"' in stripped else None

            elif stripped.startswith('version = '):
                current_version = stripped.split('"')[1] if '"' in stripped else None

            elif stripped.startswith('dependencies = '):
                # Parse inline array
                deps_match = re.findall(r'"([^"]+)"', stripped)
                for dep in deps_match:
                    # May be "name version" or just "name"
                    parts = dep.split()
                    current_deps.append(parts[0])

        # Don't forget the last package
        if current_name and current_version:
            node = DependencyNode(
                name=current_name,
                version=current_version,
                ecosystem="cargo",
                is_direct=is_root,
                depth=0 if is_root else 1
            )
            node.children = current_deps.copy()
            tree.add_node(node)

        return tree


class TransitiveVulnerabilityScanner:
    """
    Scans dependency trees for vulnerabilities, including transitive dependencies.
    """

    def __init__(self, sca_scanner=None):
        self.analyzer = TransitiveDependencyAnalyzer()
        self.sca_scanner = sca_scanner

    def scan_with_tree(
        self,
        lockfile_content: str,
        lockfile_type: str,
        project_name: str = "project"
    ) -> Dict[str, Any]:
        """
        Scan a lockfile and return vulnerability information including
        transitive dependency paths.

        Args:
            lockfile_content: Contents of the lockfile
            lockfile_type: Type of lockfile
            project_name: Name of the project

        Returns:
            Scan results with dependency tree information
        """
        # Build dependency tree
        tree = self.analyzer.analyze_lockfile(
            lockfile_content,
            lockfile_type,
            project_name
        )

        # Get all packages
        all_packages = tree.get_all_packages()

        # Map ecosystem
        ecosystem_map = {
            'npm': 'npm',
            'yarn': 'npm',
            'pip': 'pip',
            'maven': 'maven',
            'gradle': 'maven',
            'go': 'go',
            'cargo': 'cargo',
        }
        ecosystem = ecosystem_map.get(lockfile_type.lower(), 'npm')

        # Scan for vulnerabilities
        if self.sca_scanner:
            scan_results = self.sca_scanner.scan_dependencies(all_packages, ecosystem)
        else:
            scan_results = {"findings": []}

        # Enrich findings with dependency path information
        enriched_findings = []
        for finding in scan_results.get("findings", []):
            pkg_name = finding.get("package", "")
            pkg_version = finding.get("installed_version", "")
            pkg_key = f"{pkg_name}@{pkg_version}"

            # Get dependency node
            node = tree.nodes.get(pkg_key)
            if node:
                finding["is_direct_dependency"] = node.is_direct
                finding["dependency_depth"] = node.depth
                finding["dependency_path"] = tree.get_dependency_path(pkg_key)
                finding["introduced_by"] = node.parent
            else:
                finding["is_direct_dependency"] = True
                finding["dependency_depth"] = 0
                finding["dependency_path"] = [pkg_key]
                finding["introduced_by"] = None

            enriched_findings.append(finding)

        # Separate direct vs transitive findings
        direct_findings = [f for f in enriched_findings if f.get("is_direct_dependency", True)]
        transitive_findings = [f for f in enriched_findings if not f.get("is_direct_dependency", True)]

        return {
            "total_packages": len(all_packages),
            "direct_packages": len(tree.direct_deps),
            "transitive_packages": len(tree.all_deps) - len(tree.direct_deps),
            "vulnerable_packages": len(set(f["package"] for f in enriched_findings)),
            "direct_vulnerabilities": len(direct_findings),
            "transitive_vulnerabilities": len(transitive_findings),
            "severity_counts": scan_results.get("severity_counts", {}),
            "findings": enriched_findings,
            "direct_findings": direct_findings,
            "transitive_findings": transitive_findings,
            "dependency_tree": {
                "root": project_name,
                "ecosystem": ecosystem,
                "nodes": {
                    k: {
                        "name": v.name,
                        "version": v.version,
                        "is_direct": v.is_direct,
                        "depth": v.depth,
                        "parent": v.parent,
                        "children": v.children
                    }
                    for k, v in tree.nodes.items()
                }
            },
            "scan_date": scan_results.get("scan_date", ""),
            "ecosystem": ecosystem
        }


# Convenience function for use in API
def analyze_transitive_dependencies(
    lockfile_content: str,
    lockfile_type: str,
    project_name: str = "project"
) -> DependencyTree:
    """
    Analyze lockfile to extract complete dependency tree.

    Returns DependencyTree with all direct and transitive dependencies.
    """
    analyzer = TransitiveDependencyAnalyzer()
    return analyzer.analyze_lockfile(lockfile_content, lockfile_type, project_name)


# Global instance
transitive_analyzer = TransitiveDependencyAnalyzer()
transitive_scanner = TransitiveVulnerabilityScanner()
