"""
Commit Analyzer - Scores GitHub commits for insider threat risk.

Signals used:
  - SAST findings from commit diff matched against insider_threat rules
  - Metadata: off-hours commit, author/committer mismatch, unsigned commit
  - Sensitive file detection (env files, keys, certs, shadow files, etc.)
  - Large deletion (>500 lines removed)
  - Force push (score passed in from the caller if known)
  - Suspicious commit messages (vague/empty on non-trivial changes)
  - Binary file injection (executables, archives, DB dumps in source repos)
  - Dependency manipulation (typosquatting, vuln pinning, security dep removal)
  - CI/CD pipeline tampering (disabling scans, exfiltrating secrets, changing targets)
  - Config/permission weakening (gitignore, CODEOWNERS, CORS, auth config changes)
"""
import re
import sqlite3
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sensitive file patterns  (fnmatch-style substrings)
# ---------------------------------------------------------------------------
SENSITIVE_FILE_PATTERNS = [
    r"\.env$", r"\.env\.", r"secret", r"password", r"passwd",
    r"id_rsa", r"id_dsa", r"id_ecdsa", r"id_ed25519",
    r"\.pem$", r"\.pfx$", r"\.p12$", r"\.key$",
    r"shadow$", r"authorized_keys", r"\.kdbx$",
    r"aws_credentials", r"credentials\.json", r"token\.json",
    r"\.htpasswd", r"keystore", r"truststore",
]

SENSITIVE_FILE_RE = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_FILE_PATTERNS]

# ---------------------------------------------------------------------------
# Binary file patterns (suspicious in source repos)
# ---------------------------------------------------------------------------
BINARY_FILE_EXTENSIONS = {
    # Executables / libraries
    ".exe", ".dll", ".so", ".dylib", ".bin", ".com", ".msi", ".app",
    # Archives (potential data exfil containers)
    ".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z", ".bz2",
    # Database dumps
    ".sql", ".sqlite", ".sqlite3", ".dump", ".bak",
    # Compiled / bytecode
    ".class", ".pyc", ".o", ".obj", ".wasm",
}

# ---------------------------------------------------------------------------
# CI/CD pipeline file patterns
# ---------------------------------------------------------------------------
CICD_FILE_PATTERNS = [
    r"\.github/workflows/.*\.ya?ml$",
    r"Jenkinsfile$",
    r"\.gitlab-ci\.ya?ml$",
    r"azure-pipelines\.ya?ml$",
    r"\.circleci/config\.ya?ml$",
    r"Dockerfile$",
    r"docker-compose.*\.ya?ml$",
    r"\.travis\.ya?ml$",
    r"bitbucket-pipelines\.ya?ml$",
]
CICD_FILE_RE = [re.compile(p, re.IGNORECASE) for p in CICD_FILE_PATTERNS]

# ---------------------------------------------------------------------------
# Dependency manifest files
# ---------------------------------------------------------------------------
DEPENDENCY_FILES = {
    "package.json", "package-lock.json", "yarn.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "setup.py", "setup.cfg",
    "Gemfile", "Gemfile.lock",
    "go.mod", "go.sum",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "Cargo.toml", "Cargo.lock",
    "composer.json", "composer.lock",
    "pubspec.yaml", "pubspec.lock",
}

# ---------------------------------------------------------------------------
# Config / permission files that affect security posture
# ---------------------------------------------------------------------------
CONFIG_SECURITY_FILES = [
    r"\.gitignore$",
    r"CODEOWNERS$",
    r"\.github/CODEOWNERS$",
    r"branch-protection",
    r"renovate\.json",
    r"\.dependabot/",
]
CONFIG_SECURITY_RE = [re.compile(p, re.IGNORECASE) for p in CONFIG_SECURITY_FILES]

# ---------------------------------------------------------------------------
# Dependency tampering patterns (matched against diff lines)
# ---------------------------------------------------------------------------
DEPENDENCY_TAMPERING_PATTERNS = [
    # Typosquatting indicators — known attack packages
    (r"(lod[a4]sh|requ[e3]sts?|crypt0|col[o0]rs|f[a4]ker|event-stream|ua-parser-js)", "typosquat_suspect"),
    # Pinning to known-vulnerable old versions
    (r"django[=<>~!]+[012]\.\d", "vuln_version_pin"),
    (r"lodash[\"']?\s*:\s*[\"'][0-3]\.", "vuln_version_pin"),
    (r"log4j[\"']?\s*:\s*[\"']2\.(0|1[0-4])\.", "vuln_version_pin"),
    (r"spring-boot[\"']?\s*:\s*[\"']2\.[0-5]\.", "vuln_version_pin"),
    # Private/custom registry URLs (potential supply chain attack)
    (r"registry\s*[=:]\s*[\"']https?://(?!registry\.npmjs\.org|pypi\.org|rubygems\.org)", "custom_registry"),
    # Post-install scripts in package.json
    (r"\"(preinstall|postinstall|preuninstall)\"\s*:", "install_script"),
]
DEPENDENCY_TAMPERING_RE = [(re.compile(p, re.IGNORECASE), label) for p, label in DEPENDENCY_TAMPERING_PATTERNS]

# ---------------------------------------------------------------------------
# CI/CD tampering patterns (matched against diff lines in pipeline files)
# ---------------------------------------------------------------------------
CICD_TAMPERING_PATTERNS = [
    # Disabling security scans
    (r"#.*\b(snyk|sonar|trivy|semgrep|bandit|brakeman|safety|gitleaks|trufflehog|checkov)\b", "security_scan_disabled"),
    (r"(SKIP|DISABLE|NO)_(SCAN|CHECK|LINT|SECURITY|SAST|SCA|DAST)", "security_check_disabled"),
    (r"--no-verify", "hook_bypass"),
    (r"--skip-integrity-check", "integrity_bypass"),
    # Secret exfiltration from CI
    (r"echo\s+\$\{?\w*(SECRET|TOKEN|KEY|PASSWORD|CRED)\w*\}?\s*[|>]", "secret_exfil_ci"),
    (r"curl.*\$\{?\w*(SECRET|TOKEN|KEY|PASSWORD)\w*\}?", "secret_exfil_ci"),
    (r"printenv|env\s*\|", "env_dump_ci"),
    # Deployment target changes
    (r"(deploy|push|publish).*\b(prod|production|live|release)\b", "prod_deploy_change"),
    # Suspicious image changes in Docker
    (r"FROM\s+(?!.*\.(gcr\.io|ecr\.|azurecr\.io|docker\.io|ghcr\.io))", "untrusted_base_image"),
    # Adding users in Dockerfile
    (r"(useradd|adduser|net\s+user)", "docker_user_add"),
    # Exposing extra ports
    (r"EXPOSE\s+\d{4,5}", "port_exposed"),
]
CICD_TAMPERING_RE = [(re.compile(p, re.IGNORECASE), label) for p, label in CICD_TAMPERING_PATTERNS]

# ---------------------------------------------------------------------------
# Config weakening patterns (matched against diff lines in config files)
# ---------------------------------------------------------------------------
CONFIG_WEAKENING_PATTERNS = [
    # CORS weakening
    (r"(Access-Control-Allow-Origin|cors).*\*", "cors_wildcard"),
    (r"allow_origins\s*=\s*\[?\s*[\"']\*", "cors_wildcard"),
    # Auth/session weakening
    (r"(session_timeout|SESSION_TIMEOUT|token_expir).*=.*\b(9999|86400|604800|31536000)", "session_timeout_extended"),
    (r"(MFA|mfa|2fa|two_factor).*=\s*(false|False|0|disabled|off)", "mfa_disabled"),
    (r"(require_auth|REQUIRE_AUTH|auth_required).*=\s*(false|False|0)", "auth_disabled"),
    # Rate limiting removal
    (r"(rate_limit|RATE_LIMIT|throttle).*=\s*(false|False|0|none|off)", "rate_limit_disabled"),
    # Debug/verbose mode in prod
    (r"(DEBUG|debug)\s*=\s*(true|True|1|yes)", "debug_enabled"),
    # SSL/TLS weakening
    (r"(verify_ssl|SSL_VERIFY|VERIFY_SSL).*=\s*(false|False|0)", "ssl_verify_disabled"),
    (r"(TLS|tls|ssl).*=\s*[\"']?(1\.0|1\.1|SSLv3)", "weak_tls"),
]
CONFIG_WEAKENING_RE = [(re.compile(p), label) for p, label in CONFIG_WEAKENING_PATTERNS]

# Patterns to detect when .gitignore removes security-relevant entries
GITIGNORE_REMOVAL_PATTERNS = [
    r"\.env", r"\.pem", r"\.key", r"secret", r"credential",
    r"\.pfx", r"\.p12", r"token", r"password",
]
GITIGNORE_REMOVAL_RE = [re.compile(p, re.IGNORECASE) for p in GITIGNORE_REMOVAL_PATTERNS]

# Security-related dependencies (removal is suspicious)
SECURITY_DEPENDENCIES = [
    "helmet", "csurf", "cors", "express-rate-limit", "hpp",
    "bcrypt", "argon2", "scrypt",
    "jsonwebtoken", "passport", "express-session",
    "django-cors-headers", "django-csp",
    "safety", "bandit", "semgrep",
    "snyk", "audit", "eslint-plugin-security",
]


def _is_sensitive_file(path: str) -> Optional[str]:
    """Return the matched pattern string if the path looks sensitive, else None."""
    for rx in SENSITIVE_FILE_RE:
        if rx.search(path):
            return rx.pattern
    return None


# ---------------------------------------------------------------------------
# Risk scoring weights
# ---------------------------------------------------------------------------
SCORE_CRITICAL_FINDING = 2.5
SCORE_HIGH_FINDING = 1.5
SCORE_MEDIUM_FINDING = 0.5
SCORE_OFF_HOURS = 1.0
SCORE_AUTHOR_MISMATCH = 1.5
SCORE_UNSIGNED = 0.5
SCORE_SENSITIVE_FILE_PER = 1.5
SCORE_SENSITIVE_FILE_CAP = 3.0
SCORE_LARGE_DELETION = 1.0
SCORE_FORCE_PUSH = 2.0
SCORE_SUSPICIOUS_MESSAGE = 0.5
SCORE_BINARY_FILE_PER = 1.0
SCORE_BINARY_FILE_CAP = 2.0
SCORE_DEPENDENCY_TAMPER = 1.5
SCORE_CICD_TAMPER_PER = 1.5
SCORE_CICD_TAMPER_CAP = 3.0
SCORE_CONFIG_WEAKEN_PER = 1.0
SCORE_CONFIG_WEAKEN_CAP = 2.0


def _risk_level(score: float) -> str:
    if score >= 7.0:
        return "critical"
    if score >= 4.0:
        return "high"
    if score >= 2.0:
        return "medium"
    if score >= 0.5:
        return "low"
    return "clean"


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
@dataclass
class CommitFinding:
    rule_name: str
    rule_id: Optional[int]
    severity: str
    file_path: Optional[str]
    line_number: Optional[int]
    matched_text: Optional[str]
    category: str = "insider_threat"
    diff_snippet: Optional[str] = None  # surrounding diff context (±5 lines)


@dataclass
class SensitiveFileAlert:
    file_path: str
    pattern_matched: str


@dataclass
class CommitAnalysisResult:
    risk_score: float
    risk_level: str
    signals: List[str]
    findings: List[CommitFinding] = field(default_factory=list)
    sensitive_files: List[SensitiveFileAlert] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------
class CommitAnalyzer:
    """Analyzes a GitHub commit for insider threat signals."""

    def __init__(self, db_path: str):
        """
        Args:
            db_path: path to the SQLite database (used to load insider_threat rules)
        """
        self.db_path = db_path
        self._rules_cache: Optional[List[Dict]] = None

    def _load_rules(self) -> List[Dict]:
        if self._rules_cache is not None:
            return self._rules_cache
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, pattern, severity, category FROM custom_rules "
                "WHERE enabled=1 AND category='insider_threat'"
            )
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            self._rules_cache = rows
            logger.info(f"[CommitAnalyzer] Loaded {len(rows)} insider threat rules")
            return rows
        except Exception as e:
            logger.error(f"[CommitAnalyzer] Failed to load rules: {e}")
            return []

    def _scan_diff(self, diff_text: str) -> List[CommitFinding]:
        """Run insider_threat rules against the commit diff."""
        findings: List[CommitFinding] = []
        rules = self._load_rules()
        current_file: Optional[str] = None

        lines = diff_text.splitlines()
        for line_idx, line in enumerate(lines):
            # Track current file in the diff
            if line.startswith("+++ b/"):
                current_file = line[6:]
                continue
            if line.startswith("---") or not line.startswith("+"):
                continue

            content = line[1:]  # strip leading +
            for rule in rules:
                try:
                    match = re.search(rule["pattern"], content)
                    if match:
                        # Capture ±5 lines of diff context around the match
                        ctx_start = max(0, line_idx - 5)
                        ctx_end = min(len(lines), line_idx + 6)
                        snippet_lines = lines[ctx_start:ctx_end]
                        diff_snippet = "\n".join(snippet_lines)
                        if len(diff_snippet) > 1500:
                            diff_snippet = diff_snippet[:1500] + "\n... (truncated)"

                        findings.append(CommitFinding(
                            rule_name=rule["name"],
                            rule_id=rule["id"],
                            severity=rule["severity"],
                            file_path=current_file,
                            line_number=line_idx + 1,
                            matched_text=content[:200],
                            category=rule.get("category", "insider_threat"),
                            diff_snippet=diff_snippet,
                        ))
                except re.error:
                    pass

        return findings

    # ------------------------------------------------------------------
    # New signal detectors (quick wins)
    # ------------------------------------------------------------------

    def _check_commit_message(self, commit_data: Dict) -> List[str]:
        """Detect vague/suspicious commit messages on non-trivial changes."""
        signals = []
        commit = commit_data.get("commit", {})
        message = (commit.get("message") or "").strip()
        stats = commit_data.get("stats", {})
        total_changes = stats.get("total", 0)

        # Only flag if the commit is non-trivial (>50 lines changed)
        if total_changes < 50:
            return signals

        # Empty or near-empty message
        if len(message) < 4:
            signals.append("suspicious_message:empty")
            return signals

        # Single-word vague messages on large commits
        vague_patterns = [
            r"^(fix|update|change|wip|test|tmp|temp|misc|stuff|asdf|todo|ok|done|na|\.+|-+)$",
        ]
        first_line = message.split("\n")[0].strip().lower()
        for vp in vague_patterns:
            if re.match(vp, first_line, re.IGNORECASE):
                signals.append("suspicious_message:vague")
                break

        return signals

    def _check_binary_files(self, files: List[Dict]) -> List[Dict]:
        """Detect binary/archive/dump files added to the repo."""
        alerts = []
        for f in files:
            filename = f.get("filename", "").lower()
            status = f.get("status", "")
            if status not in ("added", "modified"):
                continue
            for ext in BINARY_FILE_EXTENSIONS:
                if filename.endswith(ext):
                    alerts.append({
                        "file_path": f.get("filename", ""),
                        "extension": ext,
                        "status": status,
                    })
                    break
        return alerts

    def _check_dependency_tampering(self, files: List[Dict], diff_text: str) -> List[Dict]:
        """Detect suspicious changes in dependency manifest files."""
        alerts = []

        # Check if any dependency file was touched
        dep_files_touched = []
        for f in files:
            basename = f.get("filename", "").split("/")[-1]
            if basename in DEPENDENCY_FILES:
                dep_files_touched.append(f.get("filename", ""))

        if not dep_files_touched:
            return alerts

        # Scan diff lines that are in dependency files
        current_file = None
        in_dep_file = False
        removed_security_deps = []

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
                basename = current_file.split("/")[-1]
                in_dep_file = basename in DEPENDENCY_FILES
                continue

            if not in_dep_file:
                continue

            # Check added lines for tampering patterns
            if line.startswith("+") and not line.startswith("+++"):
                content = line[1:]
                for rx, label in DEPENDENCY_TAMPERING_RE:
                    if rx.search(content):
                        alerts.append({
                            "file_path": current_file,
                            "pattern": label,
                            "matched_text": content.strip()[:150],
                        })

            # Check removed lines for security dependency removal
            if line.startswith("-") and not line.startswith("---"):
                content = line[1:].lower()
                for dep in SECURITY_DEPENDENCIES:
                    if dep in content:
                        removed_security_deps.append({
                            "file_path": current_file,
                            "pattern": "security_dep_removed",
                            "matched_text": f"Removed: {dep}",
                        })

        alerts.extend(removed_security_deps)
        return alerts

    def _check_cicd_tampering(self, files: List[Dict], diff_text: str) -> List[Dict]:
        """Detect tampering with CI/CD pipeline files."""
        alerts = []

        # Check if any CI/CD file was touched
        cicd_files_touched = []
        for f in files:
            filename = f.get("filename", "")
            for rx in CICD_FILE_RE:
                if rx.search(filename):
                    cicd_files_touched.append(filename)
                    break

        if not cicd_files_touched:
            return alerts

        # Scan diff lines in CI/CD files
        current_file = None
        in_cicd_file = False

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
                in_cicd_file = any(rx.search(current_file) for rx in CICD_FILE_RE)
                continue

            if not in_cicd_file:
                continue

            # Check added lines for tampering
            if line.startswith("+") and not line.startswith("+++"):
                content = line[1:]
                for rx, label in CICD_TAMPERING_RE:
                    if rx.search(content):
                        alerts.append({
                            "file_path": current_file,
                            "pattern": label,
                            "matched_text": content.strip()[:150],
                        })

            # Check removed lines — were security scan steps removed?
            if line.startswith("-") and not line.startswith("---"):
                content = line[1:].lower()
                security_tools = [
                    "snyk", "sonar", "trivy", "semgrep", "bandit",
                    "brakeman", "safety", "gitleaks", "trufflehog",
                    "checkov", "tfsec", "grype", "syft", "cosign",
                ]
                for tool in security_tools:
                    if tool in content:
                        alerts.append({
                            "file_path": current_file,
                            "pattern": "security_tool_removed",
                            "matched_text": f"Removed step referencing: {tool}",
                        })

        return alerts

    def _check_config_weakening(self, _files: List[Dict], diff_text: str) -> List[Dict]:
        """Detect security-weakening changes in config/permission files."""
        alerts = []
        current_file = None
        in_config_file = False
        is_gitignore = False

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
                in_config_file = any(rx.search(current_file) for rx in CONFIG_SECURITY_RE)
                is_gitignore = current_file.endswith(".gitignore")
                # Also check any config-like file for weakening patterns
                if not in_config_file:
                    lower = current_file.lower()
                    in_config_file = any(kw in lower for kw in [
                        "config", "settings", "nginx", "apache", "cors",
                        ".cfg", ".ini", ".toml", ".yaml", ".yml",
                    ])
                continue

            if not in_config_file:
                continue

            # Added lines — check for weakening patterns
            if line.startswith("+") and not line.startswith("+++"):
                content = line[1:]
                for rx, label in CONFIG_WEAKENING_RE:
                    if rx.search(content):
                        alerts.append({
                            "file_path": current_file,
                            "pattern": label,
                            "matched_text": content.strip()[:150],
                        })

            # .gitignore: removed lines = previously ignored files now tracked
            if is_gitignore and line.startswith("-") and not line.startswith("---"):
                removed_entry = line[1:].strip()
                if removed_entry and not removed_entry.startswith("#"):
                    for rx in GITIGNORE_REMOVAL_RE:
                        if rx.search(removed_entry):
                            alerts.append({
                                "file_path": current_file,
                                "pattern": "gitignore_sensitive_unignored",
                                "matched_text": f"Removed ignore rule: {removed_entry}",
                            })
                            break

            # CODEOWNERS: removed lines = reviewer protection removed
            if "codeowners" in (current_file or "").lower():
                if line.startswith("-") and not line.startswith("---"):
                    content = line[1:].strip()
                    if content and not content.startswith("#"):
                        alerts.append({
                            "file_path": current_file,
                            "pattern": "codeowner_removed",
                            "matched_text": f"Removed: {content[:100]}",
                        })

        return alerts

    def _check_sensitive_files(self, files: List[Dict]) -> List[SensitiveFileAlert]:
        alerts = []
        for f in files:
            filename = f.get("filename", "")
            matched = _is_sensitive_file(filename)
            if matched:
                alerts.append(SensitiveFileAlert(
                    file_path=filename,
                    pattern_matched=matched,
                ))
        return alerts

    def _check_metadata_signals(self, commit_data: Dict) -> List[str]:
        """Return list of signal strings from commit metadata."""
        signals = []
        commit = commit_data.get("commit", {})

        # Off-hours check (before 7am or after 9pm UTC)
        author_info = commit.get("author", {})
        committed_at_str = author_info.get("date", "")
        if committed_at_str:
            try:
                committed_at = datetime.fromisoformat(committed_at_str.replace("Z", "+00:00"))
                hour = committed_at.hour
                if hour < 7 or hour >= 21:
                    signals.append("off_hours")
            except Exception:
                pass

        # Author / committer mismatch
        author_email = commit.get("author", {}).get("email", "")
        committer_email = commit.get("committer", {}).get("email", "")
        if author_email and committer_email and author_email.lower() != committer_email.lower():
            # Ignore GitHub's noreply addresses
            if "noreply" not in committer_email.lower():
                signals.append("author_committer_mismatch")

        # Unsigned commit
        verification = commit.get("verification", {})
        if not verification.get("verified", False):
            signals.append("unsigned_commit")

        return signals

    def analyze_commit(
        self,
        commit_data: Dict,
        diff_text: str,
        is_force_push: bool = False,
    ) -> CommitAnalysisResult:
        """Full analysis of a single commit."""
        signals: List[str] = []
        score: float = 0.0

        # 1. Metadata signals
        meta_signals = self._check_metadata_signals(commit_data)
        signals.extend(meta_signals)
        if "off_hours" in meta_signals:
            score += SCORE_OFF_HOURS
        if "author_committer_mismatch" in meta_signals:
            score += SCORE_AUTHOR_MISMATCH
        if "unsigned_commit" in meta_signals:
            score += SCORE_UNSIGNED

        # 2. Force push
        if is_force_push:
            signals.append("force_push")
            score += SCORE_FORCE_PUSH

        # 3. Large deletion
        stats = commit_data.get("stats", {})
        deletions = stats.get("deletions", 0)
        if deletions > 500:
            signals.append("large_deletion")
            score += SCORE_LARGE_DELETION

        # 4. SAST on diff
        findings = self._scan_diff(diff_text)
        for finding in findings:
            if finding.severity == "critical":
                score += SCORE_CRITICAL_FINDING
            elif finding.severity == "high":
                score += SCORE_HIGH_FINDING
            else:
                score += SCORE_MEDIUM_FINDING
        if findings:
            signals.append(f"sast_findings:{len(findings)}")

        # 5. Sensitive files
        files = commit_data.get("files", [])
        sensitive_alerts = self._check_sensitive_files(files)
        if sensitive_alerts:
            sensitive_score = min(
                len(sensitive_alerts) * SCORE_SENSITIVE_FILE_PER,
                SCORE_SENSITIVE_FILE_CAP,
            )
            score += sensitive_score
            signals.append(f"sensitive_files:{len(sensitive_alerts)}")

        # 6. Suspicious commit message
        msg_signals = self._check_commit_message(commit_data)
        if msg_signals:
            signals.extend(msg_signals)
            score += SCORE_SUSPICIOUS_MESSAGE

        # 7. Binary file injection
        binary_alerts = self._check_binary_files(files)
        if binary_alerts:
            binary_score = min(
                len(binary_alerts) * SCORE_BINARY_FILE_PER,
                SCORE_BINARY_FILE_CAP,
            )
            score += binary_score
            signals.append(f"binary_files:{len(binary_alerts)}")

        # 8. Dependency manipulation
        dep_alerts = self._check_dependency_tampering(files, diff_text)
        if dep_alerts:
            score += SCORE_DEPENDENCY_TAMPER
            patterns = set(a["pattern"] for a in dep_alerts)
            signals.append(f"dependency_tampering:{','.join(patterns)}")

        # 9. CI/CD pipeline tampering
        cicd_alerts = self._check_cicd_tampering(files, diff_text)
        if cicd_alerts:
            cicd_score = min(
                len(cicd_alerts) * SCORE_CICD_TAMPER_PER,
                SCORE_CICD_TAMPER_CAP,
            )
            score += cicd_score
            patterns = set(a["pattern"] for a in cicd_alerts)
            signals.append(f"cicd_tampering:{','.join(patterns)}")

        # 10. Config/permission weakening
        config_alerts = self._check_config_weakening(files, diff_text)
        if config_alerts:
            config_score = min(
                len(config_alerts) * SCORE_CONFIG_WEAKEN_PER,
                SCORE_CONFIG_WEAKEN_CAP,
            )
            score += config_score
            patterns = set(a["pattern"] for a in config_alerts)
            signals.append(f"config_weakening:{','.join(patterns)}")

        # Cap at 10
        score = min(round(score, 2), 10.0)

        return CommitAnalysisResult(
            risk_score=score,
            risk_level=_risk_level(score),
            signals=signals,
            findings=findings,
            sensitive_files=sensitive_alerts,
        )
