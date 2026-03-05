"""
Commit Analyzer - Scores GitHub commits for insider threat risk.

Signals used:
  - SAST findings from commit diff matched against insider_threat rules
  - Metadata: off-hours commit, author/committer mismatch, unsigned commit
  - Sensitive file detection (env files, keys, certs, shadow files, etc.)
  - Large deletion (>500 lines removed)
  - Force push (score passed in from the caller if known)
"""
import re
import json
import sqlite3
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

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
                        findings.append(CommitFinding(
                            rule_name=rule["name"],
                            rule_id=rule["id"],
                            severity=rule["severity"],
                            file_path=current_file,
                            line_number=line_idx + 1,
                            matched_text=content[:200],
                            category=rule.get("category", "insider_threat"),
                        ))
                except re.error:
                    pass

        return findings

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

        # Cap at 10
        score = min(round(score, 2), 10.0)

        return CommitAnalysisResult(
            risk_score=score,
            risk_level=_risk_level(score),
            signals=signals,
            findings=findings,
            sensitive_files=sensitive_alerts,
        )
