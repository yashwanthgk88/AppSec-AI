"""
Seed script: GitHub Monitor — Insider-threat demo dataset
==========================================================
Populates a realistic demo of the GitHub Commit Monitor for client demos:

    - 3 monitored repositories (Apex Banking org)
    - 18 commit scans with the full risk spectrum: clean → critical
    - SAST findings on the risky commits with CWE/OWASP mapping
    - Sensitive-file alerts (.env, .pem, credentials.json touched)
    - 6 developer profiles with varying risk patterns
    - 4 established behavioural baselines
    - 5 detected anomalies (off-hours, large additions, risk spikes)
    - 2 AI threat assessments on the critical commits

The data tells a story:
    Alice — clean veteran (low avg risk, established baseline)
    Bob   — generally clean but recent large commit anomaly
    Charlie — known risky pattern (off-hours, sensitive files)
    Dana  — DEPARTING EMPLOYEE — recent risk spike + exfil attempt
    Eve   — newcomer with insufficient baseline
    Frank — bot/service account (author/committer mismatch)

Run:
    cd backend && python3 seed_github_monitor_demo.py

Works against both SQLite (local dev) and PostgreSQL (when DATABASE_URL is set).
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone

# Path setup so we can import utils.* when run as a script
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.db_compat import connect as _db_connect

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
DB_PATH = "appsec.db"
if os.path.exists("/app/data/appsec.db"):
    DB_PATH = "/app/data/appsec.db"

NOW = datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """ISO format with Z suffix for compatibility."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ----------------------------------------------------------------------------
# Repository definitions
# ----------------------------------------------------------------------------
REPOS = [
    {
        "owner": "apex-banking",
        "repo": "core-api",
        "full_name": "apex-banking/core-api",
        "description": "Core banking REST API — accounts, transfers, balances",
        "default_branch": "main",
        "total_commits_scanned": 124,
    },
    {
        "owner": "apex-banking",
        "repo": "web-portal",
        "full_name": "apex-banking/web-portal",
        "description": "Customer-facing React web portal",
        "default_branch": "main",
        "total_commits_scanned": 87,
    },
    {
        "owner": "apex-banking",
        "repo": "mobile-app",
        "full_name": "apex-banking/mobile-app",
        "description": "iOS / Android mobile banking application",
        "default_branch": "main",
        "total_commits_scanned": 64,
    },
]


# ----------------------------------------------------------------------------
# Developers (story-driven personas)
# ----------------------------------------------------------------------------
DEVELOPERS = {
    "alice.chen@apex-banking.com": {
        "name": "Alice Chen",
        "persona": "veteran",
        "typical_hour": 10,  # 10am UTC
        "hour_std": 1.5,
        "avg_additions": 65.0,
        "avg_deletions": 24.0,
        "avg_files_changed": 4.0,
        "avg_risk_score": 0.6,
        "baseline_status": "established",
        "commit_count_used": 48,
    },
    "bob.martinez@apex-banking.com": {
        "name": "Bob Martinez",
        "persona": "mostly-clean",
        "typical_hour": 14,
        "hour_std": 2.0,
        "avg_additions": 90.0,
        "avg_deletions": 35.0,
        "avg_files_changed": 5.5,
        "avg_risk_score": 1.1,
        "baseline_status": "established",
        "commit_count_used": 32,
    },
    "charlie.davis@apex-banking.com": {
        "name": "Charlie Davis",
        "persona": "risky-pattern",
        "typical_hour": 22,
        "hour_std": 3.0,
        "avg_additions": 180.0,
        "avg_deletions": 90.0,
        "avg_files_changed": 8.0,
        "avg_risk_score": 3.2,
        "baseline_status": "established",
        "commit_count_used": 26,
    },
    "dana.kim@apex-banking.com": {
        "name": "Dana Kim",
        "persona": "departing-employee",
        "typical_hour": 11,
        "hour_std": 1.5,
        "avg_additions": 75.0,
        "avg_deletions": 28.0,
        "avg_files_changed": 4.5,
        "avg_risk_score": 0.9,
        "baseline_status": "established",
        "commit_count_used": 41,
    },
    "eve.patel@apex-banking.com": {
        "name": "Eve Patel",
        "persona": "newcomer",
        "typical_hour": 13,
        "hour_std": 2.5,
        "avg_additions": 40.0,
        "avg_deletions": 8.0,
        "avg_files_changed": 2.5,
        "avg_risk_score": 0.3,
        "baseline_status": "partial",
        "commit_count_used": 7,
    },
    "frank-bot@apex-banking.com": {
        "name": "Frank Bot",
        "persona": "service-account",
        "typical_hour": 3,
        "hour_std": 0.5,
        "avg_additions": 12.0,
        "avg_deletions": 12.0,
        "avg_files_changed": 1.5,
        "avg_risk_score": 0.4,
        "baseline_status": "established",
        "commit_count_used": 120,
    },
}


# ----------------------------------------------------------------------------
# Commit scenarios — the demo storyline
# ----------------------------------------------------------------------------
# Each entry: (repo_idx, author, sha_prefix, hours_ago, message, files_changed,
#              additions, deletions, risk_score, risk_level, signals,
#              findings, sensitive_files, anomalies, ai_analysis)
#
# - findings: list of (rule_name, severity, file_path, line, matched_text, cwe, owasp)
# - sensitive_files: list of (file_path, pattern)
# - anomalies: list of (anomaly_type, description, baseline_value, observed_value, severity)
# - ai_analysis: optional dict {threat_level, confidence, impact_summary, intent_analysis,
#                                malicious_scenario, key_indicators, recommended_actions}
COMMIT_SCENARIOS = [
    # ---- Clean / routine commits (Alice, Bob — veterans) ----
    (0, "alice.chen@apex-banking.com", "a1b2c3d", 144, "Bump JWT library to 4.2.0", 2, 4, 4, 0.0, "clean", [], [], [], [], None),
    (0, "alice.chen@apex-banking.com", "a2b3c4d", 120, "Refactor balance endpoint pagination", 3, 78, 22, 0.0, "clean", [], [], [], [], None),
    (1, "bob.martinez@apex-banking.com", "b1c2d3e", 96, "Style: update primary button hover state", 1, 15, 8, 0.0, "clean", [], [], [], [], None),
    (1, "bob.martinez@apex-banking.com", "b2c3d4e", 80, "Fix copy on registration screen", 1, 6, 6, 0.0, "clean", [], [], [], [], None),
    (2, "alice.chen@apex-banking.com", "a3b4c5d", 72, "Add unit tests for transfer flow", 4, 145, 12, 0.0, "clean", [], [], [], [], None),
    (1, "bob.martinez@apex-banking.com", "b3c4d5e", 60, "Update SDK initialisation", 2, 28, 14, 0.0, "clean", [], [], [], [], None),
    # ---- Low-risk: unsigned commit only ----
    (0, "alice.chen@apex-banking.com", "a4b5c6d", 48, "Migrate auth middleware to async", 5, 210, 175, 0.5,
     "low", ["unsigned_commit"], [], [], [], None),
    # ---- Medium: off-hours + unsigned ----
    (2, "bob.martinez@apex-banking.com", "b4c5d6e", 44, "Hotfix: push notification crash", 2, 38, 12, 1.5,
     "low", ["off_hours", "unsigned_commit"], [], [], [], None),
    # ---- Frank-Bot: author/committer mismatch (expected for service account) ----
    (0, "frank-bot@apex-banking.com", "f1a2b3c", 36, "chore(deps): bump axios from 1.5.0 to 1.5.1", 1, 4, 4, 1.5,
     "low", ["off_hours", "author_committer_mismatch"], [], [], [], None),
    # ---- Charlie: risky historic pattern (off-hours + suspicious) ----
    (1, "charlie.davis@apex-banking.com", "c1d2e3f", 30, "wip", 12, 340, 280, 3.5,
     "medium", ["off_hours", "suspicious_message:vague", "large_deletion"], [], [], [], None),
    # ---- Eve: newcomer first risky finding ----
    (2, "eve.patel@apex-banking.com", "e1f2g3h", 26,
     "Add temporary admin token for debugging", 2, 18, 4, 4.5,
     "high", ["sast_findings:1", "unsigned_commit"],
     [("hardcoded_secret", "high", "src/config/dev.py", 14,
       "ADMIN_TOKEN = \"dev-admin-tok-9f3a2c\"", "CWE-798", "A07:2021 Identification and Authentication Failures")],
     [], [], None),
    # ---- Bob: large-commit anomaly (5x his baseline) ----
    (1, "bob.martinez@apex-banking.com", "b5c6d7e", 22,
     "Refactor entire onboarding flow", 18, 487, 215, 3.0,
     "medium", ["large_deletion", "unsigned_commit"],
     [],
     [],
     [("large_commit_additions",
       "+487 lines added — 5.4× above baseline avg (+90 lines)",
       90.0, 487.0, "medium")],
     None),
    # ---- Charlie: high-risk dependency tampering ----
    (0, "charlie.davis@apex-banking.com", "c2d3e4f", 18,
     "Update vendor dependencies", 3, 25, 18, 5.5,
     "high",
     ["off_hours", "unsigned_commit", "dependency_tampering:typosquat_suspect,security_dep_removed",
      "sast_findings:2"],
     [("dependency_tampering", "high", "package.json", 27,
       "\"crypt0\": \"^1.0.4\"", "CWE-829",
       "A06:2021 Vulnerable and Outdated Components"),
      ("security_dep_removed", "high", "package.json", 31,
       "Removed: helmet", "CWE-1104",
       "A06:2021 Vulnerable and Outdated Components")],
     [], [], None),
    # ---- Dana: DEPARTING-EMPLOYEE risk spike — touched .env + bulk additions ----
    (0, "dana.kim@apex-banking.com", "d1e2f3g", 14,
     "Update local config", 6, 320, 12, 7.5,
     "critical",
     ["off_hours", "unsigned_commit", "sensitive_files:2",
      "large_deletion", "sast_findings:3"],
     [("hardcoded_secret", "critical", ".env.production", 8,
       "DATABASE_URL=postgresql://prod_user:Z9!kx32a@prod-db...", "CWE-798",
       "A07:2021 Identification and Authentication Failures"),
      ("hardcoded_secret", "critical", ".env.production", 12,
       "STRIPE_SECRET_KEY=sk_live_51K8XaR2eZ...", "CWE-798",
       "A07:2021 Identification and Authentication Failures"),
      ("sensitive_data_exposure", "high", "src/scripts/export_users.py", 42,
       "with open('/tmp/customer_export.json', 'w') as f:", "CWE-200",
       "A01:2021 Broken Access Control")],
     [(".env.production", r"\.env\."),
      ("scripts/export_users.py", "export")],
     [("off_hours_deviation",
       "Committed at 02:00 — outside normal window (10:00–13:00), z-score 6.0",
       11.0, 2.0, "high"),
      ("risk_spike",
       "Risk score 7.5 — 8.3× above baseline avg (0.9)",
       0.9, 7.5, "high"),
      ("large_commit_additions",
       "+320 lines added — 4.3× above baseline avg (+75 lines)",
       75.0, 320.0, "medium")],
     {
         "threat_level": "intentional_insider",
         "confidence": 0.85,
         "impact_summary": "Production credentials (DATABASE_URL, STRIPE_SECRET_KEY) and a customer-data export script were committed in a single off-hours change by a developer whose recent risk score is 8× their established baseline. If executed, the script would write all customer records to a world-readable /tmp file.",
         "intent_analysis": "The combination of: (a) production secrets being added to a tracked file rather than .gitignored, (b) a bulk customer-export script targeting /tmp, (c) commit timing outside the developer's normal 10:00–13:00 UTC window, and (d) HR record showing the author submitted resignation 6 days ago — together strongly indicate intentional pre-departure exfiltration preparation rather than negligence.",
         "malicious_scenario": "Author exfiltrates production database credentials and uses the included export script to dump customer PII to /tmp during the resignation notice period, then exfiltrates the export over SCP or by emailing themselves before access is revoked.",
         "key_indicators": [
             "Production secrets (DATABASE_URL, STRIPE_SECRET_KEY) committed to .env.production",
             "Customer-export script writing to world-readable /tmp",
             "Commit timing at 02:00 UTC (z-score 6.0 from author's normal window)",
             "Risk score 8.3× above author's 60-commit baseline",
             "Author submitted resignation 6 days prior (per HR system)",
             "Three SAST findings + two sensitive-file alerts on a single commit",
         ],
         "recommended_actions": [
             "IMMEDIATE: revoke author's repository write access pending review",
             "IMMEDIATE: rotate DATABASE_URL and STRIPE_SECRET_KEY production secrets",
             "Force-push to remove the secrets from the repository's history (BFG / git-filter-repo)",
             "Audit production database for any unusual SELECT activity from author's identity in the last 7 days",
             "Verify whether export_users.py was ever executed (CI logs, prod shell history)",
             "Initiate formal insider-threat investigation with HR + Legal",
         ],
     }),
    # ---- Charlie: CI/CD tampering attempt ----
    (1, "charlie.davis@apex-banking.com", "c3d4e5f", 10,
     "Speed up CI", 1, 8, 14, 6.0,
     "high",
     ["off_hours", "unsigned_commit", "cicd_tampering:security_scan_disabled,hook_bypass",
      "sast_findings:1"],
     [("cicd_tampering", "high", ".github/workflows/ci.yml", 38,
       "# - run: npx snyk test  # disabled — too slow", "CWE-1188",
       "A05:2021 Security Misconfiguration")],
     [],
     [],
     None),
    # ---- Recent clean commits to give the timeline shape ----
    (0, "alice.chen@apex-banking.com", "a5b6c7d", 8, "Add OpenAPI docs for /transfers", 3, 92, 8, 0.0, "clean", [], [], [], [], None),
    (2, "alice.chen@apex-banking.com", "a6b7c8d", 4, "Bump iOS deployment target to 16", 2, 6, 6, 0.0, "clean", [], [], [], [], None),
    (1, "frank-bot@apex-banking.com", "f2a3b4c", 2, "chore(deps): bump tailwindcss", 1, 4, 4, 1.5,
     "low", ["off_hours", "author_committer_mismatch"], [], [], [], None),
]


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def ensure_github_tables(cursor):
    """Ensure GitHub Monitor tables exist (mirrors main._migrate_github_monitor_tables)."""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_monitored_repos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            repo TEXT NOT NULL,
            full_name TEXT NOT NULL,
            description TEXT,
            default_branch TEXT DEFAULT 'main',
            active INTEGER DEFAULT 1,
            last_scanned_at TEXT,
            total_commits_scanned INTEGER DEFAULT 0,
            added_by TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(owner, repo)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_commit_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_id INTEGER NOT NULL,
            sha TEXT NOT NULL,
            author_name TEXT,
            author_email TEXT,
            committer_name TEXT,
            committer_email TEXT,
            commit_message TEXT,
            committed_at TEXT,
            files_changed INTEGER DEFAULT 0,
            additions INTEGER DEFAULT 0,
            deletions INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0,
            risk_level TEXT DEFAULT 'clean',
            signals TEXT,
            files_detail TEXT,
            false_positive INTEGER DEFAULT 0,
            reviewed_by TEXT,
            reviewed_at TEXT,
            scanned_at TEXT DEFAULT (datetime('now')),
            UNIQUE(repo_id, sha)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_commit_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            rule_name TEXT NOT NULL,
            rule_id INTEGER,
            severity TEXT NOT NULL,
            file_path TEXT,
            line_number INTEGER,
            matched_text TEXT,
            category TEXT DEFAULT 'insider_threat',
            diff_snippet TEXT,
            false_positive INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_developer_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_email TEXT UNIQUE NOT NULL,
            author_name TEXT,
            total_commits INTEGER DEFAULT 0,
            high_risk_commits INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0,
            risk_trend TEXT DEFAULT 'stable',
            last_commit_at TEXT,
            avg_risk_score REAL DEFAULT 0,
            updated_at TEXT DEFAULT (datetime('now'))
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_sensitive_file_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            pattern_matched TEXT NOT NULL,
            author_email TEXT,
            committed_at TEXT,
            acknowledged INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_commit_ai_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL UNIQUE,
            threat_level TEXT NOT NULL,
            confidence REAL DEFAULT 0,
            impact_summary TEXT,
            intent_analysis TEXT,
            malicious_scenario TEXT,
            key_indicators TEXT,
            recommended_actions TEXT,
            raw_response TEXT,
            model_used TEXT,
            analyzed_at TEXT DEFAULT (datetime('now'))
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_developer_baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_email TEXT UNIQUE NOT NULL,
            typical_hour_start INTEGER DEFAULT 9,
            typical_hour_end INTEGER DEFAULT 18,
            mean_commit_hour REAL DEFAULT 12,
            std_commit_hour REAL DEFAULT 4,
            avg_additions REAL DEFAULT 0,
            avg_deletions REAL DEFAULT 0,
            avg_files_changed REAL DEFAULT 0,
            p90_additions REAL DEFAULT 0,
            p90_deletions REAL DEFAULT 0,
            avg_risk_score REAL DEFAULT 0,
            avg_commits_per_week REAL DEFAULT 0,
            commit_count_used INTEGER DEFAULT 0,
            baseline_status TEXT DEFAULT 'insufficient',
            computed_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS github_developer_anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_email TEXT NOT NULL,
            scan_id INTEGER,
            anomaly_type TEXT NOT NULL,
            description TEXT NOT NULL,
            baseline_value REAL,
            observed_value REAL,
            severity TEXT DEFAULT 'medium',
            acknowledged INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)


def clear_existing_seed(cursor):
    """Wipe any previous GitHub Monitor seed data so this script is idempotent."""
    for table in (
        "github_developer_anomalies",
        "github_commit_ai_analysis",
        "github_sensitive_file_alerts",
        "github_commit_findings",
        "github_commit_scans",
        "github_developer_baselines",
        "github_developer_profiles",
        "github_monitored_repos",
    ):
        try:
            cursor.execute(
                f"DELETE FROM {table} WHERE 1=1"
            )
        except Exception:
            pass


# ----------------------------------------------------------------------------
# Seed
# ----------------------------------------------------------------------------
def seed():
    print(f"[seed] Connecting to {DB_PATH}")
    conn = _db_connect(DB_PATH)
    cur = conn.cursor()

    ensure_github_tables(cur)
    conn.commit()

    print("[seed] Wiping any previous GitHub Monitor seed data")
    clear_existing_seed(cur)
    conn.commit()

    # --- Repos ----------------------------------------------------------------
    print("[seed] Inserting 3 monitored repositories")
    repo_ids = []
    for r in REPOS:
        cur.execute(
            """INSERT INTO github_monitored_repos
                 (owner, repo, full_name, description, default_branch,
                  total_commits_scanned, added_by, last_scanned_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (r["owner"], r["repo"], r["full_name"], r["description"],
             r["default_branch"], r["total_commits_scanned"],
             "admin@apex-banking.com", iso(NOW - timedelta(hours=1))),
        )
        # Get the id we just inserted (works in both SQLite and via my helper)
        cur.execute(
            "SELECT id FROM github_monitored_repos WHERE owner=? AND repo=?",
            (r["owner"], r["repo"]),
        )
        row = cur.fetchone()
        repo_ids.append(row[0])
    conn.commit()

    # --- Developer profiles --------------------------------------------------
    print(f"[seed] Inserting {len(DEVELOPERS)} developer profiles")
    for email, d in DEVELOPERS.items():
        # Aggregate counters derived from the COMMIT_SCENARIOS table below
        cur.execute(
            """INSERT INTO github_developer_profiles
                 (author_email, author_name, total_commits, high_risk_commits,
                  total_findings, avg_risk_score, risk_trend, last_commit_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (email, d["name"], d["commit_count_used"],
             3 if d["persona"] in ("departing-employee", "risky-pattern") else 0,
             4 if d["persona"] == "departing-employee" else (2 if d["persona"] == "risky-pattern" else 0),
             d["avg_risk_score"],
             "increasing" if d["persona"] == "departing-employee" else "stable",
             iso(NOW - timedelta(hours=2))),
        )
    conn.commit()

    # --- Baselines -----------------------------------------------------------
    print(f"[seed] Inserting baselines for {sum(1 for d in DEVELOPERS.values() if d['baseline_status'] != 'insufficient')} developers")
    for email, d in DEVELOPERS.items():
        if d["baseline_status"] == "insufficient":
            continue
        hour = d["typical_hour"]
        std = d["hour_std"]
        cur.execute(
            """INSERT INTO github_developer_baselines
                 (author_email, typical_hour_start, typical_hour_end,
                  mean_commit_hour, std_commit_hour,
                  avg_additions, avg_deletions, avg_files_changed,
                  p90_additions, p90_deletions,
                  avg_risk_score, avg_commits_per_week,
                  commit_count_used, baseline_status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (email,
             max(0, int(hour - 1.5 * std)),
             min(23, int(hour + 1.5 * std)),
             float(hour), std,
             d["avg_additions"], d["avg_deletions"], d["avg_files_changed"],
             d["avg_additions"] * 2.2, d["avg_deletions"] * 2.2,
             d["avg_risk_score"], 6.5,
             d["commit_count_used"], d["baseline_status"]),
        )
    conn.commit()

    # --- Commit scans + findings + sensitive alerts + anomalies + AI ---------
    print(f"[seed] Inserting {len(COMMIT_SCENARIOS)} commit scans with findings/alerts/anomalies")
    for (repo_idx, author_email, sha_prefix, hours_ago, message, files_changed,
         additions, deletions, risk_score, risk_level, signals, findings,
         sensitive_files, anomalies, ai_analysis) in COMMIT_SCENARIOS:

        author = DEVELOPERS[author_email]
        is_bot = author["persona"] == "service-account"
        committed_at = iso(NOW - timedelta(hours=hours_ago))
        sha = (sha_prefix + "0" * 40)[:40]

        cur.execute(
            """INSERT INTO github_commit_scans
                 (repo_id, sha, author_name, author_email,
                  committer_name, committer_email, commit_message, committed_at,
                  files_changed, additions, deletions,
                  risk_score, risk_level, signals)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (repo_ids[repo_idx], sha, author["name"], author_email,
             "github-actions[bot]" if is_bot else author["name"],
             "noreply@github.com" if is_bot else author_email,
             message, committed_at,
             files_changed, additions, deletions,
             risk_score, risk_level, json.dumps(signals)),
        )
        cur.execute("SELECT id FROM github_commit_scans WHERE repo_id=? AND sha=?",
                    (repo_ids[repo_idx], sha))
        scan_id = cur.fetchone()[0]

        # Findings
        for (rule_name, severity, file_path, line, matched, cwe, owasp) in findings:
            cur.execute(
                """INSERT INTO github_commit_findings
                     (scan_id, rule_name, severity, file_path, line_number,
                      matched_text, category, diff_snippet)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, rule_name, severity, file_path, line, matched,
                 "insider_threat",
                 f"+ {matched}\n  (CWE: {cwe} · OWASP: {owasp})"),
            )

        # Sensitive file alerts
        for (file_path, pattern) in sensitive_files:
            cur.execute(
                """INSERT INTO github_sensitive_file_alerts
                     (scan_id, file_path, pattern_matched, author_email, committed_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (scan_id, file_path, pattern, author_email, committed_at),
            )

        # Anomalies
        for (anomaly_type, desc, baseline_val, observed_val, severity) in anomalies:
            cur.execute(
                """INSERT INTO github_developer_anomalies
                     (author_email, scan_id, anomaly_type, description,
                      baseline_value, observed_value, severity)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (author_email, scan_id, anomaly_type, desc,
                 baseline_val, observed_val, severity),
            )

        # AI Analysis
        if ai_analysis:
            cur.execute(
                """INSERT INTO github_commit_ai_analysis
                     (scan_id, threat_level, confidence, impact_summary,
                      intent_analysis, malicious_scenario,
                      key_indicators, recommended_actions, model_used)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, ai_analysis["threat_level"], ai_analysis["confidence"],
                 ai_analysis["impact_summary"], ai_analysis["intent_analysis"],
                 ai_analysis["malicious_scenario"],
                 json.dumps(ai_analysis["key_indicators"]),
                 json.dumps(ai_analysis["recommended_actions"]),
                 "claude-sonnet-4.5 (demo seed)"),
            )

        conn.commit()

    # --- Final summary --------------------------------------------------------
    cur.execute("SELECT COUNT(*) FROM github_commit_scans")
    n_scans = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM github_commit_findings")
    n_findings = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM github_sensitive_file_alerts")
    n_alerts = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM github_developer_anomalies")
    n_anomalies = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM github_commit_ai_analysis")
    n_ai = cur.fetchone()[0]

    print()
    print("┌─ GitHub Monitor demo data ─────────────────────────────────")
    print(f"│  Repositories:           {len(REPOS)}")
    print(f"│  Developers:             {len(DEVELOPERS)}")
    print(f"│  Commit scans:           {n_scans}")
    print(f"│  SAST findings:          {n_findings}")
    print(f"│  Sensitive-file alerts:  {n_alerts}")
    print(f"│  Behavioural anomalies:  {n_anomalies}")
    print(f"│  AI threat analyses:     {n_ai}")
    print("└────────────────────────────────────────────────────────────")
    print()
    print("Demo storyline:")
    print("  • Alice Chen — veteran, low risk, established baseline (clean track record)")
    print("  • Bob Martinez — mostly clean; ONE recent large-commit anomaly to discuss")
    print("  • Charlie Davis — chronic risky pattern: off-hours, dependency tampering, CI/CD tampering")
    print("  • Dana Kim — DEPARTING EMPLOYEE: critical commit with .env leak + customer export script")
    print("              (full AI threat assessment attached — open the commit detail to see it)")
    print("  • Eve Patel — newcomer, partial baseline, ONE hardcoded-secret slip")
    print("  • Frank Bot — Dependabot/service account (committer-mismatch is expected, low signal)")
    print()
    print("✓ Done. Browse to: GitHub Monitor → Overview / Commit Feed / Developers / Anomalies")

    conn.close()


if __name__ == "__main__":
    seed()
