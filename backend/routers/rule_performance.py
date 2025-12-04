"""
Rule Performance Tracking API
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
import sqlite3
import json
from datetime import datetime, timedelta
from models.custom_rule import RulePerformanceMetric, RulePerformanceStats
from core.security import get_current_user

router = APIRouter(prefix="/api/rules/performance", tags=["Rule Performance"])

def get_db():
    """Get database connection"""
    conn = sqlite3.connect('appsec.db')
    conn.row_factory = sqlite3.Row
    return conn

@router.post("/feedback")
async def submit_rule_feedback(
    rule_id: int,
    finding_id: int,
    user_feedback: str,
    feedback_comment: Optional[str] = None,
    code_snippet: Optional[str] = None,
    file_path: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Submit feedback for a rule detection"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Insert feedback
        cursor.execute('''
            INSERT INTO rule_performance_metrics (
                rule_id, finding_id, user_feedback, code_snippet,
                file_path, feedback_comment, user_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule_id, finding_id, user_feedback, code_snippet,
            file_path, feedback_comment, current_user.id
        ))

        # The database triggers will automatically update rule statistics
        conn.commit()
        conn.close()

        return {
            "message": "Feedback recorded successfully",
            "rule_id": rule_id,
            "feedback": user_feedback
        }

    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats", response_model=List[dict])
async def get_all_rule_stats(
    needs_refinement_only: bool = False,
    min_detections: int = 0
):
    """Get performance statistics for all rules"""
    conn = get_db()
    cursor = conn.cursor()

    query = """
        SELECT
            cr.id as rule_id,
            cr.name as rule_name,
            cr.severity,
            cr.language,
            cr.enabled,
            cr.total_detections,
            cr.true_positives,
            cr.false_positives,
            COUNT(CASE WHEN rpm.user_feedback = 'ignored' THEN 1 END) as ignored,
            cr.precision,
            CASE
                WHEN cr.precision IS NOT NULL AND cr.precision < 0.85 THEN 1
                ELSE 0
            END as needs_refinement,
            MAX(rpm.created_at) as last_detection,
            cr.created_at,
            cr.created_by,
            cr.generated_by
        FROM custom_rules cr
        LEFT JOIN rule_performance_metrics rpm ON cr.id = rpm.rule_id
        WHERE cr.total_detections >= ?
        GROUP BY cr.id
    """

    params = [min_detections]

    if needs_refinement_only:
        query += " HAVING needs_refinement = 1"

    query += " ORDER BY cr.total_detections DESC, cr.precision ASC"

    cursor.execute(query, params)
    stats = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return stats

@router.get("/stats/{rule_id}", response_model=dict)
async def get_rule_stats(rule_id: int):
    """Get detailed performance statistics for a specific rule"""
    conn = get_db()
    cursor = conn.cursor()

    # Get rule info
    cursor.execute("SELECT * FROM custom_rules WHERE id = ?", (rule_id,))
    rule = cursor.fetchone()

    if not rule:
        conn.close()
        raise HTTPException(status_code=404, detail="Rule not found")

    rule_dict = dict(rule)

    # Get feedback breakdown
    cursor.execute('''
        SELECT user_feedback, COUNT(*) as count
        FROM rule_performance_metrics
        WHERE rule_id = ?
        GROUP BY user_feedback
    ''', (rule_id,))

    feedback_breakdown = {row["user_feedback"]: row["count"] for row in cursor.fetchall()}

    # Get recent feedback
    cursor.execute('''
        SELECT *
        FROM rule_performance_metrics
        WHERE rule_id = ?
        ORDER BY created_at DESC
        LIMIT 10
    ''', (rule_id,))

    recent_feedback = [dict(row) for row in cursor.fetchall()]

    # Get enhancement history
    cursor.execute('''
        SELECT *
        FROM rule_enhancement_logs
        WHERE rule_id = ?
        ORDER BY timestamp DESC
        LIMIT 10
    ''', (rule_id,))

    enhancement_history = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "rule": rule_dict,
        "feedback_breakdown": feedback_breakdown,
        "recent_feedback": recent_feedback,
        "enhancement_history": enhancement_history,
        "metrics": {
            "total_detections": rule_dict["total_detections"],
            "true_positives": rule_dict["true_positives"],
            "false_positives": rule_dict["false_positives"],
            "precision": rule_dict["precision"],
            "needs_refinement": rule_dict["precision"] < 0.85 if rule_dict["precision"] else False
        }
    }

@router.get("/feedback/{finding_id}")
async def get_feedback_for_finding(finding_id: int):
    """Get feedback for a specific finding"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT rpm.*, cr.name as rule_name
        FROM rule_performance_metrics rpm
        JOIN custom_rules cr ON rpm.rule_id = cr.id
        WHERE rpm.finding_id = ?
    ''', (finding_id,))

    feedback = cursor.fetchone()
    conn.close()

    if not feedback:
        return None

    return dict(feedback)

@router.get("/dashboard")
async def get_performance_dashboard():
    """Get overall performance dashboard data"""
    conn = get_db()
    cursor = conn.cursor()

    # Overall statistics
    cursor.execute('''
        SELECT
            COUNT(*) as total_rules,
            SUM(enabled) as enabled_rules,
            SUM(total_detections) as total_detections,
            SUM(true_positives) as total_true_positives,
            SUM(false_positives) as total_false_positives,
            AVG(precision) as avg_precision,
            SUM(CASE WHEN precision < 0.85 AND total_detections > 5 THEN 1 ELSE 0 END) as rules_needing_refinement,
            SUM(CASE WHEN generated_by = 'ai' THEN 1 ELSE 0 END) as ai_generated_rules,
            SUM(CASE WHEN generated_by = 'user' THEN 1 ELSE 0 END) as user_created_rules
        FROM custom_rules
    ''')

    overall_stats = dict(cursor.fetchone())

    # Rules by severity
    cursor.execute('''
        SELECT severity, COUNT(*) as count, SUM(total_detections) as detections
        FROM custom_rules
        WHERE enabled = 1
        GROUP BY severity
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END
    ''')

    severity_breakdown = [dict(row) for row in cursor.fetchall()]

    # Top performing rules
    cursor.execute('''
        SELECT id, name, severity, total_detections, precision, generated_by
        FROM custom_rules
        WHERE total_detections > 0 AND precision > 0.9
        ORDER BY total_detections DESC
        LIMIT 10
    ''')

    top_performers = [dict(row) for row in cursor.fetchall()]

    # Rules needing attention
    cursor.execute('''
        SELECT id, name, severity, total_detections, false_positives, precision
        FROM custom_rules
        WHERE total_detections > 5 AND (precision < 0.85 OR precision IS NULL)
        ORDER BY false_positives DESC, total_detections DESC
        LIMIT 10
    ''')

    needs_attention = [dict(row) for row in cursor.fetchall()]

    # Recent enhancement activity
    cursor.execute('''
        SELECT ej.*, COUNT(cr.id) as rules_affected
        FROM enhancement_jobs ej
        LEFT JOIN custom_rules cr ON cr.created_at >= ej.started_at AND cr.created_at <= ej.completed_at
        WHERE ej.status = 'completed'
        GROUP BY ej.id
        ORDER BY ej.completed_at DESC
        LIMIT 5
    ''')

    recent_enhancements = [dict(row) for row in cursor.fetchall()]

    # Detection trend (last 30 days)
    cursor.execute('''
        SELECT DATE(created_at) as date, COUNT(*) as count
        FROM rule_performance_metrics
        WHERE created_at >= datetime('now', '-30 days')
        GROUP BY DATE(created_at)
        ORDER BY date DESC
    ''')

    detection_trend = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "overall_stats": overall_stats,
        "severity_breakdown": severity_breakdown,
        "top_performers": top_performers,
        "needs_attention": needs_attention,
        "recent_enhancements": recent_enhancements,
        "detection_trend": detection_trend,
        "overall_precision": overall_stats["avg_precision"],
        "total_rules": overall_stats["total_rules"],
        "enabled_rules": overall_stats["enabled_rules"]
    }

@router.get("/logs")
async def get_enhancement_logs(
    rule_id: Optional[int] = None,
    action: Optional[str] = None,
    ai_generated_only: bool = False,
    limit: int = 100
):
    """Get enhancement logs with filters"""
    conn = get_db()
    cursor = conn.cursor()

    query = """
        SELECT rel.*, cr.name as rule_name
        FROM rule_enhancement_logs rel
        JOIN custom_rules cr ON rel.rule_id = cr.id
        WHERE 1=1
    """
    params = []

    if rule_id:
        query += " AND rel.rule_id = ?"
        params.append(rule_id)

    if action:
        query += " AND rel.action = ?"
        params.append(action)

    if ai_generated_only:
        query += " AND rel.ai_generated = 1"

    query += " ORDER BY rel.timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    logs = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return logs

@router.delete("/feedback/{feedback_id}")
async def delete_feedback(
    feedback_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Delete a feedback entry (admin only)"""
    conn = get_db()
    cursor = conn.cursor()

    # Get feedback to update rule stats
    cursor.execute("SELECT * FROM rule_performance_metrics WHERE id = ?", (feedback_id,))
    feedback = cursor.fetchone()

    if not feedback:
        conn.close()
        raise HTTPException(status_code=404, detail="Feedback not found")

    feedback_dict = dict(feedback)

    # Manually update rule stats since triggers only work on INSERT
    cursor.execute('''
        UPDATE custom_rules
        SET
            total_detections = total_detections - 1,
            false_positives = CASE WHEN ? = 'false_positive' THEN false_positives - 1 ELSE false_positives END,
            true_positives = CASE WHEN ? IN ('resolved', 'confirmed') THEN true_positives - 1 ELSE true_positives END
        WHERE id = ?
    ''', (feedback_dict["user_feedback"], feedback_dict["user_feedback"], feedback_dict["rule_id"]))

    # Delete feedback
    cursor.execute("DELETE FROM rule_performance_metrics WHERE id = ?", (feedback_id,))

    # Recalculate precision
    cursor.execute('''
        UPDATE custom_rules
        SET precision = CASE
            WHEN (true_positives + false_positives) > 0
            THEN CAST(true_positives AS REAL) / (true_positives + false_positives)
            ELSE NULL
        END
        WHERE id = ?
    ''', (feedback_dict["rule_id"],))

    conn.commit()
    conn.close()

    return {"message": "Feedback deleted successfully"}
