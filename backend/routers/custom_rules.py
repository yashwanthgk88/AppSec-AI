"""
Custom Rules Management API
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from typing import List, Optional
import sqlite3
import json
from datetime import datetime
from models.custom_rule import (
    CustomRule,
    CreateCustomRuleRequest,
    UpdateCustomRuleRequest,
    GenerateRuleRequest,
    RefineRuleRequest,
    RulePerformanceStats,
    EnhancementJob
)
from services.ruleset_enhancer import RulesetEnhancer
from core.security import get_current_user
from utils.db_path import get_db_path

router = APIRouter(prefix="/api/rules", tags=["Custom Rules"])

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn

# Custom Rules CRUD

@router.get("", response_model=List[dict])
async def get_all_rules(
    enabled_only: bool = False,
    severity: Optional[str] = None,
    language: Optional[str] = None
):
    """Get all custom rules with optional filters"""
    conn = get_db()
    cursor = conn.cursor()

    query = "SELECT * FROM custom_rules WHERE 1=1"
    params = []

    if enabled_only:
        query += " AND enabled = 1"
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if language:
        query += " AND (language = ? OR language = '*')"
        params.append(language)

    query += " ORDER BY severity DESC, total_detections DESC"

    cursor.execute(query, params)
    rules = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return rules

@router.get("/{rule_id}", response_model=dict)
async def get_rule_by_id(rule_id: int):
    """Get a specific rule by ID"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM custom_rules WHERE id = ?", (rule_id,))
    rule = cursor.fetchone()

    conn.close()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    return dict(rule)

@router.post("", response_model=dict)
async def create_custom_rule(
    rule: CreateCustomRuleRequest,
    current_user: dict = Depends(get_current_user)
):
    """Create a new custom rule"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Validate regex pattern
        enhancer = RulesetEnhancer()
        validation = enhancer.validate_regex_pattern(rule.pattern)

        if not validation["is_valid"]:
            raise HTTPException(status_code=400, detail=validation["error"])

        cursor.execute('''
            INSERT INTO custom_rules (
                name, pattern, severity, description, language,
                cwe, owasp, remediation, remediation_code, enabled,
                created_by, generated_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule.name, rule.pattern, rule.severity, rule.description, rule.language,
            rule.cwe, rule.owasp, rule.remediation, rule.remediation_code,
            1 if rule.enabled else 0,
            current_user.username, "user"
        ))

        rule_id = cursor.lastrowid

        # Log creation
        cursor.execute('''
            INSERT INTO rule_enhancement_logs (rule_id, action, reason, performed_by, new_pattern)
            VALUES (?, 'created', 'User created custom rule', ?, ?)
        ''', (rule_id, current_user.username, rule.pattern))

        conn.commit()

        # Fetch created rule
        cursor.execute("SELECT * FROM custom_rules WHERE id = ?", (rule_id,))
        created_rule = dict(cursor.fetchone())

        conn.close()
        return created_rule

    except sqlite3.IntegrityError as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Rule already exists: {str(e)}")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{rule_id}", response_model=dict)
async def update_custom_rule(
    rule_id: int,
    rule: UpdateCustomRuleRequest,
    current_user: dict = Depends(get_current_user)
):
    """Update an existing custom rule"""
    conn = get_db()
    cursor = conn.cursor()

    # Check if rule exists
    cursor.execute("SELECT * FROM custom_rules WHERE id = ?", (rule_id,))
    existing = cursor.fetchone()

    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Rule not found")

    existing_dict = dict(existing)

    # Build update query
    updates = []
    params = []

    if rule.name is not None:
        updates.append("name = ?")
        params.append(rule.name)
    if rule.pattern is not None:
        # Validate new pattern
        enhancer = RulesetEnhancer()
        validation = enhancer.validate_regex_pattern(rule.pattern)
        if not validation["is_valid"]:
            conn.close()
            raise HTTPException(status_code=400, detail=validation["error"])

        updates.append("pattern = ?")
        params.append(rule.pattern)

        # Log pattern change
        cursor.execute('''
            INSERT INTO rule_enhancement_logs (rule_id, action, old_pattern, new_pattern, reason, performed_by)
            VALUES (?, 'pattern_updated', ?, ?, 'User updated pattern', ?)
        ''', (rule_id, existing_dict['pattern'], rule.pattern, current_user.username))

    if rule.severity is not None:
        updates.append("severity = ?")
        params.append(rule.severity)
    if rule.description is not None:
        updates.append("description = ?")
        params.append(rule.description)
    if rule.language is not None:
        updates.append("language = ?")
        params.append(rule.language)
    if rule.cwe is not None:
        updates.append("cwe = ?")
        params.append(rule.cwe)
    if rule.owasp is not None:
        updates.append("owasp = ?")
        params.append(rule.owasp)
    if rule.remediation is not None:
        updates.append("remediation = ?")
        params.append(rule.remediation)
    if rule.remediation_code is not None:
        updates.append("remediation_code = ?")
        params.append(rule.remediation_code)
    if rule.enabled is not None:
        updates.append("enabled = ?")
        params.append(1 if rule.enabled else 0)

        # Log enable/disable
        action = 'enabled' if rule.enabled else 'disabled'
        cursor.execute('''
            INSERT INTO rule_enhancement_logs (rule_id, action, reason, performed_by)
            VALUES (?, ?, 'User toggled rule status', ?)
        ''', (rule_id, action, current_user.username))

    if updates:
        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(rule_id)

        query = f"UPDATE custom_rules SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(query, params)

    conn.commit()

    # Fetch updated rule
    cursor.execute("SELECT * FROM custom_rules WHERE id = ?", (rule_id,))
    updated_rule = dict(cursor.fetchone())

    conn.close()
    return updated_rule

@router.delete("/{rule_id}")
async def delete_custom_rule(
    rule_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Delete a custom rule"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM custom_rules WHERE id = ?", (rule_id,))
    rule = cursor.fetchone()

    if not rule:
        conn.close()
        raise HTTPException(status_code=404, detail="Rule not found")

    # Log deletion
    cursor.execute('''
        INSERT INTO rule_enhancement_logs (rule_id, action, reason, performed_by)
        VALUES (?, 'deleted', 'User deleted rule', ?)
    ''', (rule_id, current_user.username))

    cursor.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()

    return {"message": "Rule deleted successfully"}

# AI Rule Generation

@router.post("/generate", response_model=dict)
async def generate_rule_with_ai(
    request: GenerateRuleRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Generate a new rule using AI"""
    conn = get_db()
    cursor = conn.cursor()

    # Create enhancement job
    cursor.execute('''
        INSERT INTO enhancement_jobs (job_type, status, triggered_by, parameters)
        VALUES ('generate_custom', 'pending', ?, ?)
    ''', (
        current_user.username,
        json.dumps(request.dict())
    ))

    job_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Run generation in background
    background_tasks.add_task(
        run_ai_generation,
        job_id,
        request,
        current_user.username
    )

    return {
        "job_id": job_id,
        "status": "pending",
        "message": "Rule generation started"
    }

async def run_ai_generation(job_id: int, request: GenerateRuleRequest, username: str):
    """Background task to generate rule using AI"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Update job status
        cursor.execute('''
            UPDATE enhancement_jobs
            SET status = 'running', started_at = CURRENT_TIMESTAMP, progress = 10
            WHERE id = ?
        ''', (job_id,))
        conn.commit()

        # Generate rule
        enhancer = RulesetEnhancer()
        rule_data = await enhancer.generate_rule_from_description(
            rule_name=request.rule_name,
            vulnerability_description=request.vulnerability_description,
            severity=request.severity,
            languages=request.languages
        )

        cursor.execute('UPDATE enhancement_jobs SET progress = 50 WHERE id = ?', (job_id,))
        conn.commit()

        # Insert generated rules
        patterns = rule_data.get("patterns", [])
        rules_created = 0

        for pattern_data in patterns:
            try:
                cursor.execute('''
                    INSERT INTO custom_rules (
                        name, pattern, severity, description, language,
                        cwe, owasp, remediation, remediation_code, enabled,
                        created_by, generated_by, confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 'ai', 'high')
                ''', (
                    rule_data.get("name", request.rule_name),
                    pattern_data["pattern"],
                    rule_data.get("severity", request.severity),
                    rule_data.get("description", request.vulnerability_description),
                    pattern_data.get("language", "*"),
                    rule_data.get("cwe"),
                    rule_data.get("owasp"),
                    rule_data.get("remediation"),
                    rule_data.get("remediation_code"),
                    username
                ))

                rule_id = cursor.lastrowid
                rules_created += 1

                # Log creation
                cursor.execute('''
                    INSERT INTO rule_enhancement_logs (rule_id, action, reason, performed_by, ai_generated)
                    VALUES (?, 'created', 'AI generated rule', ?, 1)
                ''', (rule_id, username))

            except sqlite3.IntegrityError:
                # Rule already exists, skip
                pass

        cursor.execute('''
            UPDATE enhancement_jobs
            SET status = 'completed', completed_at = CURRENT_TIMESTAMP, progress = 100,
                rules_generated = ?
            WHERE id = ?
        ''', (rules_created, job_id))

        conn.commit()

    except Exception as e:
        cursor.execute('''
            UPDATE enhancement_jobs
            SET status = 'failed', completed_at = CURRENT_TIMESTAMP,
                errors = ?
            WHERE id = ?
        ''', (json.dumps([str(e)]), job_id))
        conn.commit()

    finally:
        conn.close()

@router.post("/refine/{rule_id}", response_model=dict)
async def refine_rule_from_feedback(
    rule_id: int,
    request: RefineRuleRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Refine a rule based on false positive feedback"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM custom_rules WHERE id = ?", (rule_id,))
    rule = cursor.fetchone()

    if not rule:
        conn.close()
        raise HTTPException(status_code=404, detail="Rule not found")

    # Create enhancement job
    cursor.execute('''
        INSERT INTO enhancement_jobs (job_type, status, triggered_by, parameters)
        VALUES ('refine_rules', 'pending', ?, ?)
    ''', (
        current_user.username,
        json.dumps({"rule_id": rule_id, "fp_count": len(request.false_positive_examples)})
    ))

    job_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Run refinement in background
    background_tasks.add_task(
        run_rule_refinement,
        job_id,
        rule_id,
        request.false_positive_examples,
        current_user.username
    )

    return {
        "job_id": job_id,
        "status": "pending",
        "message": "Rule refinement started"
    }

async def run_rule_refinement(job_id: int, rule_id: int, fp_examples: List[dict], username: str):
    """Background task to refine rule"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            UPDATE enhancement_jobs
            SET status = 'running', started_at = CURRENT_TIMESTAMP, progress = 20
            WHERE id = ?
        ''', (job_id,))
        conn.commit()

        # Get current rule
        cursor.execute("SELECT * FROM custom_rules WHERE id = ?", (rule_id,))
        rule = dict(cursor.fetchone())

        # Refine using AI
        enhancer = RulesetEnhancer()
        refinement = await enhancer.refine_rule_from_false_positives(
            rule_name=rule["name"],
            current_pattern=rule["pattern"],
            current_description=rule["description"],
            false_positive_examples=fp_examples
        )

        cursor.execute('UPDATE enhancement_jobs SET progress = 70 WHERE id = ?', (job_id,))
        conn.commit()

        # Update rule with refined pattern
        new_pattern = refinement.get("improved_pattern")
        if new_pattern:
            cursor.execute('''
                UPDATE custom_rules
                SET pattern = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (new_pattern, rule_id))

            # Log refinement
            cursor.execute('''
                INSERT INTO rule_enhancement_logs (
                    rule_id, action, old_pattern, new_pattern, reason, performed_by, ai_generated,
                    changes
                )
                VALUES (?, 'refined', ?, ?, ?, ?, 1, ?)
            ''', (
                rule_id,
                rule["pattern"],
                new_pattern,
                refinement.get("changes_made", "AI refinement based on false positives"),
                username,
                json.dumps(refinement)
            ))

        cursor.execute('''
            UPDATE enhancement_jobs
            SET status = 'completed', completed_at = CURRENT_TIMESTAMP, progress = 100,
                rules_refined = 1
            WHERE id = ?
        ''', (job_id,))

        conn.commit()

    except Exception as e:
        cursor.execute('''
            UPDATE enhancement_jobs
            SET status = 'failed', completed_at = CURRENT_TIMESTAMP,
                errors = ?
            WHERE id = ?
        ''', (json.dumps([str(e)]), job_id))
        conn.commit()

    finally:
        conn.close()

# Enhancement Jobs

@router.get("/jobs", response_model=List[dict])
async def get_enhancement_jobs(
    status: Optional[str] = None,
    limit: int = 50
):
    """Get enhancement job history"""
    conn = get_db()
    cursor = conn.cursor()

    query = "SELECT * FROM enhancement_jobs WHERE 1=1"
    params = []

    if status:
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    jobs = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return jobs

@router.get("/jobs/{job_id}", response_model=dict)
async def get_job_status(job_id: int):
    """Get status of an enhancement job"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM enhancement_jobs WHERE id = ?", (job_id,))
    job = cursor.fetchone()

    conn.close()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    return dict(job)
