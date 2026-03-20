"""
Threat Intel Router — Client-uploaded + Sector threat intelligence

CRUD for client threat intel entries, sector intel queries,
and the pipe that feeds all intel into threat modeling.
"""

import json
import sqlite3
import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from models.database import get_db
from core.security import get_current_active_user
from models.models import User
from services.sector_threat_intel import (
    get_sector_threats,
    get_sector_threats_by_type,
    SUPPORTED_SECTORS,
    format_intel_for_prompt,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/threat-intel", tags=["threat-intel"])


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


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class ThreatIntelCreate(BaseModel):
    project_id: int
    intel_type: str  # incident | threat_actor | asset | scenario | regulation | control | pentest_finding | risk_appetite
    title: str
    description: Optional[str] = None
    severity: str = "medium"  # critical | high | medium | low
    threat_category: Optional[str] = None  # STRIDE category
    mitre_techniques: Optional[List[str]] = None
    regulatory_impact: Optional[List[str]] = None
    recommended_controls: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    source: str = "client_upload"


class ThreatIntelUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    threat_category: Optional[str] = None
    mitre_techniques: Optional[List[str]] = None
    regulatory_impact: Optional[List[str]] = None
    recommended_controls: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    active: Optional[int] = None


class BulkUploadItem(BaseModel):
    intel_type: str
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    threat_category: Optional[str] = None
    mitre_techniques: Optional[List[str]] = None
    regulatory_impact: Optional[List[str]] = None
    recommended_controls: Optional[List[str]] = None
    tags: Optional[List[str]] = None


class BulkUploadRequest(BaseModel):
    project_id: int
    entries: List[BulkUploadItem]


# ---------------------------------------------------------------------------
# CRUD Endpoints
# ---------------------------------------------------------------------------
@router.post("")
async def create_threat_intel(
    body: ThreatIntelCreate,
    current_user: User = Depends(get_current_active_user),
):
    """Add a single threat intel entry for a project."""
    conn = _sqlite_conn()
    cursor = conn.cursor()

    cursor.execute(
        """INSERT INTO client_threat_intel
           (project_id, intel_type, title, description, severity,
            threat_category, mitre_techniques, regulatory_impact,
            recommended_controls, tags, source, created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            body.project_id, body.intel_type, body.title, body.description,
            body.severity, body.threat_category,
            json.dumps(body.mitre_techniques or []),
            json.dumps(body.regulatory_impact or []),
            json.dumps(body.recommended_controls or []),
            json.dumps(body.tags or []),
            body.source, current_user.email,
        )
    )
    conn.commit()
    entry_id = cursor.lastrowid
    conn.close()

    return {"id": entry_id, "message": "Threat intel entry created."}


@router.post("/bulk")
async def bulk_upload_threat_intel(
    body: BulkUploadRequest,
    current_user: User = Depends(get_current_active_user),
):
    """Upload multiple threat intel entries at once."""
    conn = _sqlite_conn()
    cursor = conn.cursor()

    created = 0
    for entry in body.entries:
        cursor.execute(
            """INSERT INTO client_threat_intel
               (project_id, intel_type, title, description, severity,
                threat_category, mitre_techniques, regulatory_impact,
                recommended_controls, tags, source, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                body.project_id, entry.intel_type, entry.title, entry.description,
                entry.severity, entry.threat_category,
                json.dumps(entry.mitre_techniques or []),
                json.dumps(entry.regulatory_impact or []),
                json.dumps(entry.recommended_controls or []),
                json.dumps(entry.tags or []),
                "client_upload", current_user.email,
            )
        )
        created += 1

    conn.commit()
    conn.close()
    return {"created": created, "message": f"{created} threat intel entries uploaded."}


@router.get("/{project_id}")
async def list_threat_intel(
    project_id: int,
    intel_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    active_only: bool = Query(default=True),
    current_user: User = Depends(get_current_active_user),
):
    """List all client-uploaded threat intel for a project."""
    conn = _sqlite_conn()
    cursor = conn.cursor()

    query = "SELECT * FROM client_threat_intel WHERE project_id = ?"
    params: list = [project_id]

    if active_only:
        query += " AND active = 1"
    if intel_type:
        query += " AND intel_type = ?"
        params.append(intel_type)
    if severity:
        query += " AND severity = ?"
        params.append(severity)

    query += " ORDER BY created_at DESC"
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    # Parse JSON fields
    for row in rows:
        for field in ("mitre_techniques", "regulatory_impact", "recommended_controls", "tags"):
            if row.get(field):
                try:
                    row[field] = json.loads(row[field])
                except Exception:
                    row[field] = []

    return {"entries": rows, "total": len(rows)}


@router.put("/{entry_id}")
async def update_threat_intel(
    entry_id: int,
    body: ThreatIntelUpdate,
    current_user: User = Depends(get_current_active_user),
):
    """Update a threat intel entry."""
    conn = _sqlite_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM client_threat_intel WHERE id = ?", (entry_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Entry not found.")

    updates = []
    params = []
    for field_name, value in body.dict(exclude_unset=True).items():
        if value is not None:
            if isinstance(value, list):
                updates.append(f"{field_name} = ?")
                params.append(json.dumps(value))
            else:
                updates.append(f"{field_name} = ?")
                params.append(value)

    if updates:
        params.append(entry_id)
        cursor.execute(
            f"UPDATE client_threat_intel SET {', '.join(updates)} WHERE id = ?",
            params
        )
        conn.commit()

    conn.close()
    return {"message": "Entry updated."}


@router.delete("/{entry_id}")
async def delete_threat_intel(
    entry_id: int,
    current_user: User = Depends(get_current_active_user),
):
    """Delete a threat intel entry."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM client_threat_intel WHERE id = ?", (entry_id,))
    conn.commit()
    deleted = cursor.rowcount
    conn.close()

    if not deleted:
        raise HTTPException(status_code=404, detail="Entry not found.")
    return {"message": "Entry deleted."}


# ---------------------------------------------------------------------------
# Sector Intel Endpoints
# ---------------------------------------------------------------------------
@router.get("/sectors/list")
async def list_supported_sectors(
    current_user: User = Depends(get_current_active_user),
):
    """List available sector threat intel libraries."""
    sector_info = []
    for sector in SUPPORTED_SECTORS:
        threats = get_sector_threats(sector)
        sector_info.append({
            "sector": sector,
            "total_entries": len(threats),
            "scenarios": len([t for t in threats if t["intel_type"] == "scenario"]),
            "threat_actors": len([t for t in threats if t["intel_type"] == "threat_actor"]),
            "regulations": len([t for t in threats if t["intel_type"] == "regulation"]),
        })
    return {"sectors": sector_info}


@router.get("/sectors/{sector}")
async def get_sector_intel(
    sector: str,
    intel_type: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_active_user),
):
    """Get threat intel for a specific sector."""
    sector_lower = sector.lower()
    if sector_lower not in SUPPORTED_SECTORS:
        raise HTTPException(status_code=404, detail=f"Sector '{sector}' not supported. Available: {SUPPORTED_SECTORS}")

    if intel_type:
        threats = get_sector_threats_by_type(sector_lower, intel_type)
    else:
        threats = get_sector_threats(sector_lower)

    return {"sector": sector_lower, "entries": threats, "total": len(threats)}


# ---------------------------------------------------------------------------
# Combined Intel for Threat Modeling
# ---------------------------------------------------------------------------
@router.get("/combined/{project_id}")
async def get_combined_intel(
    project_id: int,
    sector: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_active_user),
):
    """Get combined threat intel (sector + client) for use in threat modeling.

    This is the endpoint that threat modeling calls to gather all context.
    """
    combined = []

    # 1. Sector intel (if sector specified)
    if sector:
        sector_threats = get_sector_threats(sector.lower())
        combined.extend(sector_threats)

    # 2. Client-uploaded intel
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM client_threat_intel WHERE project_id = ? AND active = 1 ORDER BY severity DESC",
        (project_id,)
    )
    client_rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    for row in client_rows:
        for field in ("mitre_techniques", "regulatory_impact", "recommended_controls", "tags"):
            if row.get(field):
                try:
                    row[field] = json.loads(row[field])
                except Exception:
                    row[field] = []
        combined.append(row)

    return {
        "sector_count": len(get_sector_threats(sector.lower())) if sector else 0,
        "client_count": len(client_rows),
        "total": len(combined),
        "entries": combined,
    }


# ---------------------------------------------------------------------------
# SecReq → Threat Model Context
# ---------------------------------------------------------------------------
@router.get("/securereq-context/{project_id}")
async def get_securereq_context(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Pull abuse cases and security requirements from SecReq for a project.

    Returns formatted context ready to inject into threat modeling prompts.
    """
    from models.models import SecurityAnalysis, UserStory

    # Get all analyses for this project's user stories
    analyses = (
        db.query(SecurityAnalysis)
        .join(UserStory)
        .filter(UserStory.project_id == project_id)
        .order_by(SecurityAnalysis.id.desc())
        .all()
    )

    if not analyses:
        return {
            "has_data": False,
            "abuse_cases": [],
            "security_requirements": [],
            "stride_threats": [],
            "risk_score_avg": 0,
            "prompt_context": "",
        }

    # Collect latest analysis per story (avoid duplicates from versioning)
    seen_stories = set()
    all_abuse_cases = []
    all_requirements = []
    all_stride = []
    risk_scores = []

    for analysis in analyses:
        if analysis.user_story_id in seen_stories:
            continue
        seen_stories.add(analysis.user_story_id)

        if analysis.abuse_cases:
            cases = analysis.abuse_cases if isinstance(analysis.abuse_cases, list) else []
            all_abuse_cases.extend(cases)

        if analysis.security_requirements:
            reqs = analysis.security_requirements if isinstance(analysis.security_requirements, list) else []
            all_requirements.extend(reqs)

        if analysis.stride_threats:
            threats = analysis.stride_threats
            if isinstance(threats, list):
                all_stride.extend(threats)
            elif isinstance(threats, dict):
                for cat_threats in threats.values():
                    if isinstance(cat_threats, list):
                        all_stride.extend(cat_threats)

        if analysis.risk_score:
            risk_scores.append(analysis.risk_score)

    # Build prompt context
    prompt_lines = []

    if all_abuse_cases:
        prompt_lines.append("=== ABUSE CASES FROM SECURITY REQUIREMENTS ANALYSIS ===")
        for ac in all_abuse_cases[:15]:
            title = ac.get("threat") or ac.get("title", "Unknown")
            actor = ac.get("actor") or ac.get("threat_actor", "Unknown")
            impact = ac.get("impact", "Unknown")
            desc = ac.get("description", "")
            stride = ac.get("stride_category", "")
            prompt_lines.append(f"\n- [{impact}] {title}")
            prompt_lines.append(f"  Actor: {actor} | STRIDE: {stride}")
            if desc:
                prompt_lines.append(f"  {desc[:200]}")

    if all_requirements:
        prompt_lines.append("\n\n=== SECURITY REQUIREMENTS ===")
        for req in all_requirements[:20]:
            text = req.get("requirement") or req.get("text", "Unknown")
            priority = req.get("priority", "")
            category = req.get("category", "")
            prompt_lines.append(f"\n- [{priority}] [{category}] {text[:200]}")

    prompt_context = "\n".join(prompt_lines) if prompt_lines else ""

    return {
        "has_data": True,
        "abuse_cases": all_abuse_cases,
        "security_requirements": all_requirements,
        "stride_threats": all_stride,
        "risk_score_avg": round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0,
        "prompt_context": prompt_context,
        "stories_analyzed": len(seen_stories),
    }
