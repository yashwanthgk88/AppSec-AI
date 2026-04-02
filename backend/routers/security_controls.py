"""
Security Controls Registry Router
Project-level controls inventory + per-threat control linking + residual risk scoring.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

from models import get_db
from models.models import (
    User, Project, SecurityControl, ControlStatus, ControlType, ThreatModel
)
from core.security import get_current_active_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/security-controls", tags=["Security Controls"])


# ==================== Pydantic Models ====================

class ControlCreate(BaseModel):
    name: str
    description: str
    control_type: str = "preventive"
    status: str = "implemented"
    stride_categories: List[str]  # At least one STRIDE category required
    effectiveness: float = Field(default=0.7, ge=0.0, le=1.0)
    owner: str
    evidence: Optional[str] = None


class ControlUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    control_type: Optional[str] = None
    status: Optional[str] = None
    stride_categories: Optional[List[str]] = None
    effectiveness: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    owner: Optional[str] = None
    evidence: Optional[str] = None


class LinkThreatRequest(BaseModel):
    threat_ids: List[str]


class LinkRequirementRequest(BaseModel):
    requirement_ids: List[str]


class ControlResponse(BaseModel):
    id: int
    project_id: int
    name: str
    description: Optional[str]
    control_type: str
    status: str
    stride_categories: Optional[List[str]]
    effectiveness: float
    owner: Optional[str]
    evidence: Optional[str]
    linked_threat_ids: Optional[List[str]]
    linked_requirement_ids: Optional[List[str]]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


# ==================== CRUD Endpoints ====================

@router.get("/projects/{project_id}/controls", response_model=List[ControlResponse])
async def list_controls(
    project_id: int,
    status_filter: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all security controls for a project."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    query = db.query(SecurityControl).filter(SecurityControl.project_id == project_id)
    if status_filter:
        try:
            status_enum = ControlStatus(status_filter)
            query = query.filter(SecurityControl.status == status_enum)
        except ValueError:
            pass

    controls = query.order_by(SecurityControl.created_at.desc()).all()

    # Convert enum values to strings for response
    results = []
    for c in controls:
        results.append(ControlResponse(
            id=c.id,
            project_id=c.project_id,
            name=c.name,
            description=c.description,
            control_type=c.control_type.value if c.control_type else "preventive",
            status=c.status.value if c.status else "implemented",
            stride_categories=c.stride_categories,
            effectiveness=c.effectiveness or 0.7,
            owner=c.owner,
            evidence=c.evidence,
            linked_threat_ids=c.linked_threat_ids,
            linked_requirement_ids=c.linked_requirement_ids,
            created_at=c.created_at,
            updated_at=c.updated_at,
        ))
    return results


@router.post("/projects/{project_id}/controls", response_model=ControlResponse)
async def create_control(
    project_id: int,
    data: ControlCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Add a new security control to the project registry."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Map string to enum
    try:
        ct = ControlType(data.control_type) if data.control_type else ControlType.PREVENTIVE
    except ValueError:
        ct = ControlType.PREVENTIVE
    try:
        cs = ControlStatus(data.status) if data.status else ControlStatus.IMPLEMENTED
    except ValueError:
        cs = ControlStatus.IMPLEMENTED

    control = SecurityControl(
        project_id=project_id,
        name=data.name,
        description=data.description,
        control_type=ct,
        status=cs,
        stride_categories=data.stride_categories,
        effectiveness=data.effectiveness,
        owner=data.owner,
        evidence=data.evidence,
        created_by=current_user.id,
    )
    db.add(control)
    db.commit()
    db.refresh(control)

    return ControlResponse(
        id=control.id,
        project_id=control.project_id,
        name=control.name,
        description=control.description,
        control_type=control.control_type.value,
        status=control.status.value,
        stride_categories=control.stride_categories,
        effectiveness=control.effectiveness or 0.7,
        owner=control.owner,
        evidence=control.evidence,
        linked_threat_ids=control.linked_threat_ids,
        linked_requirement_ids=control.linked_requirement_ids,
        created_at=control.created_at,
        updated_at=control.updated_at,
    )


@router.put("/controls/{control_id}", response_model=ControlResponse)
async def update_control(
    control_id: int,
    data: ControlUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update an existing security control."""
    control = db.query(SecurityControl).join(Project).filter(
        SecurityControl.id == control_id,
        Project.owner_id == current_user.id
    ).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    if data.name is not None:
        control.name = data.name
    if data.description is not None:
        control.description = data.description
    if data.control_type is not None:
        try:
            control.control_type = ControlType(data.control_type)
        except ValueError:
            pass
    if data.status is not None:
        try:
            control.status = ControlStatus(data.status)
        except ValueError:
            pass
    if data.stride_categories is not None:
        control.stride_categories = data.stride_categories
    if data.effectiveness is not None:
        control.effectiveness = data.effectiveness
    if data.owner is not None:
        control.owner = data.owner
    if data.evidence is not None:
        control.evidence = data.evidence

    db.commit()
    db.refresh(control)

    return ControlResponse(
        id=control.id,
        project_id=control.project_id,
        name=control.name,
        description=control.description,
        control_type=control.control_type.value if control.control_type else "preventive",
        status=control.status.value if control.status else "implemented",
        stride_categories=control.stride_categories,
        effectiveness=control.effectiveness or 0.7,
        owner=control.owner,
        evidence=control.evidence,
        linked_threat_ids=control.linked_threat_ids,
        linked_requirement_ids=control.linked_requirement_ids,
        created_at=control.created_at,
        updated_at=control.updated_at,
    )


@router.delete("/controls/{control_id}")
async def delete_control(
    control_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete a security control."""
    control = db.query(SecurityControl).join(Project).filter(
        SecurityControl.id == control_id,
        Project.owner_id == current_user.id
    ).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    db.delete(control)
    db.commit()
    return {"message": "Control deleted successfully"}


# ==================== Per-Threat Control Linking ====================

@router.post("/controls/{control_id}/link-threats")
async def link_threats_to_control(
    control_id: int,
    data: LinkThreatRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Link threat IDs to a control (marks threats as mitigated by this control)."""
    control = db.query(SecurityControl).join(Project).filter(
        SecurityControl.id == control_id,
        Project.owner_id == current_user.id
    ).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    existing = control.linked_threat_ids or []
    merged = list(set(existing + data.threat_ids))
    control.linked_threat_ids = merged
    db.commit()

    return {"message": f"Linked {len(data.threat_ids)} threats to control '{control.name}'", "linked_threat_ids": merged}


@router.post("/controls/{control_id}/link-requirements")
async def link_requirements_to_control(
    control_id: int,
    data: LinkRequirementRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Link security requirement IDs to a control (marks requirements as satisfied)."""
    control = db.query(SecurityControl).join(Project).filter(
        SecurityControl.id == control_id,
        Project.owner_id == current_user.id
    ).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    existing = control.linked_requirement_ids or []
    merged = list(set(existing + data.requirement_ids))
    control.linked_requirement_ids = merged
    db.commit()

    return {"message": f"Linked {len(data.requirement_ids)} requirements to control '{control.name}'", "linked_requirement_ids": merged}


# ==================== Coverage & Residual Risk ====================

@router.get("/projects/{project_id}/coverage")
async def get_controls_coverage(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get coverage analysis: which threats/requirements are mitigated by controls and residual risk."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    controls = db.query(SecurityControl).filter(
        SecurityControl.project_id == project_id
    ).all()

    # Build coverage maps
    threat_to_controls = {}  # threat_id → [control details]
    requirement_to_controls = {}  # req_id → [control details]
    stride_coverage = {}  # stride_category → [controls]

    for c in controls:
        control_info = {
            "control_id": c.id,
            "name": c.name,
            "status": c.status.value if c.status else "implemented",
            "effectiveness": c.effectiveness or 0.7,
            "control_type": c.control_type.value if c.control_type else "preventive",
        }

        for tid in (c.linked_threat_ids or []):
            threat_to_controls.setdefault(tid, []).append(control_info)

        for rid in (c.linked_requirement_ids or []):
            requirement_to_controls.setdefault(rid, []).append(control_info)

        for cat in (c.stride_categories or []):
            stride_coverage.setdefault(cat, []).append(control_info)

    total_controls = len(controls)
    implemented = sum(1 for c in controls if c.status == ControlStatus.IMPLEMENTED)
    planned = sum(1 for c in controls if c.status == ControlStatus.PLANNED)
    partial = sum(1 for c in controls if c.status == ControlStatus.PARTIAL)

    # Calculate average effectiveness for implemented controls
    impl_controls = [c for c in controls if c.status == ControlStatus.IMPLEMENTED]
    avg_effectiveness = sum(c.effectiveness or 0.7 for c in impl_controls) / len(impl_controls) if impl_controls else 0

    return {
        "summary": {
            "total_controls": total_controls,
            "implemented": implemented,
            "planned": planned,
            "partial": partial,
            "not_implemented": total_controls - implemented - planned - partial,
            "average_effectiveness": round(avg_effectiveness, 2),
            "threats_mitigated": len(threat_to_controls),
            "requirements_satisfied": len(requirement_to_controls),
        },
        "stride_coverage": stride_coverage,
        "threat_coverage": threat_to_controls,
        "requirement_coverage": requirement_to_controls,
    }


# ==================== Threats List & Set ====================

@router.get("/projects/{project_id}/threats")
async def list_project_threats(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Return all threats from the project's threat model for selection UI."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    threat_model = db.query(ThreatModel).filter(
        ThreatModel.project_id == project_id
    ).first()
    if not threat_model or not threat_model.stride_analysis:
        return []

    threats = []
    for category, items in threat_model.stride_analysis.items():
        if category == "securereq_coverage" or not isinstance(items, list):
            continue
        for i, t in enumerate(items):
            threats.append({
                "id": t.get("id", f"{category}_{i}"),
                "title": t.get("threat", t.get("name", "Unknown")),
                "category": t.get("category", category),
                "severity": t.get("severity", "medium"),
                "component": t.get("component", ""),
                "description": (t.get("description", "") or "")[:150],
            })
    return threats


class SetThreatsRequest(BaseModel):
    threat_ids: List[str]


@router.put("/controls/{control_id}/threats")
async def set_control_threats(
    control_id: int,
    data: SetThreatsRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Replace all linked threats for a control (supports select/deselect)."""
    control = db.query(SecurityControl).join(Project).filter(
        SecurityControl.id == control_id,
        Project.owner_id == current_user.id
    ).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    control.linked_threat_ids = data.threat_ids
    db.commit()
    return {"message": f"Updated linked threats for '{control.name}'", "linked_threat_ids": data.threat_ids}


class SetRequirementsRequest(BaseModel):
    requirement_ids: List[str]


@router.put("/controls/{control_id}/requirements")
async def set_control_requirements(
    control_id: int,
    data: SetRequirementsRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Replace all linked requirements for a control."""
    control = db.query(SecurityControl).join(Project).filter(
        SecurityControl.id == control_id,
        Project.owner_id == current_user.id
    ).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    control.linked_requirement_ids = data.requirement_ids
    db.commit()
    return {"message": f"Updated linked requirements for '{control.name}'", "linked_requirement_ids": data.requirement_ids}


# ==================== AI Auto-Map ====================

STRIDE_CATEGORY_ALIASES = {
    "spoofing": ["spoofing", "authentication", "identity", "impersonation"],
    "tampering": ["tampering", "integrity", "modification", "injection", "input validation"],
    "repudiation": ["repudiation", "logging", "audit", "non-repudiation", "accountability"],
    "information_disclosure": ["information disclosure", "data leak", "exposure", "confidentiality", "privacy"],
    "denial_of_service": ["denial of service", "dos", "availability", "resource exhaustion", "rate limit"],
    "elevation_of_privilege": ["elevation of privilege", "privilege escalation", "authorization", "access control", "rbac"],
}


def _compute_relevance(control_name: str, control_desc: str, control_stride: list,
                       threat_title: str, threat_desc: str, threat_category: str) -> float:
    """Score how well a control matches a threat (0.0-1.0) using keyword + STRIDE overlap."""
    score = 0.0
    control_text = f"{control_name} {control_desc}".lower()
    threat_text = f"{threat_title} {threat_desc}".lower()

    # STRIDE category match (strongest signal)
    threat_cat_lower = threat_category.lower().replace(" ", "_")
    for stride_cat in control_stride:
        cat_lower = stride_cat.lower().replace(" ", "_")
        if cat_lower == threat_cat_lower:
            score += 0.5
            break
        # Check aliases
        aliases = STRIDE_CATEGORY_ALIASES.get(cat_lower, [])
        if threat_cat_lower in [a.replace(" ", "_") for a in aliases]:
            score += 0.4
            break

    # Keyword overlap between control description and threat title/description
    control_words = set(control_text.split()) - {"the", "a", "an", "is", "are", "and", "or", "to", "of", "in", "for", "with", "on"}
    threat_words = set(threat_text.split()) - {"the", "a", "an", "is", "are", "and", "or", "to", "of", "in", "for", "with", "on"}
    if control_words and threat_words:
        overlap = len(control_words & threat_words)
        keyword_score = min(overlap / max(len(control_words), 1) * 0.5, 0.4)
        score += keyword_score

    # Bonus for specific security terms matching
    security_terms = ["encrypt", "auth", "token", "firewall", "waf", "mfa", "ssl", "tls",
                      "rbac", "audit", "log", "monitor", "rate limit", "input valid", "sanitiz",
                      "cors", "csrf", "xss", "injection", "password", "hash", "session"]
    for term in security_terms:
        if term in control_text and term in threat_text:
            score += 0.1

    return min(score, 1.0)


@router.post("/controls/{control_id}/auto-map")
async def auto_map_control(
    control_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """AI-powered auto-mapping: match a control against the project's threats using
    STRIDE category overlap + keyword relevance scoring. Returns matched threats
    sorted by relevance and auto-links those above threshold."""
    control = db.query(SecurityControl).join(Project).filter(
        SecurityControl.id == control_id,
        Project.owner_id == current_user.id
    ).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    # Get the project's threat model
    threat_model = db.query(ThreatModel).filter(
        ThreatModel.project_id == control.project_id
    ).first()
    if not threat_model or not threat_model.stride_analysis:
        raise HTTPException(status_code=404, detail="No threat model found. Generate a threat model first.")

    stride_analysis = threat_model.stride_analysis
    control_stride = control.stride_categories or []
    control_name = control.name or ""
    control_desc = control.description or ""

    # Score each threat
    matched_threats = []
    for category, threats in stride_analysis.items():
        if category == "securereq_coverage":
            continue
        if not isinstance(threats, list):
            continue
        for i, threat in enumerate(threats):
            threat_id = threat.get("id", f"{category}_{i}")
            threat_title = threat.get("threat", threat.get("name", ""))
            threat_desc = threat.get("description", "")
            threat_category = threat.get("category", category)

            relevance = _compute_relevance(
                control_name, control_desc, control_stride,
                threat_title, threat_desc, threat_category
            )

            if relevance >= 0.2:  # Minimum threshold
                matched_threats.append({
                    "threat_id": threat_id,
                    "threat_title": threat_title,
                    "stride_category": threat_category,
                    "severity": threat.get("severity", "medium"),
                    "relevance_score": round(relevance, 2),
                })

    # Sort by relevance descending
    matched_threats.sort(key=lambda t: t["relevance_score"], reverse=True)

    # Return suggestions — do NOT auto-link. Let the frontend handle user selection.
    suggested = [t["threat_id"] for t in matched_threats if t["relevance_score"] >= 0.4]

    return {
        "control_id": control_id,
        "control_name": control.name,
        "total_threats_scored": len(matched_threats),
        "suggested_count": len(suggested),
        "suggested_ids": suggested,
        "matched_threats": matched_threats[:20],
    }
