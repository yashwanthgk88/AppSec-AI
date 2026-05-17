"""
Threat Intel Router — Client-uploaded + Sector threat intelligence

CRUD for client threat intel entries, sector intel queries,
and the pipe that feeds all intel into threat modeling.
"""

import json
import csv
import io
import sqlite3
import logging
from utils.db_compat import connect as _db_connect
from datetime import timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from pydantic import BaseModel
from sqlalchemy.orm import Session

from models.database import get_db
from core.security import get_current_active_user, get_current_user_or_api_key, generate_api_key, verify_api_key
from models.models import User
from services.sector_threat_intel import (
    get_sector_threats,
    get_sector_threats_by_type,
    SUPPORTED_SECTORS,
    format_intel_for_prompt,
    get_mitre_enricher,
    get_cisa_enricher,
)
from services.threat_intel import threat_intel as threat_intel_service

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
    conn = _db_connect(_get_db_path())
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


# ---------------------------------------------------------------------------
# File Upload (CSV, JSON, STIX 2.1)
# ---------------------------------------------------------------------------
VALID_INTEL_TYPES = {"incident", "threat_actor", "asset", "scenario", "regulation", "control", "pentest_finding", "risk_appetite"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_STRIDE = {"Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}

# Column aliases for CSV flexibility
CSV_COLUMN_ALIASES = {
    "intel_type": ["intel_type", "type", "category_type", "entry_type"],
    "title": ["title", "name", "threat_name", "indicator"],
    "description": ["description", "desc", "details", "summary"],
    "severity": ["severity", "risk", "risk_level", "priority"],
    "threat_category": ["threat_category", "stride", "stride_category", "category"],
    "mitre_techniques": ["mitre_techniques", "mitre", "attack_techniques", "techniques", "mitre_ids"],
    "regulatory_impact": ["regulatory_impact", "regulations", "compliance", "regulatory"],
    "recommended_controls": ["recommended_controls", "controls", "mitigations", "countermeasures"],
    "tags": ["tags", "labels", "keywords"],
    "source": ["source", "origin", "feed"],
    "references": ["references", "urls", "links", "ref"],
}


def _resolve_csv_columns(headers: List[str]) -> dict:
    """Map actual CSV headers to our schema fields using aliases."""
    mapping = {}
    lower_headers = [h.strip().lower() for h in headers]
    for field, aliases in CSV_COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in lower_headers:
                mapping[field] = headers[lower_headers.index(alias)]
                break
    return mapping


def _parse_csv_list(value: str) -> List[str]:
    """Parse a semicolon or pipe-separated string into a list."""
    if not value or not value.strip():
        return []
    for sep in [";", "|", "\n"]:
        if sep in value:
            return [v.strip() for v in value.split(sep) if v.strip()]
    return [value.strip()]


def _parse_stix_bundle(data: dict, project_id: int, user_email: str) -> List[dict]:
    """Parse STIX 2.1 bundle into our threat intel schema."""
    entries = []
    objects = data.get("objects", [])

    for obj in objects:
        obj_type = obj.get("type", "")

        # Map STIX types to our intel_type
        type_map = {
            "indicator": "scenario",
            "malware": "threat_actor",
            "threat-actor": "threat_actor",
            "attack-pattern": "scenario",
            "vulnerability": "scenario",
            "campaign": "incident",
            "intrusion-set": "threat_actor",
            "tool": "asset",
            "report": "scenario",
            "identity": "asset",
        }

        intel_type = type_map.get(obj_type)
        if not intel_type:
            continue

        title = obj.get("name", obj.get("id", "Unknown"))
        description = obj.get("description", "")

        # Extract MITRE ATT&CK techniques from kill_chain_phases
        mitre_techniques = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                mitre_techniques.append(phase.get("phase_name", ""))

        # Extract from external_references
        references = []
        for ref in obj.get("external_references", []):
            if ref.get("url"):
                references.append(ref["url"])
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                mitre_techniques.append(ref["external_id"])

        # Map confidence/severity
        confidence = obj.get("confidence", 50)
        if confidence >= 80:
            severity = "critical"
        elif confidence >= 60:
            severity = "high"
        elif confidence >= 40:
            severity = "medium"
        else:
            severity = "low"

        # Tags from labels
        tags = obj.get("labels", [])

        entries.append({
            "project_id": project_id,
            "intel_type": intel_type,
            "title": title[:500],
            "description": description[:2000] if description else None,
            "severity": severity,
            "threat_category": None,
            "mitre_techniques": list(set(mitre_techniques)),
            "regulatory_impact": [],
            "recommended_controls": [],
            "tags": tags,
            "source": "stix_import",
            "created_by": user_email,
        })

    return entries


@router.post("/upload-file")
async def upload_threat_intel_file(
    file: UploadFile = File(...),
    project_id: int = Form(...),
    current_user: User = Depends(get_current_active_user),
):
    """Upload threat intel from a file (CSV, JSON array, or STIX 2.1 bundle).

    **CSV format**: Must have at minimum a 'title' column. Supports flexible column names.
    List fields (mitre_techniques, tags, etc.) use semicolons as separators.

    **JSON format**: Array of objects matching the threat intel schema.

    **STIX 2.1**: Standard STIX bundle with `type: "bundle"` and `objects` array.
    Maps STIX types (indicator, malware, threat-actor, attack-pattern, vulnerability,
    campaign, intrusion-set) to our intel types.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided.")

    filename_lower = file.filename.lower()
    content = await file.read()

    try:
        content_str = content.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content_str = content.decode("latin-1")
        except Exception:
            raise HTTPException(status_code=400, detail="Could not decode file. Ensure UTF-8 or Latin-1 encoding.")

    entries_to_insert = []

    # --- CSV ---
    if filename_lower.endswith(".csv"):
        reader = csv.DictReader(io.StringIO(content_str))
        if not reader.fieldnames:
            raise HTTPException(status_code=400, detail="CSV file is empty or has no headers.")

        col_map = _resolve_csv_columns(list(reader.fieldnames))
        if "title" not in col_map:
            raise HTTPException(
                status_code=400,
                detail=f"CSV must have a 'title' (or 'name'/'threat_name') column. Found columns: {reader.fieldnames}",
            )

        for row_num, row in enumerate(reader, start=2):
            title = row.get(col_map.get("title", ""), "").strip()
            if not title:
                continue

            intel_type = row.get(col_map.get("intel_type", ""), "scenario").strip().lower()
            if intel_type not in VALID_INTEL_TYPES:
                intel_type = "scenario"

            severity = row.get(col_map.get("severity", ""), "medium").strip().lower()
            if severity not in VALID_SEVERITIES:
                severity = "medium"

            threat_category = row.get(col_map.get("threat_category", ""), "").strip() or None
            if threat_category and threat_category not in VALID_STRIDE:
                threat_category = None

            entries_to_insert.append({
                "project_id": project_id,
                "intel_type": intel_type,
                "title": title[:500],
                "description": row.get(col_map.get("description", ""), "").strip()[:2000] or None,
                "severity": severity,
                "threat_category": threat_category,
                "mitre_techniques": _parse_csv_list(row.get(col_map.get("mitre_techniques", ""), "")),
                "regulatory_impact": _parse_csv_list(row.get(col_map.get("regulatory_impact", ""), "")),
                "recommended_controls": _parse_csv_list(row.get(col_map.get("recommended_controls", ""), "")),
                "tags": _parse_csv_list(row.get(col_map.get("tags", ""), "")),
                "source": row.get(col_map.get("source", ""), "csv_import").strip() or "csv_import",
                "created_by": current_user.email,
            })

    # --- JSON / STIX ---
    elif filename_lower.endswith(".json"):
        try:
            data = json.loads(content_str)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")

        # Detect STIX 2.1 bundle
        if isinstance(data, dict) and data.get("type") == "bundle":
            entries_to_insert = _parse_stix_bundle(data, project_id, current_user.email)
            if not entries_to_insert:
                raise HTTPException(
                    status_code=400,
                    detail="STIX bundle parsed but no supported object types found. "
                           "Supported: indicator, malware, threat-actor, attack-pattern, vulnerability, campaign, intrusion-set, tool.",
                )

        # Plain JSON array
        elif isinstance(data, list):
            for item in data:
                if not isinstance(item, dict) or not item.get("title"):
                    continue
                intel_type = item.get("intel_type", "scenario")
                if intel_type not in VALID_INTEL_TYPES:
                    intel_type = "scenario"
                severity = item.get("severity", "medium")
                if severity not in VALID_SEVERITIES:
                    severity = "medium"

                entries_to_insert.append({
                    "project_id": project_id,
                    "intel_type": intel_type,
                    "title": str(item["title"])[:500],
                    "description": str(item.get("description", ""))[:2000] or None,
                    "severity": severity,
                    "threat_category": item.get("threat_category"),
                    "mitre_techniques": item.get("mitre_techniques", []) if isinstance(item.get("mitre_techniques"), list) else [],
                    "regulatory_impact": item.get("regulatory_impact", []) if isinstance(item.get("regulatory_impact"), list) else [],
                    "recommended_controls": item.get("recommended_controls", []) if isinstance(item.get("recommended_controls"), list) else [],
                    "tags": item.get("tags", []) if isinstance(item.get("tags"), list) else [],
                    "source": item.get("source", "json_import"),
                    "created_by": current_user.email,
                })
        else:
            raise HTTPException(
                status_code=400,
                detail="JSON must be an array of objects or a STIX 2.1 bundle.",
            )
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file.filename}. Supported: .csv, .json (plain or STIX 2.1)",
        )

    if not entries_to_insert:
        raise HTTPException(status_code=400, detail="No valid entries found in file.")

    # Insert all entries
    conn = _sqlite_conn()
    cursor = conn.cursor()
    created = 0

    for entry in entries_to_insert:
        cursor.execute(
            """INSERT INTO client_threat_intel
               (project_id, intel_type, title, description, severity,
                threat_category, mitre_techniques, regulatory_impact,
                recommended_controls, tags, source, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry["project_id"], entry["intel_type"], entry["title"], entry["description"],
                entry["severity"], entry.get("threat_category"),
                json.dumps(entry.get("mitre_techniques", [])),
                json.dumps(entry.get("regulatory_impact", [])),
                json.dumps(entry.get("recommended_controls", [])),
                json.dumps(entry.get("tags", [])),
                entry.get("source", "file_import"), entry["created_by"],
            )
        )
        created += 1

    conn.commit()
    conn.close()

    file_type = "STIX 2.1" if (filename_lower.endswith(".json") and isinstance(data, dict) and data.get("type") == "bundle") else ("CSV" if filename_lower.endswith(".csv") else "JSON")

    return {
        "created": created,
        "file_type": file_type,
        "filename": file.filename,
        "message": f"{created} threat intel entries imported from {file_type} file.",
    }


@router.get("/download-template")
async def download_csv_template(
    current_user: User = Depends(get_current_active_user),
):
    """Download a CSV template for threat intel upload."""
    from fastapi.responses import StreamingResponse

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "title", "description", "intel_type", "severity", "threat_category",
        "mitre_techniques", "regulatory_impact", "recommended_controls", "tags", "source",
    ])
    writer.writerow([
        "SQL Injection in Authentication Module",
        "Critical SQLi vulnerability discovered in login endpoint allowing authentication bypass",
        "scenario", "critical", "Tampering",
        "T1190;T1059.001", "PCI-DSS v4.0 Req 6.2;OWASP Top 10 A03",
        "Parameterized queries;Input validation;WAF rules",
        "SQLi;authentication;pentest", "internal_pentest",
    ])
    writer.writerow([
        "APT Group Targeting Our Sector",
        "Threat actor using spearphishing with macro-enabled documents targeting financial services",
        "threat_actor", "high", "Spoofing",
        "T1566.001;T1204.002", "FFIEC Cybersecurity Assessment",
        "Email gateway filtering;Security awareness training;EDR deployment",
        "APT;phishing;financial", "threat_brief",
    ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threat_intel_template.csv"},
    )


# ── Live Threat Intelligence (aggregated from CISA KEV, NVD, MISP, etc.) ──

@router.get("/threats")
async def get_threat_intelligence(
    current_user: User = Depends(get_current_active_user)
):
    """Get aggregated threat intelligence from multiple sources"""
    try:
        threats_data = await threat_intel_service.get_aggregated_threats()
        return threats_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch threat intelligence: {str(e)}")


@router.get("/stats")
async def get_threat_stats(
    current_user: User = Depends(get_current_active_user)
):
    """Get threat intelligence statistics"""
    try:
        threats_data = await threat_intel_service.get_aggregated_threats()
        threats = threats_data.get('threats', [])

        stats = {
            "total_threats": len(threats),
            "actively_exploited": len([t for t in threats if t.get('actively_exploited')]),
            "by_severity": {
                "critical": len([t for t in threats if t.get('severity') == 'critical']),
                "high": len([t for t in threats if t.get('severity') == 'high']),
                "medium": len([t for t in threats if t.get('severity') == 'medium']),
                "low": len([t for t in threats if t.get('severity') == 'low']),
            },
            "by_source": {},
            "recent_threats": threats[:10],
            "last_updated": threats_data.get('last_updated')
        }

        for threat in threats:
            source = threat.get('source', 'Unknown')
            stats['by_source'][source] = stats['by_source'].get(source, 0) + 1

        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threat stats: {str(e)}")


@router.get("/correlate")
async def correlate_threats(
    project_id: Optional[int] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Correlate vulnerabilities with active threats"""
    try:
        result = await threat_intel_service.correlate_with_vulnerabilities_async(db, project_id)

        return {
            "total_correlated": result['summary']['correlated_count'],
            "high_risk": result['summary']['high_risk_count'],
            "actively_exploited_matches": result['summary'].get('actively_exploited_matches', 0),
            "confidence_breakdown": result['summary'].get('confidence_breakdown', {}),
            "processing_time_ms": result['summary'].get('processing_time_ms', 0),
            "correlations": result['correlations']
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to correlate threats: {str(e)}")


class GenerateRuleRequest(BaseModel):
    threat_cve_id: str


@router.post("/generate-rule")
async def generate_rule_from_threat(
    request: GenerateRuleRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Auto-generate a custom SAST rule from threat intelligence"""
    try:
        threats_data = await threat_intel_service.get_aggregated_threats()
        threats = threats_data.get('threats', [])

        threat = next((t for t in threats if t.get('cve_id') == request.threat_cve_id), None)

        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")

        rule = threat_intel_service.generate_custom_rule_from_threat(threat)

        return {
            "success": True,
            "rule": rule,
            "message": f"Generated custom rule for {threat.get('name', request.threat_cve_id)}"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate rule: {str(e)}")


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


# ---------------------------------------------------------------------------
# Live Enrichment Endpoints
# ---------------------------------------------------------------------------
@router.post("/enrich/load-mitre")
async def load_mitre_attack(
    current_user: User = Depends(get_current_active_user),
):
    """Load MITRE ATT&CK Enterprise techniques from STIX feed.

    This must be called before validate or enrich endpoints.
    Data is cached in memory for the server lifetime.
    """
    enricher = get_mitre_enricher()
    count = await enricher.load_techniques()
    if count == 0:
        raise HTTPException(status_code=502, detail="Failed to fetch MITRE ATT&CK data")
    return {"loaded_techniques": count, "source": "MITRE ATT&CK Enterprise v15 (STIX)"}


@router.get("/enrich/validate/{sector}")
async def validate_sector_mitre(
    sector: str,
    current_user: User = Depends(get_current_active_user),
):
    """Validate all MITRE technique IDs in a sector's threat intel against live ATT&CK data.

    Call POST /enrich/load-mitre first to populate the technique cache.
    """
    enricher = get_mitre_enricher()
    if not enricher._loaded:
        count = await enricher.load_techniques()
        if count == 0:
            raise HTTPException(
                status_code=502,
                detail="Could not load MITRE ATT&CK data. Try POST /enrich/load-mitre first.",
            )

    sector_lower = sector.lower()
    if sector_lower not in SUPPORTED_SECTORS:
        raise HTTPException(status_code=404, detail=f"Sector '{sector}' not supported.")

    report = enricher.validate_sector_intel(sector_lower)
    return report


@router.get("/enrich/sector/{sector}")
async def get_enriched_sector_intel(
    sector: str,
    current_user: User = Depends(get_current_active_user),
):
    """Get sector threat intel enriched with live MITRE ATT&CK metadata.

    Each technique in mitre_details will have validated=True/False plus
    real tactic, platform, and data source info from ATT&CK.
    """
    enricher = get_mitre_enricher()
    if not enricher._loaded:
        count = await enricher.load_techniques()
        if count == 0:
            raise HTTPException(
                status_code=502,
                detail="Could not load MITRE ATT&CK data.",
            )

    sector_lower = sector.lower()
    if sector_lower not in SUPPORTED_SECTORS:
        raise HTTPException(status_code=404, detail=f"Sector '{sector}' not supported.")

    threats = get_sector_threats(sector_lower)
    enriched = [enricher.enrich_threat_entry(t) for t in threats]

    return {
        "sector": sector_lower,
        "entries": enriched,
        "total": len(enriched),
        "enrichment_source": "MITRE ATT&CK Enterprise STIX",
    }


@router.get("/enrich/technique/{technique_id}")
async def lookup_mitre_technique(
    technique_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Look up a single MITRE ATT&CK technique by ID (e.g., T1078, T1110.004)."""
    enricher = get_mitre_enricher()
    if not enricher._loaded:
        count = await enricher.load_techniques()
        if count == 0:
            raise HTTPException(status_code=502, detail="Could not load MITRE ATT&CK data.")

    technique = enricher.get_technique(technique_id)
    if not technique:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found in ATT&CK Enterprise.")

    return technique


@router.post("/enrich/load-kev")
async def load_cisa_kev(
    current_user: User = Depends(get_current_active_user),
):
    """Load CISA Known Exploited Vulnerabilities catalog."""
    enricher = get_cisa_enricher()
    count = await enricher.load_kev()
    if count == 0:
        raise HTTPException(status_code=502, detail="Failed to fetch CISA KEV data")
    return {"loaded_kevs": count, "source": "CISA KEV Catalog"}


@router.get("/enrich/kev/{sector}")
async def get_sector_kevs(
    sector: str,
    max_results: int = Query(default=20, le=100),
    current_user: User = Depends(get_current_active_user),
):
    """Get CISA KEV entries relevant to a sector based on vendor/product matching.

    Call POST /enrich/load-kev first to populate the KEV cache.
    """
    enricher = get_cisa_enricher()
    if not enricher._loaded:
        count = await enricher.load_kev()
        if count == 0:
            raise HTTPException(
                status_code=502,
                detail="Could not load CISA KEV data. Try POST /enrich/load-kev first.",
            )

    sector_lower = sector.lower()
    kevs = enricher.get_sector_relevant_kevs(sector_lower, max_results)

    return {
        "sector": sector_lower,
        "entries": kevs,
        "total": len(kevs),
        "source": "CISA KEV Catalog",
        "note": "Filtered by vendor/product keywords relevant to the sector",
    }


# ---------------------------------------------------------------------------
# API Key Management (JWT-authenticated users only)
# ---------------------------------------------------------------------------
class APIKeyCreate(BaseModel):
    name: str
    scopes: List[str] = ["threat_intel"]
    expires_in_days: Optional[int] = None  # None = never expires


@router.post("/api-keys")
async def create_api_key(
    body: APIKeyCreate,
    current_user: User = Depends(get_current_active_user),
):
    """Generate a new API key for external threat intel integration.

    The raw key is returned ONCE — store it securely. It cannot be retrieved later.
    """
    from datetime import datetime as _dt, timezone as _tz

    raw_key, key_hash, key_prefix = generate_api_key()

    expires_at = None
    if body.expires_in_days:
        expires_at = (_dt.now(_tz.utc) + timedelta(days=body.expires_in_days)).isoformat()

    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO api_keys (key_hash, key_prefix, name, scopes, created_by_user_id, created_by_email, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (key_hash, key_prefix, body.name, json.dumps(body.scopes), current_user.id, current_user.email, expires_at),
    )
    conn.commit()
    key_id = cursor.lastrowid
    conn.close()

    return {
        "id": key_id,
        "api_key": raw_key,
        "key_prefix": key_prefix,
        "name": body.name,
        "scopes": body.scopes,
        "expires_at": expires_at,
        "message": "Store this API key securely — it will not be shown again.",
    }


@router.get("/api-keys")
async def list_api_keys(
    current_user: User = Depends(get_current_active_user),
):
    """List all API keys created by the current user (keys are masked)."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, key_prefix, name, scopes, is_active, last_used_at, expires_at, created_at FROM api_keys WHERE created_by_user_id = ? ORDER BY created_at DESC",
        (current_user.id,),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    for row in rows:
        if row.get("scopes"):
            try:
                row["scopes"] = json.loads(row["scopes"])
            except Exception:
                row["scopes"] = []

    return {"keys": rows, "total": len(rows)}


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: int,
    current_user: User = Depends(get_current_active_user),
):
    """Revoke (deactivate) an API key."""
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE api_keys SET is_active = 0 WHERE id = ? AND created_by_user_id = ?",
        (key_id, current_user.id),
    )
    conn.commit()
    affected = cursor.rowcount
    conn.close()

    if not affected:
        raise HTTPException(status_code=404, detail="API key not found or not owned by you.")
    return {"message": "API key revoked."}


# ---------------------------------------------------------------------------
# External API Endpoints (API Key OR JWT auth)
# ---------------------------------------------------------------------------
@router.post("/external/ingest")
async def external_ingest_intel(
    body: ThreatIntelCreate,
    current_user: User = Depends(get_current_user_or_api_key),
):
    """Ingest a single threat intel entry via API key or JWT.

    This is the primary endpoint for external systems to push threat intel.

    Example:
        curl -X POST https://your-instance/api/threat-intel/external/ingest \\
          -H "X-API-Key: apsk_..." \\
          -H "Content-Type: application/json" \\
          -d '{"project_id": 1, "title": "...", "intel_type": "scenario", ...}'
    """
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
            body.source or "api_key_integration", current_user.email,
        )
    )
    conn.commit()
    entry_id = cursor.lastrowid
    conn.close()

    return {"id": entry_id, "message": "Threat intel entry ingested."}


@router.post("/external/ingest/bulk")
async def external_ingest_bulk(
    body: BulkUploadRequest,
    current_user: User = Depends(get_current_user_or_api_key),
):
    """Ingest multiple threat intel entries via API key or JWT.

    Example:
        curl -X POST https://your-instance/api/threat-intel/external/ingest/bulk \\
          -H "X-API-Key: apsk_..." \\
          -H "Content-Type: application/json" \\
          -d '{"project_id": 1, "entries": [...]}'
    """
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
                "api_key_integration", current_user.email,
            )
        )
        created += 1

    conn.commit()
    conn.close()
    return {"created": created, "message": f"{created} threat intel entries ingested."}


@router.get("/external/intel/{project_id}")
async def external_get_intel(
    project_id: int,
    intel_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_user_or_api_key),
):
    """Read threat intel entries for a project via API key or JWT.

    Example:
        curl https://your-instance/api/threat-intel/external/intel/1 \\
          -H "X-API-Key: apsk_..."
    """
    conn = _sqlite_conn()
    cursor = conn.cursor()

    query = "SELECT * FROM client_threat_intel WHERE project_id = ? AND active = 1"
    params: list = [project_id]

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

    for row in rows:
        for field in ("mitre_techniques", "regulatory_impact", "recommended_controls", "tags"):
            if row.get(field):
                try:
                    row[field] = json.loads(row[field])
                except Exception:
                    row[field] = []

    return {"entries": rows, "total": len(rows)}


# ---------------------------------------------------------------------------
# Threat Intelligence Feed Management
# ---------------------------------------------------------------------------
class FeedCreate(BaseModel):
    name: str
    feed_type: str
    url: str
    api_key: Optional[str] = None
    collection_id: Optional[str] = None
    poll_interval_minutes: int = 1440


class FeedUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    api_key: Optional[str] = None
    collection_id: Optional[str] = None
    poll_interval_minutes: Optional[int] = None
    is_active: Optional[int] = None


VALID_FEED_TYPES = {"taxii", "misp", "stix_url", "csv_url", "alienvault_otx", "abuse_ipdb"}


@router.post("/feeds")
async def create_feed(body: FeedCreate, current_user: User = Depends(get_current_active_user)):
    if body.feed_type not in VALID_FEED_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid feed type. Supported: {VALID_FEED_TYPES}")
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO threat_intel_feeds (name, feed_type, url, api_key, collection_id, poll_interval_minutes, created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (body.name, body.feed_type, body.url, body.api_key, body.collection_id, body.poll_interval_minutes, current_user.email),
    )
    conn.commit()
    feed_id = cursor.lastrowid
    conn.close()
    return {"id": feed_id, "message": f"Feed '{body.name}' created."}


@router.get("/feeds")
async def list_feeds(current_user: User = Depends(get_current_active_user)):
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_intel_feeds ORDER BY created_at DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    for row in rows:
        if row.get("api_key"):
            row["api_key"] = row["api_key"][:8] + "..." if len(row["api_key"]) > 8 else "***"
    return {"feeds": rows, "total": len(rows)}


@router.put("/feeds/{feed_id}")
async def update_feed(feed_id: int, body: FeedUpdate, current_user: User = Depends(get_current_active_user)):
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM threat_intel_feeds WHERE id = ?", (feed_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Feed not found.")
    updates, params = [], []
    for field_name, value in body.dict(exclude_unset=True).items():
        if value is not None:
            updates.append(f"{field_name} = ?")
            params.append(value)
    if updates:
        updates.append("updated_at = datetime('now')")
        params.append(feed_id)
        cursor.execute(f"UPDATE threat_intel_feeds SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()
    return {"message": "Feed updated."}


@router.delete("/feeds/{feed_id}")
async def delete_feed(feed_id: int, current_user: User = Depends(get_current_active_user)):
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM threat_intel_iocs WHERE feed_id = ?", (feed_id,))
    cursor.execute("DELETE FROM threat_intel_feeds WHERE id = ?", (feed_id,))
    conn.commit()
    deleted = cursor.rowcount
    conn.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="Feed not found.")
    return {"message": "Feed and associated IOCs deleted."}


# ---------------------------------------------------------------------------
# Feed Polling & Ingestion
# ---------------------------------------------------------------------------
@router.post("/feeds/{feed_id}/poll")
async def poll_feed(feed_id: int, current_user: User = Depends(get_current_active_user)):
    """Manually trigger a feed poll to ingest new IOCs."""
    import re as _re
    import httpx

    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_intel_feeds WHERE id = ?", (feed_id,))
    feed_row = cursor.fetchone()
    if not feed_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Feed not found.")

    feed = dict(feed_row)
    feed_type = feed["feed_type"]
    url = feed["url"]
    api_key = feed.get("api_key")
    ingested = 0

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            headers = {}
            if api_key:
                if feed_type == "alienvault_otx":
                    headers["X-OTX-API-KEY"] = api_key
                elif feed_type == "abuse_ipdb":
                    headers["Key"] = api_key
                    headers["Accept"] = "application/json"
                else:
                    headers["Authorization"] = f"Bearer {api_key}"

            response = await client.get(url, headers=headers)
            response.raise_for_status()

            iocs_to_insert: list = []

            if feed_type == "stix_url":
                data = response.json()
                objects = data.get("objects", []) if isinstance(data, dict) else data if isinstance(data, list) else []
                for obj in objects:
                    if obj.get("type") == "indicator":
                        pattern = obj.get("pattern", "")
                        labels = obj.get("labels", [])
                        threat_type = labels[0] if labels else None
                        confidence = obj.get("confidence", 50)
                        desc = obj.get("description", "")
                        for ip in _re.findall(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern):
                            iocs_to_insert.append(("ip", ip, confidence, threat_type, desc, labels))
                        for domain in _re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern):
                            iocs_to_insert.append(("domain", domain, confidence, threat_type, desc, labels))
                        for _, hash_val in _re.findall(r"file:hashes\.'([^']+)'\s*=\s*'([^']+)'", pattern):
                            ht = "hash_sha256" if len(hash_val) == 64 else "hash_sha1" if len(hash_val) == 40 else "hash_md5"
                            iocs_to_insert.append((ht, hash_val, confidence, threat_type, desc, labels))
                        for u in _re.findall(r"url:value\s*=\s*'([^']+)'", pattern):
                            iocs_to_insert.append(("url", u, confidence, threat_type, desc, labels))
                    elif obj.get("type") == "vulnerability":
                        name = obj.get("name", "")
                        if name.startswith("CVE"):
                            iocs_to_insert.append(("cve", name, 80, "exploit", obj.get("description", ""), obj.get("labels", [])))

            elif feed_type == "csv_url":
                import csv as csv_mod
                reader = csv_mod.DictReader(io.StringIO(response.text))
                for row in reader:
                    ioc_value = (row.get("indicator") or row.get("ioc") or row.get("value") or row.get("ip") or row.get("domain") or "").strip()
                    if not ioc_value:
                        continue
                    ioc_type_val = (row.get("type") or row.get("ioc_type") or "ip").strip().lower()
                    if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc_value):
                        ioc_type_val = "ip"
                    elif _re.match(r'^[a-fA-F0-9]{64}$', ioc_value):
                        ioc_type_val = "hash_sha256"
                    elif _re.match(r'^[a-fA-F0-9]{40}$', ioc_value):
                        ioc_type_val = "hash_sha1"
                    elif _re.match(r'^[a-fA-F0-9]{32}$', ioc_value):
                        ioc_type_val = "hash_md5"
                    elif _re.match(r'^https?://', ioc_value):
                        ioc_type_val = "url"
                    elif _re.match(r'^CVE-\d{4}-\d+$', ioc_value):
                        ioc_type_val = "cve"
                    elif "." in ioc_value and not ioc_value.startswith("http"):
                        ioc_type_val = "domain"
                    confidence_val = int(row.get("confidence", 50)) if str(row.get("confidence", "")).isdigit() else 50
                    iocs_to_insert.append((ioc_type_val, ioc_value, confidence_val, row.get("threat_type") or row.get("category"), row.get("description", ""), []))

            elif feed_type == "alienvault_otx":
                data = response.json()
                for pulse in (data.get("results", []) if isinstance(data, dict) else [])[:50]:
                    ioc_type_map = {"IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain", "URL": "url", "FileHash-MD5": "hash_md5", "FileHash-SHA1": "hash_sha1", "FileHash-SHA256": "hash_sha256", "email": "email", "CVE": "cve"}
                    for indicator in pulse.get("indicators", []):
                        mapped = ioc_type_map.get(indicator.get("type"), "")
                        if mapped:
                            iocs_to_insert.append((mapped, indicator.get("indicator", "").strip(), 70, pulse.get("adversary") or "unknown", (indicator.get("description") or pulse.get("description", ""))[:200], pulse.get("tags", [])))

            elif feed_type == "abuse_ipdb":
                data = response.json()
                for entry in (data.get("data", []) if isinstance(data, dict) else []):
                    ip_addr = entry.get("ipAddress", "")
                    if ip_addr:
                        iocs_to_insert.append(("ip", ip_addr, entry.get("abuseConfidenceScore", 50), "malicious_ip", f"Reports: {entry.get('totalReports', 0)}, Country: {entry.get('countryCode', 'Unknown')}", [entry.get("countryCode", "")]))

            elif feed_type in ("taxii", "misp"):
                conn.close()
                return {"message": f"{feed_type.upper()} feeds: use STIX URL type for HTTP-accessible TAXII collections, or push IOCs from MISP via the API.", "ingested": 0}

            for ioc_tuple in iocs_to_insert:
                ioc_type_val, ioc_value, confidence_val, threat_type_val, desc, tags_list = ioc_tuple
                try:
                    cursor.execute(
                        """INSERT OR REPLACE INTO threat_intel_iocs
                           (feed_id, ioc_type, ioc_value, confidence, severity, threat_type, description, source, tags, first_seen, last_seen)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,
                                   COALESCE((SELECT first_seen FROM threat_intel_iocs WHERE ioc_type=? AND ioc_value=? AND feed_id=?), datetime('now')),
                                   datetime('now'))""",
                        (feed_id, ioc_type_val, ioc_value, confidence_val,
                         "critical" if confidence_val >= 80 else "high" if confidence_val >= 60 else "medium" if confidence_val >= 40 else "low",
                         threat_type_val, (desc[:500] if desc else None), feed["name"],
                         json.dumps(tags_list if isinstance(tags_list, list) else []),
                         ioc_type_val, ioc_value, feed_id),
                    )
                    ingested += 1
                except Exception:
                    continue

            cursor.execute(
                """UPDATE threat_intel_feeds
                   SET last_polled_at=datetime('now'), last_poll_status=?, last_poll_count=?,
                       total_iocs_ingested=total_iocs_ingested+?, updated_at=datetime('now')
                   WHERE id=?""",
                ("success", ingested, ingested, feed_id),
            )
            conn.commit()

    except Exception as e:
        cursor.execute("UPDATE threat_intel_feeds SET last_polled_at=datetime('now'), last_poll_status=? WHERE id=?", (f"error: {str(e)[:200]}", feed_id))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=502, detail=f"Feed poll failed: {str(e)[:200]}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return {"ingested": ingested, "message": f"Polled feed '{feed['name']}': {ingested} IOCs ingested."}


# ---------------------------------------------------------------------------
# IOC (Indicator of Compromise) Management
# ---------------------------------------------------------------------------
VALID_IOC_TYPES = {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email", "cve", "file_path"}


class IOCCreate(BaseModel):
    ioc_type: str
    ioc_value: str
    confidence: int = 50
    severity: str = "medium"
    threat_type: Optional[str] = None
    description: Optional[str] = None
    source: Optional[str] = None
    tags: Optional[List[str]] = None
    feed_id: Optional[int] = None


class IOCBulkCreate(BaseModel):
    iocs: List[IOCCreate]


@router.post("/iocs")
async def create_ioc(body: IOCCreate, current_user: User = Depends(get_current_active_user)):
    if body.ioc_type not in VALID_IOC_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid IOC type. Supported: {VALID_IOC_TYPES}")
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT OR REPLACE INTO threat_intel_iocs
           (feed_id, ioc_type, ioc_value, confidence, severity, threat_type, description, source, tags, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
        (body.feed_id, body.ioc_type, body.ioc_value.strip(), body.confidence, body.severity,
         body.threat_type, body.description, body.source or "manual", json.dumps(body.tags or [])),
    )
    conn.commit()
    ioc_id = cursor.lastrowid
    conn.close()
    return {"id": ioc_id, "message": "IOC created."}


@router.post("/iocs/bulk")
async def bulk_create_iocs(body: IOCBulkCreate, current_user: User = Depends(get_current_active_user)):
    conn = _sqlite_conn()
    cursor = conn.cursor()
    created = 0
    for ioc in body.iocs:
        if ioc.ioc_type not in VALID_IOC_TYPES:
            continue
        try:
            cursor.execute(
                """INSERT OR REPLACE INTO threat_intel_iocs
                   (feed_id, ioc_type, ioc_value, confidence, severity, threat_type, description, source, tags, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
                (ioc.feed_id, ioc.ioc_type, ioc.ioc_value.strip(), ioc.confidence, ioc.severity,
                 ioc.threat_type, ioc.description, ioc.source or "manual", json.dumps(ioc.tags or [])),
            )
            created += 1
        except Exception:
            continue
    conn.commit()
    conn.close()
    return {"created": created, "message": f"{created} IOCs ingested."}


@router.get("/iocs")
async def list_iocs(
    ioc_type: Optional[str] = Query(default=None),
    threat_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    feed_id: Optional[int] = Query(default=None),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0),
    current_user: User = Depends(get_current_active_user),
):
    conn = _sqlite_conn()
    cursor = conn.cursor()

    query = "SELECT i.*, f.name as feed_name FROM threat_intel_iocs i LEFT JOIN threat_intel_feeds f ON i.feed_id = f.id WHERE i.is_active = 1"
    count_query = "SELECT COUNT(*) FROM threat_intel_iocs i WHERE i.is_active = 1"
    params: list = []
    count_params: list = []

    for col, val in [("i.ioc_type", ioc_type), ("i.threat_type", threat_type), ("i.severity", severity)]:
        if val:
            query += f" AND {col} = ?"
            count_query += f" AND {col} = ?"
            params.append(val)
            count_params.append(val)
    if search:
        query += " AND i.ioc_value LIKE ?"
        count_query += " AND i.ioc_value LIKE ?"
        params.append(f"%{search}%")
        count_params.append(f"%{search}%")
    if feed_id:
        query += " AND i.feed_id = ?"
        count_query += " AND i.feed_id = ?"
        params.append(feed_id)
        count_params.append(feed_id)

    cursor.execute(count_query, count_params)
    total = cursor.fetchone()[0]

    query += " ORDER BY i.last_seen DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT ioc_type, COUNT(*) as count FROM threat_intel_iocs WHERE is_active = 1 GROUP BY ioc_type ORDER BY count DESC")
    type_counts = {r["ioc_type"]: r["count"] for r in cursor.fetchall()}
    cursor.execute("SELECT COUNT(*) FROM threat_intel_iocs WHERE is_active = 1")
    total_all = cursor.fetchone()[0]
    conn.close()

    for row in rows:
        if row.get("tags"):
            try:
                row["tags"] = json.loads(row["tags"])
            except Exception:
                row["tags"] = []

    return {"iocs": rows, "total": total, "total_all": total_all, "type_counts": type_counts}


@router.delete("/iocs/{ioc_id}")
async def delete_ioc(ioc_id: int, current_user: User = Depends(get_current_active_user)):
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("UPDATE threat_intel_iocs SET is_active = 0 WHERE id = ?", (ioc_id,))
    conn.commit()
    conn.close()
    return {"message": "IOC deactivated."}


# ---------------------------------------------------------------------------
# IOC Correlation Against Scan Findings
# ---------------------------------------------------------------------------
@router.post("/correlate/{project_id}")
async def correlate_iocs_with_findings(project_id: int, current_user: User = Depends(get_current_active_user)):
    """Correlate IOCs against project scan findings (CVE, IP, domain, hash matches)."""
    import re as _re

    conn = _sqlite_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM threat_intel_iocs WHERE is_active = 1")
    iocs = [dict(r) for r in cursor.fetchall()]
    if not iocs:
        conn.close()
        return {"correlations": [], "total": 0, "message": "No IOCs to correlate."}

    cursor.execute("SELECT id, title, description, code_snippet, severity, scan_type, file_path FROM vulnerabilities WHERE project_id = ?", (project_id,))
    vulns = [dict(r) for r in cursor.fetchall()]

    cve_iocs = {i["ioc_value"].upper(): i for i in iocs if i["ioc_type"] == "cve"}
    ip_iocs = {i["ioc_value"]: i for i in iocs if i["ioc_type"] == "ip"}
    domain_iocs = {i["ioc_value"].lower(): i for i in iocs if i["ioc_type"] == "domain"}
    url_iocs = {i["ioc_value"]: i for i in iocs if i["ioc_type"] == "url"}
    hash_iocs = {i["ioc_value"].lower(): i for i in iocs if i["ioc_type"].startswith("hash_")}

    new_correlations = []
    for vuln in vulns:
        title = (vuln.get("title") or "").upper()
        searchable = f"{title} {vuln.get('code_snippet') or ''} {vuln.get('description') or ''}"

        for cve in _re.findall(r'CVE-\d{4}-\d+', title):
            if cve.upper() in cve_iocs:
                ioc = cve_iocs[cve.upper()]
                new_correlations.append({"project_id": project_id, "ioc_id": ioc["id"], "vulnerability_id": vuln["id"], "match_type": "cve_match", "match_context": f"CVE {cve} in: {vuln.get('title', '')[:100]}", "confidence": max(ioc.get("confidence", 50), 70), "severity": vuln.get("severity", "medium")})

        for ip_val, ioc in ip_iocs.items():
            if ip_val in searchable:
                new_correlations.append({"project_id": project_id, "ioc_id": ioc["id"], "vulnerability_id": vuln["id"], "match_type": "ip_in_code", "match_context": f"Malicious IP {ip_val} in {vuln.get('file_path', 'unknown')}", "confidence": ioc.get("confidence", 50), "severity": ioc.get("severity", "medium")})

        for domain_val, ioc in domain_iocs.items():
            if domain_val in searchable.lower():
                new_correlations.append({"project_id": project_id, "ioc_id": ioc["id"], "vulnerability_id": vuln["id"], "match_type": "domain_in_code", "match_context": f"Malicious domain {domain_val} in {vuln.get('file_path', 'unknown')}", "confidence": ioc.get("confidence", 50), "severity": ioc.get("severity", "medium")})

        for url_val, ioc in url_iocs.items():
            if url_val in searchable:
                new_correlations.append({"project_id": project_id, "ioc_id": ioc["id"], "vulnerability_id": vuln["id"], "match_type": "url_in_code", "match_context": f"Malicious URL in {vuln.get('file_path', 'unknown')}", "confidence": ioc.get("confidence", 50), "severity": ioc.get("severity", "medium")})

        for hash_val, ioc in hash_iocs.items():
            if hash_val in searchable.lower():
                new_correlations.append({"project_id": project_id, "ioc_id": ioc["id"], "vulnerability_id": vuln["id"], "match_type": "hash_in_code", "match_context": f"Malicious hash in {vuln.get('file_path', 'unknown')}", "confidence": ioc.get("confidence", 50), "severity": "critical"})

    cursor.execute("DELETE FROM threat_intel_correlations WHERE project_id = ?", (project_id,))
    for corr in new_correlations:
        cursor.execute(
            """INSERT INTO threat_intel_correlations (project_id, ioc_id, vulnerability_id, match_type, match_context, confidence, severity)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (corr["project_id"], corr["ioc_id"], corr["vulnerability_id"], corr["match_type"], corr["match_context"], corr["confidence"], corr["severity"]),
        )
    conn.commit()
    conn.close()

    return {"correlations": new_correlations[:100], "total": len(new_correlations), "vulnerabilities_scanned": len(vulns), "iocs_checked": len(iocs)}


@router.get("/correlations/{project_id}")
async def get_correlations(project_id: int, status: Optional[str] = Query(default=None), current_user: User = Depends(get_current_active_user)):
    conn = _sqlite_conn()
    cursor = conn.cursor()
    query = """SELECT c.*, i.ioc_type, i.ioc_value, i.threat_type as ioc_threat_type,
               v.title as vuln_title, v.severity as vuln_severity, v.scan_type, v.file_path
               FROM threat_intel_correlations c
               LEFT JOIN threat_intel_iocs i ON c.ioc_id = i.id
               LEFT JOIN vulnerabilities v ON c.vulnerability_id = v.id
               WHERE c.project_id = ?"""
    params: list = [project_id]
    if status:
        query += " AND c.status = ?"
        params.append(status)
    query += " ORDER BY c.confidence DESC"
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    summary = {"total": len(rows), "by_type": {}, "by_severity": {}, "by_status": {}}
    for r in rows:
        for key, field in [("by_type", "match_type"), ("by_severity", "severity"), ("by_status", "status")]:
            val = r.get(field, "unknown")
            summary[key][val] = summary[key].get(val, 0) + 1

    return {"correlations": rows, "summary": summary}


@router.put("/correlations/{correlation_id}")
async def update_correlation_status(correlation_id: int, status: str = Query(...), notes: Optional[str] = Query(default=None), current_user: User = Depends(get_current_active_user)):
    valid_statuses = {"new", "investigating", "confirmed", "false_positive", "resolved"}
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Supported: {valid_statuses}")
    conn = _sqlite_conn()
    cursor = conn.cursor()
    if notes:
        cursor.execute("UPDATE threat_intel_correlations SET status=?, notes=? WHERE id=?", (status, notes, correlation_id))
    else:
        cursor.execute("UPDATE threat_intel_correlations SET status=? WHERE id=?", (status, correlation_id))
    conn.commit()
    conn.close()
    return {"message": f"Correlation status updated to '{status}'."}


# ---------------------------------------------------------------------------
# IOC Dashboard Stats
# ---------------------------------------------------------------------------
@router.get("/iocs/dashboard/stats")
async def get_ioc_dashboard_stats(current_user: User = Depends(get_current_active_user)):
    conn = _sqlite_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM threat_intel_iocs WHERE is_active = 1")
    total_iocs = cursor.fetchone()[0]
    cursor.execute("SELECT ioc_type, COUNT(*) as count FROM threat_intel_iocs WHERE is_active = 1 GROUP BY ioc_type ORDER BY count DESC")
    by_type = [{"type": r["ioc_type"], "count": r["count"]} for r in cursor.fetchall()]
    cursor.execute("SELECT severity, COUNT(*) as count FROM threat_intel_iocs WHERE is_active = 1 GROUP BY severity")
    by_severity = {r["severity"]: r["count"] for r in cursor.fetchall()}
    cursor.execute("SELECT threat_type, COUNT(*) as count FROM threat_intel_iocs WHERE is_active = 1 AND threat_type IS NOT NULL GROUP BY threat_type ORDER BY count DESC LIMIT 10")
    by_threat_type = [{"type": r["threat_type"], "count": r["count"]} for r in cursor.fetchall()]
    cursor.execute("SELECT COUNT(*) FROM threat_intel_feeds WHERE is_active = 1")
    active_feeds = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM threat_intel_iocs WHERE is_active = 1 AND last_seen >= datetime('now', '-1 day')")
    recent_24h = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM threat_intel_correlations")
    total_correlations = cursor.fetchone()[0]
    conn.close()
    return {"total_iocs": total_iocs, "by_type": by_type, "by_severity": by_severity, "by_threat_type": by_threat_type, "active_feeds": active_feeds, "recent_24h": recent_24h, "total_correlations": total_correlations}
