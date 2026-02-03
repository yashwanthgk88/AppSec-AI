"""
Integration Settings API Router
Handles Jira, Azure DevOps, and ServiceNow integration configuration
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from models import get_db
from models.models import User, IntegrationSettings, IntegrationType
from core.security import get_current_active_user
from services.jira_client import JiraClient
from services.ado_client import ADOClient
from services.snow_client import SNOWClient

router = APIRouter(prefix="/api/integrations", tags=["Integrations"])


# ==================== Pydantic Models ====================

class IntegrationBase(BaseModel):
    base_url: str
    username: Optional[str] = None
    api_token: str
    abuse_cases_field: Optional[str] = None
    security_req_field: Optional[str] = None


class JiraSettingsCreate(IntegrationBase):
    pass


class ADOSettingsCreate(BaseModel):
    org_url: str
    pat: str
    abuse_cases_field: Optional[str] = None
    security_req_field: Optional[str] = None


class SNOWSettingsCreate(IntegrationBase):
    pass


class IntegrationResponse(BaseModel):
    id: int
    integration_type: str
    base_url: str
    username: Optional[str]
    is_connected: bool
    last_connected_at: Optional[datetime]
    abuse_cases_field: Optional[str]
    security_req_field: Optional[str]
    connection_error: Optional[str]

    class Config:
        from_attributes = True


class ConnectionTestResult(BaseModel):
    success: bool
    message: str


class JiraProject(BaseModel):
    id: str
    key: str
    name: str


class ADOProject(BaseModel):
    id: str
    name: str


class SNOWGroup(BaseModel):
    sys_id: str
    name: str


# ==================== Helper Functions ====================

def get_user_integration(
    db: Session,
    user_id: int,
    integration_type: IntegrationType
) -> Optional[IntegrationSettings]:
    """Get user's integration settings for a specific type."""
    return db.query(IntegrationSettings).filter(
        IntegrationSettings.user_id == user_id,
        IntegrationSettings.integration_type == integration_type
    ).first()


def mask_token(token: str) -> str:
    """Mask an API token for display."""
    if not token or len(token) < 8:
        return "****"
    return token[:4] + "****" + token[-4:]


# ==================== Jira Endpoints ====================

@router.get("/jira", response_model=Optional[IntegrationResponse])
async def get_jira_settings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get current Jira integration settings."""
    settings = get_user_integration(db, current_user.id, IntegrationType.JIRA)
    return settings


@router.put("/jira")
async def save_jira_settings(
    settings_data: JiraSettingsCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Save Jira integration settings."""
    settings = get_user_integration(db, current_user.id, IntegrationType.JIRA)

    if settings:
        settings.base_url = settings_data.base_url
        settings.username = settings_data.username
        settings.api_token = settings_data.api_token
        settings.abuse_cases_field = settings_data.abuse_cases_field
        settings.security_req_field = settings_data.security_req_field
    else:
        settings = IntegrationSettings(
            user_id=current_user.id,
            integration_type=IntegrationType.JIRA,
            base_url=settings_data.base_url,
            username=settings_data.username,
            api_token=settings_data.api_token,
            abuse_cases_field=settings_data.abuse_cases_field,
            security_req_field=settings_data.security_req_field
        )
        db.add(settings)

    db.commit()
    db.refresh(settings)

    return {"success": True, "message": "Jira settings saved successfully"}


@router.post("/jira/test", response_model=ConnectionTestResult)
async def test_jira_connection(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Test Jira connection with saved credentials."""
    settings = get_user_integration(db, current_user.id, IntegrationType.JIRA)

    if not settings:
        return ConnectionTestResult(success=False, message="Jira not configured")

    client = JiraClient(
        base_url=settings.base_url,
        email=settings.username,
        api_token=settings.api_token
    )

    result = await client.test_connection()

    # Update connection status
    settings.is_connected = result["success"]
    settings.last_connected_at = datetime.utcnow() if result["success"] else None
    settings.connection_error = None if result["success"] else result["message"]
    db.commit()

    return ConnectionTestResult(**result)


@router.get("/jira/projects", response_model=List[JiraProject])
async def get_jira_projects(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get list of Jira projects."""
    settings = get_user_integration(db, current_user.id, IntegrationType.JIRA)

    if not settings:
        raise HTTPException(status_code=400, detail="Jira not configured")

    client = JiraClient(
        base_url=settings.base_url,
        email=settings.username,
        api_token=settings.api_token
    )

    try:
        projects = await client.get_projects()
        return [
            JiraProject(
                id=str(p.get("id")),
                key=p.get("key", ""),
                name=p.get("name", "")
            )
            for p in projects
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/jira/fields")
async def get_jira_custom_fields(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get list of Jira custom fields."""
    settings = get_user_integration(db, current_user.id, IntegrationType.JIRA)

    if not settings:
        raise HTTPException(status_code=400, detail="Jira not configured")

    client = JiraClient(
        base_url=settings.base_url,
        email=settings.username,
        api_token=settings.api_token
    )

    try:
        fields = await client.get_fields()
        # Filter to show custom fields that could hold text
        custom_fields = [
            {"id": f["id"], "name": f["name"]}
            for f in fields
            if f.get("id", "").startswith("customfield_") and f.get("schema", {}).get("type") in ["string", "doc", "any"]
        ]
        return custom_fields
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/jira")
async def delete_jira_settings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete Jira integration settings."""
    settings = get_user_integration(db, current_user.id, IntegrationType.JIRA)

    if settings:
        db.delete(settings)
        db.commit()

    return {"success": True, "message": "Jira settings deleted"}


# ==================== Azure DevOps Endpoints ====================

@router.get("/ado", response_model=Optional[IntegrationResponse])
async def get_ado_settings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get current Azure DevOps integration settings."""
    settings = get_user_integration(db, current_user.id, IntegrationType.ADO)
    return settings


@router.put("/ado")
async def save_ado_settings(
    settings_data: ADOSettingsCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Save Azure DevOps integration settings."""
    settings = get_user_integration(db, current_user.id, IntegrationType.ADO)

    if settings:
        settings.base_url = settings_data.org_url
        settings.api_token = settings_data.pat
        settings.abuse_cases_field = settings_data.abuse_cases_field
        settings.security_req_field = settings_data.security_req_field
    else:
        settings = IntegrationSettings(
            user_id=current_user.id,
            integration_type=IntegrationType.ADO,
            base_url=settings_data.org_url,
            api_token=settings_data.pat,
            abuse_cases_field=settings_data.abuse_cases_field,
            security_req_field=settings_data.security_req_field
        )
        db.add(settings)

    db.commit()
    db.refresh(settings)

    return {"success": True, "message": "Azure DevOps settings saved successfully"}


@router.post("/ado/test", response_model=ConnectionTestResult)
async def test_ado_connection(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Test Azure DevOps connection with saved credentials."""
    settings = get_user_integration(db, current_user.id, IntegrationType.ADO)

    if not settings:
        return ConnectionTestResult(success=False, message="Azure DevOps not configured")

    client = ADOClient(org_url=settings.base_url, pat=settings.api_token)

    result = await client.test_connection()

    settings.is_connected = result["success"]
    settings.last_connected_at = datetime.utcnow() if result["success"] else None
    settings.connection_error = None if result["success"] else result["message"]
    db.commit()

    return ConnectionTestResult(**result)


@router.get("/ado/projects", response_model=List[ADOProject])
async def get_ado_projects(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get list of Azure DevOps projects."""
    settings = get_user_integration(db, current_user.id, IntegrationType.ADO)

    if not settings:
        raise HTTPException(status_code=400, detail="Azure DevOps not configured")

    client = ADOClient(org_url=settings.base_url, pat=settings.api_token)

    try:
        projects = await client.get_projects()
        return [
            ADOProject(id=p.get("id", ""), name=p.get("name", ""))
            for p in projects
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/ado")
async def delete_ado_settings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete Azure DevOps integration settings."""
    settings = get_user_integration(db, current_user.id, IntegrationType.ADO)

    if settings:
        db.delete(settings)
        db.commit()

    return {"success": True, "message": "Azure DevOps settings deleted"}


# ==================== ServiceNow Endpoints ====================

@router.get("/snow", response_model=Optional[IntegrationResponse])
async def get_snow_settings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get current ServiceNow integration settings."""
    settings = get_user_integration(db, current_user.id, IntegrationType.SNOW)
    return settings


@router.put("/snow")
async def save_snow_settings(
    settings_data: SNOWSettingsCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Save ServiceNow integration settings."""
    settings = get_user_integration(db, current_user.id, IntegrationType.SNOW)

    if settings:
        settings.base_url = settings_data.base_url
        settings.username = settings_data.username
        settings.api_token = settings_data.api_token
        settings.abuse_cases_field = settings_data.abuse_cases_field
        settings.security_req_field = settings_data.security_req_field
    else:
        settings = IntegrationSettings(
            user_id=current_user.id,
            integration_type=IntegrationType.SNOW,
            base_url=settings_data.base_url,
            username=settings_data.username,
            api_token=settings_data.api_token,
            abuse_cases_field=settings_data.abuse_cases_field,
            security_req_field=settings_data.security_req_field
        )
        db.add(settings)

    db.commit()
    db.refresh(settings)

    return {"success": True, "message": "ServiceNow settings saved successfully"}


@router.post("/snow/test", response_model=ConnectionTestResult)
async def test_snow_connection(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Test ServiceNow connection with saved credentials."""
    settings = get_user_integration(db, current_user.id, IntegrationType.SNOW)

    if not settings:
        return ConnectionTestResult(success=False, message="ServiceNow not configured")

    client = SNOWClient(
        instance_url=settings.base_url,
        username=settings.username,
        password=settings.api_token
    )

    result = await client.test_connection()

    settings.is_connected = result["success"]
    settings.last_connected_at = datetime.utcnow() if result["success"] else None
    settings.connection_error = None if result["success"] else result["message"]
    db.commit()

    return ConnectionTestResult(**result)


@router.get("/snow/groups", response_model=List[SNOWGroup])
async def get_snow_groups(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get list of ServiceNow assignment groups."""
    settings = get_user_integration(db, current_user.id, IntegrationType.SNOW)

    if not settings:
        raise HTTPException(status_code=400, detail="ServiceNow not configured")

    client = SNOWClient(
        instance_url=settings.base_url,
        username=settings.username,
        password=settings.api_token
    )

    try:
        groups = await client.get_assignment_groups()
        return [
            SNOWGroup(sys_id=g.get("sys_id", ""), name=g.get("name", ""))
            for g in groups
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/snow")
async def delete_snow_settings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete ServiceNow integration settings."""
    settings = get_user_integration(db, current_user.id, IntegrationType.SNOW)

    if settings:
        db.delete(settings)
        db.commit()

    return {"success": True, "message": "ServiceNow settings deleted"}


# ==================== All Integrations Summary ====================

@router.get("/status")
async def get_all_integration_status(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get status of all integrations."""
    jira = get_user_integration(db, current_user.id, IntegrationType.JIRA)
    ado = get_user_integration(db, current_user.id, IntegrationType.ADO)
    snow = get_user_integration(db, current_user.id, IntegrationType.SNOW)

    return {
        "jira": {
            "configured": jira is not None,
            "connected": jira.is_connected if jira else False,
            "url": jira.base_url if jira else None
        },
        "ado": {
            "configured": ado is not None,
            "connected": ado.is_connected if ado else False,
            "url": ado.base_url if ado else None
        },
        "snow": {
            "configured": snow is not None,
            "connected": snow.is_connected if snow else False,
            "url": snow.base_url if snow else None
        }
    }
