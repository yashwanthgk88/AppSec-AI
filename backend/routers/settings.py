"""
Settings API Router
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, Dict
import os

from models.database import get_db
from core.security import get_current_active_user
from models.models import User, SystemSettings

router = APIRouter(prefix="/api/settings", tags=["settings"])

class AIProviderSettings(BaseModel):
    ai_provider: str
    ai_api_key: str
    ai_model: Optional[str] = None
    ai_base_url: Optional[str] = None
    ai_api_version: Optional[str] = None

class OpenAISettings(BaseModel):
    openai_api_key: str

class ThreatIntelSettings(BaseModel):
    nvd_api_key: Optional[str] = None
    misp_api_key: Optional[str] = None
    misp_url: Optional[str] = None


# Helper functions for SystemSettings
def get_setting(db: Session, key: str) -> Optional[str]:
    """Get a setting value from the database"""
    setting = db.query(SystemSettings).filter(SystemSettings.key == key).first()
    return setting.value if setting else None

def set_setting(db: Session, key: str, value: str, description: str = "", is_secret: bool = False, category: str = "general"):
    """Set a setting value in the database"""
    setting = db.query(SystemSettings).filter(SystemSettings.key == key).first()
    if setting:
        setting.value = value
        setting.description = description
        setting.is_secret = is_secret
        setting.category = category
    else:
        setting = SystemSettings(
            key=key,
            value=value,
            description=description,
            is_secret=is_secret,
            category=category
        )
        db.add(setting)
    db.commit()
    return setting

@router.get("")
async def get_settings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get user settings"""
    # Get OpenAI key from environment (legacy)
    openai_key = os.getenv("OPENAI_API_KEY", "")
    has_openai_key = bool(openai_key)

    # Mask the key if it exists
    masked_key = "***" + openai_key[-4:] if openai_key and len(openai_key) > 4 else ""

    # Get AI provider settings from user
    has_ai_key = bool(current_user.ai_api_key)

    return {
        "openai_api_key": masked_key,
        "has_openai_key": has_openai_key,
        "ai_provider": current_user.ai_provider or "anthropic",
        "ai_model": current_user.ai_model,
        "ai_base_url": current_user.ai_base_url,
        "ai_api_version": current_user.ai_api_version,
        "has_ai_key": has_ai_key
    }

@router.put("")
async def update_settings(
    settings: OpenAISettings,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update OpenAI API key (legacy endpoint)"""
    # For now, just update the environment variable approach
    # In production, you'd want to encrypt and store per-user

    # Update .env file
    env_path = ".env"
    env_lines = []

    # Read existing .env if it exists
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            env_lines = f.readlines()

    # Update or add OPENAI_API_KEY
    key_found = False
    for i, line in enumerate(env_lines):
        if line.startswith("OPENAI_API_KEY="):
            env_lines[i] = f"OPENAI_API_KEY={settings.openai_api_key}\n"
            key_found = True
            break

    if not key_found:
        env_lines.append(f"OPENAI_API_KEY={settings.openai_api_key}\n")

    # Write back to .env
    with open(env_path, "w") as f:
        f.writelines(env_lines)

    # Update environment variable in current process
    os.environ["OPENAI_API_KEY"] = settings.openai_api_key

    return {
        "success": True,
        "message": "OpenAI API key updated successfully. Restart the server for changes to take effect."
    }

@router.put("/ai-provider")
async def update_ai_provider(
    settings: AIProviderSettings,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update AI provider configuration"""
    # Validate provider
    valid_providers = ["anthropic", "openai", "azure", "google", "ollama"]
    if settings.ai_provider not in valid_providers:
        raise HTTPException(status_code=400, detail=f"Invalid provider. Must be one of: {', '.join(valid_providers)}")

    # Update user settings
    current_user.ai_provider = settings.ai_provider
    current_user.ai_api_key = settings.ai_api_key  # TODO: Encrypt this
    current_user.ai_model = settings.ai_model
    current_user.ai_base_url = settings.ai_base_url
    current_user.ai_api_version = settings.ai_api_version

    db.commit()

    return {
        "success": True,
        "message": f"{settings.ai_provider.title()} configuration saved successfully"
    }


# ==================== THREAT INTEL SETTINGS ====================

@router.get("/threat-intel")
async def get_threat_intel_settings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get threat intelligence API settings"""
    # Get from database first, fallback to environment variables
    nvd_key = get_setting(db, "NVD_API_KEY") or os.getenv("NVD_API_KEY", "")
    misp_key = get_setting(db, "MISP_API_KEY") or os.getenv("MISP_API_KEY", "")
    misp_url = get_setting(db, "MISP_URL") or os.getenv("MISP_URL", "")

    # Mask API keys for display
    def mask_key(key: str) -> str:
        if key and len(key) > 8:
            return key[:4] + "*" * (len(key) - 8) + key[-4:]
        return "***" if key else ""

    return {
        "nvd_api_key": mask_key(nvd_key),
        "has_nvd_key": bool(nvd_key),
        "misp_api_key": mask_key(misp_key),
        "has_misp_key": bool(misp_key),
        "misp_url": misp_url,
        "sources": {
            "nvd": {
                "name": "NVD (National Vulnerability Database)",
                "description": "NIST's vulnerability database with CVE details and CVSS scores",
                "requires_key": False,
                "key_url": "https://nvd.nist.gov/developers/request-an-api-key",
                "benefits": "Higher rate limits (50 req/30s vs 5 req/30s without key)"
            },
            "cisa_kev": {
                "name": "CISA KEV (Known Exploited Vulnerabilities)",
                "description": "Catalog of vulnerabilities actively exploited in the wild",
                "requires_key": False,
                "key_url": None,
                "benefits": "No API key required - free public access"
            },
            "misp": {
                "name": "MISP Galaxy",
                "description": "Threat actors, ransomware families, and exploit kits",
                "requires_key": False,
                "key_url": "https://www.misp-project.org/",
                "benefits": "For private MISP instances, provides additional threat data"
            }
        }
    }


@router.put("/threat-intel")
async def update_threat_intel_settings(
    settings: ThreatIntelSettings,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update threat intelligence API settings"""
    updated = []

    # Update NVD API key
    if settings.nvd_api_key is not None:
        set_setting(
            db,
            "NVD_API_KEY",
            settings.nvd_api_key,
            "NVD API key for higher rate limits",
            is_secret=True,
            category="threat_intel"
        )
        # Also update environment variable for current process
        os.environ["NVD_API_KEY"] = settings.nvd_api_key
        updated.append("NVD API Key")

    # Update MISP settings
    if settings.misp_api_key is not None:
        set_setting(
            db,
            "MISP_API_KEY",
            settings.misp_api_key,
            "MISP API key for private instances",
            is_secret=True,
            category="threat_intel"
        )
        os.environ["MISP_API_KEY"] = settings.misp_api_key
        updated.append("MISP API Key")

    if settings.misp_url is not None:
        set_setting(
            db,
            "MISP_URL",
            settings.misp_url,
            "MISP instance URL",
            is_secret=False,
            category="threat_intel"
        )
        os.environ["MISP_URL"] = settings.misp_url
        updated.append("MISP URL")

    # Clear threat intel cache to use new keys
    try:
        from services.threat_intel import threat_intel
        threat_intel.cached_data = {}
        threat_intel.cached_time = {}
        # Update the NVD API key in the service
        threat_intel.nvd_api_key = os.getenv("NVD_API_KEY", "")
    except Exception as e:
        print(f"Warning: Could not clear threat intel cache: {e}")

    return {
        "success": True,
        "message": f"Updated: {', '.join(updated)}" if updated else "No changes made",
        "updated_fields": updated
    }


@router.delete("/threat-intel/{key_type}")
async def delete_threat_intel_key(
    key_type: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete a threat intelligence API key"""
    key_map = {
        "nvd": "NVD_API_KEY",
        "misp": "MISP_API_KEY",
        "misp_url": "MISP_URL"
    }

    if key_type not in key_map:
        raise HTTPException(status_code=400, detail=f"Invalid key type. Must be one of: {', '.join(key_map.keys())}")

    db_key = key_map[key_type]

    # Delete from database
    setting = db.query(SystemSettings).filter(SystemSettings.key == db_key).first()
    if setting:
        db.delete(setting)
        db.commit()

    # Remove from environment
    if db_key in os.environ:
        del os.environ[db_key]

    # Clear threat intel cache
    try:
        from services.threat_intel import threat_intel
        threat_intel.cached_data = {}
        threat_intel.cached_time = {}
        threat_intel.nvd_api_key = os.getenv("NVD_API_KEY", "")
    except Exception:
        pass

    return {
        "success": True,
        "message": f"{key_type.upper()} key deleted successfully"
    }


@router.post("/threat-intel/test")
async def test_threat_intel_connection(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Test threat intelligence API connections"""
    import httpx

    results = {
        "nvd": {"status": "unknown", "message": ""},
        "cisa_kev": {"status": "unknown", "message": ""},
        "misp": {"status": "unknown", "message": ""}
    }

    # Get current API key
    nvd_key = get_setting(db, "NVD_API_KEY") or os.getenv("NVD_API_KEY", "")

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Test NVD
            try:
                headers = {"apiKey": nvd_key} if nvd_key else {}
                response = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
                    headers=headers
                )
                if response.status_code == 200:
                    results["nvd"] = {
                        "status": "success",
                        "message": "Connected successfully" + (" (with API key)" if nvd_key else " (no API key - limited rate)")
                    }
                else:
                    results["nvd"] = {"status": "error", "message": f"HTTP {response.status_code}"}
            except Exception as e:
                results["nvd"] = {"status": "error", "message": str(e)}

            # Test CISA KEV
            try:
                response = await client.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                )
                if response.status_code == 200:
                    data = response.json()
                    count = len(data.get("vulnerabilities", []))
                    results["cisa_kev"] = {
                        "status": "success",
                        "message": f"Connected successfully ({count} vulnerabilities available)"
                    }
                else:
                    results["cisa_kev"] = {"status": "error", "message": f"HTTP {response.status_code}"}
            except Exception as e:
                results["cisa_kev"] = {"status": "error", "message": str(e)}

            # Test MISP Galaxy (public GitHub)
            try:
                response = await client.get(
                    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
                )
                if response.status_code == 200:
                    data = response.json()
                    count = len(data.get("values", []))
                    results["misp"] = {
                        "status": "success",
                        "message": f"Connected to MISP Galaxy ({count} threat actors available)"
                    }
                else:
                    results["misp"] = {"status": "error", "message": f"HTTP {response.status_code}"}
            except Exception as e:
                results["misp"] = {"status": "error", "message": str(e)}

    except Exception as e:
        return {"success": False, "error": str(e), "results": results}

    all_success = all(r["status"] == "success" for r in results.values())

    return {
        "success": all_success,
        "results": results
    }
