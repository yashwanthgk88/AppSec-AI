"""
Settings API Router
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import os

from models.database import get_db
from core.security import get_current_active_user
from models.models import User

router = APIRouter(prefix="/api/settings", tags=["settings"])

class AIProviderSettings(BaseModel):
    ai_provider: str
    ai_api_key: str
    ai_model: Optional[str] = None
    ai_base_url: Optional[str] = None
    ai_api_version: Optional[str] = None

class OpenAISettings(BaseModel):
    openai_api_key: str

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
