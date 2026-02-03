"""
Application Intelligence API Router

Provides endpoints for application profiling, AI rule suggestions,
and real-time profiling status updates.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, Dict, List, Any
from datetime import datetime
import asyncio
import json
import logging

from models.database import get_db
from core.security import get_current_active_user
from models.models import (
    User, Project, ApplicationProfile, SuggestedRule,
    ProfileStatus, SuggestionStatus, SeverityLevel
)
from services.application_profiler import ApplicationProfiler
from services.ai_rule_suggester import AIRuleSuggester
from services.repository_scanner import RepositoryScanner
from utils.db_path import get_db_path
import subprocess
import shutil
import os
import sqlite3

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/application-intelligence", tags=["application-intelligence"])

# Initialize services
profiler = ApplicationProfiler()
rule_suggester = AIRuleSuggester()

# In-memory store for real-time status updates (would use Redis in production)
profiling_status: Dict[int, Dict[str, Any]] = {}


# Pydantic Schemas
class ProfileResponse(BaseModel):
    id: int
    project_id: int
    status: str
    status_message: Optional[str]
    profiling_progress: int
    languages: Optional[Dict[str, float]]
    frameworks: Optional[List[Dict[str, str]]]
    databases: Optional[List[str]]
    orm_libraries: Optional[List[str]]
    entry_points: Optional[List[Dict[str, Any]]]
    sensitive_data_fields: Optional[List[Dict[str, Any]]]
    auth_mechanisms: Optional[List[str]]
    dependencies: Optional[Dict[str, str]]
    external_integrations: Optional[List[str]]
    cloud_services: Optional[List[str]]
    file_count: int
    total_lines_of_code: int
    security_score: Optional[float]
    risk_level: Optional[str]
    total_suggestions: int
    critical_suggestions: int
    high_suggestions: int
    last_profiled_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class SuggestedRuleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    category: Optional[str]
    severity: str
    reason: Optional[str]
    detected_patterns: Optional[List[Dict[str, Any]]]
    framework_context: Optional[str]
    rule_pattern: Optional[str]
    rule_type: str
    semgrep_rule: Optional[str]
    codeql_rule: Optional[str]
    checkmarx_rule: Optional[str]
    fortify_rule: Optional[str]
    cwe_ids: Optional[List[str]]
    owasp_categories: Optional[List[str]]
    mitre_techniques: Optional[List[str]]
    status: str
    confidence_score: Optional[float]
    user_feedback: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class RuleFeedback(BaseModel):
    feedback: str  # helpful, not_helpful, false_positive
    comment: Optional[str] = None


class ProfileStatusUpdate(BaseModel):
    project_id: int
    status: str
    progress: int
    message: str
    timestamp: datetime


class SuggestionStats(BaseModel):
    total: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    by_framework: Dict[str, int]
    average_confidence: float


# Helper functions
def get_project_path(project: Project) -> str:
    """Get the repository path for a project."""
    if project.repository_url:
        # Extract project name from URL
        repo_name = project.repository_url.rstrip('/').split('/')[-1]
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        return f"/tmp/repos/{repo_name}"
    return f"/tmp/repos/project_{project.id}"


def ensure_repository_cloned(project: Project) -> str:
    """
    Ensure the repository is cloned to the expected path.
    Returns the path to the cloned repository.
    """
    project_path = get_project_path(project)
    repos_dir = "/tmp/repos"

    # Create /tmp/repos if it doesn't exist
    if not os.path.exists(repos_dir):
        os.makedirs(repos_dir, exist_ok=True)
        logger.info(f"Created repos directory: {repos_dir}")

    # If repository already exists, return path
    if os.path.exists(project_path) and os.path.isdir(project_path):
        logger.info(f"Repository already exists at: {project_path}")
        return project_path

    # Clone the repository if URL is provided
    if project.repository_url:
        logger.info(f"Cloning repository from {project.repository_url} to {project_path}")
        try:
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', project.repository_url, project_path],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            if result.returncode != 0:
                raise Exception(f"Git clone failed: {result.stderr}")
            logger.info(f"Successfully cloned repository to: {project_path}")
            return project_path
        except subprocess.TimeoutExpired:
            raise Exception("Repository cloning timed out after 5 minutes")
        except Exception as e:
            # Cleanup partial clone if it exists
            if os.path.exists(project_path):
                shutil.rmtree(project_path)
            raise Exception(f"Failed to clone repository: {str(e)}")
    else:
        raise Exception("No repository URL configured for this project")


async def update_profiling_status(
    project_id: int,
    status: str,
    progress: int,
    message: str
):
    """Update the in-memory profiling status."""
    profiling_status[project_id] = {
        "status": status,
        "progress": progress,
        "message": message,
        "timestamp": datetime.utcnow().isoformat()
    }


async def run_profiling_task(
    project_id: int,
    project_path: str,
    db: Session
):
    """Background task for running application profiling."""
    try:
        # Get or create profile
        profile = db.query(ApplicationProfile).filter(
            ApplicationProfile.project_id == project_id
        ).first()

        if not profile:
            profile = ApplicationProfile(
                project_id=project_id,
                status=ProfileStatus.PROFILING
            )
            db.add(profile)
            db.commit()

        # Update status
        profile.status = ProfileStatus.PROFILING
        profile.status_message = "Starting application profiling..."
        profile.profiling_progress = 0
        db.commit()

        await update_profiling_status(project_id, "profiling", 0, "Starting application profiling...")

        # Progress callback
        async def progress_callback(progress: int, message: str):
            profile.profiling_progress = progress
            profile.status_message = message
            db.commit()
            await update_profiling_status(project_id, "profiling", progress, message)

        # Run profiling
        profile_data = await profiler.profile_application(project_path, progress_callback)

        # Update profile with results
        profile.status = ProfileStatus.ANALYZING
        profile.status_message = "Analyzing results..."
        profile.languages = profile_data.get("languages")
        profile.frameworks = profile_data.get("frameworks")
        profile.databases = profile_data.get("databases")
        profile.orm_libraries = profile_data.get("orm_libraries")
        profile.entry_points = profile_data.get("entry_points")
        profile.sensitive_data_fields = profile_data.get("sensitive_data_fields")
        profile.auth_mechanisms = profile_data.get("auth_mechanisms")
        profile.dependencies = profile_data.get("dependencies")
        profile.dev_dependencies = profile_data.get("dev_dependencies")
        profile.external_integrations = profile_data.get("external_integrations")
        profile.cloud_services = profile_data.get("cloud_services")
        profile.file_count = profile_data.get("file_count", 0)
        profile.total_lines_of_code = profile_data.get("total_lines_of_code", 0)
        profile.security_score = profile_data.get("security_score")
        profile.risk_level = profile_data.get("risk_level")
        db.commit()

        await update_profiling_status(project_id, "analyzing", 70, "Analyzing results...")

        # Generate rule suggestions
        profile.status = ProfileStatus.GENERATING_SUGGESTIONS
        profile.status_message = "Generating security rule suggestions..."
        db.commit()

        await update_profiling_status(project_id, "generating_suggestions", 80, "Generating security rule suggestions...")

        async def suggestion_progress(progress: int, message: str):
            adjusted_progress = 80 + int(progress * 0.2)  # 80-100%
            await update_profiling_status(project_id, "generating_suggestions", adjusted_progress, message)

        suggestions = await rule_suggester.generate_suggestions(profile_data, suggestion_progress)

        # Save suggestions
        critical_count = 0
        high_count = 0

        for suggestion_data in suggestions:
            severity = suggestion_data.get("severity", "medium")
            if severity == "critical":
                critical_count += 1
            elif severity == "high":
                high_count += 1

            suggested_rule = SuggestedRule(
                application_profile_id=profile.id,
                name=suggestion_data["name"],
                description=suggestion_data.get("description"),
                category=suggestion_data.get("category"),
                severity=SeverityLevel(severity),
                reason=suggestion_data.get("reason"),
                detected_patterns=suggestion_data.get("detected_patterns"),
                framework_context=suggestion_data.get("framework_context"),
                rule_pattern=suggestion_data.get("rule_pattern"),
                rule_type=suggestion_data.get("rule_type", "semgrep"),
                semgrep_rule=suggestion_data.get("semgrep_rule"),
                codeql_rule=suggestion_data.get("codeql_rule"),
                checkmarx_rule=suggestion_data.get("checkmarx_rule"),
                fortify_rule=suggestion_data.get("fortify_rule"),
                cwe_ids=suggestion_data.get("cwe_ids"),
                owasp_categories=suggestion_data.get("owasp_categories"),
                mitre_techniques=suggestion_data.get("mitre_techniques"),
                confidence_score=suggestion_data.get("confidence_score")
            )
            db.add(suggested_rule)

        # Update profile completion
        profile.status = ProfileStatus.COMPLETED
        profile.status_message = "Profiling completed successfully"
        profile.profiling_progress = 100
        profile.total_suggestions = len(suggestions)
        profile.critical_suggestions = critical_count
        profile.high_suggestions = high_count
        profile.last_profiled_at = datetime.utcnow()
        db.commit()

        await update_profiling_status(project_id, "completed", 100, "Profiling completed successfully")

        logger.info(f"Profiling completed for project {project_id}. Generated {len(suggestions)} suggestions.")

    except Exception as e:
        logger.error(f"Profiling failed for project {project_id}: {str(e)}")

        profile = db.query(ApplicationProfile).filter(
            ApplicationProfile.project_id == project_id
        ).first()

        if profile:
            profile.status = ProfileStatus.FAILED
            profile.status_message = f"Profiling failed: {str(e)}"
            db.commit()

        await update_profiling_status(project_id, "failed", 0, f"Profiling failed: {str(e)}")


# API Endpoints
@router.post("/profile/{project_id}", response_model=ProfileResponse)
async def start_profiling(
    project_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Start application profiling for a project.
    This will analyze the codebase and generate security rule suggestions.
    """
    # Verify project exists and user has access
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to access this project")

    # Check if profiling is already in progress
    existing_profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.project_id == project_id
    ).first()

    if existing_profile and existing_profile.status in [ProfileStatus.PROFILING, ProfileStatus.ANALYZING, ProfileStatus.GENERATING_SUGGESTIONS]:
        raise HTTPException(status_code=400, detail="Profiling is already in progress")

    # Ensure repository is cloned
    try:
        project_path = ensure_repository_cloned(project)
        logger.info(f"Repository ready at: {project_path}")
    except Exception as e:
        logger.error(f"Failed to prepare repository for project {project_id}: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Failed to prepare repository: {str(e)}")

    # Create or reset profile
    if existing_profile:
        existing_profile.status = ProfileStatus.PENDING
        existing_profile.profiling_progress = 0
        existing_profile.status_message = "Profiling queued..."
        db.commit()
        profile = existing_profile
    else:
        profile = ApplicationProfile(
            project_id=project_id,
            status=ProfileStatus.PENDING,
            status_message="Profiling queued..."
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)

    # Start background task
    background_tasks.add_task(run_profiling_task, project_id, project_path, db)

    return profile


@router.get("/profile/{project_id}", response_model=ProfileResponse)
async def get_profile(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get the application profile for a project."""
    # Verify project access
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to access this project")

    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.project_id == project_id
    ).first()

    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found. Start profiling first.")

    return profile


@router.get("/profile/{project_id}/status")
async def get_profiling_status(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get real-time profiling status."""
    # Verify project access
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to access this project")

    # Check in-memory status first
    if project_id in profiling_status:
        return profiling_status[project_id]

    # Fall back to database
    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.project_id == project_id
    ).first()

    if profile:
        return {
            "status": profile.status.value if profile.status else "pending",
            "progress": profile.profiling_progress or 0,
            "message": profile.status_message or "",
            "timestamp": profile.updated_at.isoformat() if profile.updated_at else None
        }

    return {
        "status": "not_started",
        "progress": 0,
        "message": "Profiling has not been started",
        "timestamp": None
    }


@router.get("/profile/{project_id}/stream")
async def stream_profiling_status(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Stream real-time profiling status updates using Server-Sent Events (SSE).
    """
    # Verify project access
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to access this project")

    async def event_generator():
        last_status = None
        retry_count = 0
        max_retries = 300  # 5 minutes at 1 second intervals

        while retry_count < max_retries:
            current_status = profiling_status.get(project_id)

            if current_status and current_status != last_status:
                last_status = current_status
                yield f"data: {json.dumps(current_status)}\n\n"

                # Stop streaming if completed or failed
                if current_status.get("status") in ["completed", "failed"]:
                    break

            await asyncio.sleep(1)
            retry_count += 1

        yield f"data: {json.dumps({'status': 'stream_ended'})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


@router.get("/suggestions/{project_id}", response_model=List[SuggestedRuleResponse])
async def get_suggestions(
    project_id: int,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all rule suggestions for a project's profile."""
    # Verify project access
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to access this project")

    # Get profile
    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.project_id == project_id
    ).first()

    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Build query
    query = db.query(SuggestedRule).filter(
        SuggestedRule.application_profile_id == profile.id
    )

    if status:
        query = query.filter(SuggestedRule.status == SuggestionStatus(status))
    if severity:
        query = query.filter(SuggestedRule.severity == SeverityLevel(severity))
    if category:
        query = query.filter(SuggestedRule.category == category)

    suggestions = query.order_by(SuggestedRule.severity, SuggestedRule.confidence_score.desc()).all()

    return suggestions


@router.get("/suggestions/{project_id}/stats", response_model=SuggestionStats)
async def get_suggestion_stats(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get statistics about rule suggestions."""
    # Verify project access
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to access this project")

    # Get profile
    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.project_id == project_id
    ).first()

    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    suggestions = db.query(SuggestedRule).filter(
        SuggestedRule.application_profile_id == profile.id
    ).all()

    stats = {
        "total": len(suggestions),
        "by_severity": {},
        "by_category": {},
        "by_framework": {},
        "average_confidence": 0
    }

    total_confidence = 0
    for suggestion in suggestions:
        # By severity
        sev = suggestion.severity.value if suggestion.severity else "unknown"
        stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1

        # By category
        cat = suggestion.category or "other"
        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

        # By framework
        fw = suggestion.framework_context or "generic"
        stats["by_framework"][fw] = stats["by_framework"].get(fw, 0) + 1

        # Confidence
        if suggestion.confidence_score:
            total_confidence += suggestion.confidence_score

    if suggestions:
        stats["average_confidence"] = total_confidence / len(suggestions)

    return stats


@router.get("/suggestion/{suggestion_id}", response_model=SuggestedRuleResponse)
async def get_suggestion(
    suggestion_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific rule suggestion with full details."""
    suggestion = db.query(SuggestedRule).filter(SuggestedRule.id == suggestion_id).first()

    if not suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found")

    # Verify access through profile -> project
    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.id == suggestion.application_profile_id
    ).first()

    project = db.query(Project).filter(Project.id == profile.project_id).first()

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    return suggestion


@router.put("/suggestion/{suggestion_id}/feedback")
async def update_suggestion_feedback(
    suggestion_id: int,
    feedback: RuleFeedback,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Provide feedback on a suggestion."""
    suggestion = db.query(SuggestedRule).filter(SuggestedRule.id == suggestion_id).first()

    if not suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found")

    # Verify access
    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.id == suggestion.application_profile_id
    ).first()

    project = db.query(Project).filter(Project.id == profile.project_id).first()

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    suggestion.user_feedback = feedback.feedback
    suggestion.feedback_comment = feedback.comment
    suggestion.reviewed_at = datetime.utcnow()
    db.commit()

    return {"message": "Feedback recorded", "suggestion_id": suggestion_id}


@router.put("/suggestion/{suggestion_id}/accept")
async def accept_suggestion(
    suggestion_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Accept a suggestion and mark it for implementation."""
    suggestion = db.query(SuggestedRule).filter(SuggestedRule.id == suggestion_id).first()

    if not suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found")

    # Verify access
    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.id == suggestion.application_profile_id
    ).first()

    project = db.query(Project).filter(Project.id == profile.project_id).first()

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    suggestion.status = SuggestionStatus.ACCEPTED
    suggestion.reviewed_at = datetime.utcnow()
    db.commit()

    return {"message": "Suggestion accepted", "suggestion_id": suggestion_id}


@router.put("/suggestion/{suggestion_id}/dismiss")
async def dismiss_suggestion(
    suggestion_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Dismiss a suggestion."""
    suggestion = db.query(SuggestedRule).filter(SuggestedRule.id == suggestion_id).first()

    if not suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found")

    # Verify access
    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.id == suggestion.application_profile_id
    ).first()

    project = db.query(Project).filter(Project.id == profile.project_id).first()

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    suggestion.status = SuggestionStatus.DISMISSED
    suggestion.reviewed_at = datetime.utcnow()
    db.commit()

    return {"message": "Suggestion dismissed", "suggestion_id": suggestion_id}


@router.get("/suggestion/{suggestion_id}/export/{format}")
async def export_rule(
    suggestion_id: int,
    format: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Export a rule in the specified format (semgrep, codeql, checkmarx, fortify)."""
    suggestion = db.query(SuggestedRule).filter(SuggestedRule.id == suggestion_id).first()

    if not suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found")

    # Verify access
    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.id == suggestion.application_profile_id
    ).first()

    project = db.query(Project).filter(Project.id == profile.project_id).first()

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    format_map = {
        "semgrep": ("semgrep_rule", "yaml", "application/x-yaml"),
        "codeql": ("codeql_rule", "ql", "text/plain"),
        "checkmarx": ("checkmarx_rule", "cxql", "text/plain"),
        "fortify": ("fortify_rule", "xml", "application/xml")
    }

    if format not in format_map:
        raise HTTPException(status_code=400, detail=f"Invalid format. Supported: {list(format_map.keys())}")

    field, ext, content_type = format_map[format]
    content = getattr(suggestion, field)

    if not content:
        raise HTTPException(status_code=404, detail=f"No {format} rule available for this suggestion")

    filename = f"{suggestion.name.replace(' ', '_').lower()}.{ext}"

    return StreamingResponse(
        iter([content]),
        media_type=content_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.delete("/profile/{project_id}")
async def delete_profile(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Delete application profile and all suggestions."""
    # Verify project access
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.project_id == project_id
    ).first()

    if profile:
        db.delete(profile)
        db.commit()

    return {"message": "Profile deleted", "project_id": project_id}


# ============== Custom Rules & Performance Integration ==============

@router.get("/rules/{project_id}")
async def get_project_rules(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get custom rules relevant to a project based on its detected languages and frameworks.
    """
    import sqlite3

    # Verify project access
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Get profile
    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.project_id == project_id
    ).first()

    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found. Run profiling first.")

    # Get detected languages
    detected_languages = list(profile.languages.keys()) if profile.languages else []

    # Map common language names to rule language identifiers
    language_map = {
        "python": ["python", "py"],
        "javascript": ["javascript", "js", "typescript", "ts"],
        "typescript": ["typescript", "ts", "javascript", "js"],
        "php": ["php"],
        "java": ["java"],
        "go": ["go", "golang"],
        "ruby": ["ruby", "rb"],
        "csharp": ["csharp", "cs", "c#"],
        "rust": ["rust", "rs"],
        "sql": ["sql"],
    }

    # Build language filter
    rule_languages = ["*"]  # Always include universal rules
    for lang in detected_languages:
        lang_lower = lang.lower()
        if lang_lower in language_map:
            rule_languages.extend(language_map[lang_lower])
        else:
            rule_languages.append(lang_lower)

    # Query custom rules from SQLite
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    placeholders = ','.join(['?' for _ in rule_languages])
    query = f"""
        SELECT cr.*,
            (SELECT COUNT(*) FROM rule_performance_metrics rpm WHERE rpm.rule_id = cr.id) as feedback_count
        FROM custom_rules cr
        WHERE cr.enabled = 1 AND (cr.language IN ({placeholders}) OR cr.language = '*')
        ORDER BY cr.total_detections DESC, cr.created_at DESC
    """

    cursor.execute(query, rule_languages)
    rules = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return {
        "project_id": project_id,
        "detected_languages": detected_languages,
        "relevant_rules": rules,
        "total_rules": len(rules)
    }


@router.get("/rules/{project_id}/performance")
async def get_project_rule_performance(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get rule performance metrics for rules relevant to a project.
    """
    import sqlite3

    # Verify project access
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Get profile
    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.project_id == project_id
    ).first()

    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found. Run profiling first.")

    # Query from SQLite
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get overall performance stats
    cursor.execute("""
        SELECT
            COUNT(*) as total_rules,
            SUM(enabled) as enabled_rules,
            SUM(total_detections) as total_detections,
            SUM(true_positives) as total_true_positives,
            SUM(false_positives) as total_false_positives,
            AVG(CASE WHEN precision IS NOT NULL THEN precision ELSE NULL END) as avg_precision,
            SUM(CASE WHEN precision < 0.85 AND total_detections > 5 THEN 1 ELSE 0 END) as rules_needing_refinement,
            SUM(CASE WHEN generated_by = 'ai' THEN 1 ELSE 0 END) as ai_generated_rules
        FROM custom_rules
    """)
    overall_stats = dict(cursor.fetchone())

    # Get top performing rules
    cursor.execute("""
        SELECT id, name, severity, language, total_detections, precision, generated_by
        FROM custom_rules
        WHERE total_detections > 0 AND (precision > 0.9 OR precision IS NULL)
        ORDER BY COALESCE(precision, 1.0) DESC, total_detections DESC
        LIMIT 5
    """)
    top_performers = [dict(row) for row in cursor.fetchall()]

    # Get rules needing attention
    cursor.execute("""
        SELECT id, name, severity, language, total_detections, false_positives, precision
        FROM custom_rules
        WHERE total_detections > 5 AND (precision < 0.85 OR false_positives > 3)
        ORDER BY false_positives DESC
        LIMIT 5
    """)
    needs_attention = [dict(row) for row in cursor.fetchall()]

    # Get rules by severity with detection counts
    cursor.execute("""
        SELECT severity, COUNT(*) as count, SUM(total_detections) as detections
        FROM custom_rules
        WHERE enabled = 1
        GROUP BY severity
        ORDER BY CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
        END
    """)
    severity_breakdown = [dict(row) for row in cursor.fetchall()]

    # Get recent rule activity
    cursor.execute("""
        SELECT rel.*, cr.name as rule_name
        FROM rule_enhancement_logs rel
        JOIN custom_rules cr ON rel.rule_id = cr.id
        ORDER BY rel.timestamp DESC
        LIMIT 10
    """)
    recent_activity = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "project_id": project_id,
        "overall_stats": overall_stats,
        "top_performers": top_performers,
        "needs_attention": needs_attention,
        "severity_breakdown": severity_breakdown,
        "recent_activity": recent_activity
    }


@router.post("/suggestion/{suggestion_id}/convert-to-rule")
async def convert_suggestion_to_rule(
    suggestion_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Convert a suggested rule into a custom rule in the rules database.
    """
    import sqlite3

    suggestion = db.query(SuggestedRule).filter(SuggestedRule.id == suggestion_id).first()

    if not suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found")

    # Verify access
    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.id == suggestion.application_profile_id
    ).first()

    project = db.query(Project).filter(Project.id == profile.project_id).first()

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Determine language from framework context
    language = "*"
    if suggestion.framework_context:
        framework_language_map = {
            "fastapi": "python",
            "django": "python",
            "flask": "python",
            "express": "javascript",
            "nestjs": "typescript",
            "spring": "java",
            "react": "javascript",
            "sqlalchemy": "python",
            "prisma": "javascript",
            "typeorm": "typescript",
        }
        fw_lower = suggestion.framework_context.lower()
        for fw, lang in framework_language_map.items():
            if fw in fw_lower:
                language = lang
                break

    # Insert into custom_rules table
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO custom_rules (
                name, pattern, severity, description, language,
                cwe, owasp, remediation, enabled,
                created_by, generated_by, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 'ai', 'high')
        """, (
            suggestion.name,
            suggestion.rule_pattern or "",
            suggestion.severity.value if suggestion.severity else "medium",
            suggestion.description or suggestion.reason,
            language,
            json.dumps(suggestion.cwe_ids) if suggestion.cwe_ids else None,
            json.dumps(suggestion.owasp_categories) if suggestion.owasp_categories else None,
            f"Detected {suggestion.framework_context or 'generic'} pattern. {suggestion.reason or ''}",
            current_user.username
        ))

        rule_id = cursor.lastrowid

        # Log creation
        cursor.execute("""
            INSERT INTO rule_enhancement_logs (rule_id, action, reason, performed_by, ai_generated)
            VALUES (?, 'created', ?, ?, 1)
        """, (rule_id, f"Converted from AI suggestion #{suggestion_id}", current_user.username))

        conn.commit()

        # Update suggestion status
        suggestion.status = SuggestionStatus.IMPLEMENTED
        suggestion.created_rule_id = rule_id
        suggestion.reviewed_at = datetime.utcnow()
        db.commit()

        # Fetch created rule
        cursor.execute("SELECT * FROM custom_rules WHERE id = ?", (rule_id,))
        created_rule = dict(cursor.fetchone())
        conn.close()

        return {
            "message": "Suggestion converted to custom rule",
            "suggestion_id": suggestion_id,
            "rule_id": rule_id,
            "rule": created_rule
        }

    except sqlite3.IntegrityError as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Rule already exists: {str(e)}")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rules/{project_id}/summary")
async def get_project_rules_summary(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a summary of rules and suggestions for a project.
    """
    import sqlite3

    # Verify project access
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Get profile
    profile = db.query(ApplicationProfile).filter(
        ApplicationProfile.project_id == project_id
    ).first()

    # Get suggestions stats
    suggestions_stats = {
        "total": 0,
        "pending": 0,
        "accepted": 0,
        "implemented": 0,
        "dismissed": 0
    }

    if profile:
        suggestions = db.query(SuggestedRule).filter(
            SuggestedRule.application_profile_id == profile.id
        ).all()

        suggestions_stats["total"] = len(suggestions)
        for s in suggestions:
            status = s.status.value if s.status else "pending"
            if status in suggestions_stats:
                suggestions_stats[status] += 1

    # Get custom rules stats
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            COUNT(*) as total_rules,
            SUM(enabled) as enabled_rules,
            SUM(total_detections) as total_detections,
            AVG(precision) as avg_precision,
            SUM(CASE WHEN generated_by = 'ai' THEN 1 ELSE 0 END) as ai_rules
        FROM custom_rules
    """)
    rules_stats = dict(cursor.fetchone())
    conn.close()

    return {
        "project_id": project_id,
        "has_profile": profile is not None,
        "suggestions": suggestions_stats,
        "custom_rules": rules_stats,
        "frameworks_detected": len(profile.frameworks) if profile and profile.frameworks else 0,
        "languages_detected": len(profile.languages) if profile and profile.languages else 0
    }
