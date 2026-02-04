"""
SecureReq API Router
Handles user stories, security analysis, and compliance mapping
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional, Union
from pydantic import BaseModel
from datetime import datetime

from models import get_db
from models.models import (
    User, Project, UserStory, SecurityAnalysis, ComplianceMapping,
    CustomStandard, StorySource, PromptFeedback, FeedbackType, FeedbackRating
)
from core.security import get_current_active_user
from services.security_requirements_analyzer import SecurityRequirementsAnalyzer

router = APIRouter(prefix="/api/securereq", tags=["SecureReq"])


# ==================== Pydantic Models ====================

class StoryCreate(BaseModel):
    title: str
    description: str
    acceptance_criteria: Optional[str] = None
    source: Optional[str] = "manual"
    external_id: Optional[str] = None
    external_url: Optional[str] = None


class StoryUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    acceptance_criteria: Optional[str] = None


class StoryResponse(BaseModel):
    id: int
    project_id: int
    title: str
    description: str
    acceptance_criteria: Optional[str]
    source: str
    external_id: Optional[str]
    external_url: Optional[str]
    is_analyzed: bool
    risk_score: int
    threat_count: int
    requirement_count: int
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class AnalysisResponse(BaseModel):
    id: int
    user_story_id: int
    version: int
    abuse_cases: List[dict]
    stride_threats: Union[dict, List[dict]]  # Can be dict (by category) or list (flat)
    security_requirements: List[dict]
    risk_score: int
    risk_factors: List[dict]
    ai_model_used: Optional[str]
    analysis_duration_ms: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True


class ComplianceMappingResponse(BaseModel):
    id: int
    requirement_id: str
    requirement_text: str
    standard_name: str
    control_id: str
    control_title: str
    relevance_score: float
    mapping_rationale: Optional[str]

    class Config:
        from_attributes = True


class ProjectStorySummary(BaseModel):
    project_id: int
    project_name: str
    total_stories: int
    analyzed_stories: int
    total_threats: int
    total_requirements: int
    average_risk_score: float
    high_risk_stories: int


# ==================== Story Endpoints ====================

@router.get("/projects/{project_id}/stories", response_model=List[StoryResponse])
async def list_stories(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all user stories for a project"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    stories = db.query(UserStory).filter(
        UserStory.project_id == project_id
    ).order_by(UserStory.created_at.desc()).all()

    return stories


@router.post("/projects/{project_id}/stories", response_model=StoryResponse)
async def create_story(
    project_id: int,
    story_data: StoryCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new user story"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Map source string to enum
    source_map = {
        "manual": StorySource.MANUAL,
        "jira": StorySource.JIRA,
        "ado": StorySource.ADO,
        "github": StorySource.GITHUB
    }
    source_enum = source_map.get(story_data.source.lower(), StorySource.MANUAL)

    story = UserStory(
        project_id=project_id,
        title=story_data.title,
        description=story_data.description,
        acceptance_criteria=story_data.acceptance_criteria,
        source=source_enum,
        external_id=story_data.external_id,
        external_url=story_data.external_url,
        created_by=current_user.id
    )

    db.add(story)
    db.commit()
    db.refresh(story)

    return story


@router.get("/stories/{story_id}", response_model=StoryResponse)
async def get_story(
    story_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get a specific user story"""
    story = db.query(UserStory).join(Project).filter(
        UserStory.id == story_id,
        Project.owner_id == current_user.id
    ).first()

    if not story:
        raise HTTPException(status_code=404, detail="Story not found")

    return story


@router.put("/stories/{story_id}", response_model=StoryResponse)
async def update_story(
    story_id: int,
    story_data: StoryUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update a user story"""
    story = db.query(UserStory).join(Project).filter(
        UserStory.id == story_id,
        Project.owner_id == current_user.id
    ).first()

    if not story:
        raise HTTPException(status_code=404, detail="Story not found")

    if story_data.title is not None:
        story.title = story_data.title
    if story_data.description is not None:
        story.description = story_data.description
    if story_data.acceptance_criteria is not None:
        story.acceptance_criteria = story_data.acceptance_criteria

    db.commit()
    db.refresh(story)

    return story


@router.delete("/stories/{story_id}")
async def delete_story(
    story_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete a user story"""
    story = db.query(UserStory).join(Project).filter(
        UserStory.id == story_id,
        Project.owner_id == current_user.id
    ).first()

    if not story:
        raise HTTPException(status_code=404, detail="Story not found")

    db.delete(story)
    db.commit()

    return {"message": "Story deleted successfully"}


# ==================== Analysis Endpoints ====================

def create_feedback_fetcher(db: Session):
    """Create a feedback fetcher function for the analyzer.
    Returns a callable that fetches feedback examples from the database."""
    def fetch_feedback():
        """Fetch feedback examples grouped by type and rating."""
        result = {
            "abuse_case_positive": [],
            "abuse_case_negative": [],
            "security_requirement_positive": [],
            "security_requirement_negative": []
        }

        # Fetch recent positive abuse case examples (limit 5)
        positive_abuse = db.query(PromptFeedback).filter(
            PromptFeedback.feedback_type == FeedbackType.ABUSE_CASE,
            PromptFeedback.rating == FeedbackRating.POSITIVE
        ).order_by(PromptFeedback.created_at.desc()).limit(5).all()
        result["abuse_case_positive"] = [{"content": f.content, "comment": f.comment} for f in positive_abuse]

        # Fetch recent negative abuse case examples (limit 3)
        negative_abuse = db.query(PromptFeedback).filter(
            PromptFeedback.feedback_type == FeedbackType.ABUSE_CASE,
            PromptFeedback.rating == FeedbackRating.NEGATIVE
        ).order_by(PromptFeedback.created_at.desc()).limit(3).all()
        result["abuse_case_negative"] = [{"content": f.content, "comment": f.comment} for f in negative_abuse]

        # Fetch recent positive security requirement examples (limit 5)
        positive_req = db.query(PromptFeedback).filter(
            PromptFeedback.feedback_type == FeedbackType.SECURITY_REQUIREMENT,
            PromptFeedback.rating == FeedbackRating.POSITIVE
        ).order_by(PromptFeedback.created_at.desc()).limit(5).all()
        result["security_requirement_positive"] = [{"content": f.content, "comment": f.comment} for f in positive_req]

        # Fetch recent negative security requirement examples (limit 3)
        negative_req = db.query(PromptFeedback).filter(
            PromptFeedback.feedback_type == FeedbackType.SECURITY_REQUIREMENT,
            PromptFeedback.rating == FeedbackRating.NEGATIVE
        ).order_by(PromptFeedback.created_at.desc()).limit(3).all()
        result["security_requirement_negative"] = [{"content": f.content, "comment": f.comment} for f in negative_req]

        total = len(result["abuse_case_positive"]) + len(result["abuse_case_negative"]) + \
                len(result["security_requirement_positive"]) + len(result["security_requirement_negative"])

        if total > 0:
            print(f"[FEEDBACK] Fetched {total} feedback examples for in-context learning")

        return result

    return fetch_feedback


@router.post("/stories/{story_id}/analyze", response_model=AnalysisResponse)
async def analyze_story(
    story_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Run security analysis on a user story"""
    print(f"[ANALYZE] Starting analysis for story_id={story_id}, user={current_user.username}")
    story = db.query(UserStory).join(Project).filter(
        UserStory.id == story_id,
        Project.owner_id == current_user.id
    ).first()

    if not story:
        raise HTTPException(status_code=404, detail="Story not found")

    # Get current version number
    latest_analysis = db.query(SecurityAnalysis).filter(
        SecurityAnalysis.user_story_id == story_id
    ).order_by(SecurityAnalysis.version.desc()).first()

    new_version = (latest_analysis.version + 1) if latest_analysis else 1

    # Initialize analyzer with user's AI settings and custom prompts if enabled
    # Default to Anthropic (Claude) for better security analysis quality
    print(f"[ANALYZE] Initializing analyzer with provider={current_user.ai_provider or 'anthropic'}")
    print(f"[ANALYZE] Custom prompts enabled: {current_user.use_custom_prompts or False}")

    # Pass custom prompts if user has enabled them
    custom_abuse_prompt = current_user.custom_abuse_case_prompt if current_user.use_custom_prompts else None
    custom_req_prompt = current_user.custom_security_req_prompt if current_user.use_custom_prompts else None

    # Create feedback fetcher for in-context learning
    feedback_fetcher = create_feedback_fetcher(db)

    analyzer = SecurityRequirementsAnalyzer(
        api_key=current_user.ai_api_key,
        provider=current_user.ai_provider or "anthropic",  # Default to Claude
        custom_abuse_case_prompt=custom_abuse_prompt,
        custom_security_req_prompt=custom_req_prompt,
        feedback_fetcher=feedback_fetcher
    )

    # Run analysis
    print(f"[ANALYZE] Running analysis for story: {story.title}")
    result = analyzer.analyze_story({
        "title": story.title,
        "description": story.description,
        "acceptance_criteria": story.acceptance_criteria
    })
    print(f"[ANALYZE] Analysis complete. Got {len(result.get('abuse_cases', []))} abuse cases, {len(result.get('security_requirements', []))} requirements")

    # Count threats - handle both dict and list formats
    stride_threats = result.get("stride_threats", {})
    if isinstance(stride_threats, dict):
        threat_count = sum(len(threats) for threats in stride_threats.values())
    elif isinstance(stride_threats, list):
        threat_count = len(stride_threats)
    else:
        threat_count = 0

    # Create analysis record
    analysis = SecurityAnalysis(
        user_story_id=story_id,
        version=new_version,
        abuse_cases=result.get("abuse_cases", []),
        stride_threats=result.get("stride_threats", {}),
        security_requirements=result.get("security_requirements", []),
        risk_score=result.get("risk_score", 0),
        risk_factors=result.get("risk_factors", []),
        ai_model_used=result.get("ai_model_used"),
        analysis_duration_ms=result.get("analysis_duration_ms")
    )

    db.add(analysis)

    # Update story metrics
    story.is_analyzed = True
    story.risk_score = result.get("risk_score", 0)
    story.threat_count = threat_count
    story.requirement_count = len(result.get("security_requirements", []))

    db.commit()
    db.refresh(analysis)

    # Generate compliance mappings
    if result.get("security_requirements"):
        mappings = analyzer.map_to_compliance(result["security_requirements"])
        for mapping in mappings:
            compliance_mapping = ComplianceMapping(
                analysis_id=analysis.id,
                requirement_id=mapping["requirement_id"],
                requirement_text=mapping["requirement_text"],
                standard_name=mapping["standard_name"],
                control_id=mapping["control_id"],
                control_title=mapping["control_title"],
                relevance_score=mapping["relevance_score"],
                mapping_rationale=mapping.get("mapping_rationale")
            )
            db.add(compliance_mapping)
        db.commit()

    return analysis


@router.get("/stories/{story_id}/analyses", response_model=List[AnalysisResponse])
async def list_story_analyses(
    story_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all analyses for a story"""
    story = db.query(UserStory).join(Project).filter(
        UserStory.id == story_id,
        Project.owner_id == current_user.id
    ).first()

    if not story:
        raise HTTPException(status_code=404, detail="Story not found")

    analyses = db.query(SecurityAnalysis).filter(
        SecurityAnalysis.user_story_id == story_id
    ).order_by(SecurityAnalysis.version.desc()).all()

    return analyses


@router.get("/analyses/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get a specific analysis"""
    analysis = db.query(SecurityAnalysis).join(UserStory).join(Project).filter(
        SecurityAnalysis.id == analysis_id,
        Project.owner_id == current_user.id
    ).first()

    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    return analysis


# ==================== Compliance Endpoints ====================

@router.get("/analyses/{analysis_id}/compliance", response_model=List[ComplianceMappingResponse])
async def get_compliance_mappings(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get compliance mappings for an analysis"""
    analysis = db.query(SecurityAnalysis).join(UserStory).join(Project).filter(
        SecurityAnalysis.id == analysis_id,
        Project.owner_id == current_user.id
    ).first()

    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    mappings = db.query(ComplianceMapping).filter(
        ComplianceMapping.analysis_id == analysis_id
    ).all()

    return mappings


@router.get("/analyses/{analysis_id}/compliance/summary")
async def get_compliance_summary(
    analysis_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get compliance summary for an analysis"""
    analysis = db.query(SecurityAnalysis).join(UserStory).join(Project).filter(
        SecurityAnalysis.id == analysis_id,
        Project.owner_id == current_user.id
    ).first()

    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    mappings = db.query(ComplianceMapping).filter(
        ComplianceMapping.analysis_id == analysis_id
    ).all()

    # Group by standard
    summary = {}
    for mapping in mappings:
        if mapping.standard_name not in summary:
            summary[mapping.standard_name] = {
                "total_mappings": 0,
                "controls_covered": set(),
                "average_relevance": 0,
                "mappings": []
            }
        summary[mapping.standard_name]["total_mappings"] += 1
        summary[mapping.standard_name]["controls_covered"].add(mapping.control_id)
        summary[mapping.standard_name]["mappings"].append({
            "requirement_id": mapping.requirement_id,
            "control_id": mapping.control_id,
            "relevance_score": mapping.relevance_score
        })

    # Calculate averages and convert sets to counts
    for standard in summary:
        mappings_list = summary[standard]["mappings"]
        summary[standard]["average_relevance"] = sum(m["relevance_score"] for m in mappings_list) / len(mappings_list)
        summary[standard]["controls_covered"] = len(summary[standard]["controls_covered"])

    return summary


# ==================== Project Summary Endpoints ====================

@router.get("/projects/{project_id}/summary", response_model=ProjectStorySummary)
async def get_project_story_summary(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get summary of security requirements for a project"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    stories = db.query(UserStory).filter(UserStory.project_id == project_id).all()

    total_stories = len(stories)
    analyzed_stories = len([s for s in stories if s.is_analyzed])
    total_threats = sum(s.threat_count for s in stories)
    total_requirements = sum(s.requirement_count for s in stories)
    avg_risk = sum(s.risk_score for s in stories) / total_stories if total_stories > 0 else 0
    high_risk = len([s for s in stories if s.risk_score >= 70])

    return ProjectStorySummary(
        project_id=project_id,
        project_name=project.name,
        total_stories=total_stories,
        analyzed_stories=analyzed_stories,
        total_threats=total_threats,
        total_requirements=total_requirements,
        average_risk_score=round(avg_risk, 1),
        high_risk_stories=high_risk
    )


@router.post("/projects/{project_id}/analyze-all")
async def analyze_all_stories(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Analyze all unanalyzed stories in a project"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Get unanalyzed stories
    stories = db.query(UserStory).filter(
        UserStory.project_id == project_id,
        UserStory.is_analyzed == False
    ).all()

    if not stories:
        return {"message": "No unanalyzed stories found", "analyzed_count": 0}

    analyzer = SecurityRequirementsAnalyzer(
        api_key=current_user.ai_api_key,
        provider=current_user.ai_provider or "openai"
    )

    analyzed_count = 0
    for story in stories:
        try:
            result = analyzer.analyze_story({
                "title": story.title,
                "description": story.description,
                "acceptance_criteria": story.acceptance_criteria
            })

            threat_count = sum(
                len(threats) for threats in result.get("stride_threats", {}).values()
            )

            analysis = SecurityAnalysis(
                user_story_id=story.id,
                version=1,
                abuse_cases=result.get("abuse_cases", []),
                stride_threats=result.get("stride_threats", {}),
                security_requirements=result.get("security_requirements", []),
                risk_score=result.get("risk_score", 0),
                risk_factors=result.get("risk_factors", []),
                ai_model_used=result.get("ai_model_used"),
                analysis_duration_ms=result.get("analysis_duration_ms")
            )
            db.add(analysis)

            story.is_analyzed = True
            story.risk_score = result.get("risk_score", 0)
            story.threat_count = threat_count
            story.requirement_count = len(result.get("security_requirements", []))

            analyzed_count += 1

        except Exception as e:
            print(f"Error analyzing story {story.id}: {e}")
            continue

    db.commit()

    return {
        "message": f"Analyzed {analyzed_count} stories",
        "analyzed_count": analyzed_count,
        "total_stories": len(stories)
    }


# ==================== Integration Sync/Publish Endpoints ====================

from models.models import IntegrationSettings, ProjectIntegration, IntegrationType
from services.jira_client import JiraClient
from services.ado_client import ADOClient
from services.snow_client import SNOWClient


class SyncRequest(BaseModel):
    external_project_id: str
    issue_types: Optional[List[str]] = None
    max_results: int = 100


class PublishRequest(BaseModel):
    story_id: int


@router.post("/projects/{project_id}/sync/jira")
async def sync_stories_from_jira(
    project_id: int,
    sync_data: SyncRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Sync user stories from Jira project."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Get Jira settings
    jira_settings = db.query(IntegrationSettings).filter(
        IntegrationSettings.user_id == current_user.id,
        IntegrationSettings.integration_type == IntegrationType.JIRA
    ).first()

    if not jira_settings:
        raise HTTPException(status_code=400, detail="Jira not configured. Go to Settings to configure.")

    client = JiraClient(
        base_url=jira_settings.base_url,
        email=jira_settings.username,
        api_token=jira_settings.api_token
    )

    try:
        # Fetch issues from Jira
        issues = await client.get_project_issues(
            project_id=sync_data.external_project_id,
            issue_types=sync_data.issue_types or ["Story", "User Story", "Task"],
            max_results=sync_data.max_results
        )

        synced_count = 0
        skipped_count = 0

        for issue in issues:
            issue_key = issue.get("key")
            fields = issue.get("fields", {})

            # Check if story already exists
            existing = db.query(UserStory).filter(
                UserStory.project_id == project_id,
                UserStory.external_id == issue_key
            ).first()

            if existing:
                # Update existing story
                existing.title = fields.get("summary", "")
                existing.description = JiraClient.extract_description_text(fields.get("description"))
                skipped_count += 1
            else:
                # Create new story
                story = UserStory(
                    project_id=project_id,
                    title=fields.get("summary", "No title"),
                    description=JiraClient.extract_description_text(fields.get("description")) or "No description",
                    source=StorySource.JIRA,
                    external_id=issue_key,
                    external_url=f"{jira_settings.base_url}/browse/{issue_key}",
                    created_by=current_user.id
                )
                db.add(story)
                synced_count += 1

        db.commit()

        return {
            "success": True,
            "message": f"Synced {synced_count} new stories, updated {skipped_count} existing",
            "synced_count": synced_count,
            "updated_count": skipped_count,
            "total_fetched": len(issues)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Jira sync failed: {str(e)}")


@router.post("/projects/{project_id}/sync/ado")
async def sync_stories_from_ado(
    project_id: int,
    sync_data: SyncRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Sync user stories from Azure DevOps project."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Get ADO settings
    ado_settings = db.query(IntegrationSettings).filter(
        IntegrationSettings.user_id == current_user.id,
        IntegrationSettings.integration_type == IntegrationType.ADO
    ).first()

    if not ado_settings:
        raise HTTPException(status_code=400, detail="Azure DevOps not configured. Go to Settings to configure.")

    client = ADOClient(org_url=ado_settings.base_url, pat=ado_settings.api_token)

    try:
        work_items = await client.get_work_items(
            project=sync_data.external_project_id,
            work_item_types=sync_data.issue_types or ["User Story", "Product Backlog Item"],
            max_results=sync_data.max_results
        )

        synced_count = 0
        skipped_count = 0

        for wi in work_items:
            wi_id = str(wi.get("id"))
            fields = wi.get("fields", {})

            existing = db.query(UserStory).filter(
                UserStory.project_id == project_id,
                UserStory.external_id == wi_id
            ).first()

            if existing:
                existing.title = fields.get("System.Title", "")
                existing.description = ADOClient.extract_description_text(fields.get("System.Description"))
                skipped_count += 1
            else:
                story = UserStory(
                    project_id=project_id,
                    title=fields.get("System.Title", "No title"),
                    description=ADOClient.extract_description_text(fields.get("System.Description")) or "No description",
                    source=StorySource.ADO,
                    external_id=wi_id,
                    external_url=wi.get("_links", {}).get("html", {}).get("href"),
                    created_by=current_user.id
                )
                db.add(story)
                synced_count += 1

        db.commit()

        return {
            "success": True,
            "message": f"Synced {synced_count} new stories, updated {skipped_count} existing",
            "synced_count": synced_count,
            "updated_count": skipped_count,
            "total_fetched": len(work_items)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ADO sync failed: {str(e)}")


@router.post("/projects/{project_id}/sync/snow")
async def sync_stories_from_snow(
    project_id: int,
    sync_data: SyncRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Sync user stories from ServiceNow."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    snow_settings = db.query(IntegrationSettings).filter(
        IntegrationSettings.user_id == current_user.id,
        IntegrationSettings.integration_type == IntegrationType.SNOW
    ).first()

    if not snow_settings:
        raise HTTPException(status_code=400, detail="ServiceNow not configured. Go to Settings to configure.")

    client = SNOWClient(
        instance_url=snow_settings.base_url,
        username=snow_settings.username,
        password=snow_settings.api_token
    )

    try:
        # Use rm_story table by default, or specified table
        table = sync_data.issue_types[0] if sync_data.issue_types else "rm_story"
        records = await client.get_stories(
            table=table,
            product=sync_data.external_project_id,
            max_results=sync_data.max_results
        )

        synced_count = 0
        skipped_count = 0

        for record in records:
            sys_id = record.get("sys_id")

            existing = db.query(UserStory).filter(
                UserStory.project_id == project_id,
                UserStory.external_id == sys_id
            ).first()

            if existing:
                existing.title = record.get("short_description", "")
                existing.description = record.get("description", "") or record.get("short_description", "")
                skipped_count += 1
            else:
                story = UserStory(
                    project_id=project_id,
                    title=record.get("short_description", "No title"),
                    description=record.get("description", "") or record.get("short_description", "No description"),
                    source=StorySource.SNOW,
                    external_id=sys_id,
                    external_url=f"{snow_settings.base_url}/{table}.do?sys_id={sys_id}",
                    created_by=current_user.id
                )
                db.add(story)
                synced_count += 1

        db.commit()

        return {
            "success": True,
            "message": f"Synced {synced_count} new stories, updated {skipped_count} existing",
            "synced_count": synced_count,
            "updated_count": skipped_count,
            "total_fetched": len(records)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ServiceNow sync failed: {str(e)}")


@router.post("/stories/{story_id}/publish")
async def publish_analysis_to_external(
    story_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Publish analysis results back to the external system (Jira/ADO/SNOW)."""
    story = db.query(UserStory).join(Project).filter(
        UserStory.id == story_id,
        Project.owner_id == current_user.id
    ).first()

    if not story:
        raise HTTPException(status_code=404, detail="Story not found")

    if not story.is_analyzed:
        raise HTTPException(status_code=400, detail="Story has not been analyzed yet")

    if story.source == StorySource.MANUAL:
        raise HTTPException(status_code=400, detail="Cannot publish manual stories to external system")

    # Get latest analysis
    analysis = db.query(SecurityAnalysis).filter(
        SecurityAnalysis.user_story_id == story_id
    ).order_by(SecurityAnalysis.version.desc()).first()

    if not analysis:
        raise HTTPException(status_code=400, detail="No analysis found for this story")

    analysis_data = {
        "abuse_cases": analysis.abuse_cases or [],
        "security_requirements": analysis.security_requirements or [],
        "risk_score": analysis.risk_score,
        "stride_threats": analysis.stride_threats or {}
    }

    try:
        if story.source == StorySource.JIRA:
            settings = db.query(IntegrationSettings).filter(
                IntegrationSettings.user_id == current_user.id,
                IntegrationSettings.integration_type == IntegrationType.JIRA
            ).first()

            if not settings:
                raise HTTPException(status_code=400, detail="Jira not configured")

            client = JiraClient(
                base_url=settings.base_url,
                email=settings.username,
                api_token=settings.api_token
            )

            result = await client.publish_analysis_to_issue(
                issue_key=story.external_id,
                analysis=analysis_data,
                abuse_cases_field=settings.abuse_cases_field,
                security_req_field=settings.security_req_field
            )

        elif story.source == StorySource.ADO:
            settings = db.query(IntegrationSettings).filter(
                IntegrationSettings.user_id == current_user.id,
                IntegrationSettings.integration_type == IntegrationType.ADO
            ).first()

            if not settings:
                raise HTTPException(status_code=400, detail="Azure DevOps not configured")

            client = ADOClient(org_url=settings.base_url, pat=settings.api_token)

            result = await client.publish_analysis_to_work_item(
                work_item_id=int(story.external_id),
                analysis=analysis_data,
                abuse_cases_field=settings.abuse_cases_field,
                security_req_field=settings.security_req_field
            )

        elif story.source == StorySource.SNOW:
            settings = db.query(IntegrationSettings).filter(
                IntegrationSettings.user_id == current_user.id,
                IntegrationSettings.integration_type == IntegrationType.SNOW
            ).first()

            if not settings:
                raise HTTPException(status_code=400, detail="ServiceNow not configured")

            client = SNOWClient(
                instance_url=settings.base_url,
                username=settings.username,
                password=settings.api_token
            )

            result = await client.publish_analysis_to_record(
                table="rm_story",  # Could be made configurable
                sys_id=story.external_id,
                analysis=analysis_data,
                abuse_cases_field=settings.abuse_cases_field,
                security_req_field=settings.security_req_field
            )

        else:
            raise HTTPException(status_code=400, detail=f"Unsupported source: {story.source}")

        return {
            "success": True,
            "message": f"Analysis published to {story.source.value.upper()} issue {story.external_id}",
            "external_id": story.external_id
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to publish: {str(e)}")


# ==================== Feedback Endpoints for In-Context Learning ====================

class FeedbackCreate(BaseModel):
    feedback_type: str  # "abuse_case" or "security_requirement"
    rating: str  # "positive" or "negative"
    content: dict  # The actual abuse case or requirement object
    story_title: Optional[str] = None
    story_description: Optional[str] = None
    comment: Optional[str] = None


class FeedbackResponse(BaseModel):
    id: int
    feedback_type: str
    rating: str
    content: dict
    story_title: Optional[str]
    comment: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


@router.post("/feedback", response_model=FeedbackResponse)
async def submit_feedback(
    feedback_data: FeedbackCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Submit feedback (thumbs up/down) for an abuse case or security requirement.
    This feedback is used to improve AI prompts through in-context learning."""

    # Validate feedback_type
    try:
        feedback_type_enum = FeedbackType(feedback_data.feedback_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid feedback_type. Must be 'abuse_case' or 'security_requirement'"
        )

    # Validate rating
    try:
        rating_enum = FeedbackRating(feedback_data.rating)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid rating. Must be 'positive' or 'negative'"
        )

    feedback = PromptFeedback(
        feedback_type=feedback_type_enum,
        rating=rating_enum,
        content=feedback_data.content,
        story_title=feedback_data.story_title,
        story_description=feedback_data.story_description,
        comment=feedback_data.comment,
        user_id=current_user.id
    )

    db.add(feedback)
    db.commit()
    db.refresh(feedback)

    return FeedbackResponse(
        id=feedback.id,
        feedback_type=feedback.feedback_type.value,
        rating=feedback.rating.value,
        content=feedback.content,
        story_title=feedback.story_title,
        comment=feedback.comment,
        created_at=feedback.created_at
    )


@router.get("/feedback", response_model=List[FeedbackResponse])
async def get_feedback(
    feedback_type: Optional[str] = None,
    rating: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get feedback entries for in-context learning.
    Filter by feedback_type (abuse_case/security_requirement) and rating (positive/negative)."""

    query = db.query(PromptFeedback)

    if feedback_type:
        try:
            ft_enum = FeedbackType(feedback_type)
            query = query.filter(PromptFeedback.feedback_type == ft_enum)
        except ValueError:
            pass

    if rating:
        try:
            r_enum = FeedbackRating(rating)
            query = query.filter(PromptFeedback.rating == r_enum)
        except ValueError:
            pass

    feedback_list = query.order_by(PromptFeedback.created_at.desc()).limit(limit).all()

    return [
        FeedbackResponse(
            id=f.id,
            feedback_type=f.feedback_type.value,
            rating=f.rating.value,
            content=f.content,
            story_title=f.story_title,
            comment=f.comment,
            created_at=f.created_at
        )
        for f in feedback_list
    ]


@router.delete("/feedback/{feedback_id}")
async def delete_feedback(
    feedback_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete a feedback entry."""
    feedback = db.query(PromptFeedback).filter(
        PromptFeedback.id == feedback_id,
        PromptFeedback.user_id == current_user.id
    ).first()

    if not feedback:
        raise HTTPException(status_code=404, detail="Feedback not found")

    db.delete(feedback)
    db.commit()

    return {"message": "Feedback deleted successfully"}


@router.get("/feedback/stats")
async def get_feedback_stats(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get feedback statistics for monitoring prompt improvement."""

    # Count by type and rating
    stats = {}

    for ft in FeedbackType:
        for r in FeedbackRating:
            count = db.query(PromptFeedback).filter(
                PromptFeedback.feedback_type == ft,
                PromptFeedback.rating == r
            ).count()
            key = f"{ft.value}_{r.value}"
            stats[key] = count

    total = db.query(PromptFeedback).count()

    return {
        "total_feedback": total,
        "abuse_case_positive": stats.get("abuse_case_positive", 0),
        "abuse_case_negative": stats.get("abuse_case_negative", 0),
        "security_requirement_positive": stats.get("security_requirement_positive", 0),
        "security_requirement_negative": stats.get("security_requirement_negative", 0)
    }
