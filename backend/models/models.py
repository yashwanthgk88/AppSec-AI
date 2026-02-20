from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float, JSON, Enum, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from models.database import Base
import enum

class ScanType(str, enum.Enum):
    SAST = "sast"
    SCA = "sca"
    SECRET = "secret"
    THREAT_MODEL = "threat_model"

class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    preferred_language = Column(String(10), default="en")

    # AI Provider Configuration
    ai_provider = Column(String(50), default="anthropic")  # anthropic, openai, azure, google, ollama
    ai_api_key = Column(Text)  # Encrypted API key
    ai_model = Column(String(100))  # Model name (e.g., claude-3-5-sonnet, gpt-4, etc.)
    ai_base_url = Column(String(500))  # For Azure or custom endpoints
    ai_api_version = Column(String(50))  # For Azure

    # Custom SecureReq Prompts
    custom_abuse_case_prompt = Column(Text)  # Custom instructions for abuse case generation
    custom_security_req_prompt = Column(Text)  # Custom instructions for security requirements
    use_custom_prompts = Column(Boolean, default=False)  # Toggle to enable custom prompts

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    projects = relationship("Project", back_populates="owner")
    chat_messages = relationship("ChatMessage", back_populates="user")

class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    architecture_doc = Column(Text)
    architecture_diagram = Column(Text)  # Base64 encoded image data
    diagram_media_type = Column(String(50))  # image/png, image/jpeg, etc.
    repository_url = Column(String(500))
    technology_stack = Column(JSON)  # ["Python", "React", "PostgreSQL"]
    compliance_targets = Column(JSON)  # ["OWASP Top 10", "SANS CWE-25"]
    risk_score = Column(Float, default=0.0)
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    owner = relationship("User", back_populates="projects")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    threat_models = relationship("ThreatModel", back_populates="project", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    scan_type = Column(Enum(ScanType), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    scan_config = Column(JSON)
    error_message = Column(Text)

    # Relationships
    project = relationship("Project", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    rule_id = Column(Integer, nullable=True)  # Link to custom_rules table for performance tracking
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(Enum(SeverityLevel), nullable=False)
    cwe_id = Column(String(20))  # CWE-79, CWE-89, etc.
    owasp_category = Column(String(100))  # A03:2021 - Injection
    cvss_score = Column(Float)
    file_path = Column(String(1000))
    line_number = Column(Integer)
    code_snippet = Column(Text)
    remediation = Column(Text)
    remediation_code = Column(Text)
    stride_category = Column(String(50))  # Spoofing, Tampering, etc.
    mitre_attack_id = Column(String(20))  # T1190, T1059, etc.
    mitre_attack_name = Column(String(200))
    is_resolved = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True))

    # AI-generated impact fields
    business_impact = Column(Text)
    technical_impact = Column(Text)
    recommendations = Column(Text)
    impact_generated_by = Column(String(50))  # 'ai', 'ai_cached', 'template', 'fallback'

    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")

class ThreatModel(Base):
    __tablename__ = "threat_models"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    name = Column(String(255), nullable=False)
    dfd_level = Column(Integer, default=0)  # 0 or 1
    dfd_data = Column(JSON)  # DFD diagram structure
    stride_analysis = Column(JSON)  # STRIDE threats per component
    mitre_mapping = Column(JSON)  # MITRE ATT&CK techniques
    trust_boundaries = Column(JSON)
    data_flows = Column(JSON)
    assets = Column(JSON)
    attack_paths = Column(JSON)  # Attack path analysis
    threat_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Enhanced threat modeling fields
    fair_risk_analysis = Column(JSON)  # FAIR risk quantification data
    attack_trees = Column(JSON)  # Attack tree structures
    kill_chain_analysis = Column(JSON)  # Cyber Kill Chain mapping
    eraser_diagrams = Column(JSON)  # Eraser AI professional diagram URLs

    # Incremental threat modeling fields
    architecture_version_id = Column(Integer, ForeignKey("architecture_versions.id"), nullable=True)
    is_incremental = Column(Boolean, default=False)  # Whether this was generated incrementally

    # Relationships
    project = relationship("Project", back_populates="threat_models")
    architecture_version = relationship("ArchitectureVersion", back_populates="threat_models")


class ThreatStatus(str, enum.Enum):
    NEW = "new"
    EXISTING = "existing"
    MODIFIED = "modified"
    RESOLVED = "resolved"


class ArchitectureVersion(Base):
    """Stores versioned snapshots of project architecture for change tracking"""
    __tablename__ = "architecture_versions"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    version_number = Column(Integer, nullable=False)  # Auto-increment per project
    architecture_hash = Column(String(64), nullable=False)  # SHA256 of architecture JSON
    architecture_snapshot = Column(JSON, nullable=False)  # Full architecture at this version
    change_summary = Column(JSON)  # {added_components: [], removed_components: [], modified_flows: [], etc.}
    change_description = Column(Text)  # Human-readable summary of changes
    impact_score = Column(Float, default=0.0)  # 0-1 indicating magnitude of change
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Relationships
    project = relationship("Project", backref="architecture_versions")
    creator = relationship("User")
    threat_models = relationship("ThreatModel", back_populates="architecture_version")
    threat_history = relationship("ThreatHistory", back_populates="architecture_version")

    __table_args__ = (
        # Unique constraint: one version number per project
        {"sqlite_autoincrement": True},
    )


class ThreatHistory(Base):
    """Tracks the lifecycle of individual threats across architecture versions"""
    __tablename__ = "threat_history"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    threat_id = Column(String(100), nullable=False, index=True)  # Stable ID: "{stride_category}_{component_hash}"
    architecture_version_id = Column(Integer, ForeignKey("architecture_versions.id"), nullable=False)
    status = Column(Enum(ThreatStatus), nullable=False)  # new, existing, modified, resolved
    threat_data = Column(JSON, nullable=False)  # Full threat details at this version
    previous_history_id = Column(Integer, ForeignKey("threat_history.id"), nullable=True)  # Link to previous version
    change_reason = Column(String(500))  # Why status changed (e.g., "Component 'API Gateway' modified")
    affected_components = Column(JSON)  # List of component IDs related to this threat
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    project = relationship("Project", backref="threat_history")
    architecture_version = relationship("ArchitectureVersion", back_populates="threat_history")
    previous_version = relationship("ThreatHistory", remote_side=[id], backref="next_versions")

    __table_args__ = (
        # Index for efficient queries on threat timeline
        {"sqlite_autoincrement": True},
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    message = Column(Text, nullable=False)
    response = Column(Text)
    detected_language = Column(String(10))
    context_type = Column(String(50))  # vulnerability, threat, general
    context_id = Column(Integer)  # ID of related vulnerability/threat
    model_used = Column(String(50))
    tokens_used = Column(Integer)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user = relationship("User", back_populates="chat_messages")


class SystemSettings(Base):
    """Store system-wide settings like API keys for threat intelligence"""
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(Text)  # Encrypted for sensitive values
    description = Column(String(500))
    is_secret = Column(Boolean, default=False)  # If true, value is encrypted
    category = Column(String(50), default="general")  # threat_intel, ai, general
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class ProfileStatus(str, enum.Enum):
    PENDING = "pending"
    PROFILING = "profiling"
    ANALYZING = "analyzing"
    GENERATING_SUGGESTIONS = "generating_suggestions"
    COMPLETED = "completed"
    FAILED = "failed"


class SuggestionStatus(str, enum.Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    DISMISSED = "dismissed"
    IMPLEMENTED = "implemented"


class ApplicationProfile(Base):
    """Application intelligence profile - stores analyzed metadata about a project"""
    __tablename__ = "application_profiles"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, unique=True)

    # Profiling Status
    status = Column(Enum(ProfileStatus), default=ProfileStatus.PENDING)
    status_message = Column(String(500))
    profiling_progress = Column(Integer, default=0)  # 0-100 percentage

    # Technology Stack
    languages = Column(JSON)  # {"python": 67.5, "typescript": 28.2, "sql": 4.3}
    frameworks = Column(JSON)  # [{"name": "FastAPI", "version": "0.104.1", "type": "backend"}]
    databases = Column(JSON)  # ["PostgreSQL", "Redis"]
    orm_libraries = Column(JSON)  # ["SQLAlchemy", "Prisma"]

    # Architecture Analysis
    entry_points = Column(JSON)  # [{"method": "POST", "path": "/api/users", "file": "routes/users.py", "risk_indicators": ["authentication"]}]
    sensitive_data_fields = Column(JSON)  # [{"field": "password", "category": "credential", "file": "models/user.py", "line": 45}]
    auth_mechanisms = Column(JSON)  # ["JWT", "OAuth2", "Session"]

    # Dependencies
    dependencies = Column(JSON)  # {"fastapi": "0.104.1", "sqlalchemy": "2.0.0"}
    dev_dependencies = Column(JSON)
    vulnerable_dependencies = Column(JSON)  # From SCA analysis

    # External Integrations
    external_integrations = Column(JSON)  # ["Stripe", "AWS S3", "SendGrid"]
    cloud_services = Column(JSON)  # ["AWS", "GCP", "Azure"]

    # Code Metrics
    file_count = Column(Integer, default=0)
    total_lines_of_code = Column(Integer, default=0)
    test_coverage = Column(Float)  # Percentage if available

    # Security Posture Summary
    security_score = Column(Float)  # 0-100
    risk_level = Column(String(20))  # low, medium, high, critical
    total_suggestions = Column(Integer, default=0)
    critical_suggestions = Column(Integer, default=0)
    high_suggestions = Column(Integer, default=0)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_profiled_at = Column(DateTime(timezone=True))

    # Relationships
    project = relationship("Project", backref="application_profile")
    suggested_rules = relationship("SuggestedRule", back_populates="application_profile", cascade="all, delete-orphan")


class SuggestedRule(Base):
    """AI-suggested security rules based on application profile"""
    __tablename__ = "suggested_rules"

    id = Column(Integer, primary_key=True, index=True)
    application_profile_id = Column(Integer, ForeignKey("application_profiles.id"), nullable=False)

    # Rule Details
    name = Column(String(255), nullable=False)
    description = Column(Text)
    category = Column(String(100))  # sql_injection, xss, auth_bypass, etc.
    severity = Column(Enum(SeverityLevel), nullable=False)

    # Why this rule is suggested
    reason = Column(Text)  # "Detected SQLAlchemy with potential raw queries"
    detected_patterns = Column(JSON)  # [{"file": "db.py", "line": 45, "pattern": "execute(f\"..."}]
    framework_context = Column(String(100))  # Which framework triggered this

    # Generated Rule Content
    rule_pattern = Column(Text)  # The actual pattern/regex
    rule_type = Column(String(50), default="semgrep")  # semgrep, regex, codeql, ast

    # Multi-format exports
    semgrep_rule = Column(Text)  # YAML format
    codeql_rule = Column(Text)  # QL format
    checkmarx_rule = Column(Text)  # CxQL format
    fortify_rule = Column(Text)  # XML format

    # Rule metadata
    cwe_ids = Column(JSON)  # ["CWE-89", "CWE-79"]
    owasp_categories = Column(JSON)  # ["A03:2021"]
    mitre_techniques = Column(JSON)  # ["T1190"]

    # Status and feedback
    status = Column(Enum(SuggestionStatus), default=SuggestionStatus.PENDING)
    confidence_score = Column(Float)  # 0-1 AI confidence
    user_feedback = Column(String(50))  # helpful, not_helpful, false_positive
    feedback_comment = Column(Text)

    # If accepted, stores the ID of the created custom rule (stored separately)
    created_rule_id = Column(Integer, nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    reviewed_at = Column(DateTime(timezone=True))

    # Relationships
    application_profile = relationship("ApplicationProfile", back_populates="suggested_rules")


# ==================== SECUREREQ MODELS ====================

class StorySource(str, enum.Enum):
    MANUAL = "manual"
    JIRA = "jira"
    ADO = "ado"  # Azure DevOps
    GITHUB = "github"
    SNOW = "snow"  # ServiceNow


class UserStory(Base):
    """User stories/requirements for security analysis"""
    __tablename__ = "user_stories"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)

    # Story Details
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    acceptance_criteria = Column(Text)

    # Source tracking
    source = Column(Enum(StorySource), default=StorySource.MANUAL)
    external_id = Column(String(100))  # Jira ticket ID, ADO work item ID, etc.
    external_url = Column(String(500))

    # Analysis status
    is_analyzed = Column(Boolean, default=False)
    risk_score = Column(Integer, default=0)  # 0-100
    threat_count = Column(Integer, default=0)
    requirement_count = Column(Integer, default=0)

    # Timestamps
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    project = relationship("Project", backref="user_stories")
    creator = relationship("User")
    analyses = relationship("SecurityAnalysis", back_populates="user_story", cascade="all, delete-orphan")


class SecurityAnalysis(Base):
    """Security analysis results for a user story"""
    __tablename__ = "security_analyses"

    id = Column(Integer, primary_key=True, index=True)
    user_story_id = Column(Integer, ForeignKey("user_stories.id"), nullable=False)

    # Version tracking (each analysis creates a new version)
    version = Column(Integer, default=1)

    # Analysis Results (stored as JSON)
    abuse_cases = Column(JSON)  # List of abuse case scenarios
    stride_threats = Column(JSON)  # STRIDE-categorized threats
    security_requirements = Column(JSON)  # Generated security requirements

    # Risk Assessment
    risk_score = Column(Integer, default=0)  # 0-100
    risk_factors = Column(JSON)  # Breakdown of risk factors

    # AI metadata
    ai_model_used = Column(String(100))
    analysis_duration_ms = Column(Integer)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user_story = relationship("UserStory", back_populates="analyses")
    compliance_mappings = relationship("ComplianceMapping", back_populates="analysis", cascade="all, delete-orphan")


class ComplianceMapping(Base):
    """Maps security requirements to compliance standards"""
    __tablename__ = "compliance_mappings"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("security_analyses.id"), nullable=False)

    # Requirement reference
    requirement_id = Column(String(50))  # SR-001, etc.
    requirement_text = Column(Text)

    # Compliance mapping
    standard_name = Column(String(100))  # OWASP ASVS, PCI-DSS, ISO 27001
    control_id = Column(String(50))  # V2.1.1, Req 6.5, A.12.6
    control_title = Column(String(500))
    control_description = Column(Text)

    # Relevance scoring
    relevance_score = Column(Float)  # 0-1 confidence
    mapping_rationale = Column(Text)

    # Relationships
    analysis = relationship("SecurityAnalysis", back_populates="compliance_mappings")


class CustomStandard(Base):
    """User-uploaded custom compliance standards"""
    __tablename__ = "custom_standards"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)

    # Standard details
    name = Column(String(255), nullable=False)
    description = Column(Text)
    version = Column(String(50))

    # File metadata
    file_type = Column(String(20))  # json, pdf, excel
    original_filename = Column(String(255))

    # Parsed controls (JSON array)
    controls = Column(JSON)  # [{"id": "1.1", "title": "...", "description": "..."}]
    control_count = Column(Integer, default=0)

    # Timestamps
    uploaded_by = Column(Integer, ForeignKey("users.id"))
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    project = relationship("Project", backref="custom_standards")
    uploader = relationship("User")


# ==================== INTEGRATION SETTINGS ====================

class IntegrationType(str, enum.Enum):
    JIRA = "jira"
    ADO = "ado"
    SNOW = "snow"


class IntegrationSettings(Base):
    """Global integration settings for Jira, ADO, and ServiceNow"""
    __tablename__ = "integration_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    integration_type = Column(Enum(IntegrationType), nullable=False)

    # Connection Details (encrypted in production)
    base_url = Column(String(500), nullable=False)  # Jira/ADO/SNOW URL
    username = Column(String(255))  # Email for Jira, username for SNOW
    api_token = Column(Text)  # Encrypted API token/PAT/password

    # Custom field configuration
    abuse_cases_field = Column(String(100))  # e.g., customfield_10001 for Jira
    security_req_field = Column(String(100))  # e.g., customfield_10002 for Jira

    # Status
    is_connected = Column(Boolean, default=False)
    last_connected_at = Column(DateTime(timezone=True))
    connection_error = Column(Text)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    user = relationship("User", backref="integration_settings")


class ProjectIntegration(Base):
    """Per-project integration configuration"""
    __tablename__ = "project_integrations"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    integration_type = Column(Enum(IntegrationType), nullable=False)

    # External project identifier
    external_project_id = Column(String(100))  # Jira project key, ADO project name, SNOW product
    external_project_name = Column(String(255))

    # Sync configuration
    sync_enabled = Column(Boolean, default=True)
    auto_publish = Column(Boolean, default=False)  # Auto-publish analysis to external system
    issue_types = Column(JSON)  # ["Story", "Task", "Bug"] for Jira/ADO

    # SNOW specific
    snow_table = Column(String(100))  # rm_story, sc_req_item, etc.
    snow_assignment_group = Column(String(100))

    # Sync status
    last_synced_at = Column(DateTime(timezone=True))
    sync_status = Column(String(50))  # success, error, in_progress
    sync_error = Column(Text)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    project = relationship("Project", backref="integrations")


# ==================== PROMPT FEEDBACK FOR IN-CONTEXT LEARNING ====================

class FeedbackType(str, enum.Enum):
    ABUSE_CASE = "abuse_case"
    SECURITY_REQUIREMENT = "security_requirement"


class FeedbackRating(str, enum.Enum):
    POSITIVE = "positive"  # 👍 Good example
    NEGATIVE = "negative"  # 👎 Bad example


class PromptFeedback(Base):
    """Stores user feedback on AI-generated abuse cases and security requirements
    Used for in-context learning to improve future AI prompts"""
    __tablename__ = "prompt_feedback"

    id = Column(Integer, primary_key=True, index=True)

    # What type of content this feedback is for
    feedback_type = Column(Enum(FeedbackType), nullable=False)

    # The rating: positive (good example) or negative (bad example)
    rating = Column(Enum(FeedbackRating), nullable=False)

    # The actual content being rated (JSON for flexibility)
    content = Column(JSON, nullable=False)  # The abuse case or requirement object

    # Context: what user story generated this (for reference)
    story_title = Column(String(500))
    story_description = Column(Text)

    # Who provided the feedback
    user_id = Column(Integer, ForeignKey("users.id"))

    # Optional comment explaining why this is good/bad
    comment = Column(Text)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user = relationship("User", backref="prompt_feedback")
