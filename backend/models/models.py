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

    # Relationships
    project = relationship("Project", back_populates="threat_models")

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
