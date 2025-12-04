"""
Custom Security Rule Models
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field

class CustomRule(BaseModel):
    """Custom security detection rule"""
    id: Optional[int] = None
    name: str = Field(..., description="Rule name")
    pattern: str = Field(..., description="Regex pattern for detection")
    severity: str = Field(..., description="Severity: critical, high, medium, low")
    description: str = Field(..., description="What this rule detects")
    language: str = Field(default="*", description="Target language or * for all")

    # Optional fields
    cwe: Optional[str] = Field(None, description="CWE identifier")
    owasp: Optional[str] = Field(None, description="OWASP category")
    remediation: Optional[str] = Field(None, description="How to fix")
    remediation_code: Optional[str] = Field(None, description="Example secure code")

    # Metadata
    enabled: bool = Field(default=True, description="Whether rule is active")
    created_by: str = Field(..., description="User who created the rule")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Generation metadata
    generated_by: Optional[str] = Field(None, description="ai, user, or cve")
    source: Optional[str] = Field(None, description="Source of rule (CVE ID, blog URL, etc)")
    confidence: Optional[str] = Field(None, description="high, medium, low")

    # Performance tracking
    total_detections: int = Field(default=0)
    false_positives: int = Field(default=0)
    true_positives: int = Field(default=0)
    precision: Optional[float] = None

    class Config:
        json_schema_extra = {
            "example": {
                "name": "SQL Injection via String Concatenation",
                "pattern": r'(execute|query|exec)\s*\(\s*["\'].*?(\+|%)',
                "severity": "critical",
                "description": "Detects SQL queries built with string concatenation",
                "language": "python",
                "cwe": "CWE-89",
                "owasp": "A03:2021 - Injection",
                "remediation": "Use parameterized queries or prepared statements",
                "enabled": True,
                "created_by": "admin"
            }
        }


class CreateCustomRuleRequest(BaseModel):
    """Request to create a custom rule"""
    name: str
    pattern: str
    severity: str
    description: str
    language: str = "*"
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    remediation: Optional[str] = None
    remediation_code: Optional[str] = None
    enabled: bool = True


class UpdateCustomRuleRequest(BaseModel):
    """Request to update a custom rule"""
    name: Optional[str] = None
    pattern: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    language: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    remediation: Optional[str] = None
    remediation_code: Optional[str] = None
    enabled: Optional[bool] = None


class GenerateRuleRequest(BaseModel):
    """Request to generate rule using AI"""
    rule_name: str
    vulnerability_description: str
    severity: str
    languages: Optional[List[str]] = None


class RefineRuleRequest(BaseModel):
    """Request to refine rule based on false positives"""
    rule_id: int
    false_positive_examples: List[dict]


class RulePerformanceMetric(BaseModel):
    """Performance metrics for a rule"""
    id: Optional[int] = None
    rule_id: int
    finding_id: int
    user_feedback: str = Field(..., description="resolved, false_positive, ignored")
    code_snippet: Optional[str] = None
    file_path: Optional[str] = None
    feedback_comment: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[int] = None

    class Config:
        json_schema_extra = {
            "example": {
                "rule_id": 1,
                "finding_id": 123,
                "user_feedback": "false_positive",
                "feedback_comment": "Variable is sanitized earlier in function"
            }
        }


class RulePerformanceStats(BaseModel):
    """Aggregated performance statistics for a rule"""
    rule_id: int
    rule_name: str
    total_detections: int
    true_positives: int
    false_positives: int
    ignored: int
    precision: float = Field(description="TP / (TP + FP)")
    recall_estimate: Optional[float] = None
    f1_score: Optional[float] = None
    needs_refinement: bool = Field(description="True if precision < 0.85")
    last_detection: Optional[datetime] = None
    average_severity: str


class EnhancementJob(BaseModel):
    """AI enhancement job status"""
    id: Optional[int] = None
    job_type: str = Field(..., description="generate_cve, refine_rules, threat_intel")
    status: str = Field(default="pending", description="pending, running, completed, failed")
    progress: int = Field(default=0, description="0-100")
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    triggered_by: str = Field(..., description="User who triggered")

    # Results
    rules_generated: int = Field(default=0)
    rules_refined: int = Field(default=0)
    errors: List[str] = Field(default_factory=list)

    # Input parameters
    parameters: Optional[dict] = None

    class Config:
        json_schema_extra = {
            "example": {
                "job_type": "generate_cve",
                "status": "running",
                "progress": 45,
                "triggered_by": "admin@example.com",
                "rules_generated": 3
            }
        }


class RuleEnhancementLog(BaseModel):
    """Log entry for rule enhancement actions"""
    id: Optional[int] = None
    rule_id: int
    action: str = Field(..., description="created, refined, enabled, disabled, deleted")
    old_pattern: Optional[str] = None
    new_pattern: Optional[str] = None
    reason: str
    performed_by: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ai_generated: bool = Field(default=False)
