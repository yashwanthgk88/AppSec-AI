"""
Custom Security Rule Models - Enhanced with AST and Taint Flow Support
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class RuleType(str, Enum):
    """Type of security rule"""
    PATTERN = "pattern"  # Regex-based pattern matching
    TAINT_FLOW = "taint_flow"  # Source -> Sink taint tracking
    AST = "ast"  # AST-based structure matching
    SEMANTIC = "semantic"  # Semantic code analysis


class OwaspCategory(str, Enum):
    """OWASP Top 10:2025 Categories"""
    A01_BROKEN_ACCESS_CONTROL = "A01:2025 - Broken Access Control"
    A02_SECURITY_MISCONFIGURATION = "A02:2025 - Security Misconfiguration"
    A03_SOFTWARE_SUPPLY_CHAIN = "A03:2025 - Software Supply Chain Failures"
    A04_CRYPTOGRAPHIC_FAILURES = "A04:2025 - Cryptographic Failures"
    A05_INJECTION = "A05:2025 - Injection"
    A06_INSECURE_DESIGN = "A06:2025 - Insecure Design"
    A07_AUTHENTICATION_FAILURES = "A07:2025 - Authentication Failures"
    A08_SSRF = "A08:2025 - Server-Side Request Forgery (SSRF)"
    A09_LOGGING_FAILURES = "A09:2025 - Security Logging and Alerting Failures"
    A10_EXCEPTION_HANDLING = "A10:2025 - Mishandling of Exceptional Conditions"


class TaintSource(BaseModel):
    """Taint source definition for taint flow rules"""
    pattern: str = Field(..., description="Pattern to identify taint source")
    description: str = Field(..., description="What this source represents")
    framework: Optional[str] = Field(None, description="Framework-specific (e.g., flask, django, express)")


class TaintSink(BaseModel):
    """Taint sink definition for taint flow rules"""
    pattern: str = Field(..., description="Pattern to identify taint sink")
    description: str = Field(..., description="What this sink represents")
    sink_type: str = Field(..., description="Type: sql, command, xss, path, ssrf, etc.")


class TaintFlowRule(BaseModel):
    """Taint flow rule definition"""
    sources: List[TaintSource] = Field(default_factory=list)
    sinks: List[TaintSink] = Field(default_factory=list)
    sanitizers: List[str] = Field(default_factory=list, description="Patterns that sanitize taint")
    propagators: List[str] = Field(default_factory=list, description="Patterns that propagate taint")


class CustomRule(BaseModel):
    """Custom security detection rule with AST and Taint Flow support"""
    id: Optional[int] = None
    name: str = Field(..., description="Rule name")
    pattern: str = Field(..., description="Regex pattern for detection")
    severity: str = Field(..., description="Severity: critical, high, medium, low")
    description: str = Field(..., description="What this rule detects")
    language: str = Field(default="*", description="Target language or * for all")

    # Rule type and advanced features
    rule_type: str = Field(default="pattern", description="pattern, taint_flow, ast, semantic")
    taint_flow: Optional[Dict[str, Any]] = Field(None, description="Taint flow configuration")
    ast_patterns: Optional[List[str]] = Field(None, description="AST node patterns to match")
    multi_patterns: Optional[List[str]] = Field(None, description="Additional patterns (all must match)")
    negative_patterns: Optional[List[str]] = Field(None, description="Patterns that exclude a match")

    # Optional fields
    cwe: Optional[str] = Field(None, description="CWE identifier")
    owasp: Optional[str] = Field(None, description="OWASP 2025 category")
    remediation: Optional[str] = Field(None, description="How to fix")
    remediation_code: Optional[str] = Field(None, description="Example secure code")

    # Metadata
    enabled: bool = Field(default=True, description="Whether rule is active")
    created_by: str = Field(..., description="User who created the rule")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Generation metadata
    generated_by: Optional[str] = Field(None, description="ai, user, cve, or template")
    source: Optional[str] = Field(None, description="Source of rule (CVE ID, blog URL, etc)")
    confidence: Optional[str] = Field(None, description="high, medium, low")
    template_id: Optional[str] = Field(None, description="Template this rule was created from")

    # Performance tracking
    total_detections: int = Field(default=0)
    false_positives: int = Field(default=0)
    true_positives: int = Field(default=0)
    precision: Optional[float] = None

    # Tags for organization
    tags: Optional[List[str]] = Field(None, description="Custom tags for filtering")

    class Config:
        json_schema_extra = {
            "example": {
                "name": "SQL Injection via String Concatenation",
                "pattern": r'(execute|query|exec)\s*\(\s*["\'].*?(\+|%)',
                "severity": "critical",
                "description": "Detects SQL queries built with string concatenation",
                "language": "python",
                "rule_type": "pattern",
                "cwe": "CWE-89",
                "owasp": "A05:2025 - Injection",
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
