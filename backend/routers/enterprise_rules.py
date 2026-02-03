"""
Enterprise Security Rules API

Provides endpoints for generating custom security rules for enterprise SAST/DAST tools:
- Checkmarx
- Fortify
- HCL AppScan
- Acunetix
- Micro Focus WebInspect
- Semgrep
- CodeQL
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import sqlite3
import json
import io
import zipfile
import logging

from services.enterprise_rule_generator import EnterpriseRuleGenerator
from core.security import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/enterprise-rules", tags=["Enterprise Rules"])

# Initialize the generator
rule_generator = EnterpriseRuleGenerator()


# Pydantic Models
class GenerateRuleRequest(BaseModel):
    """Request model for generating a single rule"""
    tool: str = Field(..., description="Target tool (checkmarx, fortify, appscan, acunetix, webinspect, semgrep, codeql)")
    rule_name: str = Field(..., description="Name of the rule")
    description: str = Field(..., description="Description of the vulnerability")
    vulnerability_type: str = Field(..., description="Type of vulnerability (sql_injection, xss, command_injection, etc.)")
    severity: str = Field(..., description="Severity level (critical, high, medium, low)")
    language: str = Field(..., description="Target programming language")
    pattern: Optional[str] = Field(None, description="Custom regex pattern (optional)")
    cwe_id: Optional[str] = Field(None, description="CWE identifier (e.g., CWE-89)")
    owasp_category: Optional[str] = Field(None, description="OWASP category (e.g., A03:2021)")
    custom_message: Optional[str] = Field(None, description="Custom finding message")
    remediation: Optional[str] = Field(None, description="Remediation guidance")


class GenerateMultipleRulesRequest(BaseModel):
    """Request model for generating rules for multiple tools"""
    rule_name: str = Field(..., description="Name of the rule")
    description: str = Field(..., description="Description of the vulnerability")
    vulnerability_type: str = Field(..., description="Type of vulnerability")
    severity: str = Field(..., description="Severity level")
    language: str = Field(..., description="Target programming language")
    pattern: Optional[str] = Field(None, description="Custom regex pattern")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    owasp_category: Optional[str] = Field(None, description="OWASP category")
    custom_message: Optional[str] = Field(None, description="Custom finding message")
    remediation: Optional[str] = Field(None, description="Remediation guidance")
    tools: Optional[List[str]] = Field(None, description="List of tools to generate for (null for all)")


class SaveGeneratedRuleRequest(BaseModel):
    """Request to save a generated rule to the database"""
    rule_name: str
    description: str
    vulnerability_type: str
    severity: str
    language: str
    pattern: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    tools: Dict[str, str] = Field(..., description="Dictionary of tool -> rule content")


class RuleTemplate(BaseModel):
    """Predefined rule template"""
    id: str
    name: str
    description: str
    vulnerability_type: str
    severity: str
    cwe_id: str
    owasp_category: str
    languages: List[str]


def get_db():
    """Get database connection"""
    conn = sqlite3.connect('appsec.db')
    conn.row_factory = sqlite3.Row
    return conn


# API Endpoints

@router.get("/tools", response_model=List[Dict[str, Any]])
async def get_supported_tools():
    """Get list of supported enterprise security tools"""
    return rule_generator.get_supported_tools()


@router.get("/vulnerability-types", response_model=List[Dict[str, Any]])
async def get_vulnerability_types():
    """Get list of supported vulnerability types with CWE mappings"""
    return [
        {"id": cwe_id, **info}
        for cwe_id, info in rule_generator.CWE_CATEGORIES.items()
    ]


@router.get("/languages", response_model=List[str])
async def get_supported_languages():
    """Get list of supported programming languages"""
    return list(rule_generator.LANGUAGE_PATTERNS.keys())


@router.get("/templates", response_model=List[RuleTemplate])
async def get_rule_templates():
    """Get predefined rule templates for common vulnerabilities"""
    templates = [
        RuleTemplate(
            id="sql_injection",
            name="SQL Injection Detection",
            description="Detects potential SQL injection vulnerabilities where user input is concatenated into SQL queries",
            vulnerability_type="sql_injection",
            severity="critical",
            cwe_id="CWE-89",
            owasp_category="A03:2021",
            languages=["python", "java", "javascript", "php", "csharp", "go"]
        ),
        RuleTemplate(
            id="xss",
            name="Cross-Site Scripting (XSS)",
            description="Detects potential XSS vulnerabilities where user input is rendered without proper encoding",
            vulnerability_type="xss",
            severity="high",
            cwe_id="CWE-79",
            owasp_category="A03:2021",
            languages=["javascript", "python", "php", "java"]
        ),
        RuleTemplate(
            id="command_injection",
            name="OS Command Injection",
            description="Detects potential command injection where user input is passed to system commands",
            vulnerability_type="command_injection",
            severity="critical",
            cwe_id="CWE-78",
            owasp_category="A03:2021",
            languages=["python", "java", "javascript", "php", "go"]
        ),
        RuleTemplate(
            id="path_traversal",
            name="Path Traversal",
            description="Detects potential path traversal vulnerabilities allowing access to arbitrary files",
            vulnerability_type="path_traversal",
            severity="high",
            cwe_id="CWE-22",
            owasp_category="A01:2021",
            languages=["python", "java", "javascript", "php", "go"]
        ),
        RuleTemplate(
            id="hardcoded_secret",
            name="Hardcoded Secrets",
            description="Detects hardcoded passwords, API keys, and other secrets in source code",
            vulnerability_type="hardcoded_secret",
            severity="high",
            cwe_id="CWE-798",
            owasp_category="A07:2021",
            languages=["python", "java", "javascript", "php", "csharp", "go"]
        ),
        RuleTemplate(
            id="deserialization",
            name="Insecure Deserialization",
            description="Detects insecure deserialization of untrusted data",
            vulnerability_type="deserialization",
            severity="critical",
            cwe_id="CWE-502",
            owasp_category="A08:2021",
            languages=["java", "python", "csharp", "php"]
        ),
        RuleTemplate(
            id="xxe",
            name="XML External Entity (XXE)",
            description="Detects potential XXE vulnerabilities in XML parsing",
            vulnerability_type="xxe",
            severity="high",
            cwe_id="CWE-611",
            owasp_category="A05:2021",
            languages=["java", "python", "csharp", "php"]
        ),
        RuleTemplate(
            id="ssrf",
            name="Server-Side Request Forgery (SSRF)",
            description="Detects potential SSRF vulnerabilities where user input controls server-side requests",
            vulnerability_type="ssrf",
            severity="high",
            cwe_id="CWE-918",
            owasp_category="A10:2021",
            languages=["python", "java", "javascript", "php", "go"]
        ),
        RuleTemplate(
            id="weak_crypto",
            name="Weak Cryptography",
            description="Detects use of weak or deprecated cryptographic algorithms",
            vulnerability_type="weak_crypto",
            severity="medium",
            cwe_id="CWE-327",
            owasp_category="A02:2021",
            languages=["python", "java", "javascript", "csharp", "go"]
        ),
        RuleTemplate(
            id="open_redirect",
            name="Open Redirect",
            description="Detects potential open redirect vulnerabilities",
            vulnerability_type="open_redirect",
            severity="medium",
            cwe_id="CWE-601",
            owasp_category="A01:2021",
            languages=["python", "java", "javascript", "php"]
        ),
    ]
    return templates


@router.post("/generate", response_model=Dict[str, Any])
async def generate_rule(
    request: GenerateRuleRequest,
    current_user: dict = Depends(get_current_user)
):
    """Generate a security rule for a specific tool"""
    try:
        result = rule_generator.generate_rule(
            tool=request.tool,
            rule_name=request.rule_name,
            description=request.description,
            vulnerability_type=request.vulnerability_type,
            severity=request.severity,
            language=request.language,
            pattern=request.pattern,
            cwe_id=request.cwe_id,
            owasp_category=request.owasp_category,
            custom_message=request.custom_message,
            remediation=request.remediation,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error generating rule: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate rule: {str(e)}")


@router.post("/generate-all", response_model=Dict[str, Any])
async def generate_all_rules(
    request: GenerateMultipleRulesRequest,
    current_user: dict = Depends(get_current_user)
):
    """Generate security rules for multiple tools at once"""
    try:
        result = rule_generator.generate_all_formats(
            rule_name=request.rule_name,
            description=request.description,
            vulnerability_type=request.vulnerability_type,
            severity=request.severity,
            language=request.language,
            pattern=request.pattern,
            cwe_id=request.cwe_id,
            owasp_category=request.owasp_category,
            custom_message=request.custom_message,
            remediation=request.remediation,
            tools=request.tools,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error generating rules: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate rules: {str(e)}")


@router.post("/generate-from-template/{template_id}", response_model=Dict[str, Any])
async def generate_from_template(
    template_id: str,
    language: str,
    tools: Optional[List[str]] = None,
    current_user: dict = Depends(get_current_user)
):
    """Generate rules from a predefined template"""
    templates = await get_rule_templates()
    template = next((t for t in templates if t.id == template_id), None)

    if not template:
        raise HTTPException(status_code=404, detail=f"Template not found: {template_id}")

    if language.lower() not in [l.lower() for l in template.languages]:
        raise HTTPException(
            status_code=400,
            detail=f"Language '{language}' not supported for this template. Supported: {template.languages}"
        )

    try:
        result = rule_generator.generate_all_formats(
            rule_name=template.name,
            description=template.description,
            vulnerability_type=template.vulnerability_type,
            severity=template.severity,
            language=language,
            cwe_id=template.cwe_id,
            owasp_category=template.owasp_category,
            tools=tools,
        )
        return result
    except Exception as e:
        logger.error(f"Error generating from template: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/validate-pattern")
async def validate_pattern(pattern: str):
    """Validate a regex pattern"""
    return rule_generator.validate_pattern(pattern)


@router.post("/export/{tool}")
async def export_rule(
    tool: str,
    request: GenerateRuleRequest,
    current_user: dict = Depends(get_current_user)
):
    """Export a generated rule as a downloadable file"""
    try:
        result = rule_generator.generate_rule(
            tool=tool,
            rule_name=request.rule_name,
            description=request.description,
            vulnerability_type=request.vulnerability_type,
            severity=request.severity,
            language=request.language,
            pattern=request.pattern,
            cwe_id=request.cwe_id,
            owasp_category=request.owasp_category,
            custom_message=request.custom_message,
            remediation=request.remediation,
        )

        tool_info = rule_generator.SUPPORTED_TOOLS.get(tool, {})
        extension = tool_info.get("extension", "txt")
        mime_type = tool_info.get("mime_type", "text/plain")
        filename = f"{request.rule_name.replace(' ', '_').lower()}_{tool}.{extension}"

        return StreamingResponse(
            iter([result["rule_content"]]),
            media_type=mime_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/export-all")
async def export_all_rules(
    request: GenerateMultipleRulesRequest,
    current_user: dict = Depends(get_current_user)
):
    """Export rules for all tools as a ZIP file"""
    try:
        result = rule_generator.generate_all_formats(
            rule_name=request.rule_name,
            description=request.description,
            vulnerability_type=request.vulnerability_type,
            severity=request.severity,
            language=request.language,
            pattern=request.pattern,
            cwe_id=request.cwe_id,
            owasp_category=request.owasp_category,
            custom_message=request.custom_message,
            remediation=request.remediation,
            tools=request.tools,
        )

        # Create ZIP file in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add README
            readme_content = f"""# Generated Security Rules
Rule Name: {request.rule_name}
Description: {request.description}
Vulnerability Type: {request.vulnerability_type}
Severity: {request.severity}
Language: {request.language}
CWE: {request.cwe_id or 'N/A'}
OWASP: {request.owasp_category or 'N/A'}
Generated: {datetime.utcnow().isoformat()}

## Included Rules
"""
            for tool, rule_data in result.get("rules", {}).items():
                if "error" not in rule_data:
                    tool_info = rule_generator.SUPPORTED_TOOLS.get(tool, {})
                    extension = tool_info.get("extension", "txt")
                    filename = f"{request.rule_name.replace(' ', '_').lower()}_{tool}.{extension}"

                    # Add rule file to ZIP
                    zip_file.writestr(filename, rule_data["rule_content"])
                    readme_content += f"- {tool_info.get('name', tool)}: {filename}\n"
                else:
                    readme_content += f"- {tool}: Error - {rule_data['error']}\n"

            zip_file.writestr("README.md", readme_content)

        zip_buffer.seek(0)
        zip_filename = f"{request.rule_name.replace(' ', '_').lower()}_rules.zip"

        return StreamingResponse(
            iter([zip_buffer.read()]),
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename={zip_filename}"}
        )
    except Exception as e:
        logger.error(f"Error exporting rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/save", response_model=Dict[str, Any])
async def save_generated_rule(
    request: SaveGeneratedRuleRequest,
    current_user: dict = Depends(get_current_user)
):
    """Save a generated rule to the database"""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Insert into custom_rules table
        cursor.execute('''
            INSERT INTO custom_rules (
                name, pattern, severity, description, language,
                cwe, owasp, remediation, enabled, created_by, generated_by, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 'ai_enterprise', 'high')
        ''', (
            request.rule_name,
            request.pattern,
            request.severity,
            request.description,
            request.language,
            request.cwe_id,
            request.owasp_category,
            request.remediation,
            current_user.username
        ))

        rule_id = cursor.lastrowid

        # Log creation
        cursor.execute('''
            INSERT INTO rule_enhancement_logs (rule_id, action, reason, performed_by, ai_generated)
            VALUES (?, 'created', ?, ?, 1)
        ''', (rule_id, f"Enterprise rule generated for tools: {', '.join(request.tools.keys())}", current_user.username))

        conn.commit()

        # Fetch created rule
        cursor.execute("SELECT * FROM custom_rules WHERE id = ?", (rule_id,))
        created_rule = dict(cursor.fetchone())

        conn.close()

        return {
            "message": "Rule saved successfully",
            "rule_id": rule_id,
            "rule": created_rule,
            "tools_generated": list(request.tools.keys())
        }

    except sqlite3.IntegrityError as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Rule already exists: {str(e)}")
    except Exception as e:
        conn.close()
        logger.error(f"Error saving rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history", response_model=List[Dict[str, Any]])
async def get_generation_history(
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    """Get history of generated enterprise rules"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT cr.*, rel.timestamp as generated_at, rel.reason
        FROM custom_rules cr
        JOIN rule_enhancement_logs rel ON cr.id = rel.rule_id
        WHERE cr.generated_by = 'ai_enterprise' AND rel.action = 'created'
        ORDER BY rel.timestamp DESC
        LIMIT ?
    ''', (limit,))

    rules = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return rules
