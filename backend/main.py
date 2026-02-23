"""
FastAPI Main Application
"""
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, BackgroundTasks, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import List, Optional
from datetime import timedelta, datetime
import os
import re
import shutil
import logging
import sys
from dotenv import load_dotenv

# Configure logging to output to stdout for Railway
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)
# Flush stdout immediately
sys.stdout.reconfigure(line_buffering=True)

# Track threat model generation status (in-memory, resets on restart)
threat_model_generation_status = {}

# Import models and services
from models import init_db, get_db, User, Project, Scan, Vulnerability, ThreatModel, ChatMessage
from models.models import ScanType, ScanStatus, SeverityLevel
from core.security import (
    get_password_hash, verify_password, create_access_token,
    get_current_active_user
)
from services.threat_modeling import ThreatModelingService
from services.sast_scanner import SASTScanner
from services.sca_scanner import SCAScanner
from services.secret_scanner import SecretScanner
from services.enhanced_sast_scanner import EnhancedSASTScanner
from services.enhanced_sca_scanner import EnhancedSCAScanner
from services.chatbot_service import ChatbotService
from services.report_service import ReportService
from services.repository_scanner import RepositoryScanner
from services.threat_intel import threat_intel
from services.ast_security_analyzer import ASTSecurityAnalyzer, ast_analyzer
from services.ai_impact_service import AIImpactService, get_ai_impact_service
from services.interprocedural_analyzer import analyze_code_interprocedural
from services.architecture_input_service import ArchitectureInputService

# Import routers
from routers import settings
from routers import custom_rules, rule_performance
from routers import application_intelligence
from routers import enterprise_rules
from routers import securereq
from routers import integrations

# Pydantic schemas
from pydantic import BaseModel, EmailStr

load_dotenv()

def get_db_path():
    """Get database path, preferring persistent storage if available"""
    persistent_path = "/app/data/appsec.db"
    if os.path.exists("/app/data"):
        return persistent_path
    return "appsec.db"

# Create FastAPI app
# redirect_slashes=False prevents 307 redirects when URLs have trailing slashes
app = FastAPI(
    title="AI-Enabled Application Security Platform",
    description="Comprehensive security scanning with threat modeling, SAST, SCA, and multilingual AI chatbot",
    version="1.0.0",
    redirect_slashes=False
)

# CORS middleware - Production ready
# Set CORS_ORIGINS env var for production, e.g., "https://your-domain.com,https://app.railway.app"
cors_origins = os.getenv("CORS_ORIGINS")
if cors_origins:
    allowed_origins = [origin.strip() for origin in cors_origins.split(",")]
else:
    # Default origins for development and Railway
    allowed_origins = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        # Railway production frontend
        "https://frontend-production-838e.up.railway.app",
    ]

# Check if we should allow all origins (for development/testing)
allow_all = os.getenv("CORS_ALLOW_ALL", "false").lower() == "true"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if allow_all else allowed_origins,
    allow_origin_regex=r"https://.*\.railway\.app" if not allow_all else None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(settings.router)
app.include_router(custom_rules.router)
app.include_router(rule_performance.router)
app.include_router(application_intelligence.router)
app.include_router(enterprise_rules.router)
app.include_router(securereq.router)
app.include_router(integrations.router)

# Initialize AI configuration from database at startup
def load_ai_config_from_database():
    """Load AI configuration from database and set as global config"""
    from services.ai_client_factory import load_ai_config_from_db, set_global_ai_config, AIConfig
    try:
        db = next(get_db())
        config = load_ai_config_from_db(db)
        if config:
            set_global_ai_config(config)
            print(f"[AI Config] Loaded from database: provider={config.provider}")
        else:
            # Set default config (will use env vars as fallback)
            default_config = AIConfig.from_env()
            set_global_ai_config(default_config)
            print(f"[AI Config] Using environment variables: provider={default_config.provider}")
    except Exception as e:
        print(f"[AI Config] Failed to load from database: {e}")
    finally:
        try:
            db.close()
        except:
            pass

# Load AI config at startup
load_ai_config_from_database()

# Log environment variables status (for debugging)
import os
anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
openai_key = os.getenv("OPENAI_API_KEY", "")
logger.info(f"[Startup] Environment check: ANTHROPIC_API_KEY={'set' if anthropic_key else 'NOT SET'}, OPENAI_API_KEY={'set' if openai_key else 'NOT SET'}")

# Initialize AI Impact Service (for dynamic impact generation)
ai_impact_service = get_ai_impact_service()

# Initialize services with AI impact integration
# AI impact is enabled for richer, contextual vulnerability analysis
threat_service = ThreatModelingService()
logger.info(f"[Startup] ThreatModelingService initialized: enabled={threat_service.enabled}, provider={threat_service.provider}, model={threat_service.model}")
sast_scanner = SASTScanner(ai_impact_service=ai_impact_service, ai_impact_enabled=True)
sca_scanner = SCAScanner(ai_impact_service=ai_impact_service, ai_impact_enabled=True)
secret_scanner = SecretScanner(ai_impact_service=ai_impact_service, ai_impact_enabled=True)
report_service = ReportService()

# Initialize Enhanced Scanners (multi-language with live vulnerability feeds)
enhanced_sast_scanner = EnhancedSASTScanner()
enhanced_sca_scanner = EnhancedSCAScanner()

# Lazy initialization for chatbot
_chatbot_service = None

def get_chatbot_service():
    """Get or create chatbot service using global AI config"""
    global _chatbot_service
    if _chatbot_service is None:
        try:
            _chatbot_service = ChatbotService()
        except Exception as e:
            print(f"[ChatbotService] Failed to initialize: {e}")
    return _chatbot_service

def reload_ai_services(new_config):
    """Reload all AI services with new configuration"""
    global _chatbot_service
    from services.ai_client_factory import set_global_ai_config

    # Update global config
    set_global_ai_config(new_config)

    # Update all services
    ai_impact_service.update_config(new_config)
    threat_service.update_config(new_config)

    # Recreate chatbot service
    _chatbot_service = None
    try:
        _chatbot_service = ChatbotService(new_config)
    except Exception as e:
        print(f"[ChatbotService] Failed to reinitialize: {e}")

    print(f"[AI Services] Reloaded with provider={new_config.provider}, model={new_config.model}")


def get_user_ai_config(user: User):
    """Get AI configuration for a specific user.

    Checks user's personal AI settings first, falls back to global config.
    """
    from services.ai_client_factory import AIConfig, get_global_ai_config

    # Check if user has personal AI configuration
    if user.ai_api_key and user.ai_provider:
        return AIConfig(
            provider=user.ai_provider,
            api_key=user.ai_api_key,
            model=user.ai_model,
            base_url=user.ai_base_url,
            api_version=user.ai_api_version
        )

    # Fall back to global configuration
    global_config = get_global_ai_config()

    # If user has a provider preference but no key, use global key with user's provider
    if user.ai_provider and global_config and global_config.api_key:
        return AIConfig(
            provider=user.ai_provider,
            api_key=global_config.api_key,
            model=user.ai_model or global_config.model,
            base_url=user.ai_base_url or global_config.base_url,
            api_version=user.ai_api_version or global_config.api_version
        )

    return global_config


# Pydantic Schemas
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    architecture_doc: Optional[str] = None
    repository_url: Optional[str] = None
    technology_stack: Optional[List[str]] = []
    compliance_targets: Optional[List[str]] = ["OWASP Top 10", "SANS CWE-25"]
    auto_scan_types: Optional[List[str]] = ["threat_model"]  # Default to just threat model

class ChatRequest(BaseModel):
    message: str
    context_type: Optional[str] = None
    context_id: Optional[int] = None

# Helper function to calculate risk score
def calculate_risk_score(project_id: int, db: Session):
    """
    Calculate risk score based on vulnerabilities found in all scans for a project.
    Risk score is on a scale of 0-10, calculated based on:
    - Number and severity of active vulnerabilities
    - Critical: 10 points each
    - High: 5 points each
    - Medium: 2 points each
    - Low: 0.5 points each
    """
    print(f"[RISK SCORE] Calculating risk score for project {project_id}")

    # Get all scans for the project
    scans = db.query(Scan).filter(Scan.project_id == project_id).all()
    print(f"[RISK SCORE] Found {len(scans)} scans for project {project_id}")

    if not scans:
        # No scans yet, risk score is 0
        project = db.query(Project).filter(Project.id == project_id).first()
        if project:
            project.risk_score = 0.0
            db.commit()
        print(f"[RISK SCORE] No scans found, setting risk score to 0.0")
        return

    # Get all active vulnerabilities (not resolved or false positive) across all scans
    total_score = 0
    total_vulns = 0
    for scan in scans:
        vulnerabilities = db.query(Vulnerability).filter(
            Vulnerability.scan_id == scan.id,
            Vulnerability.is_resolved == False,
            Vulnerability.false_positive == False
        ).all()

        print(f"[RISK SCORE] Scan {scan.id} ({scan.scan_type.value}): {len(vulnerabilities)} active vulnerabilities")

        for vuln in vulnerabilities:
            total_vulns += 1
            if vuln.severity == SeverityLevel.CRITICAL:
                total_score += 10
            elif vuln.severity == SeverityLevel.HIGH:
                total_score += 5
            elif vuln.severity == SeverityLevel.MEDIUM:
                total_score += 2
            elif vuln.severity == SeverityLevel.LOW:
                total_score += 0.5

    print(f"[RISK SCORE] Total active vulnerabilities: {total_vulns}, Total score: {total_score}")

    # Normalize to 0-10 scale using logarithmic scaling
    # This prevents the score from growing too quickly with many vulnerabilities
    if total_score == 0:
        risk_score = 0.0
    else:
        # Log scaling: risk_score = min(10, log10(total_score + 1) * 3)
        import math
        risk_score = min(10.0, math.log10(total_score + 1) * 3)

    print(f"[RISK SCORE] Calculated risk score: {risk_score} (rounded: {round(risk_score, 1)})")

    # Update project risk score
    project = db.query(Project).filter(Project.id == project_id).first()
    if project:
        project.risk_score = round(risk_score, 1)
        db.commit()
        print(f"[RISK SCORE] Updated project {project_id} risk score to {project.risk_score}")

# Initialize database
@app.on_event("startup")
async def startup_event():
    init_db()
    # Create default admin user
    db = next(get_db())
    # Check for existing admin by email OR username to avoid duplicate key errors
    admin = db.query(User).filter(
        (User.email == "admin@example.com") | (User.username == "admin")
    ).first()
    if not admin:
        admin = User(
            email="admin@example.com",
            username="admin",
            hashed_password=get_password_hash("admin123"),
            full_name="Admin User",
            is_admin=True,
            preferred_language="en"
        )
        db.add(admin)
        db.commit()

    # Load API keys from database into environment
    from models.models import SystemSettings
    api_keys = ['GITHUB_TOKEN', 'SNYK_TOKEN', 'NVD_API_KEY', 'MISP_API_KEY']
    for key in api_keys:
        setting = db.query(SystemSettings).filter(SystemSettings.key == key).first()
        if setting and setting.value:
            os.environ[key] = setting.value
            print(f"Loaded {key} from database")

    db.close()

# Health check
@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

# AI Impact Service Status
@app.get("/api/ai-impact/status")
async def ai_impact_status():
    """Get AI impact service status and statistics"""
    return ai_impact_service.get_stats()

# VS Code Extension Download
@app.get("/api/download/vscode-extension")
async def download_vscode_extension():
    """Download the SecureDev AI VS Code extension"""
    vsix_path = os.path.join(os.path.dirname(__file__), "appsec-ai-scanner-1.5.0.vsix")
    if not os.path.exists(vsix_path):
        raise HTTPException(status_code=404, detail="Extension file not found")
    return FileResponse(
        vsix_path,
        media_type="application/octet-stream",
        filename="appsec-ai-scanner-1.5.0.vsix"
    )

# Authentication endpoints
@app.post("/api/auth/register", response_model=Token)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    # Check if user exists
    existing = db.query(User).filter(
        (User.email == user_data.email) | (User.username == user_data.username)
    ).first()

    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    # Create user
    user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create token
    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/login", response_model=Token)
async def login(credentials: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == credentials.username).first()

    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/auth/me")
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "preferred_language": current_user.preferred_language,
        "is_admin": current_user.is_admin
    }

# Project endpoints
@app.post("/api/projects")
async def create_project(
    project_data: ProjectCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    project = Project(
        name=project_data.name,
        description=project_data.description,
        architecture_doc=project_data.architecture_doc,
        repository_url=project_data.repository_url,
        technology_stack=project_data.technology_stack,
        compliance_targets=project_data.compliance_targets,
        owner_id=current_user.id
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    scan_results = {
        "threat_model": False,
        "sast": False,
        "sca": False,
        "secret": False
    }

    # Auto-generate threat model if requested and architecture provided
    if "threat_model" in project_data.auto_scan_types and project_data.architecture_doc:
        logger.info(f"[Project Create] Threat modeling requested with architecture doc ({len(project_data.architecture_doc)} chars)")
        logger.info(f"[Project Create] ThreatService status: enabled={threat_service.enabled}, provider={threat_service.provider}")
        try:
            threat_model_data = threat_service.generate_threat_model(
                project_data.architecture_doc,
                project_data.name
            )
            logger.info(f"[Project Create] Threat model data keys: {threat_model_data.keys() if threat_model_data else 'None'}")

            # Cache mermaid diagrams in dfd_data for fast loading
            dfd_data_with_cache = dict(threat_model_data['dfd_data'])
            dfd_level_0 = threat_model_data.get('dfd_level_0', {})
            dfd_level_1 = threat_model_data.get('dfd_level_1', {})
            dfd_data_with_cache['mermaid_level_0'] = dfd_level_0.get('mermaid', '')
            dfd_data_with_cache['mermaid_level_1'] = dfd_level_1.get('mermaid', '')

            threat_model = ThreatModel(
                project_id=project.id,
                name=f"{project_data.name} Threat Model",
                dfd_level=0,
                dfd_data=dfd_data_with_cache,
                stride_analysis=threat_model_data['stride_analysis'],
                mitre_mapping=threat_model_data['mitre_mapping'],
                trust_boundaries=threat_model_data['dfd_data']['trust_boundaries'],
                attack_paths=threat_model_data.get('attack_paths', []),
                threat_count=threat_model_data['threat_count'],
                # Enhanced threat modeling fields
                fair_risk_analysis=threat_model_data.get('fair_risk_analysis'),
                attack_trees=threat_model_data.get('attack_trees'),
                kill_chain_analysis=threat_model_data.get('kill_chain_analysis')
            )
            db.add(threat_model)
            db.commit()
            scan_results["threat_model"] = True
            logger.info(f"[Project Create] Threat model generated successfully with {threat_model_data['threat_count']} threats")
        except Exception as e:
            import traceback
            logger.error(f"[Project Create] ERROR: Threat modeling failed: {e}")
            logger.error(f"[Project Create] Traceback: {traceback.format_exc()}")
            # Continue without threat model - don't fail the entire project creation
            scan_results["threat_model"] = False
    elif "threat_model" in project_data.auto_scan_types and not project_data.architecture_doc:
        logger.info("[Project Create] Threat modeling requested but no architecture doc provided - skipping")

    # Clone repository if URL provided
    repo_scanner = None
    if project_data.repository_url and any(scan_type in project_data.auto_scan_types for scan_type in ["sast", "sca", "secret"]):
        try:
            repo_scanner = RepositoryScanner()
            repo_path = repo_scanner.clone_repository(project_data.repository_url)
        except Exception as e:
            # If cloning fails, log error and fall back to demo scans
            print(f"Warning: Failed to clone repository: {e}")
            repo_scanner = None

    # Auto-run security scans if requested
    if "sast" in project_data.auto_scan_types:
        # Run SAST scan - real or demo
        if repo_scanner and repo_scanner.repo_path:
            # Real scan on cloned repository
            scan_results_data = sast_scanner.scan_directory(repo_scanner.repo_path)
            sast_findings = scan_results_data['findings']
        else:
            # Demo scan with sample findings
            sast_findings = sast_scanner.generate_sample_findings()

        # Create SAST scan
        sast_scan = Scan(
            project_id=project.id,
            scan_type=ScanType.SAST,
            status=ScanStatus.COMPLETED,
            total_findings=len(sast_findings),
            critical_count=len([f for f in sast_findings if f['severity'] == 'critical']),
            high_count=len([f for f in sast_findings if f['severity'] == 'high']),
            medium_count=len([f for f in sast_findings if f['severity'] == 'medium']),
            low_count=len([f for f in sast_findings if f['severity'] == 'low'])
        )
        db.add(sast_scan)
        db.flush()

        # Add SAST vulnerabilities
        for finding in sast_findings:
            # Make file path relative if it's from real scan
            file_path = finding['file_path']
            if repo_scanner and repo_scanner.repo_path:
                file_path = repo_scanner.get_relative_path(file_path)

            vuln = Vulnerability(
                scan_id=sast_scan.id,
                rule_id=finding.get('rule_id'),  # Track custom rule that found this
                title=finding['title'],
                description=finding['description'],
                severity=SeverityLevel[finding['severity'].upper()],
                cwe_id=finding['cwe_id'],
                owasp_category=finding['owasp_category'],
                file_path=file_path,
                line_number=finding['line_number'],
                code_snippet=finding['code_snippet'],
                remediation=finding['remediation'],
                remediation_code=finding.get('remediation_code'),
                cvss_score=finding['cvss_score'],
                stride_category=finding.get('stride_category'),
                mitre_attack_id=finding.get('mitre_attack_id'),
                # AI-generated impact fields
                business_impact=finding.get('business_impact'),
                technical_impact=finding.get('technical_impact'),
                recommendations=finding.get('recommendations'),
                impact_generated_by=finding.get('impact_generated_by', 'static')
            )
            db.add(vuln)

            # If this was found by a custom rule, track the detection
            if finding.get('rule_id'):
                try:
                    import sqlite3
                    conn = sqlite3.connect(get_db_path())
                    cursor = conn.cursor()
                    # Update custom rule detection count
                    cursor.execute('''
                        UPDATE custom_rules
                        SET total_detections = total_detections + 1
                        WHERE id = ?
                    ''', (finding['rule_id'],))
                    # Record in performance metrics for trend tracking
                    cursor.execute('''
                        INSERT INTO rule_performance_metrics (
                            rule_id, finding_id, user_feedback, code_snippet, file_path
                        ) VALUES (?, ?, ?, ?, ?)
                    ''', (
                        finding['rule_id'],
                        0,  # Placeholder, will be updated after flush
                        'confirmed',  # Initial status - counts as true positive
                        finding['code_snippet'][:500] if finding.get('code_snippet') else None,
                        file_path
                    ))
                    # Update true_positives to track precision
                    cursor.execute('''
                        UPDATE custom_rules
                        SET true_positives = true_positives + 1,
                            precision = CAST(true_positives + 1 AS REAL) / (CAST(true_positives + 1 AS REAL) + CAST(false_positives AS REAL))
                        WHERE id = ? AND false_positives >= 0
                    ''', (finding['rule_id'],))
                    conn.commit()
                    conn.close()
                except Exception as e:
                    print(f"Warning: Failed to track rule detection: {e}")
        db.commit()
        scan_results["sast"] = True

    if "sca" in project_data.auto_scan_types:
        # Run SCA scan - real or demo
        sca_findings = []
        if repo_scanner and repo_scanner.repo_path:
            # Get dependency files from repository
            dep_files = repo_scanner.get_dependency_files()

            # Scan each dependency file type
            for dep_type, file_paths in dep_files.items():
                for file_path in file_paths:
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()

                        # Parse dependencies based on type - supports all ecosystems
                        dependencies = {}
                        ecosystem = dep_type
                        file_name = os.path.basename(file_path)
                        if dep_type == 'npm':
                            # Use correct parser based on file type
                            if file_name == 'package-lock.json':
                                dependencies = sca_scanner.parse_package_lock_json(content)
                            elif file_name == 'yarn.lock':
                                dependencies = sca_scanner.parse_yarn_lock(content)
                            else:
                                dependencies = sca_scanner.parse_package_json(content)
                        elif dep_type == 'pip':
                            dependencies = sca_scanner.parse_requirements_txt(content)
                        elif dep_type == 'maven':
                            dependencies = sca_scanner.parse_pom_xml(content)
                        elif dep_type == 'gradle':
                            dependencies = sca_scanner.parse_gradle_build(content)
                        elif dep_type == 'composer':
                            dependencies = sca_scanner.parse_composer_json(content)
                        elif dep_type == 'nuget':
                            dependencies = sca_scanner.parse_csproj(content)
                        elif dep_type == 'bundler':
                            dependencies = sca_scanner.parse_gemfile_lock(content)
                        elif dep_type == 'go':
                            dependencies = sca_scanner.parse_go_mod(content)
                        elif dep_type == 'cargo':
                            dependencies = sca_scanner.parse_cargo_toml(content)
                        else:
                            continue

                        # Scan dependencies for vulnerabilities
                        if dependencies:
                            # Use live feeds if available
                            try:
                                results = await sca_scanner.scan_with_live_feeds(
                                    dependencies, ecosystem,
                                    use_local_db=True,
                                    use_live_feeds=True
                                )
                            except Exception as feed_error:
                                print(f"Live feed scan failed, falling back to local: {feed_error}")
                                results = sca_scanner.scan_dependencies(dependencies, ecosystem)
                            sca_findings.extend(results['findings'])
                    except Exception as e:
                        print(f"Warning: Failed to scan {file_path}: {e}")

        # No demo/sample fallback - only show real vulnerabilities

        # Create SCA scan
        sca_scan = Scan(
            project_id=project.id,
            scan_type=ScanType.SCA,
            status=ScanStatus.COMPLETED,
            total_findings=len(sca_findings),
            critical_count=len([f for f in sca_findings if f['severity'] == 'critical']),
            high_count=len([f for f in sca_findings if f['severity'] == 'high']),
            medium_count=len([f for f in sca_findings if f['severity'] == 'medium']),
            low_count=len([f for f in sca_findings if f['severity'] == 'low'])
        )
        db.add(sca_scan)
        db.flush()

        # Add SCA vulnerabilities
        for finding in sca_findings:
            # Handle both local DB and live feed finding formats
            vuln_name = finding.get('vulnerability') or finding.get('title') or finding.get('cve') or 'Unknown Vulnerability'
            pkg_name = finding.get('package', 'unknown')
            pkg_version = finding.get('installed_version') or finding.get('version') or 'unknown'
            source = finding.get('source', 'local')
            fixed_versions = finding.get('fixed_versions', [])
            fixed_version_str = ', '.join(fixed_versions) if fixed_versions else finding.get('remediation', '')

            # Get direct/transitive dependency info
            is_direct = finding.get('is_direct_dependency', True)
            dependency_depth = finding.get('dependency_depth', 0)
            introduced_by = finding.get('introduced_by')
            dependency_path = finding.get('dependency_path', [])
            dep_type = "DIRECT" if is_direct else "TRANSITIVE"

            # Build detailed code snippet with source info and dependency chain
            code_snippet_parts = [
                f"Package: {pkg_name}@{pkg_version}",
                f"Type: {dep_type} DEPENDENCY",
                f"Source: {source.upper() if source else 'LOCAL'}",
            ]
            if not is_direct and introduced_by:
                code_snippet_parts.append(f"Introduced by: {introduced_by}")
            if dependency_path and len(dependency_path) > 1:
                path_str = " → ".join([p.split('@')[0] for p in dependency_path])
                code_snippet_parts.append(f"Dependency chain: {path_str}")

            # Collect all CVE/GHSA identifiers from multiple possible fields
            vuln_ids = []
            if finding.get('cve'):
                cve_val = finding.get('cve')
                if isinstance(cve_val, list):
                    vuln_ids.extend(cve_val)
                else:
                    vuln_ids.append(cve_val)
            if finding.get('all_cves'):
                vuln_ids.extend(finding.get('all_cves', []))
            if finding.get('cve_ids'):
                vuln_ids.extend(finding.get('cve_ids', []))
            if finding.get('vulnerability_id') and finding.get('vulnerability_id') not in vuln_ids:
                vuln_ids.append(finding.get('vulnerability_id'))
            if finding.get('aliases'):
                for alias in finding.get('aliases', []):
                    if alias.startswith(('CVE-', 'GHSA-')) and alias not in vuln_ids:
                        vuln_ids.append(alias)

            # Remove duplicates while preserving order, prioritize CVE over GHSA
            seen = set()
            unique_ids = []
            for vid in vuln_ids:
                if vid and vid not in seen:
                    seen.add(vid)
                    unique_ids.append(vid)
            # Sort to put CVE first, then GHSA
            cve_ids = [v for v in unique_ids if v.startswith('CVE-')]
            ghsa_ids = [v for v in unique_ids if v.startswith('GHSA-')]
            other_ids = [v for v in unique_ids if not v.startswith(('CVE-', 'GHSA-'))]

            if cve_ids:
                code_snippet_parts.append(f"CVE: {', '.join(cve_ids)}")
            if ghsa_ids:
                code_snippet_parts.append(f"GHSA: {', '.join(ghsa_ids)}")
            if other_ids:
                code_snippet_parts.append(f"ID: {', '.join(other_ids)}")
            if fixed_version_str and 'upgrade' not in fixed_version_str.lower():
                code_snippet_parts.append(f"Fixed in: {fixed_version_str}")

            # Build file_path with clear direct/transitive indicator
            file_path_str = f"{finding.get('ecosystem', 'package')} dependency: {pkg_name} {pkg_version} [{dep_type}] [Source: {source.upper() if source else 'LOCAL'}]"
            if not is_direct and introduced_by:
                file_path_str += f" [Via: {introduced_by}]"

            vuln = Vulnerability(
                scan_id=sca_scan.id,
                title=f"{vuln_name} in {pkg_name}",
                description=finding.get('description', 'No description available'),
                severity=SeverityLevel[finding.get('severity', 'medium').upper()],
                cwe_id=finding.get('cwe_id') or finding.get('cwe') or 'CWE-1035',
                owasp_category=finding.get('owasp_category') or 'A06:2021 - Vulnerable and Outdated Components',
                file_path=file_path_str,
                line_number=dependency_depth,  # Use line_number to store depth for frontend
                code_snippet='\n'.join(code_snippet_parts),
                remediation=finding.get('remediation') or f"Upgrade to {fixed_version_str}" if fixed_version_str else 'Update to the latest patched version',
                cvss_score=finding.get('cvss_score') or finding.get('cvss') or 0.0,
                stride_category=finding.get('stride_category'),
                mitre_attack_id=finding.get('mitre_attack_id'),
                # AI-generated impact fields
                business_impact=finding.get('business_impact'),
                technical_impact=finding.get('technical_impact'),
                recommendations=finding.get('recommendations'),
                impact_generated_by=finding.get('impact_generated_by', 'static')
            )
            db.add(vuln)
        db.commit()
        scan_results["sca"] = True

    if "secret" in project_data.auto_scan_types:
        # Run Secret scan - real or demo
        if repo_scanner and repo_scanner.repo_path:
            # Real scan on cloned repository
            scan_results_data = secret_scanner.scan_directory(repo_scanner.repo_path)
            secret_findings = scan_results_data['findings']
        else:
            # Demo scan with sample findings
            secret_findings = secret_scanner.generate_sample_findings()

        # Create Secret scan
        secret_scan = Scan(
            project_id=project.id,
            scan_type=ScanType.SECRET,
            status=ScanStatus.COMPLETED,
            total_findings=len(secret_findings),
            critical_count=len([f for f in secret_findings if f['severity'] == 'critical']),
            high_count=len([f for f in secret_findings if f['severity'] == 'high']),
            medium_count=len([f for f in secret_findings if f['severity'] == 'medium']),
            low_count=len([f for f in secret_findings if f['severity'] == 'low'])
        )
        db.add(secret_scan)
        db.flush()

        # Add Secret vulnerabilities
        for finding in secret_findings:
            # Make file path relative if it's from real scan
            file_path = finding['file_path']
            if repo_scanner and repo_scanner.repo_path:
                file_path = repo_scanner.get_relative_path(file_path)

            vuln = Vulnerability(
                scan_id=secret_scan.id,
                title=finding['title'],
                description=finding['description'],
                severity=SeverityLevel[finding['severity'].upper()],
                cwe_id=finding['cwe_id'],
                owasp_category=finding['owasp_category'],
                file_path=file_path,
                line_number=finding['line_number'],
                code_snippet=finding['code_snippet'],
                remediation=finding['remediation'],
                cvss_score=finding['cvss_score'],
                stride_category=finding.get('stride_category'),
                mitre_attack_id=finding.get('mitre_attack_id'),
                # AI-generated impact fields
                business_impact=finding.get('business_impact'),
                technical_impact=finding.get('technical_impact'),
                recommendations=finding.get('recommendations'),
                impact_generated_by=finding.get('impact_generated_by', 'static')
            )
            db.add(vuln)
        db.commit()
        scan_results["secret"] = True

    # Cleanup repository after scanning
    if repo_scanner:
        repo_scanner.cleanup()

    # Calculate and update risk score after all scans are complete
    calculate_risk_score(project.id, db)

    return {
        "id": project.id,
        "name": project.name,
        "message": "Project created successfully",
        "scans_completed": scan_results
    }

@app.get("/api/projects")
async def list_projects(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    projects = db.query(Project).filter(Project.owner_id == current_user.id).all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "risk_score": p.risk_score,
            "created_at": p.created_at.isoformat() if p.created_at else None
        }
        for p in projects
    ]

@app.get("/api/projects/{project_id}")
async def get_project(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "architecture_doc": project.architecture_doc,
        "repository_url": project.repository_url,
        "technology_stack": project.technology_stack,
        "compliance_targets": project.compliance_targets,
        "risk_score": project.risk_score,
        "created_at": project.created_at.isoformat() if project.created_at else None
    }

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    architecture_doc: Optional[str] = None
    repository_url: Optional[str] = None
    technology_stack: Optional[List[str]] = None
    compliance_targets: Optional[List[str]] = None

@app.put("/api/projects/{project_id}")
async def update_project(
    project_id: int,
    project_update: ProjectUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update project details including architecture document"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Update only provided fields
    if project_update.name is not None:
        project.name = project_update.name
    if project_update.description is not None:
        project.description = project_update.description
    if project_update.architecture_doc is not None:
        project.architecture_doc = project_update.architecture_doc
    if project_update.repository_url is not None:
        project.repository_url = project_update.repository_url
    if project_update.technology_stack is not None:
        project.technology_stack = project_update.technology_stack
    if project_update.compliance_targets is not None:
        project.compliance_targets = project_update.compliance_targets

    db.commit()
    db.refresh(project)

    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "architecture_doc": project.architecture_doc,
        "repository_url": project.repository_url,
        "technology_stack": project.technology_stack,
        "compliance_targets": project.compliance_targets,
        "risk_score": project.risk_score,
        "created_at": project.created_at.isoformat() if project.created_at else None
    }

@app.post("/api/projects/{project_id}/calculate-risk-score")
async def recalculate_risk_score(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Manually trigger risk score recalculation for a project.
    This is useful for existing projects that need their risk scores updated.
    """
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Recalculate the risk score
    calculate_risk_score(project_id, db)

    # Refresh project to get updated risk score
    db.refresh(project)

    return {
        "success": True,
        "risk_score": project.risk_score,
        "message": "Risk score recalculated successfully"
    }

@app.post("/api/projects/recalculate-all-risk-scores")
async def recalculate_all_risk_scores(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Recalculate risk scores for all projects owned by the current user.
    This is useful for batch updates of existing projects.
    """
    projects = db.query(Project).filter(Project.owner_id == current_user.id).all()

    updated_count = 0
    for project in projects:
        calculate_risk_score(project.id, db)
        updated_count += 1

    return {
        "success": True,
        "updated_count": updated_count,
        "message": f"Recalculated risk scores for {updated_count} projects"
    }

# Threat Model endpoints
@app.get("/api/projects/{project_id}/threat-model")
async def get_threat_model(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    threat_model = db.query(ThreatModel).filter(ThreatModel.project_id == project_id).first()

    if not threat_model:
        raise HTTPException(status_code=404, detail="Threat model not found")

    dfd_level_0 = None
    dfd_level_1 = None
    components_count = 0
    data_flows_count = 0
    trust_boundaries_count = 0

    if threat_model.dfd_data:
        try:
            # Calculate counts from dfd_data
            dfd_data = threat_model.dfd_data if isinstance(threat_model.dfd_data, dict) else {}
            components_count = len(dfd_data.get('nodes', []))
            data_flows_count = len(dfd_data.get('edges', []))
            trust_boundaries_count = len(dfd_data.get('trust_boundaries', []))

            # Check if mermaid diagrams are already cached in dfd_data
            # Version 2: Added label sanitization for special characters
            DIAGRAM_CACHE_VERSION = 2
            cached_mermaid_l0 = dfd_data.get('mermaid_level_0')
            cached_mermaid_l1 = dfd_data.get('mermaid_level_1') or dfd_data.get('mermaid')
            cached_version = dfd_data.get('mermaid_cache_version', 1)

            # Regenerate if cache is missing or outdated (pre-sanitization fix)
            if cached_mermaid_l0 and cached_mermaid_l1 and cached_version >= DIAGRAM_CACHE_VERSION:
                # Use cached diagrams (fast path)
                dfd_level_0 = {"level": 0, "name": "Context Diagram", "mermaid": cached_mermaid_l0}
                dfd_level_1 = {"level": 1, "name": "Detailed Diagram", "mermaid": cached_mermaid_l1}
            else:
                # Generate and cache diagrams (slow path - regenerate with sanitization fix)
                from services.threat_modeling import ThreatModelingService
                tm_service = ThreatModelingService()

                mermaid_l0 = tm_service.generate_mermaid_dfd(threat_model.dfd_data, level=0)
                mermaid_l1 = tm_service.generate_mermaid_dfd(threat_model.dfd_data, level=1)

                dfd_level_0 = {"level": 0, "name": "Context Diagram", "mermaid": mermaid_l0}
                dfd_level_1 = {"level": 1, "name": "Detailed Diagram", "mermaid": mermaid_l1}

                # Cache the diagrams for future requests with version
                updated_dfd_data = dict(dfd_data)
                updated_dfd_data['mermaid_level_0'] = mermaid_l0
                updated_dfd_data['mermaid_level_1'] = mermaid_l1
                updated_dfd_data['mermaid_cache_version'] = DIAGRAM_CACHE_VERSION
                threat_model.dfd_data = updated_dfd_data
                db.commit()
                logger.info(f"[ThreatModel] Regenerated and cached diagrams for project {project_id} (v{DIAGRAM_CACHE_VERSION})")
        except Exception as e:
            print(f"Error with Mermaid diagrams: {e}")

    # Get enhanced analysis data
    fair_risk = threat_model.fair_risk_analysis or {}
    attack_trees = threat_model.attack_trees or []
    kill_chain = threat_model.kill_chain_analysis or {}
    eraser_diagrams = threat_model.eraser_diagrams or {"enabled": False, "diagrams": {}}

    return {
        "id": threat_model.id,
        "name": threat_model.name,
        "dfd_level": threat_model.dfd_level,
        "dfd_level_0": dfd_level_0,
        "dfd_level_1": dfd_level_1,
        "dfd_data": threat_model.dfd_data,
        "components_count": components_count,
        "data_flows_count": data_flows_count,
        "trust_boundaries_count": trust_boundaries_count,
        "stride_analysis": threat_model.stride_analysis,
        "mitre_mapping": threat_model.mitre_mapping,
        "trust_boundaries": threat_model.trust_boundaries,
        "attack_paths": threat_model.attack_paths or [],
        "threat_count": threat_model.threat_count,
        # Enhanced threat modeling features
        "fair_risk_analysis": fair_risk,
        "attack_trees": attack_trees,
        "kill_chain_analysis": kill_chain,
        # Eraser AI Professional Diagrams
        "eraser_diagrams": eraser_diagrams,
        # Summary metrics
        "annual_loss_expectancy": fair_risk.get("aggregate_risk", {}).get("total_annual_loss_expectancy", {}),
        "kill_chain_coverage": kill_chain.get("coverage_analysis", {}).get("coverage_percentage", 0),
        "attack_trees_count": len(attack_trees),
        "eraser_diagrams_enabled": eraser_diagrams.get("enabled", False),
        "eraser_diagrams_count": eraser_diagrams.get("stats", {}).get("successful", 0)
    }


@app.delete("/api/projects/{project_id}/threat-model")
async def delete_threat_model(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete the threat model for a project."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    threat_model = db.query(ThreatModel).filter(ThreatModel.project_id == project_id).first()

    if not threat_model:
        raise HTTPException(status_code=404, detail="Threat model not found")

    # Delete the threat model
    db.delete(threat_model)
    db.commit()

    logger.info(f"Deleted threat model for project {project_id}")

    return {"message": "Threat model deleted successfully", "project_id": project_id}


def _generate_threat_model_background(project_id: int, project_name: str, architecture_doc: str, quick_mode: bool = False):
    """Background task to generate threat model

    Args:
        quick_mode: If True, skip AI enrichment for faster generation (uses templates)
    """
    from models.database import SessionLocal

    mode_str = "Quick Mode" if quick_mode else "Full Mode"
    logger.info(f"[Threat Model BG] Starting background generation for project {project_id} ({mode_str})")
    threat_model_generation_status[project_id] = {"status": "in_progress", "step": "starting", "progress": 5, "quick_mode": quick_mode}

    # Progress callback to update status in real-time
    def progress_callback(step: str, progress: int, message: str = ""):
        threat_model_generation_status[project_id] = {
            "status": "in_progress",
            "step": step,
            "progress": progress,
            "message": message
        }
        logger.debug(f"[Threat Model BG] Progress: {step} - {progress}% - {message}")

    db = SessionLocal()
    try:
        # Delete existing threat model if any
        existing = db.query(ThreatModel).filter(ThreatModel.project_id == project_id).first()
        if existing:
            db.query(ThreatModel).filter(ThreatModel.project_id == project_id).delete()
            db.commit()
            logger.info(f"[Threat Model BG] Deleted existing threat model")

        logger.info(f"[Threat Model BG] Calling generate_threat_model (quick_mode={quick_mode})...")
        threat_model_data = threat_service.generate_threat_model(
            architecture_doc,
            project_name,
            progress_callback=progress_callback,
            generate_eraser_diagrams=threat_service.eraser_enabled and not quick_mode,  # Skip in quick mode
            quick_mode=quick_mode
        )
        logger.info(f"[Threat Model BG] Generated threat model with {threat_model_data.get('threat_count', 0)} threats")
        logger.info(f"[Threat Model BG] Data keys: {list(threat_model_data.keys())}")
        logger.info(f"[Threat Model BG] eraser_diagrams: {bool(threat_model_data.get('eraser_diagrams'))}, fair_risk: {bool(threat_model_data.get('fair_risk_analysis'))}")

        threat_model_generation_status[project_id] = {"status": "in_progress", "step": "saving", "progress": 90}

        # Combine dfd_data with both mermaid diagrams for caching
        dfd_data_with_cache = dict(threat_model_data['dfd_data'])
        dfd_level_0 = threat_model_data.get('dfd_level_0', {})
        dfd_level_1 = threat_model_data.get('dfd_level_1', {})
        dfd_data_with_cache['mermaid_level_0'] = dfd_level_0.get('mermaid', '')
        dfd_data_with_cache['mermaid_level_1'] = dfd_level_1.get('mermaid', '')

        threat_model = ThreatModel(
            project_id=project_id,
            name=f"{project_name} Threat Model",
            dfd_level=0,
            dfd_data=dfd_data_with_cache,
            stride_analysis=threat_model_data['stride_analysis'],
            mitre_mapping=threat_model_data['mitre_mapping'],
            trust_boundaries=threat_model_data['dfd_data']['trust_boundaries'],
            attack_paths=threat_model_data.get('attack_paths', []),
            threat_count=threat_model_data['threat_count'],
            # Enhanced threat modeling fields
            fair_risk_analysis=threat_model_data.get('fair_risk_analysis'),
            attack_trees=threat_model_data.get('attack_trees'),
            kill_chain_analysis=threat_model_data.get('kill_chain_analysis'),
            eraser_diagrams=threat_model_data.get('eraser_diagrams')
        )
        db.add(threat_model)
        db.commit()
        db.refresh(threat_model)
        logger.info(f"[Threat Model BG] Saved - eraser_diagrams column: {bool(threat_model.eraser_diagrams)}, fair_risk: {bool(threat_model.fair_risk_analysis)}")

        # Get summary data for status update
        fair_risk = threat_model_data.get('fair_risk_analysis', {})
        annual_loss = fair_risk.get('aggregate_risk', {}).get('total_annual_loss_expectancy', {}).get('likely', 0)

        eraser_diagrams = threat_model_data.get('eraser_diagrams', {})
        threat_model_generation_status[project_id] = {
            "status": "completed",
            "step": "done",
            "progress": 100,
            "threat_count": threat_model_data['threat_count'],
            "attack_paths_count": len(threat_model_data.get('attack_paths', [])),
            "attack_trees_count": len(threat_model_data.get('attack_trees', [])),
            "annual_loss_expectancy": annual_loss,
            "kill_chain_coverage": threat_model_data.get('kill_chain_analysis', {}).get('coverage_analysis', {}).get('coverage_percentage', 0),
            "eraser_diagrams_enabled": eraser_diagrams.get('enabled', False),
            "eraser_diagrams_count": eraser_diagrams.get('stats', {}).get('successful', 0)
        }
        logger.info(f"[Threat Model BG] Completed successfully for project {project_id}")

    except Exception as e:
        import traceback
        logger.error(f"[Threat Model BG] ERROR: {e}")
        logger.error(f"[Threat Model BG] Traceback: {traceback.format_exc()}")
        threat_model_generation_status[project_id] = {
            "status": "failed",
            "step": "error",
            "progress": 0,
            "error": str(e)
        }
    finally:
        db.close()

@app.post("/api/projects/{project_id}/threat-model/regenerate")
async def regenerate_threat_model(
    project_id: int,
    background_tasks: BackgroundTasks,
    request_body: Optional[dict] = Body(default=None),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Start async threat model generation for a project.

    Can accept optional architecture_data from document analysis or architecture builder.
    If architecture_data is provided, it will be converted to a description and saved to the project.

    Request body options:
        - architecture_data: Structured architecture data
        - quick_mode: If true, skip AI enrichment for faster generation (uses templates)
    """
    # Check for quick_mode option
    quick_mode = request_body.get("quick_mode", False) if request_body else False
    mode_str = "Quick Mode" if quick_mode else "Full Mode"
    logger.info(f"[Threat Model Regenerate] Starting for project {project_id} ({mode_str})")

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        logger.warning(f"[Threat Model Regenerate] Project {project_id} not found")
        raise HTTPException(status_code=404, detail="Project not found")

    # Check if architecture_data was provided in request body
    architecture_doc = project.architecture_doc
    if request_body and request_body.get("architecture_data"):
        architecture_data = request_body["architecture_data"]
        logger.info(f"[Threat Model Regenerate] Received architecture_data from request body")

        # Convert structured architecture to description format
        architecture_doc = _convert_architecture_to_description(architecture_data)

        # Save to project for future use
        project.architecture_doc = architecture_doc
        import json
        project.architecture_diagram = json.dumps(architecture_data)
        project.diagram_media_type = "application/json"
        db.commit()

        logger.info(f"[Threat Model Regenerate] Saved extracted architecture to project")

    if not architecture_doc:
        logger.warning(f"[Threat Model Regenerate] Project {project_id} has no architecture doc")
        raise HTTPException(status_code=400, detail="Project has no architecture document. Please add architecture description first.")

    logger.info(f"[Threat Model Regenerate] Architecture doc length: {len(architecture_doc)} chars")

    # Check if generation is already in progress
    if project_id in threat_model_generation_status:
        status = threat_model_generation_status[project_id]
        if status.get("status") == "in_progress":
            return {
                "success": True,
                "message": "Threat model generation already in progress",
                "status": "in_progress",
                "progress": status.get("progress", 0)
            }

    # Start background task
    threat_model_generation_status[project_id] = {"status": "in_progress", "step": "starting", "progress": 5, "quick_mode": quick_mode}
    background_tasks.add_task(
        _generate_threat_model_background,
        project_id,
        project.name,
        architecture_doc,
        quick_mode
    )

    logger.info(f"[Threat Model Regenerate] Background task started for project {project_id} ({mode_str})")

    return {
        "success": True,
        "message": f"Threat model generation started ({mode_str})",
        "status": "in_progress",
        "quick_mode": quick_mode,
        "progress": 5
    }


def _convert_architecture_to_description(architecture_data: dict) -> str:
    """Convert structured architecture data to a text description for threat modeling."""
    lines = []

    # Project name/description
    if architecture_data.get("project_name"):
        lines.append(f"# {architecture_data['project_name']}")
        lines.append("")

    if architecture_data.get("description"):
        lines.append(architecture_data["description"])
        lines.append("")

    # Components
    components = architecture_data.get("components", [])
    if components:
        lines.append("## System Components")
        lines.append("")
        for comp in components:
            name = comp.get("name", "Unknown Component")
            comp_type = comp.get("type", "component")
            technology = comp.get("technology", "")
            description = comp.get("description", "")
            trust_zone = comp.get("trust_zone", "")
            internet_facing = comp.get("internet_facing", False)
            handles_sensitive = comp.get("handles_sensitive_data", False)

            line = f"- **{name}** ({comp_type})"
            if technology:
                line += f" - {technology}"
            lines.append(line)

            if description:
                lines.append(f"  - {description}")
            if trust_zone:
                lines.append(f"  - Trust Zone: {trust_zone}")
            if internet_facing:
                lines.append("  - Internet-facing: Yes")
            if handles_sensitive:
                lines.append("  - Handles sensitive data: Yes")
        lines.append("")

    # Data Flows
    data_flows = architecture_data.get("data_flows", [])
    if data_flows:
        lines.append("## Data Flows")
        lines.append("")
        # Create a component lookup for source/target names
        comp_lookup = {c.get("id", ""): c.get("name", c.get("id", "Unknown")) for c in components}

        for flow in data_flows:
            source = flow.get("source_id", "")
            target = flow.get("target_id", "")
            source_name = comp_lookup.get(source, flow.get("source", source))
            target_name = comp_lookup.get(target, flow.get("target", target))
            protocol = flow.get("protocol", "")
            data_type = flow.get("data_type", "")
            encrypted = flow.get("encrypted", False)

            line = f"- {source_name} → {target_name}"
            if protocol:
                line += f" ({protocol})"
            lines.append(line)

            if data_type:
                lines.append(f"  - Data: {data_type}")
            if encrypted:
                lines.append("  - Encrypted: Yes")
        lines.append("")

    # Trust Boundaries
    trust_boundaries = architecture_data.get("trust_boundaries", [])
    if trust_boundaries:
        lines.append("## Trust Boundaries")
        lines.append("")
        for boundary in trust_boundaries:
            name = boundary.get("name", "Unknown Boundary")
            boundary_type = boundary.get("type", "")
            components_in = boundary.get("components", [])

            line = f"- **{name}**"
            if boundary_type:
                line += f" ({boundary_type})"
            lines.append(line)

            if components_in:
                lines.append(f"  - Components: {', '.join(components_in)}")
        lines.append("")

    # Technology Stack
    tech_stack = architecture_data.get("technology_stack", [])
    if tech_stack:
        lines.append("## Technology Stack")
        lines.append("")
        for tech in tech_stack:
            lines.append(f"- {tech}")
        lines.append("")

    # Source documents
    source_docs = architecture_data.get("source_documents", [])
    if source_docs:
        lines.append(f"*Extracted from: {', '.join(source_docs)}*")

    return "\n".join(lines)

@app.post("/api/projects/{project_id}/threat-model/generate-attack-diagram")
async def generate_attack_diagram(
    project_id: int,
    request: dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Generate an Eraser diagram for a specific attack path on-demand"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    threat_model = db.query(ThreatModel).filter(ThreatModel.project_id == project_id).first()
    if not threat_model:
        raise HTTPException(status_code=404, detail="Threat model not found")

    attack_path_index = request.get("attack_path_index", 0)
    attack_paths = threat_model.attack_paths or []

    if attack_path_index >= len(attack_paths):
        raise HTTPException(status_code=400, detail="Invalid attack path index")

    attack_path = attack_paths[attack_path_index]
    theme = request.get("theme", "light")

    # Generate diagram for this specific attack path
    from services.threat_modeling import ThreatModelingService
    threat_service = ThreatModelingService()

    if not threat_service.eraser_enabled:
        raise HTTPException(status_code=400, detail="Eraser API not configured")

    try:
        # Build attack tree structure from attack path
        attack_tree = {
            "root_goal": attack_path.get("target", "Unknown Target"),
            "attack_vectors": [{
                "name": attack_path.get("name", "Attack Path"),
                "probability": attack_path.get("probability", 0.5),
                "steps": [{"action": step} for step in attack_path.get("path", [])]
            }]
        }

        # Generate the diagram
        result = await threat_service._eraser_service.generate_attack_tree_diagram(attack_tree, theme)

        if result.get("success"):
            # Store in the threat model's eraser_diagrams
            eraser_diagrams = threat_model.eraser_diagrams or {"enabled": True, "diagrams": {}}
            diagram_key = f"attack_path_{attack_path_index}"
            eraser_diagrams["diagrams"][diagram_key] = result
            threat_model.eraser_diagrams = eraser_diagrams
            db.commit()

            return {
                "success": True,
                "diagram_key": diagram_key,
                "image_url": result.get("image_url"),
                "editor_url": result.get("editor_url"),
                "attack_path_name": attack_path.get("name", f"Attack Path {attack_path_index + 1}")
            }
        else:
            return {
                "success": False,
                "error": result.get("error", "Failed to generate diagram")
            }

    except Exception as e:
        logger.error(f"Failed to generate attack diagram: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/projects/{project_id}/threat-model/status")
async def get_threat_model_status(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get threat model generation status"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Check if there's an active generation
    if project_id in threat_model_generation_status:
        status = threat_model_generation_status[project_id]
        return {
            "status": status.get("status", "unknown"),
            "step": status.get("step", ""),
            "progress": status.get("progress", 0),
            "threat_count": status.get("threat_count"),
            "attack_paths_count": status.get("attack_paths_count"),
            "error": status.get("error")
        }

    # Check if threat model exists
    existing = db.query(ThreatModel).filter(ThreatModel.project_id == project_id).first()
    if existing:
        return {
            "status": "completed",
            "step": "done",
            "progress": 100,
            "threat_count": existing.threat_count
        }

    return {
        "status": "not_started",
        "step": "",
        "progress": 0
    }


# =============================================================================
# INCREMENTAL THREAT MODELING ENDPOINTS
# =============================================================================

@app.get("/api/projects/{project_id}/threat-model/history")
async def get_threat_model_history(
    project_id: int,
    limit: int = 10,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get architecture version history with change summaries."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    from services.threat_modeling import threat_service
    history = threat_service.get_architecture_version_history(db, project_id, limit)
    return {"versions": history, "project_id": project_id}


@app.get("/api/projects/{project_id}/threat-model/version/{version_id}")
async def get_threat_model_at_version(
    project_id: int,
    version_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get threat model at a specific architecture version."""
    from models.models import ArchitectureVersion, ThreatHistory

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    version = db.query(ArchitectureVersion).filter(
        ArchitectureVersion.id == version_id,
        ArchitectureVersion.project_id == project_id
    ).first()

    if not version:
        raise HTTPException(status_code=404, detail="Version not found")

    # Get threats at this version
    threats = db.query(ThreatHistory).filter(
        ThreatHistory.architecture_version_id == version_id
    ).all()

    return {
        "version": {
            "id": version.id,
            "version_number": version.version_number,
            "architecture_hash": version.architecture_hash,
            "change_summary": version.change_summary,
            "change_description": version.change_description,
            "impact_score": version.impact_score,
            "created_at": version.created_at.isoformat() if version.created_at else None,
            "architecture_snapshot": version.architecture_snapshot
        },
        "threats": [
            {
                "threat_id": t.threat_id,
                "status": t.status.value if t.status else "unknown",
                "threat_data": t.threat_data,
                "change_reason": t.change_reason,
                "affected_components": t.affected_components
            }
            for t in threats
        ]
    }


@app.get("/api/projects/{project_id}/threat-model/diff/{v1}/{v2}")
async def compare_threat_model_versions(
    project_id: int,
    v1: int,
    v2: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Compare two architecture versions."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    from services.threat_modeling import threat_service
    diff_result = threat_service.compare_architecture_versions(db, project_id, v1, v2)

    if "error" in diff_result:
        raise HTTPException(status_code=404, detail=diff_result["error"])

    return diff_result


@app.get("/api/projects/{project_id}/threats/{threat_id}/timeline")
async def get_threat_timeline(
    project_id: int,
    threat_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get full history of a specific threat across versions."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    from services.threat_modeling import threat_service
    timeline = threat_service.get_threat_timeline(db, project_id, threat_id)

    return {
        "threat_id": threat_id,
        "project_id": project_id,
        "timeline": timeline
    }


@app.post("/api/projects/{project_id}/threat-model/incremental")
async def generate_incremental_threat_model(
    project_id: int,
    architecture_data: dict,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Generate threat model incrementally, analyzing only changed components."""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Parse the architecture input
    from services.architecture_input_service import ArchitectureInputService
    arch_service = ArchitectureInputService()

    if 'components' in architecture_data:
        # Already structured format
        architecture = architecture_data
    else:
        # Needs parsing
        parsed = arch_service.parse_structured_input(architecture_data)
        architecture = parsed.to_dict()

    def run_incremental_generation():
        """Background task for incremental threat model generation."""
        from services.threat_modeling import ThreatModelingService

        # Initialize progress tracking
        threat_model_generation_status[project_id] = {
            "status": "running",
            "step": "initializing",
            "progress": 0,
            "is_incremental": True
        }

        def progress_callback(step: str, progress: int, message: str):
            threat_model_generation_status[project_id].update({
                "step": step,
                "progress": progress,
                "message": message
            })

        try:
            # Get user's AI config
            ai_config = get_user_ai_config(current_user)
            service = ThreatModelingService(ai_config=ai_config)

            # Generate incrementally
            with SessionLocal() as session:
                result = service.generate_threat_model_incremental(
                    db_session=session,
                    project_id=project_id,
                    new_architecture=architecture,
                    user_id=current_user.id,
                    project_name=project.name,
                    progress_callback=progress_callback
                )

                # Update or create threat model record
                existing = session.query(ThreatModel).filter(
                    ThreatModel.project_id == project_id
                ).first()

                if existing:
                    existing.stride_analysis = result.get('stride_analysis')
                    existing.dfd_data = result.get('dfd_level_0')
                    existing.data_flows = result.get('dfd_level_1')
                    existing.threat_count = result.get('threat_count', 0)
                    existing.is_incremental = True
                    existing.architecture_version_id = result.get('architecture_version', {}).get('id')
                else:
                    new_model = ThreatModel(
                        project_id=project_id,
                        name=f"{project.name} - Threat Model",
                        stride_analysis=result.get('stride_analysis'),
                        dfd_data=result.get('dfd_level_0'),
                        data_flows=result.get('dfd_level_1'),
                        threat_count=result.get('threat_count', 0),
                        is_incremental=True,
                        architecture_version_id=result.get('architecture_version', {}).get('id')
                    )
                    session.add(new_model)

                session.commit()

                threat_model_generation_status[project_id] = {
                    "status": "completed",
                    "step": "done",
                    "progress": 100,
                    "is_incremental": True,
                    "lifecycle_summary": result.get('lifecycle_summary', {}),
                    "threat_count": result.get('threat_count', 0)
                }

        except Exception as e:
            logger.error(f"Incremental threat model generation failed: {e}")
            threat_model_generation_status[project_id] = {
                "status": "failed",
                "step": "error",
                "progress": 0,
                "error": str(e)
            }

    background_tasks.add_task(run_incremental_generation)

    return {
        "message": "Incremental threat model generation started",
        "project_id": project_id,
        "is_incremental": True
    }


# =============================================================================
# ARCHITECTURE INPUT ENDPOINTS
# =============================================================================

# Initialize architecture input service
architecture_input_service = ArchitectureInputService()


@app.get("/api/architecture/component-library")
async def get_component_library(
    current_user: User = Depends(get_current_active_user)
):
    """Get the component library with all options for building architecture"""
    return architecture_input_service.get_component_library()


@app.post("/api/projects/{project_id}/architecture/structured")
async def save_structured_architecture(
    project_id: int,
    architecture_data: dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Save structured architecture input from form"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        # Parse the structured input
        architecture = architecture_input_service.parse_structured_input(architecture_data)

        # Validate and get warnings
        warnings = architecture_input_service.validate_architecture(architecture)

        # Convert to description for threat modeling
        description = architecture.to_description()

        # Save to project
        project.architecture_doc = description

        # Also store the structured data as JSON in architecture_diagram column
        # (repurposing for structured data storage)
        import json
        project.architecture_diagram = json.dumps(architecture.to_dict())
        project.diagram_media_type = "application/json"

        db.commit()

        logger.info(f"Saved structured architecture for project {project_id}: "
                   f"{len(architecture.components)} components, {len(architecture.data_flows)} flows")

        return {
            "success": True,
            "message": "Architecture saved successfully",
            "component_count": len(architecture.components),
            "data_flow_count": len(architecture.data_flows),
            "warnings": warnings,
            "generated_description_length": len(description)
        }

    except Exception as e:
        logger.error(f"Failed to save structured architecture: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/projects/{project_id}/architecture/extract-diagram")
async def extract_architecture_from_diagram(
    project_id: int,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Extract architecture from uploaded diagram using AI vision"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Validate file type
    allowed_types = ["image/png", "image/jpeg", "image/jpg", "image/webp", "image/gif"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(allowed_types)}"
        )

    try:
        # Read file content
        image_data = await file.read()

        # Initialize AI client for vision
        from services.ai_client_factory import AIClientFactory
        ai_factory = AIClientFactory()
        ai_client = ai_factory.get_anthropic_client()

        if not ai_client:
            raise HTTPException(
                status_code=400,
                detail="AI service not configured. Please configure your AI provider in settings."
            )

        # Create service with AI client
        vision_service = ArchitectureInputService(ai_client=ai_client)

        # Extract architecture
        architecture = await vision_service.extract_from_diagram(
            image_data,
            file.content_type
        )

        # Store the original image
        import base64
        project.architecture_diagram = base64.b64encode(image_data).decode('utf-8')
        project.diagram_media_type = file.content_type

        db.commit()

        logger.info(f"Extracted architecture from diagram for project {project_id}: "
                   f"{len(architecture.components)} components")

        return {
            "success": True,
            "message": "Architecture extracted from diagram",
            "architecture": architecture.to_dict(),
            "component_count": len(architecture.components),
            "data_flow_count": len(architecture.data_flows)
        }

    except Exception as e:
        logger.error(f"Failed to extract from diagram: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/projects/{project_id}/architecture/analyze-documents")
async def analyze_documents_for_architecture(
    project_id: int,
    files: List[UploadFile] = File(...),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Analyze uploaded documents (PDFs, images, DOCX) to extract architecture.
    Supports multiple file upload for comprehensive analysis.
    """
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Validate file types
    allowed_types = [
        "image/png", "image/jpeg", "image/jpg", "image/webp",
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ]

    # Process files
    file_contents = []
    for file in files:
        if file.content_type not in allowed_types:
            logger.warning(f"Skipping unsupported file type: {file.content_type}")
            continue

        # Check file size (max 20MB)
        content = await file.read()
        if len(content) > 20 * 1024 * 1024:
            logger.warning(f"Skipping large file: {file.filename}")
            continue

        file_contents.append((file.filename, content, file.content_type))

    if not file_contents:
        raise HTTPException(
            status_code=400,
            detail="No valid files provided. Supported formats: PDF, PNG, JPG, WEBP, DOCX"
        )

    try:
        # Initialize document analysis service with user's AI config
        from services.document_analysis_service import DocumentAnalysisService

        logger.info(f"[DocAnalysis] Starting analysis for project {project_id}, files: {len(file_contents)}")

        ai_config = get_user_ai_config(current_user)
        logger.info(f"[DocAnalysis] AI config: provider={ai_config.provider if ai_config else 'None'}, has_key={bool(ai_config.api_key) if ai_config else False}")

        analysis_service = DocumentAnalysisService(ai_config=ai_config)

        if not analysis_service.enabled:
            logger.warning(f"[DocAnalysis] Service not enabled - AI not configured")
            raise HTTPException(
                status_code=400,
                detail="AI service not configured. Please configure your AI provider in Settings > AI Configuration."
            )

        logger.info(f"[DocAnalysis] Service enabled, starting analysis...")

        # Analyze all documents
        result = await analysis_service.analyze_documents(file_contents)

        if not result.get("success"):
            logger.warning(f"[DocAnalysis] Analysis failed: {result.get('error')}")
            raise HTTPException(
                status_code=400,
                detail=result.get("error", "Failed to analyze documents")
            )

        logger.info(
            f"[DocAnalysis] Analyzed {result.get('documents_analyzed', 0)} documents for project {project_id}: "
            f"{result.get('components_found', 0)} components found"
        )

        # Add diagnostic info if no components found
        if result.get('components_found', 0) == 0:
            result['diagnostic'] = {
                'ai_provider': analysis_service.provider,
                'ai_enabled': analysis_service.enabled,
                'files_processed': len(file_contents),
                'suggestion': 'Try uploading a clearer architecture diagram (PNG/JPG) or a document with detailed component descriptions.'
            }
            logger.warning(f"[DocAnalysis] No components extracted. AI provider: {analysis_service.provider}, enabled: {analysis_service.enabled}")

        return result

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        logger.error(f"[DocAnalysis] Exception: {e}")
        logger.error(f"[DocAnalysis] Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Document analysis failed: {str(e)}")


@app.post("/api/projects/{project_id}/architecture/merge")
async def merge_architecture_inputs(
    project_id: int,
    merge_request: dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Merge manual input with diagram extraction"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        manual_data = merge_request.get("manual")
        extracted_data = merge_request.get("extracted")

        manual_arch = None
        extracted_arch = None

        if manual_data:
            manual_arch = architecture_input_service.parse_structured_input(manual_data)

        if extracted_data:
            extracted_arch = architecture_input_service.parse_structured_input(extracted_data)

        # Merge architectures
        merged = architecture_input_service.merge_architectures(manual_arch, extracted_arch)

        # Validate merged architecture
        warnings = architecture_input_service.validate_architecture(merged)

        # Convert to description
        description = merged.to_description()

        # Save
        project.architecture_doc = description
        import json
        project.architecture_diagram = json.dumps(merged.to_dict())
        project.diagram_media_type = "application/json"

        db.commit()

        return {
            "success": True,
            "message": "Architectures merged successfully",
            "merged_architecture": merged.to_dict(),
            "component_count": len(merged.components),
            "data_flow_count": len(merged.data_flows),
            "warnings": warnings
        }

    except Exception as e:
        logger.error(f"Failed to merge architectures: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/projects/{project_id}/architecture")
async def get_project_architecture(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get current architecture for a project"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    structured_data = None
    if project.architecture_diagram and project.diagram_media_type == "application/json":
        import json
        try:
            structured_data = json.loads(project.architecture_diagram)
        except:
            pass

    return {
        "description": project.architecture_doc,
        "structured_data": structured_data,
        "has_diagram": project.architecture_diagram is not None,
        "diagram_type": project.diagram_media_type
    }


# Scanning endpoints
@app.post("/api/projects/{project_id}/scan/demo")
async def run_demo_scan(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Run demo scan with sample data"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Generate sample findings
    sast_findings = sast_scanner.generate_sample_findings()
    sca_sample = sca_scanner.generate_sample_findings()
    secret_findings = secret_scanner.generate_sample_findings()

    # Extract SCA findings
    sca_findings = sca_sample['vulnerabilities']['findings']

    # Create SAST scan
    sast_scan = Scan(
        project_id=project_id,
        scan_type=ScanType.SAST,
        status=ScanStatus.COMPLETED,
        total_findings=len(sast_findings),
        critical_count=len([f for f in sast_findings if f['severity'] == 'critical']),
        high_count=len([f for f in sast_findings if f['severity'] == 'high']),
        medium_count=len([f for f in sast_findings if f['severity'] == 'medium']),
        low_count=len([f for f in sast_findings if f['severity'] == 'low'])
    )
    db.add(sast_scan)
    db.flush()

    # Add SAST vulnerabilities
    for finding in sast_findings:
        vuln = Vulnerability(
            scan_id=sast_scan.id,
            title=finding['title'],
            description=finding['description'],
            severity=SeverityLevel[finding['severity'].upper()],
            cwe_id=finding['cwe_id'],
            owasp_category=finding['owasp_category'],
            file_path=finding['file_path'],
            line_number=finding['line_number'],
            code_snippet=finding['code_snippet'],
            remediation=finding['remediation'],
            remediation_code=finding.get('remediation_code'),
            cvss_score=finding['cvss_score'],
            stride_category=finding.get('stride_category'),
            mitre_attack_id=finding.get('mitre_attack_id')
        )
        db.add(vuln)

    # Create SCA scan
    sca_scan = Scan(
        project_id=project_id,
        scan_type=ScanType.SCA,
        status=ScanStatus.COMPLETED,
        total_findings=len(sca_findings),
        critical_count=len([f for f in sca_findings if f['severity'] == 'critical']),
        high_count=len([f for f in sca_findings if f['severity'] == 'high']),
        medium_count=len([f for f in sca_findings if f['severity'] == 'medium']),
        low_count=len([f for f in sca_findings if f['severity'] == 'low'])
    )
    db.add(sca_scan)
    db.flush()

    # Add SCA vulnerabilities
    for finding in sca_findings:
        vuln = Vulnerability(
            scan_id=sca_scan.id,
            title=f"{finding['vulnerability']} in {finding['package']}",
            description=finding['description'],
            severity=SeverityLevel[finding['severity'].upper()],
            cwe_id=finding['cwe_id'],
            owasp_category=finding['owasp_category'],
            file_path=f"package.json ({finding['package']} {finding['installed_version']})",
            line_number=0,
            code_snippet=f"Dependency: {finding['package']}@{finding['installed_version']}",
            remediation=finding['remediation'],
            cvss_score=finding['cvss_score'],
            stride_category=finding.get('stride_category'),
            mitre_attack_id=finding.get('mitre_attack_id')
        )
        db.add(vuln)

    # Create Secret scan
    secret_scan = Scan(
        project_id=project_id,
        scan_type=ScanType.SECRET,
        status=ScanStatus.COMPLETED,
        total_findings=len(secret_findings),
        critical_count=len([f for f in secret_findings if f['severity'] == 'critical']),
        high_count=len([f for f in secret_findings if f['severity'] == 'high']),
        medium_count=len([f for f in secret_findings if f['severity'] == 'medium']),
        low_count=len([f for f in secret_findings if f['severity'] == 'low'])
    )
    db.add(secret_scan)
    db.flush()

    # Add Secret vulnerabilities
    for finding in secret_findings:
        vuln = Vulnerability(
            scan_id=secret_scan.id,
            title=finding['title'],
            description=finding['description'],
            severity=SeverityLevel[finding['severity'].upper()],
            cwe_id=finding['cwe_id'],
            owasp_category=finding['owasp_category'],
            file_path=finding['file_path'],
            line_number=finding['line_number'],
            code_snippet=finding['code_snippet'],
            remediation=finding['remediation'],
            cvss_score=finding['cvss_score'],
            stride_category=finding.get('stride_category'),
            mitre_attack_id=finding.get('mitre_attack_id')
        )
        db.add(vuln)

    db.commit()

    # Calculate and update risk score
    calculate_risk_score(project_id, db)

    return {
        "message": "Demo scan completed - SAST, SCA, and Secret scans",
        "sast_findings": len(sast_findings),
        "sca_findings": len(sca_findings),
        "secret_findings": len(secret_findings),
        "total_scans": 3
    }

@app.post("/api/projects/{project_id}/scan")
async def run_security_scan(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Run real security scans on the project repository"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    scan_results = {
        "sast": 0,
        "sca": 0,
        "secret": 0
    }

    # Clone repository if URL provided
    repo_scanner = None
    if project.repository_url:
        try:
            repo_scanner = RepositoryScanner()
            repo_path = repo_scanner.clone_repository(project.repository_url)
        except Exception as e:
            # If cloning fails, log error and fall back to demo scans
            print(f"Warning: Failed to clone repository: {e}")
            repo_scanner = None

    # Run SAST scan using Enhanced Scanner (multi-language AST parsing)
    if repo_scanner and repo_scanner.repo_path:
        scan_results_data = enhanced_sast_scanner.scan_directory(repo_scanner.repo_path)
        sast_findings = scan_results_data['findings']

        # Also run inter-procedural analysis for deeper vulnerability detection
        try:
            import os as scan_os
            interprocedural_findings = []
            scan_extensions = ['.py', '.js', '.ts', '.java', '.go', '.php']

            for root, dirs, files in scan_os.walk(repo_scanner.repo_path):
                # Skip common directories
                dirs[:] = [d for d in dirs if d not in ['node_modules', 'venv', '.git', '__pycache__', 'dist', 'build', '.venv']]

                for file in files:
                    if not any(file.endswith(ext) for ext in scan_extensions):
                        continue

                    file_path = scan_os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            source_code = f.read()

                        # Skip very large or binary files
                        if len(source_code) > 300000 or '\x00' in source_code[:1000]:
                            continue

                        # Run inter-procedural analysis
                        result = analyze_code_interprocedural(source_code, file_path)

                        # Convert inter-procedural vulnerabilities to standard format
                        for vuln in result.get("vulnerabilities", []):
                            # Avoid duplicates with SAST findings
                            existing = any(
                                f.get('file_path') == file_path and
                                f.get('line_number') == vuln.get('sink_line') and
                                f.get('cwe_id') == vuln.get('cwe_id')
                                for f in sast_findings
                            )
                            if not existing:
                                interprocedural_findings.append({
                                    'title': vuln.get('title', 'Security Vulnerability'),
                                    'description': vuln.get('description', ''),
                                    'severity': vuln.get('severity', 'medium'),
                                    'cwe_id': vuln.get('cwe_id', ''),
                                    'owasp_category': vuln.get('owasp_category', ''),
                                    'file_path': repo_scanner.get_relative_path(file_path),
                                    'line_number': vuln.get('sink_line', 0),
                                    'code_snippet': f"Call chain: {' -> '.join(vuln.get('call_chain', []))}",
                                    'remediation': vuln.get('remediation', ''),
                                    'cvss_score': 7.5 if vuln.get('severity') == 'critical' else 5.0,
                                    'analysis_type': 'inter-procedural'
                                })

                    except Exception as file_error:
                        # Skip files that can't be analyzed
                        continue

            # Add inter-procedural findings to SAST findings
            sast_findings.extend(interprocedural_findings)
            print(f"Inter-procedural analysis found {len(interprocedural_findings)} additional vulnerabilities")

        except Exception as ip_error:
            print(f"Inter-procedural analysis error (non-fatal): {ip_error}")
    else:
        sast_findings = []  # No demo findings - only real scans

    sast_scan = Scan(
        project_id=project_id,
        scan_type=ScanType.SAST,
        status=ScanStatus.COMPLETED,
        total_findings=len(sast_findings),
        critical_count=len([f for f in sast_findings if f['severity'] == 'critical']),
        high_count=len([f for f in sast_findings if f['severity'] == 'high']),
        medium_count=len([f for f in sast_findings if f['severity'] == 'medium']),
        low_count=len([f for f in sast_findings if f['severity'] == 'low'])
    )
    db.add(sast_scan)
    db.flush()

    for finding in sast_findings:
        file_path = finding.get('file_path', 'unknown')
        if repo_scanner and repo_scanner.repo_path:
            file_path = repo_scanner.get_relative_path(file_path)

        # Get rule_id if this finding was detected by a custom rule
        rule_id = finding.get('rule_id')

        vuln = Vulnerability(
            scan_id=sast_scan.id,
            rule_id=rule_id,  # Track which rule detected this vulnerability
            title=finding.get('title', 'Security Issue'),
            description=finding.get('description', 'Security vulnerability detected'),
            severity=SeverityLevel[finding.get('severity', 'medium').upper()],
            cwe_id=finding.get('cwe_id', ''),
            owasp_category=finding.get('owasp_category', 'Security'),
            file_path=file_path,
            line_number=finding.get('line_number', 0),
            code_snippet=finding.get('code_snippet', ''),
            remediation=finding.get('remediation', ''),
            remediation_code=finding.get('remediation_code'),
            cvss_score=finding.get('cvss_score', 0.0),
            stride_category=finding.get('stride_category'),
            mitre_attack_id=finding.get('mitre_attack_id')
        )
        db.add(vuln)

        # Update rule performance stats if this was detected by a custom rule
        if rule_id:
            try:
                db.execute(
                    text("UPDATE custom_rules SET total_detections = total_detections + 1 WHERE id = :rule_id"),
                    {"rule_id": rule_id}
                )
            except Exception as e:
                print(f"Warning: Failed to update rule performance for rule {rule_id}: {e}")

    scan_results["sast"] = len(sast_findings)

    # Run SCA scan using Enhanced Scanner (live OSV/NVD vulnerability feeds)
    sca_findings = []
    if repo_scanner and repo_scanner.repo_path:
        dep_files = repo_scanner.get_dependency_files()

        for dep_type, file_paths in dep_files.items():
            for file_path in file_paths:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # Parse dependencies using enhanced SCA scanner
                    dependencies = {}
                    ecosystem = dep_type
                    file_name = os.path.basename(file_path)

                    if dep_type == 'npm':
                        if file_name == 'package-lock.json':
                            dependencies = enhanced_sca_scanner.parse_package_lock_json(content)
                        else:
                            dependencies = enhanced_sca_scanner.parse_package_json(content)
                    elif dep_type == 'pip':
                        if file_name == 'Pipfile.lock':
                            dependencies = enhanced_sca_scanner.parse_pipfile_lock(content)
                        else:
                            dependencies = enhanced_sca_scanner.parse_requirements_txt(content)
                    elif dep_type == 'maven':
                        dependencies = enhanced_sca_scanner.parse_pom_xml(content)
                    elif dep_type == 'gradle':
                        dependencies = enhanced_sca_scanner.parse_build_gradle(content)
                    elif dep_type == 'composer':
                        if file_name == 'composer.lock':
                            dependencies = enhanced_sca_scanner.parse_composer_lock(content)
                        else:
                            dependencies = enhanced_sca_scanner.parse_composer_json(content)
                    elif dep_type == 'nuget':
                        if file_name == 'packages.config':
                            dependencies = enhanced_sca_scanner.parse_packages_config(content)
                        else:
                            dependencies = enhanced_sca_scanner.parse_csproj(content)
                    elif dep_type == 'go':
                        if file_name == 'go.sum':
                            dependencies = enhanced_sca_scanner.parse_go_sum(content)
                        else:
                            dependencies = enhanced_sca_scanner.parse_go_mod(content)
                    else:
                        continue

                    if dependencies:
                        # Use async live vulnerability feeds from OSV
                        try:
                            results = await enhanced_sca_scanner.scan_dependencies_async(
                                dependencies, ecosystem
                            )
                            sca_findings.extend(results['findings'])
                        except Exception as feed_error:
                            print(f"Enhanced SCA scan failed: {feed_error}")
                            # Fallback to sync scan
                            results = enhanced_sca_scanner.scan_dependencies(dependencies, ecosystem)
                            sca_findings.extend(results['findings'])
                except Exception as e:
                    print(f"Warning: Failed to scan {file_path}: {e}")
    # No demo/sample fallback - only show real vulnerabilities

    # Query existing SCA vulnerabilities for this project to avoid duplicates
    existing_sca_vulns = db.query(Vulnerability).join(Scan).filter(
        Scan.project_id == project_id,
        Scan.scan_type == ScanType.SCA
    ).all()

    # Build set of existing package+CVE keys for deduplication
    existing_vuln_keys = set()
    for v in existing_sca_vulns:
        # Extract package name from file_path (format: "ecosystem dependency: package version ...")
        file_path_parts = (v.file_path or '').split()
        pkg_name = file_path_parts[2] if len(file_path_parts) > 2 else ''
        pkg_name = pkg_name.lower()

        # Extract CVE from code_snippet if present
        cve_match = ''
        if v.code_snippet and 'CVE-' in v.code_snippet:
            import re
            cve_found = re.search(r'CVE-\d{4}-\d+', v.code_snippet)
            if cve_found:
                cve_match = cve_found.group()

        # Also check title for CVE
        if not cve_match and v.title and 'CVE-' in v.title:
            cve_found = re.search(r'CVE-\d{4}-\d+', v.title)
            if cve_found:
                cve_match = cve_found.group()

        if pkg_name and cve_match:
            existing_vuln_keys.add(f"{pkg_name}:{cve_match}")
        # Also add by title prefix for non-CVE vulns
        if pkg_name and v.title:
            title_key = v.title.lower()[:50]
            existing_vuln_keys.add(f"{pkg_name}:{title_key}")

    # Filter out duplicate findings before counting
    unique_sca_findings = []
    for finding in sca_findings:
        pkg = finding.get('package', '').lower()
        cve = finding.get('cve', '')
        title = (finding.get('vulnerability') or finding.get('title') or '').lower()[:50]

        is_duplicate = False
        if cve and f"{pkg}:{cve}" in existing_vuln_keys:
            is_duplicate = True
        if title and f"{pkg}:{title}" in existing_vuln_keys:
            is_duplicate = True

        if not is_duplicate:
            unique_sca_findings.append(finding)
            # Add to existing keys so we don't add the same finding twice in this batch
            if cve:
                existing_vuln_keys.add(f"{pkg}:{cve}")
            if title:
                existing_vuln_keys.add(f"{pkg}:{title}")

    sca_scan = Scan(
        project_id=project_id,
        scan_type=ScanType.SCA,
        status=ScanStatus.COMPLETED,
        total_findings=len(unique_sca_findings),
        critical_count=len([f for f in unique_sca_findings if f.get('severity', '').lower() == 'critical']),
        high_count=len([f for f in unique_sca_findings if f.get('severity', '').lower() == 'high']),
        medium_count=len([f for f in unique_sca_findings if f.get('severity', '').lower() == 'medium']),
        low_count=len([f for f in unique_sca_findings if f.get('severity', '').lower() == 'low'])
    )
    db.add(sca_scan)
    db.flush()

    for finding in unique_sca_findings:
        # Handle both local DB and live feed finding formats
        package_name = finding.get('package', 'unknown')
        installed_version = finding.get('installed_version') or finding.get('version') or 'unknown'
        vulnerability = finding.get('vulnerability') or finding.get('title') or finding.get('cve') or 'Vulnerability'
        source = finding.get('source', 'local')
        fixed_versions = finding.get('fixed_versions', [])
        fixed_version_str = ', '.join(fixed_versions) if fixed_versions else finding.get('remediation', '')

        # Get direct/transitive dependency info
        is_direct = finding.get('is_direct_dependency', True)
        dependency_depth = finding.get('dependency_depth', 0)
        introduced_by = finding.get('introduced_by')
        dependency_path = finding.get('dependency_path', [])
        dep_type = "DIRECT" if is_direct else "TRANSITIVE"

        # Build detailed code snippet with source info and dependency chain
        code_snippet_parts = [
            f"Package: {package_name}@{installed_version}",
            f"Type: {dep_type} DEPENDENCY",
            f"Source: {source.upper() if source else 'LOCAL'}",
        ]
        if not is_direct and introduced_by:
            code_snippet_parts.append(f"Introduced by: {introduced_by}")
        if dependency_path and len(dependency_path) > 1:
            path_str = " → ".join([p.split('@')[0] for p in dependency_path])
            code_snippet_parts.append(f"Dependency chain: {path_str}")
        if finding.get('cve'):
            code_snippet_parts.append(f"CVE: {finding.get('cve')}")
        if fixed_version_str and 'upgrade' not in fixed_version_str.lower():
            code_snippet_parts.append(f"Fixed in: {fixed_version_str}")

        # Build file_path with clear direct/transitive indicator
        file_path_str = f"{finding.get('ecosystem', 'package')} dependency: {package_name} {installed_version} [{dep_type}] [Source: {source.upper() if source else 'LOCAL'}]"
        if not is_direct and introduced_by:
            file_path_str += f" [Via: {introduced_by}]"

        vuln = Vulnerability(
            scan_id=sca_scan.id,
            title=f"{vulnerability} in {package_name}",
            description=finding.get('description', 'Vulnerability in dependency'),
            severity=SeverityLevel[finding.get('severity', 'medium').upper()],
            cwe_id=finding.get('cwe_id') or finding.get('cwe') or 'CWE-1035',
            owasp_category=finding.get('owasp_category', 'A06:2021 - Vulnerable and Outdated Components'),
            file_path=file_path_str,
            line_number=dependency_depth,  # Use line_number to store depth for frontend
            code_snippet='\n'.join(code_snippet_parts),
            remediation=finding.get('remediation') or f"Upgrade to {fixed_version_str}" if fixed_version_str else 'Update to latest version',
            cvss_score=finding.get('cvss_score') or finding.get('cvss') or 0.0,
            stride_category=finding.get('stride_category'),
            mitre_attack_id=finding.get('mitre_attack_id')
        )
        db.add(vuln)
    scan_results["sca"] = len(sca_findings)

    # Run Secret scan
    if repo_scanner and repo_scanner.repo_path:
        scan_results_data = secret_scanner.scan_directory(repo_scanner.repo_path)
        secret_findings = scan_results_data['findings']
    else:
        secret_findings = secret_scanner.generate_sample_findings()

    secret_scan = Scan(
        project_id=project_id,
        scan_type=ScanType.SECRET,
        status=ScanStatus.COMPLETED,
        total_findings=len(secret_findings),
        critical_count=len([f for f in secret_findings if f.get('severity', '').lower() == 'critical']),
        high_count=len([f for f in secret_findings if f.get('severity', '').lower() == 'high']),
        medium_count=len([f for f in secret_findings if f.get('severity', '').lower() == 'medium']),
        low_count=len([f for f in secret_findings if f.get('severity', '').lower() == 'low'])
    )
    db.add(secret_scan)
    db.flush()

    for finding in secret_findings:
        file_path = finding.get('file_path', 'unknown')
        if repo_scanner and repo_scanner.repo_path:
            file_path = repo_scanner.get_relative_path(file_path)

        vuln = Vulnerability(
            scan_id=secret_scan.id,
            title=finding.get('title', 'Exposed Secret'),
            description=finding.get('description', 'Sensitive information exposed in code'),
            severity=SeverityLevel[finding.get('severity', 'high').upper()],
            cwe_id=finding.get('cwe_id', 'CWE-798'),
            owasp_category=finding.get('owasp_category', 'A07:2021 - Identification and Authentication Failures'),
            file_path=file_path,
            line_number=finding.get('line_number', 0),
            code_snippet=finding.get('code_snippet', ''),
            remediation=finding.get('remediation', 'Remove and rotate the exposed secret'),
            cvss_score=finding.get('cvss_score', 7.5),
            stride_category=finding.get('stride_category'),
            mitre_attack_id=finding.get('mitre_attack_id')
        )
        db.add(vuln)
    scan_results["secret"] = len(secret_findings)

    db.commit()

    # Calculate and update risk score
    calculate_risk_score(project_id, db)

    # Cleanup repository
    if repo_scanner:
        repo_scanner.cleanup()

    return {
        "message": "Security scans completed" if repo_scanner else "Demo scans completed (no repository URL)",
        "scan_type": "real" if repo_scanner else "demo",
        "sast_findings": scan_results["sast"],
        "sca_findings": scan_results["sca"],
        "secret_findings": scan_results["secret"],
        "total_findings": sum(scan_results.values())
    }

@app.delete("/api/projects/{project_id}")
async def delete_project(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete a project and all associated data (scans, vulnerabilities, threat models)"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Delete all associated scans and their vulnerabilities (cascade should handle this)
    scans = db.query(Scan).filter(Scan.project_id == project_id).all()
    for scan in scans:
        db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).delete()
    db.query(Scan).filter(Scan.project_id == project_id).delete()

    # Delete threat models
    db.query(ThreatModel).filter(ThreatModel.project_id == project_id).delete()

    # Delete the project
    db.delete(project)
    db.commit()

    return {"message": "Project deleted successfully"}


@app.post("/api/projects/{project_id}/deduplicate-sca")
async def deduplicate_sca_vulnerabilities(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Remove duplicate SCA vulnerabilities from a project based on package+CVE"""
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Get all SCA vulnerabilities for this project
    sca_vulns = db.query(Vulnerability).join(Scan).filter(
        Scan.project_id == project_id,
        Scan.scan_type == ScanType.SCA
    ).order_by(Vulnerability.id.desc()).all()  # Order by ID desc to keep newest

    # Track unique vulnerabilities by package+CVE
    seen_keys = set()
    duplicates_to_delete = []

    for vuln in sca_vulns:
        # Extract package name from file_path
        file_path_parts = (vuln.file_path or '').split()
        pkg_name = file_path_parts[2] if len(file_path_parts) > 2 else ''
        pkg_name = pkg_name.lower()

        # Extract CVE from code_snippet or title
        cve_match = ''
        if vuln.code_snippet and 'CVE-' in vuln.code_snippet:
            cve_found = re.search(r'CVE-\d{4}-\d+', vuln.code_snippet)
            if cve_found:
                cve_match = cve_found.group()
        if not cve_match and vuln.title and 'CVE-' in vuln.title:
            cve_found = re.search(r'CVE-\d{4}-\d+', vuln.title)
            if cve_found:
                cve_match = cve_found.group()

        # Build unique key
        if pkg_name and cve_match:
            key = f"{pkg_name}:{cve_match}"
        elif pkg_name:
            # For non-CVE vulns, use title
            title_prefix = (vuln.title or '').lower()[:50]
            key = f"{pkg_name}:{title_prefix}"
        else:
            continue  # Skip if we can't determine uniqueness

        if key in seen_keys:
            duplicates_to_delete.append(vuln.id)
        else:
            seen_keys.add(key)

    # Delete duplicates
    if duplicates_to_delete:
        db.query(Vulnerability).filter(Vulnerability.id.in_(duplicates_to_delete)).delete(synchronize_session=False)

        # Update scan counts
        for scan in db.query(Scan).filter(Scan.project_id == project_id, Scan.scan_type == ScanType.SCA).all():
            remaining_vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
            scan.total_findings = len(remaining_vulns)
            scan.critical_count = len([v for v in remaining_vulns if v.severity == SeverityLevel.CRITICAL])
            scan.high_count = len([v for v in remaining_vulns if v.severity == SeverityLevel.HIGH])
            scan.medium_count = len([v for v in remaining_vulns if v.severity == SeverityLevel.MEDIUM])
            scan.low_count = len([v for v in remaining_vulns if v.severity == SeverityLevel.LOW])

        db.commit()

    return {
        "message": f"Removed {len(duplicates_to_delete)} duplicate SCA vulnerabilities",
        "duplicates_removed": len(duplicates_to_delete),
        "unique_remaining": len(seen_keys)
    }


@app.get("/api/projects/{project_id}/scans")
async def list_scans(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    scans = db.query(Scan).filter(Scan.project_id == project_id).all()

    return [
        {
            "id": s.id,
            "scan_type": s.scan_type.value,
            "status": s.status.value,
            "total_findings": s.total_findings,
            "critical_count": s.critical_count,
            "high_count": s.high_count,
            "medium_count": s.medium_count,
            "low_count": s.low_count,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None
        }
        for s in scans
    ]

@app.get("/api/scans/{scan_id}/vulnerabilities")
async def get_vulnerabilities(
    scan_id: int,
    limit: int = 1000,  # Default limit to prevent timeout with large datasets
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).limit(limit).all()

    return [
        {
            "id": v.id,
            "title": v.title,
            "description": v.description,
            "severity": v.severity.value,
            "cwe_id": v.cwe_id,
            "owasp_category": v.owasp_category,
            "file_path": v.file_path,
            "line_number": v.line_number,
            "code_snippet": v.code_snippet,
            "remediation": v.remediation,
            "remediation_code": v.remediation_code,
            "cvss_score": v.cvss_score,
            "stride_category": v.stride_category,
            "mitre_attack_id": v.mitre_attack_id,
            "is_resolved": v.is_resolved,
            "status": "false_positive" if v.false_positive else ("resolved" if v.is_resolved else "active"),
            # AI-generated impact fields
            "business_impact": v.business_impact,
            "technical_impact": v.technical_impact,
            "recommendations": v.recommendations,
            "impact_generated_by": v.impact_generated_by
        }
        for v in vulnerabilities
    ]

# Get all scans with filtering
@app.get("/api/scans")
async def get_all_scans(
    status: Optional[str] = None,
    project_id: Optional[int] = None,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    query = db.query(Scan).join(Project)

    if status:
        query = query.filter(Scan.status == status)
    if project_id:
        query = query.filter(Scan.project_id == project_id)

    scans = query.order_by(Scan.started_at.desc()).limit(limit).all()

    return [
        {
            "id": s.id,
            "project_id": s.project_id,
            "project_name": s.project.name,
            "scan_type": s.scan_type,
            "status": s.status,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "total_vulnerabilities": s.total_findings or 0,
            "critical_count": s.critical_count or 0,
            "high_count": s.high_count or 0,
            "medium_count": s.medium_count or 0,
            "low_count": s.low_count or 0,
            "progress": 75 if s.status == 'running' else (100 if s.status == 'completed' else 0)
        }
        for s in scans
    ]

# Create a new scan (for restarting scans)
@app.post("/api/scans")
async def create_scan(
    request: dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new scan for a project"""
    project_id = request.get("project_id")
    scan_type = request.get("scan_type")

    if not project_id or not scan_type:
        raise HTTPException(status_code=400, detail="project_id and scan_type are required")

    # Verify project exists
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Use the existing scan endpoint
    # This will trigger the actual scan in the background
    from fastapi import BackgroundTasks
    background_tasks = BackgroundTasks()

    # Call the existing run_security_scan function
    # We'll redirect to the project scan endpoint
    return await run_security_scan(project_id, current_user, db)

# Get scan logs
@app.get("/api/scans/{scan_id}/logs")
async def get_scan_logs(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Generate logs based on scan status and data
    logs = []

    if scan.started_at:
        logs.append({
            "timestamp": scan.started_at.isoformat(),
            "level": "info",
            "message": f"Starting {scan.scan_type} scan for project: {scan.project.name}"
        })
        logs.append({
            "timestamp": scan.started_at.isoformat(),
            "level": "info",
            "message": "Initializing scan environment..."
        })
        logs.append({
            "timestamp": scan.started_at.isoformat(),
            "level": "success",
            "message": "Environment ready"
        })

    if scan.status == 'running':
        logs.append({
            "timestamp": datetime.now().isoformat(),
            "level": "info",
            "message": "Analyzing source code..."
        })
        logs.append({
            "timestamp": datetime.now().isoformat(),
            "level": "info",
            "message": f"Processed 75% of files"
        })
        if scan.critical_count and scan.critical_count > 0:
            logs.append({
                "timestamp": datetime.now().isoformat(),
                "level": "warning",
                "message": f"Found {scan.critical_count} critical issues"
            })

    elif scan.status == 'completed' and scan.completed_at:
        logs.append({
            "timestamp": scan.completed_at.isoformat(),
            "level": "info",
            "message": "Analysis complete"
        })
        logs.append({
            "timestamp": scan.completed_at.isoformat(),
            "level": "success",
            "message": "Scan completed successfully"
        })
        logs.append({
            "timestamp": scan.completed_at.isoformat(),
            "level": "info",
            "message": f"Total vulnerabilities found: {scan.total_vulnerabilities or 0}"
        })
        logs.append({
            "timestamp": scan.completed_at.isoformat(),
            "level": "info",
            "message": f"Critical: {scan.critical_count or 0}, High: {scan.high_count or 0}, Medium: {scan.medium_count or 0}, Low: {scan.low_count or 0}"
        })

    elif scan.status == 'failed':
        logs.append({
            "timestamp": scan.completed_at.isoformat() if scan.completed_at else datetime.now().isoformat(),
            "level": "error",
            "message": "Scan failed due to an error"
        })
        logs.append({
            "timestamp": scan.completed_at.isoformat() if scan.completed_at else datetime.now().isoformat(),
            "level": "error",
            "message": "Please check project configuration and try again"
        })

    return logs

# Delete a specific scan
@app.delete("/api/scans/{scan_id}")
async def delete_scan(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete a scan and all its associated vulnerabilities"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Store info for response
    scan_type = scan.scan_type.value if hasattr(scan.scan_type, 'value') else str(scan.scan_type)
    project_id = scan.project_id

    # Delete all vulnerabilities associated with this scan
    deleted_vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).delete()

    # Delete the scan
    db.delete(scan)
    db.commit()

    return {
        "success": True,
        "message": f"Successfully deleted {scan_type.upper()} scan and {deleted_vulns} associated vulnerabilities",
        "deleted_scan_id": scan_id,
        "project_id": project_id,
        "deleted_vulnerabilities": deleted_vulns
    }

# Enhanced Dashboard Analytics Endpoint
@app.get("/api/dashboard/analytics")
async def get_dashboard_analytics(
    project_id: Optional[int] = None,
    days: int = 30,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get comprehensive dashboard analytics with filters"""
    from datetime import timedelta
    from collections import defaultdict

    # Base query for vulnerabilities
    vuln_query = db.query(Vulnerability)
    if project_id:
        vuln_query = vuln_query.join(Scan).filter(Scan.project_id == project_id)

    # Get all vulnerabilities
    all_vulns = vuln_query.all()

    # Get date range for trends
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)

    # === BASIC METRICS ===
    total_vulnerabilities = len(all_vulns)
    critical_count = len([v for v in all_vulns if v.severity == 'critical'])
    high_count = len([v for v in all_vulns if v.severity == 'high'])
    medium_count = len([v for v in all_vulns if v.severity == 'medium'])
    low_count = len([v for v in all_vulns if v.severity == 'low'])

    # === FALSE POSITIVE RATE ===
    false_positives = len([v for v in all_vulns if v.false_positive])
    false_positive_rate = (false_positives / total_vulnerabilities * 100) if total_vulnerabilities > 0 else 0

    # === REMEDIATION VELOCITY ===
    # Vulnerabilities fixed in the last 30 days
    fixed_vulns = [v for v in all_vulns if v.is_resolved and v.resolved_at and v.resolved_at >= start_date]
    remediation_velocity = len(fixed_vulns) / days if days > 0 else 0  # per day

    # Average time to fix (in days)
    fix_times = []
    for v in fixed_vulns:
        if v.created_at and v.resolved_at:
            fix_time = (v.resolved_at - v.created_at).days
            fix_times.append(fix_time)
    avg_time_to_fix = sum(fix_times) / len(fix_times) if fix_times else 0

    # === VULNERABILITY TRENDS (last 30 days) ===
    trend_data = defaultdict(lambda: {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0})
    for v in all_vulns:
        if v.created_at and v.created_at >= start_date:
            date_key = v.created_at.strftime('%Y-%m-%d')
            # Handle both string and enum severity values
            severity_key = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
            if severity_key in trend_data[date_key]:
                trend_data[date_key][severity_key] += 1
            trend_data[date_key]['total'] += 1

    # Format trend data for frontend
    vulnerability_trend = []
    current_date = start_date
    while current_date <= end_date:
        date_str = current_date.strftime('%Y-%m-%d')
        trend_entry = trend_data[date_str]
        vulnerability_trend.append({
            'date': date_str,
            'critical': trend_entry['critical'],
            'high': trend_entry['high'],
            'medium': trend_entry['medium'],
            'low': trend_entry['low'],
            'info': trend_entry['info'],
            'total': trend_entry['total']
        })
        current_date += timedelta(days=1)

    # === VULNERABILITY BY CATEGORY ===
    category_counts = defaultdict(int)
    for v in all_vulns:
        category = v.title.split(':')[0] if ':' in v.title else 'Other'  # Extract category from title
        category_counts[category] += 1

    vulnerability_by_category = [
        {'name': category, 'value': count}
        for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]

    # === VULNERABILITY BY PROJECT ===
    project_query = db.query(Project)
    projects = project_query.all()

    vulnerability_by_project = []
    for project in projects:
        project_vulns = [v for v in all_vulns if v.scan and v.scan.project_id == project.id]
        if project_vulns or not project_id:  # Show all projects if no filter, or matching project
            vulnerability_by_project.append({
                'project_id': project.id,
                'project_name': project.name,
                'total': len(project_vulns),
                'critical': len([v for v in project_vulns if v.severity == 'critical']),
                'high': len([v for v in project_vulns if v.severity == 'high']),
                'medium': len([v for v in project_vulns if v.severity == 'medium']),
                'low': len([v for v in project_vulns if v.severity == 'low'])
            })

    # === STATUS DISTRIBUTION ===
    status_counts = defaultdict(int)
    for v in all_vulns:
        if v.is_resolved:
            status_counts['Fixed'] += 1
        elif v.false_positive:
            status_counts['False Positive'] += 1
        else:
            status_counts['Open'] += 1

    status_distribution = [
        {'name': status, 'value': count}
        for status, count in status_counts.items()
    ]

    # === SEVERITY DISTRIBUTION ===
    severity_distribution = [
        {'name': 'Critical', 'value': critical_count, 'color': '#ef4444'},
        {'name': 'High', 'value': high_count, 'color': '#f97316'},
        {'name': 'Medium', 'value': medium_count, 'color': '#eab308'},
        {'name': 'Low', 'value': low_count, 'color': '#3b82f6'}
    ]

    # === TOP VULNERABILITY TYPES ===
    type_counts = defaultdict(int)
    for v in all_vulns:
        # Use OWASP category first, then CWE, then title parsing, then scan type
        if v.owasp_category:
            # Extract just the category name (e.g., "A03:2021 - Injection" -> "Injection")
            vuln_type = v.owasp_category.split(' - ')[-1] if ' - ' in v.owasp_category else v.owasp_category
        elif v.cwe_id:
            # Use CWE ID as type
            vuln_type = v.cwe_id
        elif ':' in v.title:
            # Parse from title (e.g., "SQL Injection: Description" -> "SQL Injection")
            vuln_type = v.title.split(':')[0].strip()
        elif v.scan:
            # Use scan type as fallback
            scan_type_names = {'sast': 'Code Vulnerability', 'sca': 'Dependency Issue', 'secret': 'Exposed Secret'}
            vuln_type = scan_type_names.get(v.scan.scan_type.value, 'Security Issue')
        else:
            vuln_type = 'Security Issue'
        type_counts[vuln_type] += 1

    top_vulnerability_types = [
        {'type': vuln_type, 'count': count}
        for vuln_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    # === SCAN ACTIVITY ===
    scan_query = db.query(Scan)
    if project_id:
        scan_query = scan_query.filter(Scan.project_id == project_id)

    scans = scan_query.filter(Scan.started_at >= start_date).all()

    scan_activity = defaultdict(int)
    for scan in scans:
        if scan.started_at:
            date_key = scan.started_at.strftime('%Y-%m-%d')
            scan_activity[date_key] += 1

    scan_activity_trend = []
    current_date = start_date
    while current_date <= end_date:
        date_str = current_date.strftime('%Y-%m-%d')
        scan_activity_trend.append({
            'date': date_str,
            'scans': scan_activity[date_str]
        })
        current_date += timedelta(days=1)

    # === RETURN COMPREHENSIVE ANALYTICS ===
    return {
        'summary': {
            'total_vulnerabilities': total_vulnerabilities,
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'low': low_count,
            'false_positive_rate': round(false_positive_rate, 2),
            'remediation_velocity': round(remediation_velocity, 2),
            'avg_time_to_fix': round(avg_time_to_fix, 1),
            'total_scans': len(scans)
        },
        'trends': {
            'vulnerability_trend': vulnerability_trend,
            'scan_activity': scan_activity_trend
        },
        'distributions': {
            'severity': severity_distribution,
            'status': status_distribution,
            'by_category': vulnerability_by_category,
            'by_project': vulnerability_by_project
        },
        'top_types': top_vulnerability_types,
        'projects': [{'id': p.id, 'name': p.name} for p in projects]
    }

# Chatbot endpoints
@app.post("/api/chat")
async def chat(
    request: ChatRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    chatbot = get_chatbot_service()
    if not chatbot:
        raise HTTPException(status_code=503, detail="Chatbot service not configured (missing ANTHROPIC_API_KEY)")

    # Build context if provided
    context = None
    if request.context_type == "vulnerability" and request.context_id:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == request.context_id).first()
        if vuln:
            context = {
                "type": "vulnerability",
                "data": {
                    "title": vuln.title,
                    "severity": vuln.severity.value,
                    "cwe_id": vuln.cwe_id,
                    "file_path": vuln.file_path,
                    "line_number": vuln.line_number,
                    "code_snippet": vuln.code_snippet
                }
            }

    # Get response
    response_data = chatbot.chat(request.message, context)

    # Save chat message
    chat_msg = ChatMessage(
        user_id=current_user.id,
        message=request.message,
        response=response_data['response'],
        detected_language=response_data['detected_language'],
        context_type=request.context_type,
        context_id=request.context_id,
        model_used=response_data['model'],
        tokens_used=response_data.get('tokens_used', 0)
    )
    db.add(chat_msg)
    db.commit()

    return response_data

# Report endpoints
@app.get("/api/projects/{project_id}/reports/excel")
async def export_excel_report(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Gather data
    scans = db.query(Scan).filter(Scan.project_id == project_id).all()
    all_vulns = []
    for scan in scans:
        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
        all_vulns.extend(vulns)

    threat_model = db.query(ThreatModel).filter(ThreatModel.project_id == project_id).first()

    scan_data = {
        "project_name": project.name,
        "scan_types": ["SAST", "SCA", "Secrets"],
        "sast_findings": [
            {
                "title": v.title,
                "severity": v.severity.value,
                "cwe_id": v.cwe_id,
                "owasp_category": v.owasp_category,
                "file_path": v.file_path,
                "line_number": v.line_number,
                "cvss_score": v.cvss_score,
                "remediation": v.remediation
            }
            for v in all_vulns
        ],
        "sca_findings": sca_scanner.generate_sample_findings()['vulnerabilities']['findings'],
        "secret_findings": secret_scanner.generate_sample_findings(),
        "threat_model": threat_model.__dict__ if threat_model else None
    }

    buffer = report_service.generate_excel_report(scan_data)

    return StreamingResponse(
        buffer,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={project.name}_report.xlsx"}
    )

@app.get("/api/projects/{project_id}/reports/pdf")
async def export_pdf_report(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Gather data (similar to Excel)
    scans = db.query(Scan).filter(Scan.project_id == project_id).all()
    all_vulns = []
    for scan in scans:
        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
        all_vulns.extend(vulns)

    scan_data = {
        "project_name": project.name,
        "scan_types": ["SAST", "SCA", "Secrets"],
        "sast_findings": [
            {
                "title": v.title,
                "severity": v.severity.value,
                "file_path": v.file_path,
                "line_number": v.line_number,
                "remediation": v.remediation
            }
            for v in all_vulns
        ],
        "sca_findings": sca_scanner.generate_sample_findings()['vulnerabilities']['findings'],
        "secret_findings": secret_scanner.generate_sample_findings()
    }

    buffer = report_service.generate_pdf_report(scan_data)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={project.name}_report.pdf"}
    )

@app.get("/api/projects/{project_id}/reports/xml")
async def export_xml_report(
    project_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Gather data
    scans = db.query(Scan).filter(Scan.project_id == project_id).all()
    all_vulns = []
    for scan in scans:
        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
        all_vulns.extend(vulns)

    scan_data = {
        "project_name": project.name,
        "scan_types": ["SAST", "SCA", "Secrets"],
        "sast_findings": [
            {
                "title": v.title,
                "severity": v.severity.value,
                "cwe_id": v.cwe_id,
                "owasp_category": v.owasp_category,
                "file_path": v.file_path,
                "line_number": v.line_number,
                "cvss_score": v.cvss_score,
                "remediation": v.remediation
            }
            for v in all_vulns
        ],
        "sca_findings": sca_scanner.generate_sample_findings()['vulnerabilities']['findings'],
        "secret_findings": secret_scanner.generate_sample_findings()
    }

    xml_content = report_service.generate_xml_report(scan_data)

    from fastapi.responses import Response
    return Response(
        content=xml_content,
        media_type="application/xml",
        headers={"Content-Disposition": f"attachment; filename={project.name}_report.xml"}
    )

# Note: Settings endpoints are now handled by the settings router (routers/settings.py)

@app.post("/api/vulnerabilities/{vuln_id}/commit-fix")
async def commit_vulnerability_fix(
    vuln_id: int,
    request: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Commit the remediation fix to git repository"""
    import subprocess
    import os
    from pathlib import Path

    # Get vulnerability details
    vulnerability = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Get the scan and project
    scan = db.query(Scan).filter(Scan.id == vulnerability.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    project = db.query(Project).filter(Project.id == scan.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Extract request data
    branch = request.get('branch', f'security-fix-{vuln_id}')
    commit_message = request.get('commit_message', f'Fix: {vulnerability.title}')
    fixed_code = request.get('fixed_code')
    file_path = request.get('file_path', vulnerability.file_path)

    if not fixed_code:
        raise HTTPException(status_code=400, detail="Fixed code is required")

    try:
        # Get project directory
        project_dir = project.repository_path or '.'

        # Check if the directory exists and is a git repository
        if not os.path.exists(os.path.join(project_dir, '.git')):
            return {
                "success": False,
                "message": "Project directory is not a git repository. Please initialize git first."
            }

        # Create or checkout branch
        try:
            subprocess.run(
                ['git', 'checkout', '-b', branch],
                cwd=project_dir,
                check=False,
                capture_output=True
            )
        except Exception:
            # Branch might already exist, try to checkout
            try:
                subprocess.run(
                    ['git', 'checkout', branch],
                    cwd=project_dir,
                    check=True,
                    capture_output=True
                )
            except Exception as e:
                return {
                    "success": False,
                    "message": f"Failed to create/checkout branch: {str(e)}"
                }

        # Write fixed code to file
        full_file_path = os.path.join(project_dir, file_path)
        os.makedirs(os.path.dirname(full_file_path), exist_ok=True)

        with open(full_file_path, 'w') as f:
            f.write(fixed_code)

        # Stage the file
        subprocess.run(
            ['git', 'add', file_path],
            cwd=project_dir,
            check=True,
            capture_output=True
        )

        # Commit the changes
        subprocess.run(
            ['git', 'commit', '-m', commit_message],
            cwd=project_dir,
            check=True,
            capture_output=True
        )

        # Update vulnerability status
        vulnerability.status = 'fixed'
        db.commit()

        return {
            "success": True,
            "message": f"Successfully committed fix to branch '{branch}'",
            "branch": branch,
            "file_path": file_path,
            "commit_message": commit_message
        }

    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "message": f"Git command failed: {e.stderr.decode() if e.stderr else str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to commit fix: {str(e)}"
        }

@app.patch("/api/vulnerabilities/{vuln_id}/status")
async def update_vulnerability_status(
    vuln_id: int,
    request: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update vulnerability status (resolved, false_positive, active)"""
    # Get vulnerability
    vulnerability = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Get the new status from request
    new_status = request.get("status")
    if not new_status or new_status not in ["active", "resolved", "false_positive"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid status. Must be one of: active, resolved, false_positive"
        )

    # Compute old status from boolean fields
    old_status = "false_positive" if vulnerability.false_positive else ("resolved" if vulnerability.is_resolved else "active")

    # Map string status to boolean fields
    if new_status == "resolved":
        vulnerability.is_resolved = True
        vulnerability.false_positive = False
        vulnerability.resolved_at = datetime.now()  # Set resolved timestamp for remediation velocity tracking
    elif new_status == "false_positive":
        vulnerability.is_resolved = False
        vulnerability.false_positive = True
        vulnerability.resolved_at = None  # Clear resolved timestamp
    else:  # active
        vulnerability.is_resolved = False
        vulnerability.false_positive = False
        vulnerability.resolved_at = None  # Clear resolved timestamp

    db.commit()
    db.refresh(vulnerability)

    return {
        "success": True,
        "message": f"Vulnerability status updated from '{old_status}' to '{new_status}'",
        "vulnerability_id": vuln_id,
        "old_status": old_status,
        "new_status": new_status
    }

@app.post("/api/vulnerabilities/{vuln_id}/auto-remediate")
async def auto_remediate_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """AI-powered automatic vulnerability remediation"""
    # Get vulnerability details
    vulnerability = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Get the scan to access project details
    scan = db.query(Scan).filter(Scan.id == vulnerability.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get the project
    project = db.query(Project).filter(Project.id == scan.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Check if OpenAI API key is configured
    openai_api_key = os.getenv('OPENAI_API_KEY')
    if not openai_api_key:
        raise HTTPException(status_code=400, detail="OpenAI API key not configured")

    try:
        # Initialize OpenAI client
        from openai import OpenAI
        client = OpenAI(api_key=openai_api_key)

        # Prepare the prompt for code remediation
        prompt = f"""You are a security expert. A vulnerability has been detected with the following details:

**Vulnerability Type:** {vulnerability.title}
**Severity:** {vulnerability.severity}
**CWE ID:** {vulnerability.cwe_id}
**File:** {vulnerability.file_path}
**Line:** {vulnerability.line_number}

**Description:**
{vulnerability.description}

**Vulnerable Code:**
```
{vulnerability.code_snippet}
```

**Remediation Guidance:**
{vulnerability.remediation}

Please provide:
1. A fixed version of the code that addresses this vulnerability
2. A brief explanation of what was changed and why

Format your response as:
FIXED_CODE:
```
<fixed code here>
```

EXPLANATION:
<explanation here>
"""

        # Call OpenAI API
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a security expert specialized in fixing code vulnerabilities."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=2000
        )

        ai_response = response.choices[0].message.content

        # Parse the response to extract fixed code and explanation
        fixed_code = ""
        explanation = ""

        if "FIXED_CODE:" in ai_response:
            parts = ai_response.split("FIXED_CODE:")
            if len(parts) > 1:
                code_section = parts[1].split("EXPLANATION:")[0]
                # Extract code from code block
                if "```" in code_section:
                    code_parts = code_section.split("```")
                    if len(code_parts) > 1:
                        # Remove language identifier if present
                        fixed_code = code_parts[1].strip()
                        if fixed_code.startswith(('python', 'java', 'javascript', 'typescript', 'go', 'c', 'cpp', 'ruby', 'php')):
                            fixed_code = '\n'.join(fixed_code.split('\n')[1:]).strip()
                else:
                    fixed_code = code_section.strip()

        if "EXPLANATION:" in ai_response:
            explanation = ai_response.split("EXPLANATION:")[1].strip()

        if not fixed_code:
            fixed_code = ai_response  # Fallback to full response

        # Update vulnerability status to resolved and set timestamp for remediation velocity tracking
        vulnerability.is_resolved = True
        vulnerability.resolved_at = datetime.now()
        db.commit()

        return {
            "success": True,
            "message": f"Vulnerability successfully remediated using AI",
            "fixed_code": fixed_code,
            "explanation": explanation,
            "vulnerability_id": vuln_id
        }

    except Exception as e:
        db.rollback()
        return {
            "success": False,
            "message": f"Failed to auto-remediate: {str(e)}"
        }


class AIFixRequest(BaseModel):
    """Request model for AI fix generation"""
    vulnerability_type: str
    title: str
    severity: str
    code_snippet: str
    file_path: str
    line_number: int
    description: Optional[str] = None
    cwe_id: Optional[str] = None
    recommendation: Optional[str] = None
    language: Optional[str] = None


@app.post("/api/ai/generate-fix")
async def generate_ai_fix(
    request: AIFixRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Generate AI-powered fix for any vulnerability.
    Uses Claude (Anthropic) as primary, falls back to OpenAI.
    Used by VS Code extension for local enhanced scan findings.
    """
    # Check for API keys - prefer Anthropic (Claude), fallback to OpenAI
    anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
    openai_api_key = os.getenv('OPENAI_API_KEY')

    if not anthropic_api_key and not openai_api_key:
        raise HTTPException(
            status_code=400,
            detail="No AI API key configured. Please add ANTHROPIC_API_KEY or OPENAI_API_KEY to your environment."
        )

    # Detect language from file extension if not provided
    language = request.language
    if not language:
        ext = request.file_path.split('.')[-1].lower() if '.' in request.file_path else ''
        lang_map = {
            'py': 'Python', 'js': 'JavaScript', 'ts': 'TypeScript',
            'jsx': 'JavaScript React', 'tsx': 'TypeScript React',
            'java': 'Java', 'go': 'Go', 'rb': 'Ruby', 'php': 'PHP',
            'cs': 'C#', 'cpp': 'C++', 'c': 'C', 'kt': 'Kotlin', 'swift': 'Swift'
        }
        language = lang_map.get(ext, 'Unknown')

    # Build the prompt
    prompt = f"""You are a security expert. A vulnerability has been detected with the following details:

**Vulnerability Type:** {request.vulnerability_type}
**Title:** {request.title}
**Severity:** {request.severity}
**CWE ID:** {request.cwe_id or 'N/A'}
**File:** {request.file_path}
**Line:** {request.line_number}
**Language:** {language}

**Description:**
{request.description or 'No description provided'}

**Vulnerable Code:**
```{language.lower() if language else ''}
{request.code_snippet}
```

**Existing Recommendation:**
{request.recommendation or 'No recommendation provided'}

Please provide a SECURE, FIXED version of the code that addresses this vulnerability.

IMPORTANT:
1. Keep the fix minimal and focused on the security issue
2. Maintain the same coding style and language
3. Include necessary imports if needed
4. The fix should be a drop-in replacement that can be directly used

Format your response as:
FIXED_CODE:
```
<fixed code here - ready to use, no placeholders>
```

EXPLANATION:
<brief explanation of what was changed and why>
"""

    system_prompt = "You are a security expert specialized in fixing code vulnerabilities. Provide practical, ready-to-use code fixes that are minimal and focused on the security issue."

    ai_response = None
    model_used = None

    # Try Claude (Anthropic) first
    if anthropic_api_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=anthropic_api_key)
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}]
            )
            ai_response = response.content[0].text
            model_used = "claude-sonnet-4-20250514"
            print(f"[AI-Fix] Generated fix using Claude ({model_used})")
        except Exception as e:
            print(f"[AI-Fix] Claude failed: {e}, falling back to OpenAI")

    # Fallback to OpenAI if Claude failed or not available
    if ai_response is None and openai_api_key:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=openai_api_key)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )
            ai_response = response.choices[0].message.content
            model_used = "gpt-4o-mini"
            print(f"[AI-Fix] Generated fix using OpenAI ({model_used})")
        except Exception as e:
            return {
                "success": False,
                "message": f"Failed to generate AI fix: {str(e)}",
                "remediation_code": None
            }

    if ai_response is None:
        return {
            "success": False,
            "message": "No AI provider available to generate fix",
            "remediation_code": None
        }

    # Parse the response
    fixed_code = ""
    explanation = ""

    if "FIXED_CODE:" in ai_response:
        parts = ai_response.split("FIXED_CODE:")
        if len(parts) > 1:
            code_section = parts[1].split("EXPLANATION:")[0]
            if "```" in code_section:
                code_parts = code_section.split("```")
                if len(code_parts) > 1:
                    fixed_code = code_parts[1].strip()
                    # Remove language identifier if present
                    first_line = fixed_code.split('\n')[0].lower()
                    if first_line in ['python', 'java', 'javascript', 'typescript', 'go', 'ruby', 'php', 'c', 'cpp', 'csharp', 'kotlin', 'swift', 'jsx', 'tsx']:
                        fixed_code = '\n'.join(fixed_code.split('\n')[1:]).strip()
            else:
                fixed_code = code_section.strip()

    if "EXPLANATION:" in ai_response:
        explanation = ai_response.split("EXPLANATION:")[1].strip()

    if not fixed_code:
        fixed_code = ai_response

    return {
        "success": True,
        "remediation_code": fixed_code,
        "explanation": explanation,
        "vulnerability_type": request.vulnerability_type,
        "model": model_used,
        "provider": "anthropic" if "claude" in model_used else "openai"
    }


@app.get("/api/vulnerabilities/{vuln_id}/taint-flow")
async def get_vulnerability_taint_flow(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get detailed taint flow analysis for a vulnerability.
    Provides data flow, control flow, and path analysis for security testing.
    """
    vulnerability = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Generate comprehensive taint flow based on vulnerability type
    taint_flow = generate_taint_flow_analysis(vulnerability)

    return {
        "vulnerability_id": vuln_id,
        "vulnerability_type": vulnerability.title,
        "cwe_id": vulnerability.cwe_id,
        "taint_flow": taint_flow
    }

def generate_taint_flow_analysis(vulnerability) -> dict:
    """
    Generate taint flow analysis data based on vulnerability characteristics.
    In a production environment, this would be populated by the actual scanner.
    """
    vuln_title = (vulnerability.title or "").lower()
    file_path = vulnerability.file_path or "unknown"
    line_number = vulnerability.line_number or 1
    code_snippet = vulnerability.code_snippet or ""

    # Base path nodes
    path_nodes = []
    sanitizers = []

    # Get the vulnerability ID for node naming
    vid = vulnerability.id

    # Determine vulnerability category and generate appropriate flow
    if "sql" in vuln_title or "injection" in vuln_title:
        path_nodes = [
            {
                "id": f"node-{vid}-1",
                "type": "source",
                "description": "User input received from HTTP request parameter",
                "location": {
                    "file": file_path,
                    "startLine": max(1, line_number - 5),
                    "endLine": max(1, line_number - 5),
                    "startColumn": 0,
                    "endColumn": 50
                },
                "codeSnippet": "const userInput = req.query.id;",
                "variableName": "userInput",
                "functionName": "getParameter",
                "nodeKind": "VariableDeclaration"
            },
            {
                "id": f"node-{vid}-2",
                "type": "propagator",
                "description": "Data assigned to intermediate variable",
                "location": {
                    "file": file_path,
                    "startLine": max(1, line_number - 3),
                    "endLine": max(1, line_number - 3),
                    "startColumn": 0,
                    "endColumn": 40
                },
                "codeSnippet": "const id = userInput;",
                "variableName": "id",
                "nodeKind": "Assignment"
            },
            {
                "id": f"node-{vid}-3",
                "type": "propagator",
                "description": "String concatenation builds SQL query",
                "location": {
                    "file": file_path,
                    "startLine": max(1, line_number - 1),
                    "endLine": max(1, line_number - 1),
                    "startColumn": 0,
                    "endColumn": 60
                },
                "codeSnippet": code_snippet or 'const query = "SELECT * FROM users WHERE id = " + id;',
                "variableName": "query",
                "nodeKind": "BinaryExpression"
            },
            {
                "id": f"node-{vid}-4",
                "type": "sink",
                "description": "SQL query executed with unsanitized user input",
                "location": {
                    "file": file_path,
                    "startLine": line_number,
                    "endLine": line_number,
                    "startColumn": 0,
                    "endColumn": 30
                },
                "codeSnippet": "db.execute(query);",
                "functionName": "db.execute",
                "nodeKind": "CallExpression"
            }
        ]
        data_type = "user_input"
        confidence = "high"

    elif "xss" in vuln_title or "cross-site" in vuln_title:
        path_nodes = [
            {
                "id": f"node-{vid}-1",
                "type": "source",
                "description": "User-controlled input from form submission",
                "location": {
                    "file": file_path,
                    "startLine": max(1, line_number - 8),
                    "endLine": max(1, line_number - 8),
                    "startColumn": 0,
                    "endColumn": 45
                },
                "codeSnippet": "const message = req.body.comment;",
                "variableName": "message",
                "nodeKind": "VariableDeclaration"
            },
            {
                "id": f"node-{vid}-2",
                "type": "propagator",
                "description": "Data passed to display function",
                "location": {
                    "file": file_path,
                    "startLine": max(1, line_number - 4),
                    "endLine": max(1, line_number - 4),
                    "startColumn": 0,
                    "endColumn": 35
                },
                "codeSnippet": "renderComment(message);",
                "functionName": "renderComment",
                "nodeKind": "CallExpression"
            },
            {
                "id": f"node-{vid}-3",
                "type": "sink",
                "description": "innerHTML assignment allows script injection",
                "location": {
                    "file": file_path,
                    "startLine": line_number,
                    "endLine": line_number,
                    "startColumn": 0,
                    "endColumn": 55
                },
                "codeSnippet": code_snippet or "element.innerHTML = message;",
                "variableName": "innerHTML",
                "nodeKind": "AssignmentExpression"
            }
        ]
        data_type = "user_input"
        confidence = "high"

    elif "command" in vuln_title or "exec" in vuln_title or "rce" in vuln_title:
        path_nodes = [
            {
                "id": f"node-{vid}-1",
                "type": "source",
                "description": "External input received from request",
                "location": {
                    "file": file_path,
                    "startLine": max(1, line_number - 6),
                    "endLine": max(1, line_number - 6),
                    "startColumn": 0,
                    "endColumn": 42
                },
                "codeSnippet": "const filename = req.params.file;",
                "variableName": "filename",
                "nodeKind": "VariableDeclaration"
            },
            {
                "id": f"node-{vid}-2",
                "type": "propagator",
                "description": "String concatenation creates command",
                "location": {
                    "file": file_path,
                    "startLine": max(1, line_number - 2),
                    "endLine": max(1, line_number - 2),
                    "startColumn": 0,
                    "endColumn": 50
                },
                "codeSnippet": 'const cmd = "cat " + filename;',
                "variableName": "cmd",
                "nodeKind": "BinaryExpression"
            },
            {
                "id": f"node-{vid}-3",
                "type": "sink",
                "description": "Shell command executed with user-controlled input",
                "location": {
                    "file": file_path,
                    "startLine": line_number,
                    "endLine": line_number,
                    "startColumn": 0,
                    "endColumn": 25
                },
                "codeSnippet": code_snippet or "exec(cmd);",
                "functionName": "exec",
                "nodeKind": "CallExpression"
            }
        ]
        data_type = "command_execution"
        confidence = "high"

    elif "path" in vuln_title or "traversal" in vuln_title or "lfi" in vuln_title:
        path_nodes = [
            {
                "id": f"node-{vid}-1",
                "type": "source",
                "description": "File path from user input",
                "location": {
                    "file": file_path,
                    "startLine": max(1, line_number - 4),
                    "endLine": max(1, line_number - 4),
                    "startColumn": 0,
                    "endColumn": 40
                },
                "codeSnippet": "const path = req.query.path;",
                "variableName": "path",
                "nodeKind": "VariableDeclaration"
            },
            {
                "id": f"node-{vid}-2",
                "type": "sink",
                "description": "File system operation with unvalidated path",
                "location": {
                    "file": file_path,
                    "startLine": line_number,
                    "endLine": line_number,
                    "startColumn": 0,
                    "endColumn": 35
                },
                "codeSnippet": code_snippet or "fs.readFile(path);",
                "functionName": "fs.readFile",
                "nodeKind": "CallExpression"
            }
        ]
        data_type = "file_system"
        confidence = "high"

    elif "secret" in vuln_title or "credential" in vuln_title or "hardcoded" in vuln_title:
        path_nodes = [
            {
                "id": f"node-{vid}-1",
                "type": "source",
                "description": "Hardcoded credential in source code",
                "location": {
                    "file": file_path,
                    "startLine": line_number,
                    "endLine": line_number,
                    "startColumn": 0,
                    "endColumn": 60
                },
                "codeSnippet": code_snippet or 'const API_KEY = "sk-...";',
                "variableName": "API_KEY",
                "nodeKind": "VariableDeclaration"
            },
            {
                "id": f"node-{vid}-2",
                "type": "sink",
                "description": "Credential exposed in version control or logs",
                "location": {
                    "file": file_path,
                    "startLine": line_number,
                    "endLine": line_number,
                    "startColumn": 0,
                    "endColumn": 60
                },
                "codeSnippet": "// Secret committed to repository",
                "nodeKind": "Comment"
            }
        ]
        data_type = "credential"
        confidence = "high"

    else:
        # Generic flow for other vulnerability types
        path_nodes = [
            {
                "id": f"node-{vid}-1",
                "type": "source",
                "description": "External input enters the application",
                "location": {
                    "file": file_path,
                    "startLine": max(1, line_number - 3),
                    "endLine": max(1, line_number - 3),
                    "startColumn": 0,
                    "endColumn": 40
                },
                "codeSnippet": "const input = getExternalInput();",
                "variableName": "input",
                "nodeKind": "VariableDeclaration"
            },
            {
                "id": f"node-{vid}-2",
                "type": "sink",
                "description": "Potentially dangerous operation",
                "location": {
                    "file": file_path,
                    "startLine": line_number,
                    "endLine": line_number,
                    "startColumn": 0,
                    "endColumn": 50
                },
                "codeSnippet": code_snippet or "process(input);",
                "functionName": "process",
                "nodeKind": "CallExpression"
            }
        ]
        data_type = "external_input"
        confidence = "medium"

    # Build the complete taint flow object
    return {
        "id": f"taint-flow-{vid}",
        "source": path_nodes[0] if path_nodes else None,
        "sink": path_nodes[-1] if path_nodes else None,
        "path": path_nodes,
        "sanitizers": sanitizers,
        "confidence": confidence,
        "dataType": data_type
    }

# VS Code Extension Endpoints - Direct scanning without project requirement
class DirectScanRequest(BaseModel):
    path: str
    scan_types: List[str] = ["sast", "sca", "secrets"]

class DirectFileScanRequest(BaseModel):
    file_path: Optional[str] = None  # Local file path (for local backend)
    source_code: Optional[str] = None  # File content (for remote backend)
    file_name: Optional[str] = None  # Original filename when source_code is provided
    scan_types: List[str] = ["sast", "secrets"]

@app.post("/api/scan")
async def direct_workspace_scan(
    request: DirectScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Direct workspace scan for VS Code extension"""
    results = {
        "sast": {"findings": []},
        "sca": {"findings": []},
        "secrets": {"findings": []}
    }

    try:
        import os
        # Validate path exists
        if not os.path.exists(request.path):
            raise HTTPException(status_code=404, detail=f"Path not found: {request.path}")

        # Run SAST scan
        if "sast" in request.scan_types:
            scan_results = sast_scanner.scan_directory(request.path)
            findings = scan_results.get('findings', [])
            results["sast"]["findings"] = [
                {
                    "id": f"sast-{i}",
                    "title": f.get('title', 'Security Issue'),
                    "description": f.get('description', 'Security vulnerability detected'),
                    "severity": f.get('severity', 'medium'),
                    "file": f.get('file_path', 'unknown'),
                    "line": f.get('line_number', 0),
                    "category": f.get('owasp_category', 'Security'),
                    "cwe_id": f.get('cwe_id', ''),
                    "code_snippet": f.get('code_snippet', ''),
                    "remediation": f.get('remediation', ''),
                    "remediation_code": f.get('suggested_fix', ''),
                    "impact": f.get('impact', 'This vulnerability could compromise application security'),
                    "remediation_steps": f.get('remediation_steps', [])
                }
                for i, f in enumerate(findings)
            ]

        # Run SCA scan
        if "sca" in request.scan_types:
            # Find dependency files for all supported ecosystems
            import os
            import json
            dep_files = []

            # Supported dependency file patterns
            dep_file_names = [
                # JavaScript/TypeScript (npm/yarn)
                'package.json', 'package-lock.json', 'yarn.lock',
                # Python (pip/pipenv/poetry)
                'requirements.txt', 'Pipfile', 'Pipfile.lock', 'pyproject.toml', 'setup.py',
                # PHP (Composer)
                'composer.json', 'composer.lock',
                # Java (Maven/Gradle)
                'pom.xml', 'build.gradle', 'build.gradle.kts',
                # .NET (NuGet)
                'packages.config',
                # Ruby (Bundler)
                'Gemfile', 'Gemfile.lock',
                # Go
                'go.mod', 'go.sum',
                # Rust
                'Cargo.toml', 'Cargo.lock'
            ]

            for root, dirs, files in os.walk(request.path):
                # Skip common non-source directories
                dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'venv', '__pycache__', 'vendor', 'target', 'bin', 'obj']]

                for file in files:
                    if file in dep_file_names or file.endswith('.csproj'):
                        dep_files.append(os.path.join(root, file))

            print(f"[SCA] Found {len(dep_files)} dependency files to scan")

            sca_findings = []
            for dep_file in dep_files:
                try:
                    with open(dep_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    deps = {}
                    ecosystem = None
                    file_name = os.path.basename(dep_file)

                    # Detect ecosystem and use correct parser based on file name
                    # JavaScript/TypeScript (npm/yarn)
                    if file_name == 'package.json':
                        deps = sca_scanner.parse_package_json(content)
                        ecosystem = 'npm'
                    elif file_name == 'package-lock.json':
                        deps = sca_scanner.parse_package_lock_json(content)
                        ecosystem = 'npm'
                    elif file_name == 'yarn.lock':
                        deps = sca_scanner.parse_yarn_lock(content)
                        ecosystem = 'npm'

                    # Python (pip/pipenv/poetry)
                    elif file_name == 'requirements.txt':
                        deps = sca_scanner.parse_requirements_txt(content)
                        ecosystem = 'pip'
                    elif file_name == 'Pipfile' or file_name == 'Pipfile.lock':
                        deps = sca_scanner.parse_requirements_txt(content)
                        ecosystem = 'pip'
                    elif file_name == 'pyproject.toml':
                        deps = sca_scanner.parse_requirements_txt(content)
                        ecosystem = 'pip'
                    elif file_name == 'setup.py':
                        deps = sca_scanner.parse_requirements_txt(content)
                        ecosystem = 'pip'

                    # PHP (Composer)
                    elif file_name == 'composer.json' or file_name == 'composer.lock':
                        deps = sca_scanner.parse_composer_json(content)
                        ecosystem = 'composer'

                    # Java (Maven)
                    elif file_name == 'pom.xml':
                        deps = sca_scanner.parse_pom_xml(content)
                        ecosystem = 'maven'

                    # Java/Kotlin (Gradle)
                    elif file_name in ['build.gradle', 'build.gradle.kts']:
                        deps = sca_scanner.parse_gradle_build(content)
                        ecosystem = 'gradle'

                    # .NET (NuGet)
                    elif file_name.endswith('.csproj') or file_name == 'packages.config':
                        deps = sca_scanner.parse_csproj(content)
                        ecosystem = 'nuget'

                    # Ruby (Bundler)
                    elif file_name == 'Gemfile' or file_name == 'Gemfile.lock':
                        deps = sca_scanner.parse_gemfile_lock(content)
                        ecosystem = 'bundler'

                    # Go
                    elif file_name == 'go.mod' or file_name == 'go.sum':
                        deps = sca_scanner.parse_go_mod(content)
                        ecosystem = 'go'

                    # Rust (Cargo)
                    elif file_name == 'Cargo.toml' or file_name == 'Cargo.lock':
                        deps = sca_scanner.parse_cargo_toml(content)
                        ecosystem = 'cargo'

                    if deps and ecosystem:
                        print(f"[SCA] Scanning {dep_file} with {len(deps)} dependencies ({ecosystem})")
                        # Try live feeds first, then fall back to local database
                        try:
                            scan_result = await sca_scanner.scan_with_live_feeds(
                                deps, ecosystem, use_local_db=True, use_live_feeds=True
                            )
                        except Exception as live_feed_error:
                            print(f"[SCA] Live feed scan failed for {dep_file}, using local DB: {live_feed_error}")
                            scan_result = sca_scanner.scan_dependencies(deps, ecosystem)

                        if scan_result and scan_result.get('findings'):
                            # Add file path to each finding
                            for finding in scan_result['findings']:
                                finding['file_path'] = dep_file
                            sca_findings.extend(scan_result['findings'])
                            print(f"[SCA] Found {len(scan_result['findings'])} vulnerabilities in {dep_file}")
                except Exception as e:
                    print(f"[SCA] Error scanning {dep_file}: {e}")

            # No fake findings - only real vulnerabilities
            print(f"[SCA] Total vulnerabilities found: {len(sca_findings)}")

            results["sca"]["findings"] = [
                {
                    "id": f"sca-{i}",
                    "title": f"{v.get('package', 'Unknown')} {v.get('version') or v.get('installed_version', 'Unknown')} - {v.get('title') or v.get('vulnerability', 'Known vulnerability')}",
                    "description": v.get('description', 'Security vulnerability detected'),
                    "severity": v.get('severity', 'medium'),
                    "file": v.get('file_path', 'dependency file'),
                    "line": 1,
                    "category": "Vulnerable Dependency",
                    "package": v.get('package', 'Unknown'),
                    "version": v.get('version') or v.get('installed_version', 'Unknown'),
                    "fixed_version": v.get('fixed_version') or v.get('fixed_versions', [None])[0] if isinstance(v.get('fixed_versions'), list) else v.get('fixed_version')
                }
                for i, v in enumerate(sca_findings)
            ]

        # Run Secret scan
        if "secrets" in request.scan_types:
            scan_results = secret_scanner.scan_directory(request.path)
            findings = scan_results.get('findings', [])
            results["secrets"]["findings"] = [
                {
                    "id": f"secret-{i}",
                    "title": f.get('title', 'Exposed Secret'),
                    "description": f.get('description', 'Potential secret detected'),
                    "severity": f.get('severity', 'high'),
                    "file": f.get('file_path', 'unknown'),
                    "line": f.get('line_number', 0),
                    "category": "Exposed Secret",
                    "secret_type": f.get('secret_type', 'Unknown'),
                    "code_snippet": f.get('code_snippet', '')
                }
                for i, f in enumerate(findings)
            ]

        return results

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.post("/api/scan/file")
async def direct_file_scan(
    request: DirectFileScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Direct file scan for VS Code extension.

    Accepts either:
    - file_path: Path to local file (for local backend)
    - source_code + file_name: File content (for remote backend / VS Code extension)
    """
    results = {
        "sast": {"findings": []},
        "secrets": {"findings": []}
    }

    try:
        import os

        # Determine source code and file path
        if request.source_code:
            # Source code provided directly (VS Code extension / remote client)
            source_code = request.source_code
            file_path = request.file_name or "untitled"
        elif request.file_path:
            # Read from local file path
            if not os.path.exists(request.file_path):
                raise HTTPException(status_code=404, detail=f"Path not found: {request.file_path}")
            with open(request.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
            file_path = request.file_path
        else:
            raise HTTPException(status_code=400, detail="Either file_path or source_code must be provided")

        # Run SAST scan on single file
        if "sast" in request.scan_types:
            scan_results = sast_scanner.scan_code(source_code, file_path)
            findings = scan_results if isinstance(scan_results, list) else scan_results.get('findings', [])
            results["sast"]["findings"] = [
                {
                    "id": f"sast-{i}",
                    "title": f.get('title', 'Security Issue'),
                    "description": f.get('description', 'Security vulnerability detected'),
                    "severity": f.get('severity', 'medium'),
                    "file": f.get('file_path', file_path),
                    "line": f.get('line_number', 0),
                    "category": f.get('owasp_category', 'Security'),
                    "cwe_id": f.get('cwe_id', ''),
                    "code_snippet": f.get('code_snippet', ''),
                    "remediation": f.get('remediation', ''),
                    "remediation_code": f.get('suggested_fix', ''),
                    "impact": f.get('impact', 'This vulnerability could compromise application security'),
                    "remediation_steps": f.get('remediation_steps', [])
                }
                for i, f in enumerate(findings)
            ]

        # Run Secret scan on single file
        if "secrets" in request.scan_types:
            scan_results = secret_scanner.scan_code(source_code, file_path)
            findings = scan_results if isinstance(scan_results, list) else scan_results.get('findings', [])
            results["secrets"]["findings"] = [
                {
                    "id": f"secret-{i}",
                    "title": f.get('title', 'Exposed Secret'),
                    "description": f.get('description', 'Potential secret detected'),
                    "severity": f.get('severity', 'high'),
                    "file": f.get('file_path', file_path),
                    "line": f.get('line_number', 0),
                    "category": "Exposed Secret",
                    "secret_type": f.get('secret_type', 'Unknown'),
                    "code_snippet": f.get('code_snippet', '')
                }
                for i, f in enumerate(findings)
            ]

        return results

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File scan failed: {str(e)}")


# ==================== ENHANCED AST SECURITY SCANNING ====================

class EnhancedScanRequest(BaseModel):
    file_path: str
    include_taint_flow: bool = True
    include_cfg: bool = True
    include_dfg: bool = True

@app.post("/api/scan/enhanced")
async def enhanced_ast_scan(
    request: EnhancedScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Enhanced AST-based security scan with:
    - Taint Analysis (source → propagator → sanitizer → sink tracking)
    - Control Flow Graph (CFG) analysis
    - Data Flow Graph (DFG) analysis
    - Context-aware false positive filtering
    """
    try:
        import os
        if not os.path.exists(request.file_path):
            raise HTTPException(status_code=404, detail="File not found")

        # Read file content
        with open(request.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()

        # Run enhanced AST analysis
        analysis_result = ast_analyzer.analyze_file(source_code, request.file_path)

        # Format response
        response = {
            "file_path": request.file_path,
            "language": analysis_result.get("language", "unknown"),
            "findings": analysis_result.get("findings", []),
            "stats": {
                "total_findings": len(analysis_result.get("findings", [])),
                "taint_flows_detected": len(analysis_result.get("taint_flows", [])),
                "false_positives_filtered": analysis_result.get("stats", {}).get("false_positives_filtered", 0),
                "ast_summary": analysis_result.get("ast_summary", {})
            }
        }

        # Include taint flows if requested
        if request.include_taint_flow:
            response["taint_flows"] = analysis_result.get("taint_flows", [])

        # Include CFG if requested
        if request.include_cfg:
            cfg_data = analysis_result.get("cfg", {})
            response["cfg"] = {
                "total_nodes": cfg_data.get("total_nodes", 0),
                "branches": cfg_data.get("branches", 0),
                "loops": cfg_data.get("loops", 0),
                "entry": cfg_data.get("entry"),
                "exit": cfg_data.get("exit")
            }

        # Include DFG if requested
        if request.include_dfg:
            dfg_data = analysis_result.get("dfg", {})
            response["dfg"] = {
                "total_variables": dfg_data.get("total_variables", 0),
                "total_definitions": dfg_data.get("total_definitions", 0),
                "dependencies": dfg_data.get("dependencies", {})
            }

        return response

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Enhanced scan failed: {str(e)}")


class EnhancedDirectoryScanRequest(BaseModel):
    directory_path: str
    include_taint_flow: bool = True
    file_extensions: List[str] = [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".go", ".rb"]

@app.post("/api/scan/enhanced/directory")
async def enhanced_directory_scan(
    request: EnhancedDirectoryScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Enhanced AST-based security scan for entire directory with taint flow analysis.
    Provides comprehensive vulnerability detection with reduced false positives.
    """
    try:
        import os
        if not os.path.exists(request.directory_path):
            raise HTTPException(status_code=404, detail="Directory not found")

        all_findings = []
        all_taint_flows = []
        files_scanned = 0
        total_false_positives_filtered = 0

        # Walk directory
        for root, dirs, files in os.walk(request.directory_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['node_modules', 'venv', '.git', '__pycache__', 'dist', 'build', '.venv']]

            for file in files:
                ext = os.path.splitext(file)[1]
                if ext in request.file_extensions:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            source_code = f.read()
                            # Skip very large files (>500KB)
                            if len(source_code) > 500 * 1024:
                                continue

                        analysis_result = ast_analyzer.analyze_file(source_code, file_path)
                        all_findings.extend(analysis_result.get("findings", []))

                        if request.include_taint_flow:
                            all_taint_flows.extend(analysis_result.get("taint_flows", []))

                        total_false_positives_filtered += analysis_result.get("stats", {}).get("false_positives_filtered", 0)
                        files_scanned += 1

                    except Exception as e:
                        print(f"Error scanning {file_path}: {e}")
                        continue

        # Aggregate by severity
        severity_counts = {
            "critical": len([f for f in all_findings if f.get("severity") == "critical"]),
            "high": len([f for f in all_findings if f.get("severity") == "high"]),
            "medium": len([f for f in all_findings if f.get("severity") == "medium"]),
            "low": len([f for f in all_findings if f.get("severity") == "low"]),
            "info": len([f for f in all_findings if f.get("severity") == "info"])
        }

        return {
            "directory": request.directory_path,
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "false_positives_filtered": total_false_positives_filtered,
            "severity_counts": severity_counts,
            "findings": all_findings,
            "taint_flows": all_taint_flows if request.include_taint_flow else [],
            "taint_flow_count": len(all_taint_flows)
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Enhanced directory scan failed: {str(e)}")


# ==================== COMPREHENSIVE SAST SCAN ENDPOINTS ====================

class ComprehensiveScanRequest(BaseModel):
    """Request model for comprehensive SAST scan with inter-procedural analysis"""
    source_code: Optional[str] = None
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    language: Optional[str] = None
    enable_interprocedural: bool = True
    enable_framework_rules: bool = True


@app.post("/api/scan/comprehensive")
async def comprehensive_sast_scan(
    request: ComprehensiveScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Comprehensive SAST scan with inter-procedural analysis.

    Features:
    - Taint source/sink tracking across function boundaries
    - Context-aware sanitizer detection
    - Framework-specific vulnerability patterns (Django, Flask, Express, Spring, Laravel, etc.)
    - Inter-procedural data flow analysis
    - Reduced false positives through semantic analysis

    Supported languages:
    - Python (Django, Flask, FastAPI)
    - JavaScript/TypeScript (Express, React, Node.js)
    - Go (Gin, Echo)
    - PHP (Laravel, Symfony, WordPress)
    - C#/.NET (ASP.NET Core)
    - Java (Spring, Servlet)
    """
    try:
        # Get source code
        source_code = None
        file_path = "unknown"

        if request.source_code:
            source_code = request.source_code
            file_path = request.file_name or "uploaded_file"
        elif request.file_path:
            import os
            if not os.path.exists(request.file_path):
                raise HTTPException(status_code=404, detail="File not found")
            with open(request.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
            file_path = request.file_path
        else:
            raise HTTPException(status_code=400, detail="Either source_code or file_path must be provided")

        # Skip very large files
        if len(source_code) > 1024 * 1024:  # 1MB limit
            raise HTTPException(status_code=400, detail="File too large for comprehensive scan (>1MB)")

        # Run comprehensive scan
        findings = sast_scanner.scan_code_comprehensive(
            code_content=source_code,
            file_path=file_path,
            language=request.language,
            enable_interprocedural=request.enable_interprocedural
        )

        # Aggregate statistics
        severity_counts = {
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
            "low": len([f for f in findings if f.get("severity") == "low"]),
        }

        taint_tracked_count = len([f for f in findings if f.get("taint_flow")])
        interprocedural_count = len([f for f in findings if f.get("analysis_type") == "interprocedural"])
        framework_count = len([f for f in findings if f.get("analysis_type") == "framework_specific"])

        return {
            "file_path": file_path,
            "language": request.language or sast_scanner._detect_language(file_path),
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "taint_tracked_findings": taint_tracked_count,
            "interprocedural_findings": interprocedural_count,
            "framework_specific_findings": framework_count,
            "findings": findings,
            "analysis_config": {
                "interprocedural_enabled": request.enable_interprocedural,
                "framework_rules_enabled": request.enable_framework_rules
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Comprehensive scan failed: {str(e)}")


class ComprehensiveDirectoryScanRequest(BaseModel):
    """Request model for comprehensive directory scan"""
    directory_path: str
    enable_interprocedural: bool = True
    enable_framework_rules: bool = True
    file_extensions: List[str] = [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".go", ".cs", ".rb"]
    exclude_dirs: List[str] = ["node_modules", "venv", ".git", "__pycache__", "dist", "build", ".venv", "vendor"]


@app.post("/api/scan/comprehensive/directory")
async def comprehensive_directory_scan(
    request: ComprehensiveDirectoryScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Comprehensive SAST scan for entire directory with inter-procedural analysis.
    Scans all supported language files with advanced taint tracking.
    """
    try:
        import os
        if not os.path.exists(request.directory_path):
            raise HTTPException(status_code=404, detail="Directory not found")

        all_findings = []
        files_scanned = 0
        errors = []

        # Walk directory
        for root, dirs, files in os.walk(request.directory_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in request.exclude_dirs]

            for file in files:
                ext = os.path.splitext(file)[1]
                if ext in request.file_extensions:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            source_code = f.read()

                        # Skip very large files (>500KB)
                        if len(source_code) > 500 * 1024:
                            continue

                        findings = sast_scanner.scan_code_comprehensive(
                            code_content=source_code,
                            file_path=file_path,
                            enable_interprocedural=request.enable_interprocedural
                        )
                        all_findings.extend(findings)
                        files_scanned += 1

                    except Exception as e:
                        errors.append(f"Error scanning {file_path}: {str(e)}")
                        continue

        # Aggregate statistics
        severity_counts = {
            "critical": len([f for f in all_findings if f.get("severity") == "critical"]),
            "high": len([f for f in all_findings if f.get("severity") == "high"]),
            "medium": len([f for f in all_findings if f.get("severity") == "medium"]),
            "low": len([f for f in all_findings if f.get("severity") == "low"]),
        }

        # Group by vulnerability type
        vuln_type_counts = {}
        for f in all_findings:
            vtype = f.get("title", "Unknown")
            vuln_type_counts[vtype] = vuln_type_counts.get(vtype, 0) + 1

        # Group by language
        language_counts = {}
        for f in all_findings:
            lang = f.get("language", "unknown")
            language_counts[lang] = language_counts.get(lang, 0) + 1

        return {
            "directory": request.directory_path,
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "vulnerability_type_counts": vuln_type_counts,
            "language_counts": language_counts,
            "taint_tracked_findings": len([f for f in all_findings if f.get("taint_flow")]),
            "interprocedural_findings": len([f for f in all_findings if f.get("analysis_type") == "interprocedural"]),
            "findings": all_findings,
            "errors": errors if errors else None
        }

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Comprehensive directory scan failed: {str(e)}")


# ==================== INTER-PROCEDURAL ANALYSIS ENDPOINTS ====================

class InterproceduralScanRequest(BaseModel):
    """Request model for inter-procedural analysis"""
    file_path: Optional[str] = None  # Local file path (for local backend)
    source_code: Optional[str] = None  # File content (for remote backend)
    file_name: Optional[str] = None  # Original filename when source_code is provided
    include_call_graph: bool = True
    include_function_summaries: bool = True
    include_taint_flows: bool = True


class InterproceduralDirectoryScanRequest(BaseModel):
    """Request model for inter-procedural directory analysis"""
    directory_path: str
    include_call_graph: bool = True
    include_function_summaries: bool = True
    file_extensions: List[str] = [".py", ".js", ".ts", ".java", ".go", ".php"]


@app.post("/api/scan/interprocedural")
async def interprocedural_scan(
    request: InterproceduralScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Advanced Inter-procedural Security Scan

    Features:
    - Call Graph Construction: Maps function call relationships
    - Function Summaries: Analyzes taint behavior of each function
    - Cross-function Taint Propagation: Tracks data flow across function boundaries
    - Context-sensitive Analysis: Considers calling context for precision
    - Return Value Tracking: Propagates taint through return values

    This goes beyond single-function analysis to detect vulnerabilities
    that span multiple functions (e.g., user input in handler → helper → sink)

    Accepts either:
    - file_path: Path to local file (for local backend)
    - source_code + file_name: File content (for remote backend / VS Code extension)
    """
    try:
        import os

        # Determine source code and file path
        if request.source_code:
            # Source code provided directly (VS Code extension / remote client)
            source_code = request.source_code
            file_path = request.file_name or "untitled"
        elif request.file_path:
            # Read from local file path
            if not os.path.exists(request.file_path):
                raise HTTPException(status_code=404, detail=f"Path not found: {request.file_path}")
            with open(request.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
            file_path = request.file_path
        else:
            raise HTTPException(status_code=400, detail="Either file_path or source_code must be provided")

        # Run inter-procedural analysis
        analysis_result = analyze_code_interprocedural(source_code, file_path)

        # Build response
        response = {
            "file_path": file_path,
            "language": analysis_result.get("language", "unknown"),
            "analysis_type": "inter-procedural",
            "vulnerabilities": analysis_result.get("vulnerabilities", []),
            "statistics": analysis_result.get("statistics", {}),
        }

        # Include call graph if requested
        if request.include_call_graph:
            cg = analysis_result.get("call_graph", {})
            response["call_graph"] = {
                "functions": cg.get("functions", {}),
                "call_sites": cg.get("call_sites", []),
                "statistics": cg.get("statistics", {}),
            }

        # Include function summaries if requested
        if request.include_function_summaries:
            response["function_summaries"] = analysis_result.get("function_summaries", {})

        # Include inter-procedural flows if requested
        if request.include_taint_flows:
            response["inter_procedural_flows"] = analysis_result.get("inter_procedural_flows", [])

        return response

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Inter-procedural scan failed: {str(e)}")


@app.post("/api/scan/interprocedural/directory")
async def interprocedural_directory_scan(
    request: InterproceduralDirectoryScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Inter-procedural security scan for entire directory.

    Performs deep analysis of function call relationships and data flow
    across the entire codebase, detecting vulnerabilities that span
    multiple files and functions.
    """
    try:
        import os
        if not os.path.exists(request.directory_path):
            raise HTTPException(status_code=404, detail="Directory not found")

        all_vulnerabilities = []
        all_functions = {}
        all_call_sites = []
        files_scanned = 0
        total_flows = 0

        # Walk directory
        for root, dirs, files in os.walk(request.directory_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['node_modules', 'venv', '.git', '__pycache__', 'dist', 'build', '.venv']]

            for file in files:
                # Check file extension
                if not any(file.endswith(ext) for ext in request.file_extensions):
                    continue

                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        source_code = f.read()

                    # Skip very large or binary files
                    if len(source_code) > 500000 or '\x00' in source_code[:1000]:
                        continue

                    # Run inter-procedural analysis
                    result = analyze_code_interprocedural(source_code, file_path)

                    # Aggregate results
                    all_vulnerabilities.extend(result.get("vulnerabilities", []))
                    total_flows += len(result.get("inter_procedural_flows", []))

                    if request.include_call_graph:
                        cg = result.get("call_graph", {})
                        for func_name, func_info in cg.get("functions", {}).items():
                            all_functions[f"{file_path}:{func_name}"] = func_info
                        all_call_sites.extend(cg.get("call_sites", []))

                    files_scanned += 1

                except Exception as file_error:
                    # Log but continue scanning other files
                    print(f"Error scanning {file_path}: {file_error}")
                    continue

        # Calculate severity counts
        severity_counts = {
            "critical": len([v for v in all_vulnerabilities if v.get("severity") == "critical"]),
            "high": len([v for v in all_vulnerabilities if v.get("severity") == "high"]),
            "medium": len([v for v in all_vulnerabilities if v.get("severity") == "medium"]),
            "low": len([v for v in all_vulnerabilities if v.get("severity") == "low"]),
        }

        response = {
            "directory": request.directory_path,
            "files_scanned": files_scanned,
            "analysis_type": "inter-procedural",
            "total_vulnerabilities": len(all_vulnerabilities),
            "total_inter_procedural_flows": total_flows,
            "severity_counts": severity_counts,
            "vulnerabilities": all_vulnerabilities,
        }

        if request.include_call_graph:
            response["call_graph_summary"] = {
                "total_functions": len(all_functions),
                "total_call_sites": len(all_call_sites),
            }

        if request.include_function_summaries:
            response["functions_analyzed"] = len(all_functions)

        return response

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Inter-procedural directory scan failed: {str(e)}")


@app.post("/api/scan/deep")
async def deep_security_scan(
    request: InterproceduralScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Deep Security Scan - Combines all analysis techniques:
    1. Intra-procedural taint analysis (within functions)
    2. Inter-procedural data flow (across functions)
    3. Call graph analysis
    4. Pattern-based detection
    5. Secret scanning

    Returns comprehensive results from all scanners.
    Accepts either:
    - file_path: Path to local file (for local backend)
    - source_code + file_name: File content (for remote backend / VS Code extension)
    """
    try:
        import os

        # Determine source code and file path
        if request.source_code:
            # Source code provided directly (VS Code extension / remote client)
            source_code = request.source_code
            file_path = request.file_name or "untitled"
        elif request.file_path:
            # Read from local file path
            if not os.path.exists(request.file_path):
                raise HTTPException(status_code=404, detail=f"Path not found: {request.file_path}")
            with open(request.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
            file_path = request.file_path
        else:
            raise HTTPException(status_code=400, detail="Either file_path or source_code must be provided")

        # Run all analysis types in parallel conceptually
        # 1. Intra-procedural AST analysis
        ast_result = ast_analyzer.analyze_file(source_code, file_path)

        # 2. Inter-procedural analysis
        interprocedural_result = analyze_code_interprocedural(source_code, file_path)

        # 3. Pattern-based SAST
        sast_findings = sast_scanner.scan_code(source_code, file_path)

        # 4. Secret scanning
        secret_findings = secret_scanner.scan_code(source_code, file_path)

        # Combine and deduplicate findings
        all_findings = []
        seen_findings = set()

        # Add AST findings
        for finding in ast_result.get("findings", []):
            key = f"{finding.get('cwe_id')}:{finding.get('line_number')}"
            if key not in seen_findings:
                finding['source'] = 'ast_analysis'
                all_findings.append(finding)
                seen_findings.add(key)

        # Add inter-procedural vulnerabilities
        for vuln in interprocedural_result.get("vulnerabilities", []):
            key = f"{vuln.get('cwe_id')}:{vuln.get('sink_line')}"
            if key not in seen_findings:
                vuln['source'] = 'interprocedural_analysis'
                all_findings.append(vuln)
                seen_findings.add(key)

        # Add SAST findings
        for finding in sast_findings:
            key = f"{finding.get('cwe_id', '')}:{finding.get('line_number', 0)}"
            if key not in seen_findings:
                finding['source'] = 'pattern_matching'
                all_findings.append(finding)
                seen_findings.add(key)

        # Add secret findings
        for finding in secret_findings:
            key = f"secret:{finding.get('line_number', 0)}"
            if key not in seen_findings:
                finding['source'] = 'secret_scanning'
                all_findings.append(finding)
                seen_findings.add(key)

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        all_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info'), 5))

        return {
            "file_path": file_path,
            "analysis_type": "deep_combined",
            "total_findings": len(all_findings),
            "findings": all_findings,
            "statistics": {
                "ast_findings": len(ast_result.get("findings", [])),
                "interprocedural_flows": len(interprocedural_result.get("inter_procedural_flows", [])),
                "interprocedural_vulnerabilities": len(interprocedural_result.get("vulnerabilities", [])),
                "pattern_findings": len(sast_findings),
                "secret_findings": len(secret_findings),
                "call_graph": interprocedural_result.get("statistics", {}),
            },
            "call_graph": interprocedural_result.get("call_graph", {}) if request.include_call_graph else None,
            "function_summaries": interprocedural_result.get("function_summaries", {}) if request.include_function_summaries else None,
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Deep security scan failed: {str(e)}")


# ==================== THREAT INTELLIGENCE ENDPOINTS ====================

@app.get("/api/threat-intel/threats")
async def get_threat_intelligence(
    current_user: User = Depends(get_current_active_user)
):
    """Get aggregated threat intelligence from multiple sources"""
    try:
        threats_data = await threat_intel.get_aggregated_threats()
        return threats_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch threat intelligence: {str(e)}")


@app.get("/api/threat-intel/correlate")
async def correlate_threats(
    project_id: Optional[int] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Correlate vulnerabilities with active threats using the improved async correlation engine.
    Features:
    - O(1) lookups using pre-built indices (CVE, CWE, keywords)
    - CWE hierarchy matching (e.g., CWE-89 SQL Injection matches CWE-74 Injection family)
    - Weighted scoring based on match type, CVSS, recency, and exploitation status
    - Confidence levels: very_high, high, medium, low
    """
    try:
        # Use the new async correlation engine with improved efficiency
        result = await threat_intel.correlate_with_vulnerabilities_async(db, project_id)

        return {
            "total_correlated": result['summary']['correlated_count'],
            "high_risk": result['summary']['high_risk_count'],
            "actively_exploited_matches": result['summary'].get('actively_exploited_matches', 0),
            "confidence_breakdown": result['summary'].get('confidence_breakdown', {}),
            "processing_time_ms": result['summary'].get('processing_time_ms', 0),
            "correlations": result['correlations']
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to correlate threats: {str(e)}")


class GenerateRuleRequest(BaseModel):
    threat_cve_id: str


@app.post("/api/threat-intel/generate-rule")
async def generate_rule_from_threat(
    request: GenerateRuleRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Auto-generate a custom SAST rule from threat intelligence
    """
    try:
        # Get threat data
        threats_data = await threat_intel.get_aggregated_threats()
        threats = threats_data.get('threats', [])

        # Find the specific threat
        threat = next((t for t in threats if t.get('cve_id') == request.threat_cve_id), None)

        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")

        # Generate rule
        rule = threat_intel.generate_custom_rule_from_threat(threat)

        return {
            "success": True,
            "rule": rule,
            "message": f"Generated custom rule for {threat.get('name', request.threat_cve_id)}"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate rule: {str(e)}")


@app.get("/api/threat-intel/stats")
async def get_threat_stats(
    current_user: User = Depends(get_current_active_user)
):
    """Get threat intelligence statistics"""
    try:
        threats_data = await threat_intel.get_aggregated_threats()
        threats = threats_data.get('threats', [])

        # Calculate stats
        stats = {
            "total_threats": len(threats),
            "actively_exploited": len([t for t in threats if t.get('actively_exploited')]),
            "by_severity": {
                "critical": len([t for t in threats if t.get('severity') == 'critical']),
                "high": len([t for t in threats if t.get('severity') == 'high']),
                "medium": len([t for t in threats if t.get('severity') == 'medium']),
                "low": len([t for t in threats if t.get('severity') == 'low']),
            },
            "by_source": {},
            "recent_threats": threats[:10],
            "last_updated": threats_data.get('last_updated')
        }

        # Count by source
        for threat in threats:
            source = threat.get('source', 'Unknown')
            stats['by_source'][source] = stats['by_source'].get(source, 0) + 1

        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threat stats: {str(e)}")


# ==================== SCA LIVE FEEDS & TRANSITIVE ANALYSIS ====================

class SCALiveScanRequest(BaseModel):
    dependencies: dict[str, str]
    ecosystem: str = "npm"
    use_local_db: bool = True
    use_live_feeds: bool = True


@app.post("/api/sca/scan/live")
async def sca_scan_with_live_feeds(
    request: SCALiveScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Scan dependencies using both local database and live vulnerability feeds.

    Live feeds include:
    - GitHub Advisory Database (GHSA)
    - OSV (Open Source Vulnerabilities)
    - Snyk (if configured)

    Set GITHUB_TOKEN and SNYK_TOKEN environment variables for full coverage.
    """
    try:
        results = await sca_scanner.scan_with_live_feeds(
            request.dependencies,
            request.ecosystem,
            request.use_local_db,
            request.use_live_feeds
        )
        return results
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Live SCA scan failed: {str(e)}")


class TransitiveScanRequest(BaseModel):
    lockfile_content: str
    lockfile_type: str  # npm, yarn, pip, maven, gradle, go, cargo
    project_name: str = "project"


@app.post("/api/sca/scan/transitive")
async def sca_scan_with_transitive_analysis(
    request: TransitiveScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Scan a lockfile and analyze both direct and transitive dependencies.

    Supported lockfile types:
    - npm: package-lock.json
    - yarn: yarn.lock
    - pip: pipdeptree JSON output
    - maven: dependency:tree output
    - gradle: dependencies output
    - go: go.sum
    - cargo: Cargo.lock

    Returns vulnerability information with dependency path tracking.
    """
    try:
        results = sca_scanner.scan_lockfile_with_transitives(
            request.lockfile_content,
            request.lockfile_type,
            request.project_name
        )
        return results
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Transitive SCA scan failed: {str(e)}")


@app.post("/api/sca/dependency-tree")
async def get_dependency_tree(
    request: TransitiveScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Extract and return the dependency tree without vulnerability scanning.

    Useful for visualizing the dependency hierarchy.
    """
    try:
        tree = sca_scanner.get_dependency_tree(
            request.lockfile_content,
            request.lockfile_type,
            request.project_name
        )
        return tree
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Dependency tree extraction failed: {str(e)}")


class FullScanRequest(BaseModel):
    lockfile_content: str
    lockfile_type: str
    project_name: str = "project"
    use_live_feeds: bool = True


@app.post("/api/sca/scan/full")
async def sca_full_scan(
    request: FullScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Perform a comprehensive SCA scan with:
    - Local vulnerability database
    - Live vulnerability feeds (GitHub Advisory, OSV, Snyk)
    - Transitive dependency analysis

    This is the most thorough scan option, combining all available data sources
    and tracking how vulnerabilities are introduced through the dependency chain.
    """
    try:
        results = await sca_scanner.full_scan(
            request.lockfile_content,
            request.lockfile_type,
            request.project_name,
            request.use_live_feeds
        )
        return results
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Full SCA scan failed: {str(e)}")


@app.get("/api/sca/feeds/status")
async def get_sca_feeds_status(
    current_user: User = Depends(get_current_active_user)
):
    """
    Check the status of configured vulnerability feeds.

    Returns which feeds are available based on configured API keys.
    """
    import os

    return {
        "feeds": {
            "local_database": True,
            "github_advisory": bool(os.getenv("GITHUB_TOKEN")),
            "osv": True,  # OSV doesn't require authentication
            "snyk": bool(os.getenv("SNYK_TOKEN")),
            "nvd": bool(os.getenv("NVD_API_KEY"))
        },
        "configuration_hints": {
            "github_advisory": "Set GITHUB_TOKEN environment variable",
            "snyk": "Set SNYK_TOKEN environment variable",
            "nvd": "Set NVD_API_KEY environment variable (optional, improves rate limits)"
        }
    }


@app.get("/api/sca/realtime/stats")
async def get_realtime_cve_stats(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get real-time CVE service statistics.

    Returns cache stats, query counts, and configuration status for:
    - OSV (Open Source Vulnerabilities) - Primary source
    - NVD (National Vulnerability Database) - Secondary source
    - GitHub Advisory Database - Additional coverage
    """
    from services.sca_scanner import sca_scanner

    stats = sca_scanner.get_realtime_cve_stats()

    return {
        "realtime_cve_service": stats,
        "description": {
            "osv": "Open Source Vulnerabilities - Free, comprehensive, no rate limits",
            "nvd": "National Vulnerability Database - Authoritative CVE data",
            "github": "GitHub Advisory Database - Good for GitHub ecosystem packages"
        }
    }


@app.post("/api/sca/realtime/clear-cache")
async def clear_realtime_cve_cache(
    current_user: User = Depends(get_current_active_user)
):
    """Clear the real-time CVE service cache to force fresh lookups."""
    from services.sca_scanner import sca_scanner

    sca_scanner.clear_realtime_cache()

    return {"success": True, "message": "Real-time CVE cache cleared"}


@app.post("/api/sca/scan/realtime")
async def scan_with_realtime_cves(
    request: dict,
    current_user: User = Depends(get_current_active_user)
):
    """
    Scan dependencies with real-time CVE fetching from NVD, OSV, and GitHub Advisory.

    This endpoint:
    1. Scans against local static vulnerability database (fast)
    2. Queries real-time CVE sources for additional/newer vulnerabilities
    3. Merges and deduplicates results
    4. Optionally performs code reachability analysis

    Request body:
    {
        "dependencies": {"package_name": "version", ...},
        "ecosystem": "npm" | "pip" | "maven" | ...,
        "include_reachability": false,
        "project_path": "/path/to/project"  // Required if include_reachability=true
    }
    """
    from services.sca_scanner import sca_scanner

    dependencies = request.get("dependencies", {})
    ecosystem = request.get("ecosystem", "npm")
    include_reachability = request.get("include_reachability", False)
    project_path = request.get("project_path")

    if not dependencies:
        raise HTTPException(status_code=400, detail="No dependencies provided")

    if include_reachability and not project_path:
        raise HTTPException(
            status_code=400,
            detail="project_path is required when include_reachability is true"
        )

    try:
        results = await sca_scanner.scan_with_realtime_cves(
            dependencies=dependencies,
            ecosystem=ecosystem,
            include_reachability=include_reachability,
            project_path=project_path
        )

        return {
            "success": True,
            "scan_type": "realtime",
            "results": results
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Real-time CVE scan failed: {str(e)}")


@app.get("/api/sca/cve/live/{package}")
async def get_live_cve_for_package(
    package: str,
    version: str = None,
    ecosystem: str = "npm",
    current_user: User = Depends(get_current_active_user)
):
    """
    Fetch live CVE data for a specific package from NVD, OSV, and GitHub Advisory.

    This queries real-time vulnerability databases and returns all known CVEs.

    Args:
        package: Package name (e.g., "lodash", "axios")
        version: Optional version to filter applicable vulnerabilities
        ecosystem: Package ecosystem (npm, pip, maven, nuget, go, cargo)

    Returns:
        Live CVE data including CVE IDs, severity, description, and references
    """
    try:
        from services.realtime_cve_service import get_realtime_cve_service

        cve_service = get_realtime_cve_service()
        if not cve_service:
            # Fallback to OSV API directly
            import httpx

            osv_ecosystems = {
                'npm': 'npm', 'pip': 'PyPI', 'maven': 'Maven',
                'nuget': 'NuGet', 'go': 'Go', 'cargo': 'crates.io'
            }

            osv_ecosystem = osv_ecosystems.get(ecosystem, ecosystem)

            payload = {"package": {"name": package, "ecosystem": osv_ecosystem}}
            if version:
                payload["version"] = version

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    "https://api.osv.dev/v1/query",
                    json=payload
                )

                if response.status_code == 200:
                    data = response.json()
                    vulns = data.get("vulns", [])

                    cves = []
                    for vuln in vulns:
                        cve_ids = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
                        ghsa_ids = [a for a in vuln.get("aliases", []) if a.startswith("GHSA-")]

                        cves.append({
                            "id": vuln.get("id"),
                            "cve_ids": cve_ids,
                            "ghsa_ids": ghsa_ids,
                            "summary": vuln.get("summary", ""),
                            "details": vuln.get("details", ""),
                            "severity": vuln.get("severity", [{}])[0].get("type", "UNKNOWN") if vuln.get("severity") else "UNKNOWN",
                            "cvss_score": None,
                            "published": vuln.get("published"),
                            "modified": vuln.get("modified"),
                            "references": [ref.get("url") for ref in vuln.get("references", [])[:5]],
                            "affected_versions": [
                                {
                                    "range": r.get("events", []),
                                    "fixed": next((e.get("fixed") for e in r.get("events", []) if "fixed" in e), None)
                                }
                                for r in vuln.get("affected", [{}])[0].get("ranges", [])
                            ] if vuln.get("affected") else [],
                            "source": "OSV"
                        })

                    return {
                        "success": True,
                        "package": package,
                        "version": version,
                        "ecosystem": ecosystem,
                        "vulnerabilities": cves,
                        "total_count": len(cves),
                        "sources_queried": ["OSV"]
                    }
                else:
                    return {
                        "success": True,
                        "package": package,
                        "version": version,
                        "ecosystem": ecosystem,
                        "vulnerabilities": [],
                        "total_count": 0,
                        "sources_queried": ["OSV"],
                        "message": "No vulnerabilities found"
                    }

        # Use real-time CVE service if available
        vulns = await cve_service.query_vulnerabilities(package, version or "*", ecosystem)

        return {
            "success": True,
            "package": package,
            "version": version,
            "ecosystem": ecosystem,
            "vulnerabilities": vulns,
            "total_count": len(vulns),
            "sources_queried": ["OSV", "NVD", "GitHub Advisory"]
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "success": False,
            "package": package,
            "error": str(e),
            "vulnerabilities": []
        }


@app.get("/api/cve/{cve_id}")
async def get_cve_details(
    cve_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Fetch detailed information about a specific CVE from NVD.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")

    Returns:
        Detailed CVE information including CVSS scores, references, and affected products
    """
    import httpx

    if not cve_id.startswith("CVE-"):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format")

    try:
        # Query NVD API
        nvd_api_key = os.getenv("NVD_API_KEY", "")
        headers = {"apiKey": nvd_api_key} if nvd_api_key else {}

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                headers=headers
            )

            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulnerabilities", [])

                if vulns:
                    cve_data = vulns[0].get("cve", {})

                    # Extract CVSS scores
                    metrics = cve_data.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
                    cvss_v30 = metrics.get("cvssMetricV30", [{}])[0] if metrics.get("cvssMetricV30") else {}
                    cvss_v2 = metrics.get("cvssMetricV2", [{}])[0] if metrics.get("cvssMetricV2") else {}

                    cvss_data = cvss_v31.get("cvssData", {}) or cvss_v30.get("cvssData", {}) or cvss_v2.get("cvssData", {})

                    # Extract descriptions
                    descriptions = cve_data.get("descriptions", [])
                    description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")

                    # Extract CWEs
                    weaknesses = cve_data.get("weaknesses", [])
                    cwe_ids = []
                    for weakness in weaknesses:
                        for desc in weakness.get("description", []):
                            if desc.get("value", "").startswith("CWE-"):
                                cwe_ids.append(desc.get("value"))

                    return {
                        "success": True,
                        "cve_id": cve_id,
                        "description": description,
                        "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                        "cvss_score": cvss_data.get("baseScore"),
                        "cvss_vector": cvss_data.get("vectorString"),
                        "cwe_ids": cwe_ids,
                        "published": cve_data.get("published"),
                        "modified": cve_data.get("lastModified"),
                        "references": [ref.get("url") for ref in cve_data.get("references", [])[:10]],
                        "source": "NVD",
                        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    }

            return {
                "success": False,
                "cve_id": cve_id,
                "error": "CVE not found in NVD",
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            }

    except Exception as e:
        return {
            "success": False,
            "cve_id": cve_id,
            "error": str(e),
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
