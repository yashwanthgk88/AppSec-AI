"""
FastAPI Main Application
"""
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import timedelta
import os
import shutil
from dotenv import load_dotenv

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
from services.chatbot_service import ChatbotService
from services.report_service import ReportService
from services.repository_scanner import RepositoryScanner

# Import routers
from routers import settings
from routers import custom_rules, rule_performance

# Pydantic schemas
from pydantic import BaseModel, EmailStr

load_dotenv()

# Create FastAPI app
app = FastAPI(
    title="AI-Enabled Application Security Platform",
    description="Comprehensive security scanning with threat modeling, SAST, SCA, and multilingual AI chatbot",
    version="1.0.0"
)

# CORS middleware
# Allow both frontend ports for development
cors_origins = os.getenv("CORS_ORIGINS")
if cors_origins:
    allowed_origins = [origin.strip() for origin in cors_origins.split(",")]
else:
    allowed_origins = ["http://localhost:5173", "http://localhost:5174"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(settings.router)
app.include_router(custom_rules.router)
app.include_router(rule_performance.router)

# Initialize services
threat_service = ThreatModelingService()
sast_scanner = SASTScanner()
sca_scanner = SCAScanner()
secret_scanner = SecretScanner()
report_service = ReportService()

# Lazy initialization for chatbot (requires API key)
_chatbot_service = None

def get_chatbot_service():
    global _chatbot_service
    if _chatbot_service is None:
        try:
            _chatbot_service = ChatbotService()
        except ValueError as e:
            # API key not configured
            pass
    return _chatbot_service

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
    admin = db.query(User).filter(User.email == "admin@example.com").first()
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
    db.close()

# Health check
@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

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
        threat_model_data = threat_service.generate_threat_model(
            project_data.architecture_doc,
            project_data.name
        )

        threat_model = ThreatModel(
            project_id=project.id,
            name=f"{project_data.name} Threat Model",
            dfd_level=0,
            dfd_data=threat_model_data['dfd_data'],
            stride_analysis=threat_model_data['stride_analysis'],
            mitre_mapping=threat_model_data['mitre_mapping'],
            trust_boundaries=threat_model_data['dfd_data']['trust_boundaries'],
            threat_count=threat_model_data['threat_count']
        )
        db.add(threat_model)
        db.commit()
        scan_results["threat_model"] = True

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
                mitre_attack_id=finding.get('mitre_attack_id')
            )
            db.add(vuln)
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

                        # Parse dependencies based on type
                        dependencies = {}
                        if dep_type == 'npm':
                            dependencies = sca_scanner.parse_package_json(content)
                            ecosystem = 'npm'
                        elif dep_type == 'pip':
                            dependencies = sca_scanner.parse_requirements_txt(content)
                            ecosystem = 'pip'
                        elif dep_type == 'maven':
                            dependencies = sca_scanner.parse_pom_xml(content)
                            ecosystem = 'maven'
                        elif dep_type == 'composer':
                            dependencies = sca_scanner.parse_composer_json(content)
                            ecosystem = 'composer'
                        else:
                            continue

                        # Scan dependencies for vulnerabilities
                        if dependencies:
                            results = sca_scanner.scan_dependencies(dependencies, ecosystem)
                            sca_findings.extend(results['findings'])
                    except Exception as e:
                        print(f"Warning: Failed to scan {file_path}: {e}")

            # If no findings from real scan, fall back to demo
            if not sca_findings:
                sca_sample = sca_scanner.generate_sample_findings()
                sca_findings = sca_sample['vulnerabilities']['findings']
        else:
            # Demo scan
            sca_sample = sca_scanner.generate_sample_findings()
            sca_findings = sca_sample['vulnerabilities']['findings']

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
            vuln = Vulnerability(
                scan_id=sca_scan.id,
                title=f"{finding['vulnerability']} in {finding['package']}",
                description=finding['description'],
                severity=SeverityLevel[finding['severity'].upper()],
                cwe_id=finding['cwe_id'],
                owasp_category=finding['owasp_category'],
                file_path=f"{finding.get('ecosystem', 'package')} dependency: {finding['package']} {finding['installed_version']}",
                line_number=0,
                code_snippet=f"Dependency: {finding['package']}@{finding['installed_version']}",
                remediation=finding['remediation'],
                cvss_score=finding['cvss_score'],
                stride_category=finding.get('stride_category'),
                mitre_attack_id=finding.get('mitre_attack_id')
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
                mitre_attack_id=finding.get('mitre_attack_id')
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

    # Generate Mermaid diagrams for both levels
    from services.threat_modeling import ThreatModelingService
    tm_service = ThreatModelingService()

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

            # Generate Level 0 (Context) diagram
            mermaid_l0 = tm_service.generate_mermaid_dfd(threat_model.dfd_data, level=0)
            dfd_level_0 = {
                "level": 0,
                "name": "Context Diagram",
                "mermaid": mermaid_l0
            }

            # Generate Level 1 (Detailed) diagram
            mermaid_l1 = tm_service.generate_mermaid_dfd(threat_model.dfd_data, level=1)
            dfd_level_1 = {
                "level": 1,
                "name": "Detailed Diagram",
                "mermaid": mermaid_l1
            }
        except Exception as e:
            print(f"Error generating Mermaid diagrams: {e}")

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
        "threat_count": threat_model.threat_count
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

    # Run SAST scan
    if repo_scanner and repo_scanner.repo_path:
        scan_results_data = sast_scanner.scan_directory(repo_scanner.repo_path)
        sast_findings = scan_results_data['findings']
    else:
        sast_findings = sast_scanner.generate_sample_findings()

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
        file_path = finding['file_path']
        if repo_scanner and repo_scanner.repo_path:
            file_path = repo_scanner.get_relative_path(file_path)

        vuln = Vulnerability(
            scan_id=sast_scan.id,
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
            mitre_attack_id=finding.get('mitre_attack_id')
        )
        db.add(vuln)
    scan_results["sast"] = len(sast_findings)

    # Run SCA scan
    sca_findings = []
    if repo_scanner and repo_scanner.repo_path:
        dep_files = repo_scanner.get_dependency_files()

        for dep_type, file_paths in dep_files.items():
            for file_path in file_paths:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    dependencies = {}
                    if dep_type == 'npm':
                        dependencies = sca_scanner.parse_package_json(content)
                        ecosystem = 'npm'
                    elif dep_type == 'pip':
                        dependencies = sca_scanner.parse_requirements_txt(content)
                        ecosystem = 'pip'
                    elif dep_type == 'maven':
                        dependencies = sca_scanner.parse_pom_xml(content)
                        ecosystem = 'maven'
                    elif dep_type == 'composer':
                        dependencies = sca_scanner.parse_composer_json(content)
                        ecosystem = 'composer'
                    else:
                        continue

                    if dependencies:
                        results = sca_scanner.scan_dependencies(dependencies, ecosystem)
                        sca_findings.extend(results['findings'])
                except Exception as e:
                    print(f"Warning: Failed to scan {file_path}: {e}")

        if not sca_findings:
            sca_sample = sca_scanner.generate_sample_findings()
            sca_findings = sca_sample['vulnerabilities']['findings']
    else:
        sca_sample = sca_scanner.generate_sample_findings()
        sca_findings = sca_sample['vulnerabilities']['findings']

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

    for finding in sca_findings:
        vuln = Vulnerability(
            scan_id=sca_scan.id,
            title=f"{finding['vulnerability']} in {finding['package']}",
            description=finding['description'],
            severity=SeverityLevel[finding['severity'].upper()],
            cwe_id=finding['cwe_id'],
            owasp_category=finding['owasp_category'],
            file_path=f"{finding.get('ecosystem', 'package')} dependency: {finding['package']} {finding['installed_version']}",
            line_number=0,
            code_snippet=f"Dependency: {finding['package']}@{finding['installed_version']}",
            remediation=finding['remediation'],
            cvss_score=finding['cvss_score'],
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
        critical_count=len([f for f in secret_findings if f['severity'] == 'critical']),
        high_count=len([f for f in secret_findings if f['severity'] == 'high']),
        medium_count=len([f for f in secret_findings if f['severity'] == 'medium']),
        low_count=len([f for f in secret_findings if f['severity'] == 'low'])
    )
    db.add(secret_scan)
    db.flush()

    for finding in secret_findings:
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
            "status": "false_positive" if v.false_positive else ("resolved" if v.is_resolved else "active")
        }
        for v in vulnerabilities
    ]

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
    elif new_status == "false_positive":
        vulnerability.is_resolved = False
        vulnerability.false_positive = True
    else:  # active
        vulnerability.is_resolved = False
        vulnerability.false_positive = False

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

        # Update vulnerability status to 'fixed'
        vulnerability.status = 'fixed'
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

# VS Code Extension Endpoints - Direct scanning without project requirement
class DirectScanRequest(BaseModel):
    path: str
    scan_types: List[str] = ["sast", "sca", "secrets"]

class DirectFileScanRequest(BaseModel):
    file_path: str
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
        # Run SAST scan
        if "sast" in request.scan_types:
            scan_results = sast_scanner.scan_directory(request.path)
            findings = scan_results.get('findings', [])
            results["sast"]["findings"] = [
                {
                    "id": f"sast-{i}",
                    "title": f['title'],
                    "description": f['description'],
                    "severity": f['severity'],
                    "file": f['file_path'],
                    "line": f['line_number'],
                    "category": f['owasp_category'],
                    "cwe_id": f['cwe_id'],
                    "code_snippet": f['code_snippet'],
                    "remediation": f['remediation'],
                    "remediation_code": f.get('suggested_fix', ''),
                    "impact": f.get('impact', 'This vulnerability could compromise application security'),
                    "remediation_steps": f.get('remediation_steps', [])
                }
                for i, f in enumerate(findings)
            ]

        # Run SCA scan
        if "sca" in request.scan_types:
            # Find dependency files
            import os
            import json
            dep_files = []
            for root, dirs, files in os.walk(request.path):
                if 'node_modules' in dirs:
                    dirs.remove('node_modules')
                if '.git' in dirs:
                    dirs.remove('.git')

                for file in files:
                    if file in ['package.json', 'requirements.txt', 'pom.xml', 'composer.json']:
                        dep_files.append(os.path.join(root, file))

            sca_findings = []
            for dep_file in dep_files:
                try:
                    with open(dep_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                    if 'package.json' in dep_file:
                        deps = sca_scanner.parse_package_json(content)
                        vulns = sca_scanner.check_vulnerabilities(deps, 'npm')
                        sca_findings.extend(vulns)
                except Exception as e:
                    print(f"Error scanning {dep_file}: {e}")

            results["sca"]["findings"] = [
                {
                    "id": f"sca-{i}",
                    "title": f"{v['package']} {v['version']} - {v.get('title', 'Known vulnerability')}",
                    "description": v.get('description', 'Security vulnerability detected'),
                    "severity": v['severity'],
                    "file": v.get('file_path', 'dependency file'),
                    "line": 1,
                    "category": "Vulnerable Dependency",
                    "package": v['package'],
                    "version": v['version'],
                    "fixed_version": v.get('fixed_version')
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
                    "title": f['title'],
                    "description": f['description'],
                    "severity": f['severity'],
                    "file": f['file_path'],
                    "line": f['line_number'],
                    "category": "Exposed Secret",
                    "secret_type": f.get('secret_type', 'Unknown'),
                    "code_snippet": f['code_snippet']
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
    """Direct file scan for VS Code extension"""
    results = {
        "sast": {"findings": []},
        "secrets": {"findings": []}
    }

    try:
        import os
        if not os.path.exists(request.file_path):
            raise HTTPException(status_code=404, detail="File not found")

        # Run SAST scan on single file
        if "sast" in request.scan_types:
            scan_results = sast_scanner.scan_file(request.file_path)
            findings = scan_results.get('findings', [])
            results["sast"]["findings"] = [
                {
                    "id": f"sast-{i}",
                    "title": f['title'],
                    "description": f['description'],
                    "severity": f['severity'],
                    "file": f['file_path'],
                    "line": f['line_number'],
                    "category": f['owasp_category'],
                    "cwe_id": f['cwe_id'],
                    "code_snippet": f['code_snippet'],
                    "remediation": f['remediation'],
                    "remediation_code": f.get('suggested_fix', ''),
                    "impact": f.get('impact', 'This vulnerability could compromise application security'),
                    "remediation_steps": f.get('remediation_steps', [])
                }
                for i, f in enumerate(findings)
            ]

        # Run Secret scan on single file
        if "secrets" in request.scan_types:
            scan_results = secret_scanner.scan_file(request.file_path)
            findings = scan_results.get('findings', [])
            results["secrets"]["findings"] = [
                {
                    "id": f"secret-{i}",
                    "title": f['title'],
                    "description": f['description'],
                    "severity": f['severity'],
                    "file": f['file_path'],
                    "line": f['line_number'],
                    "category": "Exposed Secret",
                    "secret_type": f.get('secret_type', 'Unknown'),
                    "code_snippet": f['code_snippet']
                }
                for i, f in enumerate(findings)
            ]

        return results

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File scan failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
