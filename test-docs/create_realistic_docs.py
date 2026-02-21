#!/usr/bin/env python3
"""Generate realistic architecture documents for testing."""

from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch, cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon
from reportlab.graphics import renderPDF
import io


def create_fintech_architecture_pdf():
    """Create a realistic fintech platform architecture document."""
    filename = "fintech_platform_architecture.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter,
                           leftMargin=0.75*inch, rightMargin=0.75*inch,
                           topMargin=0.75*inch, bottomMargin=0.75*inch)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=24, spaceAfter=20)
    h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=16, spaceBefore=20, spaceAfter=10)
    h3_style = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=12, spaceBefore=15, spaceAfter=8)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=10, spaceAfter=8)

    story = []

    # Title
    story.append(Paragraph("FinSecure Payment Platform", title_style))
    story.append(Paragraph("Technical Architecture Document v3.2", styles['Normal']))
    story.append(Paragraph("Classification: Internal - Confidential", styles['Normal']))
    story.append(Spacer(1, 30))

    # Executive Summary
    story.append(Paragraph("1. Executive Summary", h2_style))
    story.append(Paragraph("""
        FinSecure is a PCI-DSS Level 1 compliant payment processing platform handling over
        $2.5B in annual transaction volume. The platform provides real-time payment processing,
        fraud detection, and merchant services through a microservices architecture deployed
        on AWS with multi-region failover capabilities.
    """, body_style))

    # System Architecture
    story.append(Paragraph("2. System Architecture Overview", h2_style))
    story.append(Paragraph("""
        The platform follows a layered microservices architecture with clear separation between
        external-facing components (DMZ), core business services (Application Layer), and
        sensitive data stores (Data Layer). All inter-service communication uses mTLS with
        certificate rotation every 90 days.
    """, body_style))

    # Components Table
    story.append(Paragraph("2.1 Core System Components", h3_style))

    components_data = [
        ['Component', 'Technology', 'Description', 'Security Controls'],
        ['API Gateway', 'Kong Enterprise', 'Entry point for all external API traffic', 'WAF, Rate limiting, JWT validation'],
        ['Identity Service', 'Keycloak + Custom', 'OAuth2/OIDC provider with MFA', 'HSM-backed keys, Session management'],
        ['Payment Orchestrator', 'Java 17 / Spring Boot', 'Core payment routing and processing', 'PCI-DSS scope, Tokenization'],
        ['Fraud Detection Engine', 'Python / TensorFlow', 'ML-based real-time fraud scoring', 'Anomaly detection, Risk scoring'],
        ['Card Vault', 'Custom C++ / HSM', 'PAN storage and tokenization', 'HSM integration, P2PE encryption'],
        ['Ledger Service', 'Go / CockroachDB', 'Double-entry accounting system', 'Immutable audit log, Reconciliation'],
        ['Notification Hub', 'Node.js / Kafka', 'Multi-channel notifications', 'Template injection prevention'],
        ['Merchant Portal', 'React / Next.js', 'Merchant self-service dashboard', 'CSP headers, XSS protection'],
    ]

    table = Table(components_data, colWidths=[1.3*inch, 1.2*inch, 2.2*inch, 2*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a237e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
    ]))
    story.append(table)
    story.append(Spacer(1, 20))

    # Data Flows
    story.append(Paragraph("2.2 Critical Data Flows", h3_style))

    flows = [
        "1. Payment Authorization Flow:",
        "   Merchant POS → API Gateway (TLS 1.3) → Payment Orchestrator → Card Vault (HSM decrypt) → Card Network → Response",
        "",
        "2. User Authentication Flow:",
        "   Mobile App → CDN → API Gateway → Identity Service → User DB (bcrypt) → JWT issued → Redis session",
        "",
        "3. Fraud Detection Flow:",
        "   Transaction Event → Kafka → Fraud Engine (ML inference) → Risk Score → Payment Orchestrator → Approve/Decline",
        "",
        "4. Settlement Flow:",
        "   Batch Job (2AM UTC) → Ledger Service → Settlement calculations → ACH/Wire submission → Bank API",
    ]

    for flow in flows:
        story.append(Paragraph(flow, body_style))

    # Trust Boundaries
    story.append(Paragraph("3. Trust Boundaries & Network Segmentation", h2_style))

    boundaries_data = [
        ['Zone', 'Components', 'Network', 'Access Control'],
        ['Internet (Untrusted)', 'CDN, WAF', 'Public IPs', 'DDoS protection, Geo-blocking'],
        ['DMZ', 'API Gateway, Load Balancers', '10.1.0.0/24', 'Ingress firewall, IDS/IPS'],
        ['Application Zone', 'All microservices', '10.2.0.0/16', 'Service mesh (Istio), mTLS'],
        ['PCI Zone (CDE)', 'Card Vault, Payment Orch.', '10.3.0.0/24', 'HSM, Network isolation, MFA'],
        ['Data Zone', 'Databases, Caches', '10.4.0.0/24', 'Encryption at rest, VPC endpoints'],
        ['Management Zone', 'Bastion, Monitoring', '10.5.0.0/24', 'MFA + VPN required'],
    ]

    table2 = Table(boundaries_data, colWidths=[1.3*inch, 1.8*inch, 1.2*inch, 2.2*inch])
    table2.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#b71c1c')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ffebee')]),
    ]))
    story.append(table2)
    story.append(Spacer(1, 20))

    # External Integrations
    story.append(Paragraph("4. External System Integrations", h2_style))

    integrations = [
        "<b>Card Networks:</b> Visa (VTS), Mastercard (MDES), Amex - Direct API integration with dedicated circuits",
        "<b>Banking Partners:</b> Wells Fargo (ACH), JP Morgan (Wire transfers) - SFTP with PGP encryption",
        "<b>KYC/AML Providers:</b> Jumio (Identity verification), LexisNexis (Watchlist screening)",
        "<b>Cloud Services:</b> AWS (Primary), Azure (DR), Cloudflare (CDN/DDoS)",
        "<b>Monitoring:</b> Datadog (APM), PagerDuty (Alerting), Splunk (SIEM)",
    ]

    for integration in integrations:
        story.append(Paragraph(f"• {integration}", body_style))

    # Security Controls
    story.append(Paragraph("5. Security Architecture", h2_style))

    story.append(Paragraph("5.1 Authentication & Authorization", h3_style))
    story.append(Paragraph("""
        • OAuth 2.0 with PKCE for all client applications
        • Hardware MFA (FIDO2/WebAuthn) required for privileged access
        • Service-to-service auth via mTLS with short-lived certificates (Vault PKI)
        • Role-Based Access Control (RBAC) with principle of least privilege
        • Session timeout: 15 minutes idle, 8 hours absolute
    """, body_style))

    story.append(Paragraph("5.2 Data Protection", h3_style))
    story.append(Paragraph("""
        • PAN tokenization using format-preserving encryption (FPE)
        • All PII encrypted at rest using AES-256-GCM (AWS KMS)
        • TLS 1.3 enforced for all external connections
        • Database field-level encryption for sensitive columns
        • Key rotation: 90 days for service keys, annual for master keys
    """, body_style))

    story.append(Paragraph("5.3 Logging & Monitoring", h3_style))
    story.append(Paragraph("""
        • Centralized logging with 7-year retention (PCI requirement)
        • Real-time anomaly detection on authentication events
        • Transaction monitoring with velocity checks
        • Automated incident response playbooks
        • Quarterly penetration testing by third party
    """, body_style))

    # Database Architecture
    story.append(Paragraph("6. Data Architecture", h2_style))

    db_data = [
        ['Database', 'Type', 'Data Classification', 'Encryption'],
        ['card_vault_db', 'PostgreSQL (RDS)', 'PCI - Cardholder Data', 'TDE + Column-level'],
        ['user_identity_db', 'PostgreSQL (RDS)', 'PII - Personal Data', 'TDE + Field encryption'],
        ['transaction_ledger', 'CockroachDB', 'Financial Records', 'TDE'],
        ['fraud_features', 'Redis Cluster', 'Derived Data', 'In-transit only'],
        ['audit_logs', 'Elasticsearch', 'Security Logs', 'TDE'],
        ['merchant_config', 'DynamoDB', 'Configuration', 'AWS managed'],
    ]

    table3 = Table(db_data, colWidths=[1.5*inch, 1.3*inch, 1.5*inch, 1.5*inch])
    table3.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#004d40')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#e0f2f1')]),
    ]))
    story.append(table3)

    doc.build(story)
    print(f"Created: {filename}")
    return filename


def create_healthcare_architecture_pdf():
    """Create a realistic healthcare system architecture document."""
    filename = "healthsync_ehr_architecture.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter,
                           leftMargin=0.75*inch, rightMargin=0.75*inch,
                           topMargin=0.75*inch, bottomMargin=0.75*inch)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=24, spaceAfter=20)
    h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=16, spaceBefore=20, spaceAfter=10)
    h3_style = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=12, spaceBefore=15, spaceAfter=8)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=10, spaceAfter=8)

    story = []

    # Title
    story.append(Paragraph("HealthSync EHR Platform", title_style))
    story.append(Paragraph("System Design Document - HIPAA Compliant Architecture", styles['Normal']))
    story.append(Paragraph("Document Version: 2.1 | Last Updated: February 2025", styles['Normal']))
    story.append(Spacer(1, 30))

    # Overview
    story.append(Paragraph("1. System Overview", h2_style))
    story.append(Paragraph("""
        HealthSync is an enterprise Electronic Health Record (EHR) system serving 2,500+ healthcare
        providers across 180 facilities. The platform manages Protected Health Information (PHI) for
        over 12 million patients and processes 500,000+ clinical transactions daily. The architecture
        is designed for HIPAA compliance, HITRUST certification, and SOC 2 Type II requirements.
    """, body_style))

    # Architecture Components
    story.append(Paragraph("2. Core Architecture Components", h2_style))

    components_data = [
        ['Service', 'Technology Stack', 'Function', 'PHI Access'],
        ['Patient Portal', 'React, Node.js, Express', 'Patient self-service, records access', 'Read-only PHI'],
        ['Provider Workstation', 'Angular, .NET Core 8', 'Clinical documentation, orders', 'Full PHI access'],
        ['Clinical API Gateway', 'Kong + AWS API GW', 'FHIR R4 API routing, throttling', 'Pass-through'],
        ['Patient Demographics', 'Java 21, Spring Boot', 'Master patient index, registration', 'Demographics PHI'],
        ['Clinical Documents', 'Python, FastAPI', 'Notes, reports, imaging metadata', 'Clinical PHI'],
        ['Order Management', 'Java 21, Micronaut', 'Lab orders, prescriptions, referrals', 'Order PHI'],
        ['Pharmacy System', 'C#, .NET 8', 'Medication management, e-prescribing', 'Medication PHI'],
        ['Lab Integration Engine', 'Mirth Connect', 'HL7v2/FHIR lab interfaces', 'Lab results PHI'],
        ['Imaging Gateway', 'Go, DICOM', 'PACS integration, image routing', 'Imaging PHI'],
        ['Scheduling Service', 'Node.js, PostgreSQL', 'Appointments, resource management', 'Limited PHI'],
        ['Billing Engine', 'Java, Oracle', 'Claims processing, coding', 'Billing PHI'],
        ['Analytics Platform', 'Spark, Databricks', 'Population health, reporting', 'De-identified data'],
    ]

    table = Table(components_data, colWidths=[1.3*inch, 1.4*inch, 1.8*inch, 1.1*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d47a1')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#e3f2fd')]),
    ]))
    story.append(table)
    story.append(Spacer(1, 15))

    # Data Flows
    story.append(Paragraph("3. Critical Data Flows", h2_style))

    story.append(Paragraph("3.1 Patient Registration Flow", h3_style))
    story.append(Paragraph("""
        Registration Desk → Patient Demographics Service → Identity Verification (Experian) →
        MPI Matching → Master Patient Index (PostgreSQL) → Insurance Eligibility Check (Availity) →
        Account Creation → Welcome Email (encrypted)
    """, body_style))

    story.append(Paragraph("3.2 Clinical Documentation Flow", h3_style))
    story.append(Paragraph("""
        Provider Workstation → Clinical API Gateway (FHIR R4) → Clinical Documents Service →
        Document Storage (S3 encrypted) → Audit Log (immutable) → CDS Alerts Check →
        Real-time sync to Data Warehouse
    """, body_style))

    story.append(Paragraph("3.3 E-Prescribing Flow (EPCS)", h3_style))
    story.append(Paragraph("""
        Provider Order Entry → Pharmacy Service → Drug Interaction Check (FDB) →
        Provider 2FA (DEA requirement) → Digital Signature (HSM) → Surescripts Network →
        Pharmacy Fulfillment → Patient Notification
    """, body_style))

    story.append(Paragraph("3.4 Lab Results Flow", h3_style))
    story.append(Paragraph("""
        Reference Lab (Quest/LabCorp) → HL7v2 Message → Lab Integration Engine (Mirth) →
        FHIR Transformation → Results Repository → Provider In-basket Alert →
        Patient Portal Notification (with provider release)
    """, body_style))

    # HIPAA Controls
    story.append(Paragraph("4. HIPAA Security Controls", h2_style))

    story.append(Paragraph("4.1 Access Controls (§164.312(a))", h3_style))
    story.append(Paragraph("""
        • Unique user identification with role-based access (RBAC)
        • Emergency access procedure with break-glass audit
        • Automatic logoff after 15 minutes of inactivity
        • Multi-factor authentication for all PHI access
        • Minimum necessary access enforcement
    """, body_style))

    story.append(Paragraph("4.2 Audit Controls (§164.312(b))", h3_style))
    story.append(Paragraph("""
        • All PHI access logged with user, timestamp, patient, action
        • Audit logs retained for 7 years (immutable storage)
        • Real-time monitoring for suspicious access patterns
        • Monthly audit log reviews by Privacy Officer
        • Patient access reports available within 48 hours
    """, body_style))

    story.append(Paragraph("4.3 Transmission Security (§164.312(e))", h3_style))
    story.append(Paragraph("""
        • TLS 1.3 for all external communications
        • VPN required for remote workforce access
        • End-to-end encryption for patient messaging
        • Secure email gateway for PHI transmission
        • SFTP with PGP for batch data transfers
    """, body_style))

    # Infrastructure
    story.append(Paragraph("5. Infrastructure Architecture", h2_style))

    infra_data = [
        ['Component', 'Primary', 'DR Site', 'RPO/RTO'],
        ['Application Tier', 'AWS us-east-1 (EKS)', 'AWS us-west-2 (EKS)', '15 min / 4 hours'],
        ['Database Tier', 'Aurora PostgreSQL Multi-AZ', 'Cross-region replica', '5 min / 2 hours'],
        ['Document Storage', 'S3 (SSE-KMS)', 'Cross-region replication', 'Near real-time / 1 hour'],
        ['Identity Provider', 'Okta (HA)', 'Okta (multi-region)', 'N/A / 15 min'],
        ['Message Queue', 'Amazon MQ (Active-Standby)', 'Replicated', '0 / 30 min'],
        ['CDN', 'CloudFront', 'Multi-region', 'N/A'],
    ]

    table2 = Table(infra_data, colWidths=[1.3*inch, 1.8*inch, 1.6*inch, 1*inch])
    table2.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1b5e20')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#e8f5e9')]),
    ]))
    story.append(table2)

    # External Interfaces
    story.append(Paragraph("6. External System Interfaces", h2_style))

    interfaces = [
        "<b>HIE Connections:</b> CommonWell, Carequality - FHIR R4 document exchange",
        "<b>Lab Interfaces:</b> Quest, LabCorp, local hospital labs - HL7v2.5.1 / FHIR",
        "<b>Pharmacy Networks:</b> Surescripts (NCPDP SCRIPT 2017071) - EPCS certified",
        "<b>Imaging:</b> Local PACS systems - DICOM, DICOMweb",
        "<b>Insurance:</b> Availity, Change Healthcare - X12 270/271, 837/835",
        "<b>Public Health:</b> State immunization registries, CDC syndromic surveillance",
        "<b>Identity Verification:</b> Experian, LexisNexis - for patient matching",
    ]

    for interface in interfaces:
        story.append(Paragraph(f"• {interface}", body_style))

    doc.build(story)
    print(f"Created: {filename}")
    return filename


def create_architecture_diagram_svg():
    """Create an SVG architecture diagram."""
    svg_content = '''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800" width="1200" height="800">
  <defs>
    <linearGradient id="headerGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#1a237e;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#283593;stop-opacity:1" />
    </linearGradient>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="2" dy="2" stdDeviation="3" flood-opacity="0.3"/>
    </filter>
  </defs>

  <!-- Background -->
  <rect width="1200" height="800" fill="#fafafa"/>

  <!-- Title -->
  <rect x="0" y="0" width="1200" height="60" fill="url(#headerGrad)"/>
  <text x="600" y="38" font-family="Arial, sans-serif" font-size="24" font-weight="bold" fill="white" text-anchor="middle">Cloud-Native E-Commerce Platform Architecture</text>

  <!-- Internet Zone -->
  <rect x="20" y="80" width="1160" height="100" rx="10" fill="#e3f2fd" stroke="#1976d2" stroke-width="2"/>
  <text x="40" y="105" font-family="Arial" font-size="14" font-weight="bold" fill="#1976d2">INTERNET ZONE</text>

  <!-- Users -->
  <rect x="50" y="115" width="100" height="50" rx="5" fill="#fff" stroke="#1976d2" stroke-width="2" filter="url(#shadow)"/>
  <text x="100" y="145" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Mobile Users</text>

  <rect x="180" y="115" width="100" height="50" rx="5" fill="#fff" stroke="#1976d2" stroke-width="2" filter="url(#shadow)"/>
  <text x="230" y="145" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Web Users</text>

  <rect x="310" y="115" width="100" height="50" rx="5" fill="#fff" stroke="#1976d2" stroke-width="2" filter="url(#shadow)"/>
  <text x="360" y="145" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Partner APIs</text>

  <!-- CDN -->
  <rect x="500" y="115" width="120" height="50" rx="5" fill="#bbdefb" stroke="#1976d2" stroke-width="2" filter="url(#shadow)"/>
  <text x="560" y="138" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">CloudFront CDN</text>
  <text x="560" y="153" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Edge Caching</text>

  <!-- WAF -->
  <rect x="660" y="115" width="120" height="50" rx="5" fill="#ffcdd2" stroke="#c62828" stroke-width="2" filter="url(#shadow)"/>
  <text x="720" y="138" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">AWS WAF</text>
  <text x="720" y="153" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">OWASP Rules</text>

  <!-- DMZ -->
  <rect x="20" y="200" width="1160" height="120" rx="10" fill="#fff3e0" stroke="#f57c00" stroke-width="2"/>
  <text x="40" y="225" font-family="Arial" font-size="14" font-weight="bold" fill="#e65100">DMZ - LOAD BALANCING TIER</text>

  <!-- Load Balancer -->
  <rect x="200" y="245" width="150" height="60" rx="5" fill="#ffe0b2" stroke="#f57c00" stroke-width="2" filter="url(#shadow)"/>
  <text x="275" y="272" font-family="Arial" font-size="12" text-anchor="middle" fill="#333">Application LB</text>
  <text x="275" y="290" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">SSL Termination</text>

  <!-- API Gateway -->
  <rect x="450" y="245" width="150" height="60" rx="5" fill="#ffe0b2" stroke="#f57c00" stroke-width="2" filter="url(#shadow)"/>
  <text x="525" y="272" font-family="Arial" font-size="12" text-anchor="middle" fill="#333">Kong API Gateway</text>
  <text x="525" y="290" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Rate Limiting, JWT</text>

  <!-- Auth -->
  <rect x="700" y="245" width="150" height="60" rx="5" fill="#ffe0b2" stroke="#f57c00" stroke-width="2" filter="url(#shadow)"/>
  <text x="775" y="272" font-family="Arial" font-size="12" text-anchor="middle" fill="#333">Identity Service</text>
  <text x="775" y="290" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">OAuth2 / OIDC</text>

  <!-- Application Layer -->
  <rect x="20" y="340" width="1160" height="180" rx="10" fill="#e8f5e9" stroke="#388e3c" stroke-width="2"/>
  <text x="40" y="365" font-family="Arial" font-size="14" font-weight="bold" fill="#2e7d32">APPLICATION LAYER - KUBERNETES CLUSTER</text>

  <!-- Services Row 1 -->
  <rect x="50" y="385" width="130" height="55" rx="5" fill="#c8e6c9" stroke="#388e3c" stroke-width="2" filter="url(#shadow)"/>
  <text x="115" y="410" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Product Service</text>
  <text x="115" y="425" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Python/FastAPI</text>

  <rect x="200" y="385" width="130" height="55" rx="5" fill="#c8e6c9" stroke="#388e3c" stroke-width="2" filter="url(#shadow)"/>
  <text x="265" y="410" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Cart Service</text>
  <text x="265" y="425" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Node.js</text>

  <rect x="350" y="385" width="130" height="55" rx="5" fill="#c8e6c9" stroke="#388e3c" stroke-width="2" filter="url(#shadow)"/>
  <text x="415" y="410" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Order Service</text>
  <text x="415" y="425" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Java/Spring Boot</text>

  <rect x="500" y="385" width="130" height="55" rx="5" fill="#ffcdd2" stroke="#c62828" stroke-width="2" filter="url(#shadow)"/>
  <text x="565" y="410" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Payment Service</text>
  <text x="565" y="425" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Go (PCI Scope)</text>

  <rect x="650" y="385" width="130" height="55" rx="5" fill="#c8e6c9" stroke="#388e3c" stroke-width="2" filter="url(#shadow)"/>
  <text x="715" y="410" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Inventory Svc</text>
  <text x="715" y="425" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Rust</text>

  <rect x="800" y="385" width="130" height="55" rx="5" fill="#c8e6c9" stroke="#388e3c" stroke-width="2" filter="url(#shadow)"/>
  <text x="865" y="410" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Notification Svc</text>
  <text x="865" y="425" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Python</text>

  <rect x="950" y="385" width="130" height="55" rx="5" fill="#e1bee7" stroke="#7b1fa2" stroke-width="2" filter="url(#shadow)"/>
  <text x="1015" y="410" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Fraud Detection</text>
  <text x="1015" y="425" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Python/TensorFlow</text>

  <!-- Services Row 2 -->
  <rect x="200" y="455" width="130" height="55" rx="5" fill="#c8e6c9" stroke="#388e3c" stroke-width="2" filter="url(#shadow)"/>
  <text x="265" y="480" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Search Service</text>
  <text x="265" y="495" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Go/Elasticsearch</text>

  <rect x="350" y="455" width="130" height="55" rx="5" fill="#c8e6c9" stroke="#388e3c" stroke-width="2" filter="url(#shadow)"/>
  <text x="415" y="480" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">User Service</text>
  <text x="415" y="495" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Java</text>

  <rect x="500" y="455" width="130" height="55" rx="5" fill="#c8e6c9" stroke="#388e3c" stroke-width="2" filter="url(#shadow)"/>
  <text x="565" y="480" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Review Service</text>
  <text x="565" y="495" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Node.js</text>

  <!-- Message Queue -->
  <rect x="750" y="455" width="180" height="55" rx="5" fill="#b3e5fc" stroke="#0288d1" stroke-width="2" filter="url(#shadow)"/>
  <text x="840" y="480" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Apache Kafka</text>
  <text x="840" y="495" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Event Streaming</text>

  <!-- Data Layer -->
  <rect x="20" y="540" width="1160" height="130" rx="10" fill="#f3e5f5" stroke="#7b1fa2" stroke-width="2"/>
  <text x="40" y="565" font-family="Arial" font-size="14" font-weight="bold" fill="#6a1b9a">DATA LAYER - ENCRYPTED AT REST</text>

  <rect x="50" y="585" width="140" height="70" rx="5" fill="#e1bee7" stroke="#7b1fa2" stroke-width="2" filter="url(#shadow)"/>
  <text x="120" y="615" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">PostgreSQL</text>
  <text x="120" y="632" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Users, Orders</text>
  <text x="120" y="647" font-family="Arial" font-size="8" text-anchor="middle" fill="#999">Multi-AZ</text>

  <rect x="210" y="585" width="140" height="70" rx="5" fill="#e1bee7" stroke="#7b1fa2" stroke-width="2" filter="url(#shadow)"/>
  <text x="280" y="615" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">MongoDB</text>
  <text x="280" y="632" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Products, Reviews</text>
  <text x="280" y="647" font-family="Arial" font-size="8" text-anchor="middle" fill="#999">Replica Set</text>

  <rect x="370" y="585" width="140" height="70" rx="5" fill="#ffccbc" stroke="#e64a19" stroke-width="2" filter="url(#shadow)"/>
  <text x="440" y="615" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Redis Cluster</text>
  <text x="440" y="632" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Sessions, Cache</text>
  <text x="440" y="647" font-family="Arial" font-size="8" text-anchor="middle" fill="#999">6 nodes</text>

  <rect x="530" y="585" width="140" height="70" rx="5" fill="#e1bee7" stroke="#7b1fa2" stroke-width="2" filter="url(#shadow)"/>
  <text x="600" y="615" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Elasticsearch</text>
  <text x="600" y="632" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Search Index</text>
  <text x="600" y="647" font-family="Arial" font-size="8" text-anchor="middle" fill="#999">3-node cluster</text>

  <rect x="690" y="585" width="140" height="70" rx="5" fill="#b2dfdb" stroke="#00796b" stroke-width="2" filter="url(#shadow)"/>
  <text x="760" y="615" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">S3 Bucket</text>
  <text x="760" y="632" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Images, Static</text>
  <text x="760" y="647" font-family="Arial" font-size="8" text-anchor="middle" fill="#999">SSE-KMS</text>

  <rect x="850" y="585" width="140" height="70" rx="5" fill="#ffccbc" stroke="#e64a19" stroke-width="2" filter="url(#shadow)"/>
  <text x="920" y="615" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">Vault</text>
  <text x="920" y="632" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Secrets, PKI</text>
  <text x="920" y="647" font-family="Arial" font-size="8" text-anchor="middle" fill="#999">HA Cluster</text>

  <rect x="1010" y="585" width="140" height="70" rx="5" fill="#e1bee7" stroke="#7b1fa2" stroke-width="2" filter="url(#shadow)"/>
  <text x="1080" y="615" font-family="Arial" font-size="11" text-anchor="middle" fill="#333">ClickHouse</text>
  <text x="1080" y="632" font-family="Arial" font-size="9" text-anchor="middle" fill="#666">Analytics</text>
  <text x="1080" y="647" font-family="Arial" font-size="8" text-anchor="middle" fill="#999">OLAP</text>

  <!-- External Services -->
  <rect x="20" y="690" width="1160" height="90" rx="10" fill="#eceff1" stroke="#546e7a" stroke-width="2"/>
  <text x="40" y="715" font-family="Arial" font-size="14" font-weight="bold" fill="#37474f">EXTERNAL INTEGRATIONS</text>

  <rect x="50" y="730" width="120" height="40" rx="5" fill="#cfd8dc" stroke="#546e7a" stroke-width="1" filter="url(#shadow)"/>
  <text x="110" y="755" font-family="Arial" font-size="10" text-anchor="middle" fill="#333">Stripe API</text>

  <rect x="190" y="730" width="120" height="40" rx="5" fill="#cfd8dc" stroke="#546e7a" stroke-width="1" filter="url(#shadow)"/>
  <text x="250" y="755" font-family="Arial" font-size="10" text-anchor="middle" fill="#333">SendGrid</text>

  <rect x="330" y="730" width="120" height="40" rx="5" fill="#cfd8dc" stroke="#546e7a" stroke-width="1" filter="url(#shadow)"/>
  <text x="390" y="755" font-family="Arial" font-size="10" text-anchor="middle" fill="#333">Twilio SMS</text>

  <rect x="470" y="730" width="120" height="40" rx="5" fill="#cfd8dc" stroke="#546e7a" stroke-width="1" filter="url(#shadow)"/>
  <text x="530" y="755" font-family="Arial" font-size="10" text-anchor="middle" fill="#333">Auth0</text>

  <rect x="610" y="730" width="120" height="40" rx="5" fill="#cfd8dc" stroke="#546e7a" stroke-width="1" filter="url(#shadow)"/>
  <text x="670" y="755" font-family="Arial" font-size="10" text-anchor="middle" fill="#333">Datadog</text>

  <rect x="750" y="730" width="120" height="40" rx="5" fill="#cfd8dc" stroke="#546e7a" stroke-width="1" filter="url(#shadow)"/>
  <text x="810" y="755" font-family="Arial" font-size="10" text-anchor="middle" fill="#333">PagerDuty</text>

  <rect x="890" y="730" width="120" height="40" rx="5" fill="#cfd8dc" stroke="#546e7a" stroke-width="1" filter="url(#shadow)"/>
  <text x="950" y="755" font-family="Arial" font-size="10" text-anchor="middle" fill="#333">Sentry</text>

  <rect x="1030" y="730" width="120" height="40" rx="5" fill="#cfd8dc" stroke="#546e7a" stroke-width="1" filter="url(#shadow)"/>
  <text x="1090" y="755" font-family="Arial" font-size="10" text-anchor="middle" fill="#333">Snowflake</text>

  <!-- Arrows -->
  <defs>
    <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
      <polygon points="0 0, 10 3.5, 0 7" fill="#666"/>
    </marker>
  </defs>

  <!-- Connection lines -->
  <line x1="150" y1="165" x2="500" y2="115" stroke="#666" stroke-width="1.5" marker-end="url(#arrowhead)"/>
  <line x1="620" y1="165" x2="660" y2="140" stroke="#666" stroke-width="1.5" marker-end="url(#arrowhead)"/>
  <line x1="720" y1="165" x2="525" y2="245" stroke="#666" stroke-width="1.5" marker-end="url(#arrowhead)"/>

</svg>'''

    filename = "ecommerce_architecture_diagram.svg"
    with open(filename, 'w') as f:
        f.write(svg_content)
    print(f"Created: {filename}")
    print("  -> Convert to PNG: Open in browser and screenshot, or use: npx svgexport ecommerce_architecture_diagram.svg diagram.png")
    return filename


if __name__ == "__main__":
    print("=" * 60)
    print("Creating Realistic Architecture Documents")
    print("=" * 60)
    print()

    create_fintech_architecture_pdf()
    create_healthcare_architecture_pdf()
    create_architecture_diagram_svg()

    print()
    print("=" * 60)
    print("Documents created successfully!")
    print("=" * 60)
    print()
    print("Files created:")
    print("  1. fintech_platform_architecture.pdf - PCI-DSS compliant payment platform")
    print("  2. healthsync_ehr_architecture.pdf - HIPAA compliant EHR system")
    print("  3. ecommerce_architecture_diagram.svg - Visual architecture diagram")
    print()
    print("To convert SVG to PNG/JPG:")
    print("  - Open the SVG in Chrome and take a screenshot")
    print("  - Or use: npx svgexport ecommerce_architecture_diagram.svg diagram.png 2x")
