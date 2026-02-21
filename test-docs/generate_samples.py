#!/usr/bin/env python3
"""Generate sample architecture documents for testing."""

import os

# Check if reportlab is available
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    print("reportlab not installed. Run: pip install reportlab")

def create_architecture_pdf():
    """Create a sample PDF with architecture details."""
    if not HAS_REPORTLAB:
        return

    filename = "sample_architecture.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    # Title
    c.setFont("Helvetica-Bold", 24)
    c.drawString(1*inch, height - 1*inch, "E-Commerce Platform Architecture")

    # Subtitle
    c.setFont("Helvetica", 12)
    c.drawString(1*inch, height - 1.4*inch, "System Design Document v2.0")

    # Section: Overview
    y = height - 2*inch
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1*inch, y, "1. System Overview")

    y -= 0.3*inch
    c.setFont("Helvetica", 11)
    overview_text = [
        "This document describes the architecture of our e-commerce platform.",
        "The system handles user authentication, product catalog, shopping cart,",
        "order processing, and payment integration."
    ]
    for line in overview_text:
        c.drawString(1*inch, y, line)
        y -= 0.2*inch

    # Section: Components
    y -= 0.3*inch
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1*inch, y, "2. System Components")

    components = [
        ("Web Frontend", "React SPA served via CloudFront CDN"),
        ("API Gateway", "Kong API Gateway with rate limiting and JWT validation"),
        ("Auth Service", "Node.js service handling OAuth2, JWT tokens, MFA"),
        ("Product Service", "Python FastAPI for catalog management"),
        ("Order Service", "Python FastAPI for order processing"),
        ("Payment Service", "Node.js integration with Stripe API"),
        ("Notification Service", "Go service for email/SMS via SendGrid"),
        ("PostgreSQL Database", "Primary data store with read replicas"),
        ("Redis Cache", "Session storage and API response caching"),
        ("Elasticsearch", "Product search and analytics"),
    ]

    y -= 0.3*inch
    c.setFont("Helvetica", 10)
    for name, desc in components:
        c.setFont("Helvetica-Bold", 10)
        c.drawString(1.2*inch, y, f"- {name}:")
        c.setFont("Helvetica", 10)
        c.drawString(3*inch, y, desc)
        y -= 0.25*inch

    # Section: Data Flows
    y -= 0.3*inch
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1*inch, y, "3. Data Flows")

    flows = [
        "User -> Web Frontend -> API Gateway -> Auth Service (login/register)",
        "Web Frontend -> API Gateway -> Product Service (browse catalog)",
        "Web Frontend -> API Gateway -> Order Service -> Payment Service (checkout)",
        "Payment Service -> Stripe API (process payment)",
        "Order Service -> Notification Service -> SendGrid (order confirmation)",
        "All Services -> PostgreSQL (persist data)",
        "API Gateway -> Redis (cache responses)",
    ]

    y -= 0.3*inch
    c.setFont("Helvetica", 10)
    for flow in flows:
        c.drawString(1.2*inch, y, f"- {flow}")
        y -= 0.25*inch

    # Section: Trust Boundaries
    y -= 0.3*inch
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1*inch, y, "4. Trust Boundaries")

    boundaries = [
        "Internet Zone: Web Frontend, CDN",
        "DMZ: API Gateway, Load Balancer",
        "Internal Network: All microservices",
        "Data Zone: PostgreSQL, Redis, Elasticsearch",
        "External Services: Stripe, SendGrid",
    ]

    y -= 0.3*inch
    c.setFont("Helvetica", 10)
    for boundary in boundaries:
        c.drawString(1.2*inch, y, f"- {boundary}")
        y -= 0.25*inch

    # Section: Security Controls
    y -= 0.3*inch
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1*inch, y, "5. Security Controls")

    controls = [
        "TLS 1.3 for all external communications",
        "JWT tokens with 15-minute expiry",
        "Rate limiting: 100 requests/minute per user",
        "WAF rules for OWASP Top 10",
        "Database encryption at rest (AES-256)",
        "Secrets managed via HashiCorp Vault",
    ]

    y -= 0.3*inch
    c.setFont("Helvetica", 10)
    for control in controls:
        c.drawString(1.2*inch, y, f"- {control}")
        y -= 0.25*inch

    c.save()
    print(f"Created: {filename}")
    return filename


def create_microservices_pdf():
    """Create a second sample PDF with microservices architecture."""
    if not HAS_REPORTLAB:
        return

    filename = "microservices_architecture.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    # Title
    c.setFont("Helvetica-Bold", 24)
    c.drawString(1*inch, height - 1*inch, "Healthcare Platform Architecture")

    y = height - 1.5*inch
    c.setFont("Helvetica", 12)
    c.drawString(1*inch, y, "HIPAA-Compliant Medical Records System")

    # Components
    y -= 0.5*inch
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1*inch, y, "Core Components:")

    components = [
        ("Patient Portal", "React app with biometric authentication"),
        ("Provider Dashboard", "Angular app for healthcare providers"),
        ("API Gateway", "AWS API Gateway with WAF"),
        ("Identity Service", "Keycloak for SSO and RBAC"),
        ("Patient Service", "Java Spring Boot - patient records"),
        ("Appointment Service", "Python Django - scheduling"),
        ("Medical Records Service", "Java Spring Boot - EHR management"),
        ("Prescription Service", "Node.js - medication management"),
        ("Billing Service", "Go - insurance claims processing"),
        ("Audit Service", "Python - compliance logging"),
        ("MongoDB", "Patient demographics (encrypted)"),
        ("PostgreSQL", "Transactional data"),
        ("S3 Bucket", "Medical imaging storage (encrypted)"),
        ("AWS KMS", "Key management for PHI encryption"),
    ]

    y -= 0.3*inch
    c.setFont("Helvetica", 9)
    for name, desc in components:
        c.setFont("Helvetica-Bold", 9)
        c.drawString(1.2*inch, y, f"{name}:")
        c.setFont("Helvetica", 9)
        c.drawString(3*inch, y, desc)
        y -= 0.22*inch

    # Data flows
    y -= 0.3*inch
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1*inch, y, "Critical Data Flows:")

    flows = [
        "Patient -> Portal -> API GW -> Identity Service (authentication)",
        "Portal -> Medical Records Service -> MongoDB (view records)",
        "Provider -> Dashboard -> Prescription Service (prescribe)",
        "Prescription Service -> External: Pharmacy Network API",
        "All Services -> Audit Service -> CloudWatch (compliance)",
        "Medical Records -> S3 (store imaging with encryption)",
    ]

    y -= 0.3*inch
    c.setFont("Helvetica", 9)
    for flow in flows:
        c.drawString(1.2*inch, y, f"- {flow}")
        y -= 0.22*inch

    # Security
    y -= 0.3*inch
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1*inch, y, "HIPAA Security Controls:")

    controls = [
        "PHI encrypted at rest (AES-256) and in transit (TLS 1.3)",
        "Role-based access control with minimum necessary access",
        "MFA required for all provider accounts",
        "Comprehensive audit logging for all PHI access",
        "Automatic session timeout after 15 minutes",
        "Data loss prevention (DLP) scanning",
        "Annual penetration testing and vulnerability assessments",
    ]

    y -= 0.3*inch
    c.setFont("Helvetica", 9)
    for control in controls:
        c.drawString(1.2*inch, y, f"- {control}")
        y -= 0.22*inch

    c.save()
    print(f"Created: {filename}")
    return filename


def create_simple_diagram_html():
    """Create an HTML file with a simple architecture diagram that can be screenshot."""
    html_content = '''<!DOCTYPE html>
<html>
<head>
    <title>Architecture Diagram</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        h1 { color: #333; text-align: center; }
        .diagram { display: flex; flex-direction: column; gap: 20px; }
        .layer { display: flex; justify-content: center; gap: 20px; flex-wrap: wrap; }
        .box { padding: 15px 25px; border-radius: 8px; text-align: center; min-width: 120px; }
        .external { background: #e3f2fd; border: 2px solid #1976d2; }
        .frontend { background: #fff3e0; border: 2px solid #f57c00; }
        .gateway { background: #fce4ec; border: 2px solid #c2185b; }
        .service { background: #e8f5e9; border: 2px solid #388e3c; }
        .data { background: #f3e5f5; border: 2px solid #7b1fa2; }
        .arrow { text-align: center; font-size: 24px; color: #666; }
        .label { font-size: 12px; color: #666; margin-top: 20px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Banking Application Architecture</h1>

        <div class="diagram">
            <div class="label">External Users</div>
            <div class="layer">
                <div class="box external">Mobile App<br><small>iOS/Android</small></div>
                <div class="box external">Web Browser<br><small>React SPA</small></div>
                <div class="box external">Partner APIs<br><small>B2B Integration</small></div>
            </div>

            <div class="arrow">&#8595;</div>

            <div class="label">Edge Layer (DMZ)</div>
            <div class="layer">
                <div class="box gateway">CDN<br><small>CloudFront</small></div>
                <div class="box gateway">WAF<br><small>AWS WAF</small></div>
                <div class="box gateway">API Gateway<br><small>Kong</small></div>
            </div>

            <div class="arrow">&#8595;</div>

            <div class="label">Application Layer</div>
            <div class="layer">
                <div class="box service">Auth Service<br><small>OAuth2/JWT</small></div>
                <div class="box service">Account Service<br><small>Core Banking</small></div>
                <div class="box service">Payment Service<br><small>Transfers</small></div>
                <div class="box service">Fraud Detection<br><small>ML Model</small></div>
            </div>

            <div class="arrow">&#8595;</div>

            <div class="label">Data Layer</div>
            <div class="layer">
                <div class="box data">PostgreSQL<br><small>Transactions</small></div>
                <div class="box data">Redis<br><small>Session Cache</small></div>
                <div class="box data">Kafka<br><small>Event Bus</small></div>
                <div class="box data">Vault<br><small>Secrets</small></div>
            </div>
        </div>

        <div style="margin-top: 30px; padding: 15px; background: #fff9c4; border-radius: 8px;">
            <strong>Security Controls:</strong>
            <ul>
                <li>TLS 1.3 encryption for all connections</li>
                <li>OAuth2 + MFA for authentication</li>
                <li>PCI-DSS compliant payment processing</li>
                <li>Real-time fraud detection with ML</li>
                <li>Database encryption at rest (AES-256)</li>
            </ul>
        </div>
    </div>
</body>
</html>'''

    filename = "banking_architecture.html"
    with open(filename, 'w') as f:
        f.write(html_content)
    print(f"Created: {filename}")
    print("  -> Open in browser and take a screenshot, or print to PDF")
    return filename


if __name__ == "__main__":
    print("Generating sample architecture documents...\n")

    create_architecture_pdf()
    create_microservices_pdf()
    create_simple_diagram_html()

    print("\n" + "="*50)
    print("Sample documents created!")
    print("="*50)
    print("\nFor image testing, you can also download sample diagrams from:")
    print("  - https://miro.medium.com/max/1400/1*kfpbQDziWLlAsOt7vvl7pg.png (microservices)")
    print("  - https://docs.aws.amazon.com/images/wellarchitected/latest/high-performance-computing-lens/images/hpc-network.png")
    print("  - Search Google Images for 'system architecture diagram'")
