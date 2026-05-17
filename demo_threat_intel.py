"""
Demo Script: Threat Intelligence Features Showcase
===================================================
Creates a sample banking project and demonstrates:
1. Sector Threat Intel (Banking & Healthcare)
2. Client-uploaded Threat Intel CRUD
3. MITRE ATT&CK Live Enrichment & Validation
4. CISA KEV Integration
5. Combined Intel (Client + Sector)
6. SecureReq → Threat Model Pipeline

Usage:
    python3 demo_threat_intel.py [--prod]

    Default: runs against localhost:8000
    --prod:  runs against Railway production
"""

import requests
import json
import sys
import time

# ── Config ──────────────────────────────────────────────────────────────────
LOCAL_URL = "http://localhost:8000"
PROD_URL = "https://backend-production-ee900.up.railway.app"

BASE_URL = PROD_URL if "--prod" in sys.argv else LOCAL_URL

# Demo credentials — change these to match your setup
USERNAME = "admin"
PASSWORD = "admin123"

# ── Helpers ─────────────────────────────────────────────────────────────────
TOKEN = None

def header():
    return {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

def pretty(data):
    print(json.dumps(data, indent=2, default=str))

def section(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")

def step(msg):
    print(f"  >> {msg}")

def check(resp, label):
    if resp.status_code < 300:
        print(f"  [OK] {label} (HTTP {resp.status_code})")
        return resp.json() if resp.text else {}
    else:
        print(f"  [FAIL] {label} (HTTP {resp.status_code})")
        print(f"         {resp.text[:300]}")
        return None


# ── 0. Authentication ──────────────────────────────────────────────────────
section("0. AUTHENTICATION")
step(f"Logging in to {BASE_URL} as '{USERNAME}'...")

resp = requests.post(f"{BASE_URL}/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
data = check(resp, "Login")
if not data or "access_token" not in data:
    print("\n  Login failed. Update USERNAME/PASSWORD in this script.")
    sys.exit(1)

TOKEN = data["access_token"]
print(f"  Token: {TOKEN[:20]}...")


# ── 1. Sector Threat Intelligence ─────────────────────────────────────────
section("1. SECTOR THREAT INTELLIGENCE")

step("Listing available sectors...")
data = check(requests.get(f"{BASE_URL}/api/threat-intel/sectors/list", headers=header()), "List sectors")
if data:
    pretty(data)

step("Fetching Banking sector threats...")
data = check(requests.get(f"{BASE_URL}/api/threat-intel/sectors/banking", headers=header()), "Banking sector intel")
if data:
    print(f"  Found {len(data) if isinstance(data, list) else data.get('total', '?')} banking threat entries")
    # Show first entry as sample
    entries = data if isinstance(data, list) else data.get("entries", data.get("threats", []))
    if entries and len(entries) > 0:
        print("\n  Sample entry:")
        pretty(entries[0])

step("Fetching Healthcare sector threats...")
data = check(requests.get(f"{BASE_URL}/api/threat-intel/sectors/healthcare", headers=header()), "Healthcare sector intel")
if data:
    entries = data if isinstance(data, list) else data.get("entries", data.get("threats", []))
    print(f"  Found {len(entries)} healthcare threat entries")


# ── 2. Create Demo Project ────────────────────────────────────────────────
section("2. CREATE DEMO PROJECT — 'Apex Banking Platform'")

project_payload = {
    "name": "Apex Banking Platform",
    "description": "Online banking platform with SWIFT integration, payment processing, and mobile banking APIs",
    "technology_stack": ["Python", "FastAPI", "PostgreSQL", "Redis", "React", "Kubernetes"],
    "compliance_targets": ["PCI-DSS", "SOX", "GDPR", "OWASP Top 10"],
    "architecture_doc": """
## Apex Banking Platform Architecture

### Components
1. **Web Application** (React SPA) — Customer-facing online banking portal
2. **Mobile API Gateway** (FastAPI) — REST APIs for iOS/Android apps
3. **Payment Engine** (Python microservice) — Processes ACH, wire, and SWIFT transfers
4. **Authentication Service** — OAuth2/OIDC with MFA, session management
5. **Database Cluster** (PostgreSQL) — Stores accounts, transactions, PII
6. **Cache Layer** (Redis) — Session store, rate limiting, transaction queue
7. **Message Broker** (RabbitMQ) — Async event processing for transactions
8. **SWIFT Gateway** — ISO 20022 message handling for international transfers

### Data Flows
- Customer → Web App → API Gateway → Payment Engine → SWIFT Gateway → External Banks
- Mobile App → API Gateway → Auth Service → Database
- Payment Engine → Message Broker → Transaction Processor → Database
- All components → Centralized Logging (ELK Stack)

### Trust Boundaries
- Internet ↔ DMZ (WAF + Load Balancer)
- DMZ ↔ Application Zone (API Gateway)
- Application Zone ↔ Data Zone (Database, Redis)
- Internal Network ↔ SWIFT Network (SWIFT Gateway)

### Sensitive Data
- Customer PII (names, SSN, addresses)
- Financial transactions and account balances
- SWIFT credentials and certificates
- OAuth tokens and session data
- Encryption keys (AES-256 for data at rest)
""",
    "auto_scan_types": ["threat_model"]
}

step("Creating project with architecture doc...")
data = check(requests.post(f"{BASE_URL}/api/projects", json=project_payload, headers=header()), "Create project")

PROJECT_ID = None
if data:
    PROJECT_ID = data.get("id")
    print(f"  Project ID: {PROJECT_ID}")
    print(f"  Name: {data.get('name')}")


# ── 3. Client Threat Intel CRUD ───────────────────────────────────────────
section("3. CLIENT-SPECIFIC THREAT INTEL")

if PROJECT_ID:
    # Create individual entries
    client_threats = [
        {
            "project_id": PROJECT_ID,
            "intel_type": "incident",
            "title": "2024 SWIFT Credential Theft Attempt",
            "description": "Insider attempted to exfiltrate SWIFT operator credentials via USB. Detected by DLP but credentials were partially exposed. Requires enhanced monitoring on SWIFT terminal access.",
            "severity": "critical",
            "threat_category": "Elevation of Privilege",
            "mitre_techniques": ["T1078", "T1052.001", "T1071.001"],
            "regulatory_impact": ["PCI-DSS Req 7.1", "SOX Section 404"],
            "recommended_controls": ["Privileged Access Management", "USB device blocking on SWIFT terminals", "Real-time session recording"],
            "tags": ["swift", "insider-threat", "credential-theft"]
        },
        {
            "project_id": PROJECT_ID,
            "intel_type": "threat_actor",
            "title": "Lazarus Group — Active Targeting of SWIFT Systems",
            "description": "APT38/Lazarus Group actively targets financial institutions' SWIFT infrastructure. Known TTPs include spearphishing operators, deploying custom malware on SWIFT terminals, and manipulating transaction messages.",
            "severity": "critical",
            "threat_category": "Tampering",
            "mitre_techniques": ["T1566.001", "T1059.001", "T1071.001", "T1005"],
            "regulatory_impact": ["SWIFT CSP v2024"],
            "recommended_controls": ["Network segmentation for SWIFT zone", "Application whitelisting on SWIFT terminals", "Mandatory transaction verification"],
            "tags": ["apt38", "lazarus", "swift", "nation-state"]
        },
        {
            "project_id": PROJECT_ID,
            "intel_type": "pentest_finding",
            "title": "API Gateway Auth Bypass via Token Manipulation",
            "description": "Recent pentest found that JWT tokens issued by the auth service could be manipulated by modifying the 'aud' claim to escalate from mobile-api scope to admin-api scope. CVSS 8.8.",
            "severity": "high",
            "threat_category": "Spoofing",
            "mitre_techniques": ["T1134", "T1550.001"],
            "recommended_controls": ["Strict JWT audience validation", "Token binding to client certificate", "Short-lived tokens (15 min max)"],
            "tags": ["jwt", "auth-bypass", "api-gateway", "pentest-2024"]
        },
        {
            "project_id": PROJECT_ID,
            "intel_type": "regulation",
            "title": "PCI-DSS v4.0.1 — New Requirements Effective March 2025",
            "description": "PCI-DSS v4.0.1 introduces mandatory targeted risk analysis for all security controls, enhanced MFA requirements (Req 8.4.2), and script integrity monitoring for payment pages (Req 6.4.3).",
            "severity": "high",
            "threat_category": "Information Disclosure",
            "regulatory_impact": ["PCI-DSS Req 6.4.3", "PCI-DSS Req 8.4.2", "PCI-DSS Req 12.3.1"],
            "recommended_controls": ["Content Security Policy headers", "Subresource Integrity for all scripts", "Payment page change detection"],
            "tags": ["pci-dss", "compliance", "payment-security"]
        },
        {
            "project_id": PROJECT_ID,
            "intel_type": "risk_appetite",
            "title": "Zero Tolerance for Unauthorized SWIFT Transactions",
            "description": "Board-mandated zero tolerance for unauthorized SWIFT transactions. Any finding related to SWIFT message manipulation, credential exposure, or transaction integrity must be treated as Critical regardless of CVSS score.",
            "severity": "critical",
            "recommended_controls": ["Dual authorization for all SWIFT transactions", "Real-time anomaly detection", "Mandatory 4-eyes principle"],
            "tags": ["swift", "risk-appetite", "board-mandate"]
        }
    ]

    created_ids = []
    for threat in client_threats:
        step(f"Creating: {threat['title'][:50]}...")
        data = check(
            requests.post(f"{BASE_URL}/api/threat-intel", json=threat, headers=header()),
            f"Create '{threat['intel_type']}' entry"
        )
        if data and "id" in data:
            created_ids.append(data["id"])

    # List all entries
    step(f"Listing all client threat intel for project {PROJECT_ID}...")
    data = check(
        requests.get(f"{BASE_URL}/api/threat-intel/{PROJECT_ID}", headers=header()),
        "List client intel"
    )
    if data:
        print(f"  Total entries: {data.get('total', len(data.get('entries', [])))}")

    # Update an entry
    if created_ids:
        step(f"Updating entry {created_ids[0]} — adding remediation status...")
        check(
            requests.put(f"{BASE_URL}/api/threat-intel/{created_ids[0]}", json={
                "tags": ["swift", "insider-threat", "credential-theft", "remediated-partial"],
                "description": "Insider attempted to exfiltrate SWIFT operator credentials via USB. Detected by DLP but credentials were partially exposed. REMEDIATION: USB ports disabled on all SWIFT terminals as of 2024-Q4. PAM solution deployed."
            }, headers=header()),
            "Update entry"
        )


# ── 4. Combined Threat Intel ──────────────────────────────────────────────
section("4. COMBINED THREAT INTEL (Client + Sector)")

if PROJECT_ID:
    step(f"Fetching combined intel for project {PROJECT_ID}...")
    data = check(
        requests.get(f"{BASE_URL}/api/threat-intel/combined/{PROJECT_ID}", headers=header()),
        "Combined intel"
    )
    if data:
        client_count = len(data.get("client_intel", []))
        sector_count = len(data.get("sector_intel", []))
        print(f"  Client entries: {client_count}")
        print(f"  Sector entries: {sector_count}")
        print(f"  Total combined: {client_count + sector_count}")


# ── 5. MITRE ATT&CK Live Enrichment ──────────────────────────────────────
section("5. MITRE ATT&CK LIVE ENRICHMENT")

step("Loading MITRE ATT&CK STIX bundle (may take 5-10s)...")
data = check(
    requests.post(f"{BASE_URL}/api/threat-intel/enrich/load-mitre", headers=header()),
    "Load MITRE STIX"
)
if data:
    print(f"  Techniques loaded: {data.get('techniques_loaded', '?')}")

step("Validating banking sector technique IDs against live ATT&CK...")
data = check(
    requests.get(f"{BASE_URL}/api/threat-intel/enrich/validate/banking", headers=header()),
    "Validate banking techniques"
)
if data:
    pretty(data)

step("Fetching enriched banking intel with live MITRE metadata...")
data = check(
    requests.get(f"{BASE_URL}/api/threat-intel/enrich/sector/banking", headers=header()),
    "Enriched banking intel"
)
if data:
    entries = data if isinstance(data, list) else data.get("entries", [])
    if entries:
        print(f"  Enriched entries: {len(entries)}")
        print("\n  Sample enriched entry (first):")
        pretty(entries[0])

step("Looking up technique T1059.001 (PowerShell)...")
data = check(
    requests.get(f"{BASE_URL}/api/threat-intel/enrich/technique/T1059.001", headers=header()),
    "Technique lookup"
)
if data:
    pretty(data)


# ── 6. CISA KEV Integration ──────────────────────────────────────────────
section("6. CISA KEV (Known Exploited Vulnerabilities)")

step("Loading CISA KEV catalog...")
data = check(
    requests.post(f"{BASE_URL}/api/threat-intel/enrich/load-kev", headers=header()),
    "Load CISA KEV"
)
if data:
    print(f"  Total KEVs loaded: {data.get('total_kevs', '?')}")

step("Fetching banking-relevant KEVs...")
data = check(
    requests.get(f"{BASE_URL}/api/threat-intel/enrich/kev/banking", headers=header()),
    "Banking KEVs"
)
if data:
    kevs = data if isinstance(data, list) else data.get("kevs", data.get("vulnerabilities", []))
    print(f"  Banking-relevant KEVs: {len(kevs)}")
    if kevs:
        print("\n  Top 3 KEVs:")
        for kev in kevs[:3]:
            cve = kev.get("cveID", kev.get("cve_id", "?"))
            vendor = kev.get("vendorProject", kev.get("vendor", "?"))
            product = kev.get("product", "?")
            print(f"    - {cve}: {vendor} {product}")


# ── 7. SecureReq → Security Analysis ─────────────────────────────────────
section("7. SECUREREQ — USER STORY SECURITY ANALYSIS")

if PROJECT_ID:
    story_payload = {
        "title": "As a treasury manager, I want to initiate SWIFT wire transfers from the web portal",
        "description": "Treasury managers need to create and submit SWIFT MT103 wire transfer messages directly from the banking portal. The system should support single and bulk transfers, with real-time status tracking. Transfers above $50,000 require dual authorization from a second treasury officer.",
        "acceptance_criteria": """
- Treasury manager can create MT103 messages with beneficiary details
- Bulk upload via CSV for multiple transfers
- Transfers > $50,000 require second authorization
- Real-time status tracking (submitted, processing, confirmed, failed)
- Full audit trail of all transfer actions
- Integration with SWIFT Alliance Gateway
"""
    }

    step("Creating user story for SWIFT transfer feature...")
    data = check(
        requests.post(f"{BASE_URL}/api/securereq/projects/{PROJECT_ID}/stories", json=story_payload, headers=header()),
        "Create user story"
    )

    STORY_ID = None
    if data:
        STORY_ID = data.get("id")
        print(f"  Story ID: {STORY_ID}")

    if STORY_ID:
        step("Running security analysis on the SWIFT transfer story...")
        data = check(
            requests.post(f"{BASE_URL}/api/securereq/stories/{STORY_ID}/analyze", json={}, headers=header()),
            "Analyze story"
        )
        if data:
            print(f"  Risk Score: {data.get('risk_score', '?')}")
            print(f"  Abuse Cases: {len(data.get('abuse_cases', []))}")
            threats = data.get("stride_threats", {})
            if isinstance(threats, dict):
                total_threats = sum(len(v) if isinstance(v, list) else 1 for v in threats.values())
            else:
                total_threats = len(threats)
            print(f"  STRIDE Threats: {total_threats}")
            print(f"  Security Requirements: {len(data.get('security_requirements', []))}")

            # Show a sample abuse case
            abuse_cases = data.get("abuse_cases", [])
            if abuse_cases:
                print("\n  Sample Abuse Case:")
                pretty(abuse_cases[0])


# ── 8. SecReq Context for Threat Model ────────────────────────────────────
section("8. SECUREREQ CONTEXT FOR THREAT MODELING")

if PROJECT_ID:
    step(f"Fetching SecReq context that feeds into threat model for project {PROJECT_ID}...")
    data = check(
        requests.get(f"{BASE_URL}/api/threat-intel/securereq-context/{PROJECT_ID}", headers=header()),
        "SecReq context"
    )
    if data:
        print(f"  Context keys: {list(data.keys()) if isinstance(data, dict) else 'N/A'}")
        if isinstance(data, dict):
            for key, val in data.items():
                if isinstance(val, list):
                    print(f"    {key}: {len(val)} items")
                elif isinstance(val, str):
                    print(f"    {key}: {val[:100]}...")


# ── 9. Threat Model Generation ────────────────────────────────────────────
section("9. THREAT MODEL GENERATION (with Threat Intel Context)")

if PROJECT_ID:
    step("Triggering threat model regeneration (includes threat intel + SecReq context)...")
    data = check(
        requests.post(f"{BASE_URL}/api/projects/{PROJECT_ID}/threat-model/regenerate", json={}, headers=header()),
        "Regenerate threat model"
    )

    if data and data.get("status") == "in_progress":
        step("Waiting for threat model generation to complete...")
        for i in range(30):
            time.sleep(5)
            status = requests.get(f"{BASE_URL}/api/projects/{PROJECT_ID}/threat-model/status", headers=header())
            if status.status_code == 200:
                sdata = status.json()
                progress = sdata.get("progress", 0)
                current_step = sdata.get("step", "unknown")
                print(f"    [{progress}%] {current_step}")
                if sdata.get("status") == "complete" or progress >= 100:
                    print("  Threat model generation complete!")
                    break
                if sdata.get("status") == "error":
                    print(f"  Error: {sdata.get('error', 'unknown')}")
                    break
            time.sleep(5)

        step("Fetching generated threat model...")
        data = check(
            requests.get(f"{BASE_URL}/api/projects/{PROJECT_ID}/threat-model", headers=header()),
            "Get threat model"
        )
        if data:
            tm = data.get("threat_model", data)
            if isinstance(tm, str):
                import json as j
                try:
                    tm = j.loads(tm)
                except:
                    pass
            if isinstance(tm, dict):
                print(f"  Threats identified: {len(tm.get('threats', []))}")
                print(f"  Attack paths: {len(tm.get('attack_paths', []))}")
                print(f"  DFD elements: {len(tm.get('dfd', {}).get('elements', []))}")
                mitre = tm.get("mitre_mapping", [])
                print(f"  MITRE ATT&CK mappings: {len(mitre)}")


# ── Summary ───────────────────────────────────────────────────────────────
section("DEMO COMPLETE")
print(f"""
  Features demonstrated:
  1. Sector Threat Intel     — Banking & Healthcare curated catalogs
  2. Client Threat Intel     — 5 custom entries (incident, threat actor, pentest, regulation, risk appetite)
  3. Combined Intel          — Client + Sector merged view
  4. MITRE ATT&CK Enrichment — Live STIX validation + technique lookup
  5. CISA KEV Integration    — Real-time exploited vulnerabilities by sector
  6. SecureReq Analysis      — SWIFT transfer story → abuse cases + STRIDE + security requirements
  7. SecReq → Threat Model   — Security context piped into threat model generation
  8. Threat Model Generation — Full STRIDE + MITRE + DFD + attack paths

  Project: Apex Banking Platform (ID: {PROJECT_ID})
  Target:  {BASE_URL}
""")
