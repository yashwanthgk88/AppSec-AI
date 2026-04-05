"""
Sector-Specific Threat Intelligence Library

Built-in threat catalogs for 12 industry sectors: Banking/Finance, Healthcare,
Government, Retail, Manufacturing, Energy, Telecom, Education, Insurance,
Defense, Media, and Technology.
Each entry follows the same schema as client-uploaded threat intel,
so they merge seamlessly when fed into threat modeling.

MITRE ATT&CK Technique Mapping Methodology:
- All technique IDs verified against MITRE ATT&CK Enterprise v15 (October 2024)
- Mappings follow ATT&CK's official use-case descriptions
- Sub-techniques used where applicable for precision
- Source references link to real-world incidents and advisories

Live enrichment available via /api/threat-intel/enrich endpoints to
pull real-time data from MITRE ATT&CK STIX feed and CISA KEV catalog.
"""

from typing import List, Dict, Any, Optional


# ---------------------------------------------------------------------------
# Threat Intel Entry Schema
# ---------------------------------------------------------------------------
# Every entry (sector or client) follows this structure:
# {
#     "intel_type": str,       # incident | threat_actor | asset | scenario | regulation | control
#     "title": str,
#     "description": str,
#     "severity": str,         # critical | high | medium | low
#     "threat_category": str,  # STRIDE category
#     "mitre_techniques": [],  # ATT&CK IDs — verified against Enterprise ATT&CK v15
#     "mitre_details": {},     # technique_id → {name, tactic, url} for traceability
#     "regulatory_impact": [], # Affected regulations with specific clause references
#     "recommended_controls": [],
#     "tags": [],
#     "source": str,           # "sector_library" | "client_upload"
#     "references": [],        # URLs to real-world advisories, incidents, or standards
# }


# ---------------------------------------------------------------------------
# BANKING / FINANCE
# ---------------------------------------------------------------------------
BANKING_THREATS: List[Dict[str, Any]] = [
    # --- Threat Scenarios ---
    {
        "intel_type": "scenario",
        "title": "Account Takeover via Credential Stuffing",
        "description": "Attackers use leaked credentials from third-party breaches to gain access to customer banking accounts. Automated tools attempt thousands of username/password combinations against login endpoints.",
        "severity": "critical",
        "threat_category": "Spoofing",
        # T1078: Valid Accounts — using stolen creds to authenticate
        # T1110.004: Credential Stuffing — automated login attempts with breach dumps
        "mitre_techniques": ["T1078", "T1110.004"],
        "mitre_details": {
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1110.004": {"name": "Credential Stuffing", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1110/004/"},
        },
        "regulatory_impact": ["PCI-DSS v4.0 Req 8.3 (MFA)", "FFIEC Authentication Guidance (2021)", "NIST SP 800-63B"],
        "recommended_controls": [
            "Implement adaptive MFA for all customer-facing logins",
            "Deploy credential breach detection (check against HaveIBeenPwned-style feeds)",
            "Rate-limit login attempts per IP and per account",
            "Implement device fingerprinting and behavioral biometrics",
        ],
        "tags": ["authentication", "fraud", "ATO", "credential-stuffing"],
        "source": "sector_library",
        "references": [
            "https://owasp.org/www-community/attacks/Credential_stuffing",
            "https://attack.mitre.org/techniques/T1110/004/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Transaction Amount Manipulation",
        "description": "Attacker intercepts or manipulates transaction parameters (amount, recipient, currency) between the client and the server. Common in mobile banking where client-side validation can be bypassed.",
        "severity": "critical",
        "threat_category": "Tampering",
        # T1565.001: Stored Data Manipulation — modifying transaction data in transit/storage
        # T1557: Adversary-in-the-Middle — intercepting client-server communication
        "mitre_techniques": ["T1565.001", "T1557"],
        "mitre_details": {
            "T1565.001": {"name": "Stored Data Manipulation", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1565/001/"},
            "T1557": {"name": "Adversary-in-the-Middle", "tactic": "Credential Access, Collection", "url": "https://attack.mitre.org/techniques/T1557/"},
        },
        "regulatory_impact": ["PCI-DSS v4.0 Req 6.2 (Secure Development)", "SOX Section 302 (CEO/CFO Certification)"],
        "recommended_controls": [
            "Server-side validation of all transaction parameters",
            "Transaction signing with HMAC or digital signatures",
            "Real-time fraud scoring on transaction amounts vs historical patterns",
            "Out-of-band confirmation for high-value transactions",
        ],
        "tags": ["transactions", "fraud", "tampering", "payment"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/techniques/T1565/001/",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "SWIFT / Payment Network Abuse",
        "description": "Insider or compromised admin initiates unauthorized SWIFT/NEFT/RTGS transactions by abusing privileged access to payment systems. Modeled after Bangladesh Bank heist (2016).",
        "severity": "critical",
        "threat_category": "Elevation of Privilege",
        # T1078: Valid Accounts — compromised privileged credentials
        # T1098: Account Manipulation — modifying permissions to authorize payments
        # T1071.001: Web Protocols — C2 over HTTPS to exfil payment confirmations
        "mitre_techniques": ["T1078", "T1098", "T1071.001"],
        "mitre_details": {
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1098": {"name": "Account Manipulation", "tactic": "Persistence, Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1098/"},
            "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/001/"},
        },
        "regulatory_impact": ["SWIFT CSP v2024", "PCI-DSS v4.0 Req 7.1 (Access Control)", "SOX Section 404 (Internal Controls)"],
        "recommended_controls": [
            "Dual-authorization (maker-checker) for all payment instructions",
            "Segregation of duties between payment creation and approval",
            "Real-time monitoring of payment system admin actions",
            "Implement SWIFT Alliance Lite2 with mandatory two-factor",
        ],
        "tags": ["SWIFT", "payments", "insider-threat", "wire-transfer"],
        "source": "sector_library",
        "references": [
            "https://www.swift.com/myswift/customer-security-programme-csp",
            "https://www.bbc.com/news/stories-57520169",  # Bangladesh Bank heist
        ],
    },
    {
        "intel_type": "scenario",
        "title": "API-Based Price/Rate Scraping",
        "description": "Competitors or data brokers scrape exchange rates, loan rates, or product pricing via banking APIs at high frequency to gain market intelligence or front-run pricing decisions.",
        "severity": "medium",
        "threat_category": "Information Disclosure",
        # T1213: Data from Information Repositories — harvesting structured data from APIs
        # T1119: Automated Collection — scripted bulk data extraction
        "mitre_techniques": ["T1213", "T1119"],
        "mitre_details": {
            "T1213": {"name": "Data from Information Repositories", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1213/"},
            "T1119": {"name": "Automated Collection", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1119/"},
        },
        "regulatory_impact": ["EU Market Abuse Regulation (MAR) Art 12", "Dodd-Frank Act Title VII"],
        "recommended_controls": [
            "API rate limiting per consumer with tiered thresholds",
            "Behavioral analytics to detect scraping patterns",
            "Watermarking or jittering sensitive rate data",
            "Require API key registration with business justification",
        ],
        "tags": ["API", "scraping", "competitive-intel", "rates"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/techniques/T1119/",
            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Card Skimming / Magecart Attack",
        "description": "Malicious JavaScript injected into payment pages to capture card details in real-time. Targets e-commerce checkout flows and online banking bill payment pages.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        # T1059.007: JavaScript — malicious JS execution on payment pages
        # T1056.003: Web Portal Capture — capturing user input on web forms (card fields)
        "mitre_techniques": ["T1059.007", "T1056.003"],
        "mitre_details": {
            "T1059.007": {"name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/007/"},
            "T1056.003": {"name": "Input Capture: Web Portal Capture", "tactic": "Collection, Credential Access", "url": "https://attack.mitre.org/techniques/T1056/003/"},
        },
        "regulatory_impact": ["PCI-DSS v4.0 Req 6.4.3 (Script Integrity)", "PCI-DSS v4.0 Req 11.6.1 (Change Detection)"],
        "recommended_controls": [
            "Implement Content Security Policy (CSP) headers",
            "Subresource Integrity (SRI) for all external scripts",
            "Real-time JavaScript monitoring for DOM changes on payment pages",
            "Tokenization — never handle raw card data server-side",
        ],
        "tags": ["card-fraud", "magecart", "skimming", "payment-page"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/techniques/T1056/003/",
            "https://www.pcisecuritystandards.org/document_library/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Loan Application Fraud",
        "description": "Synthetic identity or document forgery used to submit fraudulent loan applications. Attackers use AI-generated documents or manipulated income proofs to bypass KYC checks.",
        "severity": "high",
        "threat_category": "Spoofing",
        # T1589.001: Gather Victim Identity: Credentials — collecting PII for synthetic identities
        # T1583.001: Acquire Infrastructure: Domains — setting up fake referral/employer sites
        "mitre_techniques": ["T1589.001", "T1583.001"],
        "mitre_details": {
            "T1589.001": {"name": "Gather Victim Identity Information: Credentials", "tactic": "Reconnaissance", "url": "https://attack.mitre.org/techniques/T1589/001/"},
            "T1583.001": {"name": "Acquire Infrastructure: Domains", "tactic": "Resource Development", "url": "https://attack.mitre.org/techniques/T1583/001/"},
        },
        "regulatory_impact": ["BSA/AML (31 CFR 1020)", "FFIEC BSA/AML Manual", "FCRA Section 615"],
        "recommended_controls": [
            "AI-based document verification (detect forged documents)",
            "Cross-reference income claims with credit bureau data",
            "Device fingerprinting to detect repeat fraud from same device",
            "Implement velocity checks on applications per identity/IP/device",
        ],
        "tags": ["fraud", "KYC", "lending", "synthetic-identity"],
        "source": "sector_library",
        "references": [
            "https://www.fincen.gov/resources/advisories/fincen-advisory-fin-2019-a003",
            "https://www.federalreserve.gov/publications/files/synthetic-identity-fraud-in-the-us-payment-system-202107.pdf",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Insider Trading via API Access",
        "description": "Employee with API access to trading systems or customer order flow leaks material non-public information or front-runs trades using privileged access.",
        "severity": "critical",
        "threat_category": "Repudiation",
        # T1078: Valid Accounts — legitimate employee credentials used for unauthorized access
        # T1567.002: Exfiltration to Cloud Storage — exfil MNPI via cloud services
        # T1005: Data from Local System — accessing order flow data from trading systems
        "mitre_techniques": ["T1078", "T1567.002", "T1005"],
        "mitre_details": {
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1567.002": {"name": "Exfiltration Over Web Service: to Cloud Storage", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1567/002/"},
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
        },
        "regulatory_impact": ["SEBI (PIT) Regulations 2015", "SEC Rule 10b-5", "SOX Section 302"],
        "recommended_controls": [
            "Comprehensive audit logging of all API access with user attribution",
            "Behavioral analytics for unusual query patterns by employees",
            "Chinese wall enforcement between research and trading desks",
            "Mandatory trade pre-clearance for all employees with system access",
        ],
        "tags": ["insider-threat", "trading", "market-abuse", "audit"],
        "source": "sector_library",
        "references": [
            "https://www.sec.gov/spotlight/insidertrading.shtml",
            "https://attack.mitre.org/techniques/T1567/002/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "ATM Jackpotting / Logical Attack",
        "description": "Physical or remote attack on ATM infrastructure to force cash dispensing. Includes black box attacks (connecting external device to ATM) and malware-based attacks (Ploutus, Tyupkin).",
        "severity": "high",
        "threat_category": "Tampering",
        # T1200: Hardware Additions — black box device connected to ATM internals
        # T1059.003: Windows Command Shell — ATM malware executing via cmd on Windows XP/7/10
        "mitre_techniques": ["T1200", "T1059.003"],
        "mitre_details": {
            "T1200": {"name": "Hardware Additions", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1200/"},
            "T1059.003": {"name": "Command and Scripting Interpreter: Windows Command Shell", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/003/"},
        },
        "regulatory_impact": ["PCI PIN Security Requirements", "PCI PTS Device Security Requirements"],
        "recommended_controls": [
            "Hard disk encryption on all ATM endpoints",
            "Application whitelisting to prevent unauthorized binaries",
            "Physical tamper detection sensors",
            "Network segmentation isolating ATM network from corporate",
        ],
        "tags": ["ATM", "physical", "malware", "cash-out"],
        "source": "sector_library",
        "references": [
            "https://www.europol.europa.eu/publications-events/publications/terminal-threat-atm-malware",
            "https://attack.mitre.org/techniques/T1200/",
        ],
    },

    # --- Threat Actors ---
    {
        "intel_type": "threat_actor",
        "title": "FIN7 (Carbanak / Anunak)",
        "description": "Financially motivated cybercrime group active since 2013. Targets financial institutions, retail, and hospitality. Known for custom backdoors (Carbanak, Lizar/Tirion), spear-phishing with malicious documents, and PoS malware. Estimated $1B+ in damages globally.",
        "severity": "critical",
        "threat_category": "Spoofing",
        # T1566.001: Spearphishing Attachment — primary initial access vector
        # T1204.002: User Execution: Malicious File — requires user to open weaponized doc
        # T1071.001: Web Protocols — Carbanak C2 over HTTPS
        "mitre_techniques": ["T1566.001", "T1204.002", "T1071.001"],
        "mitre_details": {
            "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/001/"},
            "T1204.002": {"name": "User Execution: Malicious File", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1204/002/"},
            "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/001/"},
        },
        "regulatory_impact": [],
        "recommended_controls": [
            "Advanced email security with sandboxing",
            "Endpoint Detection and Response (EDR) on all endpoints",
            "Threat intelligence feeds specific to financial sector (FS-ISAC)",
        ],
        "tags": ["FIN7", "Carbanak", "organized-crime", "APT"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/groups/G0046/",  # FIN7 ATT&CK page
            "https://www.justice.gov/opa/pr/three-members-notorious-international-cybercrime-group-fin7-custody",
        ],
    },
    {
        "intel_type": "threat_actor",
        "title": "Lazarus Group (HIDDEN COBRA)",
        "description": "North Korean state-sponsored group (APT38 subset) targeting SWIFT systems and cryptocurrency exchanges. Responsible for Bangladesh Bank heist ($81M, 2016), WannaCry ransomware, and Ronin bridge theft ($625M, 2022).",
        "severity": "critical",
        "threat_category": "Elevation of Privilege",
        # T1566.001: Spearphishing Attachment — weaponized docs targeting bank employees
        # T1059.001: PowerShell — post-compromise execution
        # T1071.001: Web Protocols — C2 communication over HTTP/HTTPS
        "mitre_techniques": ["T1566.001", "T1059.001", "T1071.001"],
        "mitre_details": {
            "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/001/"},
            "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/001/"},
            "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/001/"},
        },
        "regulatory_impact": ["OFAC Sanctions Compliance", "SWIFT CSP v2024"],
        "recommended_controls": [
            "SWIFT Customer Security Programme (CSP) compliance",
            "Network segmentation for payment systems",
            "24/7 SOC monitoring with financial threat intelligence",
        ],
        "tags": ["Lazarus", "nation-state", "SWIFT", "cryptocurrency", "APT38"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/groups/G0032/",  # Lazarus ATT&CK page
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-106a",  # CISA advisory
        ],
    },

    # --- Regulatory Requirements ---
    {
        "intel_type": "regulation",
        "title": "PCI-DSS v4.0 Compliance",
        "description": "Payment Card Industry Data Security Standard v4.0 (mandatory March 2025). Requires specific controls for handling cardholder data: encryption, access control, monitoring, and regular testing. 12 requirement families with 250+ sub-requirements.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["PCI-DSS v4.0 (mandatory March 2025)"],
        "recommended_controls": [
            "Encrypt cardholder data at rest (AES-256) and in transit (TLS 1.2+) — Req 3.5, 4.2",
            "Implement network segmentation for cardholder data environment — Req 1.3",
            "Quarterly vulnerability scans (ASV) and annual penetration tests — Req 11.3, 11.4",
            "Client-side script integrity monitoring — Req 6.4.3 (new in v4.0)",
            "Automated log review and alerting — Req 10.4.1 (new in v4.0)",
        ],
        "tags": ["PCI-DSS", "compliance", "cards", "encryption"],
        "source": "sector_library",
        "references": [
            "https://www.pcisecuritystandards.org/document_library/",
            "https://blog.pcisecuritystandards.org/pci-dss-v4-0",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "SOX IT Controls",
        "description": "Sarbanes-Oxley Act (2002) requires internal controls over financial reporting systems. Section 302 mandates CEO/CFO certification of financial statements. Section 404 requires management assessment of internal controls. PCAOB AS 2201 governs IT general controls audits.",
        "severity": "high",
        "threat_category": "Repudiation",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["SOX Section 302 (Officer Certification)", "SOX Section 404 (Internal Control Assessment)", "PCAOB AS 2201"],
        "recommended_controls": [
            "Change management process for financial application code",
            "Segregation of duties between development and production",
            "Comprehensive audit logging with tamper-evident storage",
            "Regular access reviews for financial systems (quarterly minimum)",
        ],
        "tags": ["SOX", "compliance", "audit", "financial-reporting"],
        "source": "sector_library",
        "references": [
            "https://www.sec.gov/spotlight/sarbanes-oxley.htm",
            "https://pcaobus.org/oversight/standards/auditing-standards/details/AS2201",
        ],
    },
]


# ---------------------------------------------------------------------------
# HEALTHCARE
# ---------------------------------------------------------------------------
HEALTHCARE_THREATS: List[Dict[str, Any]] = [
    # --- Threat Scenarios ---
    {
        "intel_type": "scenario",
        "title": "PHI Breach via EHR System",
        "description": "Unauthorized access to Electronic Health Records exposes Protected Health Information (PHI). Can occur through compromised credentials, excessive privileges, or application vulnerabilities in the EHR system.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        # T1078: Valid Accounts — stolen/shared credentials to access EHR
        # T1213: Data from Information Repositories — bulk extraction from EHR database
        # T1005: Data from Local System — accessing PHI stored on clinical workstations
        "mitre_techniques": ["T1078", "T1213", "T1005"],
        "mitre_details": {
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1213": {"name": "Data from Information Repositories", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1213/"},
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
        },
        "regulatory_impact": ["HIPAA Privacy Rule 45 CFR 164.502 (Minimum Necessary)", "HIPAA Security Rule 45 CFR 164.312", "HITECH Breach Notification 45 CFR 164.404"],
        "recommended_controls": [
            "Role-based access control with minimum necessary principle",
            "Break-the-glass access with mandatory justification and audit",
            "Encryption of PHI at rest and in transit (TLS 1.2+)",
            "Automated monitoring for bulk record access anomalies",
        ],
        "tags": ["EHR", "PHI", "HIPAA", "patient-data"],
        "source": "sector_library",
        "references": [
            "https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html",
            "https://attack.mitre.org/techniques/T1213/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Ransomware Attack on Hospital Systems",
        "description": "Ransomware encrypts critical hospital systems including EHR, lab systems, imaging (PACS), and pharmacy systems. Directly impacts patient care and can be life-threatening. Healthcare is the #1 ransomware target sector.",
        "severity": "critical",
        "threat_category": "Denial of Service",
        # T1486: Data Encrypted for Impact — core ransomware action
        # T1490: Inhibit System Recovery — deleting backups/shadow copies
        # T1566.001: Spearphishing Attachment — primary initial access for healthcare ransomware
        "mitre_techniques": ["T1486", "T1490", "T1566.001"],
        "mitre_details": {
            "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1486/"},
            "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1490/"},
            "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/001/"},
        },
        "regulatory_impact": ["HIPAA Security Rule 45 CFR 164.308(a)(7) (Contingency Plan)", "CMS Conditions of Participation 42 CFR 482"],
        "recommended_controls": [
            "Offline, immutable backups tested quarterly for restoration",
            "Network segmentation isolating clinical from administrative systems",
            "EDR on all endpoints with 24/7 monitoring",
            "Clinical system downtime procedures documented and drilled",
            "Email gateway with advanced threat protection",
        ],
        "tags": ["ransomware", "availability", "patient-safety", "backup"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/stopransomware/healthcare-and-public-health-sector",
            "https://www.hhs.gov/sites/default/files/healthcare-cybersecurity-tlp-clear.pdf",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Medical Device Exploitation",
        "description": "Connected medical devices (infusion pumps, MRI machines, patient monitors) running outdated firmware exploited to pivot into hospital network or directly manipulate device behavior.",
        "severity": "critical",
        "threat_category": "Tampering",
        # T1200: Hardware Additions — rogue device on medical network
        # T1495: Firmware Corruption — modifying device firmware
        # T1210: Exploitation of Remote Services — exploiting unpatched device services
        "mitre_techniques": ["T1200", "T1495", "T1210"],
        "mitre_details": {
            "T1200": {"name": "Hardware Additions", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1200/"},
            "T1495": {"name": "Firmware Corruption", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1495/"},
            "T1210": {"name": "Exploitation of Remote Services", "tactic": "Lateral Movement", "url": "https://attack.mitre.org/techniques/T1210/"},
        },
        "regulatory_impact": ["FDA Premarket Cybersecurity Guidance (2023)", "IEC 62443 (Industrial Automation Security)", "HIPAA Security Rule 45 CFR 164.310"],
        "recommended_controls": [
            "Medical device inventory with firmware version tracking",
            "Network micro-segmentation for IoMT devices",
            "Vulnerability management program specific to medical devices",
            "Manufacturer disclosure agreements for security patches",
        ],
        "tags": ["IoMT", "medical-device", "firmware", "patient-safety"],
        "source": "sector_library",
        "references": [
            "https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity",
            "https://www.cisa.gov/topics/health-care-and-public-health",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Prescription Fraud / Drug Diversion",
        "description": "Insider (clinician or staff) manipulates e-prescribing systems to create fraudulent prescriptions for controlled substances. Can also involve modifying dispensing records to cover diversion.",
        "severity": "high",
        "threat_category": "Tampering",
        # T1078: Valid Accounts — legitimate clinician credentials used for fraud
        # T1565.001: Stored Data Manipulation — altering prescription/dispensing records
        "mitre_techniques": ["T1078", "T1565.001"],
        "mitre_details": {
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1565.001": {"name": "Stored Data Manipulation", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1565/001/"},
        },
        "regulatory_impact": ["DEA EPCS Requirements (21 CFR Part 1311)", "State PDMP Reporting Requirements"],
        "recommended_controls": [
            "Two-factor authentication for all controlled substance prescriptions",
            "Audit logging with anomaly detection on prescribing patterns",
            "Cross-reference prescriptions against PDMP databases",
            "Segregation of duties between prescribing and dispensing",
        ],
        "tags": ["prescription", "controlled-substance", "insider-threat", "diversion"],
        "source": "sector_library",
        "references": [
            "https://www.deadiversion.usdoj.gov/ecomm/e_rx/",
            "https://attack.mitre.org/techniques/T1565/001/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Insurance Claims Manipulation",
        "description": "Upcoding, phantom billing, or unbundling of medical claims to defraud insurance providers. Can be perpetrated by insiders modifying claims data before submission.",
        "severity": "high",
        "threat_category": "Tampering",
        # T1565.001: Stored Data Manipulation — modifying claims/billing records
        # T1078: Valid Accounts — using authorized billing system access
        "mitre_techniques": ["T1565.001", "T1078"],
        "mitre_details": {
            "T1565.001": {"name": "Stored Data Manipulation", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1565/001/"},
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
        },
        "regulatory_impact": ["False Claims Act (31 USC 3729-3733)", "Anti-Kickback Statute (42 USC 1320a-7b)", "CMS Program Integrity Manual"],
        "recommended_controls": [
            "Claims anomaly detection using ML on billing patterns",
            "Segregation of duties between clinical documentation and billing",
            "Regular audits comparing clinical records to submitted claims",
            "Whistleblower hotline and anti-fraud training",
        ],
        "tags": ["billing-fraud", "claims", "upcoding", "insurance"],
        "source": "sector_library",
        "references": [
            "https://oig.hhs.gov/fraud/enforcement/",
            "https://www.cms.gov/Medicare/Fraud-and-Abuse",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Patient Portal Account Takeover",
        "description": "Attackers compromise patient portal accounts to access PHI, medical records, and insurance information. Used for identity theft, insurance fraud, or blackmail of patients with sensitive conditions.",
        "severity": "high",
        "threat_category": "Spoofing",
        # T1078: Valid Accounts — using compromised patient credentials
        # T1110: Brute Force — password attacks against portal login
        "mitre_techniques": ["T1078", "T1110"],
        "mitre_details": {
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1110": {"name": "Brute Force", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1110/"},
        },
        "regulatory_impact": ["HIPAA Security Rule 45 CFR 164.312(d) (Authentication)", "HITECH Act", "State Health Privacy Laws"],
        "recommended_controls": [
            "MFA for patient portal access",
            "Account lockout after failed attempts with CAPTCHA",
            "Notification to patient on login from new device/location",
            "Session timeout for inactive sessions (15 min max)",
        ],
        "tags": ["patient-portal", "ATO", "identity-theft", "PHI"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/techniques/T1110/",
            "https://www.healthit.gov/topic/privacy-security-and-hipaa",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "HL7/FHIR API Data Exposure",
        "description": "Healthcare interoperability APIs (HL7 FHIR, SMART on FHIR) misconfigured to expose patient data without proper authorization. Third-party app access to FHIR endpoints may exceed approved scopes.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        # T1213: Data from Information Repositories — extracting structured patient data via API
        # T1119: Automated Collection — scripted bulk FHIR resource extraction
        "mitre_techniques": ["T1213", "T1119"],
        "mitre_details": {
            "T1213": {"name": "Data from Information Repositories", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1213/"},
            "T1119": {"name": "Automated Collection", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1119/"},
        },
        "regulatory_impact": ["21st Century Cures Act Section 4003", "ONC Information Blocking Rule (45 CFR 171)", "HIPAA Minimum Necessary 45 CFR 164.502(b)"],
        "recommended_controls": [
            "OAuth 2.0 with SMART on FHIR scopes for all API access",
            "API gateway with request/response filtering",
            "Third-party app security assessment before granting access",
            "Audit logging of all FHIR resource access with patient context",
        ],
        "tags": ["FHIR", "HL7", "interoperability", "API", "third-party"],
        "source": "sector_library",
        "references": [
            "https://www.hl7.org/fhir/security.html",
            "https://smarthealthit.org/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Clinical Data Integrity Attack",
        "description": "Manipulation of lab results, vital signs, or medication records in EHR system. Could lead to incorrect treatment decisions and direct patient harm. Extremely difficult to detect if audit logs are also compromised.",
        "severity": "critical",
        "threat_category": "Tampering",
        # T1565.001: Stored Data Manipulation — modifying clinical records
        # T1070.003: Clear Command History — covering tracks after modification
        "mitre_techniques": ["T1565.001", "T1070.003"],
        "mitre_details": {
            "T1565.001": {"name": "Stored Data Manipulation", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1565/001/"},
            "T1070.003": {"name": "Indicator Removal: Clear Command History", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1070/003/"},
        },
        "regulatory_impact": ["HIPAA Security Rule 45 CFR 164.312(c) (Integrity Controls)", "Joint Commission IM.02.02.01", "FDA 21 CFR Part 11 (Electronic Records)"],
        "recommended_controls": [
            "Immutable audit logs stored in separate system (WORM storage)",
            "Digital signatures on clinical data modifications",
            "Automated alerts for modifications to finalized results",
            "Regular integrity checks comparing source system data with EHR",
        ],
        "tags": ["data-integrity", "patient-safety", "EHR", "lab-results"],
        "source": "sector_library",
        "references": [
            "https://www.fda.gov/regulatory-information/search-fda-guidance-documents/part-11-electronic-records-electronic-signatures",
            "https://attack.mitre.org/techniques/T1565/001/",
        ],
    },

    # --- Threat Actors ---
    {
        "intel_type": "threat_actor",
        "title": "Healthcare Ransomware Groups (LockBit, ALPHV/BlackCat)",
        "description": "LockBit and ALPHV/BlackCat (before FBI takedown) specifically targeted healthcare due to urgency of operations and willingness to pay. Change Healthcare breach (2024) caused $22B+ in damages. LockBit responsible for 25%+ of healthcare ransomware incidents in 2023-2024.",
        "severity": "critical",
        "threat_category": "Denial of Service",
        # T1486: Data Encrypted for Impact — ransomware payload
        # T1566.001: Spearphishing Attachment — primary initial access
        # T1059.001: PowerShell — post-compromise execution and lateral movement
        "mitre_techniques": ["T1486", "T1566.001", "T1059.001"],
        "mitre_details": {
            "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1486/"},
            "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/001/"},
            "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/001/"},
        },
        "regulatory_impact": ["HIPAA Breach Notification 45 CFR 164.404-408", "State AG Breach Notification"],
        "recommended_controls": [
            "Healthcare-specific threat intelligence feeds (H-ISAC)",
            "Incident response plan with clinical downtime procedures",
            "Cyber insurance with ransomware coverage",
        ],
        "tags": ["ransomware", "LockBit", "ALPHV", "organized-crime"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a",  # LockBit advisory
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a",  # ALPHV/BlackCat advisory
        ],
    },
    {
        "intel_type": "threat_actor",
        "title": "Insider Threats — Clinical Staff",
        "description": "Clinical staff (nurses, physicians, admin) accessing patient records beyond clinical need. Motivations include curiosity (celebrity patients), personal vendettas, or selling PHI on dark web. UCLA Health (2019) and Northwestern Memorial (2020) are notable examples.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        # T1078: Valid Accounts — using legitimate clinical credentials
        # T1005: Data from Local System — accessing PHI on workstations
        "mitre_techniques": ["T1078", "T1005"],
        "mitre_details": {
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
        },
        "regulatory_impact": ["HIPAA Privacy Rule 45 CFR 164.502", "State Medical Board Disciplinary Actions"],
        "recommended_controls": [
            "Behavioral analytics on EHR access patterns",
            "Automated alerts for VIP/celebrity patient record access",
            "Regular access audits comparing job role to records accessed",
            "Mandatory HIPAA training with insider threat awareness",
        ],
        "tags": ["insider-threat", "snooping", "PHI", "clinical-staff"],
        "source": "sector_library",
        "references": [
            "https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/agreements/index.html",
            "https://attack.mitre.org/techniques/T1078/",
        ],
    },

    # --- Regulatory Requirements ---
    {
        "intel_type": "regulation",
        "title": "HIPAA Security Rule Compliance",
        "description": "Health Insurance Portability and Accountability Act Security Rule (45 CFR Part 164 Subpart C) requires administrative, physical, and technical safeguards for electronic PHI (ePHI). 54 implementation specifications across 3 safeguard categories.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["HIPAA Security Rule (45 CFR 164.302-318)"],
        "recommended_controls": [
            "Risk assessment conducted annually — 45 CFR 164.308(a)(1)",
            "Access controls with unique user identification — 45 CFR 164.312(a)",
            "Audit controls for ePHI access — 45 CFR 164.312(b)",
            "Transmission security with encryption in transit — 45 CFR 164.312(e)",
            "Integrity controls to authenticate ePHI — 45 CFR 164.312(c)",
            "Contingency plan with data backup and disaster recovery — 45 CFR 164.308(a)(7)",
        ],
        "tags": ["HIPAA", "compliance", "ePHI", "safeguards"],
        "source": "sector_library",
        "references": [
            "https://www.hhs.gov/hipaa/for-professionals/security/index.html",
            "https://www.law.cornell.edu/cfr/text/45/part-164/subpart-C",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "HITECH Breach Notification Requirements",
        "description": "HITECH Act (2009) requires notification to affected individuals, HHS, and media (if >500 records) within 60 days of discovering a PHI breach. Tier-based penalty structure: $137-$2,067,813 per violation (2024 adjusted amounts).",
        "severity": "high",
        "threat_category": "Repudiation",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["HITECH Act Section 13402", "HHS Breach Notification Rule 45 CFR 164.400-414"],
        "recommended_controls": [
            "Breach detection capabilities with less than 24hr detection SLA",
            "Incident response plan with breach notification workflow",
            "PHI inventory to quickly assess breach scope",
            "Encryption as safe harbor (encrypted PHI breach = no notification required per 45 CFR 164.402)",
        ],
        "tags": ["HITECH", "breach-notification", "compliance", "penalties"],
        "source": "sector_library",
        "references": [
            "https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html",
            "https://www.law.cornell.edu/uscode/text/42/17932",
        ],
    },
]


# ---------------------------------------------------------------------------
# GOVERNMENT
# ---------------------------------------------------------------------------
GOVERNMENT_THREATS: List[Dict[str, Any]] = [
    {
        "intel_type": "scenario",
        "title": "Nation-State Espionage via Spearphishing",
        "description": "APT groups target government employees with tailored spearphishing to gain persistent access to classified networks. SolarWinds (2020) and Microsoft Exchange (2021) campaigns compromised multiple federal agencies.",
        "severity": "critical",
        "threat_category": "Spoofing",
        "mitre_techniques": ["T1566.001", "T1078", "T1071.001"],
        "mitre_details": {
            "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/001/"},
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/001/"},
        },
        "regulatory_impact": ["FISMA (44 USC 3551)", "EO 14028 (Improving the Nation's Cybersecurity)", "NIST SP 800-53 Rev 5"],
        "recommended_controls": [
            "Implement DMARC/DKIM/SPF for all government email domains",
            "Deploy EDR with 24/7 SOC monitoring on all endpoints",
            "Mandatory phishing-resistant MFA (FIDO2/PIV) per EO 14028",
            "Network segmentation between classified and unclassified systems",
        ],
        "tags": ["APT", "espionage", "phishing", "nation-state", "federal"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a",
            "https://attack.mitre.org/techniques/T1566/001/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Supply Chain Compromise of Government Contractors",
        "description": "Adversaries compromise trusted software vendors or contractors to gain access to government networks. SolarWinds Orion supply chain attack affected 18,000+ organizations including Treasury, Commerce, and DHS.",
        "severity": "critical",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1195.002", "T1199"],
        "mitre_details": {
            "T1195.002": {"name": "Supply Chain Compromise: Compromise Software Supply Chain", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1195/002/"},
            "T1199": {"name": "Trusted Relationship", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1199/"},
        },
        "regulatory_impact": ["EO 14028 Section 4 (Software Supply Chain Security)", "NIST SP 800-161 Rev 1 (C-SCRM)", "FAR 52.204-21"],
        "recommended_controls": [
            "Require SBOM (Software Bill of Materials) from all vendors",
            "Implement zero-trust architecture per NIST SP 800-207",
            "Continuous monitoring of vendor access and network connections",
            "Code signing verification for all software updates",
        ],
        "tags": ["supply-chain", "contractor", "third-party", "SolarWinds"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/news-events/directives/emergency-directive-21-01",
            "https://attack.mitre.org/techniques/T1195/002/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Government Data Leaks / Insider Threats",
        "description": "Authorized personnel exfiltrate classified or sensitive government data. Edward Snowden (2013) and Reality Winner (2017) cases demonstrated catastrophic impact of insider threats in intelligence agencies.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1005", "T1048.002", "T1078"],
        "mitre_details": {
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
            "T1048.002": {"name": "Exfiltration Over Alternative Protocol: Asymmetric Encrypted Non-C2 Protocol", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1048/002/"},
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
        },
        "regulatory_impact": ["EO 13587 (Structural Reforms for Classified Networks)", "NISPOM (32 CFR Part 117)", "Intelligence Community Directive 503"],
        "recommended_controls": [
            "User Activity Monitoring (UAM) on classified systems",
            "Data Loss Prevention (DLP) at network boundaries",
            "Continuous evaluation replacing periodic reinvestigation",
            "Removable media controls and USB device management",
        ],
        "tags": ["insider-threat", "data-leak", "classified", "exfiltration"],
        "source": "sector_library",
        "references": [
            "https://www.dni.gov/index.php/ncsc-how-we-work/ncsc-nittf",
            "https://attack.mitre.org/techniques/T1048/002/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "DDoS Attacks on Government Services",
        "description": "Volumetric and application-layer DDoS attacks targeting government portals, tax filing systems, and citizen services. Pro-Russian hacktivist group Killnet targeted US government sites in 2022-2023.",
        "severity": "high",
        "threat_category": "Denial of Service",
        "mitre_techniques": ["T1498.001", "T1499.002"],
        "mitre_details": {
            "T1498.001": {"name": "Network Denial of Service: Direct Network Flood", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1498/001/"},
            "T1499.002": {"name": "Endpoint Denial of Service: Service Exhaustion Flood", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1499/002/"},
        },
        "regulatory_impact": ["CISA Binding Operational Directive 23-02", "OMB M-22-09 (Zero Trust Strategy)"],
        "recommended_controls": [
            "CDN and DDoS mitigation service for all public-facing sites",
            "Rate limiting and WAF rules for citizen-facing APIs",
            "Redundant hosting across multiple availability zones",
            "Incident response plan with ISP coordination procedures",
        ],
        "tags": ["DDoS", "hacktivism", "availability", "citizen-services"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/sites/default/files/publications/understanding-and-responding-to-ddos-attacks_508c.pdf",
            "https://attack.mitre.org/techniques/T1498/001/",
        ],
    },
    {
        "intel_type": "threat_actor",
        "title": "APT29 (Cozy Bear) & APT28 (Fancy Bear)",
        "description": "Russian SVR (APT29) and GRU (APT28) cyber operations targeting government agencies worldwide. APT29 responsible for SolarWinds campaign; APT28 for DNC hack (2016) and German Bundestag breach (2015).",
        "severity": "critical",
        "threat_category": "Spoofing",
        "mitre_techniques": ["T1566.001", "T1195.002", "T1071.001"],
        "mitre_details": {
            "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/001/"},
            "T1195.002": {"name": "Supply Chain Compromise: Compromise Software Supply Chain", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1195/002/"},
            "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/001/"},
        },
        "regulatory_impact": [],
        "recommended_controls": [
            "CISA Shields Up guidance implementation",
            "Threat intelligence sharing via MS-ISAC and CISA AIS",
            "Hunt operations for known APT29/APT28 TTPs",
        ],
        "tags": ["APT29", "APT28", "Russia", "nation-state", "espionage"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/groups/G0016/",
            "https://attack.mitre.org/groups/G0007/",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "FedRAMP Authorization",
        "description": "Federal Risk and Authorization Management Program provides standardized approach to security assessment for cloud services used by federal agencies. Based on NIST SP 800-53 with Low/Moderate/High impact levels.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["FedRAMP Authorization Act (2022)", "NIST SP 800-53 Rev 5", "OMB Circular A-130"],
        "recommended_controls": [
            "Continuous monitoring with monthly vulnerability scans",
            "POA&M management for all identified vulnerabilities",
            "Annual security assessment by 3PAO",
            "FIPS 140-2 validated encryption modules",
        ],
        "tags": ["FedRAMP", "cloud", "compliance", "NIST", "federal"],
        "source": "sector_library",
        "references": [
            "https://www.fedramp.gov/",
            "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "FISMA Compliance Requirements",
        "description": "Federal Information Security Modernization Act (2014) requires federal agencies to implement information security programs. Mandates annual reporting to OMB and DHS on security posture across all agency systems.",
        "severity": "high",
        "threat_category": "Repudiation",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["FISMA (44 USC 3551-3558)", "OMB Circular A-130", "NIST SP 800-37 Rev 2 (RMF)"],
        "recommended_controls": [
            "Risk Management Framework (RMF) implementation per NIST SP 800-37",
            "Continuous Diagnostics and Mitigation (CDM) program participation",
            "System security plans (SSP) for all federal information systems",
            "Annual FISMA reporting with CIO/CISO metrics",
        ],
        "tags": ["FISMA", "compliance", "federal", "RMF", "reporting"],
        "source": "sector_library",
        "references": [
            "https://csrc.nist.gov/topics/laws-and-regulations/laws/fisma",
            "https://www.cisa.gov/cdm",
        ],
    },
]


# ---------------------------------------------------------------------------
# RETAIL
# ---------------------------------------------------------------------------
RETAIL_THREATS: List[Dict[str, Any]] = [
    {
        "intel_type": "scenario",
        "title": "Magecart Web Skimming on Payment Pages",
        "description": "Malicious JavaScript injected into e-commerce checkout pages to harvest payment card data in real-time. Over 2 million e-commerce sites compromised since 2015. Attackers target third-party scripts and tag managers.",
        "severity": "critical",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1059.007", "T1185"],
        "mitre_details": {
            "T1059.007": {"name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/007/"},
            "T1185": {"name": "Browser Session Hijacking", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1185/"},
        },
        "regulatory_impact": ["PCI-DSS v4.0 Req 6.4.3 (Script Integrity)", "PCI-DSS v4.0 Req 11.6.1 (Change Detection)"],
        "recommended_controls": [
            "Content Security Policy (CSP) with strict script-src directives",
            "Subresource Integrity (SRI) for all external scripts",
            "Real-time client-side monitoring for DOM mutations on payment pages",
            "Tokenization via PSP to avoid handling raw card data",
        ],
        "tags": ["magecart", "skimming", "payment-page", "javascript", "e-commerce"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/news-events/alerts/2020/10/06/attacks-magecart-style-web-skimming",
            "https://attack.mitre.org/techniques/T1059/007/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "POS Malware and Payment Card Theft",
        "description": "Malware installed on Point-of-Sale terminals scrapes card data from RAM during transaction processing. Target (2013, 40M cards) and Home Depot (2014, 56M cards) breaches caused billions in losses.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1005", "T1041"],
        "mitre_details": {
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
            "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1041/"},
        },
        "regulatory_impact": ["PCI-DSS v4.0 Req 9.5 (POI Device Protection)", "PCI PTS Device Security Requirements"],
        "recommended_controls": [
            "Point-to-point encryption (P2PE) on all POS terminals",
            "Application whitelisting on POS systems",
            "Network segmentation isolating POS from corporate network",
            "Regular POS terminal integrity checks and tamper inspections",
        ],
        "tags": ["POS", "payment-card", "malware", "RAM-scraping"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/techniques/T1005/",
            "https://www.pcisecuritystandards.org/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Loyalty Program Account Takeover",
        "description": "Attackers use credential stuffing to compromise customer loyalty accounts, redeeming points for gift cards or merchandise. Loyalty points represent $48B+ in annual value globally with weaker security than financial accounts.",
        "severity": "high",
        "threat_category": "Spoofing",
        "mitre_techniques": ["T1078", "T1110.004"],
        "mitre_details": {
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1110.004": {"name": "Credential Stuffing", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1110/004/"},
        },
        "regulatory_impact": ["CCPA/CPRA (Cal. Civ. Code 1798.100)", "State Breach Notification Laws"],
        "recommended_controls": [
            "MFA or step-up authentication for point redemption",
            "Bot detection and CAPTCHA on login endpoints",
            "Velocity checks on point redemption activity",
            "Breach credential monitoring for customer accounts",
        ],
        "tags": ["loyalty", "ATO", "credential-stuffing", "rewards", "fraud"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/techniques/T1110/004/",
            "https://owasp.org/www-community/attacks/Credential_stuffing",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Supply Chain Attacks on E-Commerce Platforms",
        "description": "Compromise of third-party plugins, extensions, or dependencies used by e-commerce platforms (Magento, Shopify apps, WooCommerce plugins). Attackers inject backdoors into widely-used packages to target thousands of stores simultaneously.",
        "severity": "high",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1195.002", "T1059.007"],
        "mitre_details": {
            "T1195.002": {"name": "Supply Chain Compromise: Compromise Software Supply Chain", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1195/002/"},
            "T1059.007": {"name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/007/"},
        },
        "regulatory_impact": ["PCI-DSS v4.0 Req 6.3 (Security Vulnerabilities)", "FTC Act Section 5 (Unfair Business Practices)"],
        "recommended_controls": [
            "Vendor security assessment for all third-party integrations",
            "Software composition analysis (SCA) for dependency monitoring",
            "Web application firewall with virtual patching capability",
            "Automated integrity monitoring of production code",
        ],
        "tags": ["supply-chain", "e-commerce", "plugins", "third-party"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/techniques/T1195/002/",
            "https://sansec.io/research",
        ],
    },
    {
        "intel_type": "threat_actor",
        "title": "FIN7 / Carbanak (Retail Operations)",
        "description": "FIN7 extensively targets retail and hospitality sectors with spearphishing campaigns delivering custom backdoors. Responsible for breaches at Saks Fifth Avenue, Lord & Taylor, and numerous restaurant chains. Estimated $1B+ stolen.",
        "severity": "critical",
        "threat_category": "Spoofing",
        "mitre_techniques": ["T1566.001", "T1204.002", "T1059.001"],
        "mitre_details": {
            "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/001/"},
            "T1204.002": {"name": "User Execution: Malicious File", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1204/002/"},
            "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/001/"},
        },
        "regulatory_impact": [],
        "recommended_controls": [
            "Advanced email filtering with attachment sandboxing",
            "Endpoint detection and response on all corporate endpoints",
            "FS-ISAC and Retail ISAC threat intelligence feeds",
        ],
        "tags": ["FIN7", "Carbanak", "organized-crime", "retail"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/groups/G0046/",
            "https://www.justice.gov/opa/pr/three-members-notorious-international-cybercrime-group-fin7-custody",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "PCI-DSS v4.0 for Retail",
        "description": "Payment Card Industry Data Security Standard v4.0 (mandatory March 2025) with retail-specific requirements including client-side script monitoring (6.4.3), authenticated vulnerability scans (11.3.1.2), and targeted risk analysis approach.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["PCI-DSS v4.0 (mandatory March 2025)", "PCI PA-DSS (Payment Application)"],
        "recommended_controls": [
            "Quarterly ASV scans and annual penetration testing — Req 11.3/11.4",
            "Client-side script integrity monitoring — Req 6.4.3",
            "Multi-factor authentication for all access to CDE — Req 8.4",
            "Automated log review with alerting — Req 10.4.1",
        ],
        "tags": ["PCI-DSS", "compliance", "payment", "retail"],
        "source": "sector_library",
        "references": [
            "https://www.pcisecuritystandards.org/document_library/",
            "https://blog.pcisecuritystandards.org/pci-dss-v4-0",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "CCPA/CPRA Consumer Data Protection",
        "description": "California Consumer Privacy Act (2018) and California Privacy Rights Act (2020) grant consumers rights over personal data collected by retailers. Applies to businesses with $25M+ revenue or handling 100K+ consumers' data.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["CCPA (Cal. Civ. Code 1798.100-199)", "CPRA (effective Jan 2023)", "CPPA Enforcement Regulations"],
        "recommended_controls": [
            "Data inventory and mapping for all consumer PII",
            "Consumer request portal for access/deletion/opt-out rights",
            "Data minimization — collect only what is necessary",
            "Vendor data processing agreements with audit rights",
        ],
        "tags": ["CCPA", "CPRA", "privacy", "consumer-data", "California"],
        "source": "sector_library",
        "references": [
            "https://oag.ca.gov/privacy/ccpa",
            "https://cppa.ca.gov/",
        ],
    },
]


# ---------------------------------------------------------------------------
# MANUFACTURING
# ---------------------------------------------------------------------------
MANUFACTURING_THREATS: List[Dict[str, Any]] = [
    {
        "intel_type": "scenario",
        "title": "ICS/SCADA Attacks on Production Systems",
        "description": "Adversaries target industrial control systems to disrupt or manipulate manufacturing processes. TRITON/TRISIS (2017) targeted safety instrumented systems at a petrochemical plant, potentially endangering human life.",
        "severity": "critical",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1565.001", "T1071.001"],
        "mitre_details": {
            "T1565.001": {"name": "Stored Data Manipulation", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1565/001/"},
            "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/001/"},
        },
        "regulatory_impact": ["IEC 62443 (Industrial Automation Security)", "NIST SP 800-82 Rev 3 (ICS Security)"],
        "recommended_controls": [
            "Air-gap or strict network segmentation between IT and OT networks",
            "ICS-specific intrusion detection (e.g., Claroty, Nozomi, Dragos)",
            "Disable unnecessary protocols and services on PLCs/HMIs",
            "Regular firmware integrity verification on all controllers",
        ],
        "tags": ["ICS", "SCADA", "OT", "production", "PLC", "safety"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/topics/industrial-control-systems",
            "https://attack.mitre.org/techniques/T1565/001/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Intellectual Property Theft / Trade Secret Exfiltration",
        "description": "State-sponsored or competitor-driven theft of proprietary designs, formulas, and manufacturing processes. Chinese APT groups have stolen IP from aerospace, automotive, and semiconductor manufacturers worth hundreds of billions.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1005", "T1048", "T1567.002"],
        "mitre_details": {
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
            "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1048/"},
            "T1567.002": {"name": "Exfiltration Over Web Service: to Cloud Storage", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1567/002/"},
        },
        "regulatory_impact": ["Defend Trade Secrets Act (18 USC 1836)", "ITAR (22 CFR 120-130)", "EAR (15 CFR 730-774)"],
        "recommended_controls": [
            "Data classification and DLP for CAD files and design documents",
            "Network monitoring for large outbound data transfers",
            "Access controls on PLM/PDM systems with need-to-know enforcement",
            "Insider threat program with behavioral analytics",
        ],
        "tags": ["IP-theft", "trade-secrets", "espionage", "CAD", "design"],
        "source": "sector_library",
        "references": [
            "https://www.fbi.gov/investigate/counterintelligence/the-china-threat",
            "https://attack.mitre.org/techniques/T1048/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Ransomware Disrupting Production Lines",
        "description": "Ransomware spreads from IT to OT networks, halting production. Norsk Hydro (2019) lost $70M when LockerGoga encrypted systems across 170 sites. JBS Foods (2021) paid $11M ransom after production shutdown.",
        "severity": "critical",
        "threat_category": "Denial of Service",
        "mitre_techniques": ["T1486", "T1490"],
        "mitre_details": {
            "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1486/"},
            "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1490/"},
        },
        "regulatory_impact": ["NIST Cybersecurity Framework v2.0", "SEC Cybersecurity Disclosure Rules (2023)"],
        "recommended_controls": [
            "Offline immutable backups for both IT and OT systems",
            "IT/OT network segmentation with DMZ architecture",
            "Incident response plan with production downtime procedures",
            "Cyber insurance covering business interruption losses",
        ],
        "tags": ["ransomware", "production", "OT", "business-continuity"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/stopransomware",
            "https://attack.mitre.org/techniques/T1486/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Supply Chain Compromise of Firmware/Components",
        "description": "Tampered firmware or counterfeit components introduced into manufacturing supply chain. Can include hardware implants, backdoored firmware updates, or substitution of components with lower-quality counterfeits.",
        "severity": "high",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1195.003", "T1195.002"],
        "mitre_details": {
            "T1195.003": {"name": "Supply Chain Compromise: Compromise Hardware Supply Chain", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1195/003/"},
            "T1195.002": {"name": "Supply Chain Compromise: Compromise Software Supply Chain", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1195/002/"},
        },
        "regulatory_impact": ["NIST SP 800-161 Rev 1 (C-SCRM)", "ISO 28000 (Supply Chain Security)"],
        "recommended_controls": [
            "Component provenance verification and traceability",
            "Firmware signing and integrity verification before deployment",
            "Supplier security assessments and audit rights",
            "X-ray and electrical testing for counterfeit component detection",
        ],
        "tags": ["supply-chain", "firmware", "counterfeit", "hardware"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/techniques/T1195/003/",
            "https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final",
        ],
    },
    {
        "intel_type": "threat_actor",
        "title": "XENOTIME / TRITON (ICS Attackers)",
        "description": "XENOTIME is the threat group behind TRITON/TRISIS malware that targeted Schneider Electric Triconex safety controllers. First known attack on safety instrumented systems (SIS) — designed to cause physical damage or endanger human life.",
        "severity": "critical",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1565.001", "T1210", "T1078"],
        "mitre_details": {
            "T1565.001": {"name": "Stored Data Manipulation", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1565/001/"},
            "T1210": {"name": "Exploitation of Remote Services", "tactic": "Lateral Movement", "url": "https://attack.mitre.org/techniques/T1210/"},
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
        },
        "regulatory_impact": [],
        "recommended_controls": [
            "Safety system isolation from process control network",
            "ICS-specific threat intelligence (Dragos, ICS-CERT)",
            "Triconex-specific hardening per Schneider advisories",
        ],
        "tags": ["XENOTIME", "TRITON", "ICS", "safety", "nation-state"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-083a",
            "https://www.dragos.com/threat/xenotime/",
        ],
    },
    {
        "intel_type": "threat_actor",
        "title": "APT41 (Winnti / Double Dragon)",
        "description": "Chinese state-sponsored group conducting both espionage and financially motivated operations. Targets manufacturing, aerospace, and technology sectors for IP theft. Known for supply chain attacks and custom malware families.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1195.002", "T1059.001", "T1005"],
        "mitre_details": {
            "T1195.002": {"name": "Supply Chain Compromise: Compromise Software Supply Chain", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1195/002/"},
            "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/001/"},
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
        },
        "regulatory_impact": [],
        "recommended_controls": [
            "Threat hunting for APT41 IOCs and TTPs",
            "Network segmentation between R&D and production",
            "Manufacturing ISAC participation for threat sharing",
        ],
        "tags": ["APT41", "Winnti", "China", "IP-theft", "supply-chain"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/groups/G0096/",
            "https://www.justice.gov/opa/pr/seven-international-cyber-defendants-charged",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "IEC 62443 Industrial Automation Security",
        "description": "International standard for cybersecurity of industrial automation and control systems. Defines security levels (SL 1-4), zone/conduit models, and requirements for asset owners, integrators, and component suppliers.",
        "severity": "high",
        "threat_category": "Tampering",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["IEC 62443 (all parts)", "NIST SP 800-82 Rev 3"],
        "recommended_controls": [
            "Zone and conduit segmentation per IEC 62443-3-2",
            "Security level target assessment for each zone",
            "Component supplier certification per IEC 62443-4-1",
            "Periodic cybersecurity assessment of IACS environment",
        ],
        "tags": ["IEC-62443", "ICS", "OT", "compliance", "industrial"],
        "source": "sector_library",
        "references": [
            "https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards",
            "https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final",
        ],
    },
]


# ---------------------------------------------------------------------------
# ENERGY
# ---------------------------------------------------------------------------
ENERGY_THREATS: List[Dict[str, Any]] = [
    {
        "intel_type": "scenario",
        "title": "Grid Control System Attacks (SCADA/EMS)",
        "description": "Attacks targeting energy management systems and SCADA controlling power generation/distribution. Ukraine grid attacks (2015, 2016) caused widespread blackouts by manipulating ICS protocols and destroying firmware.",
        "severity": "critical",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1565.001", "T1071.001"],
        "mitre_details": {
            "T1565.001": {"name": "Stored Data Manipulation", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1565/001/"},
            "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/001/"},
        },
        "regulatory_impact": ["NERC CIP-005 (Electronic Security Perimeter)", "NERC CIP-007 (System Security Management)"],
        "recommended_controls": [
            "Electronic Security Perimeter (ESP) per NERC CIP-005",
            "ICS-specific network monitoring and anomaly detection",
            "Redundant control systems with manual override capability",
            "Regular tabletop exercises simulating grid attack scenarios",
        ],
        "tags": ["SCADA", "grid", "power", "ICS", "EMS", "blackout"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/news-events/ics-advisories",
            "https://attack.mitre.org/techniques/T1565/001/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Ransomware Targeting Energy Operations",
        "description": "Ransomware disrupting energy operations and pipeline control systems. Colonial Pipeline (2021) shutdown caused fuel shortages across US East Coast. DarkSide ransomware demanded $4.4M ransom.",
        "severity": "critical",
        "threat_category": "Denial of Service",
        "mitre_techniques": ["T1486", "T1489"],
        "mitre_details": {
            "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1486/"},
            "T1489": {"name": "Service Stop", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1489/"},
        },
        "regulatory_impact": ["TSA Pipeline Security Directive SD-02D", "NERC CIP-008 (Incident Reporting)", "DOE Order 417.1B"],
        "recommended_controls": [
            "IT/OT network segmentation preventing ransomware lateral movement",
            "Offline backups for all critical OT configuration data",
            "Incident response plan with pipeline shutdown/restart procedures",
            "24/7 SOC with energy sector threat intelligence (E-ISAC)",
        ],
        "tags": ["ransomware", "pipeline", "Colonial", "DarkSide", "operations"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a",
            "https://attack.mitre.org/techniques/T1486/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Insider Threat in Critical Infrastructure",
        "description": "Disgruntled employees or contractors with OT access sabotaging energy systems. Maroochy Shire sewage incident (2000) demonstrated real-world impact when a former contractor caused 800K liters of sewage spill via SCADA manipulation.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1078", "T1005"],
        "mitre_details": {
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
        },
        "regulatory_impact": ["NERC CIP-004 (Personnel & Training)", "NERC CIP-011 (Information Protection)", "TSA Pipeline SD-01B"],
        "recommended_controls": [
            "Personnel risk assessment per NERC CIP-004",
            "Immediate access revocation upon termination",
            "Behavioral analytics on OT system access patterns",
            "Dual-authorization for critical operational changes",
        ],
        "tags": ["insider-threat", "critical-infrastructure", "sabotage", "OT"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/insider-threat-mitigation",
            "https://attack.mitre.org/techniques/T1078/",
        ],
    },
    {
        "intel_type": "threat_actor",
        "title": "Sandworm / Voodoo Bear (Russian GRU Unit 74455)",
        "description": "Russian GRU cyber unit responsible for Ukraine power grid attacks (2015, 2016), NotPetya (2017, $10B+ global damage), and Industroyer/CrashOverride malware. Primary threat to Western energy infrastructure.",
        "severity": "critical",
        "threat_category": "Denial of Service",
        "mitre_techniques": ["T1486", "T1565.001", "T1059.001"],
        "mitre_details": {
            "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1486/"},
            "T1565.001": {"name": "Stored Data Manipulation", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1565/001/"},
            "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/001/"},
        },
        "regulatory_impact": [],
        "recommended_controls": [
            "E-ISAC threat intelligence and Shields Up compliance",
            "ICS-specific detection rules for Industroyer/CrashOverride",
            "Network segmentation between IT, OT, and safety systems",
        ],
        "tags": ["Sandworm", "Russia", "GRU", "Industroyer", "grid"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/groups/G0034/",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "NERC CIP Standards",
        "description": "North American Electric Reliability Corporation Critical Infrastructure Protection standards. Mandatory for bulk electric system operators. 12 standards (CIP-002 through CIP-014) covering asset identification, access control, monitoring, incident response, and physical security.",
        "severity": "high",
        "threat_category": "Tampering",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["NERC CIP v7 (CIP-002 through CIP-014)", "FERC Order 887"],
        "recommended_controls": [
            "BES Cyber System categorization per CIP-002",
            "Electronic Security Perimeter with access controls per CIP-005",
            "Security patch management within 35 days per CIP-007",
            "Cyber Security Incident response plan per CIP-008",
        ],
        "tags": ["NERC-CIP", "compliance", "grid", "electric", "BES"],
        "source": "sector_library",
        "references": [
            "https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx",
            "https://www.ferc.gov/industries-data/electric/industry-activities/cip-reliability-standards",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "TSA Pipeline Security Directives",
        "description": "TSA Security Directives SD-01 and SD-02 (post-Colonial Pipeline) mandate cybersecurity measures for pipeline operators. Requires incident reporting within 12 hours, cybersecurity coordinator designation, and implementation plan.",
        "severity": "high",
        "threat_category": "Denial of Service",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["TSA SD Pipeline-2021-01 (Rev)", "TSA SD Pipeline-2021-02 (Rev)", "49 CFR Part 1580"],
        "recommended_controls": [
            "Designate cybersecurity coordinator with 24/7 availability",
            "Report cybersecurity incidents to CISA within 12 hours",
            "Network segmentation between IT and OT systems",
            "Develop and implement cybersecurity incident response plan",
        ],
        "tags": ["TSA", "pipeline", "compliance", "incident-reporting"],
        "source": "sector_library",
        "references": [
            "https://www.tsa.gov/for-industry/surface-transportation",
            "https://www.cisa.gov/topics/critical-infrastructure-security-and-resilience/critical-infrastructure-sectors/transportation-systems-sector",
        ],
    },
]


# ---------------------------------------------------------------------------
# TELECOM
# ---------------------------------------------------------------------------
TELECOM_THREATS: List[Dict[str, Any]] = [
    {
        "intel_type": "scenario",
        "title": "SS7/Diameter Protocol Exploitation",
        "description": "Exploitation of legacy SS7 signaling protocols to intercept calls/SMS, track subscriber locations, and redirect communications. Diameter protocol (4G/5G) also vulnerable to similar attacks. Used for surveillance and 2FA bypass.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1557", "T1040"],
        "mitre_details": {
            "T1557": {"name": "Adversary-in-the-Middle", "tactic": "Credential Access, Collection", "url": "https://attack.mitre.org/techniques/T1557/"},
            "T1040": {"name": "Network Sniffing", "tactic": "Credential Access, Discovery", "url": "https://attack.mitre.org/techniques/T1040/"},
        },
        "regulatory_impact": ["FCC CPNI Rules (47 CFR 64.2001)", "EU EECC Article 40 (Security Measures)"],
        "recommended_controls": [
            "SS7 firewall with anomaly detection for MAP/CAP messages",
            "Diameter signaling security with message filtering",
            "GSMA FS.11 SS7 monitoring and protection guidelines",
            "Migration to SIP-based signaling with TLS encryption",
        ],
        "tags": ["SS7", "Diameter", "signaling", "interception", "surveillance"],
        "source": "sector_library",
        "references": [
            "https://www.gsma.com/security/resources/fs-11-ss7-interconnect-security-monitoring-guidelines/",
            "https://attack.mitre.org/techniques/T1557/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "SIM Swapping for Account Takeover",
        "description": "Attackers socially engineer telecom customer service to transfer victim's phone number to attacker-controlled SIM. Bypasses SMS-based 2FA for banking, email, and cryptocurrency accounts. $68M+ stolen via SIM swaps in 2021 per FBI.",
        "severity": "critical",
        "threat_category": "Spoofing",
        "mitre_techniques": ["T1078", "T1111"],
        "mitre_details": {
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1111": {"name": "Multi-Factor Authentication Interception", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1111/"},
        },
        "regulatory_impact": ["FCC SIM Swap Rules (2023)", "FCC CPNI Rules (47 CFR 64.2001)"],
        "recommended_controls": [
            "Multi-step identity verification for SIM changes",
            "Customer PIN/passphrase requirement for account changes",
            "Real-time alerts to subscribers on SIM change requests",
            "Port freeze/number lock options for high-risk customers",
        ],
        "tags": ["SIM-swap", "social-engineering", "2FA-bypass", "fraud"],
        "source": "sector_library",
        "references": [
            "https://www.fcc.gov/document/fcc-adopts-rules-protect-consumers-sim-swapping",
            "https://attack.mitre.org/techniques/T1111/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "BGP Hijacking for Traffic Redirection",
        "description": "Manipulation of Border Gateway Protocol to redirect internet traffic through adversary-controlled networks. Enables mass surveillance, traffic interception, and credential harvesting. China Telecom incident (2018) redirected Western traffic through Chinese networks.",
        "severity": "high",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1557", "T1565.002"],
        "mitre_details": {
            "T1557": {"name": "Adversary-in-the-Middle", "tactic": "Credential Access, Collection", "url": "https://attack.mitre.org/techniques/T1557/"},
            "T1565.002": {"name": "Data Manipulation: Transmitted Data Manipulation", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1565/002/"},
        },
        "regulatory_impact": ["FCC Secure Internet Routing NPRM (2022)", "NIST SP 800-189 (BGP Security)"],
        "recommended_controls": [
            "RPKI (Resource Public Key Infrastructure) for route origin validation",
            "BGP route monitoring and anomaly alerting",
            "Implement ROV (Route Origin Validation) on all peering sessions",
            "MANRS (Mutually Agreed Norms for Routing Security) compliance",
        ],
        "tags": ["BGP", "routing", "hijacking", "interception", "ISP"],
        "source": "sector_library",
        "references": [
            "https://www.manrs.org/",
            "https://csrc.nist.gov/publications/detail/sp/800-189/final",
        ],
    },
    {
        "intel_type": "threat_actor",
        "title": "Salt Typhoon (Chinese Telecom Espionage)",
        "description": "Chinese state-sponsored group that compromised major US telecom providers (AT&T, Verizon, T-Mobile) in 2024. Accessed lawful intercept systems and call detail records of senior government officials. One of the most significant telecom breaches in US history.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1078", "T1005", "T1557"],
        "mitre_details": {
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
            "T1557": {"name": "Adversary-in-the-Middle", "tactic": "Credential Access, Collection", "url": "https://attack.mitre.org/techniques/T1557/"},
        },
        "regulatory_impact": [],
        "recommended_controls": [
            "Lawful intercept system hardening and access auditing",
            "End-to-end encryption for all internal management traffic",
            "Continuous monitoring for lateral movement in core networks",
        ],
        "tags": ["Salt-Typhoon", "China", "espionage", "lawful-intercept", "CDR"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/news-events/alerts/2024/12/03/cisa-and-partners-release-joint-guide-enhanced-visibility-and-hardening",
            "https://attack.mitre.org/techniques/T1078/",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "FCC CPNI Rules",
        "description": "Customer Proprietary Network Information rules (47 CFR 64.2001-2011) protect telecom customer data including call records, billing information, and service usage. Updated in 2023 to address SIM swapping and data breach notification within 30 days.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["FCC CPNI Rules (47 CFR 64.2001-2011)", "FCC Report & Order 23-112"],
        "recommended_controls": [
            "CPNI access restricted to authenticated customer service agents",
            "Data breach notification to FCC and customers within 30 days",
            "Annual CPNI compliance certification to FCC",
            "Multi-factor authentication for SIM changes per FCC 2023 rules",
        ],
        "tags": ["FCC", "CPNI", "privacy", "compliance", "telecom"],
        "source": "sector_library",
        "references": [
            "https://www.fcc.gov/consumers/guides/protecting-your-telephone-calling-records",
            "https://www.law.cornell.edu/cfr/text/47/part-64/subpart-U",
        ],
    },
]


# ---------------------------------------------------------------------------
# EDUCATION
# ---------------------------------------------------------------------------
EDUCATION_THREATS: List[Dict[str, Any]] = [
    {
        "intel_type": "scenario",
        "title": "Ransomware Targeting K-12 and Universities",
        "description": "Education is the #1 target for ransomware in public sector. Los Angeles Unified (2022), University of California SF ($1.14M ransom), and Lincoln College (2022, permanently closed) demonstrate devastating impact.",
        "severity": "critical",
        "threat_category": "Denial of Service",
        "mitre_techniques": ["T1486", "T1566.001"],
        "mitre_details": {
            "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1486/"},
            "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/001/"},
        },
        "regulatory_impact": ["FERPA (20 USC 1232g)", "State Breach Notification Laws", "CISA K-12 Cybersecurity Act (2021)"],
        "recommended_controls": [
            "Offline backups of student information systems and LMS",
            "Phishing-resistant MFA for all staff and faculty accounts",
            "Network segmentation between administrative and student networks",
            "MS-ISAC and K12 SIX membership for threat intelligence",
        ],
        "tags": ["ransomware", "K-12", "university", "availability"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/k-12-cybersecurity",
            "https://attack.mitre.org/techniques/T1486/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Student Data Breaches (FERPA Violations)",
        "description": "Unauthorized access to student education records including grades, disciplinary records, financial aid, and personal information. EdTech vendor breaches can expose millions of records simultaneously.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1213", "T1005"],
        "mitre_details": {
            "T1213": {"name": "Data from Information Repositories", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1213/"},
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
        },
        "regulatory_impact": ["FERPA (20 USC 1232g, 34 CFR Part 99)", "COPPA (for K-12 under 13)", "State Student Privacy Laws"],
        "recommended_controls": [
            "Data classification for student PII and education records",
            "Vendor security assessments for all EdTech platforms",
            "Encryption of student data at rest and in transit",
            "Annual FERPA training for all staff with data access",
        ],
        "tags": ["FERPA", "student-data", "privacy", "EdTech", "PII"],
        "source": "sector_library",
        "references": [
            "https://studentprivacy.ed.gov/",
            "https://attack.mitre.org/techniques/T1213/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Research Data Theft / Academic Espionage",
        "description": "State-sponsored actors target university research in biotechnology, AI, quantum computing, and defense-funded projects. FBI warned of systematic Chinese targeting of US universities for research IP theft.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1005", "T1048", "T1567.002"],
        "mitre_details": {
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
            "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1048/"},
            "T1567.002": {"name": "Exfiltration Over Web Service: to Cloud Storage", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1567/002/"},
        },
        "regulatory_impact": ["NSPM-33 (Research Security)", "CMMC 2.0 (for DoD-funded research)", "EAR/ITAR Export Controls"],
        "recommended_controls": [
            "Research data classification and handling procedures",
            "Controlled Unclassified Information (CUI) program for DoD research",
            "DLP monitoring on research computing environments",
            "Foreign influence disclosure requirements for researchers",
        ],
        "tags": ["research", "espionage", "IP-theft", "DoD", "academic"],
        "source": "sector_library",
        "references": [
            "https://www.fbi.gov/investigate/counterintelligence/the-china-threat/chinese-talent-programs",
            "https://attack.mitre.org/techniques/T1048/",
        ],
    },
    {
        "intel_type": "threat_actor",
        "title": "Silent Librarian / TA407 (Iranian Academic Espionage)",
        "description": "Iranian state-affiliated group systematically targeting universities worldwide since 2013. Steals academic research, credentials, and library access. Compromised 8,000+ accounts across 320+ universities in 22 countries.",
        "severity": "high",
        "threat_category": "Spoofing",
        "mitre_techniques": ["T1566.002", "T1078", "T1213"],
        "mitre_details": {
            "T1566.002": {"name": "Phishing: Spearphishing Link", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/002/"},
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1213": {"name": "Data from Information Repositories", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1213/"},
        },
        "regulatory_impact": [],
        "recommended_controls": [
            "Phishing-resistant MFA for all university accounts",
            "Security awareness training focused on library/portal phishing",
            "REN-ISAC membership for higher education threat sharing",
        ],
        "tags": ["Silent-Librarian", "Iran", "academic", "phishing", "research"],
        "source": "sector_library",
        "references": [
            "https://www.justice.gov/opa/pr/nine-iranians-charged-conducting-massive-cyber-theft-campaign-behalf-islamic-revolutionary",
            "https://attack.mitre.org/groups/G0122/",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "FERPA Compliance",
        "description": "Family Educational Rights and Privacy Act protects student education records. Requires written consent before disclosure, grants parents/students access rights, and mandates reasonable security measures. Violations can result in loss of federal funding.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["FERPA (20 USC 1232g)", "34 CFR Part 99", "PTAC Guidance Documents"],
        "recommended_controls": [
            "Directory information opt-out process for students",
            "Written consent workflow before record disclosure",
            "Annual notification to students of FERPA rights",
            "Vendor agreements with FERPA-compliant data handling clauses",
        ],
        "tags": ["FERPA", "compliance", "student-privacy", "education"],
        "source": "sector_library",
        "references": [
            "https://www2.ed.gov/policy/gen/guid/fpco/ferpa/index.html",
            "https://studentprivacy.ed.gov/resources",
        ],
    },
]


# ---------------------------------------------------------------------------
# INSURANCE
# ---------------------------------------------------------------------------
INSURANCE_THREATS: List[Dict[str, Any]] = [
    {
        "intel_type": "scenario",
        "title": "Fraudulent Claims Manipulation via System Access",
        "description": "Insiders or external attackers manipulate claims processing systems to approve fraudulent claims, inflate payouts, or create phantom claims. Insurance fraud costs the US $308.6B annually per the Coalition Against Insurance Fraud.",
        "severity": "critical",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1565.001", "T1078"],
        "mitre_details": {
            "T1565.001": {"name": "Stored Data Manipulation", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1565/001/"},
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
        },
        "regulatory_impact": ["State Insurance Fraud Statutes", "NAIC Model Fraud Act", "18 USC 1347 (Federal Insurance Fraud)"],
        "recommended_controls": [
            "Segregation of duties between claims entry and approval",
            "ML-based fraud scoring on all claims before payment",
            "Audit trail with tamper-evident logging for claims modifications",
            "SIU (Special Investigations Unit) for flagged claims review",
        ],
        "tags": ["claims-fraud", "insider-threat", "manipulation", "SIU"],
        "source": "sector_library",
        "references": [
            "https://insurancefraud.org/",
            "https://attack.mitre.org/techniques/T1565/001/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Policyholder PII Data Exfiltration",
        "description": "Breach of policyholder personal data including SSN, health records, financial information, and claims history. Anthem breach (2015) exposed 78.8M records. Insurance data is highly valuable for identity theft and targeted fraud.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1005", "T1048", "T1567"],
        "mitre_details": {
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
            "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1048/"},
            "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1567/"},
        },
        "regulatory_impact": ["NYDFS 23 NYCRR 500", "NAIC Insurance Data Security Model Law", "State Breach Notification Laws"],
        "recommended_controls": [
            "Encryption of all PII at rest (AES-256) and in transit (TLS 1.2+)",
            "Data Loss Prevention monitoring on all egress points",
            "Privileged access management for policyholder databases",
            "Regular penetration testing of customer-facing portals",
        ],
        "tags": ["PII", "data-breach", "policyholder", "identity-theft"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/techniques/T1048/",
            "https://www.dfs.ny.gov/industry_guidance/cybersecurity",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Third-Party Vendor Data Breaches (MGAs, TPAs)",
        "description": "Managing General Agents and Third-Party Administrators process claims and underwriting on behalf of insurers. MOVEit breach (2023) impacted dozens of insurance companies through third-party file transfer compromise.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1199", "T1078"],
        "mitre_details": {
            "T1199": {"name": "Trusted Relationship", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1199/"},
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
        },
        "regulatory_impact": ["NYDFS 23 NYCRR 500.11 (Third Party Service Provider Security)", "NAIC Model Law Section 6"],
        "recommended_controls": [
            "Third-party risk assessment program with annual reviews",
            "Contractual security requirements with audit rights",
            "Network segmentation for vendor access to systems",
            "Vendor access monitoring and anomaly detection",
        ],
        "tags": ["third-party", "vendor", "MGA", "TPA", "MOVEit"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/techniques/T1199/",
            "https://www.dfs.ny.gov/industry_guidance/cybersecurity",
        ],
    },
    {
        "intel_type": "threat_actor",
        "title": "CL0P Ransomware (MOVEit Campaign)",
        "description": "CL0P ransomware gang exploited MOVEit Transfer zero-day (CVE-2023-34362) affecting 2,500+ organizations including major insurance carriers. Pure data extortion model without encryption. Demonstrated supply chain risk to insurance sector.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1190", "T1005", "T1567"],
        "mitre_details": {
            "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1190/"},
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
            "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1567/"},
        },
        "regulatory_impact": [],
        "recommended_controls": [
            "Patch management with priority on internet-facing file transfer tools",
            "Web application firewall for all public-facing applications",
            "Threat intelligence feeds monitoring for zero-day exploitation",
        ],
        "tags": ["CL0P", "MOVEit", "ransomware", "zero-day", "extortion"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a",
            "https://attack.mitre.org/techniques/T1190/",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "NYDFS Cybersecurity Regulation (23 NYCRR 500)",
        "description": "New York Department of Financial Services cybersecurity regulation for financial services companies including insurers. Amended in 2023 with stricter requirements including 72-hour incident notification, CISO reporting to board, and MFA for all remote access.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["23 NYCRR 500 (2023 Amendment)", "NYDFS Enforcement Actions"],
        "recommended_controls": [
            "CISO appointment with direct board reporting per Section 500.4",
            "Multi-factor authentication for all remote access per Section 500.12",
            "Annual penetration testing and bi-annual vulnerability assessments",
            "72-hour cybersecurity event notification to DFS per Section 500.17",
        ],
        "tags": ["NYDFS", "compliance", "23-NYCRR-500", "New-York"],
        "source": "sector_library",
        "references": [
            "https://www.dfs.ny.gov/industry_guidance/cybersecurity",
            "https://govt.westlaw.com/nycrr/Browse/Home/NewYork/NewYorkCodesRulesandRegulations?guid=I60885d20d17611e79a5f000d3a7c4bc3",
        ],
    },
]


# ---------------------------------------------------------------------------
# DEFENSE
# ---------------------------------------------------------------------------
DEFENSE_THREATS: List[Dict[str, Any]] = [
    {
        "intel_type": "scenario",
        "title": "Classified Data Exfiltration from Defense Contractors",
        "description": "Advanced persistent threats targeting defense industrial base (DIB) contractors to steal classified weapons systems data, R&D, and program information. F-35 program data theft attributed to Chinese APTs cost an estimated $100B+.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1005", "T1048.002", "T1567"],
        "mitre_details": {
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
            "T1048.002": {"name": "Exfiltration Over Alternative Protocol: Asymmetric Encrypted Non-C2 Protocol", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1048/002/"},
            "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1567/"},
        },
        "regulatory_impact": ["CMMC 2.0 (32 CFR Part 170)", "NIST SP 800-171 Rev 2", "DFARS 252.204-7012"],
        "recommended_controls": [
            "CUI marking and handling per NIST SP 800-171",
            "SIEM with 90-day log retention per DFARS requirements",
            "Endpoint DLP preventing classified data exfiltration",
            "Insider threat program per NISPOM Change 2",
        ],
        "tags": ["classified", "CUI", "DIB", "exfiltration", "weapons"],
        "source": "sector_library",
        "references": [
            "https://www.acq.osd.mil/cmmc/",
            "https://attack.mitre.org/techniques/T1048/002/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Supply Chain Attacks on Defense Electronics",
        "description": "Tampering with electronic components or firmware in defense supply chain. Counterfeit or backdoored chips in weapons systems can enable surveillance or sabotage. DOD estimates 15%+ of spare parts may be counterfeit.",
        "severity": "critical",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1195.003", "T1195.002"],
        "mitre_details": {
            "T1195.003": {"name": "Supply Chain Compromise: Compromise Hardware Supply Chain", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1195/003/"},
            "T1195.002": {"name": "Supply Chain Compromise: Compromise Software Supply Chain", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1195/002/"},
        },
        "regulatory_impact": ["DFARS 252.246-7008 (Counterfeit Prevention)", "Section 889 of NDAA FY2019", "DoDI 5200.44 (SCRM)"],
        "recommended_controls": [
            "Trusted supplier programs with DMEA accreditation",
            "Component authentication and provenance verification",
            "X-ray and electrical testing for counterfeit detection",
            "Software bill of materials (SBOM) for all embedded systems",
        ],
        "tags": ["supply-chain", "counterfeit", "hardware", "firmware", "SCRM"],
        "source": "sector_library",
        "references": [
            "https://www.dla.mil/Disposition-Services/Offers/TLAM/Counterfeit/",
            "https://attack.mitre.org/techniques/T1195/003/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Spearphishing Targeting Cleared Personnel",
        "description": "Highly targeted phishing campaigns against personnel with security clearances using personal information from OPM breach (2015, 21.5M records) and social media. Goal is credential access to classified networks or recruitment for espionage.",
        "severity": "critical",
        "threat_category": "Spoofing",
        "mitre_techniques": ["T1566.001", "T1566.002", "T1598"],
        "mitre_details": {
            "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/001/"},
            "T1566.002": {"name": "Phishing: Spearphishing Link", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/002/"},
            "T1598": {"name": "Phishing for Information", "tactic": "Reconnaissance", "url": "https://attack.mitre.org/techniques/T1598/"},
        },
        "regulatory_impact": ["NISPOM (32 CFR Part 117)", "DoD Manual 5240.01 (CI Procedures)"],
        "recommended_controls": [
            "Phishing-resistant MFA (PIV/CAC) for all DoD systems",
            "Counterintelligence awareness training for cleared personnel",
            "Email gateway with advanced threat protection and sandboxing",
            "Social media OPSEC training and monitoring",
        ],
        "tags": ["spearphishing", "clearance", "espionage", "OPM", "OPSEC"],
        "source": "sector_library",
        "references": [
            "https://www.dni.gov/index.php/ncsc-how-we-work/ncsc-know-the-risk-raise-your-shield",
            "https://attack.mitre.org/techniques/T1598/",
        ],
    },
    {
        "intel_type": "threat_actor",
        "title": "APT10 / Stone Panda (Chinese Defense Espionage)",
        "description": "Chinese MSS-affiliated group targeting defense contractors, managed service providers, and government agencies. Operation Cloud Hopper compromised MSPs to gain access to defense contractor networks. Indicted by DOJ in 2018.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1199", "T1078", "T1005"],
        "mitre_details": {
            "T1199": {"name": "Trusted Relationship", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1199/"},
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
        },
        "regulatory_impact": [],
        "recommended_controls": [
            "MSP/MSSP security assessment and monitoring",
            "DC3 and DIB-ISAC threat intelligence sharing",
            "Hunt operations for APT10 known IOCs and TTPs",
        ],
        "tags": ["APT10", "China", "MSP", "Cloud-Hopper", "defense"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/groups/G0045/",
            "https://www.justice.gov/opa/pr/two-chinese-hackers-associated-ministry-state-security-charged-global-computer-intrusion",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "CMMC 2.0 (Cybersecurity Maturity Model Certification)",
        "description": "DoD cybersecurity framework requiring defense contractors to achieve certified maturity levels to handle CUI. Level 1 (foundational, 17 practices), Level 2 (advanced, 110 NIST 800-171 practices with third-party assessment), Level 3 (expert, NIST 800-172).",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["CMMC 2.0 (32 CFR Part 170)", "DFARS 252.204-7021", "NIST SP 800-171 Rev 2"],
        "recommended_controls": [
            "110 security practices aligned to NIST SP 800-171",
            "System Security Plan (SSP) and Plan of Action & Milestones (POA&M)",
            "Third-party C3PAO assessment for Level 2 certification",
            "Continuous monitoring and annual self-assessment",
        ],
        "tags": ["CMMC", "DoD", "CUI", "compliance", "certification"],
        "source": "sector_library",
        "references": [
            "https://www.acq.osd.mil/cmmc/",
            "https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "ITAR/EAR Export Control Compliance",
        "description": "International Traffic in Arms Regulations (ITAR) and Export Administration Regulations (EAR) control export of defense articles, services, and technical data. Cyber theft of ITAR-controlled data constitutes unauthorized export with severe penalties.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["ITAR (22 CFR 120-130)", "EAR (15 CFR 730-774)", "Arms Export Control Act (22 USC 2778)"],
        "recommended_controls": [
            "ITAR data marking and access control enforcement",
            "Technology Control Plans (TCP) for foreign national access",
            "Encryption of all ITAR-controlled technical data",
            "Deemed export training for all employees with ITAR access",
        ],
        "tags": ["ITAR", "EAR", "export-control", "compliance", "defense"],
        "source": "sector_library",
        "references": [
            "https://www.pmddtc.state.gov/ddtc_public",
            "https://www.bis.doc.gov/index.php/regulations/export-administration-regulations-ear",
        ],
    },
]


# ---------------------------------------------------------------------------
# MEDIA
# ---------------------------------------------------------------------------
MEDIA_THREATS: List[Dict[str, Any]] = [
    {
        "intel_type": "scenario",
        "title": "Content Delivery / DRM Bypass and Piracy",
        "description": "Circumvention of digital rights management systems to pirate premium content. Widevine L3 DRM broken in 2019, enabling mass piracy of streaming content. Annual cost to media industry estimated at $29.2B globally.",
        "severity": "high",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1565.001", "T1059.007"],
        "mitre_details": {
            "T1565.001": {"name": "Stored Data Manipulation", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1565/001/"},
            "T1059.007": {"name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/007/"},
        },
        "regulatory_impact": ["DMCA (17 USC 1201)", "EU Copyright Directive (2019/790)", "WIPO Copyright Treaty"],
        "recommended_controls": [
            "Multi-DRM strategy (Widevine, FairPlay, PlayReady)",
            "Forensic watermarking for content traceability",
            "CDN token authentication with short-lived URLs",
            "Anti-piracy monitoring and DMCA takedown automation",
        ],
        "tags": ["DRM", "piracy", "content-protection", "streaming"],
        "source": "sector_library",
        "references": [
            "https://www.copyright.gov/dmca/",
            "https://attack.mitre.org/techniques/T1565/001/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Disinformation and Deepfake Attacks",
        "description": "State-sponsored or adversarial creation and distribution of manipulated media content to spread disinformation. AI-generated deepfakes increasingly targeting journalists and news outlets to undermine public trust.",
        "severity": "high",
        "threat_category": "Spoofing",
        "mitre_techniques": ["T1566", "T1583.001"],
        "mitre_details": {
            "T1566": {"name": "Phishing", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/"},
            "T1583.001": {"name": "Acquire Infrastructure: Domains", "tactic": "Resource Development", "url": "https://attack.mitre.org/techniques/T1583/001/"},
        },
        "regulatory_impact": ["EU Digital Services Act (DSA)", "EU AI Act (deepfake disclosure)", "FCC Rules on AI-Generated Content"],
        "recommended_controls": [
            "Content authenticity verification (C2PA/CAI standards)",
            "AI-based deepfake detection for submitted content",
            "Source verification protocols for breaking news",
            "Digital provenance tracking for all published media",
        ],
        "tags": ["disinformation", "deepfake", "AI", "trust", "fake-news"],
        "source": "sector_library",
        "references": [
            "https://c2pa.org/",
            "https://attack.mitre.org/techniques/T1583/001/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Journalist/Source Credential Compromise",
        "description": "Targeting journalist accounts to identify confidential sources, obtain unpublished stories, or conduct surveillance. Pegasus spyware used against journalists in 50+ countries. AP, Al Jazeera, and Reuters reporters confirmed targets.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1078", "T1005", "T1114"],
        "mitre_details": {
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
            "T1114": {"name": "Email Collection", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1114/"},
        },
        "regulatory_impact": ["Press Freedom Laws (First Amendment)", "EU Media Freedom Act (2024)", "Shield Laws (varying by state)"],
        "recommended_controls": [
            "End-to-end encrypted communications (Signal, SecureDrop)",
            "Hardware security keys for all journalist accounts",
            "Mobile device management with spyware detection",
            "Secure source communication platforms (SecureDrop, OnionShare)",
        ],
        "tags": ["journalism", "source-protection", "surveillance", "Pegasus"],
        "source": "sector_library",
        "references": [
            "https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/",
            "https://attack.mitre.org/techniques/T1114/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "DDoS Attacks on Streaming/Publishing Platforms",
        "description": "Volumetric DDoS attacks targeting media platforms during high-traffic events (elections, breaking news, live sports). Hacktivist groups and nation-states use DDoS to suppress unfavorable coverage.",
        "severity": "high",
        "threat_category": "Denial of Service",
        "mitre_techniques": ["T1498", "T1499"],
        "mitre_details": {
            "T1498": {"name": "Network Denial of Service", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1498/"},
            "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1499/"},
        },
        "regulatory_impact": ["EU Digital Services Act (platform availability)", "FCC Emergency Alert System requirements"],
        "recommended_controls": [
            "CDN with DDoS mitigation (Cloudflare, Akamai, AWS Shield)",
            "Auto-scaling infrastructure for traffic spikes",
            "Anycast DNS with global distribution",
            "Incident response plan for high-profile event coverage",
        ],
        "tags": ["DDoS", "streaming", "availability", "live-events"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/techniques/T1498/",
            "https://attack.mitre.org/techniques/T1499/",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "EU Digital Services Act (DSA)",
        "description": "EU regulation (effective Feb 2024) requiring platforms to address illegal content, disinformation, and ensure transparency. Very Large Online Platforms (VLOPs) with 45M+ EU users face enhanced obligations including systemic risk assessments.",
        "severity": "high",
        "threat_category": "Repudiation",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["EU Digital Services Act (Regulation 2022/2065)", "EU Digital Markets Act"],
        "recommended_controls": [
            "Transparent content moderation policies and appeals process",
            "Annual systemic risk assessment for VLOPs",
            "Trusted flaggers program for illegal content removal",
            "Advertising transparency and repository requirements",
        ],
        "tags": ["DSA", "EU", "content-moderation", "platform", "compliance"],
        "source": "sector_library",
        "references": [
            "https://digital-strategy.ec.europa.eu/en/policies/digital-services-act-package",
            "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2065",
        ],
    },
]


# ---------------------------------------------------------------------------
# TECHNOLOGY
# ---------------------------------------------------------------------------
TECHNOLOGY_THREATS: List[Dict[str, Any]] = [
    {
        "intel_type": "scenario",
        "title": "CI/CD Pipeline Compromise",
        "description": "Attackers inject malicious code into build pipelines to distribute backdoored software to customers. SolarWinds (2020) compromised Orion build system affecting 18,000 organizations. Codecov (2021) bash uploader compromised CI secrets.",
        "severity": "critical",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1195.002", "T1059.004"],
        "mitre_details": {
            "T1195.002": {"name": "Supply Chain Compromise: Compromise Software Supply Chain", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1195/002/"},
            "T1059.004": {"name": "Command and Scripting Interpreter: Unix Shell", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/004/"},
        },
        "regulatory_impact": ["EO 14028 Section 4 (Software Supply Chain)", "NIST SSDF (SP 800-218)", "SLSA Framework"],
        "recommended_controls": [
            "Build pipeline hardening with ephemeral runners",
            "Code signing and provenance attestation (SLSA Level 3+)",
            "Secret scanning and rotation in CI/CD environments",
            "SBOM generation and distribution with each release",
        ],
        "tags": ["CI/CD", "supply-chain", "build", "pipeline", "SolarWinds"],
        "source": "sector_library",
        "references": [
            "https://slsa.dev/",
            "https://attack.mitre.org/techniques/T1195/002/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "API Abuse and Data Scraping at Scale",
        "description": "Automated abuse of APIs to scrape user data, enumerate accounts, or extract proprietary datasets. Facebook/Cambridge Analytica (87M profiles), LinkedIn scraping (700M profiles), and Twitter API abuse demonstrate scale of impact.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1213", "T1119"],
        "mitre_details": {
            "T1213": {"name": "Data from Information Repositories", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1213/"},
            "T1119": {"name": "Automated Collection", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1119/"},
        },
        "regulatory_impact": ["GDPR Article 5(1)(b) (Purpose Limitation)", "CCPA/CPRA", "CFAA (18 USC 1030)"],
        "recommended_controls": [
            "API rate limiting with per-user and per-IP throttling",
            "Bot detection (device fingerprinting, behavioral analysis)",
            "API authentication with OAuth 2.0 and scope restrictions",
            "Monitoring for bulk data access patterns and anomalies",
        ],
        "tags": ["API", "scraping", "data-abuse", "bot", "enumeration"],
        "source": "sector_library",
        "references": [
            "https://owasp.org/API-Security/",
            "https://attack.mitre.org/techniques/T1119/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Cloud Infrastructure Misconfiguration",
        "description": "Exposed S3 buckets, overly permissive IAM policies, and misconfigured cloud services leading to data breaches. Capital One breach (2019, 106M records) exploited misconfigured WAF and IAM role. Cloud misconfigs are the #1 cause of data breaches in tech.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1530", "T1078.004"],
        "mitre_details": {
            "T1530": {"name": "Data from Cloud Storage", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1530/"},
            "T1078.004": {"name": "Valid Accounts: Cloud Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/004/"},
        },
        "regulatory_impact": ["SOC 2 Type II", "GDPR Article 32 (Security of Processing)", "ISO 27017 (Cloud Security)"],
        "recommended_controls": [
            "Cloud Security Posture Management (CSPM) with auto-remediation",
            "Infrastructure as Code (IaC) scanning in CI/CD pipeline",
            "Least-privilege IAM policies with regular access reviews",
            "S3/blob storage public access blocking at organization level",
        ],
        "tags": ["cloud", "misconfiguration", "S3", "IAM", "CSPM"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/techniques/T1530/",
            "https://attack.mitre.org/techniques/T1078/004/",
        ],
    },
    {
        "intel_type": "scenario",
        "title": "Zero-Day Exploitation in Software Products",
        "description": "Discovery and exploitation of unknown vulnerabilities in widely-deployed software. Log4Shell (2021) affected millions of Java applications. Kaseya VSA zero-day (2021) enabled REvil ransomware to hit 1,500+ companies via single vendor.",
        "severity": "critical",
        "threat_category": "Elevation of Privilege",
        "mitre_techniques": ["T1203", "T1068"],
        "mitre_details": {
            "T1203": {"name": "Exploitation for Client Execution", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1203/"},
            "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1068/"},
        },
        "regulatory_impact": ["CISA BOD 22-01 (KEV Remediation)", "SEC Cybersecurity Disclosure Rules", "EU NIS2 Directive"],
        "recommended_controls": [
            "Vulnerability disclosure program and bug bounty",
            "Secure SDLC with fuzzing and static analysis",
            "Rapid patch deployment capability (< 24 hours for critical)",
            "Runtime application self-protection (RASP) for defense-in-depth",
        ],
        "tags": ["zero-day", "vulnerability", "exploitation", "Log4Shell"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/techniques/T1203/",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
    },
    {
        "intel_type": "threat_actor",
        "title": "APT29 / Nobelium (SolarWinds Attack)",
        "description": "Russian SVR intelligence service conducted the SolarWinds supply chain compromise (2020), one of the most sophisticated cyber espionage campaigns in history. Compromised build systems to distribute backdoored updates to 18,000+ organizations.",
        "severity": "critical",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1195.002", "T1071.001", "T1078"],
        "mitre_details": {
            "T1195.002": {"name": "Supply Chain Compromise: Compromise Software Supply Chain", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1195/002/"},
            "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/001/"},
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
        },
        "regulatory_impact": [],
        "recommended_controls": [
            "Build system isolation and integrity verification",
            "SLSA framework adoption for supply chain security",
            "Threat intelligence feeds for APT29 IOCs and TTPs",
        ],
        "tags": ["APT29", "Nobelium", "SolarWinds", "supply-chain", "Russia"],
        "source": "sector_library",
        "references": [
            "https://attack.mitre.org/groups/G0016/",
            "https://www.cisa.gov/news-events/directives/emergency-directive-21-01",
        ],
    },
    {
        "intel_type": "threat_actor",
        "title": "Scattered Spider (Social Engineering Specialists)",
        "description": "English-speaking threat group using social engineering, SIM swapping, and MFA fatigue to breach major tech companies. Responsible for MGM Resorts ($100M+ impact), Caesars ($15M ransom paid), Okta, and Twilio breaches in 2022-2023.",
        "severity": "critical",
        "threat_category": "Spoofing",
        "mitre_techniques": ["T1566.004", "T1078", "T1111"],
        "mitre_details": {
            "T1566.004": {"name": "Phishing: Spearphishing Voice", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/004/"},
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
            "T1111": {"name": "Multi-Factor Authentication Interception", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1111/"},
        },
        "regulatory_impact": [],
        "recommended_controls": [
            "Phishing-resistant MFA (FIDO2) replacing SMS/push",
            "Help desk identity verification procedures hardening",
            "Social engineering awareness training",
        ],
        "tags": ["Scattered-Spider", "social-engineering", "SIM-swap", "vishing"],
        "source": "sector_library",
        "references": [
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a",
            "https://attack.mitre.org/groups/G1015/",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "SOC 2 Type II Compliance",
        "description": "AICPA Service Organization Control 2 audit framework evaluating security, availability, processing integrity, confidentiality, and privacy controls. De facto requirement for SaaS/cloud companies serving enterprise customers.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["SOC 2 Type II (AICPA TSC 2017)", "SOC 2+ with additional criteria"],
        "recommended_controls": [
            "Continuous monitoring of all TSC control points",
            "Annual Type II audit with independent CPA firm",
            "Change management and access review processes",
            "Incident response and business continuity plans tested annually",
        ],
        "tags": ["SOC2", "compliance", "SaaS", "audit", "trust"],
        "source": "sector_library",
        "references": [
            "https://www.aicpa.org/topic/audit-assurance/audit-and-assurance-greater-than-soc-2",
            "https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/aaborserviceorganizations",
        ],
    },
    {
        "intel_type": "regulation",
        "title": "EU AI Act & GDPR for Technology Companies",
        "description": "EU AI Act (2024) establishes risk-based regulation of AI systems with strict requirements for high-risk applications. Combined with GDPR, creates comprehensive framework for data processing and AI governance with fines up to 7% of global revenue.",
        "severity": "high",
        "threat_category": "Repudiation",
        "mitre_techniques": [],
        "mitre_details": {},
        "regulatory_impact": ["EU AI Act (Regulation 2024/1689)", "GDPR (Regulation 2016/679)", "EU Data Act (2024)"],
        "recommended_controls": [
            "AI risk classification and conformity assessment",
            "Data protection impact assessments (DPIA) for AI processing",
            "Algorithmic transparency and explainability documentation",
            "Data Processing Agreements (DPA) with all processors per GDPR Art 28",
        ],
        "tags": ["AI-Act", "GDPR", "EU", "compliance", "privacy", "AI"],
        "source": "sector_library",
        "references": [
            "https://artificialintelligenceact.eu/",
            "https://gdpr.eu/",
        ],
    },
]


# ---------------------------------------------------------------------------
# Sector Registry
# ---------------------------------------------------------------------------
SECTOR_INTEL: Dict[str, List[Dict[str, Any]]] = {
    "banking": BANKING_THREATS,
    "finance": BANKING_THREATS,  # alias
    "healthcare": HEALTHCARE_THREATS,
    "government": GOVERNMENT_THREATS,
    "retail": RETAIL_THREATS,
    "manufacturing": MANUFACTURING_THREATS,
    "energy": ENERGY_THREATS,
    "telecom": TELECOM_THREATS,
    "telecommunications": TELECOM_THREATS,  # alias
    "education": EDUCATION_THREATS,
    "insurance": INSURANCE_THREATS,
    "defense": DEFENSE_THREATS,
    "media": MEDIA_THREATS,
    "entertainment": MEDIA_THREATS,  # alias
    "technology": TECHNOLOGY_THREATS,
    "tech": TECHNOLOGY_THREATS,  # alias
}

SUPPORTED_SECTORS = [
    "banking", "finance", "healthcare", "government", "retail",
    "manufacturing", "energy", "telecom", "telecommunications",
    "education", "insurance", "defense", "media", "entertainment",
    "technology", "tech",
]


def get_sector_threats(sector: str) -> List[Dict[str, Any]]:
    """Get all threat intel entries for a sector."""
    return SECTOR_INTEL.get(sector.lower(), [])


def get_sector_threats_by_type(sector: str, intel_type: str) -> List[Dict[str, Any]]:
    """Get threat intel filtered by type (scenario, threat_actor, regulation, etc.)."""
    return [t for t in get_sector_threats(sector) if t["intel_type"] == intel_type]


def get_sector_threats_for_components(sector: str, component_categories: List[str]) -> List[Dict[str, Any]]:
    """Get sector threats relevant to specific component types.

    Maps component categories (api, database, authentication, etc.) to relevant threat tags.
    """
    category_tag_map = {
        "api": ["API", "authentication", "ATO", "scraping", "FHIR", "HL7", "enumeration", "bot"],
        "database": ["PHI", "patient-data", "EHR", "data-integrity", "encryption", "PII", "CUI"],
        "authentication": ["authentication", "ATO", "credential-stuffing", "MFA", "patient-portal", "SIM-swap", "2FA-bypass"],
        "frontend": ["magecart", "skimming", "payment-page", "XSS", "javascript", "DRM", "e-commerce"],
        "cloud": ["ransomware", "backup", "encryption", "cloud", "misconfiguration", "CSPM", "S3", "IAM"],
        "microservice": ["SWIFT", "payments", "interoperability", "CI/CD", "pipeline", "supply-chain"],
        "iot": ["IoMT", "medical-device", "firmware", "ICS", "SCADA", "OT", "PLC", "safety"],
        "network": ["SS7", "Diameter", "BGP", "routing", "DDoS", "signaling"],
        "mobile": ["SIM-swap", "2FA-bypass", "fraud"],
    }

    relevant_tags = set()
    for cat in component_categories:
        relevant_tags.update(category_tag_map.get(cat, []))

    if not relevant_tags:
        return get_sector_threats(sector)

    threats = get_sector_threats(sector)
    scored = []
    for t in threats:
        overlap = len(relevant_tags.intersection(set(t.get("tags", []))))
        if overlap > 0 or t["intel_type"] in ("regulation", "threat_actor"):
            scored.append((overlap, t))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [t for _, t in scored]


def format_intel_for_prompt(threats: List[Dict[str, Any]], max_entries: int = 15) -> str:
    """Format threat intel entries into a text block suitable for AI prompts."""
    if not threats:
        return ""

    lines = []
    for i, t in enumerate(threats[:max_entries]):
        lines.append(f"\n### {t['title']} [{t['severity'].upper()}]")
        lines.append(f"Type: {t['intel_type']}")
        lines.append(f"Description: {t['description']}")
        if t.get("mitre_techniques"):
            lines.append(f"MITRE ATT&CK: {', '.join(t['mitre_techniques'])}")
        if t.get("regulatory_impact"):
            lines.append(f"Regulatory: {', '.join(t['regulatory_impact'])}")
        if t.get("recommended_controls"):
            for ctrl in t["recommended_controls"][:3]:
                lines.append(f"  - {ctrl}")
        if t.get("references"):
            lines.append(f"Sources: {', '.join(t['references'][:2])}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MITRE ATT&CK Live Enrichment
# ---------------------------------------------------------------------------
import httpx
import logging

logger = logging.getLogger(__name__)

# MITRE ATT&CK STIX data URL (Enterprise matrix)
MITRE_ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# CISA KEV catalog URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Sector → product/vendor keywords for CISA KEV filtering
SECTOR_KEV_KEYWORDS: Dict[str, List[str]] = {
    "banking": [
        "oracle", "sap", "ibm", "citrix", "vmware", "fortinet", "paloalto",
        "f5", "pulse", "cisco", "microsoft", "apache", "java",
    ],
    "healthcare": [
        "philips", "ge healthcare", "siemens healthineers", "epic", "cerner",
        "meditech", "oracle", "citrix", "vmware", "fortinet", "cisco",
        "microsoft", "apache", "openssl",
    ],
    "government": [
        "microsoft", "adobe", "cisco", "citrix", "vmware", "fortinet",
        "paloalto", "f5", "solarwinds", "ivanti", "pulse", "apache",
    ],
    "retail": [
        "magento", "adobe", "shopify", "woocommerce", "oracle", "sap",
        "microsoft", "cisco", "vmware", "citrix", "apache",
    ],
    "manufacturing": [
        "siemens", "schneider", "rockwell", "honeywell", "abb", "ge",
        "cisco", "vmware", "microsoft", "oracle", "sap", "apache",
    ],
    "energy": [
        "siemens", "schneider", "ge", "honeywell", "abb", "cisco",
        "fortinet", "paloalto", "vmware", "microsoft", "oracle",
    ],
    "telecom": [
        "cisco", "nokia", "ericsson", "huawei", "juniper", "fortinet",
        "paloalto", "f5", "vmware", "microsoft", "oracle", "apache",
    ],
    "education": [
        "microsoft", "google", "adobe", "cisco", "vmware", "citrix",
        "apache", "oracle", "blackboard", "canvas",
    ],
    "insurance": [
        "oracle", "sap", "ibm", "guidewire", "duck creek", "microsoft",
        "cisco", "vmware", "citrix", "fortinet", "progress",
    ],
    "defense": [
        "microsoft", "cisco", "vmware", "fortinet", "paloalto", "f5",
        "ivanti", "solarwinds", "oracle", "adobe", "apache",
    ],
    "media": [
        "adobe", "akamai", "cloudflare", "amazon", "microsoft", "google",
        "wordpress", "drupal", "apache", "nginx", "vmware",
    ],
    "technology": [
        "microsoft", "google", "amazon", "cisco", "vmware", "docker",
        "kubernetes", "jenkins", "gitlab", "apache", "oracle", "hashicorp",
    ],
}


class MitreAttackEnricher:
    """Pulls real MITRE ATT&CK technique metadata to validate and enrich sector intel."""

    def __init__(self):
        self._technique_cache: Dict[str, Dict[str, Any]] = {}
        self._loaded = False

    async def load_techniques(self) -> int:
        """Fetch MITRE ATT&CK STIX bundle and build technique lookup.

        Returns number of techniques loaded.
        """
        if self._loaded and self._technique_cache:
            return len(self._technique_cache)

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.get(MITRE_ATTACK_STIX_URL)
                resp.raise_for_status()
                bundle = resp.json()

            for obj in bundle.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue

                ext_refs = obj.get("external_references", [])
                mitre_ref = next(
                    (r for r in ext_refs if r.get("source_name") == "mitre-attack"),
                    None,
                )
                if not mitre_ref:
                    continue

                technique_id = mitre_ref.get("external_id", "")
                url = mitre_ref.get("url", "")
                name = obj.get("name", "")

                # Extract tactics from kill_chain_phases
                tactics = []
                for phase in obj.get("kill_chain_phases", []):
                    if phase.get("kill_chain_name") == "mitre-attack":
                        tactics.append(phase["phase_name"].replace("-", " ").title())

                # Extract data sources
                data_sources = obj.get("x_mitre_data_sources", [])

                # Extract platforms
                platforms = obj.get("x_mitre_platforms", [])

                self._technique_cache[technique_id] = {
                    "id": technique_id,
                    "name": name,
                    "description": obj.get("description", "")[:500],
                    "tactics": tactics,
                    "tactic_str": ", ".join(tactics),
                    "url": url,
                    "platforms": platforms,
                    "data_sources": data_sources[:5],
                    "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                }

            self._loaded = True
            logger.info(f"Loaded {len(self._technique_cache)} MITRE ATT&CK techniques")
            return len(self._technique_cache)

        except Exception as e:
            logger.error(f"Failed to load MITRE ATT&CK data: {e}")
            return 0

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Look up a technique by ID (e.g. T1078, T1110.004)."""
        return self._technique_cache.get(technique_id)

    def validate_sector_intel(self, sector: str) -> Dict[str, Any]:
        """Validate all MITRE technique IDs in a sector's threat intel.

        Returns a report of valid, invalid, and deprecated techniques.
        """
        threats = get_sector_threats(sector)
        if not threats:
            return {"error": f"Unknown sector: {sector}"}

        results = {
            "sector": sector,
            "total_entries": len(threats),
            "total_techniques_referenced": 0,
            "valid": [],
            "not_found": [],
            "entries": [],
        }

        for threat in threats:
            entry_result = {
                "title": threat["title"],
                "techniques": [],
            }

            for tid in threat.get("mitre_techniques", []):
                results["total_techniques_referenced"] += 1
                cached = self._technique_cache.get(tid)

                if cached:
                    entry_result["techniques"].append({
                        "id": tid,
                        "status": "valid",
                        "name": cached["name"],
                        "tactics": cached["tactic_str"],
                        "url": cached["url"],
                    })
                    results["valid"].append(tid)
                else:
                    entry_result["techniques"].append({
                        "id": tid,
                        "status": "not_found",
                    })
                    results["not_found"].append(tid)

            results["entries"].append(entry_result)

        results["validation_rate"] = (
            f"{len(results['valid'])}/{results['total_techniques_referenced']}"
            if results["total_techniques_referenced"] > 0
            else "N/A"
        )
        return results

    def enrich_threat_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a single threat entry with live MITRE ATT&CK metadata.

        Adds/updates mitre_details with real technique names, tactics, and URLs.
        """
        enriched = dict(entry)
        mitre_details = {}

        for tid in enriched.get("mitre_techniques", []):
            cached = self._technique_cache.get(tid)
            if cached:
                mitre_details[tid] = {
                    "name": cached["name"],
                    "tactic": cached["tactic_str"],
                    "url": cached["url"],
                    "platforms": cached["platforms"],
                    "data_sources": cached["data_sources"],
                    "validated": True,
                }
            else:
                # Keep existing detail if present, mark unvalidated
                existing = enriched.get("mitre_details", {}).get(tid, {})
                mitre_details[tid] = {
                    **existing,
                    "validated": False,
                    "warning": f"Technique {tid} not found in ATT&CK Enterprise v15",
                }

        enriched["mitre_details"] = mitre_details
        enriched["enriched_at"] = __import__("datetime").datetime.utcnow().isoformat()
        return enriched


class CisaKevEnricher:
    """Pulls CISA Known Exploited Vulnerabilities relevant to a sector."""

    def __init__(self):
        self._kev_cache: List[Dict[str, Any]] = []
        self._loaded = False

    async def load_kev(self) -> int:
        """Fetch CISA KEV catalog. Returns number of entries loaded."""
        if self._loaded and self._kev_cache:
            return len(self._kev_cache)

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(CISA_KEV_URL)
                resp.raise_for_status()
                data = resp.json()

            self._kev_cache = data.get("vulnerabilities", [])
            self._loaded = True
            logger.info(f"Loaded {len(self._kev_cache)} CISA KEV entries")
            return len(self._kev_cache)

        except Exception as e:
            logger.error(f"Failed to load CISA KEV: {e}")
            return 0

    def get_sector_relevant_kevs(
        self, sector: str, max_results: int = 20
    ) -> List[Dict[str, Any]]:
        """Filter KEV catalog for entries relevant to a sector based on vendor/product keywords."""
        keywords = SECTOR_KEV_KEYWORDS.get(sector.lower(), [])
        if not keywords:
            return []

        relevant = []
        for vuln in self._kev_cache:
            vendor = (vuln.get("vendorProject") or "").lower()
            product = (vuln.get("product") or "").lower()
            combined = f"{vendor} {product}"

            if any(kw in combined for kw in keywords):
                relevant.append({
                    "cve_id": vuln.get("cveID"),
                    "vendor": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "name": vuln.get("vulnerabilityName"),
                    "description": vuln.get("shortDescription"),
                    "date_added": vuln.get("dateAdded"),
                    "due_date": vuln.get("dueDate"),
                    "required_action": vuln.get("requiredAction"),
                    "known_ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                    "sector_relevance": sector,
                    "source": "CISA KEV",
                })

        # Sort by date added (most recent first)
        relevant.sort(key=lambda x: x.get("date_added", ""), reverse=True)
        return relevant[:max_results]


# Singleton enricher instances
_mitre_enricher = MitreAttackEnricher()
_cisa_enricher = CisaKevEnricher()


def get_mitre_enricher() -> MitreAttackEnricher:
    return _mitre_enricher


def get_cisa_enricher() -> CisaKevEnricher:
    return _cisa_enricher
