"""
Sector-Specific Threat Intelligence Library

Built-in threat catalogs for Banking/Finance and Healthcare sectors.
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
# Sector Registry
# ---------------------------------------------------------------------------
SECTOR_INTEL: Dict[str, List[Dict[str, Any]]] = {
    "banking": BANKING_THREATS,
    "finance": BANKING_THREATS,  # alias
    "healthcare": HEALTHCARE_THREATS,
}

SUPPORTED_SECTORS = ["banking", "finance", "healthcare"]


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
        "api": ["API", "authentication", "ATO", "scraping", "FHIR", "HL7"],
        "database": ["PHI", "patient-data", "EHR", "data-integrity", "encryption"],
        "authentication": ["authentication", "ATO", "credential-stuffing", "MFA", "patient-portal"],
        "frontend": ["magecart", "skimming", "payment-page", "XSS"],
        "cloud": ["ransomware", "backup", "encryption"],
        "microservice": ["SWIFT", "payments", "interoperability"],
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
