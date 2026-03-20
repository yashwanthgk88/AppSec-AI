"""
Sector-Specific Threat Intelligence Library

Built-in threat catalogs for Banking/Finance and Healthcare sectors.
Each entry follows the same schema as client-uploaded threat intel,
so they merge seamlessly when fed into threat modeling.
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
#     "mitre_techniques": [],  # ATT&CK IDs
#     "regulatory_impact": [], # Affected regulations
#     "recommended_controls": [],
#     "tags": [],
#     "source": str,           # "sector_library" | "client_upload"
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
        "mitre_techniques": ["T1078", "T1110.004"],
        "regulatory_impact": ["PCI-DSS 8.3", "RBI Digital Lending Guidelines", "FFIEC Authentication"],
        "recommended_controls": [
            "Implement adaptive MFA for all customer-facing logins",
            "Deploy credential breach detection (check against HaveIBeenPwned-style feeds)",
            "Rate-limit login attempts per IP and per account",
            "Implement device fingerprinting and behavioral biometrics",
        ],
        "tags": ["authentication", "fraud", "ATO", "credential-stuffing"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "Transaction Amount Manipulation",
        "description": "Attacker intercepts or manipulates transaction parameters (amount, recipient, currency) between the client and the server. Common in mobile banking where client-side validation can be bypassed.",
        "severity": "critical",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1565.001", "T1557"],
        "regulatory_impact": ["PCI-DSS 6.5", "SOX Section 302"],
        "recommended_controls": [
            "Server-side validation of all transaction parameters",
            "Transaction signing with HMAC or digital signatures",
            "Real-time fraud scoring on transaction amounts vs historical patterns",
            "Out-of-band confirmation for high-value transactions",
        ],
        "tags": ["transactions", "fraud", "tampering", "payment"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "SWIFT / Payment Network Abuse",
        "description": "Insider or compromised admin initiates unauthorized SWIFT/NEFT/RTGS transactions by abusing privileged access to payment systems. Modeled after Bangladesh Bank heist (2016).",
        "severity": "critical",
        "threat_category": "Elevation of Privilege",
        "mitre_techniques": ["T1078.004", "T1098", "T1537"],
        "regulatory_impact": ["SWIFT CSP", "PCI-DSS 7.1", "SOX Section 404"],
        "recommended_controls": [
            "Dual-authorization (maker-checker) for all payment instructions",
            "Segregation of duties between payment creation and approval",
            "Real-time monitoring of payment system admin actions",
            "Implement SWIFT Alliance Lite2 with mandatory two-factor",
        ],
        "tags": ["SWIFT", "payments", "insider-threat", "wire-transfer"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "API-Based Price/Rate Scraping",
        "description": "Competitors or data brokers scrape exchange rates, loan rates, or product pricing via banking APIs at high frequency to gain market intelligence or front-run pricing decisions.",
        "severity": "medium",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1530", "T1213"],
        "regulatory_impact": ["Market Abuse Regulation", "Competitive Intelligence Laws"],
        "recommended_controls": [
            "API rate limiting per consumer with tiered thresholds",
            "Behavioral analytics to detect scraping patterns",
            "Watermarking or jittering sensitive rate data",
            "Require API key registration with business justification",
        ],
        "tags": ["API", "scraping", "competitive-intel", "rates"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "Card Skimming / Magecart Attack",
        "description": "Malicious JavaScript injected into payment pages to capture card details in real-time. Targets e-commerce checkout flows and online banking bill payment pages.",
        "severity": "critical",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1185", "T1059.007"],
        "regulatory_impact": ["PCI-DSS 6.4.3", "PCI-DSS 11.6.1"],
        "recommended_controls": [
            "Implement Content Security Policy (CSP) headers",
            "Subresource Integrity (SRI) for all external scripts",
            "Real-time JavaScript monitoring for DOM changes on payment pages",
            "Tokenization — never handle raw card data server-side",
        ],
        "tags": ["card-fraud", "magecart", "skimming", "payment-page"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "Loan Application Fraud",
        "description": "Synthetic identity or document forgery used to submit fraudulent loan applications. Attackers use AI-generated documents or manipulated income proofs to bypass KYC checks.",
        "severity": "high",
        "threat_category": "Spoofing",
        "mitre_techniques": ["T1589", "T1598"],
        "regulatory_impact": ["AML/KYC Regulations", "RBI Fair Practices Code", "FCRA"],
        "recommended_controls": [
            "AI-based document verification (detect forged documents)",
            "Cross-reference income claims with credit bureau data",
            "Device fingerprinting to detect repeat fraud from same device",
            "Implement velocity checks on applications per identity/IP/device",
        ],
        "tags": ["fraud", "KYC", "lending", "synthetic-identity"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "Insider Trading via API Access",
        "description": "Employee with API access to trading systems or customer order flow leaks material non-public information or front-runs trades using privileged access.",
        "severity": "critical",
        "threat_category": "Repudiation",
        "mitre_techniques": ["T1078", "T1567"],
        "regulatory_impact": ["SEBI Insider Trading Regulations", "SEC Rule 10b-5", "SOX"],
        "recommended_controls": [
            "Comprehensive audit logging of all API access with user attribution",
            "Behavioral analytics for unusual query patterns by employees",
            "Chinese wall enforcement between research and trading desks",
            "Mandatory trade pre-clearance for all employees with system access",
        ],
        "tags": ["insider-threat", "trading", "market-abuse", "audit"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "ATM Jackpotting / Logical Attack",
        "description": "Physical or remote attack on ATM infrastructure to force cash dispensing. Includes black box attacks (connecting external device to ATM) and malware-based attacks (Ploutus, Tyupkin).",
        "severity": "high",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1200", "T1059"],
        "regulatory_impact": ["PCI-PIN", "ATM Security Best Practices"],
        "recommended_controls": [
            "Hard disk encryption on all ATM endpoints",
            "Application whitelisting to prevent unauthorized binaries",
            "Physical tamper detection sensors",
            "Network segmentation isolating ATM network from corporate",
        ],
        "tags": ["ATM", "physical", "malware", "cash-out"],
        "source": "sector_library",
    },

    # --- Threat Actors ---
    {
        "intel_type": "threat_actor",
        "title": "Organized Cybercrime Syndicates (FIN Groups)",
        "description": "Financially motivated groups like FIN7, FIN8, Carbanak that specifically target banking and payment systems. Use sophisticated phishing, custom malware, and insider recruitment.",
        "severity": "critical",
        "threat_category": "Spoofing",
        "mitre_techniques": ["T1566", "T1204", "T1071"],
        "regulatory_impact": [],
        "recommended_controls": [
            "Advanced email security with sandboxing",
            "Endpoint Detection and Response (EDR) on all endpoints",
            "Threat intelligence feeds specific to financial sector",
        ],
        "tags": ["FIN7", "Carbanak", "organized-crime", "APT"],
        "source": "sector_library",
    },
    {
        "intel_type": "threat_actor",
        "title": "Nation-State Actors (Lazarus Group)",
        "description": "North Korean state-sponsored group targeting SWIFT systems and cryptocurrency exchanges. Responsible for Bangladesh Bank heist ($81M) and multiple exchange thefts.",
        "severity": "critical",
        "threat_category": "Elevation of Privilege",
        "mitre_techniques": ["T1566.001", "T1059.001", "T1537"],
        "regulatory_impact": ["OFAC Sanctions Compliance", "SWIFT CSP"],
        "recommended_controls": [
            "SWIFT Customer Security Programme (CSP) compliance",
            "Network segmentation for payment systems",
            "24/7 SOC monitoring with financial threat intelligence",
        ],
        "tags": ["Lazarus", "nation-state", "SWIFT", "cryptocurrency"],
        "source": "sector_library",
    },

    # --- Regulatory Requirements ---
    {
        "intel_type": "regulation",
        "title": "PCI-DSS v4.0 Compliance",
        "description": "Payment Card Industry Data Security Standard requires specific controls for handling cardholder data: encryption, access control, monitoring, and regular testing.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": [],
        "regulatory_impact": ["PCI-DSS v4.0"],
        "recommended_controls": [
            "Encrypt cardholder data at rest (AES-256) and in transit (TLS 1.2+)",
            "Implement network segmentation for cardholder data environment",
            "Quarterly vulnerability scans and annual penetration tests",
            "Client-side script integrity monitoring (Req 6.4.3)",
            "Automated log review and alerting (Req 10.4.1)",
        ],
        "tags": ["PCI-DSS", "compliance", "cards", "encryption"],
        "source": "sector_library",
    },
    {
        "intel_type": "regulation",
        "title": "SOX IT Controls",
        "description": "Sarbanes-Oxley Act requires internal controls over financial reporting systems. IT controls must ensure integrity, access control, and audit trails for financial data.",
        "severity": "high",
        "threat_category": "Repudiation",
        "mitre_techniques": [],
        "regulatory_impact": ["SOX Section 302", "SOX Section 404"],
        "recommended_controls": [
            "Change management process for financial application code",
            "Segregation of duties between development and production",
            "Comprehensive audit logging with tamper-evident storage",
            "Regular access reviews for financial systems",
        ],
        "tags": ["SOX", "compliance", "audit", "financial-reporting"],
        "source": "sector_library",
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
        "mitre_techniques": ["T1530", "T1078", "T1213"],
        "regulatory_impact": ["HIPAA Privacy Rule (45 CFR 164.502)", "HIPAA Security Rule", "HITECH Breach Notification"],
        "recommended_controls": [
            "Role-based access control with minimum necessary principle",
            "Break-the-glass access with mandatory justification and audit",
            "Encryption of PHI at rest (AES-256) and in transit (TLS 1.2+)",
            "Automated monitoring for bulk record access anomalies",
        ],
        "tags": ["EHR", "PHI", "HIPAA", "patient-data"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "Ransomware Attack on Hospital Systems",
        "description": "Ransomware encrypts critical hospital systems including EHR, lab systems, imaging (PACS), and pharmacy systems. Directly impacts patient care and can be life-threatening. Healthcare is the #1 ransomware target sector.",
        "severity": "critical",
        "threat_category": "Denial of Service",
        "mitre_techniques": ["T1486", "T1490", "T1566"],
        "regulatory_impact": ["HIPAA Security Rule", "FDA Medical Device Guidance", "CMS Conditions of Participation"],
        "recommended_controls": [
            "Offline, immutable backups tested quarterly for restoration",
            "Network segmentation isolating clinical from administrative systems",
            "EDR on all endpoints with 24/7 monitoring",
            "Clinical system downtime procedures documented and drilled",
            "Email gateway with advanced threat protection",
        ],
        "tags": ["ransomware", "availability", "patient-safety", "backup"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "Medical Device Exploitation",
        "description": "Connected medical devices (infusion pumps, MRI machines, patient monitors) running outdated firmware exploited to pivot into hospital network or directly manipulate device behavior.",
        "severity": "critical",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1200", "T1495", "T1210"],
        "regulatory_impact": ["FDA Premarket Cybersecurity Guidance", "IEC 62443", "HIPAA Security Rule"],
        "recommended_controls": [
            "Medical device inventory with firmware version tracking",
            "Network micro-segmentation for IoMT devices",
            "Vulnerability management program specific to medical devices",
            "Manufacturer disclosure agreements for security patches",
        ],
        "tags": ["IoMT", "medical-device", "firmware", "patient-safety"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "Prescription Fraud / Drug Diversion",
        "description": "Insider (clinician or staff) manipulates e-prescribing systems to create fraudulent prescriptions for controlled substances. Can also involve modifying dispensing records to cover diversion.",
        "severity": "high",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1078", "T1565.001"],
        "regulatory_impact": ["DEA EPCS Requirements", "State Prescription Monitoring Programs", "21 CFR Part 1311"],
        "recommended_controls": [
            "Two-factor authentication for all controlled substance prescriptions",
            "Audit logging with anomaly detection on prescribing patterns",
            "Cross-reference prescriptions against PDMP databases",
            "Segregation of duties between prescribing and dispensing",
        ],
        "tags": ["prescription", "controlled-substance", "insider-threat", "diversion"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "Insurance Claims Manipulation",
        "description": "Upcoding, phantom billing, or unbundling of medical claims to defraud insurance providers. Can be perpetrated by insiders modifying claims data before submission.",
        "severity": "high",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1565.001", "T1078"],
        "regulatory_impact": ["False Claims Act", "Anti-Kickback Statute", "CMS Fraud Prevention"],
        "recommended_controls": [
            "Claims anomaly detection using ML on billing patterns",
            "Segregation of duties between clinical documentation and billing",
            "Regular audits comparing clinical records to submitted claims",
            "Whistleblower hotline and anti-fraud training",
        ],
        "tags": ["billing-fraud", "claims", "upcoding", "insurance"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "Patient Portal Account Takeover",
        "description": "Attackers compromise patient portal accounts to access PHI, medical records, and insurance information. Used for identity theft, insurance fraud, or blackmail of patients with sensitive conditions.",
        "severity": "high",
        "threat_category": "Spoofing",
        "mitre_techniques": ["T1078", "T1110"],
        "regulatory_impact": ["HIPAA Security Rule", "HITECH", "State Privacy Laws"],
        "recommended_controls": [
            "MFA for patient portal access",
            "Account lockout after failed attempts with CAPTCHA",
            "Notification to patient on login from new device/location",
            "Session timeout for inactive sessions (15 min max)",
        ],
        "tags": ["patient-portal", "ATO", "identity-theft", "PHI"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "HL7/FHIR API Data Exposure",
        "description": "Healthcare interoperability APIs (HL7 FHIR, SMART on FHIR) misconfigured to expose patient data without proper authorization. Third-party app access to FHIR endpoints may exceed approved scopes.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1530", "T1213"],
        "regulatory_impact": ["21st Century Cures Act", "ONC Information Blocking Rule", "HIPAA Minimum Necessary"],
        "recommended_controls": [
            "OAuth 2.0 with SMART on FHIR scopes for all API access",
            "API gateway with request/response filtering",
            "Third-party app security assessment before granting access",
            "Audit logging of all FHIR resource access with patient context",
        ],
        "tags": ["FHIR", "HL7", "interoperability", "API", "third-party"],
        "source": "sector_library",
    },
    {
        "intel_type": "scenario",
        "title": "Clinical Data Integrity Attack",
        "description": "Manipulation of lab results, vital signs, or medication records in EHR system. Could lead to incorrect treatment decisions and direct patient harm. Extremely difficult to detect if audit logs are also compromised.",
        "severity": "critical",
        "threat_category": "Tampering",
        "mitre_techniques": ["T1565.001", "T1070"],
        "regulatory_impact": ["HIPAA Security Rule", "Joint Commission Standards", "FDA CFR Part 11"],
        "recommended_controls": [
            "Immutable audit logs stored in separate system (WORM storage)",
            "Digital signatures on clinical data modifications",
            "Automated alerts for modifications to finalized results",
            "Regular integrity checks comparing source system data with EHR",
        ],
        "tags": ["data-integrity", "patient-safety", "EHR", "lab-results"],
        "source": "sector_library",
    },

    # --- Threat Actors ---
    {
        "intel_type": "threat_actor",
        "title": "Ransomware Groups Targeting Healthcare",
        "description": "Groups like LockBit, BlackCat/ALPHV, Royal, and Hive specifically target healthcare due to urgency of operations and willingness to pay. Average healthcare ransomware payment exceeds $1.5M.",
        "severity": "critical",
        "threat_category": "Denial of Service",
        "mitre_techniques": ["T1486", "T1566", "T1059"],
        "regulatory_impact": ["HIPAA Breach Notification", "State AG Notification"],
        "recommended_controls": [
            "Healthcare-specific threat intelligence feeds",
            "Incident response plan with clinical downtime procedures",
            "Cyber insurance with ransomware coverage",
        ],
        "tags": ["ransomware", "LockBit", "ALPHV", "organized-crime"],
        "source": "sector_library",
    },
    {
        "intel_type": "threat_actor",
        "title": "Insider Threats — Clinical Staff",
        "description": "Clinical staff (nurses, physicians, admin) accessing patient records beyond clinical need. Motivations include curiosity (celebrity patients), personal vendettas, or selling PHI on dark web.",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": ["T1078", "T1530"],
        "regulatory_impact": ["HIPAA Privacy Rule", "State Medical Board Regulations"],
        "recommended_controls": [
            "Behavioral analytics on EHR access patterns",
            "Automated alerts for VIP/celebrity patient record access",
            "Regular access audits comparing job role to records accessed",
            "Mandatory HIPAA training with insider threat awareness",
        ],
        "tags": ["insider-threat", "snooping", "PHI", "clinical-staff"],
        "source": "sector_library",
    },

    # --- Regulatory Requirements ---
    {
        "intel_type": "regulation",
        "title": "HIPAA Security Rule Compliance",
        "description": "Health Insurance Portability and Accountability Act requires administrative, physical, and technical safeguards for electronic PHI (ePHI).",
        "severity": "high",
        "threat_category": "Information Disclosure",
        "mitre_techniques": [],
        "regulatory_impact": ["HIPAA Security Rule (45 CFR 164.302-318)"],
        "recommended_controls": [
            "Risk assessment conducted annually (§164.308(a)(1))",
            "Access controls with unique user identification (§164.312(a))",
            "Audit controls for ePHI access (§164.312(b))",
            "Transmission security — encryption in transit (§164.312(e))",
            "Integrity controls — mechanism to authenticate ePHI (§164.312(c))",
            "Contingency plan with data backup and disaster recovery (§164.308(a)(7))",
        ],
        "tags": ["HIPAA", "compliance", "ePHI", "safeguards"],
        "source": "sector_library",
    },
    {
        "intel_type": "regulation",
        "title": "HITECH Breach Notification Requirements",
        "description": "HITECH Act requires notification to affected individuals, HHS, and media (if >500 records) within 60 days of discovering a PHI breach. Penalties range from $100 to $1.9M per violation.",
        "severity": "high",
        "threat_category": "Repudiation",
        "mitre_techniques": [],
        "regulatory_impact": ["HITECH Act", "HHS Breach Notification Rule"],
        "recommended_controls": [
            "Breach detection capabilities with <24hr detection SLA",
            "Incident response plan with breach notification workflow",
            "PHI inventory to quickly assess breach scope",
            "Encryption as safe harbor (encrypted PHI breach = no notification required)",
        ],
        "tags": ["HITECH", "breach-notification", "compliance", "penalties"],
        "source": "sector_library",
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

    return "\n".join(lines)
