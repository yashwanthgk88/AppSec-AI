# SecureDev AI — Threat Modeling Pipeline Technical Document

## Table of Contents
1. [Pipeline Overview](#pipeline-overview)
2. [Stage 1: Architecture Ingestion](#stage-1-architecture-ingestion)
3. [Stage 2: Intelligence Context Assembly](#stage-2-intelligence-context-assembly)
4. [Stage 3: STRIDE Threat Generation](#stage-3-stride-threat-generation)
5. [Stage 4: Attack Path, MITRE & Kill Chain Analysis](#stage-4-attack-path-mitre--kill-chain-analysis)
6. [Stage 5: Risk Quantification & Diagrams](#stage-5-risk-quantification--diagrams)
7. [How Threat Intel & SecReq Are Consumed](#how-threat-intel--securereq-are-consumed)
8. [Value Comparison: With vs Without Intelligence](#value-comparison-with-vs-without-intelligence)
9. [Recommended Workflow](#recommended-workflow)

---

## Pipeline Overview

The threat model is generated through a **5-stage pipeline**. Each stage builds on the previous one. Threat Intelligence and Security Requirements (SecReq) are injected at Stage 2 as context that shapes the AI's analysis throughout all subsequent stages.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    THREAT MODELING PIPELINE                         │
│                                                                     │
│  ┌──────────┐   ┌──────────────┐   ┌─────────┐   ┌──────────────┐ │
│  │ Stage 1  │──>│   Stage 2    │──>│ Stage 3 │──>│   Stage 4    │ │
│  │Arch Parse│   │Intel Assembly│   │ STRIDE  │   │Attack Paths  │ │
│  └──────────┘   └──────────────┘   └─────────┘   │MITRE Mapping │ │
│                       ▲                           │Kill Chain    │ │
│                       │                           └──────────────┘ │
│              ┌────────┼────────┐          │                        │
│              │        │        │          ▼                        │
│         ┌────┴──┐ ┌───┴───┐ ┌─┴────┐ ┌──────────────┐            │
│         │Sector │ │Client │ │SecReq│ │   Stage 5    │            │
│         │Threat │ │Threat │ │Abuse │ │FAIR Risk     │            │
│         │Intel  │ │Intel  │ │Cases │ │Eraser Diagrams│           │
│         └───────┘ └───────┘ └──────┘ └──────────────┘            │
└─────────────────────────────────────────────────────────────────────┘
```

**Code Entry Point:** `backend/main.py` → `_generate_threat_model_background()` (line 2423)
**Core Service:** `backend/services/threat_modeling.py` → `ThreatModelingService.generate_threat_model()` (line 2314)

---

## Stage 1: Architecture Ingestion

### Purpose
Parse the user-provided architecture (text description, uploaded diagrams, or Architecture Builder input) into a structured representation of components, data flows, and trust boundaries.

### How It Works
The architecture document is sent to the AI with a structured extraction prompt. The AI returns a JSON object containing:
- **Components** — each service, database, frontend, external integration
- **Data Flows** — how components communicate, encryption/auth status
- **Trust Boundaries** — where trust levels change
- **Component Properties** — internet-facing, handles sensitive data, trust level, technology stack

### AI Prompt Used

**File:** `backend/services/threat_modeling.py`, line 508
**Function:** `analyze_architecture_with_ai()`
**AI Parameters:** `max_tokens=4000, temperature=0.3`

```
Analyze this software architecture and extract a detailed threat model structure.

ARCHITECTURE DESCRIPTION:
{architecture_doc}

Please provide a comprehensive JSON response with the following structure:
{
    "system_overview": "Brief description of what the system does",
    "technology_stack": ["list", "of", "technologies"],
    "components": [
        {
            "id": "unique_id",
            "name": "Component Name",
            "type": "external|process|datastore",
            "technology": "specific technology (e.g., React, Node.js, PostgreSQL)",
            "category": "api|database|authentication|frontend|microservice|cloud|message_queue",
            "description": "What this component does",
            "data_handled": ["types of data this component handles"],
            "trust_level": "untrusted|semi-trusted|trusted|highly-trusted",
            "internet_facing": true/false,
            "handles_sensitive_data": true/false
        }
    ],
    "data_flows": [
        {
            "id": "flow_id",
            "from": "source_component_id",
            "to": "target_component_id",
            "data_type": "What data flows",
            "protocol": "HTTP/HTTPS/gRPC/SQL/etc",
            "encrypted": true/false,
            "authenticated": true/false,
            "sensitive": true/false
        }
    ],
    "trust_boundaries": [
        {
            "id": "boundary_id",
            "name": "Boundary Name",
            "description": "What this boundary separates",
            "components_inside": ["list of component_ids inside this boundary"],
            "boundary_type": "internet|dmz|internal|data"
        }
    ],
    "security_controls": ["list of mentioned security controls"],
    "risk_factors": ["identified risk factors from the architecture"]
}

Be thorough and extract all components, even if implied. Identify ALL data flows
between components. For each component, determine the most appropriate category
from: api, database, authentication, frontend, microservice, cloud, message_queue.
```

### Fallback
If AI is unavailable, a keyword-based parser (`_parse_architecture_basic()`) extracts components by matching terms like "api", "database", "auth", "frontend", "kafka", "redis", etc.

### Output
A parsed architecture dictionary used by all subsequent stages. For Apex Banking, this produced 14+ components across 6 trust boundaries.

---

## Stage 2: Intelligence Context Assembly

### Purpose
Before generating threats, gather all available intelligence to create a rich context document that accompanies every AI call. This is where **Threat Intel** and **SecReq** are consumed.

### How It Works

**File:** `backend/main.py`, lines 2449–2564

The system assembles context from **4 sources**:

### Source A: Sector Threat Intelligence

```python
# Line 2459-2462
sector_threats = get_sector_threats(industry)  # e.g., "banking"
if sector_threats:
    threat_intel_context = format_intel_for_prompt(sector_threats, max_entries=12)
```

- Pulls industry-specific threats based on the project's `industry_sector` field
- Uses built-in sector threat databases covering: banking, healthcare, retail, technology, government, etc.
- Each entry includes: title, severity, description, MITRE techniques, regulatory impact, recommended controls

**Format Function** (`backend/services/sector_threat_intel.py`, line 2345):
```python
def format_intel_for_prompt(threats, max_entries=15):
    # Produces text like:
    # ### FIN7 Targeting US Banking Platforms [CRITICAL]
    # Type: threat_actor
    # Description: FIN7 actively targets banking platforms...
    # MITRE ATT&CK: T1566.001, T1059.007, T1055
    # Regulatory: PCI-DSS, SOX
    #   - Network segmentation for payment systems
    #   - Application whitelisting
```

### Source B: Client-Uploaded Threat Intelligence

```python
# Lines 2466-2491
cursor.execute(
    "SELECT * FROM client_threat_intel WHERE project_id = ? AND active = 1 "
    "ORDER BY severity DESC LIMIT 15",
    (project_id,)
)
client_rows = [dict(r) for r in cursor.fetchall()]

if client_rows:
    client_context = format_intel_for_prompt(client_intel, max_entries=10)
    threat_intel_context += "\n\n=== CLIENT-SPECIFIC THREAT INTELLIGENCE ===\n"
    threat_intel_context += client_context
```

- Queries the `client_threat_intel` SQLite table for active entries for this project
- These are entries your team uploads via the Threat Intel page: threat actors, incidents, pentest findings, regulations, attack scenarios
- Each entry carries: MITRE techniques, severity, regulatory impact, recommended controls, tags
- Limited to top 15 entries sorted by severity

### Source C: SecReq Abuse Cases & Requirements

```python
# Lines 2498-2538
analyses = (
    db.query(SecurityAnalysis)
    .join(UserStory)
    .filter(UserStory.project_id == project_id)
    .order_by(SecurityAnalysis.id.desc())
    .all()
)

for analysis in analyses:
    # Abuse cases → become explicit threats
    if analysis.abuse_cases and isinstance(analysis.abuse_cases, list):
        for ac in analysis.abuse_cases[:5]:
            securereq_abuse_cases.append(ac)
            # Format: "- [Critical Impact] Social engineering bypass (Actor: Insider, STRIDE: Spoofing)"

    # Security requirements → used for coverage matrix
    if analysis.security_requirements and isinstance(analysis.security_requirements, list):
        for req in analysis.security_requirements[:5]:
            securereq_requirements.append(req)
            # Format: "- [Critical] [Cryptography] Implement HSM-backed signing for SWIFT messages"
```

- Queries `SecurityAnalysis` joined with `UserStory` for this project
- Only pulls from **analyzed** user stories (stories that have been run through the SecReq AI analysis)
- Abuse cases = "what can go wrong" (threat actor, impact, STRIDE category, description)
- Security requirements = "what must be true" (requirement text, priority, category)

### Source D: Existing Security Controls

```python
# Lines 2544-2561
controls = db.query(SecurityControl).filter(
    SecurityControl.project_id == project_id
).all()

for c in controls:
    ctrl_lines.append(
        f"- [{status.upper()}] {c.name} (type: {ctype}, effectiveness: {effectiveness:.0%}, "
        f"covers: {stride_cats})"
    )
threat_intel_context += "\n\n=== EXISTING SECURITY CONTROLS ===\n" + controls_context
```

- Pulls already-registered controls from the Controls tab
- Includes: control name, type (preventive/detective/corrective), status, effectiveness score, STRIDE coverage
- Tells the AI what mitigations are already in place

### Final Assembled Context

All four sources are concatenated into a single `system_context` string:

```
System Overview: Enterprise digital banking platform...
Technology Stack: Spring Boot, React, PostgreSQL, Kafka, Redis...

Components (14):
- API Gateway (api): Internet-facing, Handles sensitive data
- Auth Service (authentication): Internal, Handles sensitive data
- Fund Transfer Service (microservice): Internal, Handles sensitive data
...

Data Flows (20):
- API Gateway → Auth Service: Encrypted, Authenticated
- Transfer Service → SWIFT Network: Encrypted, Authenticated
...

=== THREAT INTELLIGENCE (BANKING SECTOR) ===

### FIN7 Targeting US Banking Platforms [CRITICAL]
Type: threat_actor
Description: FIN7 actively targets banking platforms using spear-phishing...
MITRE ATT&CK: T1566.001, T1059.007, T1055
  - Network segmentation for payment systems
  - Application whitelisting

### Magecart Skimming on Banking Payment Pages [CRITICAL]
Type: scenario
Description: JavaScript skimming attacks on payment form pages...
MITRE ATT&CK: T1189, T1059.007, T1041

=== CLIENT-SPECIFIC THREAT INTELLIGENCE ===

### 2024 SWIFT Credential Theft Attempt [CRITICAL]
Type: incident
Description: Insider attempted to exfiltrate SWIFT operator credentials...
MITRE ATT&CK: T1078, T1052.001, T1071.001
Regulatory: PCI-DSS Req 7.1, SOX Section 404

=== EXISTING SECURITY CONTROLS ===
- [IMPLEMENTED] WAF (type: preventive, effectiveness: 85%, covers: Tampering, Injection)
- [PLANNED] FIDO2 Hardware Keys (type: preventive, covers: Spoofing)

=== SECURITY REQUIREMENTS ANALYSIS ===
- [Critical Impact] Social engineering to bypass multi-level approvals (Actor: Insider, STRIDE: Spoofing)
  Insider with authorized access manipulates approval workflow to authorize fraudulent transfers
- [Critical] [Cryptography] Implement cryptographic signing of MT103 messages with HSM-backed keys
- [Critical] [Access Control] Enforce dynamic MFA for wire transfer approval actions
```

**This entire context document is passed to every AI call in Stages 3 and 4.**

---

## Stage 3: STRIDE Threat Generation

### Purpose
Generate comprehensive STRIDE threats for every component in the architecture, enriched with AI-powered analysis for the highest-risk threats.

### How It Works

**File:** `backend/services/threat_modeling.py`, line 949
**Function:** `generate_stride_analysis()`

This runs in **3 passes**:

### Pass 1: Template-Based Generation (all threats)

For each component × each STRIDE category, the system matches technology-specific threat templates from `TECHNOLOGY_THREATS`:

```python
for component in parsed_arch['components']:
    category = component['category']  # e.g., "api", "authentication", "database"
    tech_threats = self.TECHNOLOGY_THREATS.get(category, {})

    for stride_cat, threats in tech_threats.items():
        for threat_template in threats:
            # Calculate risk score
            base_score = {'critical': 9.5, 'high': 7.5, 'medium': 5.0, 'low': 2.5}[severity]

            # Adjust for component properties
            if component['internet_facing']:     base_score += 1.0
            if component['handles_sensitive_data']: base_score += 0.5
            if component['trust_level'] == 'untrusted': base_score += 0.5

            # Create threat with template description/mitigation
            threat_obj = {
                "component": comp_name,
                "category": stride_cat,
                "threat": threat_template['threat'],
                "severity": threat_template['severity'],
                "risk_score": round(min(10.0, base_score), 1),
                "cwe": threat_template['cwe'],
                "mitre": threat_template['mitre'],
                "description": self._generate_threat_description(threat_template, component),
                "mitigation": self._generate_mitigation(threat_template, component),
                "detection": self._generate_detection_guidance(threat_template),
                ...
            }
```

This produces the bulk of threats (500+ for a complex architecture) with template-based descriptions and mitigations. These are fast to generate and don't require AI API calls.

### Pass 2: AI Enrichment (top 15 critical/high threats)

The 15 highest-risk threats are sent to Claude/GPT **with the full intelligence context from Stage 2**.

```python
# Select top 15 by risk score
threats_to_enrich = sorted(threats_to_enrich, key=lambda x: x['threat_obj']['risk_score'], reverse=True)[:15]

for item in threats_to_enrich:
    enriched = self._enrich_threat_with_ai(
        item['threat_template'],
        item['component'],
        system_context  # <-- THIS CONTAINS ALL THREAT INTEL + SECUREREQ
    )
```

**AI Enrichment Prompt** (`_enrich_threat_with_ai()`, line 87):

```
You are a senior application security expert performing threat modeling.
Analyze this specific threat and provide detailed, contextual information.

SYSTEM CONTEXT:
{system_context}
<-- This is the full assembled context from Stage 2, including:
    - Architecture components and data flows
    - Sector threat intel (banking threats)
    - Client-uploaded threat intel (FIN7, Magecart, incidents)
    - SecReq abuse cases and requirements
    - Existing security controls

COMPONENT BEING ANALYZED:
- Name: {component_name}
- Type: {component_type}
- Category: {component_category}
- Technology: {technology}
- Internet Facing: {internet_facing}
- Handles Sensitive Data: {handles_sensitive_data}
- Trust Level: {trust_level}
- Data Handled: {data_handled}

THREAT TO ANALYZE:
- Threat Name: {threat_name}
- STRIDE Category: {stride_category}
- Severity: {severity}
- CWE: {cwe}
- MITRE Techniques: {mitre_techniques}

Provide a detailed JSON response with the following structure. Be SPECIFIC
to this component and system - do not give generic advice:
{
    "description": "A detailed 2-3 sentence description of how this specific
                    threat applies to this component in this system",
    "attack_vector": {
        "description": "Detailed explanation of how an attacker would exploit
                        this vulnerability in this specific component",
        "entry_points": ["List of specific entry points for this attack"],
        "techniques": ["Specific attack techniques that could be used"]
    },
    "business_impact": {
        "financial": "Specific financial impact if this threat is realized",
        "reputational": "Reputational damage assessment",
        "operational": "Operational impact on business",
        "compliance": "Regulatory and compliance implications"
    },
    "affected_assets": ["List of specific assets at risk"],
    "prerequisites": {
        "access_required": "What access level an attacker needs",
        "conditions": ["Conditions that must be true for this attack to succeed"]
    },
    "attack_complexity": {
        "level": "Low/Medium/High",
        "skill_level": "Basic/Intermediate/Advanced",
        "time_required": "Estimated time to execute",
        "description": "Why this complexity level"
    },
    "mitigation": "Specific, actionable mitigation recommendations for this component",
    "detection": "How to detect this attack in progress or after the fact"
}

Be specific and technical. Reference the actual component name and technology.
```

**AI Parameters:** `max_tokens=2000`

### Pass 3: SecReq Threat Injection

**Function:** `_inject_securereq_threats()`, line 772

Each analyzed abuse case from SecReq is injected as a dedicated STRIDE threat:

```python
for ac in abuse_cases:
    stride_cat = stride_key_map[ac['stride_category'].lower()]
    severity = _impact_to_severity(ac['impact'])
    risk_score = _likelihood_to_score(ac['likelihood'], severity)

    threat_obj = {
        "id": f"securereq_{ac_id}",
        "component": "System-wide",
        "category": stride_cat,
        "threat": ac['title'],
        "description": ac['description'],
        "severity": severity,
        "risk_score": risk_score,
        "source": "securereq",           # <-- Tagged for traceability
        "abuse_case_id": ac_id,
        "mitre_techniques": ac.get('mitre_techniques', []),
        "threat_actor": ac.get('actor', ''),
    }
    stride_analysis[stride_cat].append(threat_obj)
```

A **coverage matrix** is also built:
```python
coverage = {
    "requirements": [
        {
            "id": "SR-001",
            "requirement": "Implement HSM-backed signing for MT103 messages",
            "priority": "Critical",
            "category": "Cryptography",
            "covered_by_threats": ["threat_id_1", "threat_id_2"],
            "coverage_status": "covered" | "uncovered"
        }
    ],
    "summary": {
        "total_requirements": 5,
        "covered": 3,
        "uncovered": 2,
        "coverage_percentage": 60.0
    }
}
```

### Output
A complete STRIDE analysis dictionary with threats categorized under: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. For Apex Banking: **541 threats** (536 template + 5 SecReq-injected, with 15 AI-enriched).

---

## Stage 4: Attack Path, MITRE & Kill Chain Analysis

### 4A: Attack Path Generation

**File:** `backend/services/threat_modeling.py`, line 1928
**Function:** `generate_attack_paths()`

**How It Works:**
1. Identify **entry points** (internet-facing components) and **targets** (sensitive data stores)
2. Build an adjacency graph from data flows
3. Find all paths from entry points to targets using BFS (max depth 5)
4. Score each path based on threats along the route
5. Top 10 paths selected by risk score
6. Top 5 paths are AI-enriched with the **full system context (including threat intel)**

**Attack Path AI Prompt** (`_generate_attack_path_with_ai()`, line 186):

```
You are a senior penetration tester analyzing an attack path through a system.
Generate a detailed attack path analysis.

SYSTEM CONTEXT:
{system_context}
<-- Same full context including threat intel, SecReq, controls

ATTACK PATH:
Entry Point: {entry_point_name} ({entry_point_category})
Target: {target_name} ({target_category})
Path: Component A → Component B → Component C → Target DB

THREATS ALONG THIS PATH:
- Request Smuggling (critical) at API Gateway
- JWT Token Forgery (high) at Auth Service
- SQL Injection (critical) at Core Banking DB

Generate a detailed JSON response:
{
    "attack_scenario": "A compelling 3-4 sentence narrative describing how an
                        attacker would exploit this path, referencing specific
                        components and threats",
    "exploitation_steps": [
        {
            "step": 1,
            "phase": "Reconnaissance/Initial Access/Lateral Movement/
                      Privilege Escalation/Objective",
            "action": "Brief action description",
            "details": "Detailed explanation including tools and techniques"
        }
    ],
    "potential_impact": {
        "level": "Critical/High/Medium/Low",
        "description": "Overall impact description",
        "data_exposure": "What data could be exposed",
        "system_impact": "Impact on system availability/integrity",
        "business_impact": "Business consequences",
        "compliance_impact": "Regulatory implications"
    },
    "difficulty": {
        "level": "Low/Medium/High",
        "description": "Why this difficulty level",
        "required_skills": "Skills needed to execute",
        "time_estimate": "Estimated time to execute",
        "tools_needed": ["List of attacker tools"]
    },
    "detection_opportunities": [
        {
            "point": "Where in the attack chain this can be detected",
            "method": "How to detect it",
            "effectiveness": "High/Medium/Low"
        }
    ],
    "recommended_controls": [
        {
            "control": "Security control name",
            "implementation": "Specific implementation guidance",
            "priority": "Critical/High/Medium"
        }
    ]
}

Be specific to this system and path. Reference actual component names.
```

**AI Parameters:** `max_tokens=3000`

### 4B: MITRE ATT&CK Mapping

**Function:** `map_mitre_attack()` — Template-based, fast.

Maps each STRIDE threat's CWE and MITRE technique IDs to the full MITRE ATT&CK framework:
- Technique ID → Tactic → Description → Mitigation
- Aggregates techniques across all threats
- Groups by tactic (Initial Access, Execution, Persistence, etc.)

### 4C: Kill Chain Analysis

**Function:** `generate_kill_chain_analysis()`

Maps STRIDE threats to Cyber Kill Chain phases:
1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control
7. Actions on Objectives

### 4D: Attack Trees

**Function:** `generate_attack_trees()`

Hierarchical decomposition of high-risk goals showing AND/OR relationships between attack sub-goals.

---

## Stage 5: Risk Quantification & Diagrams

### 5A: FAIR Risk Quantification

**File:** `backend/services/threat_modeling.py`, line 2584
**Function:** `calculate_fair_risk()`

Uses the FAIR (Factor Analysis of Information Risk) model to calculate dollar-based loss estimates:

```python
# Parameters
organization_size = "medium"  # Multiplier: small=0.3, medium=1.0, large=2.5, enterprise=5.0
industry = "banking"          # Multiplier: finance=1.8, healthcare=1.5, technology=1.0
annual_revenue = 10000000
customer_count = 10000

# For each threat:
# 1. Calculate Loss Event Frequency (LEF) = Threat Event Frequency × Vulnerability
# 2. Calculate Loss Magnitude (LM) across 6 categories:
#    - Productivity, Response, Replacement, Fines, Reputation, Legal
# 3. Annualized Loss Expectancy (ALE) = LEF × LM
# 4. Apply industry and size multipliers
# 5. Generate confidence intervals (min, likely, max)
```

No AI calls — this is a pure calculation based on threat severities, component properties, and industry parameters.

### 5B: Eraser AI Diagrams

**Function:** `generate_eraser_diagrams()`, line 1752

Generates 3 professional diagrams via the Eraser.io API (requires `ERASER_API_KEY`):

1. **Architecture/Threat Model Diagram** — Components + top threats overlaid
2. **Kill Chain Diagram** — Visual kill chain with threats mapped to phases
3. **Data Flow Diagram** — Components, data flows, and trust boundaries

Attack path diagrams are generated on-demand via the `/generate-attack-diagram` endpoint.

### 5C: Mermaid DFDs

**Functions:** `generate_dfd()` and `generate_mermaid_dfd()`

Generates Level 0 (high-level) and Level 1 (detailed) Data Flow Diagrams as Mermaid syntax, rendered in the browser. These are always available as fallback when Eraser is not configured.

---

## How Threat Intel & SecReq Are Consumed

### Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        THREAT INTEL                              │
│                                                                  │
│  ┌─────────────┐     ┌──────────────┐     ┌──────────────┐     │
│  │Sector Intel │     │Client Upload │     │Live Feeds    │     │
│  │(built-in DB)│     │(your entries)│     │(CISA/NVD/    │     │
│  │             │     │             │     │ MISP) [*]    │     │
│  └──────┬──────┘     └──────┬──────┘     └──────────────┘     │
│         │                   │                                   │
│         ▼                   ▼                                   │
│  ┌──────────────────────────────────┐                          │
│  │   format_intel_for_prompt()      │                          │
│  │   → Structured text block        │                          │
│  └──────────────┬───────────────────┘                          │
│                 │                                               │
│                 ▼                                               │
│  ┌──────────────────────────────────┐                          │
│  │      threat_intel_context        │ ◄── Combined text        │
│  │  "=== THREAT INTELLIGENCE ==="   │     block with all       │
│  │  "=== CLIENT-SPECIFIC ==="       │     intel sources        │
│  │  "=== EXISTING CONTROLS ==="     │                          │
│  └──────────────┬───────────────────┘                          │
└─────────────────┼──────────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                         SECUREREQ                                │
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐                          │
│  │ User Stories │────>│  AI Analysis │                          │
│  │ (20 stories) │     │ (per story)  │                          │
│  └──────────────┘     └──────┬───────┘                          │
│                              │                                   │
│                    ┌─────────┴─────────┐                        │
│                    ▼                   ▼                         │
│           ┌──────────────┐   ┌──────────────┐                  │
│           │ Abuse Cases  │   │ Security     │                  │
│           │ (threats)    │   │ Requirements │                  │
│           └──────┬───────┘   └──────┬───────┘                  │
│                  │                  │                            │
│                  ▼                  ▼                            │
│  ┌──────────────────────────────────────┐                      │
│  │      securereq_context               │                      │
│  │  "=== SECURITY REQUIREMENTS ==="     │                      │
│  │  + securereq_abuse_cases (list)      │                      │
│  │  + securereq_requirements (list)     │                      │
│  └──────────────┬───────────────────────┘                      │
└─────────────────┼──────────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                    SYSTEM CONTEXT                                 │
│  (architecture + threat intel + SecReq + controls)               │
│                                                                  │
│  Used by:                                                        │
│  ├── _enrich_threat_with_ai()     → 15 critical/high threats    │
│  ├── _generate_attack_path_with_ai() → Top 5 attack paths      │
│  └── _inject_securereq_threats()  → Direct threat injection     │
│                                      + Coverage matrix           │
└──────────────────────────────────────────────────────────────────┘

[*] Live feeds (CISA KEV, NVD, MISP) are NOT currently ingested
    into threat modeling. Only sector + client intel are used.
```

### Where Each Source Impacts Results

| Source | What It Influences | How |
|--------|-------------------|-----|
| **Sector Intel** | AI-enriched threat descriptions, mitigations, business impact | Passed as context in AI prompt — AI references industry-specific attack patterns |
| **Client Intel** | AI-enriched threat descriptions; awareness of your specific threat actors | AI sees your FIN7 entry and generates threats mentioning FIN7 TTPs against your components |
| **SecReq Abuse Cases** | Direct STRIDE threats + coverage matrix | Each abuse case becomes a tagged threat (`source: "securereq"`) with traceability |
| **SecReq Requirements** | Coverage matrix showing gaps | Requirements compared against generated threats to show % coverage |
| **Existing Controls** | AI-enriched mitigations | AI knows what you already have and recommends what's missing instead of duplicating |

---

## Value Comparison: With vs Without Intelligence

| Aspect | Without Intel/SecReq | With Intel/SecReq |
|--------|---------------------|-------------------|
| **Descriptions** | "Potential SQL Injection vulnerability in Database" | "SQL Injection in Core Banking Oracle DB could enable unauthorized SWIFT transaction modification, similar to FIN7 campaign techniques (T1059.007)" |
| **Mitigations** | "Use parameterized queries" | "Implement parameterized queries with Oracle-specific bind variables. Given existing WAF (85% effective), add SQL injection rules specifically for MT103 message parsing endpoints" |
| **Business Impact** | "Financial impact possible" | "$500K-$10M based on banking industry breach data. Regulatory exposure under PCI-DSS Req 6.5.1 and SOX Section 404" |
| **Threat Actors** | Not considered | "FIN7 actively targets banking platforms using T1566.001 spear-phishing to gain initial access to payment processing systems" |
| **Coverage** | No traceability | "60% of security requirements covered. 2 critical requirements uncovered: HSM-backed signing, Dynamic MFA for approvals" |
| **Controls** | Generic recommendations | Recommendations that account for existing controls and recommend what's missing |

---

## Recommended Workflow

For maximum value from the threat modeling pipeline:

```
Step 1: SecureReq
  └── Add user stories (manual or import from Jira)
  └── Analyze each story → generates abuse cases + security requirements
  └── These feed directly into the threat model as explicit threats + coverage matrix

Step 2: Threat Intel
  └── Upload client-specific intel:
      - Known threat actors targeting your organization
      - Past incidents and pentest findings
      - Regulatory requirements (BSA/AML, PCI-DSS, SOX)
      - Industry-specific attack scenarios
  └── These inform the AI's threat descriptions, mitigations, and impact assessments

Step 3: Architecture
  └── Define system architecture (text, diagram upload, or Architecture Builder)
  └── Include: components, data flows, trust boundaries, technology stack

Step 4: Generate Threat Model
  └── The pipeline automatically ingests all of the above
  └── Full mode: AI enrichment for top 15 threats + top 5 attack paths
  └── Quick mode: Template-only, no AI calls (faster but less contextual)

Step 5: Review & Triage
  └── 541 threats with severity/component/STRIDE/status filters + pagination
  └── AI-enriched threats have banking-specific context
  └── SecReq-derived threats traceable to user stories
  └── Coverage matrix shows requirement gaps

Step 6: Register Controls
  └── Add security controls in the Controls tab (now inside Threat Model page)
  └── Link controls to threats
  └── Track coverage and effectiveness

Step 7: Iterate
  └── When architecture or intel changes, regenerate the threat model
  └── New model accounts for updated context
  └── Incremental mode available to preserve existing threat status/notes
```

---

## Appendix: Key Files Reference

| File | Purpose |
|------|---------|
| `backend/main.py` (line 2423) | `_generate_threat_model_background()` — Orchestrates the full pipeline, assembles intel context |
| `backend/services/threat_modeling.py` (line 2314) | `generate_threat_model()` — Core generation logic |
| `backend/services/threat_modeling.py` (line 499) | `analyze_architecture_with_ai()` — Stage 1 architecture parsing |
| `backend/services/threat_modeling.py` (line 87) | `_enrich_threat_with_ai()` — Stage 3 AI enrichment |
| `backend/services/threat_modeling.py` (line 949) | `generate_stride_analysis()` — Stage 3 STRIDE generation |
| `backend/services/threat_modeling.py` (line 772) | `_inject_securereq_threats()` — Stage 3 SecReq injection |
| `backend/services/threat_modeling.py` (line 1928) | `generate_attack_paths()` — Stage 4 attack paths |
| `backend/services/threat_modeling.py` (line 175) | `_generate_attack_path_with_ai()` — Stage 4 AI-enriched paths |
| `backend/services/threat_modeling.py` (line 2584) | `calculate_fair_risk()` — Stage 5 FAIR quantification |
| `backend/services/threat_modeling.py` (line 1752) | `generate_eraser_diagrams()` — Stage 5 Eraser diagrams |
| `backend/services/sector_threat_intel.py` (line 2345) | `format_intel_for_prompt()` — Formats intel for AI prompts |
| `backend/routers/threat_intel.py` | Client threat intel CRUD + feed management |
| `backend/routers/securereq.py` | User stories + security analysis management |
| `frontend/src/pages/ThreatModelPage.tsx` | Threat model UI with all tabs |
