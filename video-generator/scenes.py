"""
5-MINUTE demo with rapid page navigation.
Each scene navigates to MANY pages — no idle scrolling on a single page.
"""

from config import (
    APP_BASE_URL, DEMO_EMAIL, DEMO_PASSWORD, DEMO_PROJECT_ID,
    DEFAULT_PAUSE, LONG_PAUSE, SHORT_PAUSE
)

P = 3   # 3s standard pause
S = 2   # 2s short pause
L = 5   # 5s long pause (page load + read)


def get_scenes():
    pid = DEMO_PROJECT_ID
    base = APP_BASE_URL

    return [
        # ── SCENE 1: Login → Dashboard → Project Overview (0:00 - 1:10) ──
        {
            "id": "01_opening_dashboard",
            "title": "Opening + Dashboard BI",
            "voiceover": (
                "Every 39 seconds, a cyberattack targets a software application "
                "somewhere in the world. Yet most security vulnerabilities are "
                "introduced during development, long before they ever reach production. "
                "Meet Secure Dev AI. The intelligent application security platform "
                "that shifts security left across your entire software development lifecycle. "
                "From the moment you log in, the dashboard delivers full business intelligence. "
                "Four key performance indicators track total vulnerabilities with critical "
                "and high severity breakdowns, your false positive rate, remediation velocity "
                "in fixes per day, and average time to fix. "
                "Interactive trend charts show severity patterns over 7, 30, or 90 day windows, "
                "with stacked area charts, severity distribution pie charts, status tracking, "
                "and scan activity timelines. "
                "The Threat Intelligence widget surfaces actively exploited CVEs from CISA KEV, "
                "critical vulnerabilities from NVD, tracked threat actors, ransomware families, "
                "and exploit kits. When scan findings correlate with active threats, a pulsing "
                "high-risk alert flags immediate attention."
            ),
            "actions": [
                # Login
                {"type": "goto", "url": f"{base}/login", "wait": S},
                {"type": "fill", "selector": "input[name='username'], input[type='text'], input[type='email']", "value": DEMO_EMAIL, "wait": 1},
                {"type": "fill", "selector": "input[type='password'], input[name='password']", "value": DEMO_PASSWORD, "wait": 1},
                {"type": "click", "selector": "button[type='submit']", "wait": L},
                # Dashboard - KPI cards
                {"type": "scroll", "y": 0, "wait": P},
                # Dashboard - trend charts
                {"type": "scroll", "y": 300, "wait": P},
                # Dashboard - severity distribution
                {"type": "scroll", "y": 550, "wait": P},
                # Dashboard - threat intel widget
                {"type": "scroll", "y": 800, "wait": P},
                # Dashboard - project table
                {"type": "scroll", "y": 1100, "wait": P},
                # Dashboard - bottom
                {"type": "scroll", "y": 1400, "wait": P},
                # Back to top
                {"type": "scroll", "y": 0, "wait": S},
                # Navigate to project list
                {"type": "goto", "url": f"{base}/projects", "wait": P},
                {"type": "scroll", "y": 300, "wait": P},
                # Navigate to the demo project
                {"type": "goto", "url": f"{base}/projects/{pid}", "wait": L},
                {"type": "scroll", "y": 300, "wait": P},
                {"type": "scroll", "y": 600, "wait": P},
            ],
        },

        # ── SCENE 2: Threat Model pages (1:10 - 2:30) ──
        {
            "id": "02_threat_model_bi",
            "title": "Threat Modeling, BI & Correlation",
            "voiceover": (
                "Create a project, define your technology stack, and describe your architecture. "
                "Secure Dev AI generates Data Flow Diagrams at Level 0 and Level 1, validates "
                "trust boundaries, and versions every architecture change with diff comparison. "
                "The AI engine performs STRIDE-based threat modeling, identifying Spoofing, "
                "Tampering, Repudiation, Information Disclosure, Denial of Service, and "
                "Elevation of Privilege threats across every component. "
                "Here is where business intelligence becomes critical. The threat matrix "
                "view displays a heat map of components versus STRIDE categories with "
                "severity color coding, available in full-screen for executive presentations. "
                "Each threat maps to MITRE ATT&CK Enterprise v15 with sub-technique support. "
                "Attack path analysis visualizes multi-hop chains showing how an attacker "
                "could move laterally through your system. "
                "Critically, threat model threats are directly correlated with SAST and SCA "
                "scan findings. When a STRIDE threat identifies an injection risk on a component, "
                "and SAST finds SQL injection in that same code path, the platform links them "
                "together, showing which code-level vulnerabilities validate which architectural "
                "threats. SCA findings map vulnerable dependencies to the threat model's "
                "data flow components, so you see which supply chain risks affect which "
                "trust boundaries. "
                "Threat lifecycle tracking monitors each threat through new, existing, modified, "
                "and resolved states, with version diffing showing exactly how your threat "
                "landscape evolved between architecture changes."
            ),
            "actions": [
                # Threat model page
                {"type": "goto", "url": f"{base}/projects/{pid}/threat-model", "wait": L},
                {"type": "scroll", "y": 0, "wait": P},
                # DFD section
                {"type": "scroll", "y": 300, "wait": P},
                # STRIDE threats
                {"type": "scroll", "y": 600, "wait": P},
                # Threat details / MITRE mapping
                {"type": "scroll", "y": 900, "wait": P},
                # Attack paths
                {"type": "scroll", "y": 1200, "wait": P},
                # More threat details
                {"type": "scroll", "y": 1500, "wait": P},
                # Back to top for matrix view
                {"type": "scroll", "y": 0, "wait": P},
                # Scroll through again for correlation section
                {"type": "scroll", "y": 400, "wait": P},
                {"type": "scroll", "y": 800, "wait": P},
                {"type": "scroll", "y": 1200, "wait": P},
                {"type": "scroll", "y": 1600, "wait": P},
                {"type": "scroll", "y": 2000, "wait": P},
                # Back to top
                {"type": "scroll", "y": 0, "wait": S},
                # Navigate to vulnerabilities to show correlation
                {"type": "goto", "url": f"{base}/projects/{pid}/vulnerabilities", "wait": L},
                {"type": "scroll", "y": 300, "wait": P},
                {"type": "scroll", "y": 600, "wait": P},
            ],
        },

        # ── SCENE 3: Scanning + GitHub Monitor + Insider Threats (2:30 - 3:30) ──
        {
            "id": "03_scanning_insider",
            "title": "Scanning & Insider Threat Intelligence",
            "voiceover": (
                "Three layers of scanning run simultaneously. SAST detects SQL injection, "
                "XSS, command injection, and more across 8 languages with 68 OWASP rules, "
                "CWE mapping, and CVSS scoring. The taint analysis engine traces data from "
                "source to sink, and reachability analysis confirms exploitability. "
                "SCA scans dependencies against NVD and OSV, mapping CVEs like Log4Shell "
                "with transitive dependency chains and license compliance. "
                "Secrets detection covers 50-plus categories with Shannon entropy analysis. "
                "GitHub commit monitoring delivers deep insider threat intelligence. Every "
                "push is analyzed against 25-plus rules: sensitive file changes, binary "
                "injection, force pushes, off-hours activity, author mismatches, dependency "
                "typosquatting, and CI/CD pipeline tampering. "
                "The insider threat engine classifies threats as intentional, suspicious, or "
                "negligent, with confidence scoring, intent analysis, and recommended actions. "
                "Developer profiling tracks each contributor's risk score and trend direction, "
                "while behavioral baselines detect anomalies using Z-score analysis of commit "
                "timing, sizes, and risk deviations."
            ),
            "actions": [
                # Vulnerabilities - SAST tab
                {"type": "goto", "url": f"{base}/projects/{pid}/vulnerabilities", "wait": L},
                {"type": "scroll", "y": 300, "wait": P},
                {"type": "scroll", "y": 600, "wait": P},
                {"type": "scroll", "y": 900, "wait": P},
                # Scan monitor
                {"type": "goto", "url": f"{base}/scan-monitor", "wait": L},
                {"type": "scroll", "y": 300, "wait": P},
                {"type": "scroll", "y": 0, "wait": S},
                # GitHub monitor
                {"type": "goto", "url": f"{base}/github-monitor", "wait": L},
                {"type": "scroll", "y": 300, "wait": P},
                {"type": "scroll", "y": 600, "wait": P},
                {"type": "scroll", "y": 900, "wait": P},
                {"type": "scroll", "y": 1200, "wait": P},
                {"type": "scroll", "y": 0, "wait": S},
            ],
        },

        # ── SCENE 4: SecReq + Controls + Threat Intel (3:30 - 4:30) ──
        {
            "id": "04_controls_intel_mapping",
            "title": "Requirements, Controls & Threat Intel Mapping",
            "voiceover": (
                "Security requirements generation creates abuse cases, STRIDE mapping, "
                "and compliance-mapped requirements for NIST, ISO, SOC 2, PCI-DSS, HIPAA, "
                "and GDPR, with insider threat scenarios for privileged users. "
                "The security controls framework is directly mapped to threat model findings. "
                "Define preventive, detective, and corrective controls, then link them to "
                "specific STRIDE threats from your threat model. The STRIDE coverage heatmap "
                "shows exactly which threat categories have adequate controls and where gaps "
                "exist. Control effectiveness scores and requirement satisfaction tracking "
                "give you measurable compliance posture. "
                "Threat intelligence from 12 industry sectors feeds directly into the threat "
                "model. Each intel entry maps to MITRE ATT&CK techniques that correlate with "
                "your STRIDE threats. The CVE correlation engine links scan vulnerabilities "
                "to CISA KEV, NVD, and Exploit-DB feeds, so you see which of your threat "
                "model's predicted risks are actively being exploited in the wild. "
                "This closed loop, from threat model to controls to intelligence to scan "
                "findings, gives you complete traceability across your security lifecycle."
            ),
            "actions": [
                # Security requirements
                {"type": "goto", "url": f"{base}/projects/{pid}/security-requirements", "wait": L},
                {"type": "scroll", "y": 300, "wait": P},
                {"type": "scroll", "y": 600, "wait": P},
                {"type": "scroll", "y": 0, "wait": S},
                # Security controls
                {"type": "goto", "url": f"{base}/projects/{pid}/security-controls", "wait": L},
                {"type": "scroll", "y": 300, "wait": P},
                {"type": "scroll", "y": 600, "wait": P},
                {"type": "scroll", "y": 0, "wait": S},
                # Threat intelligence
                {"type": "goto", "url": f"{base}/threat-intel", "wait": L},
                {"type": "scroll", "y": 300, "wait": P},
                {"type": "scroll", "y": 600, "wait": P},
                {"type": "scroll", "y": 900, "wait": P},
                {"type": "scroll", "y": 0, "wait": S},
            ],
        },

        # ── SCENE 5: AppInt + Rules + Chat + Settings + VS Code + Close (4:30 - 5:10) ──
        {
            "id": "05_remaining_close",
            "title": "App Intelligence, Rules, Chat, Reports, VS Code & Close",
            "voiceover": (
                "Application Intelligence profiles your codebase, detecting frameworks, "
                "databases, authentication mechanisms, and sensitive data fields, then "
                "generates AI rule suggestions for Semgrep, CodeQL, Checkmarx, and Fortify. "
                "Custom rules with performance analytics track precision, detection trends, "
                "and false positive rates. "
                "The AI chatbot provides multilingual security guidance with OWASP Top 10 "
                "training, supporting Anthropic Claude, OpenAI, Azure, and local Ollama models. "
                "Enterprise reports export in Excel with 20-plus sheets, styled PDF, and "
                "Checkmarx-compatible XML. Native integrations sync to JIRA, Azure DevOps, "
                "and ServiceNow. "
                "The VS Code extension delivers inline scanning with severity coloring, "
                "one-click AI remediation, taint flow visualization, and an integrated "
                "chatbot, all directly in the developer's editor. "
                "Secure Dev AI. Complete business intelligence across your entire application "
                "security lifecycle. Shift left. Stay secure. Build with confidence."
            ),
            "actions": [
                # Application intelligence
                {"type": "goto", "url": f"{base}/application-intelligence", "wait": L},
                {"type": "scroll", "y": 300, "wait": P},
                {"type": "scroll", "y": 0, "wait": S},
                # Custom rules
                {"type": "goto", "url": f"{base}/custom-rules", "wait": L},
                {"type": "scroll", "y": 300, "wait": P},
                # Rule performance
                {"type": "goto", "url": f"{base}/rule-performance", "wait": L},
                {"type": "scroll", "y": 300, "wait": S},
                # AI Chat
                {"type": "goto", "url": f"{base}/chat", "wait": L},
                {"type": "scroll", "y": 200, "wait": P},
                # Settings (AI providers + integrations + VS Code download)
                {"type": "goto", "url": f"{base}/settings", "wait": L},
                {"type": "scroll", "y": 300, "wait": P},
                {"type": "scroll", "y": 600, "wait": P},
                {"type": "scroll", "y": 900, "wait": P},
                {"type": "scroll", "y": 0, "wait": S},
                # Back to dashboard for closing shot
                {"type": "goto", "url": f"{base}/", "wait": L},
            ],
        },
    ]
