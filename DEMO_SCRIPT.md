# Secure Dev AI - Comprehensive Product Demo Script

## Production Notes
- **Total Duration**: ~12-15 minutes (full feature coverage) or trim to 5-7 min highlight reel
- **Recording**: Screen capture with voiceover
- **Tools**: OBS Studio / Loom / ScreenFlow for recording, ElevenLabs for AI voiceover
- **Resolution**: 1920x1080, 30fps
- **Music**: Subtle corporate background track (lower volume during voiceover)

---

## SCENE 1: Opening / Hook (0:00 - 0:25)
**[SCREEN: Animated logo or title slide — "Secure Dev AI"]**

**VOICEOVER:**
> "Every 39 seconds, a cyberattack targets a software application somewhere in the world. Yet most security vulnerabilities are introduced during development, long before they ever reach production."
>
> "What if your team could catch threats at the design stage, scan code in real time, generate security requirements, and get full business intelligence across your security posture, all powered by AI?"
>
> "Meet Secure Dev AI. The intelligent application security platform that shifts security left across your entire software development lifecycle."

---

## SCENE 2: Security Command Center & BI Dashboard (0:25 - 1:15)
**[SCREEN: Login with admin@example.com → Dashboard loads]**

**VOICEOVER:**
> "From the moment you log in, Secure Dev AI gives you a unified security command center packed with business intelligence."

**[SCREEN: Highlight the 4 KPI cards at top — Total Vulnerabilities, False Positive Rate, Remediation Velocity, Avg Time to Fix]**

> "The dashboard presents four key performance indicators front and center: total vulnerabilities with critical and high severity breakdowns, your organization's false positive rate, remediation velocity measured in fixes per day, and average time to fix in days."

**[SCREEN: Scroll to charts — hover over stacked area chart, pie chart, bar charts, line chart]**

> "Below that, interactive trend charts show vulnerability patterns over configurable time windows of 7, 30, or 90 days. A stacked area chart breaks down severity trends over time, a pie chart visualizes severity distribution with percentage labels, a horizontal bar chart tracks finding statuses — open, fixed, in progress, and false positive. A vertical bar chart ranks your top vulnerability categories, and a line chart monitors scan activity frequency day by day."

**[SCREEN: Show Threat Intelligence Overview widget with counts and pulsing alert]**

> "The Threat Intelligence Overview widget surfaces real-time threat data: actively exploited vulnerabilities from CISA's Known Exploited Vulnerabilities catalog, critical CVEs from the National Vulnerability Database, tracked threat actors, ransomware families, exploit kits, and total threat count. When your vulnerabilities correlate with active threats, a high-risk correlation alert pulses to grab your attention."

**[SCREEN: Show project breakdown table with pagination]**

> "A project-level breakdown table shows every project's vulnerability count by severity, risk score, and last scan date, all paginated and filterable."

---

## SCENE 3: Project Creation & Architecture Intelligence (1:15 - 2:00)
**[SCREEN: Click "New Project" → Fill in project name, tech stack, compliance targets, description]**

**VOICEOVER:**
> "Getting started is simple. Create a project by defining your name, description, technology stack, and compliance targets."

**[SCREEN: Show architecture input options — text input, file upload, document analysis, component library, structured builder]**

> "The architecture input system supports multiple methods: type a text-based description, upload diagrams in PNG, JPG, or SVG, analyze Word and PDF documents automatically, use the pre-built component library, build visually with the structured architecture builder, or merge inputs from multiple sources."

**[SCREEN: Show auto-generated DFD with Mermaid visualization → Click through L0 and L1 views]**

> "Secure Dev AI automatically generates Data Flow Diagrams at Level 0 and Level 1 using Mermaid.js visualization, with optional Eraser AI integration for professional-grade diagrams. The platform validates DFDs for completeness, verifies trust boundaries, checks component dependencies, and identifies data flow gaps."

**[SCREEN: Show architecture version history → Click to compare two versions]**

> "Every architecture change is versioned. Compare versions side by side, see change summaries with impact scoring, and understand exactly how your system evolved."

---

## SCENE 4: AI-Powered Threat Modeling & Analytics (2:00 - 3:10)
**[SCREEN: Navigate to Threat Model tab → Show STRIDE analysis generating]**

**VOICEOVER:**
> "Our AI engine performs comprehensive STRIDE-based threat modeling, automatically identifying Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege threats across every component."

**[SCREEN: Show threat details panel — AI business impact, MITRE mapping, severity score]**

> "Each threat is enriched with AI-generated business impact descriptions, mapped to MITRE ATT&CK Enterprise v15 including sub-technique support, and scored for severity."

**[SCREEN: Show Threat Matrix View in full screen — components × STRIDE heatmap]**

> "The threat matrix view displays a heat map of components versus STRIDE categories, with severity color coding and threat count aggregation, available in full-screen mode for presentations."

**[SCREEN: Click "Attack Path Analysis" → Show multi-hop attack chain diagram]**

> "Attack path analysis visualizes multi-hop attack chains showing lateral movement, with exploitability assessments for each path."

**[SCREEN: Show threat timeline → expand a threat to show lifecycle transitions]**

> "Threat lifecycle management tracks every threat through its states: new, existing, modified, and resolved. Each transition records reasons, affected components, and user attribution."

**[SCREEN: Show version history → click diff between two versions]**

> "Version history and architecture diffing compare threat models across versions, showing which threats were added, changed, or resolved. The validation dashboard scores completeness across architecture, data flows, trust boundaries, and dependencies."

**[SCREEN: Show export options — PNG, SVG, JSON, Excel]**

> "Export DFDs as PNG or SVG, and threat models as JSON or Excel for stakeholder review."

---

## SCENE 5: Multi-Layer Vulnerability Scanning (3:10 - 4:30)
**[SCREEN: Click "Run Scan" → Show Scan Monitor with progress bars and live logs]**

**VOICEOVER:**
> "Secure Dev AI runs three layers of automated scanning simultaneously. The scan monitor tracks running, pending, completed, and failed scans in real time, with a live log viewer streaming color-coded output."

**[SCREEN: Show SAST findings tab → filter by severity → expand a finding]**

> "Static Application Security Testing supports eight languages: Python, JavaScript, TypeScript, Java, PHP, C-Sharp, Go, and Ruby. It detects SQL injection, cross-site scripting, command injection, LDAP injection, NoSQL injection, insecure cryptography, insecure deserialization, path traversal, XXE, CSRF, and sensitive data exposure across 68 OWASP rules with CWE and CVSS scoring."

**[SCREEN: Show Taint Flow Visualization panel]**

> "Under the hood, the taint analysis engine tracks data through states — untainted, tainted, sanitized, and partially sanitized — tracing propagation through assignments, function calls, and returns to detect when untrusted input reaches sensitive operations."

**[SCREEN: Show Reachability Analysis panel]**

> "Reachability analysis assesses whether vulnerabilities are actually exploitable, potentially exploitable, imported only, or not reachable, with confidence scoring."

**[SCREEN: Switch to SCA tab → Show dependency tree visualization with transitive deps]**

> "Software Composition Analysis supports npm, pip, Maven, NuGet, Composer, and Go modules. It queries NVD and OSV databases live, tracking direct and transitive dependencies with full chain visualization. Each finding includes CVE IDs, GitHub Security Advisories, CVSS scores, affected and fixed versions, and upgrade paths. License compliance checking and automatic deduplication keep results clean."

**[SCREEN: Switch to Secrets tab → Show detected credentials with entropy indicators]**

> "Secrets detection covers over 50 categories: AWS, Azure, Google Cloud, GitHub, Slack, Stripe, Twilio, database credentials, private keys in RSA, DSA, ECDSA, and ED25519 formats, SSH keys, PEM files, and certificates. Shannon entropy analysis catches high-entropy strings that pattern matching misses, with context-aware false positive filtering."

**[SCREEN: Show baseline engine metrics — rolling window, Z-score anomaly indicators]**

> "The baseline engine computes developer behavioral baselines using rolling 60-commit windows, detecting anomalies through Z-score analysis of commit timing, commit sizes, risk score deviations, and activity rates."

**[SCREEN: Expand a finding → Show AI remediation guidance with code fix]**

> "Every finding includes AI-generated remediation guidance with code examples developers can apply immediately."

---

## SCENE 5B: Scan Monitoring & Real-Time Operations (4:30 - 4:50)
**[SCREEN: Navigate to Scan Monitor → Show running/pending/completed/failed scan cards]**

**VOICEOVER:**
> "The scan monitor provides real-time operational visibility. Track running, pending, completed, and failed scans across SAST, SCA, secrets, and threat model scan types. Each scan shows progress indicators, start and completion times, total vulnerabilities found, and severity breakdowns."

**[SCREEN: Show live log viewer with color-coded output streaming]**

> "A live log viewer streams scan output in real-time with color-coded log levels: info, warning, error, and success. Scan history per project enables performance comparison across runs, with duration tracking and findings trend analysis."

---

## SCENE 6: Security Requirements & Compliance Intelligence (4:50 - 5:50)
**[SCREEN: Navigate to Security Requirements → Create a user story]**

**VOICEOVER:**
> "Enter a user story — or sync stories from JIRA, Azure DevOps, or ServiceNow — and the platform generates comprehensive security analysis."

**[SCREEN: Show generated abuse cases with threat actor profiles]**

> "For each story, it produces 5 to 7 abuse cases with threat actor identification, attack vectors, STRIDE mapping, impact and likelihood assessments, and mitigations."

**[SCREEN: Show generated security requirements list]**

> "It generates 10 to 15 security requirements covering access control, audit logging, data loss prevention, privileged access management, separation of duties, behavioral analytics, data classification, session management, monitoring, and cryptographic controls."

**[SCREEN: Toggle insider threat analysis mode → Show specialized scenarios]**

> "An optional insider threat analysis mode generates scenarios for privileged user abuse, data exfiltration, backdoor injection, audit log tampering, and permission escalation, with profiles for employees, contractors, and departing staff."

**[SCREEN: Show compliance mapping panel — NIST, ISO, SOC2, PCI-DSS, HIPAA, GDPR]**

> "Every requirement automatically maps to NIST SP 800-53, ISO 27001, SOC 2, PCI-DSS, HIPAA, and GDPR. BDD acceptance criteria generate in Gherkin format for test automation. Custom AI prompts let you tailor generation to your organization's policies."

---

## SCENE 7: Security Controls Framework (5:30 - 6:00)
**[SCREEN: Navigate to Security Controls → Show control registry with types and statuses]**

**VOICEOVER:**
> "The security controls module provides a complete control registry. Define controls by type: preventive, detective, corrective, or compensating. Track status as implemented, planned, partial, or not implemented. Score effectiveness and assign owners."

**[SCREEN: Show STRIDE coverage heatmap → Show coverage summary metrics]**

> "Link controls to threats and requirements for full traceability. The STRIDE coverage heatmap highlights gaps where controls are insufficient. A coverage summary shows total controls, implementation status, average effectiveness, threats mitigated, and requirements satisfied. Import and export via CSV with NIST 800-53 and CIS Controls mappings."

---

## SCENE 8: GitHub Monitoring & Insider Threat Intelligence (6:00 - 7:00)
**[SCREEN: Navigate to GitHub Monitor → Show monitored repos list]**

**VOICEOVER:**
> "Continuous GitHub commit monitoring analyzes every push against 25-plus detection rules."

**[SCREEN: Show commit timeline with risk scores → Click a high-risk commit]**

> "The risk scoring engine evaluates SAST findings in diffs, sensitive file changes, binary injection, force pushes, off-hours activity, author mismatches, unsigned commits, large deletions, suspicious messages, dependency manipulation including typosquatting, CI/CD tampering, and configuration weakening."

**[SCREEN: Show insider threat classification panel]**

> "Insider threat detection classifies threats as intentional, suspicious, negligent, or false positive, with confidence scoring, intent analysis, impact summaries, and recommended actions."

**[SCREEN: Show developer profiles with risk metrics and baselines]**

> "Developer profiling tracks each contributor's commits, high-risk count, average risk score, and trend direction. Behavioral baselines detect off-hours deviations, abnormally large commits, and risk spikes using Z-score analysis."

**[SCREEN: Show CSV export options with filters]**

> "Export findings as CSV filtered by repository, severity, rule, author, and date range."

---

## SCENE 9: Threat Intelligence & CVE Correlation (7:00 - 7:40)
**[SCREEN: Navigate to Threat Intel → Show sector library selector → Pick "Banking/Finance"]**

**VOICEOVER:**
> "The threat intelligence module provides sector-specific libraries for 12 industries: banking, healthcare, government, retail, manufacturing, energy, telecom, education, insurance, defense, media, and technology."

**[SCREEN: Show threat intel entries with MITRE mapping and regulatory impact]**

> "Each entry includes severity, STRIDE category, MITRE ATT&CK techniques, regulatory impact across PCI-DSS, HIPAA, GDPR, NIST, and SOC 2, and recommended controls. Entry types span incident reports, threat actor profiles, attack scenarios, and penetration test findings."

**[SCREEN: Show bulk upload → Show CVE correlation panel with live feeds]**

> "Upload custom intelligence in CSV, JSON, or STIX 2.1. The CVE correlation engine links scan results to CISA KEV, NVD, Exploit-DB, and GitHub Security Advisories, flagging actively exploited vulnerabilities. Generate custom SAST rules directly from threat intelligence."

---

## SCENE 10: Application Intelligence & Profiling (7:40 - 8:20)
**[SCREEN: Navigate to Application Intelligence → Trigger profiling → Show progress]**

**VOICEOVER:**
> "Application Intelligence automatically profiles your codebase. It detects languages with percentage breakdowns and lines of code, identifies frameworks with version detection — FastAPI, Django, Spring, React, Vue, Angular, and more."

**[SCREEN: Show profiling results — frameworks, databases, integrations, auth mechanisms]**

> "It discovers databases, ORMs, task queues, cloud services, payment processors, message queues, and CDN providers. It detects authentication mechanisms: OAuth2, JWT, SAML, API keys, and certificate-based auth. It identifies sensitive data fields across PII, financial, authentication, and healthcare categories, and maps all API entry points."

**[SCREEN: Show security score → Show AI rule suggestions with confidence scores]**

> "A security score from 0 to 100 summarizes posture. AI generates framework-specific rule suggestions with confidence scores, CWE and MITRE mappings, and export formats for Semgrep, CodeQL, Checkmarx, and Fortify."

---

## SCENE 11: Custom Rules & Performance Analytics (8:20 - 9:00)
**[SCREEN: Navigate to Custom Rules → Create a new rule with regex, severity, CWE]**

**VOICEOVER:**
> "Create organization-specific detection rules with custom patterns, severity levels, language filters, CWE and OWASP mappings, and remediation guidance with code examples."

**[SCREEN: Navigate to Rule Performance Dashboard → Show KPI cards and charts]**

> "The rule performance dashboard provides total rules, enabled count, detections, average precision, and rules needing refinement below 85 percent. It shows severity breakdowns, AI-generated versus user-created ratios, and a 30-day detection trend chart."

**[SCREEN: Show top performers, rules needing attention, and enhancement activity log]**

> "Top performing rules and those needing attention surface automatically. The feedback system tracks true positives, false positives, and precision. AI-powered enhancement suggests refinements, with job tracking for status and completion."

---

## SCENE 12: AI Security Assistant (9:00 - 9:30)
**[SCREEN: Navigate to AI Chat → Type a question about SQL injection → Show streaming response]**

**VOICEOVER:**
> "The AI security chatbot provides context-aware guidance with built-in training on the complete OWASP Top 10, secure coding practices, authentication, cryptography, web, API, cloud, and mobile security."

**[SCREEN: Switch language → Show response in Spanish/French → Show provider settings]**

> "It auto-detects the developer's language and responds in kind. Multi-turn conversations maintain context from your project's vulnerabilities and threat models. Choose from Anthropic Claude, OpenAI GPT-4, Azure OpenAI, Google PaLM, or local Ollama models."

---

## SCENE 13: Enterprise Reporting (9:30 - 10:00)
**[SCREEN: Click "Export Report" → Download Excel → Open and scroll through sheets]**

**VOICEOVER:**
> "Excel reports include over 20 sheets: cover page, visual dashboard, overall summary, SAST findings grouped by severity, CWE, OWASP category, and file, SCA by severity, package, and CVE details, secrets findings, STRIDE analysis, MITRE mappings, and remediation summary — all with charts and color-coded formatting."

**[SCREEN: Show PDF report → Show XML report structure]**

> "PDF reports provide styled executive summaries with embedded charts and severity highlighting. XML reports follow Checkmarx-compatible schemas for third-party tool integration."

---

## SCENE 14: Integration Ecosystem (10:00 - 10:30)
**[SCREEN: Navigate to Settings → Show JIRA integration config → Test connection → Show sync]**

**VOICEOVER:**
> "Native integrations connect to JIRA with OAuth, field mapping for abuse cases and security requirements, project discovery, and bidirectional sync. Azure DevOps supports work item creation, field mapping, and status synchronization. ServiceNow enables incident and change request creation with assignment routing. GitHub webhook integration powers continuous commit scanning."

---

## SCENE 15: VS Code Extension — Full Developer Experience (10:30 - 11:30)
**[SCREEN: Open VS Code → Show Secure Dev AI extension installed → Show sidebar tree views]**

**VOICEOVER:**
> "The Secure Dev AI VS Code extension, version 1.5.0, brings the full power of the platform directly into the developer's editor."

**[SCREEN: Click through SAST tree view → SCA tree view → Secrets tree view → Custom Rules tree view]**

> "Four dedicated sidebar tree views organize findings by category: SAST, SCA, secrets, and custom rules. Each is fully navigable — click through to the exact line of vulnerable code."

**[SCREEN: Hover over an inline highlighted vulnerability → Show diagnostic popup]**

> "Inline security feedback highlights vulnerabilities with severity-based coloring. Hover to see diagnostic details including vulnerability type, CWE classification, and risk level."

**[SCREEN: Click the code action lightbulb → Apply AI-suggested fix]**

> "One-click code actions apply AI-suggested fixes right in the editor without manual editing."

**[SCREEN: Show status bar progress during scan → Show workspace scan completing]**

> "The extension supports workspace-wide and file-specific scanning with real-time progress in the status bar. It covers Python, TypeScript, JavaScript, Java, Go, PHP, C-Sharp, and Ruby, with AST parsing, control flow graph analysis, data flow tracking, and interprocedural analysis running locally."

**[SCREEN: Open vulnerability details panel → Show taint flow visualization panel]**

> "A vulnerability details panel shows full context, attack scenarios, and remediation steps. The taint flow visualization renders source-to-sink data paths showing how untrusted input reaches sensitive operations."

**[SCREEN: Open rule performance panel → Open integrated chatbot panel]**

> "A rule performance panel tracks detection rates and precision. An integrated AI chatbot lets developers ask security questions without leaving the editor."

**[SCREEN: Show right-click context menu → Show extension settings with connection test]**

> "Right-click context menu triggers scans and views findings for any file. Results cache locally with auto-refresh. Configuration includes API URL, auth token, and built-in connection testing. The extension downloads directly from the settings page."

---

## SCENE 16: Configuration & Enterprise Settings (11:30 - 12:00)
**[SCREEN: Navigate to Settings → Show AI provider dropdown → Show feed configs]**

**VOICEOVER:**
> "Full control over AI providers with model selection, API keys, custom endpoints, and connection testing. Configure NVD and MISP threat feeds, prioritize SCA sources across GitHub Advisory and Snyk databases, and customize AI prompts for your organization's security policies."

---

## SCENE 17: Closing / Call to Action (12:00 - 12:15)
**[SCREEN: Return to dashboard or show closing title slide]**

**VOICEOVER:**
> "Secure Dev AI. Complete business intelligence across your entire application security lifecycle. From architecture design through threat modeling, vulnerability scanning, compliance tracking, and continuous monitoring — every feature delivers actionable analytics, measurable metrics, and enterprise-grade reporting."
>
> "Shift left. Stay secure. Build with confidence."

**[SCREEN: Logo + contact information + "Request a Demo" CTA]**

---

## Recording Workflow

1. **Set up the environment**: `docker-compose up`, seed demo data via `/api/seed-demo`
2. **Pre-configure integrations**: Set up JIRA/GitHub tokens so sync demos work
3. **Install VS Code extension**: Download from settings page, configure connection
4. **Practice the flow**: Walk through each scene 2-3 times
5. **Record screen first**: Capture all interactions without audio
6. **Generate voiceover**: Paste `VOICEOVER_SCRIPT.txt` into ElevenLabs Projects
7. **Edit together**: Sync screen + audio in DaVinci Resolve or CapCut
8. **Add polish**: Background music, transitions, logo animations

## ElevenLabs Setup
1. Go to [elevenlabs.io](https://elevenlabs.io) → **Projects** (for long-form)
2. Paste full `VOICEOVER_SCRIPT.txt` content
3. Voice: **"Daniel"** or **"Adam"** (professional corporate tone)
4. Stability: ~0.60 | Clarity: ~0.75
5. Generate → Download MP3

## Editing Options
- **Full demo** (~12 min): Use all 17 scenes for internal stakeholders or deep-dive demos
- **Highlight reel** (~5 min): Scenes 1, 2, 4, 5, 6, 8, 15, 17 for executive overview
- **Feature spotlight** (~2 min each): Individual scenes for targeted feature demos

## Tools
| Tool | Purpose | Cost |
|------|---------|------|
| ElevenLabs | AI voiceover | Free tier (10 min) |
| OBS Studio | Screen recording | Free |
| DaVinci Resolve | Video editing | Free |
| CapCut | Video editing (simpler) | Free |
| Loom | Quick recording | Free tier |
