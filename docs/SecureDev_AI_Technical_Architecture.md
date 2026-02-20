# SecureDev AI - Technical Architecture Documentation

*Comprehensive technical overview of SecureDev AI's security scanning capabilities*

---

## Table of Contents

1. [Threat Modeling Architecture](#1-threat-modeling-architecture)
2. [Mermaid Diagram Generation](#2-mermaid-diagram-generation)
3. [SAST Scanner Architecture](#3-sast-scanner-architecture)
4. [SCA Scanner Architecture](#4-sca-scanner-architecture)
5. [Secret Scanner Architecture](#5-secret-scanner-architecture)
6. [Inter-Procedural Analysis](#6-inter-procedural-analysis)
7. [AI Prompts for Security Scanners](#7-ai-prompts-for-security-scanners)
8. [Secret Handling & Data Privacy](#8-secret-handling--data-privacy)

---

## 1. Threat Modeling Architecture

### Overview

SecureDev AI's threat modeling feature uses AI to automatically generate comprehensive STRIDE-based threat models from architecture documentation.

### Technology Stack

| Component | Technology |
|-----------|------------|
| **AI Provider** | Claude (Anthropic) primary, OpenAI fallback |
| **Methodology** | STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation) |
| **Attack Framework** | MITRE ATT&CK mapping |
| **Diagram Generation** | Mermaid.js (client-side rendering) |

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                     User Provides Input                          │
│         (Architecture Description or Document)                   │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Backend Processing                              │
│                                                                  │
│  1. Parse architecture document                                  │
│  2. Identify components, data flows, trust boundaries            │
│  3. Build AI prompt with STRIDE methodology                      │
│  4. Call Claude/OpenAI API                                       │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                  AI Analysis                                     │
│                                                                  │
│  • Analyze architecture for each STRIDE category                 │
│  • Identify attack vectors and entry points                      │
│  • Map to MITRE ATT&CK techniques                               │
│  • Generate Mermaid DFD syntax                                   │
│  • Suggest mitigations for each threat                          │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Output                                          │
│                                                                  │
│  • List of threats with severity and likelihood                 │
│  • STRIDE categorization                                         │
│  • MITRE ATT&CK IDs                                             │
│  • Data Flow Diagram (Mermaid syntax)                           │
│  • Recommended mitigations                                       │
└─────────────────────────────────────────────────────────────────┘
```

### Key Files

| File | Purpose |
|------|---------|
| `backend/services/threat_modeling.py` | Core threat modeling service |
| `backend/services/ai_client_factory.py` | Multi-provider AI client |
| `frontend/src/pages/ThreatModelPage.tsx` | React UI component |

### Sample Output Structure

```json
{
  "threats": [
    {
      "id": "T-001",
      "title": "SQL Injection via User Input",
      "description": "Attacker could inject malicious SQL...",
      "stride_category": "Tampering",
      "severity": "High",
      "likelihood": "Medium",
      "mitre_attack_id": "T1190",
      "mitre_attack_name": "Exploit Public-Facing Application",
      "affected_components": ["API Gateway", "Database"],
      "mitigation": "Use parameterized queries..."
    }
  ],
  "data_flow_diagram": "graph TD\n  A[User] --> B[API Gateway]..."
}
```

---

## 2. Mermaid Diagram Generation

### How Diagrams Are Created

SecureDev AI uses **Mermaid.js** for diagram rendering. This is a **client-side JavaScript library**, NOT an external API.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Backend (Python)                             │
│                                                                  │
│  AI generates Mermaid SYNTAX (plain text):                       │
│                                                                  │
│  graph TD                                                        │
│      A[User Browser] -->|HTTPS| B[Load Balancer]                │
│      B --> C[API Gateway]                                        │
│      C --> D[(Database)]                                         │
│      C --> E[Auth Service]                                       │
│                                                                  │
│  This text is stored in database and sent to frontend            │
└─────────────────┬───────────────────────────────────────────────┘
                  │ JSON Response
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Frontend (React)                             │
│                                                                  │
│  import mermaid from 'mermaid';                                  │
│                                                                  │
│  // Mermaid.js runs IN THE BROWSER                               │
│  mermaid.initialize({ startOnLoad: true });                      │
│                                                                  │
│  // Converts text syntax to SVG diagram                          │
│  <div className="mermaid">                                       │
│    {diagram_syntax}                                              │
│  </div>                                                          │
│                                                                  │
│  // Browser renders the SVG                                      │
└─────────────────────────────────────────────────────────────────┘
```

### Key Points

| Aspect | Details |
|--------|---------|
| **No External API** | Mermaid.js is bundled with the frontend |
| **Client-Side Rendering** | Diagrams render in the user's browser |
| **No Image Files** | SVG generated dynamically from text |
| **Offline Capable** | Works without internet (after initial load) |

### Supported Diagram Types

- **Flowcharts** - Data flow diagrams
- **Sequence Diagrams** - API interactions
- **Class Diagrams** - Component relationships
- **State Diagrams** - Application states

---

## 3. SAST Scanner Architecture

### Overview

The SAST (Static Application Security Testing) scanner performs multi-layer analysis on source code to detect vulnerabilities.

### Multi-Layer Analysis

| Layer | Scanner | Analysis Type | What It Does |
|-------|---------|---------------|--------------|
| **Layer 1** | `SASTScanner` | Regex-based | Fast line-by-line pattern matching (40+ patterns) |
| **Layer 2** | `ASTSecurityAnalyzer` | AST-based | Parses code into Abstract Syntax Tree for semantic analysis |
| **Layer 3** | `InterproceduralAnalyzer` | Cross-function | Tracks data flow across function boundaries |

### Supported Languages

| Language | Extensions |
|----------|------------|
| Python | `.py` |
| JavaScript | `.js`, `.jsx`, `.mjs` |
| TypeScript | `.ts`, `.tsx` |
| Java | `.java` |
| PHP | `.php` |
| Ruby | `.rb` |
| Go | `.go` |
| C# | `.cs` |
| C/C++ | `.c`, `.cpp`, `.h`, `.hpp`, `.cc`, `.cxx` |
| Kotlin | `.kt`, `.kts` |
| Swift | `.swift` |
| Rust | `.rs` |
| Scala | `.scala` |
| Perl | `.pl`, `.pm` |
| Shell | `.sh`, `.bash` |

### Vulnerability Categories

| Category | Examples |
|----------|----------|
| **Injection** | SQL Injection, NoSQL Injection, Command Injection, XSS, LDAP Injection |
| **Cryptographic** | Weak hashing (MD5/SHA1), hardcoded keys, insecure random |
| **Authentication** | Hardcoded passwords, JWT issues, session fixation |
| **Access Control** | Path traversal, IDOR, privilege escalation |
| **Security Misconfig** | Debug mode, CORS wildcards, missing headers |
| **Data Exposure** | Sensitive data logging, unmasked PII |
| **Error Handling** | Fail-open logic, stack trace exposure |

### Output Per Finding

```python
{
    "title": "Injection: SQL Injection",
    "description": "SQL query construction using string concatenation",
    "severity": "critical",
    "cwe_id": "CWE-89",
    "owasp_category": "A05:2025 - Injection",
    "file_path": "app/database.py",
    "line_number": 42,
    "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
    "business_impact": "AI-generated contextual impact...",
    "technical_impact": "AI-generated technical details...",
    "remediation": "Use parameterized queries...",
    "remediation_code": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    "cvss_score": 9.8,
    "stride_category": "Tampering",
    "mitre_attack_id": "T1190",
    "confidence": "high",
    "impact_generated_by": "ai"
}
```

### Key Files

| File | Purpose |
|------|---------|
| `backend/services/sast_scanner.py` | Main SAST scanner with regex patterns |
| `backend/services/ast_security_analyzer.py` | AST-based analysis |
| `backend/services/interprocedural_analyzer.py` | Cross-function taint tracking |
| `backend/services/ai_impact_service.py` | AI-powered impact generation |

---

## 4. SCA Scanner Architecture

### Overview

The SCA (Software Composition Analysis) scanner detects vulnerabilities in third-party dependencies.

### How It Works

| Step | Description |
|------|-------------|
| **1. Parse Manifest** | Reads dependency files (package.json, requirements.txt, pom.xml, etc.) |
| **2. O(1) Lookup** | Uses pre-indexed vulnerability database for instant matching |
| **3. Version Comparison** | Pre-compiled version constraints for fast range checking |
| **4. CVE Database** | Contains 200+ known vulnerabilities with real CVEs |
| **5. AI Impact Generation** | Contextual impact based on package, CVE, and ecosystem |

### Supported Ecosystems

| Ecosystem | Manifest Files |
|-----------|---------------|
| **npm** | package.json, package-lock.json |
| **pip** | requirements.txt, Pipfile, pyproject.toml |
| **Maven** | pom.xml |
| **Gradle** | build.gradle |
| **Composer** | composer.json |
| **RubyGems** | Gemfile, Gemfile.lock |
| **Go** | go.mod, go.sum |
| **Cargo** | Cargo.toml |
| **NuGet** | packages.config, *.csproj |

### Sample Vulnerabilities in Database

| Package | Vulnerability | CVE | CVSS |
|---------|--------------|-----|------|
| log4j-core | Remote Code Execution (Log4Shell) | CVE-2021-44228 | 10.0 |
| lodash | Prototype Pollution | CVE-2020-8203 | 7.4 |
| axios | SSRF | CVE-2021-3749 | 5.9 |
| spring-core | Spring4Shell RCE | CVE-2022-22965 | 9.8 |
| pillow | Buffer Overflow | CVE-2023-44271 | 7.5 |

### Output Per Finding

```python
{
    "package": "lodash",
    "installed_version": "4.17.15",
    "vulnerability": "Prototype Pollution",
    "cve": ["CVE-2020-8203", "CVE-2019-10744"],
    "severity": "high",
    "cvss_score": 7.4,
    "ecosystem": "npm",
    "remediation": "Upgrade to lodash >= 4.17.21",
    "business_impact": "AI-generated or static template...",
    "technical_impact": "Object prototype manipulation..."
}
```

### Key Files

| File | Purpose |
|------|---------|
| `backend/services/sca_scanner.py` | Main SCA scanner |
| `backend/services/vulnerability_feeds.py` | Live vulnerability feeds |
| `backend/services/transitive_analyzer.py` | Transitive dependency analysis |

---

## 5. Secret Scanner Architecture

### Overview

The Secret Scanner detects hardcoded credentials, API keys, and sensitive data with entropy analysis and false positive reduction.

### How It Works

| Step | Description |
|------|-------------|
| **1. Regex Matching** | Scans for 50+ secret patterns (API keys, tokens, passwords) |
| **2. Entropy Analysis** | Uses **Shannon entropy** to detect high-entropy random strings |
| **3. Context Awareness** | Checks if in comments, test files, or mock data |
| **4. Confidence Scoring** | Calculates confidence (high/medium/low) to reduce false positives |
| **5. Value Masking** | Masks detected secrets in output for security |

### Secret Types Detected

| Category | Secret Types |
|----------|-------------|
| **Cloud Providers** | AWS Access Keys, AWS Secret Keys, Azure Storage Keys, GCP API Keys, GCP Service Account Keys |
| **Version Control** | GitHub PATs (ghp_), GitLab Tokens (glpat-), Bitbucket App Passwords |
| **Payment** | Stripe Live Keys (sk_live_), PayPal OAuth, Square Tokens |
| **Communication** | Slack Bot Tokens (xoxb-), Discord Tokens, Telegram Bot Tokens |
| **Databases** | MongoDB/MySQL/PostgreSQL connection strings with embedded credentials |
| **Cryptographic** | Private Keys (RSA, SSH, PGP), Certificates |
| **Generic** | Generic API keys, Bearer tokens, Passwords in config |

### Confidence Scoring Logic

```
Starting Score: 100

Deductions:
- In test file: -30 points
- In comment: -25 points
- Low entropy: -40 points
- False positive indicators: -50 points

Result:
≥70 = High confidence
40-69 = Medium confidence
<40 = Low confidence (filtered out for test files)
```

### Shannon Entropy Calculation

```python
def calculate_shannon_entropy(self, data: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0.0

    # Count character frequencies
    freq = Counter(data)
    length = len(data)

    # Calculate entropy
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

# High entropy (random) = likely a real secret
# Low entropy (patterns) = likely false positive
```

### Output Per Finding

```python
{
    "title": "AWS Access Key ID Detected",
    "severity": "critical",
    "confidence": "high",
    "cwe_id": "CWE-798",
    "owasp_category": "A07:2021 - Identification and Authentication Failures",
    "file_path": "config/aws.py",
    "line_number": 15,
    "code_snippet": "AWS_KEY = 'AKIA...'",
    "secret_type": "AWS Access Key ID",
    "masked_value": "AKIA************MPLE",
    "entropy": 4.2,
    "remediation": "Remove AWS credentials from code. Use AWS IAM roles or Secrets Manager.",
    "mitre_attack_id": "T1552.001",
    "is_test_file": false,
    "impact_generated_by": "ai"
}
```

### Masking Function

```python
def _mask_secret(self, secret: str) -> str:
    """Mask secret value for safe display"""
    if len(secret) <= 8:
        return '*' * len(secret)
    elif len(secret) <= 16:
        return secret[:2] + '*' * (len(secret) - 4) + secret[-2:]
    else:
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]

# Examples:
# "short" → "*****"
# "medium_secret" → "me*********et"
# "AKIAIOSFODNN7EXAMPLE" → "AKIA************MPLE"
```

---

## 6. Inter-Procedural Analysis

### Overview

The Inter-Procedural Analyzer performs advanced static analysis that tracks data flow across function boundaries, catching vulnerabilities that single-function analysis misses.

### Features

| Feature | Implementation |
|---------|---------------|
| **Call Graph Construction** | Builds caller → callee relationships across all functions |
| **Taint Tracking** | Tracks tainted data from sources through propagators to sinks |
| **Function Summaries** | Generates summaries of which params carry taint, what returns tainted data |
| **Context-Sensitive Analysis** | Distinguishes call sites (same function called from different places) |
| **Alias Analysis** | Tracks variable aliasing |
| **Sanitizer Detection** | Recognizes sanitization functions to eliminate false positives |

### Taint States

```python
class TaintState(Enum):
    TAINTED = "tainted"      # Contains user input
    CLEAN = "clean"          # Known safe
    UNKNOWN = "unknown"      # Not yet analyzed
    SANITIZED = "sanitized"  # Was tainted, now cleaned
    CONDITIONAL = "conditional"  # Tainted in some paths only
```

### Source/Sink/Sanitizer Detection

```python
# Sources (user input entry points)
- @route, @get, @post decorators (Flask/FastAPI)
- request.*, params.*, input()
- Environment variables, file reads

# Sinks (dangerous operations)
- execute(), system(), eval(), exec()
- subprocess.*, popen()
- innerHTML, document.write()

# Sanitizers (cleaning functions)
- escape(), sanitize(), clean()
- validate(), encode(), quote()
```

### What Inter-Procedural Catches That Regex Misses

| Scenario | Regex | Inter-Procedural |
|----------|-------|------------------|
| Taint flows across 3+ functions | ❌ | ✅ |
| User input → helper function → SQL query | ❌ | ✅ |
| Return value propagation | ❌ | ✅ |
| Sanitized paths (escape called before sink) | False positive | ✅ Filters out |
| Recursive function taint | ❌ | ✅ |

### Example Detection

```python
def get_user_input():
    return request.args.get('id')  # SOURCE

def process_data(data):
    return data.strip()  # PROPAGATOR

def execute_query(query):
    db.execute(query)  # SINK

# In another function:
user_id = get_user_input()
processed = process_data(user_id)
execute_query(f"SELECT * FROM users WHERE id = {processed}")  # VULNERABLE!
```

**Regex scanner:** Would miss this (SQL injection is 3 function calls away from source)

**Inter-procedural analyzer:** Tracks the flow:
```
get_user_input() → process_data() → execute_query() [SQL Injection detected!]
```

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/scan/interprocedural` | Single file inter-procedural scan |
| `POST /api/scan/interprocedural/directory` | Directory-wide cross-file analysis |
| `POST /api/scan/ast` | AST-based security analysis |

---

## 7. AI Prompts for Security Scanners

### Overview

SecureDev AI uses AI prompts to generate contextual, dynamic impact statements for security findings.

### 7.1 System Prompt (Used for All Scanners)

```
You are a senior application security expert with deep expertise in
vulnerability assessment, threat modeling, and secure development practices.

Your task is to generate detailed, actionable impact statements for security
vulnerabilities. Your response MUST be valid JSON with this exact structure:

{
    "business_impact": "Bullet points explaining business consequences",
    "technical_impact": "Bullet points explaining technical attack vectors",
    "recommendations": "Numbered list of specific, actionable remediation steps"
}

Guidelines:
- Business impact: financial risk, regulatory/compliance (GDPR, PCI-DSS,
  HIPAA, SOC2), reputational damage, operational disruption
- Technical impact: attack scenarios, exploitation methods, lateral movement,
  data exposure
- Recommendations: specific and actionable, including tool names, code patterns
- Each section should be 80-120 words
- Use markdown formatting (bullet points, bold for emphasis)
- Be concise but comprehensive
```

### 7.2 SAST Prompt

```
Generate a detailed impact statement for this SAST finding:

**Vulnerability Type:** {title}
**Severity:** {severity}
**CWE:** {cwe_id}
**OWASP Category:** {owasp_category}
**File:** {file_path}
**Language/Framework:** {language}
**Affected Code:**
```
{code_snippet}  # Truncated to 300 chars
```

Consider the specific programming language context and provide relevant
attack scenarios and language-specific remediation.
```

### 7.3 SCA Prompt

```
Generate a detailed impact statement for this SCA finding:

**Package:** {package}
**Installed Version:** {installed_version}
**Fixed Version:** {fixed_version}
**Vulnerability:** {vulnerability}
**CVE:** {cve}
**Severity:** {severity}
**CVSS Score:** {cvss_score}
**Ecosystem:** {ecosystem}

Consider known exploits for this CVE if applicable, and provide
package-specific upgrade guidance.
```

### 7.4 Secret Prompt

```
Generate a detailed impact statement for this exposed secret/credential:

**Secret Type:** {secret_type}
**Severity:** {severity}
**File:** {file_path}
**Confidence:** {confidence}
**Description:** {description}

Consider what an attacker could do with this specific type of credential
and provide immediate rotation/revocation steps.
```

### 7.5 Rule Generation Prompts

**Generate New Rule:**
```
You are a security expert creating vulnerability detection rules.

Generate precise regex patterns to detect this vulnerability:

Vulnerability Name: {rule_name}
Description: {vulnerability_description}
Severity: {severity}
Target Languages: python, javascript, java, php, go

Return a JSON object with:
{
    "patterns": [{"pattern": "...", "language": "...", "description": "..."}],
    "cwe": "CWE-XXX",
    "owasp": "OWASP category",
    "remediation": "how to fix",
    "remediation_code": "secure example",
    "false_positive_prevention": "tips"
}
```

**Refine Rule from False Positives:**
```
Refine this vulnerability detection rule based on false positive feedback:

Current Pattern: {current_pattern}
Description: {current_description}

False Positive Examples:
{false_positive_examples}

Generate an improved pattern that excludes these false positive cases.
```

### AI Usage Summary

| Component | AI Usage | Model | Purpose |
|-----------|----------|-------|---------|
| **Impact Statements** | ✅ Yes | Claude/GPT-4o-mini | Generate contextual business/technical impact |
| **Rule Generation** | ✅ Yes | GPT-4o | Create new detection patterns |
| **Rule Refinement** | ✅ Yes | GPT-4o | Improve patterns from false positive feedback |
| **CVE Rules** | ✅ Yes | GPT-4o | Generate detection rules from CVE data |
| **Threat Intel Rules** | ✅ Yes | GPT-4o | Create rules from security advisories |
| **Framework Suggestions** | ❌ Template | - | Static templates for common frameworks |

---

## 8. Secret Handling & Data Privacy

### Current Implementation Analysis

#### Secret Scanner → AI: ✅ SAFE

For Secret findings, the AI only receives metadata - **NOT the actual secret**:

```python
def _build_secret_prompt(self, vuln_info: Dict) -> str:
    return f"""Generate impact statement for:

**Secret Type:** {vuln_info.get('secret_type')}      # "AWS Access Key ID"
**Severity:** {vuln_info.get('severity')}            # "critical"
**File:** {vuln_info.get('file_path')}               # "config/aws.py"
**Confidence:** {vuln_info.get('confidence')}        # "high"
**Description:** {vuln_info.get('description')}      # "AWS Access Key detected"
"""
    # ✅ NO code_snippet, NO masked_value, NO actual secret sent
```

#### SCA Scanner → AI: ✅ SAFE

Only package metadata is sent - no code:

```python
# What's sent for SCA
**Package:** lodash
**Installed Version:** 4.17.15
**CVE:** CVE-2020-8203
# ✅ No code or secrets
```

#### SAST Scanner → AI: ⚠️ POTENTIAL RISK

Code snippets ARE sent to AI (truncated to 300 chars):

```python
def _build_sast_prompt(self, vuln_info: Dict) -> str:
    code_snippet = vuln_info.get('code_snippet')
    if len(code_snippet) > 300:
        code_snippet = code_snippet[:300] + "..."

    return f"""...
**Affected Code:**
```
{code_snippet}    # ⚠️ Raw code sent - could contain secrets!
```
"""
```

### Risk Scenario

```python
# This SQL injection finding would send the password to AI:
cursor.execute(f"SELECT * FROM users WHERE password = 'MyS3cr3tP@ss!'")
#                                                      ^^^^^^^^^^^^^^^^
#                                                      Sent to OpenAI/Claude!
```

### Security Summary

| Scanner | Sends to AI | Secret Risk | Status |
|---------|-------------|-------------|--------|
| **Secret Scanner** | Metadata only | ✅ No secrets sent | SAFE |
| **SCA Scanner** | Package info only | ✅ No code sent | SAFE |
| **SAST Scanner** | Code snippets (300 chars) | ⚠️ Could contain embedded secrets | NEEDS FIX |
| **Threat Modeling** | Architecture doc | ⚠️ Could contain secrets in docs | NEEDS REVIEW |

### Recommended Fix: Secret Scrubber

```python
import re

SECRET_PATTERNS_FOR_SCRUBBING = [
    # Passwords in code
    (r'(password|passwd|pwd|secret|api_key|apikey|token|auth)["\']?\s*[:=]\s*["\'][^"\']{6,}["\']',
     r'\1="[REDACTED]"'),
    # AWS Keys
    (r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
     '[AWS_KEY_REDACTED]'),
    # GitHub Tokens
    (r'ghp_[0-9a-zA-Z]{36}',
     '[GITHUB_TOKEN_REDACTED]'),
    # Stripe Keys
    (r'sk_live_[0-9a-zA-Z]{24,}',
     '[STRIPE_KEY_REDACTED]'),
    # Generic high-entropy strings
    (r'["\'][A-Za-z0-9+/=]{32,}["\']',
     '"[HIGH_ENTROPY_REDACTED]"'),
]

def scrub_secrets_from_code(code: str) -> str:
    """Remove potential secrets from code before sending to AI."""
    scrubbed = code
    for pattern, replacement in SECRET_PATTERNS_FOR_SCRUBBING:
        scrubbed = re.sub(pattern, replacement, scrubbed, flags=re.IGNORECASE)
    return scrubbed
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        SecureDev AI Backend                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│   │ SAST Scanner │    │ SCA Scanner  │    │Secret Scanner│     │
│   │              │    │              │    │              │      │
│   │ • Regex      │    │ • Manifest   │    │ • Regex      │      │
│   │   patterns   │    │   parsing    │    │   patterns   │      │
│   │ • AST        │    │ • CVE DB     │    │ • Entropy    │      │
│   │   analysis   │    │ • Version    │    │ • Confidence │      │
│   │ • Inter-     │    │   matching   │    │ • Masking    │      │
│   │   procedural │    │              │    │              │      │
│   └──────┬───────┘    └──────┬───────┘    └──────┬───────┘      │
│          │                   │                   │               │
│          └───────────────────┼───────────────────┘               │
│                              ▼                                   │
│                  ┌────────────────────┐                         │
│                  │  AI Impact Service │                          │
│                  │  (Claude/OpenAI +  │                          │
│                  │   LRU caching)     │                          │
│                  └──────────┬─────────┘                          │
│                             ▼                                    │
│                  ┌────────────────────┐                          │
│                  │  Unified Findings  │                          │
│                  │  with AI-powered   │                          │
│                  │  impact statements │                          │
│                  └────────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Differentiators

| Feature | How SecureDev AI Does It |
|---------|-------------------------|
| **AI-Powered Impact** | Uses Claude/GPT to generate contextual business/technical impact per finding |
| **Multi-Layer SAST** | Regex + AST + Inter-procedural analysis |
| **Multi-Language** | 15+ languages with language-specific patterns |
| **Entropy-Based Secrets** | Shannon entropy calculation reduces false positives |
| **Pre-Indexed SCA** | O(1) lookups instead of O(n) linear scans |
| **STRIDE/MITRE Mapping** | Every finding mapped to threat model and attack framework |
| **Custom Rules** | User-defined rules stored in SQLite, applied alongside built-in patterns |
| **Caching** | LRU cache (1000 entries, 24hr TTL) for AI impact to avoid duplicate API calls |

---

*Document generated for SecureDev AI Technical Documentation*
*Version 1.0 | February 2026*
