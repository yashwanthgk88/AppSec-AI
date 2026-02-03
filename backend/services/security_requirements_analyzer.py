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
    DEFAULT_ABUSE_CASE_PROMPT = """Generate 5-7 detailed abuse cases. For EACH abuse case provide:

1. **Threat Title**: Specific attack name (e.g., "SQL Injection via Search Parameter", "Session Hijacking through XSS")
2. **Threat Actor**: External Attacker / Malicious Insider / Automated Bot / Competitor
3. **Attack Description** (6-8 bullet points):
   • How the attacker discovers and exploits the vulnerability
   • Tools and techniques used (Burp Suite, SQLMap, custom scripts, etc.)
   • Step-by-step attack execution with example payloads
   • Data or assets targeted
   • Potential for lateral movement or persistence
   • Real-world examples if applicable
4. **Impact Assessment**:
   • Confidentiality: Data exposed or stolen
   • Integrity: Data modified or corrupted
   • Availability: Service disruption potential
   • Business Impact: Financial loss, regulatory fines, reputation damage
5. **Likelihood**: High/Medium/Low with brief justification
6. **STRIDE Category**: Spoofing/Tampering/Repudiation/Information Disclosure/Denial of Service/Elevation of Privilege
7. **Mitigations** (5-6 specific controls):
   • Preventive controls with implementation details
   • Specific libraries/frameworks to use
   • Configuration recommendations
   • Monitoring and detection approaches
   • Verification methods (SAST, DAST, penetration testing)"""

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
                        "description": "• Attacker identifies login endpoint and tests for rate limiting weaknesses\n• Uses automated tools (Hydra, Burp Intruder) to submit thousands of password combinations\n• Bypasses weak rate limits by rotating IP addresses through proxy networks\n• Targets common passwords, dictionary words, and leaked credential databases\n• Successful compromise grants full access to victim's account and data\n• Can lead to lateral movement if user has elevated privileges",
                        "threat_actor": "External Attacker / Automated Bot",
                        "impact": "Critical",
                        "likelihood": "High",
                        "stride_category": "Spoofing",
                        "mitigations": [
                            "Implement progressive rate limiting: 5 attempts/minute per IP and username",
                            "Deploy CAPTCHA after 3 consecutive failed attempts",
                            "Implement account lockout with exponential backoff (15min, 1hr, 24hr)",
                            "Use Argon2id or bcrypt for password hashing with cost factor >= 12",
                            "Configure SIEM alerts for authentication anomalies",
                            "Enforce MFA for all user accounts"
                        ]
                    },
                    {
                        "title": "Credential Stuffing Attack",
                        "description": "• Attacker obtains leaked credentials from dark web or previous data breaches\n• Uses automated tools to test stolen username/password pairs against login endpoint\n• Exploits password reuse - approximately 65% of users reuse passwords across services\n• Rotates through proxy networks to avoid IP-based blocking\n• Successful attacks can compromise thousands of accounts rapidly\n• Similar to British Airways (2018) and Zoom (2020) credential stuffing incidents",
                        "threat_actor": "External Attacker / Organized Crime",
                        "impact": "Critical",
                        "likelihood": "High",
                        "stride_category": "Spoofing",
                        "mitigations": [
                            "Integrate HaveIBeenPwned API to detect compromised passwords",
                            "Implement device fingerprinting and behavioral anomaly detection",
                            "Require step-up authentication for logins from new devices/locations",
                            "Deploy WAF with bot detection and challenge capabilities",
                            "Monitor login velocity across the platform",
                            "Proactively reset passwords found in breach databases"
                        ]
                    },
                    {
                        "title": "Session Hijacking via Token Theft",
                        "description": "• Attacker intercepts session tokens through XSS, network sniffing, or malware\n• Tokens stored in localStorage/sessionStorage are vulnerable to JavaScript access\n• Network interception possible on unencrypted connections or compromised networks\n• Stolen token allows full impersonation without knowing user credentials\n• Attacker gains complete access to victim's account and permissions\n• Can perform unauthorized transactions or exfiltrate sensitive data",
                        "threat_actor": "External Attacker / Malicious Insider",
                        "impact": "High",
                        "likelihood": "Medium",
                        "stride_category": "Spoofing",
                        "mitigations": [
                            "Store tokens in httpOnly, secure, sameSite=strict cookies",
                            "Use short-lived access tokens (15 min) with refresh token rotation",
                            "Bind sessions to client fingerprint with re-auth on significant changes",
                            "Implement immediate token revocation on password change",
                            "Enforce TLS 1.3 with HSTS preload for all communications",
                            "Alert on concurrent sessions from different locations"
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
                        "description": "• Attacker injects malicious JavaScript into payment page via compromised third-party library or XSS\n• Script captures card numbers, CVV, and expiry dates as users enter them\n• Data silently exfiltrated to attacker-controlled server in real-time\n• Users and merchants unaware of theft until fraudulent transactions occur\n• Similar to British Airways breach (2018) affecting 380,000 cards\n• Results in PCI-DSS non-compliance and mandatory breach notification",
                        "threat_actor": "External Attacker / Organized Crime",
                        "impact": "Critical",
                        "likelihood": "Medium",
                        "stride_category": "Information Disclosure",
                        "mitigations": [
                            "Implement strict Content Security Policy (CSP) with script-src directives",
                            "Use Subresource Integrity (SRI) for all third-party JavaScript",
                            "Host payment forms on isolated subdomain with minimal dependencies",
                            "Use payment tokenization (Stripe Elements, Braintree) to avoid handling raw card data",
                            "Monitor JavaScript integrity with real-time change detection",
                            "Conduct regular security scans of all JavaScript dependencies"
                        ]
                    },
                    {
                        "title": "Transaction Amount Manipulation",
                        "description": "• Attacker intercepts checkout request using browser tools or proxy (Burp Suite)\n• Modifies price field in request body before submission to server\n• Changes $100.00 purchase to $1.00 if server trusts client-side pricing\n• Can be automated for large-scale fraud across multiple transactions\n• Results in direct financial loss and inventory discrepancies\n• Indicates fundamental flaw in payment flow architecture",
                        "threat_actor": "External Attacker / Fraudster",
                        "impact": "High",
                        "likelihood": "High",
                        "stride_category": "Tampering",
                        "mitigations": [
                            "Calculate all prices server-side from product catalog at checkout time",
                            "Sign cart contents with HMAC to detect any tampering",
                            "Validate submitted prices against database before processing",
                            "Log and alert on any price discrepancies",
                            "Implement velocity checks for unusual purchasing patterns",
                            "Use transaction signing for high-value purchases"
                        ]
                    },
                    {
                        "title": "Card Testing Fraud (Carding Attack)",
                        "description": "• Attacker uses automated scripts to test validity of stolen card numbers\n• Submits small transactions ($1-5) to verify which cards are active\n• Validated cards sold on dark web or used for larger fraudulent purchases\n• Results in high chargeback rates threatening payment processor relationship\n• Can process hundreds of card tests per hour without proper controls\n• Chargeback fees range from $15-100 per incident plus potential account termination",
                        "threat_actor": "External Attacker / Automated Bot",
                        "impact": "High",
                        "likelihood": "High",
                        "stride_category": "Tampering",
                        "mitigations": [
                            "Implement CAPTCHA after first failed payment attempt",
                            "Enable 3D Secure 2.0 for all card-not-present transactions",
                            "Enforce velocity limits: max 3 card attempts per session/IP",
                            "Deploy fraud detection ML (Stripe Radar, Signifyd)",
                            "Require AVS (Address Verification) and CVV match",
                            "Block known proxy/VPN IP ranges on payment endpoints"
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
                        "description": "• Attacker tests input fields with SQL syntax (single quotes, comments) to find vulnerable parameters\n• Injects malicious SQL via search boxes, login forms, or URL parameters\n• Can bypass authentication using payloads like: admin'-- or ' OR '1'='1\n• Extracts sensitive data using UNION SELECT queries or blind injection techniques\n• Complete database compromise possible - read, modify, or delete any data\n• May escalate to OS command execution on misconfigured database servers",
                        "threat_actor": "External Attacker",
                        "impact": "Critical",
                        "likelihood": "High",
                        "stride_category": "Tampering",
                        "mitigations": [
                            "Use parameterized queries/prepared statements exclusively",
                            "Implement ORM (SQLAlchemy, Hibernate) with parameterized queries",
                            "Apply input validation with whitelist approach",
                            "Use database accounts with minimal privileges",
                            "Deploy WAF rules for SQL injection patterns",
                            "Run regular SAST scans (Semgrep, SonarQube) for injection vulnerabilities"
                        ]
                    },
                    {
                        "title": "Cross-Site Scripting (XSS) Attack",
                        "description": "• Attacker injects malicious JavaScript through input fields that reflect content without encoding\n• Stored XSS persists in database and executes for all users viewing affected content\n• Reflected XSS delivered via malicious links sent to victims\n• Can steal session cookies, tokens, or perform actions as the victim user\n• Enables account takeover, data theft, and malware distribution\n• May spread virally if injected content is shared between users",
                        "threat_actor": "External Attacker",
                        "impact": "High",
                        "likelihood": "High",
                        "stride_category": "Information Disclosure",
                        "mitigations": [
                            "Implement context-aware output encoding (HTML, JavaScript, URL, CSS)",
                            "Use templating engines with auto-escaping (React, Angular, Jinja2)",
                            "Deploy Content Security Policy (CSP) with strict script-src",
                            "Set httpOnly and secure flags on session cookies",
                            "Use DOMPurify for sanitizing user-generated HTML content",
                            "Configure X-Content-Type-Options: nosniff header"
                        ]
                    },
                    {
                        "title": "Command Injection Attack",
                        "description": "• Attacker identifies functionality that executes system commands (file ops, network utilities)\n• Injects shell metacharacters to execute arbitrary commands on the server\n• Example: input of '8.8.8.8; cat /etc/passwd' in a ping function\n• Achieves remote code execution with application's privilege level\n• Can install backdoors, exfiltrate data, or pivot to other systems\n• Complete server compromise possible leading to ransomware deployment",
                        "threat_actor": "External Attacker",
                        "impact": "Critical",
                        "likelihood": "Medium",
                        "stride_category": "Elevation of Privilege",
                        "mitigations": [
                            "Avoid passing user input to system commands - use native libraries instead",
                            "If commands required, use strict allowlist validation",
                            "Run application with minimal OS privileges (non-root)",
                            "Implement container sandboxing to limit execution scope",
                            "Use subprocess with shell=False in Python",
                            "Deploy RASP for real-time command injection detection"
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
                        "description": "• Attacker uploads executable script disguised with innocent extension (shell.php.jpg)\n• Exploits weak validation that only checks file extension or trusts MIME type\n• Accesses uploaded file directly to execute arbitrary commands on server\n• Gains remote code execution with web application's privileges\n• Can install persistent backdoors, create admin accounts, or exfiltrate data\n• Average breach cost exceeds $4M including incident response and regulatory fines",
                        "threat_actor": "External Attacker",
                        "impact": "Critical",
                        "likelihood": "High",
                        "stride_category": "Elevation of Privilege",
                        "mitigations": [
                            "Validate file type using magic bytes, not extension or MIME type",
                            "Store uploads outside web root with randomized filenames",
                            "Serve files with Content-Disposition: attachment header",
                            "Implement antivirus scanning (ClamAV) on all uploads",
                            "Use separate domain for user content with no script execution",
                            "Re-encode images to remove any embedded executable code"
                        ]
                    },
                    {
                        "title": "Path Traversal via Filename Manipulation",
                        "description": "• Attacker crafts filename with directory traversal sequences (../../../)\n• Bypasses upload directory restrictions to write files anywhere on filesystem\n• Can overwrite application files, configuration, or system files\n• May achieve remote code execution by overwriting executable content\n• Results in data destruction, configuration tampering, or complete compromise\n• Indicates fundamental flaw in file handling implementation",
                        "threat_actor": "External Attacker",
                        "impact": "Critical",
                        "likelihood": "Medium",
                        "stride_category": "Tampering",
                        "mitigations": [
                            "Generate server-side filenames (UUID), never use client-provided names",
                            "Sanitize filenames by removing path separators and special characters",
                            "Validate resolved path is within intended upload directory",
                            "Use containerization to limit filesystem access scope",
                            "Set restrictive permissions on upload directory",
                            "Log all file operations with original and sanitized filenames"
                        ]
                    },
                    {
                        "title": "Denial of Service via Resource Exhaustion",
                        "description": "• Attacker floods upload endpoint with maximum-size files repeatedly\n• May use zip bombs that expand to massive sizes during processing\n• Exhausts disk space, memory, or processing capacity\n• Causes service unavailability for legitimate users\n• Results in infrastructure costs and SLA violations\n• Can be automated for sustained attack with minimal attacker resources",
                        "threat_actor": "External Attacker / Competitor",
                        "impact": "High",
                        "likelihood": "Medium",
                        "stride_category": "Denial of Service",
                        "mitigations": [
                            "Enforce file size limits at web server level (10MB default)",
                            "Use streaming processing to reject oversized files early",
                            "Implement per-user and per-IP upload quotas",
                            "Detect archive bombs by limiting decompression ratio",
                            "Use separate storage volume with quota limits",
                            "Apply rate limiting on upload endpoints"
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
                        "description": "• Attacker manipulates resource IDs in API requests to access other users' data\n• Changes /api/users/123/orders to /api/users/124/orders to view another user's orders\n• API returns data without verifying the requestor owns the requested resource\n• Can enumerate through sequential IDs to extract data at scale\n• Results in mass data exposure and privacy violations\n• BOLA is the #1 API vulnerability according to OWASP API Security Top 10",
                        "threat_actor": "External Attacker / Malicious User",
                        "impact": "Critical",
                        "likelihood": "High",
                        "stride_category": "Information Disclosure",
                        "mitigations": [
                            "Implement object-level authorization on every API endpoint",
                            "Use indirect references instead of direct database IDs",
                            "Verify resource ownership against authenticated user context",
                            "Use UUIDs instead of sequential IDs to prevent enumeration",
                            "Add automated BOLA testing to CI/CD pipeline",
                            "Monitor and alert on unusual access patterns"
                        ]
                    },
                    {
                        "title": "API Rate Limiting Bypass and Abuse",
                        "description": "• Attacker identifies rate limiting gaps by testing request volumes\n• Bypasses limits using IP rotation, API key cycling, or header manipulation\n• Overwhelms API causing service degradation for legitimate users\n• May scrape entire databases through paginated endpoints\n• Results in infrastructure costs and potential data theft\n• Causes SLA violations and customer impact",
                        "threat_actor": "External Attacker / Automated Bot",
                        "impact": "High",
                        "likelihood": "High",
                        "stride_category": "Denial of Service",
                        "mitigations": [
                            "Implement tiered rate limiting: per-IP, per-user, per-API-key",
                            "Use token bucket or sliding window rate limiting algorithms",
                            "Deploy API gateway with DDoS protection",
                            "Implement request signing to prevent replay attacks",
                            "Monitor and alert on unusual traffic patterns",
                            "Add CAPTCHA for sensitive operations after threshold"
                        ]
                    },
                    {
                        "title": "Mass Assignment / Excessive Data Exposure",
                        "description": "• Attacker adds unauthorized fields to API requests (role, permissions, balance)\n• API blindly binds request body to database model without filtering\n• Can escalate privileges by setting admin role or modify financial data\n• API responses may expose sensitive fields not intended for client\n• Results in unauthorized access and data integrity violations\n• Indicates missing input validation and response filtering",
                        "threat_actor": "External Attacker / Malicious User",
                        "impact": "High",
                        "likelihood": "Medium",
                        "stride_category": "Tampering",
                        "mitigations": [
                            "Define explicit allowlist of modifiable fields per endpoint",
                            "Use DTOs/schemas with only intended fields (Pydantic, Marshmallow)",
                            "Never bind request body directly to database models",
                            "Remove sensitive fields from API responses",
                            "Implement field-level authorization for sensitive attributes",
                            "Document and security review all API fields"
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
