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
    DEFAULT_ABUSE_CASE_PROMPT = """Generate 4-5 abuse cases. Each must have: threat title, actor, 2-3 sentence description with attack tools (Burp Suite, SQLMap, etc.), impact level, STRIDE category, and 3 specific mitigations."""

    DEFAULT_SECURITY_REQ_PROMPT = """Generate 6-8 security requirements covering: Authentication, Input Validation, Cryptography, Logging, Rate Limiting, API Security. Each must include: requirement title, priority, category, and implementation details with library names (bcrypt, argon2), CWE-XXX reference, and OWASP reference."""

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
      "threat": "Short threat title",
      "actor": "Who performs the attack",
      "description": "2-3 sentence attack description with tools used",
      "impact": "Critical/High/Medium/Low",
      "likelihood": "High/Medium/Low",
      "stride_category": "Spoofing/Tampering/Repudiation/Information Disclosure/Denial of Service/Elevation of Privilege",
      "mitigations": ["Specific mitigation 1", "Specific mitigation 2", "Specific mitigation 3"]
    }}
  ],
  "stride_threats": [
    {{"category": "Spoofing", "threat": "Threat name", "description": "Brief description", "risk_level": "Critical/High/Medium/Low"}}
  ],
  "security_requirements": [
    {{
      "id": "SR-001",
      "text": "Requirement title",
      "priority": "Critical/High/Medium/Low",
      "category": "Authentication/Input Validation/Cryptography/Logging/Rate Limiting/API Security",
      "details": "Implementation details with library names, CWE-XXX, OWASP reference"
    }}
  ],
  "risk_score": 75
}}

Generate 4-5 abuse_cases and 6-8 security_requirements specific to: {title}
Return ONLY valid JSON."""

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
                        "title": "Brute Force Attack",
                        "description": "An attacker attempts multiple password combinations to gain unauthorized access",
                        "threat_actor": "External Attacker",
                        "impact": "high",
                        "likelihood": "high"
                    },
                    {
                        "title": "Credential Stuffing",
                        "description": "Attacker uses leaked credentials from other breaches to access accounts",
                        "threat_actor": "External Attacker",
                        "impact": "high",
                        "likelihood": "medium"
                    }
                ],
                "stride_threats": {
                    "S": [{"threat": "Attacker spoofs legitimate user identity", "mitigation": "Implement MFA"}],
                    "I": [{"threat": "Password exposed in transit or logs", "mitigation": "Use HTTPS, never log credentials"}],
                    "E": [{"threat": "Privilege escalation via authentication bypass", "mitigation": "Implement proper session management"}]
                },
                "requirements": [
                    {"category": "Authentication", "requirement": "Implement rate limiting on authentication endpoints", "priority": "must"},
                    {"category": "Authentication", "requirement": "Enforce strong password policy (min 12 chars, complexity)", "priority": "must"},
                    {"category": "Authentication", "requirement": "Implement account lockout after failed attempts", "priority": "must"},
                    {"category": "Logging", "requirement": "Log all authentication attempts with timestamp and IP", "priority": "should"}
                ],
                "risk_factor": {"factor": "Authentication", "score": 20, "description": "Feature involves user authentication"}
            })

        # Payment/Financial patterns
        payment_keywords = ["payment", "credit card", "transaction", "purchase", "billing", "checkout"]
        if any(kw in text for kw in payment_keywords):
            patterns.append({
                "abuse_cases": [
                    {
                        "title": "Payment Fraud",
                        "description": "Attacker uses stolen payment credentials for unauthorized purchases",
                        "threat_actor": "External Attacker",
                        "impact": "high",
                        "likelihood": "medium"
                    }
                ],
                "stride_threats": {
                    "T": [{"threat": "Transaction amount manipulation", "mitigation": "Server-side validation of all amounts"}],
                    "R": [{"threat": "User denies making transaction", "mitigation": "Implement transaction logging and receipts"}],
                    "I": [{"threat": "Payment data exposure", "mitigation": "Use tokenization, never store full card numbers"}]
                },
                "requirements": [
                    {"category": "Data Protection", "requirement": "Never store full credit card numbers (PCI-DSS compliance)", "priority": "must"},
                    {"category": "Input Validation", "requirement": "Validate all transaction amounts server-side", "priority": "must"},
                    {"category": "Logging", "requirement": "Maintain audit trail for all financial transactions", "priority": "must"}
                ],
                "risk_factor": {"factor": "Financial Data", "score": 25, "description": "Feature handles financial transactions"}
            })

        # Data input patterns
        input_keywords = ["form", "input", "submit", "upload", "enter", "search", "query"]
        if any(kw in text for kw in input_keywords):
            patterns.append({
                "abuse_cases": [
                    {
                        "title": "Injection Attack",
                        "description": "Attacker injects malicious code through user input fields",
                        "threat_actor": "External Attacker",
                        "impact": "high",
                        "likelihood": "high"
                    }
                ],
                "stride_threats": {
                    "T": [{"threat": "SQL/NoSQL injection to modify data", "mitigation": "Use parameterized queries"}],
                    "I": [{"threat": "Data extraction via injection", "mitigation": "Input validation and sanitization"}]
                },
                "requirements": [
                    {"category": "Input Validation", "requirement": "Validate and sanitize all user inputs", "priority": "must"},
                    {"category": "Input Validation", "requirement": "Use parameterized queries for database operations", "priority": "must"},
                    {"category": "Input Validation", "requirement": "Implement input length limits", "priority": "should"}
                ],
                "risk_factor": {"factor": "User Input", "score": 15, "description": "Feature accepts user input"}
            })

        # File upload patterns
        if "upload" in text or "file" in text:
            patterns.append({
                "abuse_cases": [
                    {
                        "title": "Malicious File Upload",
                        "description": "Attacker uploads malware or web shell disguised as legitimate file",
                        "threat_actor": "External Attacker",
                        "impact": "high",
                        "likelihood": "medium"
                    }
                ],
                "stride_threats": {
                    "T": [{"threat": "Malicious file execution", "mitigation": "Validate file types, scan for malware"}],
                    "D": [{"threat": "Storage exhaustion via large uploads", "mitigation": "Implement file size limits"}]
                },
                "requirements": [
                    {"category": "Input Validation", "requirement": "Validate file types using magic bytes, not just extension", "priority": "must"},
                    {"category": "Input Validation", "requirement": "Scan uploaded files for malware", "priority": "should"},
                    {"category": "Input Validation", "requirement": "Limit file upload size", "priority": "must"}
                ],
                "risk_factor": {"factor": "File Upload", "score": 20, "description": "Feature allows file uploads"}
            })

        # API patterns
        api_keywords = ["api", "endpoint", "rest", "graphql", "webhook"]
        if any(kw in text for kw in api_keywords):
            patterns.append({
                "stride_threats": {
                    "S": [{"threat": "API key theft or spoofing", "mitigation": "Implement proper API authentication"}],
                    "D": [{"threat": "API abuse causing service degradation", "mitigation": "Implement rate limiting"}]
                },
                "requirements": [
                    {"category": "Authentication", "requirement": "Implement API authentication (OAuth2/API keys)", "priority": "must"},
                    {"category": "Authorization", "requirement": "Implement rate limiting on API endpoints", "priority": "must"},
                    {"category": "Logging", "requirement": "Log all API calls with authentication context", "priority": "should"}
                ],
                "risk_factor": {"factor": "API Exposure", "score": 15, "description": "Feature exposes API endpoints"}
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
