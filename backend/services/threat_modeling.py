"""
Enhanced Threat Modeling Service
- AI-Powered Architecture Analysis with Claude
- Technology-Specific STRIDE Threats with Risk Scoring
- Comprehensive MITRE ATT&CK Mapping
- Professional DFD Generation
- Attack Path Analysis
- Multi-Provider Support (OpenAI, Anthropic, Azure, Google, Ollama)
- Eraser AI Professional Diagram Generation
"""
from typing import Dict, List, Any, Optional, Tuple
import re
import json
import os
import logging
import asyncio
from datetime import datetime

logger = logging.getLogger(__name__)


class ThreatModelingService:
    """Professional threat modeling with AI-powered analysis"""

    def __init__(self, ai_config=None, enable_eraser_diagrams: bool = True):
        """
        Initialize threat modeling service.

        Args:
            ai_config: Optional AIConfig object. If None, uses global settings.
            enable_eraser_diagrams: Enable Eraser AI professional diagram generation.
        """
        self._ai_client = None
        self.enabled = False
        self.provider = "none"
        self.model = "none"
        self._init_client(ai_config)

        # Initialize Eraser diagram service
        self._eraser_service = None
        self.eraser_enabled = False
        if enable_eraser_diagrams:
            self._init_eraser_service()

    def _init_client(self, ai_config=None):
        """Initialize AI client from config or global settings"""
        try:
            from services.ai_client_factory import get_ai_client, get_global_ai_config

            config = ai_config if ai_config else get_global_ai_config()

            if config.api_key:
                self._ai_client = get_ai_client(config)
                self.enabled = self._ai_client.is_configured
                self.provider = config.provider
                self.model = self._ai_client.model
                logger.info(f"[ThreatModelingService] Initialized with {self.provider}, model={self.model}")
            else:
                logger.warning("[ThreatModelingService] No API key configured, using fallback templates")
        except Exception as e:
            logger.warning(f"[ThreatModelingService] Failed to initialize AI client: {e}")

    def _init_eraser_service(self):
        """Initialize Eraser AI diagram service"""
        try:
            from services.eraser_diagram_service import EraserDiagramService
            self._eraser_service = EraserDiagramService()
            self.eraser_enabled = self._eraser_service.enabled
            if self.eraser_enabled:
                logger.info("[ThreatModelingService] Eraser AI diagram service enabled")
            else:
                logger.info("[ThreatModelingService] Eraser API key not configured, using Mermaid diagrams")
        except Exception as e:
            logger.warning(f"[ThreatModelingService] Failed to initialize Eraser service: {e}")
            self.eraser_enabled = False

    def update_config(self, ai_config) -> None:
        """Update AI configuration"""
        self._init_client(ai_config)

    # Legacy property for backward compatibility
    @property
    def anthropic_client(self):
        """Backward compatibility - returns True if AI is configured"""
        return self._ai_client if self.enabled else None

    def _enrich_threat_with_ai(self, threat: Dict, component: Dict, system_context: str) -> Dict:
        """Use AI to generate rich, contextual threat details"""
        if not self.enabled or not self._ai_client:
            return self._get_fallback_threat_details(threat, component)

        prompt = f"""You are a senior application security expert performing threat modeling. Analyze this specific threat and provide detailed, contextual information.

SYSTEM CONTEXT:
{system_context}

COMPONENT BEING ANALYZED:
- Name: {component.get('name', 'Unknown')}
- Type: {component.get('type', 'process')}
- Category: {component.get('category', 'api')}
- Technology: {component.get('technology', 'Unknown')}
- Internet Facing: {component.get('internet_facing', False)}
- Handles Sensitive Data: {component.get('handles_sensitive_data', False)}
- Trust Level: {component.get('trust_level', 'trusted')}
- Data Handled: {component.get('data_handled', [])}

THREAT TO ANALYZE:
- Threat Name: {threat.get('threat', 'Unknown')}
- STRIDE Category: {threat.get('category', 'Unknown')}
- Severity: {threat.get('severity', 'medium')}
- CWE: {threat.get('cwe', 'N/A')}
- MITRE Techniques: {threat.get('mitre_techniques', [])}

Provide a detailed JSON response with the following structure. Be SPECIFIC to this component and system - do not give generic advice:
{{
    "description": "A detailed 2-3 sentence description of how this specific threat applies to this component in this system",
    "attack_vector": {{
        "description": "Detailed explanation of how an attacker would exploit this vulnerability in this specific component",
        "entry_points": ["List of specific entry points for this attack on this component"],
        "techniques": ["Specific attack techniques that could be used"]
    }},
    "business_impact": {{
        "financial": "Specific financial impact if this threat is realized",
        "reputational": "Reputational damage assessment",
        "operational": "Operational impact on business",
        "compliance": "Regulatory and compliance implications"
    }},
    "affected_assets": ["List of specific assets at risk"],
    "prerequisites": {{
        "access_required": "What access level an attacker needs",
        "conditions": ["List of conditions that must be true for this attack to succeed"]
    }},
    "attack_complexity": {{
        "level": "Low/Medium/High",
        "skill_level": "Basic/Intermediate/Advanced",
        "time_required": "Estimated time to execute",
        "description": "Why this complexity level"
    }},
    "mitigation": "Specific, actionable mitigation recommendations for this component",
    "detection": "How to detect this attack in progress or after the fact"
}}

Be specific and technical. Reference the actual component name and technology."""

        try:
            messages = [{"role": "user", "content": prompt}]
            response = self._ai_client.chat_completion(
                messages=messages,
                max_tokens=2000
            )

            response_text = response['content']
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                enriched = json.loads(json_match.group())
                return enriched
        except Exception as e:
            logger.warning(f"[ThreatModelingService] AI threat enrichment failed: {e}")

        return self._get_fallback_threat_details(threat, component)

    def _get_fallback_threat_details(self, threat: Dict, component: Dict) -> Dict:
        """Fallback when AI is not available"""
        return {
            "description": f"{threat.get('threat', 'Security threat')} affecting {component.get('name', 'component')}",
            "attack_vector": self._get_attack_vector(threat, component),
            "business_impact": self._get_business_impact(threat, component),
            "affected_assets": self._get_affected_assets(component),
            "prerequisites": self._get_attack_prerequisites(threat, component),
            "attack_complexity": self._get_attack_complexity(threat),
            "mitigation": self._generate_mitigation(threat, component),
            "detection": self._generate_detection_guidance(threat)
        }

    def _generate_attack_path_with_ai(self, path_names: List[str], threats: List[Dict],
                                       entry: Dict, target: Dict, system_context: str) -> Dict:
        """Use AI to generate detailed attack path analysis"""
        if not self.enabled or not self._ai_client:
            return self._get_fallback_attack_path(path_names, threats, entry, target)

        threats_summary = "\n".join([
            f"- {t.get('threat', 'Unknown')} ({t.get('severity', 'medium')}) at {t.get('component', 'unknown')}"
            for t in threats[:5]
        ])

        prompt = f"""You are a senior penetration tester analyzing an attack path through a system. Generate a detailed attack path analysis.

SYSTEM CONTEXT:
{system_context}

ATTACK PATH:
Entry Point: {entry.get('name', 'Unknown')} ({entry.get('category', 'unknown')})
Target: {target.get('name', 'Unknown')} ({target.get('category', 'unknown')})
Path: {' → '.join(path_names)}

THREATS ALONG THIS PATH:
{threats_summary}

Generate a detailed JSON response:
{{
    "attack_scenario": "A compelling 3-4 sentence narrative describing how an attacker would exploit this path, referencing specific components and threats",
    "exploitation_steps": [
        {{
            "step": 1,
            "phase": "Reconnaissance/Initial Access/Lateral Movement/Privilege Escalation/Objective",
            "action": "Brief action description",
            "details": "Detailed explanation of what the attacker does at this step, tools they might use, and what they gain"
        }}
    ],
    "potential_impact": {{
        "level": "Critical/High/Medium/Low",
        "description": "Overall impact description",
        "data_exposure": "What data could be exposed",
        "system_impact": "Impact on system availability/integrity",
        "business_impact": "Business consequences",
        "compliance_impact": "Regulatory implications"
    }},
    "difficulty": {{
        "level": "Low/Medium/High",
        "description": "Why this difficulty level",
        "required_skills": "Skills needed to execute this attack",
        "time_estimate": "Estimated time to execute",
        "tools_needed": ["List of tools an attacker might use"]
    }},
    "detection_opportunities": [
        {{
            "point": "Where in the attack chain this can be detected",
            "method": "How to detect it",
            "effectiveness": "High/Medium/Low"
        }}
    ],
    "recommended_controls": [
        {{
            "control": "Security control name",
            "implementation": "Specific implementation guidance",
            "priority": "Critical/High/Medium"
        }}
    ]
}}

Be specific to this system and path. Reference actual component names."""

        try:
            messages = [{"role": "user", "content": prompt}]
            response = self._ai_client.chat_completion(
                messages=messages,
                max_tokens=3000
            )

            response_text = response['content']
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"[ThreatModelingService] AI attack path generation failed: {e}")

        return self._get_fallback_attack_path(path_names, threats, entry, target)

    def _get_fallback_attack_path(self, path_names: List[str], threats: List[Dict],
                                   entry: Dict, target: Dict) -> Dict:
        """Fallback attack path details when AI is not available"""
        return {
            "attack_scenario": self._generate_attack_scenario(entry, target, path_names, threats),
            "exploitation_steps": self._generate_exploitation_steps(path_names, threats),
            "potential_impact": self._generate_path_impact(target, threats),
            "difficulty": self._assess_path_difficulty(threats),
            "detection_opportunities": self._identify_detection_points(path_names, threats),
            "recommended_controls": self._recommend_path_controls(threats)
        }

    def _build_system_context(self, parsed_arch: Dict) -> str:
        """Build a system context string for AI prompts"""
        components = parsed_arch.get('components', [])
        data_flows = parsed_arch.get('data_flows', [])
        tech_stack = parsed_arch.get('technology_stack', [])

        context_parts = [
            f"System Overview: {parsed_arch.get('system_overview', 'Web application')}",
            f"Technology Stack: {', '.join(tech_stack) if tech_stack else 'Not specified'}",
            f"\nComponents ({len(components)}):"
        ]

        for comp in components[:10]:  # Limit to 10 components for context length
            context_parts.append(
                f"- {comp.get('name', 'Unknown')} ({comp.get('category', 'unknown')}): "
                f"{'Internet-facing' if comp.get('internet_facing') else 'Internal'}, "
                f"{'Handles sensitive data' if comp.get('handles_sensitive_data') else 'Standard data'}"
            )

        context_parts.append(f"\nData Flows ({len(data_flows)}):")
        for flow in data_flows[:8]:  # Limit flows
            context_parts.append(
                f"- {flow.get('from', '?')} → {flow.get('to', '?')}: "
                f"{'Encrypted' if flow.get('encrypted') else 'Unencrypted'}, "
                f"{'Authenticated' if flow.get('authenticated') else 'Unauthenticated'}"
            )

        return "\n".join(context_parts)

    # STRIDE Categories with detailed descriptions
    STRIDE_CATEGORIES = {
        "Spoofing": {
            "description": "Pretending to be someone or something other than yourself",
            "icon": "👤",
            "color": "#ef4444"
        },
        "Tampering": {
            "description": "Modifying data or code without authorization",
            "icon": "✏️",
            "color": "#f97316"
        },
        "Repudiation": {
            "description": "Claiming to not have performed an action",
            "icon": "🙈",
            "color": "#eab308"
        },
        "Information Disclosure": {
            "description": "Exposing information to unauthorized parties",
            "icon": "👁️",
            "color": "#22c55e"
        },
        "Denial of Service": {
            "description": "Denying access to valid users",
            "icon": "🚫",
            "color": "#3b82f6"
        },
        "Elevation of Privilege": {
            "description": "Gaining capabilities without proper authorization",
            "icon": "⬆️",
            "color": "#8b5cf6"
        }
    }

    # Comprehensive MITRE ATT&CK techniques for web applications
    MITRE_TECHNIQUES = {
        # Initial Access
        "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1190/"},
        "T1133": {"name": "External Remote Services", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1133/"},
        "T1566": {"name": "Phishing", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/"},
        "T1195": {"name": "Supply Chain Compromise", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1195/"},
        # Execution
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/"},
        "T1203": {"name": "Exploitation for Client Execution", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1203/"},
        "T1047": {"name": "Windows Management Instrumentation", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1047/"},
        # Persistence
        "T1078": {"name": "Valid Accounts", "tactic": "Persistence", "url": "https://attack.mitre.org/techniques/T1078/"},
        "T1136": {"name": "Create Account", "tactic": "Persistence", "url": "https://attack.mitre.org/techniques/T1136/"},
        "T1505": {"name": "Server Software Component", "tactic": "Persistence", "url": "https://attack.mitre.org/techniques/T1505/"},
        # Privilege Escalation
        "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1068/"},
        "T1055": {"name": "Process Injection", "tactic": "Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1055/"},
        "T1134": {"name": "Access Token Manipulation", "tactic": "Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1134/"},
        # Defense Evasion
        "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1070/"},
        "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1027/"},
        # Credential Access
        "T1110": {"name": "Brute Force", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1110/"},
        "T1212": {"name": "Exploitation for Credential Access", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1212/"},
        "T1557": {"name": "Adversary-in-the-Middle", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1557/"},
        "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1552/"},
        "T1539": {"name": "Steal Web Session Cookie", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1539/"},
        # Discovery
        "T1087": {"name": "Account Discovery", "tactic": "Discovery", "url": "https://attack.mitre.org/techniques/T1087/"},
        "T1082": {"name": "System Information Discovery", "tactic": "Discovery", "url": "https://attack.mitre.org/techniques/T1082/"},
        # Lateral Movement
        "T1021": {"name": "Remote Services", "tactic": "Lateral Movement", "url": "https://attack.mitre.org/techniques/T1021/"},
        # Collection
        "T1530": {"name": "Data from Cloud Storage", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1530/"},
        "T1213": {"name": "Data from Information Repositories", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1213/"},
        # Exfiltration
        "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1041/"},
        "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1567/"},
        # Impact
        "T1498": {"name": "Network Denial of Service", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1498/"},
        "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1499/"},
        "T1565": {"name": "Data Manipulation", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1565/"},
        "T1485": {"name": "Data Destruction", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1485/"},
        "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1486/"},
    }

    # Technology-specific threat templates
    TECHNOLOGY_THREATS = {
        "api": {
            "Spoofing": [
                {"threat": "API Key Theft/Replay", "severity": "high", "cwe": "CWE-294", "mitre": ["T1078", "T1539"]},
                {"threat": "JWT Token Forgery", "severity": "critical", "cwe": "CWE-347", "mitre": ["T1134"]},
                {"threat": "OAuth Token Hijacking", "severity": "high", "cwe": "CWE-384", "mitre": ["T1539"]},
            ],
            "Tampering": [
                {"threat": "Parameter Tampering", "severity": "high", "cwe": "CWE-472", "mitre": ["T1565"]},
                {"threat": "Request Smuggling", "severity": "critical", "cwe": "CWE-444", "mitre": ["T1190"]},
                {"threat": "Mass Assignment Vulnerability", "severity": "high", "cwe": "CWE-915", "mitre": ["T1565"]},
            ],
            "Information Disclosure": [
                {"threat": "Excessive Data Exposure", "severity": "high", "cwe": "CWE-200", "mitre": ["T1213"]},
                {"threat": "API Error Information Leakage", "severity": "medium", "cwe": "CWE-209", "mitre": ["T1082"]},
                {"threat": "Broken Object Level Authorization (BOLA)", "severity": "critical", "cwe": "CWE-639", "mitre": ["T1213"]},
            ],
            "Elevation of Privilege": [
                {"threat": "Broken Function Level Authorization", "severity": "high", "cwe": "CWE-285", "mitre": ["T1068"]},
                {"threat": "IDOR Vulnerability", "severity": "high", "cwe": "CWE-639", "mitre": ["T1078"]},
            ],
        },
        "database": {
            "Spoofing": [
                {"threat": "Database Credential Compromise", "severity": "critical", "cwe": "CWE-522", "mitre": ["T1552"]},
            ],
            "Tampering": [
                {"threat": "SQL Injection", "severity": "critical", "cwe": "CWE-89", "mitre": ["T1190", "T1565"]},
                {"threat": "NoSQL Injection", "severity": "critical", "cwe": "CWE-943", "mitre": ["T1190"]},
                {"threat": "Stored XSS via Database", "severity": "high", "cwe": "CWE-79", "mitre": ["T1059"]},
            ],
            "Information Disclosure": [
                {"threat": "Unencrypted Sensitive Data at Rest", "severity": "high", "cwe": "CWE-311", "mitre": ["T1530"]},
                {"threat": "Database Backup Exposure", "severity": "high", "cwe": "CWE-530", "mitre": ["T1530"]},
                {"threat": "Insufficient Column-Level Security", "severity": "medium", "cwe": "CWE-653", "mitre": ["T1213"]},
            ],
            "Denial of Service": [
                {"threat": "Resource-Intensive Query Attack", "severity": "medium", "cwe": "CWE-400", "mitre": ["T1499"]},
                {"threat": "Connection Pool Exhaustion", "severity": "medium", "cwe": "CWE-770", "mitre": ["T1499"]},
            ],
        },
        "authentication": {
            "Spoofing": [
                {"threat": "Credential Stuffing Attack", "severity": "high", "cwe": "CWE-307", "mitre": ["T1110"]},
                {"threat": "Password Spraying", "severity": "high", "cwe": "CWE-307", "mitre": ["T1110"]},
                {"threat": "Session Fixation", "severity": "high", "cwe": "CWE-384", "mitre": ["T1539"]},
                {"threat": "Weak Password Policy", "severity": "medium", "cwe": "CWE-521", "mitre": ["T1110"]},
            ],
            "Repudiation": [
                {"threat": "Insufficient Login Attempt Logging", "severity": "medium", "cwe": "CWE-778", "mitre": ["T1070"]},
                {"threat": "Missing Security Event Audit Trail", "severity": "medium", "cwe": "CWE-223", "mitre": ["T1070"]},
            ],
            "Elevation of Privilege": [
                {"threat": "Privilege Escalation via Role Manipulation", "severity": "critical", "cwe": "CWE-269", "mitre": ["T1068"]},
                {"threat": "Insecure Direct Object Reference", "severity": "high", "cwe": "CWE-639", "mitre": ["T1078"]},
            ],
        },
        "frontend": {
            "Spoofing": [
                {"threat": "Phishing via Cloned Interface", "severity": "medium", "cwe": "CWE-451", "mitre": ["T1566"]},
            ],
            "Tampering": [
                {"threat": "Cross-Site Scripting (XSS)", "severity": "high", "cwe": "CWE-79", "mitre": ["T1059"]},
                {"threat": "DOM-based XSS", "severity": "high", "cwe": "CWE-79", "mitre": ["T1059"]},
                {"threat": "Client-Side Template Injection", "severity": "high", "cwe": "CWE-94", "mitre": ["T1059"]},
            ],
            "Information Disclosure": [
                {"threat": "Sensitive Data in Browser Storage", "severity": "medium", "cwe": "CWE-922", "mitre": ["T1539"]},
                {"threat": "Source Map Exposure", "severity": "low", "cwe": "CWE-200", "mitre": ["T1082"]},
            ],
            "Denial of Service": [
                {"threat": "Client-Side Resource Exhaustion", "severity": "low", "cwe": "CWE-400", "mitre": ["T1499"]},
            ],
        },
        "microservice": {
            "Spoofing": [
                {"threat": "Service Identity Spoofing", "severity": "high", "cwe": "CWE-290", "mitre": ["T1078"]},
                {"threat": "mTLS Certificate Theft", "severity": "critical", "cwe": "CWE-295", "mitre": ["T1552"]},
            ],
            "Tampering": [
                {"threat": "Service Mesh Configuration Tampering", "severity": "high", "cwe": "CWE-94", "mitre": ["T1565"]},
                {"threat": "Inter-Service Message Modification", "severity": "high", "cwe": "CWE-345", "mitre": ["T1557"]},
            ],
            "Information Disclosure": [
                {"threat": "Service Discovery Information Leak", "severity": "medium", "cwe": "CWE-200", "mitre": ["T1082"]},
                {"threat": "Distributed Tracing Data Exposure", "severity": "medium", "cwe": "CWE-532", "mitre": ["T1213"]},
            ],
        },
        "cloud": {
            "Spoofing": [
                {"threat": "IAM Role Assumption Attack", "severity": "critical", "cwe": "CWE-269", "mitre": ["T1078"]},
                {"threat": "Cloud Metadata Service Abuse", "severity": "critical", "cwe": "CWE-918", "mitre": ["T1552"]},
            ],
            "Tampering": [
                {"threat": "Cloud Resource Misconfiguration", "severity": "high", "cwe": "CWE-1188", "mitre": ["T1565"]},
                {"threat": "Infrastructure as Code Injection", "severity": "critical", "cwe": "CWE-94", "mitre": ["T1195"]},
            ],
            "Information Disclosure": [
                {"threat": "Public S3/Blob Storage Exposure", "severity": "critical", "cwe": "CWE-552", "mitre": ["T1530"]},
                {"threat": "Secrets in Environment Variables", "severity": "high", "cwe": "CWE-312", "mitre": ["T1552"]},
            ],
        },
        "message_queue": {
            "Spoofing": [
                {"threat": "Message Producer Impersonation", "severity": "high", "cwe": "CWE-290", "mitre": ["T1078"]},
            ],
            "Tampering": [
                {"threat": "Message Content Manipulation", "severity": "high", "cwe": "CWE-345", "mitre": ["T1565"]},
                {"threat": "Message Replay Attack", "severity": "medium", "cwe": "CWE-294", "mitre": ["T1557"]},
            ],
            "Denial of Service": [
                {"threat": "Queue Flooding Attack", "severity": "high", "cwe": "CWE-400", "mitre": ["T1499"]},
                {"threat": "Poison Message Attack", "severity": "medium", "cwe": "CWE-400", "mitre": ["T1499"]},
            ],
        },
    }

    def analyze_architecture_with_ai(self, architecture_doc: str, architecture_diagram: Optional[str] = None,
                                     diagram_media_type: str = "image/png") -> Dict[str, Any]:
        """Use AI to deeply analyze architecture and extract components with context"""

        if not self.enabled or not self._ai_client:
            # Fallback to basic parsing if no AI available
            logger.info("[ThreatModeling] AI not available, using basic parsing")
            return self._parse_architecture_basic(architecture_doc)

        prompt = f"""Analyze this software architecture and extract a detailed threat model structure.

ARCHITECTURE DESCRIPTION:
{architecture_doc}

Please provide a comprehensive JSON response with the following structure:
{{
    "system_overview": "Brief description of what the system does",
    "technology_stack": ["list", "of", "technologies"],
    "components": [
        {{
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
        }}
    ],
    "data_flows": [
        {{
            "id": "flow_id",
            "from": "source_component_id",
            "to": "target_component_id",
            "data_type": "What data flows",
            "protocol": "HTTP/HTTPS/gRPC/SQL/etc",
            "encrypted": true/false,
            "authenticated": true/false,
            "sensitive": true/false
        }}
    ],
    "trust_boundaries": [
        {{
            "id": "boundary_id",
            "name": "Boundary Name",
            "description": "What this boundary separates",
            "components_inside": ["list of component_ids inside this boundary"],
            "boundary_type": "internet|dmz|internal|data"
        }}
    ],
    "security_controls": ["list of mentioned security controls"],
    "risk_factors": ["identified risk factors from the architecture"]
}}

Be thorough and extract all components, even if implied. Identify ALL data flows between components.
For each component, determine the most appropriate category from: api, database, authentication, frontend, microservice, cloud, message_queue.
"""

        try:
            # Use the unified chat_completion interface
            messages = [
                {"role": "user", "content": prompt}
            ]

            logger.info(f"[ThreatModeling] Calling AI for architecture analysis (provider={self.provider})")
            response = self._ai_client.chat_completion(
                messages=messages,
                max_tokens=4000,
                temperature=0.3
            )

            # Extract JSON from response
            response_text = response.get("content", "")
            logger.info(f"[ThreatModeling] AI response received, length={len(response_text)}")

            # Try to find JSON in the response
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                parsed = json.loads(json_match.group())
                logger.info(f"[ThreatModeling] Parsed {len(parsed.get('components', []))} components from AI response")
                return parsed
            else:
                logger.warning("[ThreatModeling] No JSON found in AI response, using basic parsing")
                return self._parse_architecture_basic(architecture_doc)

        except Exception as e:
            logger.error(f"[ThreatModeling] AI analysis failed: {e}, falling back to basic parsing")
            return self._parse_architecture_basic(architecture_doc)

    def _parse_architecture_basic(self, architecture_doc: str) -> Dict[str, Any]:
        """Fallback basic parsing when AI is not available"""
        components = []
        data_flows = []
        trust_boundaries = []

        lines = architecture_doc.lower().split('\n')
        component_id = 0

        # Enhanced keyword detection
        component_keywords = {
            'api': ['api', 'rest', 'graphql', 'endpoint', 'gateway', 'service'],
            'database': ['database', 'db', 'sql', 'postgresql', 'mysql', 'mongodb', 'redis', 'cache', 'storage'],
            'authentication': ['auth', 'login', 'identity', 'oauth', 'sso', 'jwt', 'session'],
            'frontend': ['frontend', 'web', 'ui', 'react', 'angular', 'vue', 'client', 'browser', 'mobile'],
            'microservice': ['microservice', 'container', 'kubernetes', 'docker', 'pod'],
            'cloud': ['aws', 'azure', 'gcp', 'cloud', 's3', 'lambda', 'ec2'],
            'message_queue': ['kafka', 'rabbitmq', 'sqs', 'queue', 'message', 'event', 'pub/sub'],
        }

        type_keywords = {
            'external': ['user', 'client', 'browser', 'mobile', 'third-party', 'external', 'customer'],
            'datastore': ['database', 'db', 'cache', 'storage', 'redis', 's3', 'bucket'],
        }

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Determine component type
            comp_type = 'process'
            for t, keywords in type_keywords.items():
                if any(kw in line for kw in keywords):
                    comp_type = t
                    break

            # Determine technology category
            category = 'api'  # default
            for cat, keywords in component_keywords.items():
                if any(kw in line for kw in keywords):
                    category = cat
                    break

            # Check if this line describes a component
            if any(kw in line for kws in component_keywords.values() for kw in kws):
                name = self._extract_component_name(line)
                if name and not any(c['name'].lower() == name.lower() for c in components):
                    components.append({
                        "id": f"comp_{component_id}",
                        "name": name,
                        "type": comp_type,
                        "category": category,
                        "technology": category,
                        "description": line[:100],
                        "data_handled": [],
                        "trust_level": "trusted" if comp_type != 'external' else "untrusted",
                        "internet_facing": comp_type == 'external' or 'api' in category,
                        "handles_sensitive_data": any(w in line for w in ['auth', 'password', 'credential', 'personal', 'pii'])
                    })
                    component_id += 1

        # Infer data flows
        data_flows = self._infer_data_flows_enhanced(components)

        # Create default trust boundaries
        external_comps = [c['id'] for c in components if c['type'] == 'external']
        internal_comps = [c['id'] for c in components if c['type'] != 'external']
        datastore_comps = [c['id'] for c in components if c['type'] == 'datastore']

        if external_comps:
            trust_boundaries.append({
                "id": "tb_internet",
                "name": "Internet Boundary",
                "description": "Separates external users from internal systems",
                "components_inside": internal_comps,
                "boundary_type": "internet"
            })

        if datastore_comps:
            trust_boundaries.append({
                "id": "tb_data",
                "name": "Data Layer Boundary",
                "description": "Protects data storage systems",
                "components_inside": datastore_comps,
                "boundary_type": "data"
            })

        return {
            "system_overview": "System analyzed from architecture document",
            "technology_stack": list(set(c['category'] for c in components)),
            "components": components,
            "data_flows": data_flows,
            "trust_boundaries": trust_boundaries,
            "security_controls": [],
            "risk_factors": []
        }

    def _extract_component_name(self, line: str) -> Optional[str]:
        """Extract meaningful component name from text"""
        # Remove common prefixes and clean up
        line = re.sub(r'^[-*#:\d.)\]]+\s*', '', line.strip())

        # Take first meaningful phrase
        words = line.split()
        if not words:
            return None

        name_parts = []
        stop_words = {'the', 'a', 'an', 'is', 'are', 'with', 'using', 'for', 'to', 'and', 'or', 'that', 'which', 'handles'}

        for word in words[:5]:
            clean_word = re.sub(r'[^\w\s-]', '', word)
            if clean_word.lower() not in stop_words and len(clean_word) > 1:
                name_parts.append(clean_word.capitalize())

        return ' '.join(name_parts[:4]) if name_parts else None

    def _infer_data_flows_enhanced(self, components: List[Dict]) -> List[Dict]:
        """Infer data flows based on component types and categories"""
        flows = []
        flow_id = 0

        externals = [c for c in components if c['type'] == 'external']
        processes = [c for c in components if c['type'] == 'process']
        datastores = [c for c in components if c['type'] == 'datastore']

        # Frontends that externals connect to
        frontends = [c for c in processes if c.get('category') in ['frontend', 'api']]

        # External -> Frontend/API
        for ext in externals:
            targets = frontends if frontends else processes[:1]
            for target in targets:
                flows.append({
                    "id": f"flow_{flow_id}",
                    "from": ext['id'],
                    "to": target['id'],
                    "data_type": "User requests, authentication",
                    "protocol": "HTTPS",
                    "encrypted": True,
                    "authenticated": False,
                    "sensitive": True
                })
                flow_id += 1

        # API -> Database
        apis = [c for c in processes if c.get('category') == 'api']
        for api in apis:
            for ds in datastores:
                flows.append({
                    "id": f"flow_{flow_id}",
                    "from": api['id'],
                    "to": ds['id'],
                    "data_type": "Query/Response data",
                    "protocol": "Database Protocol",
                    "encrypted": True,
                    "authenticated": True,
                    "sensitive": True
                })
                flow_id += 1

        # Inter-service flows for microservices
        services = [c for c in processes if c.get('category') in ['api', 'microservice']]
        for i, svc in enumerate(services):
            for j, other_svc in enumerate(services):
                if i != j and i < j:  # Avoid duplicates
                    flows.append({
                        "id": f"flow_{flow_id}",
                        "from": svc['id'],
                        "to": other_svc['id'],
                        "data_type": "Internal API calls",
                        "protocol": "HTTP/gRPC",
                        "encrypted": True,
                        "authenticated": True,
                        "sensitive": False
                    })
                    flow_id += 1

        return flows

    def generate_stride_analysis(self, parsed_arch: Dict[str, Any], system_context: str = "") -> Dict[str, List[Dict]]:
        """Generate comprehensive STRIDE analysis with AI-powered threat enrichment"""
        stride_threats = {cat: [] for cat in self.STRIDE_CATEGORIES.keys()}

        # Build system context if not provided
        if not system_context:
            system_context = self._build_system_context(parsed_arch)

        # Track which threats to enrich with AI (limit to most critical)
        threats_to_enrich = []

        for component in parsed_arch.get('components', []):
            category = component.get('category', 'api')
            comp_name = component.get('name', 'Unknown')
            comp_type = component.get('type', 'process')

            # Get technology-specific threats
            tech_threats = self.TECHNOLOGY_THREATS.get(category, {})

            for stride_cat, threats in tech_threats.items():
                for threat_template in threats:
                    # Calculate risk score
                    base_score = {'critical': 9.5, 'high': 7.5, 'medium': 5.0, 'low': 2.5}.get(
                        threat_template['severity'], 5.0
                    )

                    # Adjust score based on component properties
                    if component.get('internet_facing'):
                        base_score += 1.0
                    if component.get('handles_sensitive_data'):
                        base_score += 0.5
                    if component.get('trust_level') == 'untrusted':
                        base_score += 0.5

                    risk_score = min(10.0, base_score)

                    mitre_techs = threat_template.get('mitre', [])

                    # Create base threat object
                    threat_obj = {
                        "id": f"threat_{len(stride_threats[stride_cat])}",
                        "component": comp_name,
                        "component_id": component.get('id'),
                        "component_type": comp_type,
                        "component_category": category,
                        "category": stride_cat,
                        "threat": threat_template['threat'],
                        "severity": threat_template['severity'],
                        "risk_score": round(risk_score, 1),
                        "cwe": threat_template.get('cwe'),
                        "cwe_id": threat_template.get('cwe'),
                        "mitre": mitre_techs,
                        "mitre_techniques": mitre_techs,
                        "likelihood": self._calculate_likelihood(component, threat_template),
                        "impact": self._calculate_impact(component, threat_template),
                        "references": self._get_threat_references(threat_template),
                    }

                    # Always add fallback values first (will be overwritten by AI if enriched)
                    threat_obj.update({
                        "description": self._generate_threat_description(threat_template, component),
                        "mitigation": self._generate_mitigation(threat_template, component),
                        "detection": self._generate_detection_guidance(threat_template),
                        "attack_vector": self._get_attack_vector(threat_template, component),
                        "business_impact": self._get_business_impact(threat_template, component),
                        "affected_assets": self._get_affected_assets(component),
                        "prerequisites": self._get_attack_prerequisites(threat_template, component),
                        "attack_complexity": self._get_attack_complexity(threat_template),
                    })

                    # Queue high-severity threats for AI enrichment (will override fallbacks)
                    if threat_template['severity'] in ['critical', 'high'] and self.anthropic_client:
                        threats_to_enrich.append({
                            'threat_obj': threat_obj,
                            'threat_template': threat_template,
                            'component': component,
                            'stride_cat': stride_cat
                        })

                    stride_threats[stride_cat].append(threat_obj)

        # Enrich critical/high threats with AI (limit to top 15 to manage API calls)
        threats_to_enrich = sorted(
            threats_to_enrich,
            key=lambda x: x['threat_obj']['risk_score'],
            reverse=True
        )[:15]

        for item in threats_to_enrich:
            threat_obj = item['threat_obj']
            enriched = self._enrich_threat_with_ai(
                item['threat_template'],
                item['component'],
                system_context
            )

            # Update threat with AI-generated content (use fallback if AI returns empty)
            threat_obj.update({
                "description": enriched.get('description') or self._generate_threat_description(item['threat_template'], item['component']),
                "mitigation": enriched.get('mitigation') or self._generate_mitigation(item['threat_template'], item['component']),
                "detection": enriched.get('detection') or self._generate_detection_guidance(item['threat_template']),
                "attack_vector": enriched.get('attack_vector') or self._get_attack_vector(item['threat_template'], item['component']),
                "business_impact": enriched.get('business_impact') or self._get_business_impact(item['threat_template'], item['component']),
                "affected_assets": enriched.get('affected_assets') or self._get_affected_assets(item['component']),
                "prerequisites": enriched.get('prerequisites') or self._get_attack_prerequisites(item['threat_template'], item['component']),
                "attack_complexity": enriched.get('attack_complexity') or self._get_attack_complexity(item['threat_template']),
            })

        # Add data flow threats
        for flow in parsed_arch.get('data_flows', []):
            if not flow.get('encrypted'):
                stride_threats['Information Disclosure'].append({
                    "id": f"threat_flow_{flow.get('id')}",
                    "component": f"Data Flow: {flow.get('from')} → {flow.get('to')}",
                    "component_type": "dataflow",
                    "category": "Information Disclosure",
                    "threat": "Unencrypted Data in Transit",
                    "description": f"Data flowing from {flow.get('from')} to {flow.get('to')} may not be encrypted, allowing eavesdropping",
                    "severity": "high" if flow.get('sensitive') else "medium",
                    "risk_score": 7.5 if flow.get('sensitive') else 5.0,
                    "cwe": "CWE-319",
                    "cwe_id": "CWE-319",
                    "mitre": ["T1557"],
                    "mitre_techniques": ["T1557"],
                    "mitigation": "Implement TLS 1.3 for all data in transit",
                    "detection": "Monitor for unencrypted traffic patterns",
                    "likelihood": "high",
                    "impact": "high" if flow.get('sensitive') else "medium",
                })

            if not flow.get('authenticated'):
                stride_threats['Spoofing'].append({
                    "id": f"threat_auth_{flow.get('id')}",
                    "component": f"Data Flow: {flow.get('from')} → {flow.get('to')}",
                    "component_type": "dataflow",
                    "category": "Spoofing",
                    "threat": "Unauthenticated Data Flow",
                    "description": f"Communication between {flow.get('from')} and {flow.get('to')} lacks authentication",
                    "severity": "high",
                    "risk_score": 7.0,
                    "cwe": "CWE-306",
                    "cwe_id": "CWE-306",
                    "mitre": ["T1078"],
                    "mitre_techniques": ["T1078"],
                    "mitigation": "Implement mutual TLS or API key authentication",
                    "detection": "Monitor for unauthorized access attempts",
                    "likelihood": "medium",
                    "impact": "high",
                })

        return stride_threats

    def _generate_threat_description(self, threat_template: Dict, component: Dict) -> str:
        """Generate context-aware threat description"""
        base_desc = {
            "SQL Injection": f"Attacker could inject malicious SQL queries into {component['name']} to access or modify database contents",
            "JWT Token Forgery": f"Attacker could forge JWT tokens to impersonate legitimate users of {component['name']}",
            "XSS": f"Malicious scripts could be injected into {component['name']} and executed in user browsers",
            "BOLA": f"Attacker could access unauthorized objects through {component['name']} by manipulating object references",
        }

        return base_desc.get(
            threat_template['threat'],
            f"Potential {threat_template['threat']} vulnerability in {component['name']} ({component.get('category', 'component')})"
        )

    def _generate_mitigation(self, threat_template: Dict, component: Dict) -> str:
        """Generate specific mitigation recommendations"""
        mitigations = {
            "CWE-89": "Use parameterized queries, prepared statements, and ORM frameworks. Implement input validation.",
            "CWE-79": "Implement Content Security Policy (CSP), use output encoding, and sanitize user input.",
            "CWE-347": "Use strong cryptographic algorithms (RS256/ES256) for JWT signing. Validate all token claims.",
            "CWE-639": "Implement proper authorization checks. Verify user ownership of requested resources.",
            "CWE-307": "Implement account lockout, rate limiting, CAPTCHA, and multi-factor authentication.",
            "CWE-311": "Encrypt sensitive data at rest using AES-256. Implement proper key management.",
            "CWE-918": "Validate and sanitize URLs. Use allowlists for permitted destinations.",
            "CWE-319": "Implement TLS 1.3 for all data in transit. Enforce HTTPS with HSTS headers.",
            "CWE-306": "Implement mutual TLS or API key authentication. Validate all incoming requests.",
            "CWE-287": "Implement strong authentication mechanisms. Use MFA for sensitive operations.",
            "CWE-862": "Implement role-based access control (RBAC). Verify authorization for all requests.",
            "CWE-200": "Implement proper error handling. Avoid exposing sensitive information in responses.",
            "CWE-522": "Use secure password hashing (bcrypt/Argon2). Enforce strong password policies.",
            "CWE-798": "Remove hardcoded credentials. Use secrets management solutions (Vault, AWS Secrets Manager).",
            "CWE-502": "Validate and sanitize all deserialized data. Use safe deserialization libraries.",
            "CWE-611": "Disable external entity processing. Use secure XML parser configurations.",
            "CWE-94": "Avoid dynamic code execution. Implement strict input validation and sandboxing.",
            "CWE-78": "Use parameterized commands. Avoid shell execution with user input.",
            "CWE-434": "Validate file types and content. Store uploads outside web root with random names.",
            "CWE-352": "Implement CSRF tokens. Validate Origin and Referer headers.",
            "CWE-269": "Apply principle of least privilege. Review and audit access permissions regularly.",
        }

        cwe = threat_template.get('cwe', '')
        if cwe in mitigations:
            return mitigations[cwe]

        # Category-based fallbacks
        category = threat_template.get('category', '')
        category_mitigations = {
            "Spoofing": "Implement strong authentication and identity verification. Use certificates or tokens for service-to-service communication.",
            "Tampering": "Implement integrity checks using cryptographic signatures. Use secure channels for data transmission.",
            "Repudiation": "Implement comprehensive audit logging. Use tamper-evident logs with timestamps and digital signatures.",
            "Information Disclosure": "Encrypt sensitive data at rest and in transit. Implement proper access controls and data masking.",
            "Denial of Service": "Implement rate limiting, resource quotas, and auto-scaling. Use CDN and DDoS protection.",
            "Elevation of Privilege": "Implement role-based access control. Apply principle of least privilege. Regular access reviews.",
        }

        if category in category_mitigations:
            return category_mitigations[category]

        threat_name = threat_template.get('threat', 'this threat')
        return f"Implement appropriate security controls to mitigate {threat_name}. Conduct security review and testing."

    def _generate_detection_guidance(self, threat_template: Dict) -> str:
        """Generate detection guidance for the threat"""
        detections = {
            "CWE-89": "Monitor for SQL syntax in input parameters. Use WAF with SQL injection rules.",
            "CWE-79": "Implement CSP violation reporting. Monitor for unusual script sources.",
            "CWE-307": "Track failed authentication attempts. Alert on credential stuffing patterns.",
            "CWE-639": "Log and monitor access patterns. Alert on unauthorized resource access.",
        }

        return detections.get(
            threat_template.get('cwe'),
            "Implement logging and monitoring for anomalous behavior"
        )

    def _calculate_likelihood(self, component: Dict, threat_template: Dict) -> str:
        """Calculate threat likelihood based on exposure"""
        if component.get('internet_facing'):
            return "high"
        elif component.get('trust_level') == 'untrusted':
            return "high"
        elif threat_template.get('severity') == 'critical':
            return "medium"
        return "low"

    def _calculate_impact(self, component: Dict, threat_template: Dict) -> str:
        """Calculate threat impact based on data sensitivity"""
        if component.get('handles_sensitive_data'):
            return "critical" if threat_template.get('severity') == 'critical' else "high"
        return threat_template.get('severity', 'medium')

    def _get_attack_vector(self, threat_template: Dict, component: Dict) -> Dict[str, Any]:
        """Generate detailed attack vector description as structured object"""
        threat_name = threat_template.get('threat', '')

        vectors = {
            "SQL Injection": {
                "description": "Network-based attack via malicious input in SQL queries. Attacker sends crafted SQL statements through user input fields, URL parameters, or API endpoints to manipulate database queries.",
                "entry_points": ["Form inputs", "URL parameters", "API request bodies", "HTTP headers"],
                "techniques": ["UNION-based injection", "Blind SQL injection", "Time-based injection", "Error-based injection"]
            },
            "NoSQL Injection": {
                "description": "Network-based attack exploiting improper input validation in NoSQL databases. Attacker injects operators or JavaScript code to bypass authentication or extract data.",
                "entry_points": ["JSON request bodies", "Query parameters", "Form fields"],
                "techniques": ["Operator injection ($gt, $ne)", "JavaScript injection", "Query manipulation"]
            },
            "JWT Token Forgery": {
                "description": "Network-based attack targeting authentication tokens. Attacker exploits weak signing algorithms, key leakage, or algorithm confusion to create forged tokens.",
                "entry_points": ["Authorization headers", "Cookies", "URL tokens"],
                "techniques": ["Algorithm confusion (none/HS256)", "Key brute-forcing", "Token sidejacking", "Claim manipulation"]
            },
            "XSS": {
                "description": "Client-side attack injecting malicious scripts. Attacker exploits insufficient output encoding to execute JavaScript in victim's browser context.",
                "entry_points": ["Form inputs", "URL parameters", "Comment fields", "User profile data"],
                "techniques": ["Reflected XSS", "Stored XSS", "DOM-based XSS", "Event handler injection"]
            },
            "BOLA": {
                "description": "Network-based API attack. Attacker manipulates object identifiers (IDs) in API requests to access resources belonging to other users.",
                "entry_points": ["API endpoints", "Resource URLs", "Request parameters"],
                "techniques": ["ID enumeration", "GUID prediction", "Reference manipulation"]
            },
            "SSRF": {
                "description": "Server-side attack forcing the application to make requests. Attacker exploits URL parameters to access internal services or cloud metadata endpoints.",
                "entry_points": ["URL parameters", "Webhook configurations", "File import features"],
                "techniques": ["Internal service access", "Cloud metadata exposure", "Port scanning", "Protocol smuggling"]
            },
            "Command Injection": {
                "description": "Network-based attack executing arbitrary system commands. Attacker exploits improper input sanitization in shell command construction.",
                "entry_points": ["File upload names", "System configuration fields", "Export features"],
                "techniques": ["Shell metacharacter injection", "Command chaining", "Argument injection"]
            },
            "Brute Force": {
                "description": "Network-based credential attack. Attacker systematically attempts password combinations to gain unauthorized access.",
                "entry_points": ["Login forms", "API authentication endpoints", "Password reset flows"],
                "techniques": ["Dictionary attacks", "Credential stuffing", "Rainbow table attacks", "Distributed attacks"]
            },
        }

        result = vectors.get(threat_name, {
            "description": f"Attack targeting {component.get('name', 'component')} through network-accessible interfaces.",
            "entry_points": ["Network endpoints", "User inputs"],
            "techniques": ["Exploitation of identified vulnerability"]
        })

        if component.get('internet_facing'):
            result["description"] += " Component is internet-facing, increasing exposure."
            result["entry_points"].insert(0, "Public internet")

        return result

    def _get_business_impact(self, threat_template: Dict, component: Dict) -> Dict[str, Any]:
        """Generate detailed business impact analysis"""
        severity = threat_template.get('severity', 'medium')
        handles_sensitive = component.get('handles_sensitive_data', False)

        impacts = {
            "critical": {
                "financial": "Potential for significant financial losses including regulatory fines, legal costs, and revenue loss. Estimated impact: $1M+",
                "reputational": "Severe damage to brand trust and customer confidence. May result in customer churn and negative media coverage.",
                "operational": "Major disruption to business operations. May require system-wide shutdown and incident response activation.",
                "compliance": "Likely violation of GDPR, PCI-DSS, HIPAA, or other regulations. Mandatory breach notification may be required.",
                "data_loss": "Complete compromise of sensitive data possible. Personal information, credentials, or financial data at risk."
            },
            "high": {
                "financial": "Significant financial impact including potential fines and remediation costs. Estimated impact: $100K-$1M",
                "reputational": "Noticeable damage to reputation. Customer trust may be affected.",
                "operational": "Partial service disruption possible. May require targeted remediation efforts.",
                "compliance": "Potential compliance violations requiring investigation and reporting.",
                "data_loss": "Partial data exposure possible. Sensitive information may be at risk."
            },
            "medium": {
                "financial": "Moderate financial impact. Remediation costs and potential minor penalties. Estimated impact: $10K-$100K",
                "reputational": "Limited reputational impact. May affect specific customer segments.",
                "operational": "Minor service disruption. Normal operations can continue with workarounds.",
                "compliance": "Minor compliance concerns. Documentation and process review recommended.",
                "data_loss": "Limited data exposure. Non-critical information may be accessed."
            },
            "low": {
                "financial": "Minimal financial impact. Standard remediation costs. Estimated impact: <$10K",
                "reputational": "Negligible reputational impact.",
                "operational": "No significant operational impact.",
                "compliance": "No compliance concerns.",
                "data_loss": "No sensitive data at risk."
            }
        }

        impact = impacts.get(severity, impacts['medium']).copy()

        if handles_sensitive:
            impact['data_sensitivity'] = "HIGH - Component handles sensitive data including PII, credentials, or financial information."
        else:
            impact['data_sensitivity'] = "NORMAL - Component handles standard application data."

        return impact

    def _get_affected_assets(self, component: Dict) -> List[str]:
        """Identify assets affected by the threat"""
        assets = []

        data_handled = component.get('data_handled', [])
        if data_handled:
            assets.extend(data_handled)

        if component.get('handles_sensitive_data'):
            assets.extend(["User credentials", "Personal information", "Session data"])

        category = component.get('category', '')
        category_assets = {
            'database': ["Stored records", "Database schemas", "Backup data"],
            'authentication': ["User accounts", "Authentication tokens", "Password hashes", "OAuth tokens"],
            'api': ["API keys", "Request/response data", "Business logic"],
            'frontend': ["Client-side data", "User inputs", "Browser storage"],
            'cloud': ["Cloud resources", "IAM credentials", "Storage buckets"],
        }

        assets.extend(category_assets.get(category, ["Application data"]))
        return list(set(assets))[:8]  # Return unique assets, limit to 8

    def _get_attack_prerequisites(self, threat_template: Dict, component: Dict) -> Dict[str, Any]:
        """Get prerequisites for the attack as structured object"""
        threat_name = threat_template.get('threat', '')

        prereq_map = {
            "SQL Injection": {
                "access_required": "Network access to application",
                "conditions": ["Application accepts user input", "Input is used in SQL queries", "Insufficient input validation"]
            },
            "JWT Token Forgery": {
                "access_required": "Valid or intercepted JWT token",
                "conditions": ["JWT is used for authentication", "Weak signing algorithm or key", "Token validation bypass possible"]
            },
            "XSS": {
                "access_required": "Ability to submit content to application",
                "conditions": ["Application renders user input", "Insufficient output encoding", "Missing Content-Security-Policy"]
            },
            "BOLA": {
                "access_required": "Authenticated user session",
                "conditions": ["Direct object references in API", "Missing authorization checks", "Predictable object identifiers"]
            },
            "Brute Force": {
                "access_required": "Network access to authentication endpoint",
                "conditions": ["Authentication endpoint accessible", "No rate limiting", "No account lockout"]
            },
            "SSRF": {
                "access_required": "Ability to provide URLs to application",
                "conditions": ["Application makes outbound requests", "User-controllable URLs", "No URL validation"]
            },
            "Session Hijacking": {
                "access_required": "Network position for interception or XSS access",
                "conditions": ["Session tokens transmitted", "Insecure token storage", "Missing secure cookie flags"]
            },
            "Command Injection": {
                "access_required": "Ability to provide input to system commands",
                "conditions": ["Application executes system commands", "User input in command construction", "Insufficient input sanitization"]
            },
        }

        result = prereq_map.get(threat_name, {
            "access_required": "Network access to vulnerable component",
            "conditions": ["Vulnerable component accessible", "Attack surface exists"]
        })

        # Add additional conditions based on component properties
        if component.get('internet_facing'):
            result["conditions"].append("Internet accessibility (confirmed)")
        if component.get('trust_level') == 'untrusted':
            result["conditions"].append("Untrusted input accepted")

        return result

    def _get_attack_complexity(self, threat_template: Dict) -> Dict[str, Any]:
        """Assess attack complexity with frontend-compatible field names"""
        severity = threat_template.get('severity', 'medium')

        complexity_map = {
            'critical': {
                'level': 'Low',
                'description': 'Attack is well-documented with publicly available exploits',
                'skill_level': 'Basic',
                'time_required': 'Minutes to hours',
                'tools_available': True,
                'automation_possible': True
            },
            'high': {
                'level': 'Low to Medium',
                'description': 'Attack requires some understanding of the vulnerability',
                'skill_level': 'Intermediate',
                'time_required': 'Hours',
                'tools_available': True,
                'automation_possible': True
            },
            'medium': {
                'level': 'Medium',
                'description': 'Attack requires specific conditions and knowledge',
                'skill_level': 'Intermediate',
                'time_required': 'Hours to days',
                'tools_available': True,
                'automation_possible': False
            },
            'low': {
                'level': 'High',
                'description': 'Attack requires significant expertise and specific conditions',
                'skill_level': 'Advanced',
                'time_required': 'Days to weeks',
                'tools_available': False,
                'automation_possible': False
            }
        }

        return complexity_map.get(severity, complexity_map['medium'])

    def _get_threat_references(self, threat_template: Dict) -> Dict[str, str]:
        """Get reference links for the threat as object with cwe, mitre, owasp URLs"""
        cwe = threat_template.get('cwe', '')
        references = {}

        # Add CWE reference
        if cwe:
            cwe_num = cwe.replace('CWE-', '')
            references['cwe'] = f'https://cwe.mitre.org/data/definitions/{cwe_num}.html'

        # Add MITRE reference (use first technique if available)
        mitre_techs = threat_template.get('mitre', [])
        if mitre_techs:
            tech = mitre_techs[0]
            references['mitre'] = f'https://attack.mitre.org/techniques/{tech}/'

        # Add OWASP reference based on threat type
        owasp_map = {
            'SQL Injection': 'https://owasp.org/www-community/attacks/SQL_Injection',
            'XSS': 'https://owasp.org/www-community/attacks/xss/',
            'SSRF': 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
            'BOLA': 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
            'Command Injection': 'https://owasp.org/www-community/attacks/Command_Injection',
            'Path Traversal': 'https://owasp.org/www-community/attacks/Path_Traversal',
            'JWT': 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens',
            'Brute Force': 'https://owasp.org/www-community/attacks/Brute_force_attack',
        }

        threat_name = threat_template.get('threat', '')
        for key, url in owasp_map.items():
            if key.lower() in threat_name.lower():
                references['owasp'] = url
                break

        return references

    def map_mitre_attack(self, stride_threats: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Map STRIDE threats to MITRE ATT&CK with full technique details"""
        mitre_mapping = {}
        technique_threat_count = {}

        for stride_cat, threats in stride_threats.items():
            for threat in threats:
                for technique_id in threat.get('mitre_techniques', []):
                    if technique_id in self.MITRE_TECHNIQUES:
                        tech_info = self.MITRE_TECHNIQUES[technique_id]

                        if technique_id not in mitre_mapping:
                            mitre_mapping[technique_id] = {
                                "id": technique_id,
                                "name": tech_info['name'],
                                "tactic": tech_info['tactic'],
                                "url": tech_info['url'],
                                "related_threats": [],
                                "threat_count": 0,
                                "max_severity": "low",
                                "affected_components": set()
                            }

                        mitre_mapping[technique_id]['related_threats'].append({
                            "threat_id": threat.get('id'),
                            "threat_name": threat.get('threat'),
                            "stride_category": stride_cat,
                            "component": threat.get('component'),
                            "severity": threat.get('severity')
                        })
                        mitre_mapping[technique_id]['threat_count'] += 1
                        mitre_mapping[technique_id]['affected_components'].add(threat.get('component'))

                        # Track max severity
                        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
                        current_max = severity_order.get(mitre_mapping[technique_id]['max_severity'], 0)
                        new_severity = severity_order.get(threat.get('severity', 'low'), 0)
                        if new_severity > current_max:
                            mitre_mapping[technique_id]['max_severity'] = threat.get('severity')

        # Convert sets to lists for JSON serialization
        for tech_id in mitre_mapping:
            mitre_mapping[tech_id]['affected_components'] = list(mitre_mapping[tech_id]['affected_components'])

        # Group by tactic for attack chain visualization
        tactics_order = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Exfiltration", "Impact"
        ]

        attack_chain = {tactic: [] for tactic in tactics_order}
        for tech_id, tech_data in mitre_mapping.items():
            tactic = tech_data['tactic']
            if tactic in attack_chain:
                attack_chain[tactic].append(tech_data)

        return {
            "techniques": mitre_mapping,
            "attack_chain": attack_chain,
            "total_techniques": len(mitre_mapping),
            "tactics_covered": len([t for t in attack_chain.values() if t])
        }

    def generate_dfd(self, parsed_arch: Dict[str, Any], level: int = 0) -> Dict[str, Any]:
        """Generate DFD data structure for visualization"""
        nodes = []
        edges = []

        for component in parsed_arch.get('components', []):
            nodes.append({
                "id": component['id'],
                "label": component['name'],
                "type": component['type'],
                "category": component.get('category', 'process'),
                "technology": component.get('technology', ''),
                "trust_level": component.get('trust_level', 'trusted'),
                "internet_facing": component.get('internet_facing', False),
                "handles_sensitive_data": component.get('handles_sensitive_data', False),
            })

        for flow in parsed_arch.get('data_flows', []):
            edges.append({
                "id": flow['id'],
                "source": flow['from'],
                "target": flow['to'],
                "label": flow.get('data_type', 'Data'),
                "protocol": flow.get('protocol', 'HTTP'),
                "encrypted": flow.get('encrypted', False),
                "authenticated": flow.get('authenticated', False),
                "sensitive": flow.get('sensitive', False),
            })

        return {
            "level": level,
            "nodes": nodes,
            "edges": edges,
            "trust_boundaries": parsed_arch.get('trust_boundaries', [])
        }

    def generate_mermaid_dfd(self, dfd_data: Dict[str, Any], level: int = 0) -> str:
        """Generate professional Mermaid DFD with proper styling"""
        lines = ["graph TB"]

        # Enhanced styling
        lines.extend([
            "    %% Styling",
            "    classDef external fill:#fee2e2,stroke:#dc2626,stroke-width:2px,color:#991b1b",
            "    classDef process fill:#dbeafe,stroke:#2563eb,stroke-width:2px,color:#1e40af",
            "    classDef datastore fill:#d1fae5,stroke:#059669,stroke-width:2px,color:#065f46",
            "    classDef sensitive fill:#fef3c7,stroke:#d97706,stroke-width:3px,color:#92400e",
            "    classDef internet fill:#fce7f3,stroke:#db2777,stroke-width:2px,color:#9d174d",
            "    classDef trustBoundary fill:none,stroke:#6366f1,stroke-width:2px,stroke-dasharray:5 5",
            ""
        ])

        if level == 0:
            # Context diagram - simplified view
            lines.append("    %% Level 0: Context Diagram")

            external_nodes = [n for n in dfd_data['nodes'] if n['type'] == 'external']
            internal_nodes = [n for n in dfd_data['nodes'] if n['type'] != 'external']

            # System process node
            lines.extend([
                "    subgraph System[\"🔐 Application System\"]",
                "        direction TB"
            ])

            # Add a summary of internal components
            proc_count = len([n for n in internal_nodes if n['type'] == 'process'])
            ds_count = len([n for n in internal_nodes if n['type'] == 'datastore'])
            lines.append(f"        CORE[\"📦 {proc_count} Processes | 💾 {ds_count} Data Stores\"]")
            lines.append("        class CORE process")
            lines.append("    end")
            lines.append("")

            # Add external entities
            for node in external_nodes:
                node_id = self._sanitize_id(node['id'])
                label = node['label']
                emoji = "👤" if 'user' in label.lower() else "🌐"
                lines.append(f"    {node_id}[\"{emoji} {label}\"]")
                lines.append(f"    class {node_id} external")

            lines.append("")

            # Simplified flows
            seen_flows = set()
            for node in external_nodes:
                node_id = self._sanitize_id(node['id'])
                if f"{node_id}_in" not in seen_flows:
                    lines.append(f"    {node_id} -->|\"Requests\"| CORE")
                    seen_flows.add(f"{node_id}_in")
                if f"{node_id}_out" not in seen_flows:
                    lines.append(f"    CORE -->|\"Responses\"| {node_id}")
                    seen_flows.add(f"{node_id}_out")

        else:
            # Detailed diagram
            lines.append("    %% Level 1: Detailed Diagram")
            lines.append("")

            # Group by trust boundary
            boundary_nodes = {}
            for boundary in dfd_data.get('trust_boundaries', []):
                boundary_nodes[boundary['id']] = set(boundary.get('components_inside', []))

            all_boundary_nodes = set()
            for nodes_set in boundary_nodes.values():
                all_boundary_nodes.update(nodes_set)

            # Add trust boundaries as subgraphs
            for boundary in dfd_data.get('trust_boundaries', []):
                b_id = self._sanitize_id(boundary['id'])
                b_name = boundary.get('name', 'Trust Boundary')
                emoji = "🔒" if 'internet' in b_name.lower() else "🛡️"

                lines.append(f"    subgraph {b_id}[\"{emoji} {b_name}\"]")
                lines.append("        direction TB")

                for node in dfd_data['nodes']:
                    if node['id'] in boundary_nodes.get(boundary['id'], set()):
                        self._add_node_to_mermaid(lines, node, indent=8)

                lines.append("    end")
                lines.append(f"    class {b_id} trustBoundary")
                lines.append("")

            # Add nodes not in any boundary
            lines.append("    %% External Components")
            for node in dfd_data['nodes']:
                if node['id'] not in all_boundary_nodes:
                    self._add_node_to_mermaid(lines, node, indent=4)

            lines.append("")

            # Add all data flows with security annotations
            lines.append("    %% Data Flows")
            for edge in dfd_data['edges']:
                source = self._sanitize_id(edge['source'])
                target = self._sanitize_id(edge['target'])

                # Build label with security indicators
                label_parts = [edge.get('label', 'Data')]
                if edge.get('encrypted'):
                    label_parts.append("🔐")
                if edge.get('authenticated'):
                    label_parts.append("✓")
                if edge.get('sensitive'):
                    label_parts.append("⚠️")

                label = ' '.join(label_parts)
                lines.append(f"    {source} -->|\"{label}\"| {target}")

        return '\n'.join(lines)

    def _sanitize_id(self, id_str: str) -> str:
        """Sanitize ID for Mermaid compatibility"""
        return re.sub(r'[^a-zA-Z0-9_]', '_', str(id_str))

    def _add_node_to_mermaid(self, lines: List[str], node: Dict, indent: int = 4):
        """Add a node to Mermaid diagram with proper styling"""
        spaces = ' ' * indent
        node_id = self._sanitize_id(node['id'])
        label = node['label']

        # Choose shape and emoji based on type
        if node['type'] == 'external':
            emoji = "👤" if 'user' in label.lower() else "🌐"
            lines.append(f"{spaces}{node_id}[\"{emoji} {label}\"]")
            cls = "internet" if node.get('internet_facing') else "external"
        elif node['type'] == 'datastore':
            lines.append(f"{spaces}{node_id}[(\"{label}\")]")
            cls = "sensitive" if node.get('handles_sensitive_data') else "datastore"
        else:
            emoji = self._get_component_emoji(node.get('category', ''))
            lines.append(f"{spaces}{node_id}(\"{emoji} {label}\")")
            cls = "sensitive" if node.get('handles_sensitive_data') else "process"

        lines.append(f"{spaces}class {node_id} {cls}")

    def _get_component_emoji(self, category: str) -> str:
        """Get appropriate emoji for component category"""
        emojis = {
            'api': '🔌',
            'database': '💾',
            'authentication': '🔑',
            'frontend': '🖥️',
            'microservice': '📦',
            'cloud': '☁️',
            'message_queue': '📨',
        }
        return emojis.get(category, '⚙️')

    # =========================================================================
    # ERASER AI PROFESSIONAL DIAGRAM GENERATION
    # =========================================================================

    async def generate_eraser_diagrams(
        self,
        parsed_arch: Dict[str, Any],
        stride_analysis: Dict[str, List[Dict]],
        attack_trees: List[Dict],
        kill_chain: Dict[str, Any],
        theme: str = "light"
    ) -> Dict[str, Any]:
        """
        Generate professional diagrams using Eraser AI.

        Args:
            parsed_arch: Parsed architecture data
            stride_analysis: STRIDE threat analysis results
            attack_trees: Generated attack trees
            kill_chain: Kill chain analysis
            theme: Diagram theme ("light" or "dark")

        Returns:
            Dict with diagram URLs and metadata for each diagram type
        """
        if not self.eraser_enabled or not self._eraser_service:
            return {
                "enabled": False,
                "message": "Eraser AI not configured. Set ERASER_API_KEY environment variable.",
                "diagrams": {}
            }

        diagrams = {}

        # Collect all threats for architecture diagram
        all_threats = []
        for threats in stride_analysis.values():
            all_threats.extend(threats[:5])  # Top 5 per category

        # Generate diagrams concurrently
        # Note: Attack path diagrams are generated on-demand via /generate-attack-diagram endpoint
        tasks = []

        # 1. Architecture/Threat Model Diagram
        arch_description = self._build_eraser_architecture_prompt(parsed_arch)
        tasks.append(("architecture", self._eraser_service.generate_threat_model_diagram(
            arch_description, all_threats, theme
        )))

        # 2. Kill Chain Diagram
        tasks.append(("kill_chain", self._eraser_service.generate_kill_chain_diagram(
            kill_chain, theme
        )))

        # 4. Data Flow Diagram
        components = [
            {"name": c.get("name"), "type": c.get("type", "process")}
            for c in parsed_arch.get("components", [])
        ]
        data_flows = [
            {
                "source": df.get("source"),
                "target": df.get("target"),
                "data_type": df.get("data_type", "data")
            }
            for df in parsed_arch.get("data_flows", [])
        ]
        trust_boundaries = [
            tb.get("name", "Boundary")
            for tb in parsed_arch.get("trust_boundaries", [])
        ]
        tasks.append(("data_flow", self._eraser_service.generate_data_flow_diagram(
            components, data_flows, trust_boundaries, theme
        )))

        # Execute all tasks concurrently
        results = await asyncio.gather(*[task[1] for task in tasks], return_exceptions=True)

        # Process results
        for (name, _), result in zip(tasks, results):
            if isinstance(result, Exception):
                logger.error(f"Failed to generate {name} diagram: {result}")
                diagrams[name] = {
                    "success": False,
                    "error": str(result)
                }
            else:
                diagrams[name] = result

        # Calculate success stats
        successful = sum(1 for d in diagrams.values() if d.get("success"))
        total = len(diagrams)

        return {
            "enabled": True,
            "provider": "eraser_ai",
            "theme": theme,
            "diagrams": diagrams,
            "stats": {
                "total": total,
                "successful": successful,
                "failed": total - successful
            }
        }

    def _build_eraser_architecture_prompt(self, parsed_arch: Dict[str, Any]) -> str:
        """Build architecture description for Eraser diagram generation"""
        components = parsed_arch.get("components", [])
        data_flows = parsed_arch.get("data_flows", [])
        trust_boundaries = parsed_arch.get("trust_boundaries", [])

        # Build component list
        component_text = []
        for comp in components[:15]:
            name = comp.get("name", "Unknown")
            comp_type = comp.get("type", "process")
            category = comp.get("category", "")
            tech = comp.get("technology", "")
            internet_facing = "⚠️ INTERNET FACING" if comp.get("internet_facing") else ""
            sensitive = "🔐 HANDLES SENSITIVE DATA" if comp.get("handles_sensitive_data") else ""

            component_text.append(
                f"- {name} ({comp_type}/{category}): {tech} {internet_facing} {sensitive}".strip()
            )

        # Build data flow list
        flow_text = []
        for flow in data_flows[:20]:
            source = flow.get("source", "?")
            target = flow.get("target", "?")
            data_type = flow.get("data_type", "data")
            protocol = flow.get("protocol", "")
            encrypted = "🔒" if flow.get("encrypted") else ""
            flow_text.append(f"- {source} → {target}: {data_type} ({protocol}) {encrypted}".strip())

        # Build trust boundary list
        boundary_text = []
        for tb in trust_boundaries:
            name = tb.get("name", "Boundary")
            level = tb.get("trust_level", "trusted")
            boundary_text.append(f"- {name} (Trust Level: {level})")

        return f"""System Overview: {parsed_arch.get('system_overview', 'Application System')}

Components:
{chr(10).join(component_text)}

Data Flows:
{chr(10).join(flow_text)}

Trust Boundaries:
{chr(10).join(boundary_text)}

Technology Stack: {', '.join(parsed_arch.get('technology_stack', []))}
"""

    def generate_eraser_diagrams_sync(
        self,
        parsed_arch: Dict[str, Any],
        stride_analysis: Dict[str, List[Dict]],
        attack_trees: List[Dict],
        kill_chain: Dict[str, Any],
        theme: str = "light"
    ) -> Dict[str, Any]:
        """
        Synchronous wrapper for Eraser diagram generation.
        Use this from synchronous code paths.
        """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(
            self.generate_eraser_diagrams(
                parsed_arch, stride_analysis, attack_trees, kill_chain, theme
            )
        )

    def generate_attack_paths(self, parsed_arch: Dict, stride_threats: Dict, system_context: str = "") -> List[Dict]:
        """Generate potential attack paths with AI-powered analysis"""
        attack_paths = []

        # Build system context if not provided
        if not system_context:
            system_context = self._build_system_context(parsed_arch)

        # Find entry points (external-facing components)
        entry_points = [c for c in parsed_arch.get('components', [])
                       if c.get('internet_facing') or c.get('type') == 'external']

        # Find high-value targets (sensitive data stores)
        targets = [c for c in parsed_arch.get('components', [])
                  if c.get('handles_sensitive_data') or c.get('type') == 'datastore']

        # Build adjacency list from data flows
        adjacency = {}
        for flow in parsed_arch.get('data_flows', []):
            src = flow['from']
            if src not in adjacency:
                adjacency[src] = []
            adjacency[src].append(flow['to'])

        # Collect all paths first
        all_path_data = []

        # Find paths from entry points to targets
        for entry in entry_points:
            for target in targets:
                paths = self._find_paths(entry['id'], target['id'], adjacency)
                for path in paths[:3]:  # Limit to top 3 paths per entry-target pair
                    # Calculate path risk
                    path_threats = []
                    for node_id in path:
                        node = next((c for c in parsed_arch['components'] if c['id'] == node_id), None)
                        if node:
                            for _, threats in stride_threats.items():
                                for threat in threats:
                                    if threat.get('component_id') == node_id:
                                        path_threats.append(threat)

                    if path_threats:
                        max_severity = max(
                            path_threats,
                            key=lambda t: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(t.get('severity', 'low'), 0)
                        )

                        # Convert path IDs to component names
                        path_names = []
                        for node_id in path:
                            node = next((c for c in parsed_arch['components'] if c['id'] == node_id), None)
                            if node:
                                path_names.append(node['name'])
                            else:
                                path_names.append(node_id)

                        # Calculate risk score on 0-100 scale
                        avg_risk = sum(t.get('risk_score', 5) for t in path_threats) / len(path_threats) if path_threats else 0
                        risk_score_100 = min(100, avg_risk * 10)  # Scale to 0-100

                        all_path_data.append({
                            'entry': entry,
                            'target': target,
                            'path_names': path_names,
                            'path_threats': path_threats,
                            'risk_score_100': risk_score_100,
                            'max_severity': max_severity,
                            'path_length': len(path)
                        })

        # Sort by risk score and take top 10
        all_path_data = sorted(all_path_data, key=lambda x: x['risk_score_100'], reverse=True)[:10]

        # Generate attack paths with AI enrichment for top 5 highest risk
        for idx, path_data in enumerate(all_path_data):
            entry = path_data['entry']
            target = path_data['target']
            path_names = path_data['path_names']
            path_threats = path_data['path_threats']
            risk_score_100 = path_data['risk_score_100']
            max_severity = path_data['max_severity']

            # Use AI for top 5 highest risk paths
            if idx < 5 and self.anthropic_client:
                ai_details = self._generate_attack_path_with_ai(
                    path_names, path_threats, entry, target, system_context
                )
            else:
                ai_details = self._get_fallback_attack_path(path_names, path_threats, entry, target)

            attack_paths.append({
                "id": f"path_{len(attack_paths)}",
                "entry_point": entry['name'],
                "entry_point_type": entry.get('category', 'unknown'),
                "target": target['name'],
                "target_type": target.get('category', 'unknown'),
                "path": path_names,
                "path_length": path_data['path_length'],
                "threats_along_path": len(path_threats),
                "max_severity": max_severity.get('severity', 'low'),
                "risk_score": round(risk_score_100, 1),
                "threats": [t.get('threat') for t in path_threats[:5]],
                "mitre_techniques": list(set(
                    tech for t in path_threats for tech in t.get('mitre_techniques', [])
                )),
                # AI-generated or fallback details
                "attack_scenario": ai_details.get('attack_scenario', ''),
                "exploitation_steps": ai_details.get('exploitation_steps', []),
                "potential_impact": ai_details.get('potential_impact', {}),
                "difficulty": ai_details.get('difficulty', {}),
                "detection_opportunities": ai_details.get('detection_opportunities', []),
                "recommended_controls": ai_details.get('recommended_controls', []),
            })

        # Sort by risk score
        attack_paths.sort(key=lambda p: p['risk_score'], reverse=True)
        return attack_paths[:10]  # Return top 10 attack paths

    def _find_paths(self, start: str, end: str, adjacency: Dict, max_depth: int = 5) -> List[List[str]]:
        """Find all paths between two nodes using BFS"""
        if start == end:
            return [[start]]

        paths = []
        queue = [(start, [start])]

        while queue and len(paths) < 10:
            current, path = queue.pop(0)

            if len(path) > max_depth:
                continue

            for neighbor in adjacency.get(current, []):
                if neighbor not in path:
                    new_path = path + [neighbor]
                    if neighbor == end:
                        paths.append(new_path)
                    else:
                        queue.append((neighbor, new_path))

        return paths

    def _generate_attack_scenario(self, entry: Dict, target: Dict, path_names: List[str], threats: List[Dict]) -> str:
        """Generate a detailed narrative of the attack scenario"""
        entry_name = entry.get('name', 'Entry Point')
        target_name = target.get('name', 'Target')
        entry_type = entry.get('category', 'component')
        target_type = target.get('category', 'data store')

        # Get the most critical threat for context
        critical_threats = [t for t in threats if t.get('severity') == 'critical']
        main_threat = critical_threats[0] if critical_threats else (threats[0] if threats else None)

        if not main_threat:
            return f"An attacker could potentially traverse from {entry_name} to {target_name} through the identified path."

        threat_name = main_threat.get('threat', 'unknown vulnerability')

        scenarios = {
            'SQL Injection': f"An attacker targets {entry_name} ({entry_type}) by injecting malicious SQL queries through user input fields. The attack progresses through {' → '.join(path_names)}, exploiting the {threat_name} vulnerability. The attacker gains unauthorized access to {target_name} ({target_type}), potentially exfiltrating sensitive data, modifying records, or escalating privileges within the database.",

            'JWT Token Forgery': f"An attacker intercepts or forges JWT tokens used for authentication at {entry_name}. By exploiting weak signing algorithms or key management, they create valid-looking tokens to impersonate legitimate users. Traversing through {' → '.join(path_names)}, the attacker gains unauthorized access to {target_name} with elevated privileges.",

            'XSS': f"An attacker injects malicious JavaScript through {entry_name}'s input fields. When other users access the application, the script executes in their browsers, stealing session cookies or credentials. The attacker uses these to access {target_name} through the path {' → '.join(path_names)}, compromising sensitive user data.",

            'BOLA': f"An attacker manipulates object references in API requests to {entry_name}. By changing user IDs or resource identifiers, they access other users' data. Progressing through {' → '.join(path_names)}, the attacker reaches {target_name} and extracts confidential information without proper authorization.",

            'SSRF': f"An attacker exploits {entry_name} to make unauthorized server-side requests. By manipulating URL parameters, they access internal services and eventually reach {target_name} through {' → '.join(path_names)}. This may expose internal APIs, cloud metadata, or sensitive backend services.",
        }

        base_scenario = scenarios.get(threat_name, f"An attacker exploits {threat_name} at {entry_name} to gain initial access. They then move laterally through {' → '.join(path_names)}, exploiting additional vulnerabilities at each step. The ultimate goal is to compromise {target_name} and extract or manipulate its sensitive data.")

        return base_scenario

    def _generate_exploitation_steps(self, path_names: List[str], threats: List[Dict]) -> List[Dict]:
        """Generate step-by-step exploitation details with action and details fields"""
        steps = []

        # Step 1: Reconnaissance
        steps.append({
            "step": 1,
            "phase": "Reconnaissance",
            "action": f"Identify {path_names[0]} as entry point",
            "details": f"Attacker identifies {path_names[0]} as an entry point through network scanning, web crawling, or social engineering. Techniques include port scanning, web application fingerprinting, and OSINT gathering.",
        })

        # Step 2: Initial Access
        if threats:
            initial_threat = threats[0]
            threat_name = initial_threat.get('threat', 'vulnerability')
            cwe = initial_threat.get('cwe_id', '')
            steps.append({
                "step": 2,
                "phase": "Initial Access",
                "action": f"Exploit {threat_name}",
                "details": f"Attacker exploits {threat_name} in {path_names[0]} to gain initial foothold.{' Related to ' + cwe + '.' if cwe else ''} This provides initial access to the system.",
            })

        # Step 3-N: Lateral Movement
        for i, node in enumerate(path_names[1:-1], start=3):
            step_threats = [t for t in threats if node in t.get('component', '')]
            step_threat = step_threats[0] if step_threats else None
            technique = step_threat.get('threat') if step_threat else "trust relationship exploitation"

            steps.append({
                "step": i,
                "phase": "Lateral Movement",
                "action": f"Move laterally to {node}",
                "details": f"Attacker moves to {node}, exploiting {technique}. This step involves privilege escalation or credential reuse to gain access to additional systems.",
            })

        # Final Step: Objective
        if len(path_names) > 1:
            target = path_names[-1]
            steps.append({
                "step": len(steps) + 1,
                "phase": "Objective Completion",
                "action": f"Compromise {target}",
                "details": f"Attacker reaches {target} and achieves their goal: data exfiltration, modification, or destruction. May also establish persistence for future access.",
            })

        return steps

    def _generate_path_impact(self, target: Dict, threats: List[Dict]) -> Dict[str, Any]:
        """Generate detailed impact assessment for the attack path"""
        target_name = target.get('name', 'Target')
        handles_sensitive = target.get('handles_sensitive_data', False)
        target_type = target.get('category', 'unknown')

        # Calculate severity counts
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for t in threats:
            sev = t.get('severity', 'medium')
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Determine overall impact level
        if severity_counts['critical'] > 0 or handles_sensitive:
            impact_level = "Critical"
            impact_description = f"Complete compromise of {target_name} is possible, leading to full data breach, service disruption, or unauthorized system control."
        elif severity_counts['high'] > 0:
            impact_level = "High"
            impact_description = f"Significant compromise of {target_name} is possible, with potential for substantial data exposure or service degradation."
        elif severity_counts['medium'] > 0:
            impact_level = "Medium"
            impact_description = f"Partial compromise of {target_name} may occur, with limited data exposure or minor service impact."
        else:
            impact_level = "Low"
            impact_description = f"Minimal impact to {target_name} expected, with little to no data exposure."

        return {
            "level": impact_level,
            "description": impact_description,
            "data_at_risk": ["Sensitive user data", "Credentials", "Business data"] if handles_sensitive else ["Application data"],
            "affected_systems": [target_name],
            "recovery_time": "Hours to days" if impact_level in ["Critical", "High"] else "Hours",
            "regulatory_implications": "Potential breach notification required" if handles_sensitive else "None expected",
            "severity_breakdown": severity_counts
        }

    def _assess_path_difficulty(self, threats: List[Dict]) -> Dict[str, Any]:
        """Assess the difficulty of executing the attack path with frontend-compatible fields"""
        if not threats:
            return {
                "level": "Unknown",
                "description": "Unable to assess difficulty",
                "required_skills": "Unknown",
                "time_estimate": "Unknown",
                "tools_needed": []
            }

        # Check for critical/high severity (usually easier to exploit)
        critical_count = sum(1 for t in threats if t.get('severity') == 'critical')
        high_count = sum(1 for t in threats if t.get('severity') == 'high')

        if critical_count >= 2:
            difficulty = "Low"
            description = "Multiple critical vulnerabilities make this path easily exploitable with widely available tools and techniques."
            time_estimate = "Hours"
            required_skills = "Intermediate"
            tools = ["SQLMap", "Burp Suite", "OWASP ZAP", "Metasploit"]
        elif critical_count >= 1 or high_count >= 2:
            difficulty = "Low to Medium"
            description = "Critical or multiple high-severity vulnerabilities reduce the skill required for exploitation."
            time_estimate = "Hours to days"
            required_skills = "Intermediate"
            tools = ["Burp Suite", "Custom scripts", "Exploitation frameworks"]
        elif high_count >= 1:
            difficulty = "Medium"
            description = "High-severity vulnerabilities exist but may require specific conditions or knowledge to exploit."
            time_estimate = "Days"
            required_skills = "Intermediate to Advanced"
            tools = ["Custom exploit code", "Proxy tools", "Network sniffers"]
        else:
            difficulty = "High"
            description = "Lower severity vulnerabilities require significant skill and specific conditions to chain together."
            time_estimate = "Days to weeks"
            required_skills = "Advanced"
            tools = ["Custom tooling", "Reverse engineering tools", "Advanced debugging"]

        return {
            "level": difficulty,
            "description": description,
            "required_skills": required_skills,
            "time_estimate": time_estimate,
            "tools_needed": tools,
            "chaining_required": len(threats) > 1
        }

    def _identify_detection_points(self, path_names: List[str], threats: List[Dict]) -> List[Dict]:
        """Identify opportunities for detecting the attack with frontend-compatible fields"""
        detection_points = []

        # Entry point detection
        detection_points.append({
            "point": f"Entry Point: {path_names[0]}",
            "method": "Web Application Firewall (WAF) rules, input validation monitoring, and anomaly detection on request patterns. Monitor web server logs, application logs, and WAF logs.",
            "effectiveness": "High"
        })

        # Add detection for each threat
        for threat in threats[:3]:  # Top 3 threats
            threat_name = threat.get('threat', 'Unknown Threat')
            detection_method = threat.get('detection', 'Anomaly detection')
            detection_points.append({
                "point": f"{threat_name} at {threat.get('component', 'component')}",
                "method": f"{detection_method}. Use SIEM correlation rules and behavioral analysis. Monitor security logs, application logs, and database logs.",
                "effectiveness": "High" if threat.get('severity') in ['critical', 'high'] else "Medium"
            })

        # Target detection
        if len(path_names) > 1:
            detection_points.append({
                "point": f"Target: {path_names[-1]}",
                "method": "Database activity monitoring, Data Loss Prevention (DLP), and unusual query pattern detection. Monitor database audit logs, access logs, and DLP alerts.",
                "effectiveness": "High"
            })

        return detection_points

    def _recommend_path_controls(self, threats: List[Dict]) -> List[Dict]:
        """Recommend security controls with implementation details"""
        controls = []

        # Collect unique mitigations from threats
        seen_mitigations = set()
        for threat in threats:
            mitigation = threat.get('mitigation', '')
            if mitigation and mitigation not in seen_mitigations:
                seen_mitigations.add(mitigation)
                threat_name = threat.get('threat', 'vulnerability')
                severity = threat.get('severity', 'medium')
                controls.append({
                    "control": f"Mitigate {threat_name}",
                    "implementation": mitigation,
                    "priority": "Critical" if severity == 'critical' else "High" if severity == 'high' else "Medium"
                })

        # Add general controls with implementation details
        general_controls = [
            {
                "control": "Network Segmentation",
                "implementation": "Implement network segmentation to limit lateral movement. Use VLANs, firewalls, and micro-segmentation to isolate critical systems.",
                "priority": "High"
            },
            {
                "control": "Logging and Monitoring",
                "implementation": "Deploy comprehensive logging and monitoring with SIEM integration. Set up alerts for suspicious patterns and ensure log retention policies.",
                "priority": "High"
            },
            {
                "control": "Incident Response",
                "implementation": "Establish incident response procedures for this attack path. Include playbooks, communication plans, and recovery procedures.",
                "priority": "Medium"
            },
            {
                "control": "Penetration Testing",
                "implementation": "Conduct regular penetration testing focusing on this attack path. Include both automated scanning and manual testing.",
                "priority": "Medium"
            }
        ]

        controls.extend(general_controls)
        return controls[:10]  # Limit to top 10 controls

    def generate_threat_model(
        self,
        architecture_doc: str,
        project_name: str,
        architecture_diagram: Optional[str] = None,
        diagram_media_type: str = "image/png",
        organization_size: str = "medium",
        industry: str = "technology",
        annual_revenue: float = 10000000,
        customer_count: int = 10000,
        generate_eraser_diagrams: bool = False,  # Disabled by default - requires API key
        diagram_theme: str = "light",
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Complete threat modeling workflow with AI-powered analysis.

        Args:
            architecture_doc: Architecture documentation text
            project_name: Name of the project
            architecture_diagram: Optional base64-encoded architecture diagram
            diagram_media_type: MIME type of the diagram image
            organization_size: "small", "medium", or "large"
            industry: Industry vertical for risk calculations
            annual_revenue: Annual revenue for FAIR calculations
            customer_count: Number of customers for impact calculations
            generate_eraser_diagrams: Whether to generate Eraser AI professional diagrams
            diagram_theme: "light" or "dark" theme for Eraser diagrams
            progress_callback: Optional callback function(step: str, progress: int, message: str)
        """

        def update_progress(step: str, progress: int, message: str = ""):
            if progress_callback:
                try:
                    progress_callback(step, progress, message)
                except Exception as e:
                    logger.warning(f"Progress callback failed: {e}")

        update_progress("analyzing", 10, "Analyzing architecture...")

        # Analyze architecture with AI
        parsed_arch = self.analyze_architecture_with_ai(
            architecture_doc,
            architecture_diagram,
            diagram_media_type
        )
        update_progress("architecture", 20, "Architecture analyzed")

        # Build system context once for AI prompts
        system_context = self._build_system_context(parsed_arch)
        update_progress("dfd", 25, "Generating data flow diagrams...")

        # Generate DFD structures
        dfd_level_0 = self.generate_dfd(parsed_arch, level=0)
        dfd_level_0['mermaid'] = self.generate_mermaid_dfd(dfd_level_0, level=0)

        dfd_level_1 = self.generate_dfd(parsed_arch, level=1)
        dfd_level_1['mermaid'] = self.generate_mermaid_dfd(dfd_level_1, level=1)
        update_progress("stride", 35, "Running STRIDE analysis...")

        # Generate STRIDE analysis with AI enrichment
        stride_analysis = self.generate_stride_analysis(parsed_arch, system_context)
        update_progress("mitre", 50, "Mapping to MITRE ATT&CK...")

        # Map to MITRE ATT&CK
        mitre_mapping = self.map_mitre_attack(stride_analysis)
        update_progress("attack_paths", 60, "Analyzing attack paths...")

        # Generate attack paths with AI analysis
        attack_paths = self.generate_attack_paths(parsed_arch, stride_analysis, system_context)
        update_progress("fair", 70, "Calculating FAIR risk...")

        # Generate FAIR Risk Quantification
        fair_risk = self.calculate_fair_risk(
            stride_analysis, parsed_arch,
            organization_size=organization_size,
            industry=industry,
            annual_revenue=annual_revenue,
            customer_count=customer_count
        )
        update_progress("attack_trees", 80, "Building attack trees...")

        # Generate Attack Trees
        attack_trees = self.generate_attack_trees(stride_analysis, parsed_arch)
        update_progress("kill_chain", 85, "Analyzing kill chain...")

        # Generate Kill Chain Analysis
        kill_chain = self.generate_kill_chain_analysis(stride_analysis, mitre_mapping, attack_paths)

        # Generate Eraser AI Professional Diagrams (if enabled and configured)
        eraser_diagrams = {"enabled": False, "diagrams": {}}
        if generate_eraser_diagrams and self.eraser_enabled:
            update_progress("eraser", 90, "Generating Eraser AI diagrams...")
            try:
                eraser_diagrams = self.generate_eraser_diagrams_sync(
                    parsed_arch, stride_analysis, attack_trees, kill_chain, diagram_theme
                )
                logger.info(f"[ThreatModelingService] Generated {eraser_diagrams.get('stats', {}).get('successful', 0)} Eraser diagrams")
            except Exception as e:
                logger.error(f"[ThreatModelingService] Eraser diagram generation failed: {e}")
                eraser_diagrams = {
                    "enabled": False,
                    "error": str(e),
                    "diagrams": {}
                }

        # Calculate statistics
        total_threats = sum(len(threats) for threats in stride_analysis.values())
        critical_threats = sum(
            1 for threats in stride_analysis.values()
            for t in threats if t.get('severity') == 'critical'
        )
        high_threats = sum(
            1 for threats in stride_analysis.values()
            for t in threats if t.get('severity') == 'high'
        )

        # Calculate overall risk score
        all_scores = [
            t.get('risk_score', 5)
            for threats in stride_analysis.values()
            for t in threats
        ]
        avg_risk = sum(all_scores) / len(all_scores) if all_scores else 0

        return {
            "project_name": project_name,
            "generated_at": datetime.now().isoformat(),
            "system_overview": parsed_arch.get('system_overview', ''),
            "technology_stack": parsed_arch.get('technology_stack', []),

            # DFD data
            "dfd_level_0": dfd_level_0,
            "dfd_level_1": dfd_level_1,
            "dfd_data": dfd_level_0,  # Backward compatibility

            # Analysis results
            "stride_analysis": stride_analysis,
            "mitre_mapping": mitre_mapping,
            "attack_paths": attack_paths,

            # NEW: Enhanced analysis features
            "fair_risk_analysis": fair_risk,
            "attack_trees": attack_trees,
            "kill_chain_analysis": kill_chain,

            # Professional Eraser AI Diagrams
            "eraser_diagrams": eraser_diagrams,

            # Risk metrics
            "threat_count": total_threats,
            "risk_score": round(avg_risk, 1),
            "risk_level": "Critical" if avg_risk >= 8 else "High" if avg_risk >= 6 else "Medium" if avg_risk >= 4 else "Low",
            "annual_loss_expectancy": fair_risk.get("aggregate_risk", {}).get("total_annual_loss_expectancy", {}),

            "summary": {
                "total_components": len(parsed_arch.get('components', [])),
                "total_data_flows": len(parsed_arch.get('data_flows', [])),
                "trust_boundaries": len(parsed_arch.get('trust_boundaries', [])),
                "total_threats": total_threats,
                "critical_threats": critical_threats,
                "high_threats": high_threats,
                "stride_breakdown": {cat: len(threats) for cat, threats in stride_analysis.items()},
                "mitre_techniques_count": mitre_mapping.get('total_techniques', 0),
                "tactics_covered": mitre_mapping.get('tactics_covered', 0),
                "attack_paths_identified": len(attack_paths),
                # NEW: Enhanced summary
                "attack_trees_generated": len(attack_trees),
                "kill_chain_coverage": kill_chain.get("coverage_analysis", {}).get("coverage_percentage", 0),
                "estimated_annual_risk": fair_risk.get("aggregate_risk", {}).get("total_annual_loss_expectancy", {}).get("likely", 0),
                # Eraser diagram stats
                "eraser_diagrams_enabled": eraser_diagrams.get("enabled", False),
                "eraser_diagrams_generated": eraser_diagrams.get("stats", {}).get("successful", 0),
            }
        }


# =============================================================================
    # FAIR RISK QUANTIFICATION MODEL
    # =============================================================================

    # FAIR Loss Magnitude Categories (in USD)
    FAIR_LOSS_MAGNITUDE = {
        "productivity": {
            "description": "Lost productivity due to incident response",
            "per_hour_cost": 150,  # Average hourly rate for IT/Dev staff
        },
        "response": {
            "description": "Incident response costs",
            "base_cost": 50000,  # Base incident response
            "per_severity": {"critical": 500000, "high": 200000, "medium": 75000, "low": 25000}
        },
        "replacement": {
            "description": "System replacement/recovery costs",
            "per_severity": {"critical": 250000, "high": 100000, "medium": 40000, "low": 10000}
        },
        "fines": {
            "description": "Regulatory fines and penalties",
            "pci_dss": 500000,
            "hipaa": 1500000,
            "gdpr": 4000000,  # Up to 4% of global revenue
            "general": 100000
        },
        "reputation": {
            "description": "Reputational damage and customer loss",
            "customer_churn_rate": 0.05,  # 5% customer churn
            "avg_customer_value": 10000
        },
        "legal": {
            "description": "Legal fees and settlements",
            "base_cost": 100000,
            "per_affected_user": 150  # Class action settlement per user
        }
    }

    # FAIR Threat Event Frequency (Annual)
    FAIR_TEF_ESTIMATES = {
        "critical": {"min": 1, "likely": 3, "max": 12},    # 1-12 attempts per year
        "high": {"min": 2, "likely": 6, "max": 24},        # 2-24 attempts per year
        "medium": {"min": 4, "likely": 12, "max": 52},     # Monthly to weekly
        "low": {"min": 12, "likely": 52, "max": 365}       # Weekly to daily
    }

    # FAIR Vulnerability (Success Rate)
    FAIR_VULNERABILITY_RATES = {
        "critical": {"min": 0.6, "likely": 0.8, "max": 0.95},   # High success rate
        "high": {"min": 0.3, "likely": 0.5, "max": 0.7},        # Medium-high success
        "medium": {"min": 0.1, "likely": 0.25, "max": 0.4},     # Medium success
        "low": {"min": 0.01, "likely": 0.05, "max": 0.15}       # Low success rate
    }

    def calculate_fair_risk(self, stride_threats: Dict[str, List[Dict]],
                           parsed_arch: Dict[str, Any],
                           organization_size: str = "medium",
                           industry: str = "technology",
                           annual_revenue: float = 10000000,
                           customer_count: int = 10000) -> Dict[str, Any]:
        """
        Calculate quantitative risk using FAIR (Factor Analysis of Information Risk) model.

        Returns dollar-based loss estimates with confidence intervals.
        """
        fair_results = {
            "methodology": "FAIR (Factor Analysis of Information Risk)",
            "parameters": {
                "organization_size": organization_size,
                "industry": industry,
                "annual_revenue": annual_revenue,
                "customer_count": customer_count
            },
            "threat_analysis": [],
            "aggregate_risk": {},
            "loss_categories": {},
            "recommendations": []
        }

        # Size multipliers
        size_multipliers = {"small": 0.3, "medium": 1.0, "large": 2.5, "enterprise": 5.0}
        size_mult = size_multipliers.get(organization_size, 1.0)

        # Industry risk multipliers
        industry_multipliers = {
            "healthcare": 1.5, "finance": 1.8, "government": 1.3,
            "retail": 1.2, "technology": 1.0, "manufacturing": 0.9
        }
        industry_mult = industry_multipliers.get(industry, 1.0)

        total_ale_min = 0
        total_ale_likely = 0
        total_ale_max = 0
        loss_by_category = {
            "productivity": 0,
            "response": 0,
            "replacement": 0,
            "fines": 0,
            "reputation": 0,
            "legal": 0
        }

        # Analyze each threat
        for stride_cat, threats in stride_threats.items():
            for threat in threats:
                severity = threat.get('severity', 'medium')
                component = threat.get('component', 'Unknown')
                handles_sensitive = any(
                    c.get('handles_sensitive_data', False)
                    for c in parsed_arch.get('components', [])
                    if c.get('name') == component
                )

                # Calculate Loss Event Frequency (LEF) = TEF × Vulnerability
                tef = self.FAIR_TEF_ESTIMATES.get(severity, self.FAIR_TEF_ESTIMATES['medium'])
                vuln = self.FAIR_VULNERABILITY_RATES.get(severity, self.FAIR_VULNERABILITY_RATES['medium'])

                lef_min = tef['min'] * vuln['min']
                lef_likely = tef['likely'] * vuln['likely']
                lef_max = tef['max'] * vuln['max']

                # Calculate Loss Magnitude (LM)
                response_cost = self.FAIR_LOSS_MAGNITUDE['response']['per_severity'].get(severity, 50000)
                replacement_cost = self.FAIR_LOSS_MAGNITUDE['replacement']['per_severity'].get(severity, 25000)

                # Productivity loss (assume 40 hours for critical, scaled down)
                hours_lost = {"critical": 160, "high": 80, "medium": 40, "low": 16}.get(severity, 40)
                productivity_cost = hours_lost * self.FAIR_LOSS_MAGNITUDE['productivity']['per_hour_cost']

                # Fines (if handles sensitive data)
                fines_cost = 0
                if handles_sensitive:
                    if industry == "healthcare":
                        fines_cost = self.FAIR_LOSS_MAGNITUDE['fines']['hipaa'] * 0.1
                    elif industry == "finance":
                        fines_cost = self.FAIR_LOSS_MAGNITUDE['fines']['pci_dss'] * 0.1
                    else:
                        fines_cost = self.FAIR_LOSS_MAGNITUDE['fines']['general'] * 0.1

                # Reputation cost
                if severity in ['critical', 'high'] and handles_sensitive:
                    reputation_cost = (
                        self.FAIR_LOSS_MAGNITUDE['reputation']['customer_churn_rate'] *
                        customer_count *
                        self.FAIR_LOSS_MAGNITUDE['reputation']['avg_customer_value'] * 0.1
                    )
                else:
                    reputation_cost = 0

                # Legal costs
                legal_cost = 0
                if severity == 'critical' and handles_sensitive:
                    affected_users = customer_count * 0.1  # Assume 10% affected
                    legal_cost = (
                        self.FAIR_LOSS_MAGNITUDE['legal']['base_cost'] +
                        affected_users * self.FAIR_LOSS_MAGNITUDE['legal']['per_affected_user']
                    )

                # Total Loss Magnitude per event
                lm_min = (response_cost + productivity_cost) * 0.5 * size_mult * industry_mult
                lm_likely = (response_cost + replacement_cost + productivity_cost +
                            fines_cost + reputation_cost) * size_mult * industry_mult
                lm_max = (response_cost + replacement_cost + productivity_cost +
                         fines_cost + reputation_cost + legal_cost) * 1.5 * size_mult * industry_mult

                # Annual Loss Expectancy (ALE) = LEF × LM
                ale_min = lef_min * lm_min
                ale_likely = lef_likely * lm_likely
                ale_max = lef_max * lm_max

                total_ale_min += ale_min
                total_ale_likely += ale_likely
                total_ale_max += ale_max

                # Track by category
                loss_by_category["productivity"] += productivity_cost * lef_likely
                loss_by_category["response"] += response_cost * lef_likely
                loss_by_category["replacement"] += replacement_cost * lef_likely * 0.3
                loss_by_category["fines"] += fines_cost * lef_likely
                loss_by_category["reputation"] += reputation_cost * lef_likely
                loss_by_category["legal"] += legal_cost * lef_likely * 0.1

                fair_results["threat_analysis"].append({
                    "threat_id": threat.get('id'),
                    "threat_name": threat.get('threat'),
                    "component": component,
                    "severity": severity,
                    "stride_category": stride_cat,
                    "loss_event_frequency": {
                        "min": round(lef_min, 2),
                        "likely": round(lef_likely, 2),
                        "max": round(lef_max, 2),
                        "unit": "events/year"
                    },
                    "loss_magnitude": {
                        "min": round(lm_min, 0),
                        "likely": round(lm_likely, 0),
                        "max": round(lm_max, 0),
                        "currency": "USD"
                    },
                    "annual_loss_expectancy": {
                        "min": round(ale_min, 0),
                        "likely": round(ale_likely, 0),
                        "max": round(ale_max, 0),
                        "currency": "USD"
                    }
                })

        # Aggregate results
        fair_results["aggregate_risk"] = {
            "total_annual_loss_expectancy": {
                "min": round(total_ale_min, 0),
                "likely": round(total_ale_likely, 0),
                "max": round(total_ale_max, 0),
                "currency": "USD"
            },
            "risk_as_percentage_of_revenue": {
                "min": round((total_ale_min / annual_revenue) * 100, 2),
                "likely": round((total_ale_likely / annual_revenue) * 100, 2),
                "max": round((total_ale_max / annual_revenue) * 100, 2)
            },
            "confidence_interval": "90%",
            "risk_level": self._determine_fair_risk_level(total_ale_likely, annual_revenue)
        }

        # Loss by category
        fair_results["loss_categories"] = {
            cat: {"annual_expected_loss": round(val, 0), "currency": "USD"}
            for cat, val in loss_by_category.items()
        }

        # Generate recommendations based on risk
        fair_results["recommendations"] = self._generate_fair_recommendations(
            total_ale_likely, loss_by_category, fair_results["threat_analysis"]
        )

        return fair_results

    def _determine_fair_risk_level(self, ale: float, revenue: float) -> str:
        """Determine risk level based on ALE as percentage of revenue"""
        risk_pct = (ale / revenue) * 100 if revenue > 0 else 0
        if risk_pct >= 5:
            return "Critical"
        elif risk_pct >= 2:
            return "High"
        elif risk_pct >= 0.5:
            return "Medium"
        else:
            return "Low"

    def _generate_fair_recommendations(self, total_ale: float, loss_categories: Dict,
                                       threat_analysis: List[Dict]) -> List[Dict]:
        """Generate prioritized recommendations based on FAIR analysis"""
        recommendations = []

        # Sort threats by ALE
        sorted_threats = sorted(
            threat_analysis,
            key=lambda t: t['annual_loss_expectancy']['likely'],
            reverse=True
        )

        # Top 3 risk reduction opportunities
        for i, threat in enumerate(sorted_threats[:3], 1):
            ale = threat['annual_loss_expectancy']['likely']
            potential_reduction = ale * 0.7  # Assume 70% reduction with mitigation
            recommendations.append({
                "priority": i,
                "threat": threat['threat_name'],
                "component": threat['component'],
                "current_annual_risk": f"${ale:,.0f}",
                "potential_savings": f"${potential_reduction:,.0f}",
                "action": f"Implement mitigation for {threat['threat_name']} to reduce annual expected loss by ${potential_reduction:,.0f}",
                "roi": f"{(potential_reduction / (ale * 0.1)) * 100:.0f}%" if ale > 0 else "N/A"  # Assume 10% of ALE as mitigation cost
            })

        # Category-based recommendations
        top_category = max(loss_categories.items(), key=lambda x: x[1])
        if top_category[1] > 0:
            category_actions = {
                "productivity": "Implement automation and incident response playbooks to reduce recovery time",
                "response": "Establish dedicated incident response team and pre-negotiated retainer agreements",
                "fines": "Conduct compliance audit and implement regulatory controls",
                "reputation": "Develop crisis communication plan and customer notification procedures",
                "legal": "Review cyber insurance coverage and establish legal response procedures"
            }
            recommendations.append({
                "priority": 4,
                "category": top_category[0],
                "annual_exposure": f"${top_category[1]:,.0f}",
                "action": category_actions.get(top_category[0], "Review and enhance security controls"),
                "type": "category_mitigation"
            })

        return recommendations

    # =============================================================================
    # ATTACK TREE GENERATION
    # =============================================================================

    def generate_attack_trees(self, stride_threats: Dict[str, List[Dict]],
                             parsed_arch: Dict[str, Any]) -> List[Dict]:
        """
        Generate attack trees for each high-value target showing all possible attack paths.
        Attack trees visualize how an attacker could achieve a goal.
        """
        attack_trees = []

        # Identify high-value targets
        targets = [
            c for c in parsed_arch.get('components', [])
            if c.get('handles_sensitive_data') or c.get('type') == 'datastore'
        ]

        for target in targets[:5]:  # Limit to top 5 targets
            tree = self._build_attack_tree(target, stride_threats, parsed_arch)
            if tree['children']:  # Only include if there are attack vectors
                attack_trees.append(tree)

        return attack_trees

    def _build_attack_tree(self, target: Dict, stride_threats: Dict[str, List[Dict]],
                          parsed_arch: Dict[str, Any]) -> Dict:
        """Build an attack tree for a specific target"""
        target_name = target.get('name', 'Unknown Target')
        target_id = target.get('id')

        # Root node: The attacker's goal
        tree = {
            "id": f"tree_{target_id}",
            "name": f"Compromise {target_name}",
            "type": "goal",
            "description": f"Attacker goal: Gain unauthorized access to {target_name}",
            "target": target_name,
            "target_type": target.get('category', 'unknown'),
            "children": [],
            "metadata": {
                "handles_sensitive_data": target.get('handles_sensitive_data', False),
                "total_attack_vectors": 0,
                "critical_paths": 0,
                "mermaid": ""
            }
        }

        # Group threats by STRIDE category as primary branches
        stride_branches = {}
        for stride_cat, threats in stride_threats.items():
            relevant_threats = [
                t for t in threats
                if t.get('component_id') == target_id or t.get('component') == target_name
            ]
            if relevant_threats:
                stride_branches[stride_cat] = relevant_threats

        # Find indirect attacks (attacks on components that connect to target)
        data_flows = parsed_arch.get('data_flows', [])
        connecting_components = set()
        for flow in data_flows:
            if flow.get('to') == target_id:
                connecting_components.add(flow.get('from'))

        for comp_id in connecting_components:
            comp = next((c for c in parsed_arch.get('components', []) if c.get('id') == comp_id), None)
            if comp:
                for stride_cat, threats in stride_threats.items():
                    for threat in threats:
                        if threat.get('component_id') == comp_id:
                            if stride_cat not in stride_branches:
                                stride_branches[stride_cat] = []
                            # Mark as indirect attack
                            threat_copy = threat.copy()
                            threat_copy['indirect'] = True
                            threat_copy['via_component'] = comp.get('name')
                            stride_branches[stride_cat].append(threat_copy)

        # Build tree branches
        for stride_cat, threats in stride_branches.items():
            if not threats:
                continue

            branch = {
                "id": f"branch_{stride_cat.lower().replace(' ', '_')}",
                "name": stride_cat,
                "type": "or",  # OR gate - any of these attack vectors
                "description": self.STRIDE_CATEGORIES.get(stride_cat, {}).get('description', ''),
                "icon": self.STRIDE_CATEGORIES.get(stride_cat, {}).get('icon', '⚠️'),
                "children": []
            }

            for threat in threats[:5]:  # Limit to top 5 per category
                attack_node = {
                    "id": f"attack_{threat.get('id')}",
                    "name": threat.get('threat'),
                    "type": "attack",
                    "severity": threat.get('severity'),
                    "cwe": threat.get('cwe'),
                    "mitre": threat.get('mitre_techniques', []),
                    "risk_score": threat.get('risk_score', 5.0),
                    "indirect": threat.get('indirect', False),
                    "via_component": threat.get('via_component'),
                    "children": []
                }

                # Add prerequisites as AND children (all must be true)
                prerequisites = self._get_attack_prerequisites(threat, target)
                if prerequisites.get('conditions'):
                    prereq_node = {
                        "id": f"prereq_{threat.get('id')}",
                        "name": "Prerequisites",
                        "type": "and",  # AND gate - all conditions must be met
                        "children": [
                            {"id": f"cond_{i}", "name": cond, "type": "condition"}
                            for i, cond in enumerate(prerequisites.get('conditions', []))
                        ]
                    }
                    attack_node['children'].append(prereq_node)

                branch['children'].append(attack_node)
                tree['metadata']['total_attack_vectors'] += 1
                if threat.get('severity') == 'critical':
                    tree['metadata']['critical_paths'] += 1

            tree['children'].append(branch)

        # Generate Mermaid diagram for the tree
        tree['metadata']['mermaid'] = self._generate_attack_tree_mermaid(tree)

        return tree

    def _generate_attack_tree_mermaid(self, tree: Dict) -> str:
        """Generate Mermaid flowchart for attack tree visualization"""
        lines = ["graph TD"]
        lines.append("    %% Attack Tree: " + tree['name'])
        lines.append("    classDef goal fill:#dc2626,stroke:#991b1b,color:#fff,stroke-width:3px")
        lines.append("    classDef or fill:#f97316,stroke:#c2410c,color:#fff")
        lines.append("    classDef and fill:#eab308,stroke:#a16207,color:#000")
        lines.append("    classDef attack fill:#3b82f6,stroke:#1d4ed8,color:#fff")
        lines.append("    classDef critical fill:#dc2626,stroke:#991b1b,color:#fff")
        lines.append("    classDef high fill:#f97316,stroke:#c2410c,color:#fff")
        lines.append("    classDef condition fill:#d1d5db,stroke:#6b7280,color:#000")
        lines.append("")

        # Root node
        root_id = self._sanitize_id(tree['id'])
        lines.append(f"    {root_id}{{\"🎯 {tree['name']}\"}}")
        lines.append(f"    class {root_id} goal")

        # Process children recursively
        self._add_tree_nodes_to_mermaid(lines, tree, root_id)

        return '\n'.join(lines)

    def _add_tree_nodes_to_mermaid(self, lines: List[str], parent: Dict, parent_id: str, depth: int = 0):
        """Recursively add tree nodes to Mermaid diagram"""
        if depth > 4:  # Limit depth
            return

        for child in parent.get('children', []):
            child_id = self._sanitize_id(child['id'])
            child_name = child.get('name', 'Node')[:40]  # Truncate long names
            node_type = child.get('type', 'node')

            # Determine shape based on type
            if node_type == 'or':
                icon = self.STRIDE_CATEGORIES.get(child_name, {}).get('icon', '⚡')
                lines.append(f"    {child_id}((\"{icon} {child_name}\"))")
                lines.append(f"    class {child_id} or")
            elif node_type == 'and':
                lines.append(f"    {child_id}[[\"{child_name}\"]]]")
                lines.append(f"    class {child_id} and")
            elif node_type == 'attack':
                severity = child.get('severity', 'medium')
                sev_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(severity, '⚪')
                lines.append(f"    {child_id}[\"{sev_icon} {child_name}\"]")
                if severity == 'critical':
                    lines.append(f"    class {child_id} critical")
                elif severity == 'high':
                    lines.append(f"    class {child_id} high")
                else:
                    lines.append(f"    class {child_id} attack")
            elif node_type == 'condition':
                lines.append(f"    {child_id}>{child_name}]")
                lines.append(f"    class {child_id} condition")
            else:
                lines.append(f"    {child_id}[\"{child_name}\"]")

            # Add edge
            edge_label = ""
            if child.get('indirect'):
                edge_label = f"|via {child.get('via_component', 'component')}|"
            lines.append(f"    {parent_id} --> {edge_label}{child_id}")

            # Recurse
            self._add_tree_nodes_to_mermaid(lines, child, child_id, depth + 1)

    # =============================================================================
    # ENHANCED KILL CHAIN ANALYSIS
    # =============================================================================

    # Cyber Kill Chain phases with ATT&CK mapping
    KILL_CHAIN_PHASES = {
        "reconnaissance": {
            "name": "Reconnaissance",
            "description": "Adversary gathers information about the target",
            "icon": "🔍",
            "color": "#6366f1",
            "attack_tactics": ["Reconnaissance"],
            "typical_techniques": ["T1595", "T1592", "T1589", "T1590", "T1591"]
        },
        "weaponization": {
            "name": "Weaponization",
            "description": "Adversary creates or acquires exploit tools",
            "icon": "🔧",
            "color": "#8b5cf6",
            "attack_tactics": ["Resource Development"],
            "typical_techniques": ["T1587", "T1588", "T1583", "T1584"]
        },
        "delivery": {
            "name": "Delivery",
            "description": "Adversary transmits weapon to target",
            "icon": "📨",
            "color": "#ec4899",
            "attack_tactics": ["Initial Access"],
            "typical_techniques": ["T1566", "T1190", "T1133", "T1195", "T1199"]
        },
        "exploitation": {
            "name": "Exploitation",
            "description": "Adversary exploits vulnerability to gain access",
            "icon": "💥",
            "color": "#ef4444",
            "attack_tactics": ["Execution", "Initial Access"],
            "typical_techniques": ["T1203", "T1059", "T1047", "T1190"]
        },
        "installation": {
            "name": "Installation",
            "description": "Adversary installs malware or backdoor",
            "icon": "📥",
            "color": "#f97316",
            "attack_tactics": ["Persistence", "Defense Evasion"],
            "typical_techniques": ["T1505", "T1136", "T1078", "T1070"]
        },
        "command_control": {
            "name": "Command & Control",
            "description": "Adversary establishes communication channel",
            "icon": "📡",
            "color": "#eab308",
            "attack_tactics": ["Command and Control"],
            "typical_techniques": ["T1071", "T1095", "T1573", "T1105"]
        },
        "actions_on_objectives": {
            "name": "Actions on Objectives",
            "description": "Adversary achieves their goals",
            "icon": "🎯",
            "color": "#22c55e",
            "attack_tactics": ["Collection", "Exfiltration", "Impact"],
            "typical_techniques": ["T1530", "T1567", "T1041", "T1486", "T1565"]
        }
    }

    # Map ATT&CK tactics to Kill Chain phases
    TACTIC_TO_KILLCHAIN = {
        "Reconnaissance": "reconnaissance",
        "Resource Development": "weaponization",
        "Initial Access": "delivery",
        "Execution": "exploitation",
        "Persistence": "installation",
        "Privilege Escalation": "exploitation",
        "Defense Evasion": "installation",
        "Credential Access": "exploitation",
        "Discovery": "reconnaissance",
        "Lateral Movement": "exploitation",
        "Collection": "actions_on_objectives",
        "Command and Control": "command_control",
        "Exfiltration": "actions_on_objectives",
        "Impact": "actions_on_objectives"
    }

    def generate_kill_chain_analysis(self, stride_threats: Dict[str, List[Dict]],
                                     mitre_mapping: Dict[str, Any],
                                     attack_paths: List[Dict]) -> Dict[str, Any]:
        """
        Generate comprehensive Kill Chain analysis with ATT&CK tactics visualization.
        Maps all identified threats to Kill Chain phases.
        """
        kill_chain = {
            "phases": {},
            "attack_sequences": [],
            "coverage_analysis": {},
            "mermaid_diagram": "",
            "timeline": [],
            "detection_matrix": {}
        }

        # Initialize all phases
        for phase_id, phase_info in self.KILL_CHAIN_PHASES.items():
            kill_chain["phases"][phase_id] = {
                **phase_info,
                "threats": [],
                "techniques": [],
                "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "affected_components": set(),
                "detection_opportunities": []
            }

        # Map threats to Kill Chain phases
        for stride_cat, threats in stride_threats.items():
            for threat in threats:
                mitre_techs = threat.get('mitre_techniques', [])
                for tech_id in mitre_techs:
                    if tech_id in mitre_mapping.get('techniques', {}):
                        tech_info = mitre_mapping['techniques'][tech_id]
                        tactic = tech_info.get('tactic', '')
                        phase_id = self.TACTIC_TO_KILLCHAIN.get(tactic)

                        if phase_id and phase_id in kill_chain["phases"]:
                            phase = kill_chain["phases"][phase_id]
                            phase["threats"].append({
                                "threat_id": threat.get('id'),
                                "threat_name": threat.get('threat'),
                                "component": threat.get('component'),
                                "severity": threat.get('severity'),
                                "stride_category": stride_cat,
                                "technique_id": tech_id,
                                "technique_name": tech_info.get('name')
                            })

                            if tech_id not in phase["techniques"]:
                                phase["techniques"].append(tech_id)

                            severity = threat.get('severity', 'medium')
                            phase["severity_breakdown"][severity] += 1
                            phase["affected_components"].add(threat.get('component', 'Unknown'))

        # Convert sets to lists for JSON serialization
        for phase_id in kill_chain["phases"]:
            kill_chain["phases"][phase_id]["affected_components"] = list(
                kill_chain["phases"][phase_id]["affected_components"]
            )
            # Add detection opportunities
            kill_chain["phases"][phase_id]["detection_opportunities"] = \
                self._get_phase_detection_opportunities(phase_id)

        # Generate attack sequences from attack paths
        for path in attack_paths[:5]:  # Top 5 paths
            sequence = self._map_path_to_killchain(path, kill_chain["phases"])
            if sequence:
                kill_chain["attack_sequences"].append(sequence)

        # Coverage analysis
        phases_with_threats = sum(
            1 for p in kill_chain["phases"].values() if p["threats"]
        )
        kill_chain["coverage_analysis"] = {
            "phases_covered": phases_with_threats,
            "total_phases": len(self.KILL_CHAIN_PHASES),
            "coverage_percentage": round((phases_with_threats / len(self.KILL_CHAIN_PHASES)) * 100, 1),
            "most_vulnerable_phase": self._get_most_vulnerable_phase(kill_chain["phases"]),
            "gaps": [
                p_info["name"] for p_id, p_info in kill_chain["phases"].items()
                if not p_info["threats"]
            ]
        }

        # Generate timeline visualization
        kill_chain["timeline"] = self._generate_killchain_timeline(kill_chain["phases"])

        # Generate Mermaid diagram
        kill_chain["mermaid_diagram"] = self._generate_killchain_mermaid(kill_chain)

        # Detection matrix
        kill_chain["detection_matrix"] = self._generate_detection_matrix(kill_chain["phases"])

        return kill_chain

    def _get_phase_detection_opportunities(self, phase_id: str) -> List[Dict]:
        """Get detection opportunities for a Kill Chain phase"""
        detection_map = {
            "reconnaissance": [
                {"method": "Network traffic analysis", "effectiveness": "Medium", "tools": ["IDS/IPS", "SIEM"]},
                {"method": "Honeypots and decoys", "effectiveness": "High", "tools": ["Honeypot systems"]},
                {"method": "DNS query monitoring", "effectiveness": "Medium", "tools": ["DNS logs", "SIEM"]}
            ],
            "weaponization": [
                {"method": "Threat intelligence feeds", "effectiveness": "Medium", "tools": ["TIP", "SIEM"]},
                {"method": "Dark web monitoring", "effectiveness": "Low", "tools": ["Dark web scrapers"]}
            ],
            "delivery": [
                {"method": "Email gateway scanning", "effectiveness": "High", "tools": ["Email security gateway"]},
                {"method": "Web application firewall", "effectiveness": "High", "tools": ["WAF"]},
                {"method": "Endpoint protection", "effectiveness": "High", "tools": ["EDR", "Antivirus"]}
            ],
            "exploitation": [
                {"method": "Intrusion detection", "effectiveness": "High", "tools": ["IDS/IPS", "WAF"]},
                {"method": "Vulnerability scanning", "effectiveness": "Medium", "tools": ["Vulnerability scanner"]},
                {"method": "Application monitoring", "effectiveness": "High", "tools": ["APM", "SIEM"]}
            ],
            "installation": [
                {"method": "File integrity monitoring", "effectiveness": "High", "tools": ["FIM", "EDR"]},
                {"method": "Registry monitoring", "effectiveness": "High", "tools": ["EDR", "SIEM"]},
                {"method": "Process monitoring", "effectiveness": "High", "tools": ["EDR"]}
            ],
            "command_control": [
                {"method": "Network traffic analysis", "effectiveness": "High", "tools": ["NDR", "SIEM"]},
                {"method": "DNS monitoring", "effectiveness": "High", "tools": ["DNS security"]},
                {"method": "Proxy logs analysis", "effectiveness": "High", "tools": ["Proxy", "SIEM"]}
            ],
            "actions_on_objectives": [
                {"method": "Data loss prevention", "effectiveness": "High", "tools": ["DLP"]},
                {"method": "Database activity monitoring", "effectiveness": "High", "tools": ["DAM"]},
                {"method": "User behavior analytics", "effectiveness": "High", "tools": ["UEBA"]}
            ]
        }
        return detection_map.get(phase_id, [])

    def _map_path_to_killchain(self, attack_path: Dict, phases: Dict) -> Dict:
        """Map an attack path to Kill Chain phases"""
        sequence = {
            "path_id": attack_path.get('id'),
            "entry_point": attack_path.get('entry_point'),
            "target": attack_path.get('target'),
            "risk_score": attack_path.get('risk_score'),
            "phases_involved": []
        }

        # Map MITRE techniques to phases
        mitre_techs = attack_path.get('mitre_techniques', [])
        phases_seen = set()

        for tech in mitre_techs:
            if tech in self.MITRE_TECHNIQUES:
                tactic = self.MITRE_TECHNIQUES[tech].get('tactic', '')
                phase_id = self.TACTIC_TO_KILLCHAIN.get(tactic)
                if phase_id and phase_id not in phases_seen:
                    phases_seen.add(phase_id)
                    sequence["phases_involved"].append({
                        "phase": phase_id,
                        "phase_name": self.KILL_CHAIN_PHASES.get(phase_id, {}).get('name', phase_id),
                        "technique": tech,
                        "technique_name": self.MITRE_TECHNIQUES[tech].get('name', tech)
                    })

        # Sort by Kill Chain order
        phase_order = list(self.KILL_CHAIN_PHASES.keys())
        sequence["phases_involved"].sort(
            key=lambda x: phase_order.index(x["phase"]) if x["phase"] in phase_order else 99
        )

        return sequence if sequence["phases_involved"] else None

    def _get_most_vulnerable_phase(self, phases: Dict) -> Dict:
        """Identify the most vulnerable Kill Chain phase"""
        max_score = 0
        most_vulnerable = None

        for phase_id, phase_info in phases.items():
            # Calculate vulnerability score
            score = (
                phase_info["severity_breakdown"]["critical"] * 4 +
                phase_info["severity_breakdown"]["high"] * 3 +
                phase_info["severity_breakdown"]["medium"] * 2 +
                phase_info["severity_breakdown"]["low"] * 1
            )
            if score > max_score:
                max_score = score
                most_vulnerable = {
                    "phase_id": phase_id,
                    "phase_name": phase_info["name"],
                    "vulnerability_score": score,
                    "threat_count": len(phase_info["threats"])
                }

        return most_vulnerable or {"phase_id": "none", "phase_name": "None identified"}

    def _generate_killchain_timeline(self, phases: Dict) -> List[Dict]:
        """Generate a timeline representation of the Kill Chain"""
        timeline = []
        phase_order = list(self.KILL_CHAIN_PHASES.keys())

        for phase_id in phase_order:
            phase_info = phases.get(phase_id, {})
            timeline.append({
                "phase": phase_id,
                "name": phase_info.get('name', phase_id),
                "icon": phase_info.get('icon', '⚪'),
                "color": phase_info.get('color', '#gray'),
                "threat_count": len(phase_info.get('threats', [])),
                "severity_breakdown": phase_info.get('severity_breakdown', {}),
                "active": bool(phase_info.get('threats')),
                "techniques": phase_info.get('techniques', [])[:5]  # Top 5 techniques
            })

        return timeline

    def _generate_killchain_mermaid(self, kill_chain: Dict) -> str:
        """Generate Mermaid diagram for Kill Chain visualization"""
        lines = ["graph LR"]
        lines.append("    %% Cyber Kill Chain Visualization")
        lines.append("    classDef active fill:#22c55e,stroke:#16a34a,color:#fff")
        lines.append("    classDef inactive fill:#d1d5db,stroke:#9ca3af,color:#374151")
        lines.append("    classDef critical fill:#dc2626,stroke:#991b1b,color:#fff")
        lines.append("    classDef high fill:#f97316,stroke:#c2410c,color:#fff")
        lines.append("")

        phase_order = list(self.KILL_CHAIN_PHASES.keys())
        phases = kill_chain.get("phases", {})

        prev_node = None
        for phase_id in phase_order:
            phase_info = phases.get(phase_id, {})
            node_id = self._sanitize_id(phase_id)
            name = phase_info.get('name', phase_id)
            icon = phase_info.get('icon', '⚪')
            threat_count = len(phase_info.get('threats', []))

            # Node with threat count
            if threat_count > 0:
                lines.append(f"    {node_id}[\"{icon} {name}<br/>({threat_count} threats)\"]")
                critical = phase_info.get('severity_breakdown', {}).get('critical', 0)
                high = phase_info.get('severity_breakdown', {}).get('high', 0)
                if critical > 0:
                    lines.append(f"    class {node_id} critical")
                elif high > 0:
                    lines.append(f"    class {node_id} high")
                else:
                    lines.append(f"    class {node_id} active")
            else:
                lines.append(f"    {node_id}[\"{icon} {name}\"]")
                lines.append(f"    class {node_id} inactive")

            # Connect to previous phase
            if prev_node:
                lines.append(f"    {prev_node} --> {node_id}")
            prev_node = node_id

        return '\n'.join(lines)

    def _generate_detection_matrix(self, phases: Dict) -> Dict:
        """Generate a detection capability matrix"""
        matrix = {
            "headers": ["Phase", "Threats", "Detection Tools", "Effectiveness"],
            "rows": []
        }

        for phase_id, phase_info in phases.items():
            detection = phase_info.get('detection_opportunities', [])
            tools = list(set(
                tool for d in detection for tool in d.get('tools', [])
            ))[:3]  # Top 3 tools

            avg_effectiveness = "Medium"
            if detection:
                eff_scores = {"High": 3, "Medium": 2, "Low": 1}
                avg_score = sum(
                    eff_scores.get(d.get('effectiveness', 'Medium'), 2)
                    for d in detection
                ) / len(detection)
                avg_effectiveness = "High" if avg_score >= 2.5 else "Medium" if avg_score >= 1.5 else "Low"

            matrix["rows"].append({
                "phase": phase_info.get('name', phase_id),
                "threat_count": len(phase_info.get('threats', [])),
                "detection_tools": tools,
                "effectiveness": avg_effectiveness
            })

        return matrix

    # =============================================================================
    # INCREMENTAL THREAT MODELING
    # =============================================================================

    def generate_threat_model_incremental(
        self,
        db_session,
        project_id: int,
        new_architecture: Dict[str, Any],
        user_id: Optional[int] = None,
        project_name: str = "Project",
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Generate threats incrementally by analyzing only changed components.

        Args:
            db_session: SQLAlchemy database session
            project_id: Project ID
            new_architecture: New architecture to compare against
            user_id: ID of user making the change
            project_name: Project name for display
            progress_callback: Optional callback function(step: str, progress: int, message: str)

        Returns:
            Threat model with lifecycle status annotations on each threat
        """
        from services.architecture_diff_service import ArchitectureDiffService
        from services.threat_lifecycle_service import ThreatLifecycleService
        from models.models import ArchitectureVersion, ThreatHistory, ThreatModel, ThreatStatus

        diff_service = ArchitectureDiffService()
        lifecycle_service = ThreatLifecycleService()

        def update_progress(step: str, progress: int, message: str = ""):
            if progress_callback:
                try:
                    progress_callback(step, progress, message)
                except Exception as e:
                    logger.warning(f"Progress callback failed: {e}")

        update_progress("loading", 5, "Loading previous architecture...")

        # 1. Get the latest architecture version
        prev_version = self._get_latest_architecture_version(db_session, project_id)
        old_architecture = prev_version.architecture_snapshot if prev_version else None

        update_progress("diffing", 10, "Computing architecture changes...")

        # 2. Compute diff
        arch_hash = diff_service.compute_hash(new_architecture)
        diff = diff_service.compute_diff(old_architecture, new_architecture)

        # 3. Check if there are any changes
        if diff.is_empty() and prev_version:
            update_progress("complete", 100, "No changes detected")
            # Return existing threat model with existing threats marked
            existing_model = self._get_current_threat_model(db_session, project_id)
            if existing_model:
                return self._annotate_existing_model(existing_model, lifecycle_service)

        update_progress("versioning", 15, "Creating architecture version...")

        # 4. Create new architecture version
        new_version_number = (prev_version.version_number + 1) if prev_version else 1
        new_version = ArchitectureVersion(
            project_id=project_id,
            version_number=new_version_number,
            architecture_hash=arch_hash,
            architecture_snapshot=new_architecture,
            change_summary=diff.to_summary_dict(),
            change_description=diff.generate_description(),
            impact_score=diff.impact_score,
            created_by=user_id
        )
        db_session.add(new_version)
        db_session.flush()  # Get the ID

        update_progress("analyzing", 20, "Loading existing threats...")

        # 5. Get existing threats from the last threat model
        existing_threats = self._get_existing_threats(db_session, project_id)

        update_progress("incremental", 30, "Analyzing changed components...")

        # 6. Analyze only changed components (or all if first version)
        if diff.is_empty() and not prev_version:
            # First version - analyze everything
            new_threats = self._analyze_all_components(new_architecture, project_name)
        else:
            # Incremental - only analyze affected components
            new_threats = self._analyze_changed_components(
                diff, new_architecture, project_name, update_progress
            )

        update_progress("classifying", 70, "Classifying threat lifecycle...")

        # 7. Classify threats
        classification = lifecycle_service.classify_threats(existing_threats, new_threats, diff)

        update_progress("saving", 80, "Saving threat history...")

        # 8. Save to threat_history
        self._save_threat_history(
            db_session, project_id, new_version.id, classification, lifecycle_service
        )

        update_progress("merging", 90, "Building final threat model...")

        # 9. Merge and return annotated threat model
        merged_threats = lifecycle_service.merge_threat_results(classification)

        # Build the final threat model structure
        system_context = self._build_system_context(new_architecture)

        result = {
            "project_name": project_name,
            "generated_at": datetime.now().isoformat(),
            "is_incremental": True,
            "architecture_version": {
                "id": new_version.id,
                "version_number": new_version_number,
                "change_summary": diff.to_summary_dict(),
                "change_description": diff.generate_description(),
                "impact_score": diff.impact_score
            },

            # Architecture data
            "system_overview": new_architecture.get('system_overview', ''),
            "technology_stack": new_architecture.get('technology_stack', []),

            # DFD data
            "dfd_level_0": self.generate_dfd(new_architecture, level=0),
            "dfd_level_1": self.generate_dfd(new_architecture, level=1),

            # Threats with lifecycle status
            "stride_analysis": self._group_threats_by_stride(merged_threats),
            "threats_with_status": merged_threats,

            # Lifecycle summary
            "lifecycle_summary": classification.summary(),

            # Statistics
            "threat_count": len(merged_threats),
            "summary": {
                "total_components": len(new_architecture.get('components', [])),
                "total_data_flows": len(new_architecture.get('data_flows', [])),
                "trust_boundaries": len(new_architecture.get('trust_boundaries', [])),
                "total_threats": len(merged_threats),
                "new_threats": classification.summary()['new'],
                "modified_threats": classification.summary()['modified'],
                "resolved_threats": classification.summary()['resolved'],
                "changes_detected": diff.total_change_count()
            }
        }

        update_progress("complete", 100, "Incremental analysis complete")

        return result

    def _get_latest_architecture_version(self, db_session, project_id: int):
        """Get the most recent architecture version for a project."""
        from models.models import ArchitectureVersion
        return db_session.query(ArchitectureVersion).filter(
            ArchitectureVersion.project_id == project_id
        ).order_by(ArchitectureVersion.version_number.desc()).first()

    def _get_current_threat_model(self, db_session, project_id: int):
        """Get the current threat model for a project."""
        from models.models import ThreatModel
        return db_session.query(ThreatModel).filter(
            ThreatModel.project_id == project_id
        ).order_by(ThreatModel.created_at.desc()).first()

    def _get_existing_threats(self, db_session, project_id: int) -> List[Dict]:
        """Get existing threats from the last threat model."""
        from models.models import ThreatHistory
        # Get the latest threats for each threat_id
        latest_threats = {}
        history_records = db_session.query(ThreatHistory).filter(
            ThreatHistory.project_id == project_id,
            ThreatHistory.status != ThreatStatus.RESOLVED
        ).order_by(ThreatHistory.created_at.desc()).all()

        for record in history_records:
            if record.threat_id not in latest_threats:
                threat_data = record.threat_data.copy() if record.threat_data else {}
                threat_data['threat_id'] = record.threat_id
                threat_data['affected_components'] = record.affected_components or []
                latest_threats[record.threat_id] = threat_data

        return list(latest_threats.values())

    def _analyze_all_components(
        self,
        architecture: Dict[str, Any],
        project_name: str
    ) -> List[Dict]:
        """Analyze all components (used for first version)."""
        system_context = self._build_system_context(architecture)
        stride_analysis = self.generate_stride_analysis(architecture, system_context)

        # Flatten STRIDE analysis into threat list with IDs
        threats = []
        from services.threat_lifecycle_service import ThreatLifecycleService
        lifecycle_service = ThreatLifecycleService()

        for category, category_threats in stride_analysis.items():
            for threat in category_threats:
                threat['stride_category'] = category
                threat['threat_id'] = lifecycle_service.generate_stable_threat_id(threat)
                threats.append(threat)

        return threats

    def _analyze_changed_components(
        self,
        diff,
        architecture: Dict[str, Any],
        project_name: str,
        update_progress: callable
    ) -> List[Dict]:
        """Analyze only components that changed."""
        from services.threat_lifecycle_service import ThreatLifecycleService
        lifecycle_service = ThreatLifecycleService()

        affected_ids = diff.get_affected_component_ids()
        if not affected_ids:
            return []

        # Filter architecture to only affected components
        affected_components = [
            c for c in architecture.get('components', [])
            if c.get('id') in affected_ids
        ]

        if not affected_components:
            return []

        update_progress("stride", 40, f"Analyzing {len(affected_components)} affected components...")

        # Create a subset architecture for analysis
        subset_arch = {
            'components': affected_components,
            'data_flows': [
                f for f in architecture.get('data_flows', [])
                if f.get('source') in affected_ids or f.get('target') in affected_ids
            ],
            'trust_boundaries': architecture.get('trust_boundaries', []),
            'technology_stack': architecture.get('technology_stack', []),
            'system_overview': architecture.get('system_overview', '')
        }

        system_context = self._build_system_context(subset_arch)
        stride_analysis = self.generate_stride_analysis(subset_arch, system_context)

        # Flatten and add IDs
        threats = []
        for category, category_threats in stride_analysis.items():
            for threat in category_threats:
                threat['stride_category'] = category
                threat['threat_id'] = lifecycle_service.generate_stable_threat_id(threat)
                threats.append(threat)

        return threats

    def _save_threat_history(
        self,
        db_session,
        project_id: int,
        version_id: int,
        classification,
        lifecycle_service
    ):
        """Save threat classification results to threat_history table."""
        from models.models import ThreatHistory, ThreatStatus

        status_map = {
            'new': ThreatStatus.NEW,
            'existing': ThreatStatus.EXISTING,
            'modified': ThreatStatus.MODIFIED,
            'resolved': ThreatStatus.RESOLVED
        }

        for threat_update in classification.all_threats():
            history_record = ThreatHistory(
                project_id=project_id,
                threat_id=threat_update.threat_id,
                architecture_version_id=version_id,
                status=status_map[threat_update.status],
                threat_data=threat_update.threat_data,
                change_reason=threat_update.change_reason,
                affected_components=threat_update.affected_components
            )
            db_session.add(history_record)

        db_session.flush()

    def _group_threats_by_stride(self, threats: List[Dict]) -> Dict[str, List[Dict]]:
        """Group threats by STRIDE category."""
        grouped = {
            'Spoofing': [],
            'Tampering': [],
            'Repudiation': [],
            'Information Disclosure': [],
            'Denial of Service': [],
            'Elevation of Privilege': []
        }

        for threat in threats:
            category = threat.get('stride_category', threat.get('category', 'Tampering'))
            if category in grouped:
                grouped[category].append(threat)
            else:
                grouped['Tampering'].append(threat)

        return grouped

    def _annotate_existing_model(self, threat_model, lifecycle_service) -> Dict:
        """Annotate an existing model's threats with 'existing' status."""
        # This is used when no changes are detected
        result = {
            "project_name": threat_model.name,
            "generated_at": datetime.now().isoformat(),
            "is_incremental": True,
            "no_changes_detected": True,
            "stride_analysis": threat_model.stride_analysis or {},
            "threat_count": threat_model.threat_count or 0,
            "lifecycle_summary": {
                'new': 0, 'existing': threat_model.threat_count or 0,
                'modified': 0, 'resolved': 0
            }
        }
        return result

    def get_architecture_version_history(
        self,
        db_session,
        project_id: int,
        limit: int = 10
    ) -> List[Dict]:
        """Get architecture version history for a project."""
        from models.models import ArchitectureVersion
        versions = db_session.query(ArchitectureVersion).filter(
            ArchitectureVersion.project_id == project_id
        ).order_by(ArchitectureVersion.version_number.desc()).limit(limit).all()

        return [
            {
                'id': v.id,
                'version_number': v.version_number,
                'architecture_hash': v.architecture_hash,
                'change_summary': v.change_summary,
                'change_description': v.change_description,
                'impact_score': v.impact_score,
                'created_at': v.created_at.isoformat() if v.created_at else None,
                'created_by': v.created_by
            }
            for v in versions
        ]

    def get_threat_timeline(
        self,
        db_session,
        project_id: int,
        threat_id: str
    ) -> List[Dict]:
        """Get the complete timeline for a specific threat."""
        from models.models import ThreatHistory
        from services.threat_lifecycle_service import ThreatLifecycleService

        records = db_session.query(ThreatHistory).filter(
            ThreatHistory.project_id == project_id,
            ThreatHistory.threat_id == threat_id
        ).order_by(ThreatHistory.created_at.asc()).all()

        lifecycle_service = ThreatLifecycleService()
        return lifecycle_service.get_threat_timeline([
            {
                'id': r.id,
                'threat_id': r.threat_id,
                'architecture_version_id': r.architecture_version_id,
                'status': r.status.value if r.status else 'unknown',
                'threat_data': r.threat_data,
                'change_reason': r.change_reason,
                'created_at': r.created_at
            }
            for r in records
        ])

    def compare_architecture_versions(
        self,
        db_session,
        project_id: int,
        version1_id: int,
        version2_id: int
    ) -> Dict:
        """Compare two architecture versions."""
        from models.models import ArchitectureVersion
        from services.architecture_diff_service import ArchitectureDiffService

        v1 = db_session.query(ArchitectureVersion).filter(
            ArchitectureVersion.id == version1_id,
            ArchitectureVersion.project_id == project_id
        ).first()

        v2 = db_session.query(ArchitectureVersion).filter(
            ArchitectureVersion.id == version2_id,
            ArchitectureVersion.project_id == project_id
        ).first()

        if not v1 or not v2:
            return {"error": "Version not found"}

        diff_service = ArchitectureDiffService()
        diff = diff_service.compute_diff(v1.architecture_snapshot, v2.architecture_snapshot)

        return {
            "version1": {
                "id": v1.id,
                "version_number": v1.version_number,
                "created_at": v1.created_at.isoformat() if v1.created_at else None
            },
            "version2": {
                "id": v2.id,
                "version_number": v2.version_number,
                "created_at": v2.created_at.isoformat() if v2.created_at else None
            },
            "diff": diff.to_summary_dict(),
            "description": diff.generate_description(),
            "impact_score": diff.impact_score,
            "has_security_relevant_changes": diff.has_security_relevant_changes
        }


# Singleton instance
threat_service = ThreatModelingService()
