"""
Architecture Input Service

Handles structured architecture input for threat modeling:
1. Structured form-based component/control input
2. Diagram upload with AI vision extraction
3. Merging both inputs for comprehensive threat modeling
"""

import json
import logging
import base64
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# COMPONENT TYPES AND SECURITY CONTROLS LIBRARY
# =============================================================================

class ComponentType(str, Enum):
    """Predefined component types for architecture"""
    WEB_FRONTEND = "web_frontend"
    MOBILE_APP = "mobile_app"
    API_GATEWAY = "api_gateway"
    REST_API = "rest_api"
    GRAPHQL_API = "graphql_api"
    GRPC_SERVICE = "grpc_service"
    MICROSERVICE = "microservice"
    MONOLITH = "monolith"
    AUTH_SERVICE = "auth_service"
    DATABASE_SQL = "database_sql"
    DATABASE_NOSQL = "database_nosql"
    CACHE = "cache"
    MESSAGE_QUEUE = "message_queue"
    FILE_STORAGE = "file_storage"
    CDN = "cdn"
    LOAD_BALANCER = "load_balancer"
    WAF = "waf"
    REVERSE_PROXY = "reverse_proxy"
    EXTERNAL_API = "external_api"
    PAYMENT_GATEWAY = "payment_gateway"
    EMAIL_SERVICE = "email_service"
    SMS_SERVICE = "sms_service"
    IDENTITY_PROVIDER = "identity_provider"
    LOGGING_SERVICE = "logging_service"
    MONITORING = "monitoring"
    SECRETS_MANAGER = "secrets_manager"
    CONTAINER_ORCHESTRATOR = "container_orchestrator"
    SERVERLESS_FUNCTION = "serverless_function"
    BATCH_PROCESSOR = "batch_processor"
    ML_MODEL = "ml_model"
    OTHER = "other"


class TrustZone(str, Enum):
    """Trust zones for components"""
    INTERNET = "internet"           # Public internet, untrusted
    DMZ = "dmz"                     # Demilitarized zone
    INTERNAL = "internal"           # Internal network
    RESTRICTED = "restricted"       # Highly restricted zone
    MANAGEMENT = "management"       # Management plane


class DataClassification(str, Enum):
    """Data sensitivity classifications"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"                     # Personally Identifiable Information
    PHI = "phi"                     # Protected Health Information
    PCI = "pci"                     # Payment Card Industry data
    CREDENTIALS = "credentials"     # Passwords, tokens, keys
    FINANCIAL = "financial"


class SecurityControl(str, Enum):
    """Security controls that can be applied"""
    # Authentication & Authorization
    AUTH_REQUIRED = "auth_required"
    MFA_ENABLED = "mfa_enabled"
    RBAC = "rbac"
    OAUTH2 = "oauth2"
    JWT_TOKENS = "jwt_tokens"
    API_KEYS = "api_keys"
    CERTIFICATE_AUTH = "certificate_auth"

    # Input Validation & Sanitization
    INPUT_VALIDATION = "input_validation"
    OUTPUT_ENCODING = "output_encoding"
    PARAMETERIZED_QUERIES = "parameterized_queries"
    CONTENT_TYPE_VALIDATION = "content_type_validation"
    FILE_TYPE_VALIDATION = "file_type_validation"

    # Encryption
    TLS_ENCRYPTION = "tls_encryption"
    DATA_AT_REST_ENCRYPTION = "data_at_rest_encryption"
    E2E_ENCRYPTION = "e2e_encryption"
    FIELD_LEVEL_ENCRYPTION = "field_level_encryption"

    # Network Security
    FIREWALL = "firewall"
    WAF_ENABLED = "waf_enabled"
    RATE_LIMITING = "rate_limiting"
    DDOS_PROTECTION = "ddos_protection"
    IP_ALLOWLIST = "ip_allowlist"
    VPN_REQUIRED = "vpn_required"
    NETWORK_SEGMENTATION = "network_segmentation"

    # Logging & Monitoring
    AUDIT_LOGGING = "audit_logging"
    SECURITY_MONITORING = "security_monitoring"
    INTRUSION_DETECTION = "intrusion_detection"
    ANOMALY_DETECTION = "anomaly_detection"

    # Session & Access Control
    SESSION_MANAGEMENT = "session_management"
    SESSION_TIMEOUT = "session_timeout"
    CSRF_PROTECTION = "csrf_protection"
    CORS_CONFIGURED = "cors_configured"

    # Data Protection
    DATA_MASKING = "data_masking"
    DATA_ANONYMIZATION = "data_anonymization"
    BACKUP_ENCRYPTION = "backup_encryption"
    SECURE_DELETE = "secure_delete"

    # Secrets Management
    SECRETS_ROTATION = "secrets_rotation"
    SECRETS_VAULT = "secrets_vault"
    NO_HARDCODED_SECRETS = "no_hardcoded_secrets"

    # Other
    SECURITY_HEADERS = "security_headers"
    CONTENT_SECURITY_POLICY = "content_security_policy"
    DEPENDENCY_SCANNING = "dependency_scanning"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    PENETRATION_TESTING = "penetration_testing"


# Technology options by component type
TECHNOLOGY_OPTIONS = {
    ComponentType.WEB_FRONTEND: [
        "React", "Vue.js", "Angular", "Next.js", "Nuxt.js", "Svelte",
        "jQuery", "Vanilla JS", "Ember.js", "Backbone.js"
    ],
    ComponentType.MOBILE_APP: [
        "React Native", "Flutter", "Swift/iOS", "Kotlin/Android",
        "Xamarin", "Ionic", "Cordova"
    ],
    ComponentType.API_GATEWAY: [
        "Kong", "AWS API Gateway", "Azure API Management", "Apigee",
        "Nginx", "Traefik", "Envoy", "Ambassador"
    ],
    ComponentType.REST_API: [
        "Node.js/Express", "Python/FastAPI", "Python/Django", "Python/Flask",
        "Java/Spring Boot", "Go/Gin", "Go/Echo", "Ruby/Rails",
        ".NET Core", "PHP/Laravel", "Rust/Actix"
    ],
    ComponentType.GRAPHQL_API: [
        "Apollo Server", "Hasura", "AWS AppSync", "graphql-yoga",
        "Ariadne (Python)", "Strawberry (Python)", "gqlgen (Go)"
    ],
    ComponentType.DATABASE_SQL: [
        "PostgreSQL", "MySQL", "MariaDB", "SQL Server", "Oracle",
        "SQLite", "CockroachDB", "TiDB", "Aurora"
    ],
    ComponentType.DATABASE_NOSQL: [
        "MongoDB", "Redis", "DynamoDB", "Cassandra", "CouchDB",
        "Elasticsearch", "Neo4j", "Firebase Firestore", "InfluxDB"
    ],
    ComponentType.CACHE: [
        "Redis", "Memcached", "Varnish", "Hazelcast", "Ehcache"
    ],
    ComponentType.MESSAGE_QUEUE: [
        "RabbitMQ", "Kafka", "AWS SQS", "Azure Service Bus",
        "Google Pub/Sub", "NATS", "ActiveMQ", "ZeroMQ"
    ],
    ComponentType.FILE_STORAGE: [
        "AWS S3", "Azure Blob Storage", "Google Cloud Storage",
        "MinIO", "Local Filesystem", "NFS"
    ],
    ComponentType.AUTH_SERVICE: [
        "Auth0", "Okta", "AWS Cognito", "Firebase Auth", "Keycloak",
        "Azure AD", "Custom JWT", "LDAP", "SAML"
    ],
    ComponentType.IDENTITY_PROVIDER: [
        "Okta", "Auth0", "Azure AD", "Google Workspace", "AWS IAM",
        "Ping Identity", "OneLogin"
    ],
    ComponentType.PAYMENT_GATEWAY: [
        "Stripe", "PayPal", "Braintree", "Square", "Adyen",
        "Authorize.net", "Razorpay"
    ],
    ComponentType.CONTAINER_ORCHESTRATOR: [
        "Kubernetes", "Docker Swarm", "AWS ECS", "Azure AKS",
        "Google GKE", "Nomad", "OpenShift"
    ],
    ComponentType.SERVERLESS_FUNCTION: [
        "AWS Lambda", "Azure Functions", "Google Cloud Functions",
        "Cloudflare Workers", "Vercel Edge Functions"
    ],
}


@dataclass
class DataFlow:
    """Represents data flow between components"""
    source_id: str
    target_id: str
    protocol: str = "HTTPS"  # HTTP, HTTPS, gRPC, WebSocket, TCP, etc.
    data_types: List[str] = field(default_factory=list)  # What data flows
    is_encrypted: bool = True
    authentication: Optional[str] = None  # JWT, API Key, mTLS, etc.
    description: str = ""


@dataclass
class Component:
    """Represents a system component"""
    id: str
    name: str
    type: str  # ComponentType value
    technology: str
    trust_zone: str  # TrustZone value
    description: str = ""

    # Data handling
    data_handled: List[str] = field(default_factory=list)  # DataClassification values
    data_stored: List[str] = field(default_factory=list)
    data_processed: List[str] = field(default_factory=list)

    # Security controls
    security_controls: List[str] = field(default_factory=list)  # SecurityControl values

    # Network
    exposed_ports: List[int] = field(default_factory=list)
    internal_only: bool = False

    # Additional context
    third_party: bool = False
    cloud_provider: str = ""
    compliance_scope: List[str] = field(default_factory=list)  # PCI, HIPAA, SOC2, etc.


@dataclass
class TrustBoundary:
    """Represents a trust boundary in the architecture"""
    id: str
    name: str
    zone: str  # TrustZone value
    component_ids: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class StructuredArchitecture:
    """Complete structured architecture input"""
    project_name: str
    description: str
    components: List[Component] = field(default_factory=list)
    data_flows: List[DataFlow] = field(default_factory=list)
    trust_boundaries: List[TrustBoundary] = field(default_factory=list)

    # Global settings
    deployment_model: str = "cloud"  # cloud, on-premise, hybrid
    cloud_providers: List[str] = field(default_factory=list)
    compliance_requirements: List[str] = field(default_factory=list)

    # Metadata
    diagram_extracted: bool = False
    manual_input: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "project_name": self.project_name,
            "description": self.description,
            "components": [asdict(c) for c in self.components],
            "data_flows": [asdict(f) for f in self.data_flows],
            "trust_boundaries": [asdict(b) for b in self.trust_boundaries],
            "deployment_model": self.deployment_model,
            "cloud_providers": self.cloud_providers,
            "compliance_requirements": self.compliance_requirements,
            "diagram_extracted": self.diagram_extracted,
            "manual_input": self.manual_input,
        }

    def to_description(self) -> str:
        """Convert structured input to descriptive text for AI processing"""
        lines = [
            f"# {self.project_name}",
            "",
            self.description,
            "",
            f"## Deployment: {self.deployment_model}",
        ]

        if self.cloud_providers:
            lines.append(f"Cloud Providers: {', '.join(self.cloud_providers)}")

        if self.compliance_requirements:
            lines.append(f"Compliance: {', '.join(self.compliance_requirements)}")

        # Components
        lines.extend(["", "## Components", ""])

        # Group by trust zone
        zones = {}
        for comp in self.components:
            zone = comp.trust_zone
            if zone not in zones:
                zones[zone] = []
            zones[zone].append(comp)

        for zone, comps in zones.items():
            lines.append(f"### Trust Zone: {zone.upper()}")
            for comp in comps:
                lines.append(f"\n**{comp.name}** ({comp.type})")
                lines.append(f"- Technology: {comp.technology}")
                if comp.description:
                    lines.append(f"- Description: {comp.description}")
                if comp.data_handled:
                    lines.append(f"- Data Handled: {', '.join(comp.data_handled)}")
                if comp.data_stored:
                    lines.append(f"- Data Stored: {', '.join(comp.data_stored)}")
                if comp.security_controls:
                    controls = [c.replace('_', ' ').title() for c in comp.security_controls]
                    lines.append(f"- Security Controls: {', '.join(controls)}")
                if comp.exposed_ports:
                    lines.append(f"- Exposed Ports: {comp.exposed_ports}")
                if comp.third_party:
                    lines.append(f"- Third Party: Yes")
            lines.append("")

        # Data Flows
        if self.data_flows:
            lines.extend(["## Data Flows", ""])

            # Create component name lookup
            comp_names = {c.id: c.name for c in self.components}

            for flow in self.data_flows:
                src = comp_names.get(flow.source_id, flow.source_id)
                tgt = comp_names.get(flow.target_id, flow.target_id)
                lines.append(f"- {src} -> {tgt}")
                lines.append(f"  - Protocol: {flow.protocol}")
                if flow.data_types:
                    lines.append(f"  - Data: {', '.join(flow.data_types)}")
                lines.append(f"  - Encrypted: {'Yes' if flow.is_encrypted else 'No'}")
                if flow.authentication:
                    lines.append(f"  - Auth: {flow.authentication}")

        # Trust Boundaries
        if self.trust_boundaries:
            lines.extend(["", "## Trust Boundaries", ""])
            for boundary in self.trust_boundaries:
                lines.append(f"### {boundary.name} ({boundary.zone})")
                if boundary.description:
                    lines.append(boundary.description)
                comps = [comp_names.get(cid, cid) for cid in boundary.component_ids]
                lines.append(f"Components: {', '.join(comps)}")

        return "\n".join(lines)


class ArchitectureInputService:
    """Service for processing architecture inputs"""

    def __init__(self, ai_client=None):
        self.ai_client = ai_client
        logger.info("ArchitectureInputService initialized")

    def get_component_library(self) -> Dict[str, Any]:
        """Get the component library for the frontend"""
        return {
            "component_types": [
                {"value": t.value, "label": t.value.replace("_", " ").title()}
                for t in ComponentType
            ],
            "trust_zones": [
                {"value": z.value, "label": z.value.replace("_", " ").title(),
                 "description": self._get_zone_description(z)}
                for z in TrustZone
            ],
            "data_classifications": [
                {"value": d.value, "label": d.value.upper(),
                 "description": self._get_data_description(d)}
                for d in DataClassification
            ],
            "security_controls": self._get_controls_by_category(),
            "technology_options": {
                t.value: opts for t, opts in TECHNOLOGY_OPTIONS.items()
            },
            "protocols": ["HTTPS", "HTTP", "gRPC", "WebSocket", "TCP", "UDP", "AMQP", "MQTT"],
            "auth_methods": ["JWT", "API Key", "OAuth2", "mTLS", "Basic Auth", "Session", "None"],
            "compliance_frameworks": ["PCI-DSS", "HIPAA", "SOC2", "GDPR", "ISO27001", "NIST", "FedRAMP"],
            "cloud_providers": ["AWS", "Azure", "GCP", "On-Premise", "Hybrid"],
        }

    def _get_zone_description(self, zone: TrustZone) -> str:
        descriptions = {
            TrustZone.INTERNET: "Public internet, completely untrusted",
            TrustZone.DMZ: "Semi-trusted zone between internet and internal",
            TrustZone.INTERNAL: "Internal corporate network",
            TrustZone.RESTRICTED: "Highly restricted, sensitive systems only",
            TrustZone.MANAGEMENT: "Administrative and management plane",
        }
        return descriptions.get(zone, "")

    def _get_data_description(self, data: DataClassification) -> str:
        descriptions = {
            DataClassification.PUBLIC: "Can be publicly disclosed",
            DataClassification.INTERNAL: "Internal use only",
            DataClassification.CONFIDENTIAL: "Confidential business data",
            DataClassification.RESTRICTED: "Highly sensitive, restricted access",
            DataClassification.PII: "Personally Identifiable Information (GDPR/CCPA)",
            DataClassification.PHI: "Protected Health Information (HIPAA)",
            DataClassification.PCI: "Payment Card Data (PCI-DSS)",
            DataClassification.CREDENTIALS: "Passwords, tokens, API keys, secrets",
            DataClassification.FINANCIAL: "Financial records and transactions",
        }
        return descriptions.get(data, "")

    def _get_controls_by_category(self) -> Dict[str, List[Dict]]:
        """Organize security controls by category"""
        categories = {
            "Authentication & Authorization": [
                SecurityControl.AUTH_REQUIRED, SecurityControl.MFA_ENABLED,
                SecurityControl.RBAC, SecurityControl.OAUTH2, SecurityControl.JWT_TOKENS,
                SecurityControl.API_KEYS, SecurityControl.CERTIFICATE_AUTH,
            ],
            "Input Validation": [
                SecurityControl.INPUT_VALIDATION, SecurityControl.OUTPUT_ENCODING,
                SecurityControl.PARAMETERIZED_QUERIES, SecurityControl.CONTENT_TYPE_VALIDATION,
                SecurityControl.FILE_TYPE_VALIDATION,
            ],
            "Encryption": [
                SecurityControl.TLS_ENCRYPTION, SecurityControl.DATA_AT_REST_ENCRYPTION,
                SecurityControl.E2E_ENCRYPTION, SecurityControl.FIELD_LEVEL_ENCRYPTION,
            ],
            "Network Security": [
                SecurityControl.FIREWALL, SecurityControl.WAF_ENABLED,
                SecurityControl.RATE_LIMITING, SecurityControl.DDOS_PROTECTION,
                SecurityControl.IP_ALLOWLIST, SecurityControl.VPN_REQUIRED,
                SecurityControl.NETWORK_SEGMENTATION,
            ],
            "Logging & Monitoring": [
                SecurityControl.AUDIT_LOGGING, SecurityControl.SECURITY_MONITORING,
                SecurityControl.INTRUSION_DETECTION, SecurityControl.ANOMALY_DETECTION,
            ],
            "Session & Access": [
                SecurityControl.SESSION_MANAGEMENT, SecurityControl.SESSION_TIMEOUT,
                SecurityControl.CSRF_PROTECTION, SecurityControl.CORS_CONFIGURED,
            ],
            "Data Protection": [
                SecurityControl.DATA_MASKING, SecurityControl.DATA_ANONYMIZATION,
                SecurityControl.BACKUP_ENCRYPTION, SecurityControl.SECURE_DELETE,
            ],
            "Secrets Management": [
                SecurityControl.SECRETS_ROTATION, SecurityControl.SECRETS_VAULT,
                SecurityControl.NO_HARDCODED_SECRETS,
            ],
            "Security Testing": [
                SecurityControl.SECURITY_HEADERS, SecurityControl.CONTENT_SECURITY_POLICY,
                SecurityControl.DEPENDENCY_SCANNING, SecurityControl.VULNERABILITY_SCANNING,
                SecurityControl.PENETRATION_TESTING,
            ],
        }

        result = {}
        for category, controls in categories.items():
            result[category] = [
                {
                    "value": c.value,
                    "label": c.value.replace("_", " ").title()
                }
                for c in controls
            ]
        return result

    def parse_structured_input(self, data: Dict[str, Any]) -> StructuredArchitecture:
        """Parse structured input from frontend"""
        components = [
            Component(
                id=c.get("id", f"comp_{i}"),
                name=c.get("name", "Unknown"),
                type=c.get("type", "other"),
                technology=c.get("technology", ""),
                trust_zone=c.get("trust_zone", "internal"),
                description=c.get("description", ""),
                data_handled=c.get("data_handled", []),
                data_stored=c.get("data_stored", []),
                data_processed=c.get("data_processed", []),
                security_controls=c.get("security_controls", []),
                exposed_ports=c.get("exposed_ports", []),
                internal_only=c.get("internal_only", False),
                third_party=c.get("third_party", False),
                cloud_provider=c.get("cloud_provider", ""),
                compliance_scope=c.get("compliance_scope", []),
            )
            for i, c in enumerate(data.get("components", []))
        ]

        data_flows = [
            DataFlow(
                source_id=f.get("source_id", ""),
                target_id=f.get("target_id", ""),
                protocol=f.get("protocol", "HTTPS"),
                data_types=f.get("data_types", []),
                is_encrypted=f.get("is_encrypted", True),
                authentication=f.get("authentication"),
                description=f.get("description", ""),
            )
            for f in data.get("data_flows", [])
        ]

        trust_boundaries = [
            TrustBoundary(
                id=b.get("id", f"boundary_{i}"),
                name=b.get("name", ""),
                zone=b.get("zone", "internal"),
                component_ids=b.get("component_ids", []),
                description=b.get("description", ""),
            )
            for i, b in enumerate(data.get("trust_boundaries", []))
        ]

        return StructuredArchitecture(
            project_name=data.get("project_name", ""),
            description=data.get("description", ""),
            components=components,
            data_flows=data_flows,
            trust_boundaries=trust_boundaries,
            deployment_model=data.get("deployment_model", "cloud"),
            cloud_providers=data.get("cloud_providers", []),
            compliance_requirements=data.get("compliance_requirements", []),
            manual_input=True,
        )

    async def extract_from_diagram(
        self,
        image_data: bytes,
        media_type: str
    ) -> StructuredArchitecture:
        """Extract architecture from diagram using AI vision"""

        if not self.ai_client:
            raise ValueError("AI client not configured for vision extraction")

        # Encode image to base64
        image_base64 = base64.b64encode(image_data).decode('utf-8')

        extraction_prompt = """Analyze this architecture diagram and extract all components, data flows, and security elements.

Return a JSON object with this exact structure:
{
    "project_name": "extracted name or 'Architecture'",
    "description": "brief description of the system",
    "components": [
        {
            "id": "unique_id",
            "name": "Component Name",
            "type": "one of: web_frontend, mobile_app, api_gateway, rest_api, graphql_api, grpc_service, microservice, auth_service, database_sql, database_nosql, cache, message_queue, file_storage, cdn, load_balancer, waf, external_api, payment_gateway, identity_provider, serverless_function, other",
            "technology": "detected technology (e.g., React, Node.js, PostgreSQL)",
            "trust_zone": "one of: internet, dmz, internal, restricted",
            "description": "what this component does",
            "data_handled": ["pii", "pci", "credentials", etc if visible],
            "third_party": true/false,
            "exposed_ports": [detected ports if any]
        }
    ],
    "data_flows": [
        {
            "source_id": "component_id",
            "target_id": "component_id",
            "protocol": "HTTPS, HTTP, gRPC, etc",
            "data_types": ["user data", "api requests", etc],
            "is_encrypted": true/false based on arrows/labels,
            "authentication": "JWT, API Key, etc if labeled"
        }
    ],
    "trust_boundaries": [
        {
            "id": "boundary_id",
            "name": "Boundary Name",
            "zone": "internal, dmz, etc",
            "component_ids": ["list of component ids in this zone"]
        }
    ],
    "detected_security_controls": ["any visible security controls like WAF, firewall, etc"]
}

Be thorough - extract EVERY component and connection visible in the diagram.
If you cannot determine a value, use reasonable defaults.
Return ONLY the JSON, no other text."""

        try:
            response = await self.ai_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4000,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": media_type,
                                    "data": image_base64,
                                },
                            },
                            {
                                "type": "text",
                                "text": extraction_prompt
                            }
                        ],
                    }
                ],
            )

            response_text = response.content[0].text

            # Extract JSON from response
            if "```json" in response_text:
                json_str = response_text.split("```json")[1].split("```")[0]
            elif "```" in response_text:
                json_str = response_text.split("```")[1].split("```")[0]
            else:
                json_str = response_text

            extracted = json.loads(json_str.strip())

            # Parse into structured architecture
            architecture = self.parse_structured_input(extracted)
            architecture.diagram_extracted = True
            architecture.manual_input = False

            logger.info(f"Extracted {len(architecture.components)} components from diagram")

            return architecture

        except Exception as e:
            logger.error(f"Failed to extract from diagram: {e}")
            raise

    def merge_architectures(
        self,
        manual: Optional[StructuredArchitecture],
        extracted: Optional[StructuredArchitecture]
    ) -> StructuredArchitecture:
        """Merge manual input and diagram extraction"""

        if not manual and not extracted:
            raise ValueError("At least one input source required")

        if not manual:
            return extracted

        if not extracted:
            return manual

        # Start with manual input as base (user input takes priority)
        merged = StructuredArchitecture(
            project_name=manual.project_name or extracted.project_name,
            description=manual.description or extracted.description,
            deployment_model=manual.deployment_model,
            cloud_providers=manual.cloud_providers or extracted.cloud_providers,
            compliance_requirements=manual.compliance_requirements or extracted.compliance_requirements,
            diagram_extracted=True,
            manual_input=True,
        )

        # Merge components
        manual_ids = {c.id for c in manual.components}
        merged.components = list(manual.components)

        # Add extracted components that aren't in manual
        for comp in extracted.components:
            if comp.id not in manual_ids:
                # Check if there's a component with similar name
                similar = next(
                    (m for m in manual.components
                     if m.name.lower() == comp.name.lower()),
                    None
                )
                if not similar:
                    merged.components.append(comp)

        # Merge data flows
        existing_flows = {(f.source_id, f.target_id) for f in manual.data_flows}
        merged.data_flows = list(manual.data_flows)

        for flow in extracted.data_flows:
            if (flow.source_id, flow.target_id) not in existing_flows:
                merged.data_flows.append(flow)

        # Merge trust boundaries
        merged.trust_boundaries = list(manual.trust_boundaries)
        existing_boundaries = {b.name.lower() for b in manual.trust_boundaries}

        for boundary in extracted.trust_boundaries:
            if boundary.name.lower() not in existing_boundaries:
                merged.trust_boundaries.append(boundary)

        logger.info(
            f"Merged architecture: {len(merged.components)} components, "
            f"{len(merged.data_flows)} data flows"
        )

        return merged

    def validate_architecture(self, arch: StructuredArchitecture) -> List[Dict[str, str]]:
        """Validate architecture for completeness and return warnings"""
        warnings = []

        # Check for components without security controls
        for comp in arch.components:
            if not comp.security_controls:
                warnings.append({
                    "type": "missing_controls",
                    "component": comp.name,
                    "message": f"Component '{comp.name}' has no security controls defined"
                })

            # Check for sensitive data without encryption
            if any(d in ["pii", "phi", "pci", "credentials", "financial"]
                   for d in comp.data_stored):
                if "data_at_rest_encryption" not in comp.security_controls:
                    warnings.append({
                        "type": "sensitive_data",
                        "component": comp.name,
                        "message": f"'{comp.name}' stores sensitive data but encryption at rest is not enabled"
                    })

            # Check for internet-facing without auth
            if comp.trust_zone == "internet" or comp.trust_zone == "dmz":
                if "auth_required" not in comp.security_controls:
                    warnings.append({
                        "type": "missing_auth",
                        "component": comp.name,
                        "message": f"'{comp.name}' is internet-facing but has no authentication"
                    })

        # Check for unencrypted data flows
        for flow in arch.data_flows:
            if not flow.is_encrypted and flow.protocol != "internal":
                src = next((c.name for c in arch.components if c.id == flow.source_id), flow.source_id)
                tgt = next((c.name for c in arch.components if c.id == flow.target_id), flow.target_id)
                warnings.append({
                    "type": "unencrypted_flow",
                    "flow": f"{src} -> {tgt}",
                    "message": f"Data flow from '{src}' to '{tgt}' is not encrypted"
                })

        # Check for orphan components (no data flows)
        component_ids = {c.id for c in arch.components}
        connected_ids = set()
        for flow in arch.data_flows:
            connected_ids.add(flow.source_id)
            connected_ids.add(flow.target_id)

        orphans = component_ids - connected_ids
        for orphan_id in orphans:
            comp = next((c for c in arch.components if c.id == orphan_id), None)
            if comp:
                warnings.append({
                    "type": "orphan_component",
                    "component": comp.name,
                    "message": f"'{comp.name}' has no data flows defined"
                })

        return warnings
