"""
Threat Modeling Service - DFD Generation, STRIDE Analysis, MITRE ATT&CK Mapping
"""
from typing import Dict, List, Any, Optional
import re
import json
import base64
import os
from anthropic import Anthropic

class ThreatModelingService:
    """Service for threat modeling with DFD, STRIDE, and MITRE ATT&CK"""

    def __init__(self):
        """Initialize the threat modeling service"""
        self.anthropic_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    # STRIDE threat categories
    STRIDE_CATEGORIES = {
        "Spoofing": "Authentication compromise",
        "Tampering": "Data integrity violations",
        "Repudiation": "Audit and logging failures",
        "Information Disclosure": "Confidentiality breaches",
        "Denial of Service": "Availability attacks",
        "Elevation of Privilege": "Authorization bypass"
    }

    # MITRE ATT&CK techniques commonly found in web applications
    MITRE_TECHNIQUES = {
        "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
        "T1055": {"name": "Process Injection", "tactic": "Execution"},
        "T1078": {"name": "Valid Accounts", "tactic": "Persistence"},
        "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
        "T1212": {"name": "Exploitation for Credential Access", "tactic": "Credential Access"},
        "T1557": {"name": "Man-in-the-Middle", "tactic": "Credential Access"},
        "T1498": {"name": "Network Denial of Service", "tactic": "Impact"},
        "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact"},
        "T1565": {"name": "Data Manipulation", "tactic": "Impact"},
    }

    def analyze_architecture_diagram(self, image_data: str, image_media_type: str = "image/png") -> str:
        """
        Analyze an architecture diagram image using Claude's vision capabilities

        Args:
            image_data: Base64 encoded image data
            image_media_type: MIME type of the image (image/png, image/jpeg, etc.)

        Returns:
            Text description of the architecture extracted from the image
        """
        prompt = """Analyze this architecture diagram and provide a detailed text description of the system architecture.

Please identify and describe:
1. All external entities (users, third-party services, clients, etc.)
2. All internal processes/components (servers, services, APIs, applications, backend, frontend, etc.)
3. All data stores (databases, caches, storage systems, etc.)
4. Data flows between components (what data moves where)
5. Technologies mentioned or implied
6. Trust boundaries and security zones

Format your response as a structured text description that includes:
- List of components with their types and purposes
- Data flows between components
- Security-relevant details

Be specific about component names, technologies, and relationships."""

        try:
            response = self.anthropic_client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2000,
                messages=[{
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": image_media_type,
                                "data": image_data
                            }
                        },
                        {
                            "type": "text",
                            "text": prompt
                        }
                    ]
                }]
            )

            # Extract text from response
            architecture_text = response.content[0].text
            return architecture_text

        except Exception as e:
            print(f"Error analyzing architecture diagram: {e}")
            raise Exception(f"Failed to analyze architecture diagram: {str(e)}")

    def parse_architecture(self, architecture_doc: str) -> Dict[str, Any]:
        """Parse architecture document and extract components"""
        components = []
        data_stores = []
        external_entities = []
        data_flows = []

        # Simple keyword-based parsing
        lines = architecture_doc.lower().split('\n')

        for i, line in enumerate(lines):
            # Detect components/processes
            if any(keyword in line for keyword in ['server', 'service', 'api', 'application', 'backend', 'frontend']):
                if 'database' not in line and 'store' not in line:
                    component_name = self._extract_component_name(line)
                    if component_name:
                        components.append({
                            "id": f"process_{len(components)}",
                            "name": component_name,
                            "type": "process",
                            "line": i
                        })

            # Detect data stores
            if any(keyword in line for keyword in ['database', 'db', 'cache', 'storage', 'redis', 'mongodb', 'postgresql']):
                store_name = self._extract_component_name(line)
                if store_name:
                    data_stores.append({
                        "id": f"datastore_{len(data_stores)}",
                        "name": store_name,
                        "type": "datastore",
                        "line": i
                    })

            # Detect external entities
            if any(keyword in line for keyword in ['user', 'client', 'browser', 'mobile app', 'third-party', 'external']):
                entity_name = self._extract_component_name(line)
                if entity_name:
                    external_entities.append({
                        "id": f"external_{len(external_entities)}",
                        "name": entity_name,
                        "type": "external",
                        "line": i
                    })

        return {
            "components": components,
            "data_stores": data_stores,
            "external_entities": external_entities,
            "data_flows": self._infer_data_flows(components, data_stores, external_entities)
        }

    def _extract_component_name(self, line: str) -> str:
        """Extract component name from line"""
        # Remove common words and clean up
        line = line.strip('- *#:')
        words = line.split()
        if len(words) > 0:
            # Take first few meaningful words
            name_parts = []
            for word in words[:4]:
                if word not in ['the', 'a', 'an', 'is', 'are', 'with', 'using']:
                    name_parts.append(word.capitalize())
            return ' '.join(name_parts) if name_parts else None
        return None

    def _infer_data_flows(self, components: List[Dict], data_stores: List[Dict], external_entities: List[Dict]) -> List[Dict]:
        """Infer data flows between components"""
        flows = []

        # External entities to components (typical user flows)
        for external in external_entities:
            for component in components:
                if 'frontend' in component['name'].lower() or 'web' in component['name'].lower():
                    flows.append({
                        "id": f"flow_{len(flows)}",
                        "from": external['id'],
                        "to": component['id'],
                        "data": "User requests, authentication data",
                        "protocol": "HTTPS"
                    })

        # Components to data stores
        for component in components:
            for store in data_stores:
                flows.append({
                    "id": f"flow_{len(flows)}",
                    "from": component['id'],
                    "to": store['id'],
                    "data": "Query/response data",
                    "protocol": "Database protocol"
                })

        # Inter-component flows
        if len(components) > 1:
            for i in range(len(components) - 1):
                flows.append({
                    "id": f"flow_{len(flows)}",
                    "from": components[i]['id'],
                    "to": components[i + 1]['id'],
                    "data": "API requests/responses",
                    "protocol": "HTTP/REST"
                })

        return flows

    def generate_dfd(self, parsed_arch: Dict[str, Any], level: int = 0) -> Dict[str, Any]:
        """Generate Data Flow Diagram"""
        nodes = []
        edges = []

        # Add all nodes
        all_elements = (
            parsed_arch['external_entities'] +
            parsed_arch['components'] +
            parsed_arch['data_stores']
        )

        for element in all_elements:
            nodes.append({
                "id": element['id'],
                "label": element['name'],
                "type": element['type'],
                "x": self._calculate_x_position(element['type'], len(nodes)),
                "y": self._calculate_y_position(element['type'])
            })

        # Add edges (data flows)
        for flow in parsed_arch['data_flows']:
            edges.append({
                "id": flow['id'],
                "source": flow['from'],
                "target": flow['to'],
                "label": flow['data']
            })

        return {
            "level": level,
            "nodes": nodes,
            "edges": edges,
            "trust_boundaries": self._identify_trust_boundaries(nodes, edges)
        }

    def _calculate_x_position(self, node_type: str, index: int) -> int:
        """Calculate X position for node in diagram"""
        if node_type == "external":
            return 100
        elif node_type == "process":
            return 300 + (index * 150)
        else:  # datastore
            return 600

    def _calculate_y_position(self, node_type: str) -> int:
        """Calculate Y position for node in diagram"""
        if node_type == "external":
            return 200
        elif node_type == "process":
            return 200
        else:  # datastore
            return 350

    def _identify_trust_boundaries(self, nodes: List[Dict], edges: List[Dict]) -> List[Dict]:
        """Identify trust boundaries in the system"""
        boundaries = []

        # Trust boundary between external entities and internal components
        external_ids = [n['id'] for n in nodes if n['type'] == 'external']
        internal_ids = [n['id'] for n in nodes if n['type'] != 'external']

        if external_ids and internal_ids:
            boundaries.append({
                "id": "tb_1",
                "name": "Internet/DMZ Boundary",
                "description": "Separates untrusted external users from internal systems",
                "crosses": [e for e in edges if e['source'] in external_ids and e['target'] in internal_ids]
            })

        # Trust boundary between application and data layer
        process_ids = [n['id'] for n in nodes if n['type'] == 'process']
        datastore_ids = [n['id'] for n in nodes if n['type'] == 'datastore']

        if process_ids and datastore_ids:
            boundaries.append({
                "id": "tb_2",
                "name": "Application/Data Boundary",
                "description": "Separates application logic from persistent data storage",
                "crosses": [e for e in edges if e['source'] in process_ids and e['target'] in datastore_ids]
            })

        return boundaries

    def apply_stride(self, dfd_data: Dict[str, Any]) -> Dict[str, List[Dict]]:
        """Apply STRIDE threat analysis to DFD components"""
        stride_threats = {
            "Spoofing": [],
            "Tampering": [],
            "Repudiation": [],
            "Information Disclosure": [],
            "Denial of Service": [],
            "Elevation of Privilege": []
        }

        for node in dfd_data['nodes']:
            node_threats = self._generate_stride_threats_for_node(node, dfd_data)
            for category, threats in node_threats.items():
                stride_threats[category].extend(threats)

        for edge in dfd_data['edges']:
            edge_threats = self._generate_stride_threats_for_edge(edge, dfd_data)
            for category, threats in edge_threats.items():
                stride_threats[category].extend(threats)

        return stride_threats

    def _generate_stride_threats_for_node(self, node: Dict, dfd_data: Dict) -> Dict[str, List[Dict]]:
        """Generate STRIDE threats for a specific node"""
        threats = {cat: [] for cat in self.STRIDE_CATEGORIES.keys()}

        if node['type'] == 'external':
            threats['Spoofing'].append({
                "component": node['label'],
                "threat": "External entity could be impersonated",
                "description": "Attacker could pose as legitimate external user/system",
                "mitigation": "Implement strong authentication (MFA, certificates)"
            })

        elif node['type'] == 'process':
            threats['Spoofing'].append({
                "component": node['label'],
                "threat": "Process authentication bypass",
                "description": "Weak authentication could allow unauthorized access",
                "mitigation": "Use OAuth 2.0, JWT tokens with proper validation"
            })
            threats['Tampering'].append({
                "component": node['label'],
                "threat": "Process logic manipulation",
                "description": "Business logic could be bypassed or manipulated",
                "mitigation": "Implement input validation, integrity checks"
            })
            threats['Repudiation'].append({
                "component": node['label'],
                "threat": "Insufficient logging",
                "description": "Lack of audit trail for security events",
                "mitigation": "Implement comprehensive logging and monitoring"
            })
            threats['Denial of Service'].append({
                "component": node['label'],
                "threat": "Resource exhaustion",
                "description": "Process could be overwhelmed with requests",
                "mitigation": "Implement rate limiting, resource quotas"
            })
            threats['Elevation of Privilege'].append({
                "component": node['label'],
                "threat": "Authorization bypass",
                "description": "Users could access unauthorized functions",
                "mitigation": "Implement RBAC, principle of least privilege"
            })

        elif node['type'] == 'datastore':
            threats['Tampering'].append({
                "component": node['label'],
                "threat": "Data integrity violation",
                "description": "Unauthorized modification of stored data",
                "mitigation": "Use database access controls, encryption at rest"
            })
            threats['Information Disclosure'].append({
                "component": node['label'],
                "threat": "Unauthorized data access",
                "description": "Sensitive data could be exposed",
                "mitigation": "Encrypt sensitive data, implement column-level security"
            })
            threats['Denial of Service'].append({
                "component": node['label'],
                "threat": "Database resource exhaustion",
                "description": "Expensive queries could degrade performance",
                "mitigation": "Query optimization, connection pooling, timeouts"
            })

        return threats

    def _generate_stride_threats_for_edge(self, edge: Dict, dfd_data: Dict) -> Dict[str, List[Dict]]:
        """Generate STRIDE threats for data flows (edges)"""
        threats = {cat: [] for cat in self.STRIDE_CATEGORIES.keys()}

        threats['Tampering'].append({
            "component": edge['label'],
            "threat": "Data in transit tampering",
            "description": f"Data flow '{edge['label']}' could be intercepted and modified",
            "mitigation": "Use TLS/HTTPS, message integrity checks (HMAC)"
        })

        threats['Information Disclosure'].append({
            "component": edge['label'],
            "threat": "Data interception",
            "description": f"Sensitive data in '{edge['label']}' could be eavesdropped",
            "mitigation": "Encrypt all data in transit with TLS 1.3+"
        })

        threats['Denial of Service'].append({
            "component": edge['label'],
            "threat": "Communication channel flooding",
            "description": "Data flow could be overwhelmed with traffic",
            "mitigation": "Implement DDoS protection, rate limiting"
        })

        return threats

    def map_mitre_attack(self, stride_threats: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Map STRIDE threats to MITRE ATT&CK techniques"""
        mitre_mapping = {}

        # Map common STRIDE categories to MITRE techniques
        stride_to_mitre = {
            "Spoofing": ["T1078", "T1110"],
            "Tampering": ["T1565", "T1190"],
            "Repudiation": ["T1070"],
            "Information Disclosure": ["T1557", "T1212"],
            "Denial of Service": ["T1498", "T1499"],
            "Elevation of Privilege": ["T1068", "T1055"]
        }

        for stride_cat, threats in stride_threats.items():
            if threats:
                mitre_techniques = stride_to_mitre.get(stride_cat, [])
                for technique_id in mitre_techniques:
                    if technique_id in self.MITRE_TECHNIQUES:
                        tech_info = self.MITRE_TECHNIQUES[technique_id]
                        mitre_mapping[technique_id] = {
                            "name": tech_info['name'],
                            "tactic": tech_info['tactic'],
                            "related_stride": stride_cat,
                            "threat_count": len(threats),
                            "description": f"Adversary may use {tech_info['name']} to exploit {stride_cat} vulnerabilities"
                        }

        return mitre_mapping

    def generate_mermaid_dfd(self, dfd_data: Dict[str, Any], level: int = 0) -> str:
        """Generate professional Mermaid DFD diagram

        Level 0: Context diagram - shows system as single process with external entities
        Level 1: Detailed diagram - shows all internal processes, data stores, and flows
        """
        mermaid = ["graph TD"]

        # Enhanced styling with trust boundary colors
        mermaid.append("    classDef external fill:#dbeafe,stroke:#3b82f6,stroke-width:3px")
        mermaid.append("    classDef process fill:#fef3c7,stroke:#f59e0b,stroke-width:3px")
        mermaid.append("    classDef datastore fill:#d1fae5,stroke:#10b981,stroke-width:3px")
        mermaid.append("    classDef system fill:#f3e8ff,stroke:#9333ea,stroke-width:4px")
        mermaid.append("    classDef trustBoundary fill:none,stroke:#dc2626,stroke-width:3px,stroke-dasharray:10 5")
        mermaid.append("")

        if level == 0:
            # LEVEL 0: Context Diagram
            # Show only external entities and the system as a single process

            external_nodes = [n for n in dfd_data['nodes'] if n['type'] == 'external']

            # Create a single "System" node
            mermaid.append("    System[Application Security Platform]")
            mermaid.append("    class System system")
            mermaid.append("")

            # Add external entities
            for node in external_nodes:
                node_id = node['id'].replace('-', '_').replace(' ', '_')
                label = node['label']
                mermaid.append(f"    {node_id}[{label}]")
                mermaid.append(f"    class {node_id} external")

            mermaid.append("")

            # Add simplified data flows (external entities <-> System)
            external_ids = {n['id'].replace('-', '_').replace(' ', '_') for n in external_nodes}

            # Group flows to/from external entities
            flows_added = set()
            for edge in dfd_data['edges']:
                source_id = edge['source'].replace('-', '_').replace(' ', '_')
                target_id = edge['target'].replace('-', '_').replace(' ', '_')

                # Only show flows involving external entities
                if source_id in external_ids:
                    flow_key = f"{source_id}_to_System"
                    if flow_key not in flows_added:
                        mermaid.append(f"    {source_id} -->|User Data & Requests| System")
                        flows_added.add(flow_key)
                elif target_id in external_ids:
                    flow_key = f"System_to_{target_id}"
                    if flow_key not in flows_added:
                        mermaid.append(f"    System -->|Processed Data & Responses| {target_id}")
                        flows_added.add(flow_key)

            # Add trust boundary around the system with dotted lines
            mermaid.append("")
            mermaid.append("    %% Trust Boundary - Dotted Line")
            mermaid.append("    subgraph TB0[\" 🔒 Trusted System Boundary \"]")
            mermaid.append("        System")
            mermaid.append("    end")
            mermaid.append("    class TB0 trustBoundary")

        else:
            # LEVEL 1: Detailed Diagram
            # Show all processes, data stores, and detailed data flows

            # Add trust boundaries first as subgraphs
            trust_boundary_nodes = {}
            if dfd_data.get('trust_boundaries'):
                for i, boundary in enumerate(dfd_data['trust_boundaries']):
                    boundary_id = f"TB{i}"
                    trust_boundary_nodes[boundary_id] = set()
                    for node_id in boundary.get('nodes', []):
                        clean_id = node_id.replace('-', '_').replace(' ', '_')
                        trust_boundary_nodes[boundary_id].add(clean_id)

            # Organize nodes by trust boundary
            nodes_in_boundaries = set()
            for boundary_nodes in trust_boundary_nodes.values():
                nodes_in_boundaries.update(boundary_nodes)

            # Add trust boundaries with nodes - using dotted lines
            if trust_boundary_nodes:
                mermaid.append("    %% Trust Boundaries - Dotted Lines")
                for boundary_id, node_ids in trust_boundary_nodes.items():
                    boundary_data = dfd_data['trust_boundaries'][int(boundary_id[2:])]
                    boundary_name = boundary_data.get('name', f'Trust Boundary {boundary_id}')

                    mermaid.append(f"    subgraph {boundary_id}[\" 🔒 {boundary_name} \"]")
                    mermaid.append("        direction TB")

                    # Add nodes within this boundary
                    for node in dfd_data['nodes']:
                        node_id = node['id'].replace('-', '_').replace(' ', '_')
                        if node_id in node_ids:
                            label = node['label']

                            if node['type'] == 'external':
                                mermaid.append(f"        {node_id}[{label}]")
                                mermaid.append(f"        class {node_id} external")
                            elif node['type'] == 'process':
                                mermaid.append(f"        {node_id}({label})")
                                mermaid.append(f"        class {node_id} process")
                            elif node['type'] == 'datastore':
                                mermaid.append(f"        {node_id}[({label})]")
                                mermaid.append(f"        class {node_id} datastore")

                    mermaid.append("    end")
                    mermaid.append(f"    class {boundary_id} trustBoundary")

                mermaid.append("")

            # Add nodes NOT in any trust boundary
            mermaid.append("    %% Nodes outside trust boundaries")
            for node in dfd_data['nodes']:
                node_id = node['id'].replace('-', '_').replace(' ', '_')

                if node_id not in nodes_in_boundaries:
                    label = node['label']

                    if node['type'] == 'external':
                        mermaid.append(f"    {node_id}[{label}]")
                        mermaid.append(f"    class {node_id} external")
                    elif node['type'] == 'process':
                        mermaid.append(f"    {node_id}({label})")
                        mermaid.append(f"    class {node_id} process")
                    elif node['type'] == 'datastore':
                        mermaid.append(f"    {node_id}[({label})]")
                        mermaid.append(f"    class {node_id} datastore")

            mermaid.append("")

            # Add all detailed data flows
            mermaid.append("    %% Data Flows")
            for edge in dfd_data['edges']:
                source_id = edge['source'].replace('-', '_').replace(' ', '_')
                target_id = edge['target'].replace('-', '_').replace(' ', '_')
                label = edge['label'][:30] if len(edge['label']) > 30 else edge['label']

                mermaid.append(f"    {source_id} -->|{label}| {target_id}")

        return "\n".join(mermaid)

    def generate_threat_model(
        self,
        architecture_doc: str,
        project_name: str,
        architecture_diagram: Optional[str] = None,
        diagram_media_type: str = "image/png"
    ) -> Dict[str, Any]:
        """Complete threat modeling workflow

        Args:
            architecture_doc: Text description of the architecture
            project_name: Name of the project
            architecture_diagram: Optional base64 encoded architecture diagram image
            diagram_media_type: MIME type of the diagram image
        """
        # If architecture diagram is provided, analyze it first
        if architecture_diagram:
            try:
                diagram_description = self.analyze_architecture_diagram(
                    architecture_diagram,
                    diagram_media_type
                )
                # Combine diagram description with existing architecture doc
                architecture_doc = f"{architecture_doc}\n\n## Extracted from Architecture Diagram:\n{diagram_description}"
            except Exception as e:
                print(f"Warning: Could not analyze architecture diagram: {e}")
                # Continue with text-only analysis

        # Parse architecture
        parsed = self.parse_architecture(architecture_doc)

        # Generate DFD Level 0 (Context Diagram - high-level system view)
        dfd_level_0 = self.generate_dfd(parsed, level=0)
        dfd_level_0['mermaid'] = self.generate_mermaid_dfd(dfd_level_0, level=0)

        # Generate DFD Level 1 (Detailed Diagram - component-level view)
        dfd_level_1 = self.generate_dfd(parsed, level=1)
        dfd_level_1['mermaid'] = self.generate_mermaid_dfd(dfd_level_1, level=1)

        # Apply STRIDE
        stride_analysis = self.apply_stride(dfd_level_0)

        # Map to MITRE ATT&CK
        mitre_mapping = self.map_mitre_attack(stride_analysis)

        # Calculate total threat count
        total_threats = sum(len(threats) for threats in stride_analysis.values())

        return {
            "project_name": project_name,
            "dfd_level_0": dfd_level_0,
            "dfd_level_1": dfd_level_1,
            "dfd_data": dfd_level_0,  # Keep for backward compatibility
            "dfd_level": 0,  # Add level indicator
            "stride_analysis": stride_analysis,
            "mitre_mapping": mitre_mapping,
            "threat_count": total_threats,
            "summary": {
                "total_components": len(dfd_level_0['nodes']),
                "total_data_flows": len(dfd_level_0['edges']),
                "trust_boundaries": len(dfd_level_0['trust_boundaries']),
                "stride_threats": {cat: len(threats) for cat, threats in stride_analysis.items()},
                "mitre_techniques": len(mitre_mapping)
            }
        }
