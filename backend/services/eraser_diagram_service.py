"""
Eraser AI Diagram Generation Service

Integrates with Eraser's DiagramGPT API to generate professional diagrams
for threat models, attack trees, and architecture visualizations.

API Documentation: https://docs.eraser.io/reference/generate-diagram-from-prompt
"""

import os
import httpx
import asyncio
import logging
from typing import Dict, Any, Optional, List
from enum import Enum
from functools import lru_cache
import hashlib
import json

logger = logging.getLogger(__name__)


class DiagramType(Enum):
    """Supported Eraser diagram types"""
    SEQUENCE = "sequence-diagram"
    ENTITY_RELATIONSHIP = "entity-relationship-diagram"
    CLOUD_ARCHITECTURE = "cloud-architecture-diagram"
    FLOWCHART = "flowchart-diagram"
    BPMN = "bpmn-diagram"


class DiagramMode(Enum):
    """Generation modes - affects quality and cost"""
    STANDARD = "standard"  # GPT-4.1
    PREMIUM = "premium"    # o4-mini-high (better quality)


class ImageQuality(Enum):
    """Output image quality levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class EraserDiagramService:
    """
    Service for generating professional diagrams using Eraser AI's DiagramGPT API.

    Features:
    - Generates cloud architecture, flowchart, sequence, ER, and BPMN diagrams
    - Supports light/dark themes
    - Caches diagram prompts to avoid duplicate API calls
    - Graceful fallback to Mermaid when API unavailable
    """

    API_URL = "https://app.eraser.io/api/render/prompt"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the Eraser diagram service.

        Args:
            api_key: Eraser API key. Falls back to ERASER_API_KEY env var.
        """
        self.api_key = api_key or os.getenv("ERASER_API_KEY")
        self.enabled = bool(self.api_key)
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_max_size = 500

        if not self.enabled:
            logger.warning("Eraser API key not configured. Diagram generation will use Mermaid fallback.")
        else:
            logger.info("Eraser diagram service initialized successfully")

    def _get_cache_key(self, prompt: str, diagram_type: str, theme: str) -> str:
        """Generate cache key from prompt parameters"""
        content = f"{prompt}:{diagram_type}:{theme}"
        return hashlib.md5(content.encode()).hexdigest()

    async def generate_diagram(
        self,
        prompt: str,
        diagram_type: Optional[DiagramType] = None,
        mode: DiagramMode = DiagramMode.STANDARD,
        theme: str = "light",
        image_quality: ImageQuality = ImageQuality.MEDIUM,
        transparent_background: bool = False,
        create_file: bool = False,
        timeout: float = 60.0
    ) -> Dict[str, Any]:
        """
        Generate a diagram using Eraser AI.

        Args:
            prompt: Natural language description of the diagram
            diagram_type: Type of diagram (auto-detected if not specified)
            mode: Generation mode (standard or premium)
            theme: "light" or "dark"
            image_quality: Output quality (1=low, 2=medium, 3=high)
            transparent_background: Whether to use transparent background
            create_file: Whether to create an editable file on Eraser
            timeout: Request timeout in seconds

        Returns:
            Dict with:
                - success: bool
                - image_url: URL to generated diagram image
                - editor_url: URL to edit diagram in Eraser
                - diagram_code: Eraser DSL code for the diagram
                - diagram_type: Detected or specified diagram type
                - request_id: For subsequent edits
                - error: Error message if failed
        """
        if not self.enabled:
            return {
                "success": False,
                "error": "Eraser API not configured",
                "fallback_required": True
            }

        # Check cache
        cache_key = self._get_cache_key(
            prompt,
            diagram_type.value if diagram_type else "auto",
            theme
        )
        if cache_key in self._cache:
            logger.debug(f"Cache hit for diagram: {cache_key[:8]}...")
            return self._cache[cache_key]

        # Build request body
        request_body: Dict[str, Any] = {
            "text": prompt,
            "mode": mode.value,
            "theme": theme,
            "imageQuality": image_quality.value,
            "background": not transparent_background
        }

        if diagram_type:
            request_body["diagramType"] = diagram_type.value

        if create_file:
            request_body["fileOptions"] = {
                "create": True,
                "linkAccess": "publicly-viewable"
            }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    self.API_URL,
                    json=request_body,
                    headers=headers
                )

                if response.status_code == 200:
                    data = response.json()
                    result = {
                        "success": True,
                        "image_url": data.get("imageUrl"),
                        "editor_url": data.get("createEraserFileUrl") or data.get("fileUrl"),
                        "request_id": data.get("requestId"),
                        "diagrams": data.get("diagrams", []),
                        "diagram_code": data.get("diagrams", [{}])[0].get("code") if data.get("diagrams") else None,
                        "diagram_type": data.get("diagrams", [{}])[0].get("diagramType") if data.get("diagrams") else None
                    }

                    # Cache successful results
                    if len(self._cache) < self._cache_max_size:
                        self._cache[cache_key] = result

                    return result

                elif response.status_code == 403:
                    logger.error("Eraser API authentication failed")
                    return {
                        "success": False,
                        "error": "Invalid API key",
                        "fallback_required": True
                    }

                elif response.status_code == 503:
                    logger.warning("Eraser API rate limited")
                    return {
                        "success": False,
                        "error": "Rate limited - try again later",
                        "fallback_required": True
                    }

                else:
                    error_text = response.text
                    logger.error(f"Eraser API error {response.status_code}: {error_text}")
                    return {
                        "success": False,
                        "error": f"API error: {response.status_code}",
                        "fallback_required": True
                    }

        except httpx.TimeoutException:
            logger.error("Eraser API request timed out")
            return {
                "success": False,
                "error": "Request timed out",
                "fallback_required": True
            }
        except Exception as e:
            logger.error(f"Eraser API request failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "fallback_required": True
            }

    async def generate_threat_model_diagram(
        self,
        architecture_description: str,
        threats: List[Dict[str, Any]],
        theme: str = "light"
    ) -> Dict[str, Any]:
        """
        Generate a threat model architecture diagram.

        Args:
            architecture_description: Description of the system architecture
            threats: List of identified threats with categories and targets
            theme: Diagram theme

        Returns:
            Diagram generation result
        """
        # Build a detailed prompt for threat model visualization
        threat_summary = []
        for threat in threats[:10]:  # Limit to top 10 threats
            threat_summary.append(
                f"- {threat.get('category', 'Unknown')}: {threat.get('threat', 'Unknown threat')} "
                f"targeting {threat.get('target', 'system')}"
            )

        prompt = f"""Generate a cloud architecture security diagram showing:

System Architecture:
{architecture_description[:2000]}

Security Threats to Visualize:
{chr(10).join(threat_summary)}

Requirements:
- Show all system components and their connections
- Highlight security boundaries and trust zones
- Mark threat entry points with warning indicators
- Include data flow directions
- Use security-focused iconography
- Group components by security zone (public, DMZ, private, data)
"""

        return await self.generate_diagram(
            prompt=prompt,
            diagram_type=DiagramType.CLOUD_ARCHITECTURE,
            theme=theme,
            image_quality=ImageQuality.HIGH
        )

    async def generate_attack_tree_diagram(
        self,
        attack_tree: Dict[str, Any],
        theme: str = "light"
    ) -> Dict[str, Any]:
        """
        Generate an attack tree visualization.

        Args:
            attack_tree: Attack tree structure with root goal and attack vectors
            theme: Diagram theme

        Returns:
            Diagram generation result
        """
        root_goal = attack_tree.get("root_goal", "Unknown Attack Goal")
        attack_vectors = attack_tree.get("attack_vectors", [])

        # Build hierarchical prompt
        vector_descriptions = []
        for i, vector in enumerate(attack_vectors[:8], 1):
            vector_name = vector.get("name", f"Attack Vector {i}")
            steps = vector.get("steps", [])
            step_text = " → ".join(s.get("action", "step") for s in steps[:5])
            probability = vector.get("probability", 0.5)
            vector_descriptions.append(
                f"{i}. {vector_name} (P={probability:.0%}): {step_text}"
            )

        prompt = f"""Generate an attack tree flowchart diagram:

Root Goal (Attacker Objective):
🎯 {root_goal}

Attack Vectors (branches from root):
{chr(10).join(vector_descriptions)}

Diagram Requirements:
- Root goal at the top in red/warning color
- Each attack vector as a branch with OR gate
- Show attack steps as sequential nodes
- Include probability percentages on branches
- Use color coding: red=critical, orange=high, yellow=medium, green=mitigated
- Add icons for attack types (network, social engineering, exploit, etc.)
- Show AND/OR logic gates at decision points
"""

        return await self.generate_diagram(
            prompt=prompt,
            diagram_type=DiagramType.FLOWCHART,
            theme=theme,
            image_quality=ImageQuality.HIGH
        )

    async def generate_kill_chain_diagram(
        self,
        kill_chain_analysis: Dict[str, Any],
        theme: str = "light"
    ) -> Dict[str, Any]:
        """
        Generate a Cyber Kill Chain visualization.

        Args:
            kill_chain_analysis: Kill chain analysis with phase coverage
            theme: Diagram theme

        Returns:
            Diagram generation result
        """
        phases = kill_chain_analysis.get("phases", {})
        coverage = kill_chain_analysis.get("coverage_analysis", {})

        phase_details = []
        phase_order = [
            "reconnaissance", "weaponization", "delivery",
            "exploitation", "installation", "command_and_control", "actions_on_objectives"
        ]

        for phase_key in phase_order:
            phase = phases.get(phase_key, {})
            phase_name = phase.get("phase_name", phase_key.replace("_", " ").title())
            threat_count = len(phase.get("threats", []))
            techniques = phase.get("mitre_techniques", [])[:3]
            technique_names = [t.get("name", "") for t in techniques]

            status = "🔴 Vulnerable" if threat_count > 0 else "🟢 Protected"
            phase_details.append(
                f"Phase: {phase_name}\n"
                f"  Status: {status} ({threat_count} threats)\n"
                f"  Techniques: {', '.join(technique_names) or 'None identified'}"
            )

        coverage_pct = coverage.get("coverage_percentage", 0)

        prompt = f"""Generate a Cyber Kill Chain sequence diagram:

Kill Chain Overview:
- Total Coverage: {coverage_pct:.0f}% of phases have active threats
- Framework: Lockheed Martin Cyber Kill Chain + MITRE ATT&CK

Phases (left to right flow):
{chr(10).join(phase_details)}

Diagram Requirements:
- Show 7 kill chain phases as a horizontal sequence
- Use arrows showing attack progression
- Color code by threat level (red=threats found, green=protected)
- Include MITRE ATT&CK technique labels
- Show phase icons (reconnaissance binoculars, delivery envelope, etc.)
- Add a timeline/progression indicator at the bottom
- Include a legend for threat severity
"""

        return await self.generate_diagram(
            prompt=prompt,
            diagram_type=DiagramType.SEQUENCE,
            theme=theme,
            image_quality=ImageQuality.HIGH
        )

    async def generate_data_flow_diagram(
        self,
        components: List[Dict[str, Any]],
        data_flows: List[Dict[str, Any]],
        trust_boundaries: List[str],
        theme: str = "light"
    ) -> Dict[str, Any]:
        """
        Generate a Data Flow Diagram (DFD) for threat modeling.

        Args:
            components: System components with types and descriptions
            data_flows: Data flows between components
            trust_boundaries: Trust boundary names
            theme: Diagram theme

        Returns:
            Diagram generation result
        """
        component_text = []
        for comp in components[:15]:
            comp_type = comp.get("type", "process")
            comp_name = comp.get("name", "Unknown")
            component_text.append(f"- [{comp_type.upper()}] {comp_name}")

        flow_text = []
        for flow in data_flows[:20]:
            source = flow.get("source", "?")
            target = flow.get("target", "?")
            data_type = flow.get("data_type", "data")
            flow_text.append(f"- {source} --({data_type})--> {target}")

        prompt = f"""Generate a Data Flow Diagram (DFD) for security analysis:

System Components:
{chr(10).join(component_text)}

Data Flows:
{chr(10).join(flow_text)}

Trust Boundaries:
{chr(10).join(f'- {tb}' for tb in trust_boundaries)}

DFD Requirements:
- External entities as rectangles
- Processes as circles/rounded rectangles
- Data stores as parallel lines
- Data flows as labeled arrows
- Trust boundaries as dashed boxes grouping components
- Different colors for different trust zones
- Show data types on flow arrows
- Use standard DFD notation
"""

        return await self.generate_diagram(
            prompt=prompt,
            diagram_type=DiagramType.FLOWCHART,
            theme=theme,
            image_quality=ImageQuality.HIGH
        )

    async def generate_batch_diagrams(
        self,
        diagram_requests: List[Dict[str, Any]],
        max_concurrent: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Generate multiple diagrams concurrently.

        Args:
            diagram_requests: List of diagram generation parameters
            max_concurrent: Maximum concurrent API requests

        Returns:
            List of diagram generation results
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def generate_with_limit(request: Dict[str, Any]) -> Dict[str, Any]:
            async with semaphore:
                return await self.generate_diagram(**request)

        tasks = [generate_with_limit(req) for req in diagram_requests]
        return await asyncio.gather(*tasks)

    def clear_cache(self):
        """Clear the diagram cache"""
        self._cache.clear()
        logger.info("Eraser diagram cache cleared")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "size": len(self._cache),
            "max_size": self._cache_max_size,
            "hit_rate": "N/A"  # Would need to track hits/misses
        }


# Singleton instance
_eraser_service: Optional[EraserDiagramService] = None


def get_eraser_service() -> EraserDiagramService:
    """Get or create the singleton Eraser service instance"""
    global _eraser_service
    if _eraser_service is None:
        _eraser_service = EraserDiagramService()
    return _eraser_service


# Convenience functions for synchronous usage
def generate_diagram_sync(
    prompt: str,
    diagram_type: Optional[DiagramType] = None,
    **kwargs
) -> Dict[str, Any]:
    """Synchronous wrapper for diagram generation"""
    service = get_eraser_service()
    return asyncio.run(service.generate_diagram(prompt, diagram_type, **kwargs))
