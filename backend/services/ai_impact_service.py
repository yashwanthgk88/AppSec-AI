"""
AI Impact Statement Service
Generates contextual, dynamic impact statements for security findings using AI.
Uses the unified AI client factory to support multiple providers.
"""
import json
import hashlib
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from collections import OrderedDict
import threading

logger = logging.getLogger(__name__)


class LRUCache:
    """Thread-safe LRU cache with TTL support."""

    def __init__(self, max_size: int = 1000, ttl_hours: int = 24):
        self.max_size = max_size
        self.ttl = timedelta(hours=ttl_hours)
        self._cache: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Dict]:
        with self._lock:
            if key not in self._cache:
                return None

            entry = self._cache[key]
            # Check TTL
            if datetime.now() - entry['timestamp'] > self.ttl:
                del self._cache[key]
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            return entry['data']

    def set(self, key: str, data: Dict) -> None:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                self._cache[key] = {'data': data, 'timestamp': datetime.now()}
            else:
                if len(self._cache) >= self.max_size:
                    # Remove oldest
                    self._cache.popitem(last=False)
                self._cache[key] = {'data': data, 'timestamp': datetime.now()}

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                'size': len(self._cache),
                'max_size': self.max_size
            }


class AIImpactService:
    """
    Service for generating AI-powered impact statements for security findings.

    Features:
    - Contextual impact generation based on vulnerability details
    - Multi-provider support (OpenAI, Anthropic, Azure, Google, Ollama)
    - In-memory caching with LRU eviction
    - Graceful fallback to static templates
    - Support for SAST, SCA, and Secret findings
    """

    MAX_TOKENS = 1024

    def __init__(self, cache_max_size: int = 1000, cache_ttl_hours: int = 24):
        """
        Initialize the AI Impact Service.

        Args:
            cache_max_size: Maximum number of cached responses
            cache_ttl_hours: Cache TTL in hours
        """
        self._ai_client = None
        self.enabled = False
        self.provider = "none"
        self.model = "none"

        # Try to initialize AI client from global settings
        try:
            from services.ai_client_factory import get_ai_client, get_global_ai_config

            config = get_global_ai_config()
            if config.api_key:
                self._ai_client = get_ai_client(config)
                self.enabled = self._ai_client.is_configured
                self.provider = config.provider
                self.model = self._ai_client.model
                logger.info(f"[AIImpactService] Initialized with {self.provider}, model={self.model}")
            else:
                logger.info("[AIImpactService] No API key configured, using fallback templates")
        except Exception as e:
            logger.warning(f"[AIImpactService] Failed to initialize AI client: {e}")

        # Initialize cache
        self._cache = LRUCache(max_size=cache_max_size, ttl_hours=cache_ttl_hours)
        self._cache_hits = 0
        self._cache_misses = 0

    def update_config(self, ai_config) -> None:
        """
        Update the AI configuration (called when settings change).

        Args:
            ai_config: AIConfig object with new settings
        """
        try:
            from services.ai_client_factory import AIClientFactory

            self._ai_client = AIClientFactory(ai_config)
            self.enabled = self._ai_client.is_configured
            self.provider = ai_config.provider
            self.model = self._ai_client.model
            logger.info(f"[AIImpactService] Config updated: {self.provider}, model={self.model}")
        except Exception as e:
            logger.warning(f"[AIImpactService] Failed to update config: {e}")
            self.enabled = False

    def generate_impact_statement(
        self,
        finding_type: str,
        vulnerability_info: Dict[str, Any],
        fallback_impact: Optional[str] = None,
        fallback_recommendations: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Generate AI-powered impact statement for a single finding.

        Args:
            finding_type: Type of finding - "sast", "sca", or "secret"
            vulnerability_info: Dictionary containing vulnerability details
            fallback_impact: Fallback impact text if AI fails
            fallback_recommendations: Fallback recommendations if AI fails

        Returns:
            Dictionary with keys: business_impact, technical_impact, recommendations, generated_by
        """
        # Generate cache key based on vulnerability characteristics (not file-specific)
        cache_key = self._generate_cache_key(finding_type, vulnerability_info)

        # Check cache first
        cached = self._cache.get(cache_key)
        if cached:
            self._cache_hits += 1
            logger.debug(f"[AIImpactService] Cache hit for {cache_key[:8]}...")
            return {**cached, 'generated_by': 'ai_cached'}

        self._cache_misses += 1

        # If AI not enabled, return fallback
        if not self.enabled:
            return self._generate_fallback(finding_type, vulnerability_info, fallback_impact, fallback_recommendations)

        try:
            # Build prompts
            system_prompt = self._get_system_prompt()
            user_prompt = self._build_prompt(finding_type, vulnerability_info)

            # Call AI using the unified client factory
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]

            response = self._ai_client.chat_completion(
                messages=messages,
                max_tokens=self.MAX_TOKENS,
                temperature=0.3  # Lower temperature for more consistent outputs
            )

            response_text = response['content']

            # Parse response
            result = self._parse_response(response_text)

            # Cache the result
            self._cache.set(cache_key, result)

            logger.debug(f"[AIImpactService] Generated impact for {finding_type}: {vulnerability_info.get('title', vulnerability_info.get('vulnerability', 'unknown'))}")

            return {**result, 'generated_by': 'ai'}

        except Exception as e:
            logger.warning(f"[AIImpactService] AI generation failed: {e}")
            return self._generate_fallback(finding_type, vulnerability_info, fallback_impact, fallback_recommendations)

    def generate_impact_statements_batch(
        self,
        findings: List[Dict[str, Any]],
        finding_type: str
    ) -> List[Dict[str, str]]:
        """
        Generate impact statements for multiple findings.
        Uses caching to avoid duplicate API calls for similar vulnerabilities.

        Args:
            findings: List of finding dictionaries
            finding_type: Type of findings - "sast", "sca", or "secret"

        Returns:
            List of impact statement dictionaries
        """
        results = [None] * len(findings)
        uncached_indices = []

        # Check cache for each finding
        for i, finding in enumerate(findings):
            cache_key = self._generate_cache_key(finding_type, finding)
            cached = self._cache.get(cache_key)
            if cached:
                self._cache_hits += 1
                results[i] = {**cached, 'generated_by': 'ai_cached'}
            else:
                uncached_indices.append(i)

        # Process uncached findings
        for i in uncached_indices:
            self._cache_misses += 1
            result = self.generate_impact_statement(finding_type, findings[i])
            results[i] = result

        return results

    def _generate_cache_key(self, finding_type: str, vuln_info: Dict) -> str:
        """
        Generate a unique cache key for the vulnerability.
        Key is based on vulnerability characteristics, not file location,
        to allow reuse across similar findings.
        """
        key_data = {
            "type": finding_type,
            "vuln_type": (
                vuln_info.get("title") or
                vuln_info.get("vulnerability") or
                vuln_info.get("secret_type") or
                vuln_info.get("pattern_name") or
                "unknown"
            ),
            "severity": vuln_info.get("severity", "unknown"),
            "cwe": vuln_info.get("cwe_id") or vuln_info.get("cwe") or "",
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()

    def _get_system_prompt(self) -> str:
        """Get the system prompt for AI generation."""
        return """You are a senior application security expert with deep expertise in vulnerability assessment, threat modeling, and secure development practices.

Your task is to generate detailed, actionable impact statements for security vulnerabilities. Your response MUST be valid JSON with this exact structure:

{
    "business_impact": "Bullet points explaining business consequences",
    "technical_impact": "Bullet points explaining technical attack vectors and consequences",
    "recommendations": "Numbered list of specific, actionable remediation steps"
}

Guidelines:
- Business impact should cover: financial risk, regulatory/compliance implications (GDPR, PCI-DSS, HIPAA, SOC2), reputational damage, operational disruption
- Technical impact should cover: specific attack scenarios, exploitation methods, potential for lateral movement, data exposure risks
- Recommendations should be specific and actionable, including tool names, code patterns, and configuration changes
- Each section should be 80-120 words
- Use markdown formatting (bullet points, bold for emphasis)
- Be concise but comprehensive"""

    def _build_prompt(self, finding_type: str, vuln_info: Dict) -> str:
        """Build the user prompt based on finding type."""
        if finding_type == "sast":
            return self._build_sast_prompt(vuln_info)
        elif finding_type == "sca":
            return self._build_sca_prompt(vuln_info)
        elif finding_type == "secret":
            return self._build_secret_prompt(vuln_info)
        else:
            return self._build_generic_prompt(vuln_info)

    def _build_sast_prompt(self, vuln_info: Dict) -> str:
        """Build prompt for SAST findings."""
        code_snippet = vuln_info.get('code_snippet') or vuln_info.get('vulnerable_code') or 'N/A'
        # Truncate code snippet to avoid token limits
        if len(code_snippet) > 300:
            code_snippet = code_snippet[:300] + "..."

        return f"""Generate a detailed impact statement for this SAST (Static Application Security Testing) finding:

**Vulnerability Type:** {vuln_info.get('title', 'Unknown')}
**Severity:** {vuln_info.get('severity', 'Unknown')}
**CWE:** {vuln_info.get('cwe_id') or vuln_info.get('cwe', 'Unknown')}
**OWASP Category:** {vuln_info.get('owasp_category', 'Unknown')}
**File:** {vuln_info.get('file_path') or vuln_info.get('file', 'Unknown')}
**Language/Framework:** {vuln_info.get('language', 'Unknown')}
**Affected Code:**
```
{code_snippet}
```

Consider the specific programming language context and provide relevant attack scenarios and language-specific remediation."""

    def _build_sca_prompt(self, vuln_info: Dict) -> str:
        """Build prompt for SCA findings."""
        return f"""Generate a detailed impact statement for this SCA (Software Composition Analysis) finding:

**Package:** {vuln_info.get('package', 'Unknown')}
**Installed Version:** {vuln_info.get('installed_version') or vuln_info.get('version', 'Unknown')}
**Fixed Version:** {vuln_info.get('fixed_version') or vuln_info.get('patched_version', 'Unknown')}
**Vulnerability:** {vuln_info.get('vulnerability', 'Unknown')}
**CVE:** {vuln_info.get('cve', 'Unknown')}
**Severity:** {vuln_info.get('severity', 'Unknown')}
**CVSS Score:** {vuln_info.get('cvss_score') or vuln_info.get('cvss', 'Unknown')}
**Ecosystem:** {vuln_info.get('ecosystem', 'Unknown')}

Consider known exploits for this CVE if applicable, and provide package-specific upgrade guidance."""

    def _build_secret_prompt(self, vuln_info: Dict) -> str:
        """Build prompt for Secret findings."""
        return f"""Generate a detailed impact statement for this exposed secret/credential:

**Secret Type:** {vuln_info.get('secret_type') or vuln_info.get('pattern_name', 'Unknown')}
**Severity:** {vuln_info.get('severity', 'Unknown')}
**File:** {vuln_info.get('file_path') or vuln_info.get('file', 'Unknown')}
**Confidence:** {vuln_info.get('confidence', 'Unknown')}
**Description:** {vuln_info.get('description', 'Exposed credential detected')}

Consider what an attacker could do with this specific type of credential and provide immediate rotation/revocation steps."""

    def _build_generic_prompt(self, vuln_info: Dict) -> str:
        """Build a generic prompt for unknown finding types."""
        return f"""Generate a detailed impact statement for this security finding:

**Finding:** {json.dumps(vuln_info, indent=2, default=str)[:500]}

Provide comprehensive business impact, technical impact, and remediation recommendations."""

    def _parse_response(self, response_text: str) -> Dict[str, str]:
        """Parse the AI response and extract structured data."""
        try:
            # Try to extract JSON from the response
            text = response_text.strip()

            # Handle markdown code blocks
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]

            result = json.loads(text.strip())

            # Validate expected keys
            return {
                "business_impact": result.get("business_impact", "Impact assessment unavailable"),
                "technical_impact": result.get("technical_impact", "Technical impact unavailable"),
                "recommendations": result.get("recommendations", "Contact security team for guidance")
            }

        except (json.JSONDecodeError, IndexError, KeyError) as e:
            logger.warning(f"[AIImpactService] Failed to parse AI response: {e}")
            # Return the raw response as a fallback
            return {
                "business_impact": response_text[:500] if response_text else "Impact assessment unavailable",
                "technical_impact": "See business impact for details",
                "recommendations": "Contact security team for remediation guidance"
            }

    def _generate_fallback(
        self,
        finding_type: str,
        vuln_info: Dict,
        fallback_impact: Optional[str],
        fallback_recommendations: Optional[str]
    ) -> Dict[str, str]:
        """Generate fallback impact statement when AI is unavailable."""
        from services.impact_templates import get_fallback_impact

        # Try to get template-based fallback
        template = get_fallback_impact(finding_type, vuln_info)

        if template:
            return {**template, 'generated_by': 'template'}

        # Use provided fallback or generic message
        severity = vuln_info.get('severity', 'medium').lower()
        vuln_name = (
            vuln_info.get('title') or
            vuln_info.get('vulnerability') or
            vuln_info.get('secret_type') or
            'Security vulnerability'
        )

        return {
            "business_impact": fallback_impact or f"**{severity.upper()} Severity Finding**\n- Potential security risk requiring immediate attention\n- May lead to data exposure or system compromise\n- Review for compliance implications",
            "technical_impact": f"**{vuln_name}**\n- Vulnerability may be exploitable by attackers\n- Could lead to unauthorized access or data manipulation\n- Requires security review and remediation",
            "recommendations": fallback_recommendations or f"1. Review the affected code/component immediately\n2. Apply recommended security fixes\n3. Test the fix thoroughly\n4. Consider security scanning in CI/CD pipeline",
            "generated_by": "fallback"
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics."""
        cache_stats = self._cache.stats()
        total_requests = self._cache_hits + self._cache_misses
        hit_rate = (self._cache_hits / total_requests * 100) if total_requests > 0 else 0

        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "model": self.model,
            "cache_size": cache_stats['size'],
            "cache_max_size": cache_stats['max_size'],
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cache_hit_rate": f"{hit_rate:.1f}%"
        }


# Singleton instance
_ai_impact_service: Optional[AIImpactService] = None

def get_ai_impact_service() -> AIImpactService:
    """Get or create the singleton AI Impact Service instance."""
    global _ai_impact_service
    if _ai_impact_service is None:
        _ai_impact_service = AIImpactService()
    return _ai_impact_service
