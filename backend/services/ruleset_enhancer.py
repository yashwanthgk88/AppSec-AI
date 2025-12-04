"""
AI-Powered Ruleset Enhancement Service
Generates and refines vulnerability detection rules using OpenAI
"""
import os
import json
import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from openai import OpenAI
from dotenv import load_dotenv
import logging

load_dotenv()
logger = logging.getLogger(__name__)

class RulesetEnhancer:
    """AI-powered ruleset generator and refiner"""

    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        self.client = OpenAI(api_key=api_key)
        self.model = "gpt-4o"  # Use more powerful model for rule generation

    async def generate_rule_from_description(
        self,
        rule_name: str,
        vulnerability_description: str,
        severity: str,
        languages: List[str] = None
    ) -> Dict[str, Any]:
        """
        Generate detection rule from vulnerability description

        Args:
            rule_name: Name of the vulnerability
            vulnerability_description: Description of what to detect
            severity: Severity level (critical, high, medium, low)
            languages: Target programming languages

        Returns:
            Dict with pattern, description, remediation, etc.
        """
        if languages is None:
            languages = ["python", "javascript", "java", "php", "go"]

        prompt = f"""You are a security expert creating vulnerability detection rules.

Generate precise regex patterns to detect this vulnerability:

Vulnerability Name: {rule_name}
Description: {vulnerability_description}
Severity: {severity}
Target Languages: {', '.join(languages)}

Return a JSON object with the following structure:
{{
    "patterns": [
        {{
            "pattern": "regex pattern here",
            "language": "python|javascript|java|php|go|*",
            "description": "what this pattern detects"
        }}
    ],
    "cwe": "CWE-XXX",
    "owasp": "OWASP category",
    "description": "detailed description of the vulnerability",
    "remediation": "how to fix this vulnerability",
    "remediation_code": "example secure code",
    "false_positive_prevention": "tips to avoid false positives"
}}

Make the patterns precise to minimize false positives. Use non-capturing groups (?:) where possible.
Focus on real security issues, not code style."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": "You are a security expert generating vulnerability detection rules. Always return valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3  # Lower temperature for more consistent output
            )

            rule_data = json.loads(response.choices[0].message.content)

            # Add metadata
            rule_data["name"] = rule_name
            rule_data["severity"] = severity
            rule_data["generated_at"] = datetime.utcnow().isoformat()
            rule_data["generated_by"] = "ai"

            return rule_data

        except Exception as e:
            logger.error(f"Failed to generate rule: {str(e)}")
            raise

    async def refine_rule_from_false_positives(
        self,
        rule_name: str,
        current_pattern: str,
        current_description: str,
        false_positive_examples: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Refine rule based on false positive feedback

        Args:
            rule_name: Name of the rule
            current_pattern: Current regex pattern
            current_description: Current description
            false_positive_examples: List of false positive cases with code snippets

        Returns:
            Refined rule with improved pattern
        """

        fp_cases = "\n".join([
            f"Case {i+1}:\nCode: {fp['code_snippet']}\nReason: {fp.get('reason', 'Marked as false positive')}"
            for i, fp in enumerate(false_positive_examples[:5])  # Limit to 5 examples
        ])

        prompt = f"""You are refining a security detection rule that's producing false positives.

Current Rule:
Name: {rule_name}
Pattern: {current_pattern}
Description: {current_description}

False Positive Cases (these should NOT be detected):
{fp_cases}

Task:
1. Analyze why the current pattern matches these false positives
2. Generate an improved regex pattern that:
   - Still catches the real vulnerability
   - Excludes these specific false positive cases
   - Maintains high precision
   - Uses negative lookaheads/lookbehinds if needed

Return JSON:
{{
    "improved_pattern": "new regex pattern",
    "changes_made": "explanation of what was changed and why",
    "expected_impact": "how this affects detection",
    "confidence": "high|medium|low"
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": "You are refining security detection rules. Return valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2
            )

            refinement = json.loads(response.choices[0].message.content)
            refinement["refined_at"] = datetime.utcnow().isoformat()
            refinement["false_positive_count"] = len(false_positive_examples)

            return refinement

        except Exception as e:
            logger.error(f"Failed to refine rule: {str(e)}")
            raise

    async def generate_rules_from_cve(self, cve_id: str, cve_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate detection rules from CVE information

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
            cve_data: CVE details from NVD or similar source

        Returns:
            List of generated rules
        """

        prompt = f"""Generate vulnerability detection rules for this CVE:

CVE ID: {cve_id}
Description: {cve_data.get('description', 'N/A')}
Affected Software: {cve_data.get('affected_software', 'N/A')}
Attack Vector: {cve_data.get('attack_vector', 'N/A')}
CWE: {cve_data.get('cwe', 'N/A')}

Generate regex patterns to detect vulnerable code patterns in source code.
Include patterns for multiple languages if applicable.

Return JSON array:
[
    {{
        "pattern": "regex pattern",
        "language": "python|javascript|java|etc",
        "severity": "critical|high|medium|low",
        "description": "what this detects",
        "remediation": "how to fix"
    }}
]

Only generate rules if this CVE represents detectable code patterns.
If it's a configuration or deployment issue, return empty array."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": "You are generating security rules from CVE data. Return valid JSON with a 'rules' array."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )

            result = json.loads(response.choices[0].message.content)
            rules = result.get("rules", [])

            # Add CVE metadata to each rule
            for rule in rules:
                rule["cve_id"] = cve_id
                rule["generated_from"] = "cve"
                rule["generated_at"] = datetime.utcnow().isoformat()

            return rules

        except Exception as e:
            logger.error(f"Failed to generate CVE rules: {str(e)}")
            return []

    async def generate_threat_intel_rules(self, threat_description: str, source: str) -> List[Dict[str, Any]]:
        """
        Generate rules from threat intelligence or security advisories

        Args:
            threat_description: Description of the threat/attack pattern
            source: Source of the threat intel (e.g., "MITRE ATT&CK", "OWASP", blog URL)

        Returns:
            List of generated rules
        """

        prompt = f"""Generate vulnerability detection rules from this security threat intelligence:

Source: {source}
Threat Description:
{threat_description}

Analyze this threat and generate regex patterns to detect vulnerable code patterns.

Return JSON:
{{
    "rules": [
        {{
            "name": "vulnerability name",
            "pattern": "regex pattern",
            "language": "target language or *",
            "severity": "critical|high|medium|low",
            "description": "what this detects",
            "remediation": "how to fix",
            "confidence": "high|medium|low"
        }}
    ]
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": "Generate security detection rules from threat intelligence. Return valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )

            result = json.loads(response.choices[0].message.content)
            rules = result.get("rules", [])

            for rule in rules:
                rule["source"] = source
                rule["generated_from"] = "threat_intel"
                rule["generated_at"] = datetime.utcnow().isoformat()

            return rules

        except Exception as e:
            logger.error(f"Failed to generate threat intel rules: {str(e)}")
            return []

    def validate_regex_pattern(self, pattern: str) -> Dict[str, Any]:
        """
        Validate that a regex pattern is valid and safe

        Args:
            pattern: Regex pattern to validate

        Returns:
            Dict with is_valid, error message if any
        """
        try:
            # Test compilation
            re.compile(pattern)

            # Check for catastrophic backtracking patterns
            dangerous_patterns = [
                r'\(.*\)\*\(.*\)\*',  # Nested quantifiers
                r'\(.*\+\)\+',         # Nested + quantifiers
                r'(.+)*',              # Greedy nested quantifiers
            ]

            for danger in dangerous_patterns:
                if re.search(danger, pattern):
                    return {
                        "is_valid": False,
                        "error": "Pattern may cause catastrophic backtracking",
                        "severity": "high"
                    }

            return {
                "is_valid": True,
                "error": None
            }

        except re.error as e:
            return {
                "is_valid": False,
                "error": f"Invalid regex: {str(e)}",
                "severity": "critical"
            }

    async def enhance_existing_rule(
        self,
        rule: Dict[str, Any],
        enhancement_type: str = "precision"
    ) -> Dict[str, Any]:
        """
        Enhance an existing rule for better precision or recall

        Args:
            rule: Existing rule to enhance
            enhancement_type: "precision" (fewer false positives) or "recall" (catch more)

        Returns:
            Enhanced rule
        """

        prompt = f"""Enhance this vulnerability detection rule for better {enhancement_type}:

Current Rule:
Name: {rule.get('name')}
Pattern: {rule.get('pattern')}
Description: {rule.get('description')}
Language: {rule.get('language', '*')}

Task: Improve this rule to {"reduce false positives" if enhancement_type == "precision" else "catch more true vulnerabilities"}.

Return JSON:
{{
    "enhanced_pattern": "improved regex pattern",
    "improvements_made": "list of specific improvements",
    "expected_impact": "how this changes detection",
    "backward_compatible": true|false
}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": "Enhance security detection rules. Return valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2
            )

            enhancement = json.loads(response.choices[0].message.content)
            enhancement["enhanced_at"] = datetime.utcnow().isoformat()
            enhancement["enhancement_type"] = enhancement_type

            return enhancement

        except Exception as e:
            logger.error(f"Failed to enhance rule: {str(e)}")
            raise
