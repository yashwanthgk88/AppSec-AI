"""
AI Chatbot Service
Provides security assistance using the configured AI provider.
Supports: OpenAI, Anthropic, Azure, Google, Ollama
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class ChatbotService:
    """
    Security chatbot powered by the user's configured AI provider.
    Uses the unified AI client factory for multi-provider support.
    """

    def __init__(self, ai_config=None):
        """
        Initialize the chatbot service.

        Args:
            ai_config: Optional AIConfig object. If None, uses global settings.
        """
        self._ai_client = None
        self.enabled = False
        self.provider = "none"
        self.model = "none"

        try:
            from services.ai_client_factory import get_ai_client, get_global_ai_config, AIConfig

            # Use provided config or fall back to global
            config = ai_config if ai_config else get_global_ai_config()

            if config.api_key:
                self._ai_client = get_ai_client(config)
                self.enabled = self._ai_client.is_configured
                self.provider = config.provider
                self.model = self._ai_client.model
                logger.info(f"[ChatbotService] Initialized with {self.provider}, model={self.model}")
            else:
                logger.warning("[ChatbotService] No API key configured")

        except Exception as e:
            logger.error(f"[ChatbotService] Failed to initialize: {e}")
            raise ValueError(f"Failed to initialize chatbot: {e}")

    def update_config(self, ai_config) -> None:
        """
        Update the AI configuration.

        Args:
            ai_config: AIConfig object with new settings
        """
        try:
            from services.ai_client_factory import AIClientFactory

            self._ai_client = AIClientFactory(ai_config)
            self.enabled = self._ai_client.is_configured
            self.provider = ai_config.provider
            self.model = self._ai_client.model
            logger.info(f"[ChatbotService] Config updated: {self.provider}, model={self.model}")
        except Exception as e:
            logger.error(f"[ChatbotService] Failed to update config: {e}")
            self.enabled = False

    def chat(self, message: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Process chat message and return response.

        Args:
            message: User's message
            context: Optional context (vulnerability, threat model, etc.)

        Returns:
            Dict with response and metadata
        """
        if not self.enabled or not self._ai_client:
            return {
                "response": "AI service is not configured. Please configure your AI provider in Settings.",
                "detected_language": "en",
                "language_name": "English",
                "tokens_used": 0,
                "model": self.model,
                "provider": self.provider,
                "error": "AI not configured"
            }

        # Build system prompt
        system_prompt = self._build_system_prompt(context)

        # Build user message with context
        user_message = self._build_user_message(message, context)

        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ]

            response = self._ai_client.chat_completion(
                messages=messages,
                max_tokens=2048
            )

            return {
                "response": response['content'],
                "detected_language": "en",
                "language_name": "English",
                "tokens_used": response.get('tokens_used', 0),
                "model": response.get('model', self.model),
                "provider": response.get('provider', self.provider),
                "context_type": context.get("type") if context else None
            }

        except Exception as e:
            logger.error(f"[ChatbotService] Chat failed: {e}")
            return {
                "response": f"I apologize, but I encountered an error processing your request: {str(e)}",
                "detected_language": "en",
                "language_name": "English",
                "tokens_used": 0,
                "model": self.model,
                "provider": self.provider,
                "error": str(e)
            }

    def _build_system_prompt(self, context: Optional[Dict[str, Any]]) -> str:
        """Build system prompt"""
        base_prompt = """You are an application security expert assistant. Your role is to:

1. Provide security guidance and vulnerability remediation assistance
2. Explain security concepts in clear, accessible language
3. Reference OWASP Top 10, CWE, STRIDE, and MITRE ATT&CK frameworks
4. Provide actionable, context-specific advice

Key responsibilities:
- Explain vulnerabilities in simple terms appropriate to the developer's skill level
- Provide step-by-step remediation instructions
- Suggest secure coding patterns and best practices
- Reference relevant security standards and compliance requirements
- Help developers understand the "why" behind security issues

Always respond in English."""

        if context:
            context_type = context.get("type")
            if context_type == "vulnerability":
                base_prompt += f"\n\nContext: You are helping with a specific vulnerability:\n{context.get('data', {})}"
            elif context_type == "threat_model":
                base_prompt += f"\n\nContext: You are discussing a threat model:\n{context.get('data', {})}"

        return base_prompt

    def _build_user_message(self, message: str, context: Optional[Dict[str, Any]]) -> str:
        """Build user message with context"""
        if not context:
            return message

        context_type = context.get("type")
        context_data = context.get("data", {})

        if context_type == "vulnerability":
            return f"""I have a security question about this vulnerability:

Vulnerability: {context_data.get('title', 'Unknown')}
Severity: {context_data.get('severity', 'Unknown')}
CWE: {context_data.get('cwe_id', 'Unknown')}
File: {context_data.get('file_path', 'Unknown')} (Line {context_data.get('line_number', '?')})
Code: {context_data.get('code_snippet', 'N/A')}

My question: {message}"""

        elif context_type == "threat_model":
            return f"""I have a question about threat modeling:

STRIDE Category: {context_data.get('stride_category', 'Unknown')}
Component: {context_data.get('component', 'Unknown')}
Threat: {context_data.get('threat', 'Unknown')}

My question: {message}"""

        return message

    def generate_remediation_guide(self, vulnerability: Dict[str, Any]) -> str:
        """Generate detailed remediation guide for a vulnerability"""
        if not self.enabled or not self._ai_client:
            return "AI service is not configured. Please configure your AI provider in Settings."

        prompt = f"""Generate a comprehensive remediation guide for this vulnerability:

Title: {vulnerability.get('title')}
Severity: {vulnerability.get('severity')}
CWE: {vulnerability.get('cwe_id')}
OWASP: {vulnerability.get('owasp_category')}
Description: {vulnerability.get('description')}
File: {vulnerability.get('file_path')} (Line {vulnerability.get('line_number')})
Code: {vulnerability.get('code_snippet')}

Please provide:
1. A clear explanation of why this is a security issue
2. Step-by-step remediation instructions
3. Secure code example
4. Best practices to prevent this in the future
5. Testing recommendations"""

        try:
            response = self._ai_client.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2048
            )
            return response['content']
        except Exception as e:
            logger.error(f"[ChatbotService] Remediation guide failed: {e}")
            return f"Error generating remediation guide: {str(e)}"

    def explain_stride_threat(self, threat: Dict[str, Any]) -> str:
        """Explain a STRIDE threat"""
        if not self.enabled or not self._ai_client:
            return "AI service is not configured. Please configure your AI provider in Settings."

        prompt = f"""Explain this security threat in simple terms:

STRIDE Category: {threat.get('stride_category')}
Component: {threat.get('component')}
Threat: {threat.get('threat')}
Description: {threat.get('description')}
Current Mitigation: {threat.get('mitigation')}

Please provide:
1. What this threat means in plain language
2. Real-world attack scenarios
3. Why the current mitigation is important
4. Additional security measures to consider"""

        try:
            response = self._ai_client.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024
            )
            return response['content']
        except Exception as e:
            logger.error(f"[ChatbotService] Explain threat failed: {e}")
            return f"Error explaining threat: {str(e)}"

    def get_security_tips(self, technology: str) -> str:
        """Get proactive security tips for a specific technology"""
        if not self.enabled or not self._ai_client:
            return "AI service is not configured. Please configure your AI provider in Settings."

        prompt = f"""Provide 5 important security tips for developers working with {technology}.

Focus on:
- Common vulnerabilities specific to {technology}
- Best practices and secure coding patterns
- Recent security trends and threats
- Actionable advice"""

        try:
            response = self._ai_client.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024
            )
            return response['content']
        except Exception as e:
            logger.error(f"[ChatbotService] Security tips failed: {e}")
            return f"Error generating security tips: {str(e)}"

    def answer_compliance_question(self, question: str, framework: str = "OWASP Top 10") -> Dict[str, Any]:
        """Answer compliance-related questions"""
        if not self.enabled or not self._ai_client:
            return {
                "response": "AI service is not configured. Please configure your AI provider in Settings.",
                "detected_language": "en",
                "framework": framework,
                "error": "AI not configured"
            }

        prompt = f"""Answer this compliance question about {framework}:

{question}

Provide:
1. A clear, accurate answer
2. Relevant requirements and controls
3. Implementation guidance
4. Evidence/documentation recommendations"""

        try:
            response = self._ai_client.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1536
            )

            return {
                "response": response['content'],
                "detected_language": "en",
                "framework": framework,
                "provider": response.get('provider', self.provider)
            }
        except Exception as e:
            logger.error(f"[ChatbotService] Compliance question failed: {e}")
            return {
                "response": f"Error: {str(e)}",
                "detected_language": "en",
                "framework": framework,
                "error": str(e)
            }

    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics"""
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "model": self.model
        }
