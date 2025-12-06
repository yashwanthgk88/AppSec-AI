"""
AI Chatbot Service using OpenAI API
Provides security assistance in English
"""
import os
from typing import Dict, Any, Optional
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

class ChatbotService:
    """Security chatbot powered by OpenAI (English only)"""

    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        self.client = OpenAI(api_key=api_key)
        self.model = "gpt-4o-mini"

    def chat(self, message: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Process chat message and return response in English

        Args:
            message: User's message
            context: Optional context (vulnerability, threat model, etc.)

        Returns:
            Dict with response and metadata
        """
        # Build system prompt
        system_prompt = self._build_system_prompt(context)

        # Build user message with context
        user_message = self._build_user_message(message, context)

        try:
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=2048,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ]
            )

            response_text = response.choices[0].message.content
            tokens_used = response.usage.total_tokens

            return {
                "response": response_text,
                "detected_language": "en",
                "language_name": "English",
                "tokens_used": tokens_used,
                "model": self.model,
                "context_type": context.get("type") if context else None
            }

        except Exception as e:
            # Fallback response
            return {
                "response": f"I apologize, but I encountered an error processing your request: {str(e)}",
                "detected_language": "en",
                "language_name": "English",
                "tokens_used": 0,
                "model": self.model,
                "error": str(e)
            }

    def _build_system_prompt(self, context: Optional[Dict[str, Any]]) -> str:
        """Build system prompt for OpenAI"""
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
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=2048,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating remediation guide: {str(e)}"

    def explain_stride_threat(self, threat: Dict[str, Any]) -> str:
        """Explain a STRIDE threat"""
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
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=1024,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error explaining threat: {str(e)}"

    def get_security_tips(self, technology: str) -> str:
        """Get proactive security tips for a specific technology"""
        prompt = f"""Provide 5 important security tips for developers working with {technology}.

Focus on:
- Common vulnerabilities specific to {technology}
- Best practices and secure coding patterns
- Recent security trends and threats
- Actionable advice"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=1024,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating security tips: {str(e)}"

    def answer_compliance_question(self, question: str, framework: str = "OWASP Top 10") -> Dict[str, Any]:
        """Answer compliance-related questions"""
        prompt = f"""Answer this compliance question about {framework}:

{question}

Provide:
1. A clear, accurate answer
2. Relevant requirements and controls
3. Implementation guidance
4. Evidence/documentation recommendations"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=1536,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            return {
                "response": response.choices[0].message.content,
                "detected_language": "en",
                "framework": framework
            }
        except Exception as e:
            return {
                "response": f"Error: {str(e)}",
                "detected_language": "en",
                "framework": framework,
                "error": str(e)
            }
