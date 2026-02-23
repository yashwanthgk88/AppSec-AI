"""
Unified AI Client Factory
Provides a centralized way to create AI clients based on user/system settings.
Supports: OpenAI, Anthropic, Azure OpenAI, Google Gemini, Ollama
"""
import os
import logging
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

# Try to import AI providers
try:
    from openai import OpenAI, AzureOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("OpenAI package not installed")

try:
    from anthropic import Anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logger.warning("Anthropic package not installed")

try:
    import google.generativeai as genai
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False


class AIProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE = "azure"
    GOOGLE = "google"
    OLLAMA = "ollama"


@dataclass
class AIConfig:
    """Configuration for AI client"""
    provider: str
    api_key: str
    model: Optional[str] = None
    base_url: Optional[str] = None
    api_version: Optional[str] = None

    @classmethod
    def from_user(cls, user) -> 'AIConfig':
        """Create config from user object (database model)"""
        return cls(
            provider=user.ai_provider or "openai",
            api_key=user.ai_api_key or "",
            model=user.ai_model,
            base_url=user.ai_base_url,
            api_version=user.ai_api_version
        )

    @classmethod
    def from_dict(cls, settings: Dict[str, Any]) -> 'AIConfig':
        """Create config from dictionary"""
        return cls(
            provider=settings.get('ai_provider', 'openai'),
            api_key=settings.get('ai_api_key', ''),
            model=settings.get('ai_model'),
            base_url=settings.get('ai_base_url'),
            api_version=settings.get('ai_api_version')
        )

    @classmethod
    def from_env(cls) -> 'AIConfig':
        """Create config from environment variables (fallback)"""
        # Check for explicit AI provider selection
        ai_provider = os.getenv("AI_PROVIDER", "").lower()

        # Azure OpenAI configuration
        azure_key = os.getenv("AZURE_OPENAI_API_KEY", "")
        azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "")
        azure_deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        azure_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")

        # Other provider keys
        anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
        openai_key = os.getenv("OPENAI_API_KEY", "")
        gemini_key = os.getenv("GEMINI_API_KEY", "")

        # If explicit provider is set, use it
        if ai_provider == "azure" and azure_key and azure_endpoint:
            return cls(
                provider="azure",
                api_key=azure_key,
                base_url=azure_endpoint,
                model=azure_deployment,
                api_version=azure_version
            )
        elif ai_provider == "anthropic" and anthropic_key:
            return cls(provider="anthropic", api_key=anthropic_key)
        elif ai_provider == "openai" and openai_key:
            return cls(provider="openai", api_key=openai_key)
        elif ai_provider == "google" and gemini_key:
            return cls(provider="google", api_key=gemini_key)

        # Auto-detect based on available keys (priority order)
        if azure_key and azure_endpoint:
            return cls(
                provider="azure",
                api_key=azure_key,
                base_url=azure_endpoint,
                model=azure_deployment,
                api_version=azure_version
            )
        elif anthropic_key:
            return cls(provider="anthropic", api_key=anthropic_key)
        elif openai_key:
            return cls(provider="openai", api_key=openai_key)
        elif gemini_key:
            return cls(provider="google", api_key=gemini_key)
        else:
            return cls(provider="openai", api_key="")


# Default models for each provider
DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-sonnet-4-20250514",
    "azure": "gpt-4o",
    "google": "gemini-1.5-flash",
    "ollama": "llama3.1"
}

# Model mappings for different use cases
RECOMMENDED_MODELS = {
    "openai": {
        "fast": "gpt-4o-mini",
        "balanced": "gpt-4o",
        "powerful": "gpt-4-turbo"
    },
    "anthropic": {
        "fast": "claude-3-5-haiku-20241022",
        "balanced": "claude-sonnet-4-20250514",
        "powerful": "claude-opus-4-20250514"
    },
    "google": {
        "fast": "gemini-1.5-flash",
        "balanced": "gemini-1.5-pro",
        "powerful": "gemini-1.5-pro"
    }
}


class AIClientFactory:
    """
    Factory for creating AI clients based on configuration.
    Provides a unified interface for different AI providers.
    """

    def __init__(self, config: Optional[AIConfig] = None):
        """
        Initialize the factory with configuration.

        Args:
            config: AI configuration. If None, will use environment variables.
        """
        self.config = config or AIConfig.from_env()
        self._client = None
        self._provider_type = None

    @property
    def is_configured(self) -> bool:
        """Check if the factory has a valid API key configured"""
        return bool(self.config.api_key)

    @property
    def provider(self) -> str:
        """Get the configured provider"""
        return self.config.provider

    @property
    def model(self) -> str:
        """Get the configured model or default for the provider"""
        return self.config.model or DEFAULT_MODELS.get(self.config.provider, "gpt-4o-mini")

    def get_client(self) -> Tuple[Any, str]:
        """
        Get or create the AI client.

        Returns:
            Tuple of (client, provider_type)
        """
        if self._client is not None:
            return self._client, self._provider_type

        provider = self.config.provider.lower()

        if provider == "anthropic":
            self._client, self._provider_type = self._create_anthropic_client()
        elif provider == "azure":
            self._client, self._provider_type = self._create_azure_client()
        elif provider == "google":
            self._client, self._provider_type = self._create_google_client()
        elif provider == "ollama":
            self._client, self._provider_type = self._create_ollama_client()
        else:  # Default to OpenAI
            self._client, self._provider_type = self._create_openai_client()

        return self._client, self._provider_type

    def _create_openai_client(self) -> Tuple[Any, str]:
        """Create OpenAI client"""
        if not OPENAI_AVAILABLE:
            raise RuntimeError("OpenAI package not installed")

        if not self.config.api_key:
            raise ValueError("OpenAI API key not configured")

        client = OpenAI(api_key=self.config.api_key)
        return client, "openai"

    def _create_anthropic_client(self) -> Tuple[Any, str]:
        """Create Anthropic client"""
        if not ANTHROPIC_AVAILABLE:
            raise RuntimeError("Anthropic package not installed")

        if not self.config.api_key:
            raise ValueError("Anthropic API key not configured")

        client = Anthropic(api_key=self.config.api_key)
        return client, "anthropic"

    def _create_azure_client(self) -> Tuple[Any, str]:
        """Create Azure OpenAI client"""
        if not OPENAI_AVAILABLE:
            raise RuntimeError("OpenAI package not installed (required for Azure)")

        if not self.config.api_key:
            raise ValueError("Azure OpenAI API key not configured")

        if not self.config.base_url:
            raise ValueError("Azure OpenAI endpoint URL not configured")

        client = AzureOpenAI(
            api_key=self.config.api_key,
            api_version=self.config.api_version or "2024-02-15-preview",
            azure_endpoint=self.config.base_url
        )
        return client, "azure"

    def _create_google_client(self) -> Tuple[Any, str]:
        """Create Google Gemini client"""
        if not GOOGLE_AVAILABLE:
            raise RuntimeError("Google GenAI package not installed")

        if not self.config.api_key:
            raise ValueError("Google API key not configured")

        genai.configure(api_key=self.config.api_key)
        # Return the genai module itself as client
        return genai, "google"

    def _create_ollama_client(self) -> Tuple[Any, str]:
        """Create Ollama client (uses OpenAI-compatible API)"""
        if not OPENAI_AVAILABLE:
            raise RuntimeError("OpenAI package not installed (required for Ollama)")

        base_url = self.config.base_url or "http://localhost:11434/v1"
        client = OpenAI(
            api_key="ollama",  # Ollama doesn't require a real key
            base_url=base_url
        )
        return client, "ollama"

    def chat_completion(
        self,
        messages: list,
        max_tokens: int = 2048,
        temperature: float = 0.7,
        model: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Unified chat completion interface for all providers.

        Args:
            messages: List of message dicts with 'role' and 'content'
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            model: Override model (uses configured model if None)

        Returns:
            Dict with 'content', 'model', 'tokens_used', 'provider'
        """
        client, provider_type = self.get_client()
        use_model = model or self.model

        try:
            if provider_type == "anthropic":
                return self._anthropic_chat(client, messages, max_tokens, temperature, use_model)
            elif provider_type == "google":
                return self._google_chat(client, messages, max_tokens, temperature, use_model)
            else:  # openai, azure, ollama
                return self._openai_chat(client, messages, max_tokens, temperature, use_model)

        except Exception as e:
            logger.error(f"[AIClientFactory] Chat completion failed: {e}")
            raise

    def _openai_chat(self, client, messages, max_tokens, temperature, model) -> Dict[str, Any]:
        """OpenAI/Azure/Ollama chat completion"""
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature
        )

        return {
            "content": response.choices[0].message.content,
            "model": model,
            "tokens_used": response.usage.total_tokens if response.usage else 0,
            "provider": self.config.provider
        }

    def _anthropic_chat(self, client, messages, max_tokens, temperature, model) -> Dict[str, Any]:
        """Anthropic chat completion"""
        # Extract system message if present
        system_content = None
        chat_messages = []

        for msg in messages:
            if msg["role"] == "system":
                system_content = msg["content"]
            else:
                chat_messages.append(msg)

        kwargs = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": chat_messages
        }

        if system_content:
            kwargs["system"] = system_content

        response = client.messages.create(**kwargs)

        return {
            "content": response.content[0].text,
            "model": model,
            "tokens_used": response.usage.input_tokens + response.usage.output_tokens,
            "provider": "anthropic"
        }

    def _google_chat(self, client, messages, max_tokens, temperature, model) -> Dict[str, Any]:
        """Google Gemini chat completion"""
        # Convert messages to Gemini format
        gemini_model = client.GenerativeModel(model)

        # Combine system and user messages
        prompt_parts = []
        for msg in messages:
            if msg["role"] == "system":
                prompt_parts.append(f"System: {msg['content']}\n\n")
            elif msg["role"] == "user":
                prompt_parts.append(f"User: {msg['content']}\n\n")
            elif msg["role"] == "assistant":
                prompt_parts.append(f"Assistant: {msg['content']}\n\n")

        prompt = "".join(prompt_parts) + "Assistant:"

        response = gemini_model.generate_content(
            prompt,
            generation_config={
                "max_output_tokens": max_tokens,
                "temperature": temperature
            }
        )

        return {
            "content": response.text,
            "model": model,
            "tokens_used": 0,  # Gemini doesn't provide token count in same way
            "provider": "google"
        }


# Global settings cache (loaded from database)
_global_ai_config: Optional[AIConfig] = None


def set_global_ai_config(config: AIConfig) -> None:
    """Set the global AI configuration (called at startup from database)"""
    global _global_ai_config
    _global_ai_config = config
    logger.info(f"[AIClientFactory] Global AI config set: provider={config.provider}, model={config.model or 'default'}")


def get_global_ai_config() -> AIConfig:
    """Get the global AI configuration"""
    global _global_ai_config
    if _global_ai_config is None:
        # Fallback to environment variables
        _global_ai_config = AIConfig.from_env()
    return _global_ai_config


def get_ai_client(config: Optional[AIConfig] = None) -> AIClientFactory:
    """
    Get an AI client factory.

    Args:
        config: Optional config override. Uses global config if None.

    Returns:
        AIClientFactory instance
    """
    if config is None:
        config = get_global_ai_config()
    return AIClientFactory(config)


def load_ai_config_from_db(db_session) -> Optional[AIConfig]:
    """
    Load AI configuration from database settings.
    Looks for system-wide settings first, then falls back to admin user settings.

    Args:
        db_session: SQLAlchemy database session

    Returns:
        AIConfig or None if not found
    """
    from models import SystemSettings, User

    try:
        # Try to load from SystemSettings table first
        settings = {}
        for key in ['ai_provider', 'ai_api_key', 'ai_model', 'ai_base_url', 'ai_api_version']:
            setting = db_session.query(SystemSettings).filter(
                SystemSettings.key == key,
                SystemSettings.category == 'ai'
            ).first()
            if setting:
                settings[key] = setting.value

        if settings.get('ai_api_key'):
            logger.info(f"[AIClientFactory] Loaded AI config from SystemSetting: provider={settings.get('ai_provider')}")
            return AIConfig.from_dict(settings)

        # Fallback: Try to load from first admin user with configured AI
        admin_user = db_session.query(User).filter(
            User.ai_api_key.isnot(None),
            User.ai_api_key != ''
        ).first()

        if admin_user:
            logger.info(f"[AIClientFactory] Loaded AI config from user: provider={admin_user.ai_provider}")
            return AIConfig.from_user(admin_user)

        logger.warning("[AIClientFactory] No AI config found in database, using environment variables")
        return None

    except Exception as e:
        logger.error(f"[AIClientFactory] Failed to load AI config from database: {e}")
        return None
