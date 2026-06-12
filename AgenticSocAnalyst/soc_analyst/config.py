"""
Centralized configuration for HallucinatingCrusaders.
All secrets and connection details in one place.
Override via environment variables.
"""

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()


@dataclass
class WazuhConfig:
    """Wazuh Manager REST API configuration."""
    api_url: str = os.getenv("WAZUH_API_URL", "https://127.0.0.1:56000")
    api_user: str = os.getenv("WAZUH_API_USER", "wazuh-wui")
    api_pass: str = os.getenv("WAZUH_API_PASS", "MyS3cr37P450r.*-")
    verify_ssl: bool = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"


@dataclass
class IndexerConfig:
    """Wazuh Indexer (OpenSearch) configuration."""
    url: str = os.getenv("INDEXER_URL", "https://127.0.0.1:9200")
    user: str = os.getenv("INDEXER_USER", "admin")
    password: str = os.getenv("INDEXER_PASS", "SecretPassword")
    alert_index: str = os.getenv("INDEXER_ALERT_INDEX", "wazuh-alerts-4.x-*")
    verify_ssl: bool = os.getenv("INDEXER_VERIFY_SSL", "false").lower() == "true"


@dataclass
class PostgresConfig:
    """PostgreSQL configuration."""
    host: str = os.getenv("POSTGRES_HOST", "localhost")
    port: int = int(os.getenv("POSTGRES_PORT", "5432"))
    database: str = os.getenv("POSTGRES_DB", "soc_analyst")
    user: str = os.getenv("POSTGRES_USER", "soc_user")
    password: str = os.getenv("POSTGRES_PASS", "soc_password")

    @property
    def dsn(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"

    @property
    def async_dsn(self) -> str:
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"


@dataclass
class ChromaConfig:
    """ChromaDB configuration."""
    host: str = os.getenv("CHROMA_HOST", "localhost")
    port: int = int(os.getenv("CHROMA_PORT", "8000"))
    collection: str = os.getenv("CHROMA_COLLECTION", "soc_alerts")


@dataclass
class OktaConfig:
    """Okta API configuration."""
    domain: str = os.getenv("OKTA_DOMAIN", "")
    api_token: str = os.getenv("OKTA_API_TOKEN", "")
    verify_ssl: bool = os.getenv("OKTA_VERIFY_SSL", "true").lower() == "true"

@dataclass
class AuthConfig:
    """JWT Authentication configuration."""
    secret_key: str = os.getenv("JWT_SECRET_KEY", "soc-analyst-dev-secret-change-in-production")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
    # Default admin user (for development only)
    default_username: str = os.getenv("ADMIN_USER", "admin")
    default_password: str = os.getenv("ADMIN_PASS", "socadmin2026")


@dataclass
class CollectorConfig:
    """Alert collector polling configuration."""
    poll_interval_seconds: int = int(os.getenv("POLL_INTERVAL", "30"))
    batch_size: int = int(os.getenv("POLL_BATCH_SIZE", "100"))
    max_retries: int = int(os.getenv("POLL_MAX_RETRIES", "3"))
    retry_delay_seconds: int = int(os.getenv("POLL_RETRY_DELAY", "5"))
    enabled_connectors: list = field(default_factory=lambda: [
        "wazuh",
        "mock_guardduty",
        "okta",
        "mock_defender",
    ])


@dataclass
class LLMConfig:
    """LLM provider configuration for the Dual-LLM Analyst Pipeline."""
    provider: str = os.getenv("LLM_PROVIDER", "mock")
    model_name: str = os.getenv("LLM_MODEL", "gemini-2.0-flash")
    api_key: str = os.getenv("GEMINI_API_KEY", os.getenv("LLM_API_KEY", ""))
    base_url: str = os.getenv("LLM_BASE_URL", "")
    temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.1"))
    max_tokens: int = int(os.getenv("LLM_MAX_TOKENS", "2048"))


@dataclass
class AppConfig:
    """Top-level application configuration."""
    app_name: str = "HallucinatingCrusaders"
    version: str = "0.1.0"
    debug: bool = os.getenv("DEBUG", "true").lower() == "true"
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    host: str = os.getenv("APP_HOST", "0.0.0.0")
    port: int = int(os.getenv("APP_PORT", "8080"))

    wazuh: WazuhConfig = field(default_factory=WazuhConfig)
    indexer: IndexerConfig = field(default_factory=IndexerConfig)
    postgres: PostgresConfig = field(default_factory=PostgresConfig)
    chroma: ChromaConfig = field(default_factory=ChromaConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    okta: OktaConfig = field(default_factory=OktaConfig)


# Singleton
settings = AppConfig()
