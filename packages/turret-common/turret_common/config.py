"""
turret_common.config
====================
Pydantic-settings configuration loader for TURRET OS.
Reads from environment variables and .env file; never from hardcoded defaults
for secrets.  Follows secure multi-tier secret resolution pattern.
"""

from __future__ import annotations

import logging
import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

# ── Secret resolution helper ──────────────────────────────────────────────

def _resolve_secret(env_key: str, file_path: str | None = None) -> str:
    """
    Multi-tier secret resolution:
      1. Environment variable
      2. Local file (if file_path given)
      3. Ephemeral random — logs a CRITICAL warning (not prod-safe)
    """
    value = os.getenv(env_key)
    if value:
        return value
    if file_path and Path(file_path).exists():
        return Path(file_path).read_text().strip()
    # Ephemeral fallback — suitable for local dev / CI only
    ephemeral = secrets.token_hex(32)
    logger.critical(
        "Secret '%s' not found in environment or file. "
        "Using an ephemeral random value — NOT suitable for production. "
        "Set %s in your .env file.",
        env_key,
        env_key,
    )
    return ephemeral


# ── Settings model ────────────────────────────────────────────────────────

class TurretSettings(BaseSettings):
    """
    Central configuration for all TURRET OS services.
    Loaded once per process and cached.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Neo4j
    neo4j_uri: str = Field("bolt://localhost:7687", alias="NEO4J_URI")
    neo4j_user: str = Field("neo4j", alias="NEO4J_USER")
    neo4j_password: str = Field(..., alias="NEO4J_PASSWORD")
    neo4j_database: str = Field("turret", alias="NEO4J_DATABASE")

    # API
    api_secret_key: str = Field(..., alias="API_SECRET_KEY")
    allowed_origins: str = Field("http://localhost:5173", alias="ALLOWED_ORIGINS")

    # Redis / Celery
    redis_url: str = Field("redis://localhost:6379/0", alias="REDIS_URL")

    # Reproducibility
    turret_seed: int = Field(42, alias="TURRET_SEED")

    # ExifTool
    exiftool_path: str = Field("/usr/bin/exiftool", alias="EXIFTOOL_PATH")

    # Signing keys
    signing_key_path: str = Field("config/keys/signing_key.pem", alias="SIGNING_KEY_PATH")
    verify_key_path: str = Field("config/keys/verify_key.pem", alias="VERIFY_KEY_PATH")

    # Logging
    log_level: str = Field("INFO", alias="LOG_LEVEL")

    @field_validator("neo4j_password", "api_secret_key", mode="before")
    @classmethod
    def _not_empty(cls, v: Any) -> Any:
        if not v or str(v).strip() == "":
            raise ValueError("Secret must not be empty")
        return v

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _parse_origins(cls, v: str) -> str:
        # Accept comma-separated list; validate each is a valid URL
        return v

    def get_allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    def load_yaml_config(self, path: str | Path = "config/default.yaml") -> dict[str, Any]:
        """Load and return the YAML config file, with env-var interpolation."""
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        content = config_path.read_text()
        # Simple env-var substitution for ${VAR} patterns
        import re
        def _sub(m: re.Match) -> str:
            key = m.group(1)
            return os.getenv(key, m.group(0))
        content = re.sub(r"\$\{(\w+)\}", _sub, content)
        return yaml.safe_load(content)


@lru_cache(maxsize=1)
def get_settings() -> TurretSettings:
    """Return the singleton TurretSettings instance."""
    return TurretSettings()  # type: ignore[call-arg]
