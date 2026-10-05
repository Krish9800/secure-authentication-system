"""Central configuration and security settings for the authentication service."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SecuritySettings(BaseSettings):
    """Application configuration with defensive cryptographic defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General Service
    APP_NAME: str = "Secure Authentication Service"
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    DATABASE_URL: str = "sqlite:///./secure_auth.db"

    # Cryptographic Parameters: Argon2id (RFC 9106 / OWASP recommendations)
    ARGON2_TIME_COST: int = Field(default=3, ge=1, description="Number of passes")
    ARGON2_MEMORY_COST: int = Field(
        default=65536, ge=1024, description="Memory size in KiB (64 MB)"
    )
    ARGON2_PARALLELISM: int = Field(default=4, ge=1, description="Number of parallel threads")
    ARGON2_HASH_LEN: int = Field(default=32, ge=16, description="Output hash length in bytes")
    ARGON2_SALT_LEN: int = Field(
        default=16, ge=16, description="Cryptographic salt length in bytes"
    )

    # Brute-Force & Lockout Controls
    MAX_FAILED_LOGIN_ATTEMPTS: int = Field(default=5, ge=1, description="Failures before lockout")
    LOCKOUT_BASE_DURATION_SECONDS: int = Field(
        default=300, ge=30, description="Base lockout duration"
    )
    MAX_LOCKOUT_DURATION_SECONDS: int = Field(
        default=86400, description="Max progressive lockout (24h)"
    )
    FAILED_ATTEMPTS_RESET_WINDOW_SECONDS: int = Field(
        default=900, description="Reset counter after 15m"
    )

    # Session Management
    SESSION_LIFETIME_HOURS: int = Field(default=24, ge=1, description="Sliding session duration")
    SESSION_TOKEN_BYTES: int = Field(default=32, ge=32, description="256-bit CSPRNG token length")

    # Rate Limiting (IP Level)
    RATE_LIMIT_GLOBAL_PER_MINUTE: int = Field(default=120, description="Max global requests per IP")
    RATE_LIMIT_AUTH_PER_MINUTE: int = Field(default=15, description="Max login/register per IP")

    # Multi-Factor Authentication (MFA / TOTP)
    TOTP_ISSUER_NAME: str = "CyberSecurityPortfolio"
    TOTP_WINDOW: int = Field(default=1, description="Acceptable time-step tolerance (±30s)")
    BACKUP_RECOVERY_CODES_COUNT: int = Field(default=10, description="Number of recovery codes")


settings = SecuritySettings()
