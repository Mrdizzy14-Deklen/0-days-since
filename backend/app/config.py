"""Application settings loaded from environment variables / `.env`."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed runtime configuration. Every value can be overridden via env vars."""

    # .env.local (server-only, never synced) overrides .env; deploy/brev uses it to switch the
    # model endpoint without a redeploy.
    model_config = SettingsConfigDict(env_file=(".env", ".env.local"), env_file_encoding="utf-8",
                                      extra="ignore")

    # Database
    database_url: str = "postgresql+asyncpg://zeroday:zeroday@localhost:5432/zeroday"
    database_ssl: bool = False
    # Tiger Cloud signs server certificates with its own CA (ca.timescale.com), which public CA
    # bundles don't include. Point this at that CA certificate (PEM) to verify the server.
    database_ssl_root_cert: str = ""
    database_echo: bool = False
    enable_timescale: bool = True

    # GitHub App
    github_app_id: str = ""
    github_app_slug: str = "zeroday-score"
    github_app_private_key: str = ""
    github_app_private_key_path: str = ""
    github_webhook_secret: str = ""
    github_api_url: str = "https://api.github.com"

    # LLM (OpenAI-compatible endpoints)
    llm_base_url: str = "https://integrate.api.nvidia.com/v1"
    llm_api_key: str = ""
    llm_model: str = "nvidia/llama-3.1-nemotron-70b-instruct"
    llm_fallback_base_url: str = ""
    llm_fallback_api_key: str = ""
    llm_fallback_model: str = ""
    llm_timeout_seconds: float = 90.0
    llm_max_tokens: int = 4096
    llm_context_chars: int = Field(default=60_000, ge=4_000)

    # Nemotron agent: Pass 1 becomes a plan -> tool calls -> report loop over the code graph,
    # and confirmed vulnerabilities get an auto-fix that is re-scanned before a PR is opened.
    agent_enabled: bool = True
    # Optional faster model for the agent's investigation turns (same endpoint as LLM_MODEL),
    # e.g. nvidia/nemotron-3.5-lightning-30b-a3b. Empty = use LLM_MODEL everywhere.
    llm_agent_model: str = ""
    # Model "thinking" (hidden reasoning before each answer). On for the skeptic and fixer,
    # where judgement matters; off for the agent's tool-choosing turns, which are mechanical
    # and become several times faster. Only sent to OpenAI-compatible servers that support
    # chat_template_kwargs (NVIDIA NIM, vLLM).
    llm_thinking: bool = True
    llm_agent_thinking: bool = False
    agent_max_steps: int = Field(default=10, ge=2, le=30)
    agent_fix_enabled: bool = True
    # Opening fix PRs needs the App's Contents and Pull requests permissions set to write.
    agent_open_fix_prs: bool = False
    agent_max_fixes: int = Field(default=2, ge=0, le=10)

    # Scanner limits (guard against hostile / gigantic repositories)
    max_python_files: int = Field(default=5000, ge=1)
    max_file_bytes: int = Field(default=1_000_000, ge=1)
    blast_radius_hops: int = Field(default=2, ge=1, le=5)
    max_annotations: int = Field(default=150, ge=1)
    readability_neutral_threshold: float = 180.0  # craft push score (0-300) below this -> neutral
    graph_cache_size: int = Field(default=16, ge=0)

    # App
    frontend_origin: str = "http://localhost:3000"
    log_level: str = "INFO"
    # Shared secret the Next.js server sends as `Authorization: Bearer <token>` to the dashboard
    # API. Empty = open API (local development only).
    api_token: str = ""
    # Comma-separated team slugs anyone may view read-only, signed in or not (the demo team).
    public_teams: str = ""

    @property
    def public_team_slugs(self) -> frozenset[str]:
        return frozenset(t.strip() for t in self.public_teams.split(",") if t.strip())

    @property
    def llm_configured(self) -> bool:
        return bool(self.llm_api_key or self.llm_fallback_api_key)

    @property
    def github_private_key_pem(self) -> str:
        """Return the GitHub App private key PEM from inline env or file path."""
        if self.github_app_private_key:
            return self.github_app_private_key.replace("\\n", "\n")
        if self.github_app_private_key_path:
            return Path(self.github_app_private_key_path).expanduser().read_text()
        return ""


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide cached settings object."""
    return Settings()
