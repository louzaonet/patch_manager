"""
Configuration: typed settings loaded from environment variables and,
optionally, from an env file (config/ai.env by default).

LLM routing: every agent node can use its own model. Each value has the form
"provider:model". Supported providers:

    openai          OpenAI API                     openai:gpt-5-mini
    anthropic       Anthropic API                  anthropic:claude-haiku-5-5
    ollama          Ollama server                  ollama:qwen3.5:9b
    openai_compat   any OpenAI-compatible server   openai_compat:gpt-oss-20b
                    (llama-swap, llama.cpp, vLLM)
    openrouter      OpenRouter                     openrouter:anthropic/claude-haiku-5.5

"local" and "llamaswap" are accepted as aliases of "openai_compat".
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Nodes that call an LLM. Kept here so config, router and /api/health agree.
LLM_NODES: tuple[str, ...] = ("classify_intent", "generate_briefing", "handle_question")


def _env_file() -> str | None:
    """Env file to read. PATCH_AI_ENV_FILE overrides; empty string disables it."""
    value = os.environ.get("PATCH_AI_ENV_FILE", "config/ai.env")
    return value or None


class Settings(BaseSettings):
    """Application settings. Field aliases are the environment variable names."""

    model_config = SettingsConfigDict(
        env_file=_env_file(),
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # ─── LLM: default model and per-node overrides ──────────────────────
    llm_default: str = Field(default="", alias="LLM_DEFAULT")
    llm_node_classify_intent: str | None = Field(default=None, alias="LLM_NODE_CLASSIFY_INTENT")
    llm_node_generate_briefing: str | None = Field(default=None, alias="LLM_NODE_GENERATE_BRIEFING")
    llm_node_handle_question: str | None = Field(default=None, alias="LLM_NODE_HANDLE_QUESTION")

    # None = provider default. Leave unset for reasoning models: several of
    # them reject a custom temperature.
    llm_temperature: float | None = Field(default=None, alias="LLM_TEMPERATURE")
    llm_max_tokens: int = Field(default=2048, alias="LLM_MAX_TOKENS")
    llm_timeout: float = Field(default=90.0, alias="LLM_TIMEOUT")
    llm_max_retries: int = Field(default=1, alias="LLM_MAX_RETRIES")

    # ─── Provider: OpenAI ───────────────────────────────────────────────
    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    openai_base_url: str | None = Field(default=None, alias="OPENAI_BASE_URL")

    # ─── Provider: Anthropic ────────────────────────────────────────────
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")

    # ─── Provider: Ollama ───────────────────────────────────────────────
    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_num_ctx: int = Field(default=8192, alias="OLLAMA_NUM_CTX")
    # None = model default; false disables "thinking" on reasoning models.
    ollama_reasoning: bool | None = Field(default=None, alias="OLLAMA_REASONING")

    # ─── Provider: OpenAI-compatible (llama-swap / llama.cpp / vLLM) ────
    openai_compat_base_url: str = Field(
        default="http://localhost:8080/v1", alias="OPENAI_COMPAT_BASE_URL"
    )
    openai_compat_api_key: str = Field(default="not-needed", alias="OPENAI_COMPAT_API_KEY")
    # JSON merged into every request body, e.g.
    # {"chat_template_kwargs": {"reasoning_effort": "low"}}
    openai_compat_extra_body: dict[str, Any] = Field(
        default_factory=dict, alias="OPENAI_COMPAT_EXTRA_BODY"
    )

    # ─── Provider: OpenRouter ───────────────────────────────────────────
    openrouter_api_key: str | None = Field(default=None, alias="OPENROUTER_API_KEY")
    openrouter_base_url: str = Field(
        default="https://openrouter.ai/api/v1", alias="OPENROUTER_BASE_URL"
    )
    # e.g. {"provider": {"data_collection": "deny"}, "reasoning": {"effort": "low"}}
    openrouter_extra_body: dict[str, Any] = Field(
        default_factory=dict, alias="OPENROUTER_EXTRA_BODY"
    )
    openrouter_app_title: str = Field(default="Patch Manager AI", alias="OPENROUTER_APP_TITLE")
    openrouter_referer: str | None = Field(default=None, alias="OPENROUTER_REFERER")

    # ─── Web app and authentication ─────────────────────────────────────
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")  # noqa: S104 (container default)
    app_port: int = Field(default=8501, alias="APP_PORT")
    app_auth_user: str = Field(default="admin", alias="APP_AUTH_USER")
    app_auth_password: str = Field(default="", alias="APP_AUTH_PASSWORD")
    # Optional bearer token for scripts (Authorization: Bearer <token>).
    app_api_token: str = Field(default="", alias="APP_API_TOKEN")
    # Only for local development. Never enable on a reachable host.
    app_auth_disabled: bool = Field(default=False, alias="APP_AUTH_DISABLED")
    app_enable_docs: bool = Field(default=False, alias="APP_ENABLE_DOCS")
    # Public URL of the dashboard, used for links in Slack/Teams messages.
    public_base_url: str = Field(default="", alias="PUBLIC_BASE_URL")

    # ─── Semaphore ──────────────────────────────────────────────────────
    semaphore_url: str = Field(default="http://localhost:3000", alias="SEMAPHORE_URL")
    semaphore_api_token: str = Field(default="", alias="SEMAPHORE_API_TOKEN")
    semaphore_project_id: int | None = Field(default=None, alias="SEMAPHORE_PROJECT_ID")
    semaphore_template_apply: str = Field(default="Apply Patches", alias="SEMAPHORE_TEMPLATE_APPLY")
    semaphore_template_check: str = Field(default="Check Updates", alias="SEMAPHORE_TEMPLATE_CHECK")
    semaphore_timeout: float = Field(default=30.0, alias="SEMAPHORE_TIMEOUT")

    # ─── Inventory and host reports ─────────────────────────────────────
    inventory_path: str = Field(
        default="/opt/patch-manager/inventory/hosts.yml", alias="INVENTORY_PATH"
    )
    # Directory where check_updates.yml writes one JSON file per host.
    reports_path: str = Field(default="/var/lib/patch-manager/reports", alias="REPORTS_PATH")
    report_max_age_hours: float = Field(default=48.0, alias="REPORT_MAX_AGE_HOURS")

    # ─── CVE enrichment ─────────────────────────────────────────────────
    nvd_enabled: bool = Field(default=True, alias="NVD_ENABLED")
    nvd_api_key: str | None = Field(default=None, alias="NVD_API_KEY")
    nvd_api_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0", alias="NVD_API_URL"
    )
    # Max CVE IDs looked up per run, and a wall-clock budget for those lookups.
    nvd_lookup_limit: int = Field(default=25, alias="NVD_LOOKUP_LIMIT")
    nvd_lookup_budget_seconds: float = Field(default=45.0, alias="NVD_LOOKUP_BUDGET_SECONDS")
    # Recent critical CVEs per OS family, shown as context only (not matched to hosts).
    nvd_context_enabled: bool = Field(default=True, alias="NVD_CONTEXT_ENABLED")
    nvd_context_days: int = Field(default=14, alias="NVD_CONTEXT_DAYS")
    kev_enabled: bool = Field(default=True, alias="KEV_ENABLED")
    kev_url: str = Field(
        default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        alias="KEV_URL",
    )

    # ─── Patch plans (human approval step) ──────────────────────────────
    plan_ttl_minutes: int = Field(default=30, alias="PLAN_TTL_MINUTES")

    # ─── Slack ──────────────────────────────────────────────────────────
    slack_enabled: bool = Field(default=False, alias="SLACK_ENABLED")
    slack_bot_token: str | None = Field(default=None, alias="SLACK_BOT_TOKEN")
    slack_signing_secret: str | None = Field(default=None, alias="SLACK_SIGNING_SECRET")
    slack_default_channel: str = Field(default="#patch-management", alias="SLACK_DEFAULT_CHANNEL")
    # Comma-separated Slack user IDs (U0123...) allowed to approve plans.
    slack_approver_ids: str = Field(default="", alias="SLACK_APPROVER_IDS")

    # ─── Microsoft Teams ────────────────────────────────────────────────
    teams_enabled: bool = Field(default=False, alias="TEAMS_ENABLED")
    # Workflows webhook URL ("When a Teams webhook request is received").
    teams_webhook_url: str | None = Field(default=None, alias="TEAMS_WEBHOOK_URL")
    # Security token shown when creating a Teams Outgoing Webhook (base64).
    teams_outgoing_secret: str | None = Field(default=None, alias="TEAMS_OUTGOING_SECRET")

    # ─── Logging ────────────────────────────────────────────────────────
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    @field_validator("openai_compat_extra_body", "openrouter_extra_body", mode="before")
    @classmethod
    def _parse_json_dict(cls, value: Any) -> Any:
        """Accept JSON strings (from env files) as well as dicts."""
        if value is None or value == "":
            return {}
        if isinstance(value, str):
            parsed = json.loads(value)
            if not isinstance(parsed, dict):
                raise ValueError("expected a JSON object")
            return parsed
        return value

    @field_validator(
        "llm_node_classify_intent",
        "llm_node_generate_briefing",
        "llm_node_handle_question",
        "semaphore_project_id",
        "ollama_reasoning",
        "llm_temperature",
        mode="before",
    )
    @classmethod
    def _empty_to_none(cls, value: Any) -> Any:
        """Treat empty env values (KEY=) as unset."""
        return None if value == "" else value

    @property
    def llm_node_config(self) -> dict[str, str]:
        """Node name -> provider:model, only for nodes with an explicit override."""
        mapping = {
            "classify_intent": self.llm_node_classify_intent,
            "generate_briefing": self.llm_node_generate_briefing,
            "handle_question": self.llm_node_handle_question,
        }
        return {node: spec for node, spec in mapping.items() if spec}

    @property
    def slack_approvers(self) -> set[str]:
        return {u.strip() for u in self.slack_approver_ids.split(",") if u.strip()}

    def startup_problems(self) -> list[str]:
        """Configuration errors that should stop the service from starting."""
        problems: list[str] = []
        if not self.llm_default:
            problems.append("LLM_DEFAULT is not set (format provider:model).")
        if not self.app_auth_disabled:
            weak = {"change_me", "changeme", "change-me", "admin", "password"}
            if not self.app_auth_password:
                problems.append(
                    "APP_AUTH_PASSWORD is not set. Set it, or APP_AUTH_DISABLED=true for local dev only."
                )
            elif self.app_auth_password.lower() in weak or len(self.app_auth_password) < 12:
                problems.append("APP_AUTH_PASSWORD is a placeholder or shorter than 12 characters.")
        if self.slack_enabled and not self.slack_signing_secret:
            problems.append("SLACK_ENABLED=true requires SLACK_SIGNING_SECRET.")
        if self.teams_enabled and not (self.teams_webhook_url or self.teams_outgoing_secret):
            problems.append(
                "TEAMS_ENABLED=true requires TEAMS_WEBHOOK_URL and/or TEAMS_OUTGOING_SECRET."
            )
        return problems


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings instance. Tests call get_settings.cache_clear()."""
    return Settings()
