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

# Same vocabulary as community.general.mail, so one set of values fits both.
SMTP_SECURE_MODES: tuple[str, ...] = ("starttls", "always", "never", "try")


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
    # Live package queries ("which version of nginx do we have, right now?").
    semaphore_template_packages: str = Field(default="Package Query", alias="SEMAPHORE_TEMPLATE_PACKAGES")
    # How long a live query may take before the answer falls back to the inventory.
    package_query_timeout: float = Field(default=180.0, alias="PACKAGE_QUERY_TIMEOUT")
    # Longest a chat request waits for a Semaphore task (capabilities with
    # run.wait, live package queries). Keep it under the proxy's read timeout
    # (300 s in the shipped nginx), or the browser gets a 504 while the task
    # goes on. A longer run.timeout in a manifest is cut to this.
    request_wait_max: float = Field(default=270.0, ge=10, alias="REQUEST_WAIT_MAX")
    semaphore_timeout: float = Field(default=30.0, alias="SEMAPHORE_TIMEOUT")

    # ─── Inventory and host reports ─────────────────────────────────────
    inventory_path: str = Field(
        default="/opt/patch-manager/inventory/hosts.yml", alias="INVENTORY_PATH"
    )
    # Directory where check_updates.yml writes one JSON file per host.
    reports_path: str = Field(default="/var/lib/patch-manager/reports", alias="REPORTS_PATH")
    report_max_age_hours: float = Field(default=48.0, alias="REPORT_MAX_AGE_HOURS")

    # ─── Capabilities (playbooks the AI can use, declared by manifests) ─
    # Directory of YAML manifests; see config/capabilities.d.example/.
    # Missing directory = no capabilities.
    capabilities_path: str = Field(
        default="/etc/patch-manager/capabilities.d", alias="CAPABILITIES_PATH"
    )

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
    # Comma-separated Slack user IDs allowed to use /patch at all (read the
    # fleet, run read-only checks, ask for plans). Empty: anyone in the
    # workspace who can run the command. Approvers are always allowed.
    slack_user_ids: str = Field(default="", alias="SLACK_USER_IDS")

    # ─── Microsoft Teams ────────────────────────────────────────────────
    teams_enabled: bool = Field(default=False, alias="TEAMS_ENABLED")
    # Workflows webhook URL ("When a Teams webhook request is received").
    teams_webhook_url: str | None = Field(default=None, alias="TEAMS_WEBHOOK_URL")
    # Security token shown when creating a Teams Outgoing Webhook (base64).
    teams_outgoing_secret: str | None = Field(default=None, alias="TEAMS_OUTGOING_SECRET")
    # Comma-separated Entra ID object IDs (from.aadObjectId) allowed to talk
    # to the bot. Empty: anyone who can mention it in the team.
    teams_user_ids: str = Field(default="", alias="TEAMS_USER_IDS")

    # ─── Scheduled analysis and email ───────────────────────────────────
    # Cron expression (minute hour day month weekday) evaluated in
    # AUTO_ANALYSIS_TZ. Empty = no scheduled analysis. Put it a few minutes
    # after Semaphore's Check Updates schedule.
    auto_analysis_cron: str = Field(default="", alias="AUTO_ANALYSIS_CRON")
    auto_analysis_tz: str = Field(default="UTC", alias="AUTO_ANALYSIS_TZ")
    # Ansible limit for the scheduled analysis; empty = all hosts.
    auto_analysis_target: str = Field(default="", alias="AUTO_ANALYSIS_TARGET")
    # The subject is flagged when the newest host report is older than this:
    # Check Updates probably did not run before the analysis.
    auto_analysis_fresh_hours: float = Field(default=2.0, alias="AUTO_ANALYSIS_FRESH_HOURS")

    # SMTP used by the AI service itself (not by Semaphore). SMTP_SECURE takes
    # the same values as the playbooks: starttls | always (TLS on connect) |
    # never | try (STARTTLS if the server offers it).
    smtp_host: str = Field(default="", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_secure: str = Field(default="starttls", alias="SMTP_SECURE")
    smtp_user: str = Field(default="", alias="SMTP_USER")
    smtp_password: str = Field(default="", alias="SMTP_PASSWORD")
    smtp_timeout: float = Field(default=30.0, alias="SMTP_TIMEOUT")
    email_from: str = Field(default="", alias="EMAIL_FROM")
    # Comma-separated recipients.
    email_to: str = Field(default="", alias="EMAIL_TO")
    email_subject_prefix: str = Field(default="[PATCH-AI]", alias="EMAIL_SUBJECT_PREFIX")

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
    def email_recipients(self) -> list[str]:
        return [a.strip() for a in self.email_to.split(",") if a.strip()]

    @property
    def email_configured(self) -> bool:
        return bool(self.smtp_host and self.email_from and self.email_recipients)

    def _email_problems(self) -> list[str]:
        problems: list[str] = []
        if self.smtp_secure.lower() not in SMTP_SECURE_MODES:
            problems.append(f"SMTP_SECURE must be one of {', '.join(SMTP_SECURE_MODES)}.")
        addresses = [self.email_from, *self.email_recipients] if self.email_from else self.email_recipients
        for address in addresses:
            # Not a full RFC 5322 check: catches typos and header injection.
            if "@" not in address or any(c in address for c in "\r\n,;"):
                problems.append(f"'{address}' is not a valid email address (EMAIL_FROM / EMAIL_TO).")
        return problems

    def _schedule_problems(self) -> list[str]:
        from zoneinfo import ZoneInfoNotFoundError

        from app.services.cron import CronSchedule, resolve_tz

        problems: list[str] = []
        try:
            tz = resolve_tz(self.auto_analysis_tz)
        except (ZoneInfoNotFoundError, ValueError):
            problems.append(
                f"AUTO_ANALYSIS_TZ '{self.auto_analysis_tz}' is not a known time zone "
                "(zones other than UTC need the system tzdata package or pip's tzdata)."
            )
            tz = None
        try:
            schedule = CronSchedule.parse(self.auto_analysis_cron)
            if tz is not None:
                from datetime import datetime

                schedule.next_after(datetime.now(tz), tz)
        except ValueError as exc:
            problems.append(f"AUTO_ANALYSIS_CRON: {exc}")
        if not self.email_configured:
            problems.append("AUTO_ANALYSIS_CRON needs SMTP_HOST, EMAIL_FROM and EMAIL_TO.")
        return problems

    @property
    def slack_approvers(self) -> set[str]:
        return {u.strip() for u in self.slack_approver_ids.split(",") if u.strip()}

    @property
    def slack_users(self) -> set[str]:
        """Users allowed to use /patch; empty means everyone."""
        users = {u.strip() for u in self.slack_user_ids.split(",") if u.strip()}
        return users | self.slack_approvers if users else set()

    @property
    def teams_users(self) -> set[str]:
        """Entra ID object IDs allowed to use the bot; empty means everyone."""
        return {u.strip().lower() for u in self.teams_user_ids.split(",") if u.strip()}

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
        if self.smtp_host or self.email_from or self.email_to:
            problems.extend(self._email_problems())
        if self.auto_analysis_cron.strip():
            problems.extend(self._schedule_problems())
        return problems


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings instance. Tests call get_settings.cache_clear()."""
    return Settings()
