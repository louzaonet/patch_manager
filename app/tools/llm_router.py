"""
LLM Router: creates and caches one LangChain chat model per provider:model.

Each agent node asks for a model by task name ("classify_intent",
"generate_briefing", "handle_question"). The router resolves:

    1. LLM_NODE_<TASK>   (per-node override)
    2. LLM_DEFAULT

If a per-node model cannot be created (missing key, unknown provider), the
router logs it and falls back to LLM_DEFAULT. Runtime failures (server down,
timeout) are handled by the nodes, which degrade to deterministic output.
"""

from __future__ import annotations

import re
from typing import Any

import structlog
from langchain_core.language_models.chat_models import BaseChatModel

from app.config import LLM_NODES, get_settings

logger = structlog.get_logger()

PROVIDERS = ("openai", "anthropic", "ollama", "openai_compat", "openrouter")
PROVIDER_ALIASES = {"local": "openai_compat", "llamaswap": "openai_compat", "llama-swap": "openai_compat"}

_llm_cache: dict[str, BaseChatModel] = {}

# Reasoning models served through OpenAI-compatible APIs sometimes inline their
# chain of thought in the content. Strip it before parsing or showing it.
_THINK_RE = re.compile(r"<(think|thinking|reasoning)>.*?</\1>\s*", re.DOTALL | re.IGNORECASE)


def parse_model_spec(spec: str) -> tuple[str, str]:
    """
    Split "provider:model" into (provider, model).

    Only the first colon separates the provider, so Ollama tags survive:
        "ollama:qwen3.5:9b"                     -> ("ollama", "qwen3.5:9b")
        "openrouter:anthropic/claude-haiku-5.5" -> ("openrouter", "anthropic/claude-haiku-5.5")
        "gpt-5-mini"                            -> ("openai", "gpt-5-mini")
    """
    spec = spec.strip()
    if ":" in spec:
        head, tail = spec.split(":", 1)
        provider = PROVIDER_ALIASES.get(head.lower().strip(), head.lower().strip())
        if provider in PROVIDERS:
            return provider, tail.strip()
    return "openai", spec


def _compat_chat_openai_class():
    """
    ChatOpenAI subclass for third-party OpenAI-compatible endpoints.

    Current langchain-openai sends `max_completion_tokens`. OpenRouter and
    llama.cpp document `max_tokens`, so translate it back for those servers.
    """
    from langchain_openai import ChatOpenAI

    class CompatChatOpenAI(ChatOpenAI):
        def _get_request_payload(self, input_: Any, *, stop: Any = None, **kwargs: Any) -> dict:
            payload = super()._get_request_payload(input_, stop=stop, **kwargs)
            if "max_completion_tokens" in payload:
                payload["max_tokens"] = payload.pop("max_completion_tokens")
            return payload

    return CompatChatOpenAI


def _create_llm(provider: str, model: str) -> BaseChatModel:
    """Instantiate a chat model. Imports are lazy so unused providers can be absent."""
    s = get_settings()
    common: dict[str, Any] = {"max_retries": s.llm_max_retries}
    if s.llm_temperature is not None:
        common["temperature"] = s.llm_temperature

    if provider == "ollama":
        from langchain_ollama import ChatOllama

        kwargs: dict[str, Any] = {
            "model": model,
            "base_url": s.ollama_base_url,
            "num_ctx": s.ollama_num_ctx,
            "num_predict": s.llm_max_tokens,
            "client_kwargs": {"timeout": s.llm_timeout},
        }
        if s.llm_temperature is not None:
            kwargs["temperature"] = s.llm_temperature
        if s.ollama_reasoning is not None:
            kwargs["reasoning"] = s.ollama_reasoning
        logger.info("llm_init", provider=provider, model=model, base_url=s.ollama_base_url)
        return ChatOllama(**kwargs)

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        if not s.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is required for provider 'anthropic'")
        logger.info("llm_init", provider=provider, model=model)
        return ChatAnthropic(
            model=model,
            api_key=s.anthropic_api_key,
            max_tokens=s.llm_max_tokens,
            default_request_timeout=s.llm_timeout,
            **common,
        )

    if provider == "openai":
        from langchain_openai import ChatOpenAI

        if not s.openai_api_key:
            raise ValueError("OPENAI_API_KEY is required for provider 'openai'")
        logger.info("llm_init", provider=provider, model=model)
        return ChatOpenAI(
            model=model,
            api_key=s.openai_api_key,
            base_url=s.openai_base_url,
            max_tokens=s.llm_max_tokens,
            timeout=s.llm_timeout,
            **common,
        )

    if provider == "openai_compat":
        cls = _compat_chat_openai_class()
        logger.info("llm_init", provider=provider, model=model, base_url=s.openai_compat_base_url)
        return cls(
            model=model,
            api_key=s.openai_compat_api_key or "not-needed",
            base_url=s.openai_compat_base_url,
            max_tokens=s.llm_max_tokens,
            timeout=s.llm_timeout,
            extra_body=s.openai_compat_extra_body or None,
            use_responses_api=False,
            **common,
        )

    if provider == "openrouter":
        if not s.openrouter_api_key:
            raise ValueError("OPENROUTER_API_KEY is required for provider 'openrouter'")
        cls = _compat_chat_openai_class()
        headers = {"X-Title": s.openrouter_app_title}
        if s.openrouter_referer:
            headers["HTTP-Referer"] = s.openrouter_referer
        logger.info("llm_init", provider=provider, model=model)
        return cls(
            model=model,
            api_key=s.openrouter_api_key,
            base_url=s.openrouter_base_url,
            max_tokens=s.llm_max_tokens,
            timeout=s.llm_timeout,
            default_headers=headers,
            extra_body=s.openrouter_extra_body or None,
            use_responses_api=False,
            **common,
        )

    raise ValueError(f"Unknown LLM provider '{provider}'. Supported: {', '.join(PROVIDERS)}")


def _get_or_create(spec: str) -> BaseChatModel:
    provider, model = parse_model_spec(spec)
    key = f"{provider}:{model}"
    if key not in _llm_cache:
        _llm_cache[key] = _create_llm(provider, model)
    return _llm_cache[key]


def resolve_spec(task: str) -> str:
    """The provider:model string that `task` will use."""
    s = get_settings()
    return s.llm_node_config.get(task) or s.llm_default


def get_llm(task: str) -> BaseChatModel:
    """Return the chat model configured for an agent task (cached)."""
    s = get_settings()
    spec = resolve_spec(task)
    if not spec:
        raise ValueError("LLM_DEFAULT is not set")
    try:
        return _get_or_create(spec)
    except Exception as exc:
        logger.error("llm_init_failed", task=task, spec=spec, error=str(exc))
        if spec != s.llm_default and s.llm_default:
            logger.warning("llm_fallback_to_default", task=task, default=s.llm_default)
            return _get_or_create(s.llm_default)
        raise


def message_text(response: Any) -> str:
    """
    Plain text from a chat model response.

    Handles string content, list-of-blocks content (Anthropic, some reasoning
    models) and inline <think> blocks.
    """
    content = getattr(response, "content", response)
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
        content = "".join(parts)
    return _THINK_RE.sub("", str(content or "")).strip()


def get_active_models() -> dict[str, str]:
    """Model assigned to each node, for /api/health and debugging."""
    s = get_settings()
    result = {"default": s.llm_default or "(not set)"}
    for task in LLM_NODES:
        override = s.llm_node_config.get(task)
        result[task] = override if override else f"(default) {s.llm_default}"
    return result


def clear_cache() -> None:
    """Drop cached model instances (tests, config reload)."""
    _llm_cache.clear()
