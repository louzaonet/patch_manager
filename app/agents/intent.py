"""
Intent parsing: turns the LLM's answer into a validated Intent, with a
keyword fallback when the model is unavailable or returns garbage.

Works with small local models: no tool calling or JSON mode required, just
"answer with a JSON object". Fenced blocks, prose around the JSON and
<think> sections are tolerated.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ValidationError, field_validator

ActionName = Literal[
    "analyze_risk", "check_updates", "apply_patches", "generate_report", "status", "ask_question"
]


class Intent(BaseModel):
    action: ActionName = "ask_question"
    target_hosts: str | None = None
    security_only: bool = False
    dry_run: bool = False
    no_reboot: bool = False

    @field_validator("target_hosts", mode="before")
    @classmethod
    def _blank_to_none(cls, value: Any) -> Any:
        if value is None:
            return None
        value = str(value).strip()
        return None if value.lower() in ("", "null", "none", "all", "all hosts") else value

    @field_validator("action", mode="before")
    @classmethod
    def _normalise_action(cls, value: Any) -> Any:
        return str(value or "ask_question").strip().lower().replace("-", "_").replace(" ", "_")


INTENT_PROMPT = """You classify requests for a patch management system that manages
Ubuntu, Rocky Linux, macOS and Windows hosts with Ansible.

Pick exactly one action:
- analyze_risk: assess vulnerabilities / risk of hosts
- check_updates: list pending updates
- apply_patches: install updates (the system will build a plan for human approval)
- generate_report: summary or report of current state
- status: status of running or recent patch jobs
- ask_question: anything else (how-to, explanations)

Known inventory groups and hosts: {known}

Also extract:
- target_hosts: a group or hostname from the list above, or null for all hosts
- security_only, dry_run, no_reboot: true only if the user asks for it

Reply with one JSON object and nothing else, for example:
{{"action": "check_updates", "target_hosts": null,
 "security_only": false, "dry_run": false, "no_reboot": false}}

User request:
<<<
{message}
>>>"""


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Find the first JSON object in `text` and decode it."""
    if not text:
        return None
    text = re.sub(r"<(think|thinking|reasoning)>.*?</\1>", "", text, flags=re.S | re.I)
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.S)
    candidates = [fenced.group(1)] if fenced else []
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[start : i + 1])
                    break
        start = text.find("{", start + 1)
    for candidate in candidates:
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def parse_intent(text: str) -> Intent | None:
    """Validated Intent from LLM output, or None if it can't be parsed."""
    obj = extract_json_object(text)
    if obj is None:
        return None
    # Some models nest the flags under "options".
    options = obj.get("options")
    if isinstance(options, dict):
        for key in ("security_only", "dry_run", "no_reboot"):
            obj.setdefault(key, options.get(key, False))
    try:
        return Intent.model_validate(obj)
    except ValidationError:
        return None


_KEYWORDS: list[tuple[str, str]] = [
    (r"\b(status|progress|running|last (run|job|task))\b", "status"),
    (r"\b(apply|install|patch(?:es)?(?! report| summary)|upgrade|deploy updates?)\b", "apply_patches"),
    (r"\b(risk|vulnerab|cve|exposure|exploit)", "analyze_risk"),
    (r"\b(report|summary|summari[sz]e|briefing)\b", "generate_report"),
    (r"\b(pending|available|outdated|check)\b.*\b(updates?|patch)", "check_updates"),
]


def keyword_intent(message: str, known_names: set[str]) -> Intent:
    """Deterministic fallback used when the LLM is unavailable."""
    low = message.lower()
    action = "ask_question"
    for pattern, name in _KEYWORDS:
        if re.search(pattern, low):
            action = name
            break
    target = next(
        (n for n in sorted(known_names, key=len, reverse=True)
         if re.search(rf"(?<![\w-]){re.escape(n.lower())}(?![\w-])", low)),
        None,
    )
    return Intent(
        action=action,
        target_hosts=target,
        security_only=bool(re.search(r"security[ -]only|only security|security patches", low)),
        dry_run=bool(re.search(r"dry[ -]?run|simulat", low)),
        no_reboot=bool(re.search(r"no[ -]reboot|without reboot|don'?t reboot|prevent reboot", low)),
    )
