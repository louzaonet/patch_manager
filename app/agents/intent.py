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
    "analyze_risk", "check_updates", "apply_patches", "generate_report", "status", "ask_question",
    "package_query", "capability",
]

# A package name or a glob. The same pattern is enforced again by
# package_query.yml before the name reaches a host.
PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._*-]{0,99}$")
# Same rule as the manifest names in app/services/capabilities.py.
CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
MAX_INTENT_PARAMS = 20


class Intent(BaseModel):
    action: ActionName = "ask_question"
    target_hosts: str | None = None
    security_only: bool = False
    dry_run: bool = False
    no_reboot: bool = False
    package: str | None = None
    live: bool = False
    capability: str | None = None
    params: dict[str, bool | int | float | str] | None = None
    run: bool = False

    @field_validator("capability", mode="before")
    @classmethod
    def _valid_capability(cls, value: Any) -> Any:
        """Only a plausible manifest name; whether it exists is checked by the node."""
        if value is None:
            return None
        value = str(value).strip().lower()
        return value if CAPABILITY_RE.match(value) else None

    @field_validator("params", mode="before")
    @classmethod
    def _plain_params(cls, value: Any) -> Any:
        """Scalars only, bounded. The capability's manifest validates the values."""
        if not isinstance(value, dict):
            return None
        clean: dict[str, Any] = {}
        for key, val in list(value.items())[:MAX_INTENT_PARAMS]:
            if isinstance(val, bool | int | float) or (isinstance(val, str) and len(val) <= 200):
                clean[str(key)[:64]] = val
        return clean or None

    @field_validator("package", mode="before")
    @classmethod
    def _valid_package(cls, value: Any) -> Any:
        """Anything that is not a plain package name is dropped, not passed on."""
        if value is None:
            return None
        value = str(value).strip()
        return value if PACKAGE_RE.match(value) else None

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
- package_query: which version of a package is installed on the hosts, or whether it is installed
- capability: use one of the extra capabilities listed below (run it, or ask about its results)
- ask_question: anything else (how-to, explanations)

Extra capabilities (choose "capability" only for these, by exact name):
{capabilities}

Known inventory groups and hosts: {known}

Also extract:
- target_hosts: a group or hostname from the list above, or null for all hosts
- security_only, dry_run, no_reboot: true only if the user asks for it
- package: for package_query, the package name as the OS names it (e.g. "nginx", "openssl",
  "openssh-server"); "*" is allowed as a wildcard. null otherwise
- live: true only if the user wants current data checked on the hosts now ("right now",
  "live", "ahora", "actualizado"), otherwise false
- capability: for action capability, the capability name from the list. null otherwise
- params: for action capability, an object with only the params the user asked for. null otherwise
- run: for action capability, true ONLY if the user explicitly asks to run, launch, execute or
  refresh it ("run the docker check", "lanza el docker check", "check again now"). A question about
  its results ("are there new images?", "¿hay imágenes nuevas?", "how are the widgets?") is false

Reply with one JSON object and nothing else, for example:
{{"action": "check_updates", "target_hosts": null,
 "security_only": false, "dry_run": false, "no_reboot": false, "package": null, "live": false,
 "capability": null, "params": null, "run": false}}

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


# First match wins. Explicit action verbs come first; read-only questions
# ("list pending patches", "which hosts have updates available") come before
# the bare word "patch", which alone used to turn a question into a plan.
# "which version of nginx", "qué versión de nginx tenemos", "is curl installed"
_PACKAGE_PATTERNS = [
    re.compile(r"\bversi(?:on|ón|ones|ons)\s+(?:of|de|del)\s+(?:the\s+|el\s+|la\s+|los\s+)?"
               r"(?:package\s+|paquete\s+)?([A-Za-z0-9][A-Za-z0-9+._*-]*)"),
    re.compile(r"\b(?:is|está|esta)\s+([A-Za-z0-9][A-Za-z0-9+._*-]*)\s+(?:installed|instalad[oa])"),
    re.compile(r"\b(?:which|what|qué|que)\s+hosts?\s+(?:have|has|tienen?)\s+([A-Za-z0-9][A-Za-z0-9+._*-]*)"
               r"\s+(?:installed|instalad[oa])"),
]
# "nginx version": the word before "version", unless it is a filler word.
_NAME_BEFORE_VERSION = re.compile(r"\b([A-Za-z0-9][A-Za-z0-9+._-]*)\s+(?:version|versión)\b")
_NOT_PACKAGES = {"what", "which", "the", "latest", "current", "new", "this", "that", "que", "qué",
                 "la", "el", "una", "a", "os", "same", "misma", "nueva", "última", "ultima"}
_LIVE_RE = re.compile(r"\b(right now|now|live|current(?:ly)?|fresh|ahora|actualizad[oa]s?|en vivo|"
                      r"en este momento|al momento)\b")


def package_from_text(message: str) -> str | None:
    """Package name asked about in plain text, if any."""
    for pattern in _PACKAGE_PATTERNS:
        m = pattern.search(message)
        if m and PACKAGE_RE.match(m.group(1)):
            return m.group(1).rstrip(".")
    m = _NAME_BEFORE_VERSION.search(message)
    if m and m.group(1).lower() not in _NOT_PACKAGES and PACKAGE_RE.match(m.group(1)):
        return m.group(1)
    return None


def wants_live(message: str) -> bool:
    """The user asks for data checked on the hosts now, not the last inventory."""
    return bool(_LIVE_RE.search(message.lower()))


_KEYWORDS: list[tuple[str, str]] = [
    (r"\b(status|progress|running|last (run|job|task))\b", "status"),
    (r"\b(apply|install|upgrade|deploy)\b|\bplan\b.*\b(patch|update)", "apply_patches"),
    (r"\b(risk|vulnerab|cve|exposure|exploit)", "analyze_risk"),
    (r"\b(report|summary|summari[sz]e|briefing)\b", "generate_report"),
    (r"\b(pending|available|outdated|outstanding|missing|check|list|show|which|how many)\b"
     r".*\b(updates?|patch(?:es)?)\b"
     r"|\b(updates?|patch(?:es)?)\b.*\b(pending|available|outstanding)\b", "check_updates"),
    (r"\bpatch(?:es|ing)?\b", "apply_patches"),
]


_APPLY_RE = re.compile(_KEYWORDS[1][0])
_RUN_RE = re.compile(r"\b(run|launch|execute|start|trigger|now|lanza|lanzar|ejecuta|ejecutar|arranca|"
                     r"haz|ahora)\b")


def capability_from_text(low: str, capabilities: list[tuple[str, list[str]]]) -> str | None:
    """Capability whose name or one of its keywords appears in the (lowercase) message."""
    for name, keywords in capabilities:
        for word in [name, name.replace("_", " "), *keywords]:
            if re.search(rf"(?<![\w-]){re.escape(word)}(?![\w-])", low):
                return name
    return None


def keyword_intent(
    message: str, known_names: set[str], capabilities: list[tuple[str, list[str]]] | None = None
) -> Intent:
    """Deterministic fallback used when the LLM is unavailable."""
    low = message.lower()
    action = "ask_question"
    package = package_from_text(low)
    capability = None
    if package:
        action = "package_query"
    else:
        # An explicit patching verb wins over a capability keyword: "apply
        # patches on the docker hosts" is about patching.
        if not _APPLY_RE.search(low):
            capability = capability_from_text(low, capabilities or [])
        if capability:
            action = "capability"
        else:
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
        package=package,
        live=bool(package) and wants_live(low),
        capability=capability,
        run=bool(capability) and bool(_RUN_RE.search(low)),
    )
