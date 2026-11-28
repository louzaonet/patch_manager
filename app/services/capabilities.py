"""
Capabilities: playbooks the AI can use without code changes.

A capability is a YAML manifest in CAPABILITIES_PATH that tells the service
which Semaphore template to run, which extra vars the AI may set (and the
allowed values), which hosts it may target, whether it changes anything, and
where its per-host JSON reports are. Adding a capability is: write the
playbook, create the Semaphore template, drop a manifest, reload.

The manifest is the contract, and it is written by a person:

- The AI can only pick a loaded capability by name. It never chooses a
  template, a playbook or a report path.
- Extra vars are typed and validated here (bool, int range, enum, string with
  a pattern). Names starting with ansible_ and Ansible magic variables are
  refused: an ansible_* extra var can change the interpreter or the shell
  that runs on the hosts.
- risk: changes never runs straight away. It becomes a plan that a person
  approves, like patching.
- Reports are read only from REPORTS_PATH/<path with {host}>, with a size
  cap, and are passed to the model as data.
- Manifests are refused when the file or the directory can be written by
  group or others, when the file is a symlink, or when its owner is neither
  root nor the user running the service. The service can't write its own
  capabilities.

See config/capabilities.d.example/ for an example.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import structlog
import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

try:  # google-re2: matching time is linear in the input, whatever the pattern
    import re2 as _re2
except ImportError:  # pragma: no cover (it is in requirements.txt and the lock)
    _re2 = None

from app.config import get_settings

logger = structlog.get_logger()
audit = structlog.get_logger("audit")

CAP_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
PARAM_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
GROUP_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
KEYWORD_RE = re.compile(r"^[\w .+-]{2,40}$")
# {host} is the only placeholder; no "..", no absolute paths.
REPORT_PATH_RE = re.compile(r"^[A-Za-z0-9_.{}-]+(?:/[A-Za-z0-9_.{}-]+)*$")
_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")

MAX_MANIFESTS = 50
MAX_MANIFEST_BYTES = 64 * 1024
MAX_PARAMS = 20
MAX_STRING_PARAM = 200
# Ansible renders Jinja inside extra vars when the playbook uses them, on the
# controller: "{{ lookup('pipe', ...) }}" in a parameter would run there,
# whatever the playbook does with the value afterwards. Refused in every
# string parameter, whatever its pattern allows.
JINJA_MARKERS = ("{{", "{%", "{#")
# String parameter patterns are compiled with RE2 (google-re2), which matches
# in linear time: no pattern can hang the event loop. RE2 has no
# backreferences or lookarounds, so those patterns are refused at load time.
# This cheap check runs first anyway: a group with a quantifier inside,
# repeated without a bound ("(a+)+", "(\\w*)*", "([a-z]+){2,}") is a mistake
# whatever the engine.
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*(?:[+*]|\{\d*,\d*\})\)\s*(?:[+*]|\{\d+,\})")
# Without RE2 (a platform with no wheel) Python's re backtracks, and the check
# above is not enough: "(a|aa)+", "(a+){10}" and forty "a?" in a row also hang
# it. Then only simple patterns load: no repeated group with a quantifier or
# an alternation inside, and a handful of quantifiers in all.
_REPEATED_COMPLEX_GROUP = re.compile(
    r"\((?:[^()\\]|\\.)*(?:[+*?|]|\{\d*,?\d*\})(?:[^()\\]|\\.)*\)\s*(?:[+*?]|\{\d*,?\d*\})")
_QUANTIFIER = re.compile(r"(?<!\\)(?:[+*?]|\{\d*,?\d*\})")
_GROUP_PREFIX = re.compile(r"\(\?(?:[:=!]|<[=!]|P<\w+>)")
MAX_PATTERN = 200
MAX_QUANTIFIERS_WITHOUT_RE2 = 6


def _compile_pattern(pattern: str) -> Any:
    """The compiled pattern (RE2 when installed), or ValueError."""
    if len(pattern) > MAX_PATTERN or _NESTED_QUANTIFIER.search(pattern):
        raise ValueError("pattern too long, or with a repeated group that has its own quantifier "
                         "(like (a+)+): that can hang the service; use a bounded repeat")
    if _re2 is not None:
        options = _re2.Options()
        options.log_errors = False
        try:
            return _re2.compile(pattern, options)
        except _re2.error as exc:
            raise ValueError(f"invalid pattern for RE2 (no backreferences or lookarounds): {exc}") from exc
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid pattern: {exc}") from exc
    plain = _GROUP_PREFIX.sub("(", pattern)
    if _REPEATED_COMPLEX_GROUP.search(plain) or len(_QUANTIFIER.findall(plain)) > MAX_QUANTIFIERS_WITHOUT_RE2:
        raise ValueError("google-re2 is not installed: only simple patterns are accepted (no repeated "
                         f"group with a quantifier or | inside, at most {MAX_QUANTIFIERS_WITHOUT_RE2} "
                         "quantifiers); install google-re2 for the rest")
    return compiled

# Ansible variables that must never come from the AI as extra vars: they
# control connection, privilege escalation, interpreters and the play itself.
_RESERVED_VARS = {
    "hostvars", "groups", "group_names", "inventory_hostname", "inventory_hostname_short",
    "inventory_dir", "inventory_file", "play_hosts", "playbook_dir", "role_path", "role_name",
    "omit", "environment", "vars", "lookup", "query", "q", "item",
}


class CapabilityError(ValueError):
    """A capability request that can't be honoured (unknown name, bad value, bad scope)."""


# ─── Manifest schema ────────────────────────────────────────────────────


class ParamSpec(BaseModel):
    """One extra var the AI may set. Values are always checked here."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["bool", "int", "enum", "string"]
    description: str = Field(default="", max_length=300)
    values: list[str] | None = None  # enum
    pattern: str | None = None  # string: full match required
    min: int | None = None  # int
    max: int | None = None  # int
    default: bool | int | str | None = None  # sent when the AI gives no value
    required: bool = False  # no value and no default: refused before calling Semaphore
    _matcher: Any = PrivateAttr(default=None)  # compiled pattern (string)

    @model_validator(mode="after")
    def _consistent(self) -> ParamSpec:
        if self.type == "enum":
            if not self.values or not all(isinstance(v, str) and 0 < len(v) <= 100 for v in self.values):
                raise ValueError("enum needs 'values': a list of short strings")
            if any(m in v for v in self.values for m in JINJA_MARKERS):
                raise ValueError("enum values can't contain {{, {% or {#")
        elif self.values is not None:
            raise ValueError("'values' is only for type enum")
        if self.type == "string":
            if not self.pattern:
                raise ValueError("string needs a 'pattern' (free text is not accepted)")
            self._matcher = _compile_pattern(self.pattern)
        elif self.pattern is not None:
            raise ValueError("'pattern' is only for type string")
        if self.type != "int" and (self.min is not None or self.max is not None):
            raise ValueError("'min'/'max' are only for type int")
        if self.default is not None:
            self.default = self.coerce(self.default)
            if self.required:
                raise ValueError("'required' makes no sense with a 'default'")
        return self

    def coerce(self, value: Any) -> bool | int | str:
        """The validated value, or ValueError."""
        if self.type == "bool":
            if isinstance(value, bool):
                return value
            text = str(value).strip().lower()
            if text in ("true", "yes", "1", "on"):
                return True
            if text in ("false", "no", "0", "off"):
                return False
            raise ValueError("expected true or false")
        if self.type == "int":
            if isinstance(value, bool):
                raise ValueError("expected an integer")
            try:
                number = int(str(value).strip())
            except ValueError as exc:
                raise ValueError("expected an integer") from exc
            if self.min is not None and number < self.min:
                raise ValueError(f"must be >= {self.min}")
            if self.max is not None and number > self.max:
                raise ValueError(f"must be <= {self.max}")
            return number
        text = str(value).strip()
        if self.type == "enum":
            if text not in (self.values or []):
                raise ValueError(f"must be one of {', '.join(self.values or [])}")
            return text
        # string
        if any(m in text for m in JINJA_MARKERS):
            raise ValueError("can't contain {{, {% or {# (Ansible would run it as a template)")
        matcher = self._matcher
        if not text or len(text) > MAX_STRING_PARAM or matcher is None or not matcher.fullmatch(text):
            raise ValueError("does not match the allowed pattern")
        return text


class RunSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Read-only runs: wait for the Semaphore task and answer from the fresh
    # reports. Long jobs can set wait: false and report the task number.
    wait: bool = True
    timeout: int = Field(default=300, ge=10, le=3600)
    # Read-only only: every request runs it, questions included. For on-demand
    # queries whose last report may be stale or from another command.
    on_request: bool = False


class ReportsSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str  # relative to REPORTS_PATH, with {host}
    max_age_hours: float = Field(default=168.0, gt=0, le=24 * 365)
    max_bytes: int = Field(default=64 * 1024, ge=1024, le=512 * 1024)

    @field_validator("path")
    @classmethod
    def _safe_path(cls, value: str) -> str:
        value = value.strip()
        if (not REPORT_PATH_RE.match(value) or ".." in value.split("/")
                or "{host}" not in value or value.replace("{host}", "").count("{")):
            raise ValueError("path must be relative, without '..', and contain {host} once, "
                             "e.g. docker-checks/{host}.json")
        if value.count("{host}") != 1:
            raise ValueError("path must contain {host} exactly once")
        return value


class Capability(BaseModel):
    """A loaded manifest."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = Field(min_length=1, max_length=500)
    template: str = Field(min_length=1, max_length=100)  # Semaphore template name
    risk: Literal["read_only", "changes"]
    # Hosts this capability may target; a limit outside the group is refused.
    # Empty: no limit is ever sent and the template runs on its own hosts.
    limit_group: str | None = None
    params: dict[str, ParamSpec] = Field(default_factory=dict)
    run: RunSpec = Field(default_factory=RunSpec)
    reports: ReportsSpec | None = None
    include_in_analysis: bool = False
    # Words that select this capability when the LLM is not available.
    keywords: list[str] = Field(default_factory=list, max_length=20)
    source_file: str = Field(default="", exclude=True)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not CAP_NAME_RE.match(value):
            raise ValueError("name: lowercase letters, digits and _, 2-41 chars, starting with a letter")
        return value

    @field_validator("limit_group")
    @classmethod
    def _group(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        if not GROUP_RE.match(value):
            raise ValueError("limit_group: a single inventory group name")
        return value

    @field_validator("params")
    @classmethod
    def _param_names(cls, value: dict[str, ParamSpec]) -> dict[str, ParamSpec]:
        if len(value) > MAX_PARAMS:
            raise ValueError(f"at most {MAX_PARAMS} params")
        for name in value:
            if not PARAM_NAME_RE.match(name):
                raise ValueError(f"param '{name}': lowercase letters, digits and _")
            if name.startswith("ansible_") or name in _RESERVED_VARS:
                raise ValueError(f"param '{name}' is reserved by Ansible and can't be set by the AI")
        return value

    @field_validator("keywords")
    @classmethod
    def _keywords(cls, value: list[str]) -> list[str]:
        clean = [k.strip().lower() for k in value]
        for k in clean:
            if not KEYWORD_RE.match(k):
                raise ValueError(f"keyword '{k}': 2-40 letters, digits, spaces or . + -")
        return clean

    @model_validator(mode="after")
    def _consistent(self) -> Capability:
        if self.include_in_analysis and not self.reports:
            raise ValueError("include_in_analysis needs 'reports'")
        if self.risk == "changes" and not self.limit_group:
            # A plan must say which hosts it touches; the approver has to see them.
            raise ValueError("risk: changes needs limit_group")
        if self.risk == "changes" and self.run.on_request:
            raise ValueError("run.on_request is only for risk: read_only")
        return self

    # ─── Helpers ──────────────────────────────────────────────────────

    def validate_params(self, raw: dict[str, Any] | None) -> tuple[dict[str, Any], list[str]]:
        """
        Extra vars for a run: defaults plus validated values from the request.
        Unknown names are dropped with a warning; a known name with a bad
        value is an error (the run would otherwise do something else).
        """
        warnings: list[str] = []
        extra: dict[str, Any] = {n: p.default for n, p in self.params.items() if p.default is not None}
        for name, value in (raw or {}).items():
            spec = self.params.get(str(name))
            if spec is None:
                warnings.append(f"Ignored unknown parameter '{str(name)[:40]}' for {self.name}.")
                continue
            if value is None:
                continue
            try:
                extra[str(name)] = spec.coerce(value)
            except ValueError as exc:
                raise CapabilityError(f"parameter '{name}': {exc}") from exc
        missing = [n for n, p in self.params.items() if p.required and n not in extra]
        if missing:
            raise CapabilityError(f"missing required parameter {', '.join(missing)}")
        return extra, warnings

    def prompt_line(self) -> str:
        """One line for the intent prompt."""
        params = []
        for name, p in self.params.items():
            kind = f"one of {'|'.join(p.values or [])}" if p.type == "enum" else p.type
            req = ", required" if p.required else ""
            params.append(f"{name} ({kind}{req}{': ' + p.description if p.description else ''})")
        what = "CHANGES hosts, needs approval" if self.risk == "changes" else "read-only"
        if self.run.on_request:
            what += ", always runs when asked"
        line = f"- {self.name}: {self.description} [{what}"
        if self.limit_group:
            line += f"; hosts: {self.limit_group}"
        line += "]"
        if params:
            line += f" params: {'; '.join(params)}"
        return line

    def public(self) -> dict[str, Any]:
        """Description for the API and the dashboard."""
        return {
            "name": self.name,
            "description": self.description,
            "template": self.template,
            "risk": self.risk,
            "limit_group": self.limit_group,
            "params": {n: p.model_dump(exclude_none=True) for n, p in self.params.items()},
            "run": self.run.model_dump(),
            "reports": self.reports.model_dump() if self.reports else None,
            "include_in_analysis": self.include_in_analysis,
            "keywords": self.keywords,
            "file": self.source_file,
        }


# ─── Loading ────────────────────────────────────────────────────────────


def _unsafe(st: os.stat_result, what: str) -> str | None:
    """Why a file or directory may not be trusted, or None."""
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"{what} is writable by group or others"
    if st.st_uid not in (0, os.getuid()):
        return f"{what} is owned by uid {st.st_uid}, not root or the service user"
    return None


class CapabilityRegistry:
    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path or get_settings().capabilities_path)
        self.capabilities: dict[str, Capability] = {}
        self.errors: list[dict[str, str]] = []
        self.loaded_at: float | None = None

    def load(self) -> CapabilityRegistry:
        caps: dict[str, Capability] = {}
        errors: list[dict[str, str]] = []
        base = self.path
        try:
            dir_st = base.stat()
        except FileNotFoundError:
            dir_st = None
        except OSError as exc:
            errors.append({"file": str(base), "error": f"unreadable: {exc}"})
            dir_st = None

        if dir_st is not None:
            problem = _unsafe(dir_st, "directory") if stat.S_ISDIR(dir_st.st_mode) else "not a directory"
            if problem:
                errors.append({"file": str(base), "error": f"{problem}; no capability loaded"})
            else:
                files = sorted(p for p in base.iterdir() if p.suffix in (".yml", ".yaml"))
                if len(files) > MAX_MANIFESTS:
                    errors.append({"file": str(base),
                                   "error": f"more than {MAX_MANIFESTS} manifests; the rest are ignored"})
                for file in files[:MAX_MANIFESTS]:
                    try:
                        cap = self._load_file(file)
                    except (CapabilityError, ValidationError, yaml.YAMLError, OSError) as exc:
                        errors.append({"file": file.name, "error": _short_error(exc)})
                        continue
                    if cap.name in caps:
                        used_by = caps[cap.name].source_file
                        errors.append({"file": file.name,
                                       "error": f"name '{cap.name}' already used by {used_by}"})
                        continue
                    caps[cap.name] = cap

        self.capabilities, self.errors, self.loaded_at = caps, errors, time.time()
        for err in errors:
            logger.warning("capability_rejected", **err)
        logger.info("capabilities_loaded", path=str(base), names=sorted(caps), rejected=len(errors))
        if _re2 is None:
            logger.warning("re2_missing", detail="google-re2 is not installed: string parameters only "
                           "accept simple patterns (pip install google-re2)")
        return self

    @staticmethod
    def _load_file(file: Path) -> Capability:
        st = file.lstat()
        if stat.S_ISLNK(st.st_mode):
            raise CapabilityError("symlinks are not followed")
        if not stat.S_ISREG(st.st_mode):
            raise CapabilityError("not a regular file")
        problem = _unsafe(st, "file")
        if problem:
            raise CapabilityError(problem)
        if st.st_size > MAX_MANIFEST_BYTES:
            raise CapabilityError(f"larger than {MAX_MANIFEST_BYTES} bytes")
        data = yaml.safe_load(file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise CapabilityError("the manifest must be a YAML mapping")
        cap = Capability.model_validate(data)
        cap.source_file = file.name
        return cap

    def get(self, name: str | None) -> Capability | None:
        return self.capabilities.get(name or "")

    def all(self) -> list[Capability]:
        return [self.capabilities[n] for n in sorted(self.capabilities)]

    def status(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "loaded_at": datetime.fromtimestamp(self.loaded_at, UTC).isoformat(timespec="seconds")
            if self.loaded_at else None,
            "capabilities": [c.public() for c in self.all()],
            "errors": self.errors,
        }


def _short_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        parts = []
        for err in exc.errors()[:5]:
            where = ".".join(str(x) for x in err.get("loc", ())) or "manifest"
            parts.append(f"{where}: {err.get('msg', '')}")
        return "; ".join(parts)[:400]
    return str(exc)[:400]


_registry: CapabilityRegistry | None = None


def get_registry() -> CapabilityRegistry:
    """Loaded on first use; reload_registry() re-reads the directory."""
    global _registry  # noqa: PLW0603 (module-level cache, like get_settings)
    if _registry is None or _registry.path != Path(get_settings().capabilities_path):
        _registry = CapabilityRegistry().load()
    return _registry


def reload_registry() -> CapabilityRegistry:
    global _registry  # noqa: PLW0603
    _registry = CapabilityRegistry().load()
    return _registry


# ─── Reports ────────────────────────────────────────────────────────────


def read_reports(
    cap: Capability, hosts: list[str], now: float | None = None
) -> dict[str, dict[str, Any] | None]:
    """
    Per-host report of a capability: {"age_hours": float, "stale": bool, "data": Any}
    or None when the host has no (readable) report. Paths can't leave REPORTS_PATH.
    """
    if not cap.reports:
        return {}
    base = Path(get_settings().reports_path).resolve()
    now = now or time.time()
    out: dict[str, dict[str, Any] | None] = {}
    for host in hosts:
        if not _SAFE_HOST_RE.match(host) or host in (".", ".."):
            out[host] = None
            continue
        path = (base / cap.reports.path.replace("{host}", host)).resolve()
        if not path.is_relative_to(base):
            out[host] = None
            continue
        try:
            st = path.stat()
            if not stat.S_ISREG(st.st_mode) or st.st_size > cap.reports.max_bytes:
                logger.warning("capability_report_skipped", capability=cap.name, host=host,
                               size=st.st_size)
                out[host] = None
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            out[host] = None
            continue
        except (OSError, ValueError) as exc:
            logger.warning("capability_report_unreadable", capability=cap.name, host=host, error=str(exc))
            out[host] = None
            continue
        age = round(max(now - st.st_mtime, 0) / 3600, 1)
        out[host] = {"age_hours": age, "stale": age > cap.reports.max_age_hours, "data": data}
    return out


def compact_reports(reports: dict[str, dict[str, Any] | None], max_chars: int = 6000) -> str:
    """JSON for a prompt, cut at max_chars so one noisy host can't fill the context."""
    rows = {h: ({"age_h": r["age_hours"], "stale": r["stale"], "report": r["data"]} if r else None)
            for h, r in reports.items()}
    text = json.dumps(rows, ensure_ascii=False, separators=(",", ":"), default=str)
    if len(text) > max_chars:
        text = text[:max_chars] + " …[truncated]"
    return text
