"""
Inventory Reader: parses the Ansible YAML inventory into HostInfo objects and
validates --limit expressions against the groups and hosts it contains.

Supports nested groups (children of children) and inline `!vault` values,
which plain yaml.safe_load rejects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
import yaml

from app.agents.state import OS_GROUPS, HostInfo
from app.config import get_settings

logger = structlog.get_logger()


class _InventoryLoader(yaml.SafeLoader):
    """SafeLoader that tolerates Ansible tags such as !vault and !unsafe."""


def _opaque_tag(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> str:
    # Secret values are never needed here; keep a placeholder.
    return f"<{tag_suffix or 'tagged'}>"


_InventoryLoader.add_multi_constructor("!", _opaque_tag)


@dataclass
class ParsedInventory:
    """Result of parsing the inventory file."""

    hosts: dict[str, dict[str, Any]] = field(default_factory=dict)  # host -> merged vars
    groups: dict[str, set[str]] = field(default_factory=dict)  # group -> all member hosts

    def os_group_of(self, host: str) -> str | None:
        for group in OS_GROUPS:
            if host in self.groups.get(group, set()):
                return group
        return None


class InventoryReader:
    """Reads the Ansible inventory file."""

    def __init__(self, path: str | None = None):
        self.inventory_path = Path(path or get_settings().inventory_path)

    # ─── Parsing ────────────────────────────────────────────────────────

    def parse(self) -> ParsedInventory:
        try:
            with self.inventory_path.open(encoding="utf-8") as fh:
                data = yaml.load(fh, Loader=_InventoryLoader) or {}  # noqa: S506 (SafeLoader subclass)
        except FileNotFoundError:
            logger.error("inventory_not_found", path=str(self.inventory_path))
            return ParsedInventory()
        except yaml.YAMLError as exc:
            logger.error("inventory_parse_error", error=str(exc))
            return ParsedInventory()

        parsed = ParsedInventory()
        root = data.get("all", data) if isinstance(data, dict) else {}
        direct: dict[str, set[str]] = {}
        children: dict[str, set[str]] = {}
        self._walk_group("all", root or {}, {}, parsed, direct, children)

        # A group can be declared in several places (e.g. "production:
        # children: ubuntu_servers:" just references it), so resolve
        # membership by name after the walk, like Ansible does.
        def members(group: str, seen: frozenset[str] = frozenset()) -> set[str]:
            if group in seen:  # defensive: cyclic children
                return set()
            result = set(direct.get(group, set()))
            for child in children.get(group, set()):
                result |= members(child, seen | {group})
            return result

        parsed.groups = {g: members(g) for g in set(direct) | set(children)}
        return parsed

    def _walk_group(
        self,
        name: str,
        group: dict[str, Any],
        inherited_vars: dict[str, Any],
        parsed: ParsedInventory,
        direct: dict[str, set[str]],
        children: dict[str, set[str]],
    ) -> None:
        """Depth-first walk recording direct hosts, child groups and host vars."""
        group = group or {}
        group_vars = {**inherited_vars, **(group.get("vars") or {})}
        direct.setdefault(name, set())
        children.setdefault(name, set())

        for host, host_vars in (group.get("hosts") or {}).items():
            parsed.hosts[host] = {**parsed.hosts.get(host, {}), **group_vars, **(host_vars or {})}
            direct[name].add(host)

        for child_name, child in (group.get("children") or {}).items():
            children[name].add(child_name)
            self._walk_group(child_name, child or {}, group_vars, parsed, direct, children)

    # ─── Public API ─────────────────────────────────────────────────────

    def load_all(self) -> tuple[dict[str, list[HostInfo]], list[HostInfo], list[str]]:
        """Parse the file and build HostInfo objects (see build())."""
        return self.build(self.parse())

    def build(
        self, parsed: ParsedInventory
    ) -> tuple[dict[str, list[HostInfo]], list[HostInfo], list[str]]:
        """
        Return (hosts by OS group, flat host list, all group names).

        The flat list and the grouped dict contain the *same* HostInfo objects,
        so enrichment of one is visible in the other.
        """
        by_group: dict[str, list[HostInfo]] = {}
        flat: list[HostInfo] = []

        for hostname in sorted(parsed.hosts):
            os_group = parsed.os_group_of(hostname)
            if not os_group:
                continue  # host not in any OS group: not managed by these playbooks
            host_vars = parsed.hosts[hostname]
            criticality = str(host_vars.get("patch_criticality", "medium")).lower()
            host = HostInfo(
                hostname=hostname,
                ip=str(host_vars.get("ansible_host", hostname)),
                os_group=os_group,
                criticality=criticality if criticality in ("high", "medium", "low") else "medium",
            )
            by_group.setdefault(os_group, []).append(host)
            flat.append(host)

        groups = sorted(g for g in parsed.groups if g not in ("all", "ungrouped"))
        return by_group, flat, groups

    def get_host_count(self) -> dict[str, int]:
        by_group, _, _ = self.load_all()
        return {group: len(hosts) for group, hosts in by_group.items()}


# ─── --limit validation ─────────────────────────────────────────────────

_LIMIT_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-*]+$")


def validate_limit(limit: str | None, known_hosts: set[str], known_groups: set[str]) -> str | None:
    """
    Validate an Ansible --limit expression coming from a user or an LLM.

    Accepts comma/colon separated host or group names, with optional ! (exclude)
    and & (intersect) prefixes and simple * wildcards that match at least one
    known name. Returns the normalised expression, or None for "all hosts".
    Raises ValueError for anything else.
    """
    if limit is None:
        return None
    limit = str(limit).strip()
    if limit.lower() in ("", "all", "none", "null", "*"):
        return None

    names = known_hosts | known_groups
    tokens = [t for t in re.split(r"[,:]", limit) if t.strip()]
    if not tokens:
        return None

    clean: list[str] = []
    for raw in tokens:
        token = raw.strip()
        prefix = token[0] if token[0] in "!&" else ""
        name = token[1:] if prefix else token
        if not _LIMIT_TOKEN_RE.match(name):
            raise ValueError(f"invalid characters in limit token '{token}'")
        if "*" in name:
            pattern = re.compile("^" + re.escape(name).replace(r"\*", ".*") + "$")
            if not any(pattern.match(n) for n in names):
                raise ValueError(f"limit pattern '{name}' matches no known host or group")
        elif name not in names:
            raise ValueError(f"unknown host or group '{name}'")
        clean.append(prefix + name)
    return ",".join(clean)
