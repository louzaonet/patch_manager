"""
Agent state: the typed object that flows through the LangGraph nodes.

Nodes receive the current AgentState and return a dict with only the fields
they change. LangGraph merges those updates into the state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ActionType(StrEnum):
    """What the user asked for."""

    ANALYZE_RISK = "analyze_risk"
    CHECK_UPDATES = "check_updates"
    APPLY_PATCHES = "apply_patches"  # builds a plan; execution needs approval
    GENERATE_REPORT = "generate_report"
    ASK_QUESTION = "ask_question"
    STATUS = "status"


OS_GROUPS: tuple[str, ...] = ("ubuntu_servers", "rocky_servers", "macos_servers", "windows_servers")


@dataclass
class HostInfo:
    """One managed host, merged from the inventory and its latest update report."""

    hostname: str
    ip: str
    os_group: str  # one of OS_GROUPS
    criticality: str = "medium"  # inventory var patch_criticality: high | medium | low

    # From the per-host report written by check_updates.yml
    report_found: bool = False
    report_age_hours: float | None = None
    os_name: str = ""
    update_count: int = 0
    security_count: int = 0
    pending_updates: list[str] = field(default_factory=list)
    security_updates: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    reboot_required: bool = False
    last_patch_status: str = ""
    last_patch_at: str = ""

    # Filled by enrichment and scoring
    cve_matches: list[dict[str, Any]] = field(default_factory=list)
    kev_cves: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_factors: list[str] = field(default_factory=list)

    @property
    def data_stale(self) -> bool:
        from app.config import get_settings

        if not self.report_found or self.report_age_hours is None:
            return True
        return self.report_age_hours > get_settings().report_max_age_hours


@dataclass
class PatchPhase:
    """
    Hosts of a plan grouped by risk level. Informational: an approved plan
    runs as ONE Semaphore task over the whole scope, with the same options
    for every host. The groups tell the approver what is urgent.
    """

    phase_number: int = 0
    description: str = ""
    hosts: list[str] = field(default_factory=list)
    priority: str = "normal"  # critical, high, normal, low


@dataclass
class PatchPlan:
    """Prioritised plan. Only executed after explicit approval."""

    phases: list[PatchPhase] = field(default_factory=list)
    total_hosts: int = 0
    critical_count: int = 0
    high_count: int = 0
    estimated_duration_minutes: int = 0
    limit: str | None = None
    security_only: bool = False
    dry_run: bool = False
    no_reboot: bool = False


@dataclass
class AgentState:
    """State shared by all graph nodes."""

    # ─── Request ────────────────────────────────────────────────────────
    user_message: str = ""
    requested_by: str = "unknown"
    source: str = "web"  # web, api, slack, teams
    # Set by quick-action endpoints to skip LLM intent classification.
    forced_action: ActionType | None = None
    action: ActionType = ActionType.ASK_QUESTION
    target_hosts: str | None = None  # validated Ansible --limit expression
    options: dict[str, Any] = field(default_factory=dict)

    # ─── Inventory ──────────────────────────────────────────────────────
    inventory: dict[str, list[HostInfo]] = field(default_factory=dict)
    all_hosts: list[HostInfo] = field(default_factory=list)
    known_groups: list[str] = field(default_factory=list)
    group_members: dict[str, list[str]] = field(default_factory=dict)

    # ─── CVE context ────────────────────────────────────────────────────
    cve_data: list[dict[str, Any]] = field(default_factory=list)  # CVEs matched to hosts
    cve_context: list[dict[str, Any]] = field(default_factory=list)  # recent CVEs per OS family

    # ─── Planning and status ────────────────────────────────────────────
    patch_plan: PatchPlan | None = None
    plan_id: str | None = None
    recent_tasks: list[dict[str, Any]] = field(default_factory=list)

    # ─── Output ─────────────────────────────────────────────────────────
    briefing: str = ""
    ai_response: str = ""
    messages: list[dict[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
