"""
Pending patch plans and their execution.

The agent never runs the patch playbook by itself. When someone asks to
apply patches, the graph builds a plan and registers it here. Somebody with
approval rights (authenticated dashboard user, API token, or a Slack user in
SLACK_APPROVER_IDS) then approves it, and only then is the Semaphore
template triggered, with parameters taken from the stored plan, not from
anything an LLM says at approval time.

Plans live in memory and expire after PLAN_TTL_MINUTES. Restarting the
service drops pending plans, which is the safe failure mode.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import structlog

from app.agents.state import PatchPlan
from app.config import get_settings
from app.tools.semaphore_client import SemaphoreClient, SemaphoreError

logger = structlog.get_logger()
audit = structlog.get_logger("audit")


@dataclass
class PendingPlan:
    id: str
    created_at: float
    expires_at: float
    requested_by: str
    source: str
    request_text: str
    limit: str | None
    security_only: bool
    dry_run: bool
    no_reboot: bool
    summary: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"  # pending | executing | started | failed | rejected | expired
    decided_by: str | None = None
    decided_at: float | None = None
    semaphore_project_id: int | None = None
    semaphore_task_id: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def extra_vars(self) -> dict[str, str]:
        """Ansible extra vars passed to the Apply Patches template."""
        return {
            "patch_security_only": str(self.security_only).lower(),
            "patch_dry_run": str(self.dry_run).lower(),
            "patch_reboot_allowed": str(not self.no_reboot).lower(),
        }


class PlanNotFound(KeyError):
    pass


class PlanStateError(RuntimeError):
    pass


class PlanStore:
    def __init__(self) -> None:
        self._plans: dict[str, PendingPlan] = {}
        self._lock = asyncio.Lock()

    def _expire(self) -> None:
        now = time.time()
        for plan in self._plans.values():
            if plan.status == "pending" and plan.expires_at < now:
                plan.status = "expired"
        # Keep finished plans for a day for audit and the UI, then drop them.
        cutoff = now - 86400
        for plan_id in [p.id for p in self._plans.values() if p.created_at < cutoff]:
            self._plans.pop(plan_id, None)

    async def create(
        self,
        plan: PatchPlan,
        requested_by: str,
        source: str,
        request_text: str,
    ) -> PendingPlan:
        ttl = get_settings().plan_ttl_minutes * 60
        now = time.time()
        pending = PendingPlan(
            id=secrets.token_hex(6),
            created_at=now,
            expires_at=now + ttl,
            requested_by=requested_by,
            source=source,
            request_text=request_text[:500],
            limit=plan.limit,
            security_only=plan.security_only,
            dry_run=plan.dry_run,
            no_reboot=plan.no_reboot,
            summary={
                "total_hosts": plan.total_hosts,
                "critical": plan.critical_count,
                "high": plan.high_count,
                "estimated_duration_minutes": plan.estimated_duration_minutes,
                "phases": [
                    {
                        "phase": p.phase_number,
                        "priority": p.priority,
                        "hosts": p.hosts,
                        "description": p.description,
                    }
                    for p in plan.phases
                ],
            },
        )
        async with self._lock:
            self._expire()
            self._plans[pending.id] = pending
        audit.info("plan_created", plan_id=pending.id, by=requested_by, source=source,
                   limit=pending.limit, security_only=pending.security_only,
                   dry_run=pending.dry_run, no_reboot=pending.no_reboot)
        return pending

    async def get(self, plan_id: str) -> PendingPlan:
        async with self._lock:
            self._expire()
            plan = self._plans.get(plan_id)
        if not plan:
            raise PlanNotFound(plan_id)
        return plan

    async def list(self) -> list[PendingPlan]:
        async with self._lock:
            self._expire()
            return sorted(self._plans.values(), key=lambda p: p.created_at, reverse=True)

    async def reject(self, plan_id: str, by: str) -> PendingPlan:
        async with self._lock:
            self._expire()
            plan = self._plans.get(plan_id)
            if not plan:
                raise PlanNotFound(plan_id)
            if plan.status != "pending":
                raise PlanStateError(f"plan is {plan.status}")
            plan.status, plan.decided_by, plan.decided_at = "rejected", by, time.time()
        audit.info("plan_rejected", plan_id=plan_id, by=by)
        return plan

    async def approve_and_execute(self, plan_id: str, by: str) -> PendingPlan:
        """Mark the plan as executing (atomically) and trigger Semaphore."""
        async with self._lock:
            self._expire()
            plan = self._plans.get(plan_id)
            if not plan:
                raise PlanNotFound(plan_id)
            if plan.status != "pending":
                raise PlanStateError(f"plan is {plan.status}")
            plan.status, plan.decided_by, plan.decided_at = "executing", by, time.time()
        audit.info("plan_approved", plan_id=plan_id, by=by, limit=plan.limit,
                   extra_vars=plan.extra_vars())

        settings = get_settings()
        client = SemaphoreClient()
        try:
            project_id = await client.resolve_project_id()
            template = await client.find_template_by_name(
                project_id, settings.semaphore_template_apply
            )
            if not template:
                raise SemaphoreError(
                    f"Template '{settings.semaphore_template_apply}' not found in Semaphore"
                )
            result = await client.run_template(
                project_id=project_id,
                template_id=int(template["id"]),
                extra_vars=plan.extra_vars(),
                limit=plan.limit,
                message=f"Patch plan {plan.id} approved by {by}",
            )
            plan.semaphore_project_id = project_id
            plan.semaphore_task_id = int(result.get("id")) if result and result.get("id") else None
            plan.status = "started"
            audit.info("plan_started", plan_id=plan_id, task_id=plan.semaphore_task_id)
        except Exception as exc:  # anything unexpected must not leave the plan "executing"
            plan.status, plan.error = "failed", str(exc) or type(exc).__name__
            if not isinstance(exc, SemaphoreError):
                logger.exception("plan_execution_error", plan_id=plan_id)
            audit.error("plan_failed", plan_id=plan_id, error=plan.error)
        return plan


plan_store = PlanStore()
