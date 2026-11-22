"""
Scheduled risk analysis: run the agent on a cron schedule and email the result.

Runs inside the web service as an asyncio task. If uvicorn is started with
several workers, a file lock makes sure only one of them schedules, so the
report is sent once. The same code path backs the "Email report now" button.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import os
import tempfile
from datetime import UTC, datetime, tzinfo
from typing import Any

import structlog

from app.agents.graph import run_agent
from app.agents.state import ActionType, AgentState
from app.config import get_settings
from app.services.cron import CronSchedule, resolve_tz
from app.services.mailer import build_report_email, send_email

logger = structlog.get_logger()
audit = structlog.get_logger("audit")

LOCK_PATH = os.path.join(tempfile.gettempdir(), "patch-ai-scheduler.lock")
# Sleep in short chunks so a changed clock (NTP, suspend) can't push a run far away.
MAX_SLEEP_SECONDS = 60.0

ANALYSIS_REQUEST = (
    "Scheduled risk analysis. Summarise the current risk, list what needs patching first "
    "and flag hosts whose data is missing or stale."
)


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat(timespec="seconds") if moment else None


class AutoAnalysis:
    def __init__(self) -> None:
        self._task: asyncio.Task[None] | None = None
        self._run_lock = asyncio.Lock()
        self._lock_fd: int | None = None
        self.next_run: datetime | None = None
        self.last_run: datetime | None = None
        self.last_ok: bool | None = None
        self.last_detail: str = ""
        self.scheduler_here = False

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the schedule if AUTO_ANALYSIS_CRON is set (config already validated)."""
        s = get_settings()
        if not s.auto_analysis_cron.strip() or self._task is not None:
            return
        if not self._acquire_lock():
            logger.info("auto_analysis_other_worker", lock=LOCK_PATH)
            return
        self.scheduler_here = True
        schedule = CronSchedule.parse(s.auto_analysis_cron)
        tz = resolve_tz(s.auto_analysis_tz)
        self._task = asyncio.create_task(self._loop(schedule, tz), name="auto-analysis")
        logger.info("auto_analysis_scheduled", cron=schedule.expression, tz=s.auto_analysis_tz,
                    recipients=len(s.email_recipients))

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._lock_fd is not None:
            os.close(self._lock_fd)  # releases the flock
            self._lock_fd = None
        self.scheduler_here = False

    def _acquire_lock(self) -> bool:
        fd = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        self._lock_fd = fd
        return True

    async def _loop(self, schedule: CronSchedule, tz: tzinfo) -> None:
        due = schedule.next_after(datetime.now(tz), tz)
        while True:
            self.next_run = due
            remaining = (due - datetime.now(tz)).total_seconds()
            if remaining > 0:
                await asyncio.sleep(min(remaining, MAX_SLEEP_SECONDS))
                continue
            # Failures are logged and recorded by run_once; the schedule goes on.
            with contextlib.suppress(Exception):
                await self.run_once(trigger="schedule")
            # From "now", not from "due": a run that took longer than the
            # interval must not fire again straight away.
            due = schedule.next_after(max(datetime.now(tz), due), tz)

    # ─── One analysis + email ─────────────────────────────────────────────

    async def run_once(self, trigger: str) -> dict[str, Any]:
        """Analyse, email the report and return a short summary. Raises on failure."""
        s = get_settings()
        if not s.email_configured:
            raise RuntimeError("Email is not configured (SMTP_HOST, EMAIL_FROM, EMAIL_TO).")
        async with self._run_lock:
            started = datetime.now(UTC)
            tz = resolve_tz(s.auto_analysis_tz)
            try:
                state = await run_agent(AgentState(
                    user_message=ANALYSIS_REQUEST,
                    requested_by=trigger,
                    source="schedule",
                    forced_action=ActionType.ANALYZE_RISK,
                    target_hosts=s.auto_analysis_target.strip() or None,
                    messages=[{"role": "user", "content": ANALYSIS_REQUEST}],
                ))
                msg = build_report_email(state, s, started.astimezone(tz))
                await asyncio.to_thread(send_email, msg, s)
            except Exception as exc:
                self.last_run, self.last_ok = started, False
                self.last_detail = str(exc)[:300]
                logger.exception("auto_analysis_failed", trigger=trigger)
                audit.warning("report_email_failed", trigger=trigger, error=self.last_detail)
                raise
            self.last_run, self.last_ok = started, True
            self.last_detail = str(msg["Subject"])
            audit.info("report_email_sent", trigger=trigger, recipients=len(s.email_recipients),
                       subject=self.last_detail)
            return {"subject": self.last_detail, "recipients": len(s.email_recipients)}

    def status(self) -> dict[str, Any]:
        s = get_settings()
        return {
            "email_configured": s.email_configured,
            "cron": s.auto_analysis_cron.strip() or None,
            "tz": s.auto_analysis_tz,
            "target": s.auto_analysis_target.strip() or None,
            "scheduled_in_this_process": self.scheduler_here,
            "next_run": _iso(self.next_run),
            "last_run": _iso(self.last_run),
            "last_ok": self.last_ok,
            "last_detail": self.last_detail or None,
        }


auto_analysis = AutoAnalysis()
