"""
HTTP endpoints: chat, quick actions, patch plans (approval), inventory,
Semaphore task status, Slack and Teams webhooks, health.
"""

from __future__ import annotations

import asyncio
import html
import re
from typing import Any
from urllib.parse import parse_qs

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.agents.graph import run_agent
from app.agents.nodes import hosts_in_scope
from app.agents.state import ActionType, AgentState
from app.config import get_settings
from app.integrations.slack_bot import SlackBot
from app.integrations.teams_bot import TeamsBot
from app.security import (
    Principal,
    require_user,
    require_user_csrf,
    verify_slack_signature,
    verify_teams_hmac,
)
from app.services.plans import PlanNotFound, PlanStateError, plan_store
from app.tools.inventory_reader import InventoryReader, validate_limit
from app.tools.llm_router import get_active_models
from app.tools.semaphore_client import SemaphoreClient, SemaphoreError

logger = structlog.get_logger()
audit = structlog.get_logger("audit")
router = APIRouter()

# Background tasks must be referenced or the event loop may drop them.
_background: set[asyncio.Task] = set()


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _background.add(task)
    task.add_done_callback(_background.discard)


# ─── Models ─────────────────────────────────────────────────────────────


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    target_hosts: str | None = Field(default=None, max_length=200)
    options: dict[str, bool] | None = None
    history: list[dict[str, str]] | None = Field(default=None, max_length=20)


class ActionRequest(BaseModel):
    target_hosts: str | None = Field(default=None, max_length=200)
    security_only: bool = False
    dry_run: bool = False
    no_reboot: bool = False


class ChatResponse(BaseModel):
    response: str
    action: str
    target_hosts: str | None = None
    has_plan: bool = False
    plan_id: str | None = None
    plan_summary: dict[str, Any] | None = None
    risk_summary: list[dict[str, Any]] | None = None
    warnings: list[str] = []
    errors: list[str] = []


# ─── Agent helpers ──────────────────────────────────────────────────────


def _to_response(state: AgentState) -> ChatResponse:
    risk_summary = None
    if state.all_hosts and state.action != ActionType.ASK_QUESTION:
        risk_summary = [
            {
                "hostname": h.hostname,
                "os_group": h.os_group,
                "risk_score": h.risk_score,
                "risk_factors": h.risk_factors[:3],
                "updates": h.update_count,
                "security_updates": h.security_count,
                "kev": h.kev_cves[:5],
                "report_age_hours": h.report_age_hours,
            }
            for h in sorted(hosts_in_scope(state), key=lambda x: x.risk_score, reverse=True)[:50]
        ]

    plan_summary = None
    if state.patch_plan:
        p = state.patch_plan
        plan_summary = {
            "limit": p.limit,
            "security_only": p.security_only,
            "dry_run": p.dry_run,
            "no_reboot": p.no_reboot,
            "total_hosts": p.total_hosts,
            "critical": p.critical_count,
            "high": p.high_count,
            "phases": [
                {"phase": ph.phase_number, "priority": ph.priority, "host_count": len(ph.hosts),
                 "hosts": ph.hosts, "description": ph.description}
                for ph in p.phases
            ],
        }

    return ChatResponse(
        response=state.ai_response or state.briefing or "No response generated.",
        action=state.action.value,
        target_hosts=state.target_hosts,
        has_plan=state.plan_id is not None,
        plan_id=state.plan_id,
        plan_summary=plan_summary,
        risk_summary=risk_summary,
        warnings=state.warnings,
        errors=state.errors,
    )


def _clean_history(history: list[dict[str, str]] | None) -> list[dict[str, str]]:
    """Keep the last turns, known roles only, bounded size (it goes into a prompt)."""
    clean = []
    for turn in (history or [])[-10:]:
        role = turn.get("role")
        if role in ("user", "assistant"):
            clean.append({"role": role, "content": str(turn.get("content", ""))[:2000]})
    return clean


async def _run(
    message: str,
    *,
    requested_by: str,
    source: str,
    target: str | None = None,
    options: dict[str, Any] | None = None,
    forced: ActionType | None = None,
    history: list[dict[str, str]] | None = None,
) -> AgentState:
    state = AgentState(
        user_message=message,
        requested_by=requested_by,
        source=source,
        forced_action=forced,
        target_hosts=target or None,
        options=options or {},
        messages=[*_clean_history(history), {"role": "user", "content": message}],
    )
    return await run_agent(state)


# ═══════════════════════════════════════════════════════════════════════════
# Chat and quick actions
# ═══════════════════════════════════════════════════════════════════════════


@router.post("/api/chat", response_model=ChatResponse)
async def chat(req: ChatRequest, user: Principal = Depends(require_user_csrf)) -> ChatResponse:
    logger.info("chat_request", user=user.name, message=req.message[:100])
    try:
        state = await _run(req.message, requested_by=user.name, source="web",
                           target=req.target_hosts, options=req.options, history=req.history)
    except Exception as exc:
        logger.exception("agent_error")
        raise HTTPException(status_code=500, detail="Agent failed; see server logs") from exc
    return _to_response(state)


async def _quick(action: ActionType, message: str, req: ActionRequest, user: Principal) -> ChatResponse:
    options = {"security_only": req.security_only, "dry_run": req.dry_run, "no_reboot": req.no_reboot}
    try:
        state = await _run(message, requested_by=user.name, source="web", target=req.target_hosts,
                           options=options, forced=action)
    except Exception as exc:
        logger.exception("agent_error")
        raise HTTPException(status_code=500, detail="Agent failed; see server logs") from exc
    return _to_response(state)


@router.post("/api/action/check-updates", response_model=ChatResponse)
async def action_check_updates(req: ActionRequest | None = None,
                               user: Principal = Depends(require_user_csrf)) -> ChatResponse:
    """Summarise the latest update reports (does not contact hosts)."""
    return await _quick(ActionType.CHECK_UPDATES, "Summarise pending updates",
                        req or ActionRequest(), user)


@router.post("/api/action/analyze-risk", response_model=ChatResponse)
async def action_analyze_risk(req: ActionRequest | None = None,
                              user: Principal = Depends(require_user_csrf)) -> ChatResponse:
    return await _quick(ActionType.ANALYZE_RISK, "Analyze security risk and prioritise",
                        req or ActionRequest(), user)


@router.post("/api/action/plan-patches", response_model=ChatResponse)
async def action_plan_patches(req: ActionRequest | None = None,
                              user: Principal = Depends(require_user_csrf)) -> ChatResponse:
    """Build a patch plan. Nothing runs until the plan is approved."""
    return await _quick(ActionType.APPLY_PATCHES, "Plan patch installation",
                        req or ActionRequest(), user)


@router.post("/api/action/run-check")
async def action_run_check(req: ActionRequest | None = None,
                           user: Principal = Depends(require_user_csrf)) -> dict[str, Any]:
    """Trigger the Check Updates template in Semaphore (read-only on hosts)."""
    req = req or ActionRequest()
    s = get_settings()
    _, hosts, groups = InventoryReader().load_all()
    try:
        limit = validate_limit(req.target_hosts, {h.hostname for h in hosts}, set(groups))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    client = SemaphoreClient()
    try:
        project_id = await client.resolve_project_id()
        template = await client.find_template_by_name(project_id, s.semaphore_template_check)
        if not template:
            raise HTTPException(status_code=404,
                                detail=f"Template '{s.semaphore_template_check}' not found")
        task = await client.run_template(project_id, int(template["id"]), limit=limit,
                                         message=f"Check requested by {user.name}")
    except SemaphoreError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    audit.info("check_started", by=user.name, limit=limit, task_id=task.get("id"))
    return {"task_id": task.get("id"), "project_id": project_id, "limit": limit}


# ═══════════════════════════════════════════════════════════════════════════
# Plans
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/api/plans")
async def list_plans(user: Principal = Depends(require_user)) -> list[dict[str, Any]]:
    return [p.to_dict() for p in await plan_store.list()]


@router.get("/api/plans/{plan_id}")
async def get_plan(plan_id: str, user: Principal = Depends(require_user)) -> dict[str, Any]:
    try:
        return (await plan_store.get(plan_id)).to_dict()
    except PlanNotFound as exc:
        raise HTTPException(status_code=404, detail="Plan not found") from exc


@router.post("/api/plans/{plan_id}/approve")
async def approve_plan(plan_id: str, user: Principal = Depends(require_user_csrf)) -> dict[str, Any]:
    try:
        plan = await plan_store.approve_and_execute(plan_id, by=user.name)
    except PlanNotFound as exc:
        raise HTTPException(status_code=404, detail="Plan not found") from exc
    except PlanStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if plan.status == "failed":
        raise HTTPException(status_code=502, detail=plan.error or "Execution failed")
    return plan.to_dict()


@router.post("/api/plans/{plan_id}/reject")
async def reject_plan(plan_id: str, user: Principal = Depends(require_user_csrf)) -> dict[str, Any]:
    try:
        return (await plan_store.reject(plan_id, by=user.name)).to_dict()
    except PlanNotFound as exc:
        raise HTTPException(status_code=404, detail="Plan not found") from exc
    except PlanStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/api/tasks/{task_id}")
async def task_status(task_id: int, user: Principal = Depends(require_user)) -> dict[str, Any]:
    client = SemaphoreClient()
    try:
        project_id = await client.resolve_project_id()
        task = await client.get_task(project_id, task_id)
    except SemaphoreError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {k: task.get(k) for k in ("id", "status", "created", "start", "end", "message")}


@router.get("/api/inventory")
async def inventory(user: Principal = Depends(require_user)) -> dict[str, Any]:
    by_group, hosts, groups = InventoryReader().load_all()
    return {
        "groups": groups,
        "os_groups": {g: [h.hostname for h in hs] for g, hs in by_group.items()},
        "host_count": len(hosts),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Slack
# ═══════════════════════════════════════════════════════════════════════════

_APPROVAL_RE = re.compile(r"^\s*(approve|reject)\s+([0-9a-f]{12})\s*$", re.I)


async def _slack_run_and_reply(slack: SlackBot, text: str, user_name: str, response_url: str | None,
                               channel_id: str | None) -> None:
    try:
        state = await _run(text, requested_by=f"slack:{user_name}", source="slack")
        reply = state.ai_response or state.briefing or "Done."
        await slack.respond(response_url, reply[:200], slack.build_blocks(reply, state.plan_id),
                            channel=channel_id)
    except Exception:
        logger.exception("slack_agent_error")
        await slack.respond(response_url, "Patch Manager AI failed to process that request; check the logs.",
                            in_channel=False, channel=channel_id)


async def _slack_decide(slack: SlackBot, verb: str, plan_id: str, user_id: str, user_name: str,
                        response_url: str | None) -> None:
    who = f"slack:{user_name}({user_id})"
    try:
        if verb == "approve":
            plan = await plan_store.approve_and_execute(plan_id, by=who)
            if plan.status == "failed":
                msg = f":x: Plan `{plan_id}` failed to start: {plan.error}"
            else:
                msg = (f":rocket: Plan `{plan_id}` approved by <@{user_id}>. "
                       f"Semaphore task #{plan.semaphore_task_id}.")
        else:
            await plan_store.reject(plan_id, by=who)
            msg = f":no_entry: Plan `{plan_id}` rejected by <@{user_id}>."
    except PlanNotFound:
        msg = f"Plan `{plan_id}` not found (expired or unknown)."
    except PlanStateError as exc:
        msg = f"Plan `{plan_id}` can't be changed: {exc}."
    except Exception:
        logger.exception("slack_decision_error", plan_id=plan_id)
        msg = f"Plan `{plan_id}`: internal error, check the service logs."
    await slack.respond(response_url, msg)


@router.post("/api/integrations/slack")
async def slack_webhook(request: Request) -> JSONResponse:
    s = get_settings()
    if not s.slack_enabled:
        raise HTTPException(status_code=404)
    slack = SlackBot()

    body = await request.body()
    if not verify_slack_signature(
        slack.signing_secret,
        request.headers.get("X-Slack-Request-Timestamp", ""),
        body,
        request.headers.get("X-Slack-Signature", ""),
    ):
        raise HTTPException(status_code=401, detail="Invalid Slack signature")

    form = {k: v[0] for k, v in parse_qs(body.decode("utf-8"), keep_blank_values=True).items()}
    text = form.get("text", "").strip()
    user_id = form.get("user_id", "")
    user_name = form.get("user_name", "unknown")
    response_url = form.get("response_url")
    channel_id = form.get("channel_id")
    logger.info("slack_command", user=user_name, text=text[:100])

    if not text:
        usage = "Usage: `/patch <request>`, `/patch approve <plan_id>`, `/patch reject <plan_id>`"
        return JSONResponse({"response_type": "ephemeral", "text": usage})

    match = _APPROVAL_RE.match(text)
    if match:
        verb, plan_id = match.group(1).lower(), match.group(2).lower()
        if user_id not in s.slack_approvers:
            audit.warning("slack_approval_denied", user=user_name, user_id=user_id, plan_id=plan_id)
            return JSONResponse({"response_type": "ephemeral",
                                 "text": "You are not allowed to approve or reject patch plans."})
        _spawn(_slack_decide(slack, verb, plan_id, user_id, user_name, response_url))
        return JSONResponse({"response_type": "ephemeral", "text": f"Processing {verb} for `{plan_id}`..."})

    _spawn(_slack_run_and_reply(slack, text, user_name, response_url, channel_id))
    return JSONResponse({"response_type": "ephemeral", "text": "Working on it, results will follow here."})


# ═══════════════════════════════════════════════════════════════════════════
# Teams
# ═══════════════════════════════════════════════════════════════════════════


# Teams sends the message as HTML. Both patterns are linear: every match
# attempt stops at the next '<', so input such as "<<<<..." or
# "<at><at><at>..." can't trigger quadratic backtracking (CodeQL
# py/polynomial-redos). The display name inside <at>...</at> arrives
# HTML-escaped (&lt;), so [^<]* is enough for mentions.
_TEAMS_MENTION_RE = re.compile(r"<at>[^<]*</at>")
_HTML_TAG_RE = re.compile(r"<[^<>]+>")
# Cap on the raw HTML before any processing. Real Teams messages are
# smaller; this only bounds the work if someone sends something huge.
_TEAMS_RAW_MAX = 20_000


def _teams_text(raw: Any) -> str:
    """Plain text of a Teams message, without mentions, tags or entities."""
    text = _TEAMS_MENTION_RE.sub("", str(raw)[:_TEAMS_RAW_MAX])
    text = _HTML_TAG_RE.sub(" ", text)
    # Entities go last, so an escaped "&lt;b&gt;" stays as text. &nbsp;
    # becomes a normal space or hostnames and "approve <id>" would not match.
    text = html.unescape(text).replace("\xa0", " ")
    return " ".join(text.split())[:4000]


async def _teams_run_and_post(teams: TeamsBot, text: str, sender: str) -> None:
    try:
        state = await _run(text, requested_by=f"teams:{sender}", source="teams")
        await teams.send_briefing(state.ai_response or state.briefing or "Done.", state.plan_id)
    except Exception:
        logger.exception("teams_agent_error")


@router.post("/api/integrations/teams")
async def teams_webhook(request: Request) -> JSONResponse:
    s = get_settings()
    if not (s.teams_enabled and s.teams_outgoing_secret):
        raise HTTPException(status_code=404)
    body = await request.body()
    if not verify_teams_hmac(s.teams_outgoing_secret, body, request.headers.get("Authorization", "")):
        raise HTTPException(status_code=401, detail="Invalid HMAC")
    try:
        data = await request.json()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")

    text = _teams_text(data.get("text", ""))
    sender_info = data.get("from")
    sender = str(sender_info.get("name", "unknown") if isinstance(sender_info, dict) else "unknown")[:100]
    if not text:
        return JSONResponse({"type": "message", "text": "Send me a patching request."})
    if _APPROVAL_RE.match(text):
        return JSONResponse({"type": "message",
                             "text": "Plans can't be approved from Teams. Use the dashboard."})

    teams = TeamsBot()
    if not teams.webhook_url:
        return JSONResponse({"type": "message",
                             "text": "TEAMS_WEBHOOK_URL is not configured, so I can't post results."})
    _spawn(_teams_run_and_post(teams, text, sender))
    return JSONResponse({"type": "message",
                         "text": "Working on it, the briefing will be posted in the channel."})


# ═══════════════════════════════════════════════════════════════════════════
# Health
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/api/health")
async def health() -> dict[str, Any]:
    """Liveness. Deliberately reveals no configuration."""
    return {"status": "healthy", "service": "patch-manager-ai"}


@router.get("/api/info")
async def info(user: Principal = Depends(require_user)) -> dict[str, Any]:
    s = get_settings()
    return {
        "llm_routing": get_active_models(),
        "integrations": {"slack": s.slack_enabled, "teams": s.teams_enabled},
        "nvd": {"enabled": s.nvd_enabled, "api_key": bool(s.nvd_api_key)},
        "kev": s.kev_enabled,
        "plan_ttl_minutes": s.plan_ttl_minutes,
    }
