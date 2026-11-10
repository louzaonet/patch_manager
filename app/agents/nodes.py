"""
Agent nodes. Each node reads AgentState and returns a dict with the fields it
changes. LLM calls are wrapped so that a dead or slow model degrades to a
deterministic answer instead of a 500.
"""

from __future__ import annotations

import fnmatch
import json
from typing import Any

import structlog

from app.agents.intent import INTENT_PROMPT, Intent, keyword_intent, parse_intent
from app.agents.state import ActionType, AgentState, HostInfo, PatchPhase, PatchPlan
from app.services.plans import plan_store
from app.tools.cve_scanner import CVEScanner
from app.tools.inventory_reader import InventoryReader, validate_limit
from app.tools.llm_router import get_llm, message_text
from app.tools.report_reader import ReportReader
from app.tools.risk_scorer import RiskScorer
from app.tools.semaphore_client import SemaphoreClient, SemaphoreError

logger = structlog.get_logger()

MAX_HOSTS_IN_PROMPT = 40
MAX_CVES_IN_PROMPT = 25


async def _ask_llm(task: str, prompt: str) -> str:
    """Call the model for `task` and return clean text. Raises on failure."""
    llm = get_llm(task)
    response = await llm.ainvoke(prompt)
    return message_text(response)


def _known_names(state: AgentState) -> set[str]:
    return {h.hostname for h in state.all_hosts} | set(state.known_groups)


def hosts_in_scope(state: AgentState) -> list[HostInfo]:
    """
    Hosts matched by state.target_hosts. Mirrors Ansible --limit semantics
    for the forms validate_limit() accepts: union, !exclude, &intersect, *.
    """
    if not state.target_hosts:
        return list(state.all_hosts)

    all_names = {h.hostname for h in state.all_hosts}
    groups = {g: set(m) for g, m in state.group_members.items()}
    selected: set[str] | None = None
    excluded: set[str] = set()
    for token in state.target_hosts.split(","):
        prefix, name = (token[0], token[1:]) if token[:1] in "!&" else ("", token)
        if "*" in name:
            members = {h for h in all_names if fnmatch.fnmatch(h, name)}
            for group, hosts in groups.items():
                if fnmatch.fnmatch(group, name):
                    members |= hosts
        else:
            members = groups.get(name, {name} if name in all_names else set())
        if prefix == "!":
            excluded |= members
        elif prefix == "&":
            selected = (selected if selected is not None else set(all_names)) & members
        else:
            selected = (selected or set()) | members
    names = (selected if selected is not None else all_names) - excluded
    return [h for h in state.all_hosts if h.hostname in names]


# ═══════════════════════════════════════════════════════════════════════════
# 1. Load inventory (+ per-host update reports)
# ═══════════════════════════════════════════════════════════════════════════


async def load_inventory(state: AgentState) -> dict[str, Any]:
    reader = InventoryReader()
    parsed = reader.parse()
    by_group, flat, groups = reader.build(parsed)
    ReportReader().enrich(flat)
    stale = sum(1 for h in flat if h.data_stale)
    warnings = list(state.warnings)
    if flat and stale == len(flat):
        warnings.append("No recent update reports found. Run the Check Updates template first.")
    elif stale:
        warnings.append(f"{stale} host(s) have no recent update report.")
    logger.info("inventory_loaded", groups=list(by_group), hosts=len(flat), stale=stale)
    return {
        "inventory": by_group,
        "all_hosts": flat,
        "known_groups": groups,
        "group_members": {g: sorted(m) for g, m in parsed.groups.items()},
        "warnings": warnings,
    }


# ═══════════════════════════════════════════════════════════════════════════
# 2. Classify intent
# ═══════════════════════════════════════════════════════════════════════════


async def classify_intent(state: AgentState) -> dict[str, Any]:
    """
    Decide what the user wants. Quick actions set forced_action and skip the
    LLM. Explicit UI options and target always win over what the model says.
    """
    known = _known_names(state)
    warnings = list(state.warnings)

    if state.forced_action is not None:
        intent = Intent(action=state.forced_action.value)
    else:
        intent = None
        try:
            prompt = INTENT_PROMPT.format(
                known=", ".join(sorted(known)) or "(inventory empty)",
                message=state.user_message[:2000],
            )
            intent = parse_intent(await _ask_llm("classify_intent", prompt))
            if intent is None:
                logger.warning("intent_unparseable")
        except Exception as exc:  # model down, timeout, auth error...
            logger.warning("intent_llm_failed", error=str(exc))
            warnings.append("Intent model unavailable; used keyword matching.")
        if intent is None:
            intent = keyword_intent(state.user_message, known)

    # Merge: explicit request fields (UI/API) override model guesses.
    opts = dict(state.options)
    target = state.target_hosts or intent.target_hosts
    try:
        target = validate_limit(target, {h.hostname for h in state.all_hosts}, set(state.known_groups))
    except ValueError as exc:
        warnings.append(f"Ignored target '{target}': {exc}. Using all hosts.")
        target = None

    options = {
        "security_only": bool(opts.get("security_only") or intent.security_only),
        "dry_run": bool(opts.get("dry_run") or intent.dry_run),
        "no_reboot": bool(opts.get("no_reboot") or intent.no_reboot),
    }
    action = ActionType(intent.action)
    logger.info("intent_classified", action=action.value, target=target, **options)
    return {"action": action, "target_hosts": target, "options": options, "warnings": warnings}


# ═══════════════════════════════════════════════════════════════════════════
# 3. CVE enrichment (KEV + NVD)
# ═══════════════════════════════════════════════════════════════════════════


async def enrich_cves(state: AgentState) -> dict[str, Any]:
    """
    Attach CVE details to hosts *only* for CVE IDs that host reported (from
    its package advisories). Add recent critical CVEs per OS family as
    separate context for the briefing.
    """
    scanner = CVEScanner()
    hosts = hosts_in_scope(state)
    all_ids = sorted({cve for h in hosts for cve in h.cve_ids})

    kev = await scanner.get_kev_ids()
    # Look up KEV hits first: they matter most if the budget runs out.
    ordered = sorted(all_ids, key=lambda c: (c not in kev, c))
    details = await scanner.lookup_cves(ordered) if ordered else {}

    matched: dict[str, dict[str, Any]] = {}
    for host in hosts:
        host.kev_cves = [c for c in host.cve_ids if c in kev]
        host.cve_matches = []
        for cve_id in host.cve_ids:
            info = dict(details.get(cve_id) or {"id": cve_id, "score": 0.0, "severity": "UNKNOWN"})
            info["known_exploited"] = cve_id in kev
            host.cve_matches.append(info)
            matched[cve_id] = info
        host.cve_matches.sort(key=lambda c: (c["known_exploited"], c.get("score", 0)), reverse=True)

    cve_data = sorted(matched.values(), key=lambda c: (c["known_exploited"], c.get("score", 0)),
                      reverse=True)
    context = await scanner.recent_context(sorted({h.os_group for h in hosts}))
    logger.info("cve_enrichment_complete", host_cves=len(cve_data),
                kev_hits=sum(1 for c in cve_data if c["known_exploited"]), context=len(context))
    return {"cve_data": cve_data, "cve_context": context, "all_hosts": state.all_hosts}


# ═══════════════════════════════════════════════════════════════════════════
# 4. Risk scoring
# ═══════════════════════════════════════════════════════════════════════════


async def score_risks(state: AgentState) -> dict[str, Any]:
    scored = RiskScorer().score_all(state.all_hosts)
    by_group: dict[str, list[HostInfo]] = {}
    for host in scored:
        by_group.setdefault(host.os_group, []).append(host)
    critical = sum(1 for h in scored if h.risk_score >= 80)
    high = sum(1 for h in scored if 60 <= h.risk_score < 80)
    logger.info("risk_scoring_complete", critical=critical, high=high)
    return {"all_hosts": scored, "inventory": by_group}


# ═══════════════════════════════════════════════════════════════════════════
# 5. Build patch plan (registered for approval, never executed here)
# ═══════════════════════════════════════════════════════════════════════════


async def build_patch_plan(state: AgentState) -> dict[str, Any]:
    hosts = hosts_in_scope(state)
    names = {h.hostname for h in hosts}
    scored = [h for h in state.all_hosts if h.hostname in names]
    no_reboot = bool(state.options.get("no_reboot"))

    # Risk groups are informational: the approved plan runs as one Semaphore
    # task over the whole scope (see PatchPhase).
    buckets = [
        (1, "critical", "Critical risk", lambda s: s >= 80),
        (2, "high", "High risk", lambda s: 60 <= s < 80),
        (3, "normal", "Medium risk", lambda s: 40 <= s < 60),
        (4, "low", "Low risk", lambda s: s < 40),
    ]
    phases = []
    for number, priority, description, match in buckets:
        members = [h.hostname for h in scored if match(h.risk_score)]
        if members:
            phases.append(
                PatchPhase(phase_number=number, description=description, hosts=members, priority=priority)
            )

    plan = PatchPlan(
        phases=phases,
        total_hosts=len(scored),
        critical_count=sum(1 for h in scored if h.risk_score >= 80),
        high_count=sum(1 for h in scored if 60 <= h.risk_score < 80),
        estimated_duration_minutes=max(5, len(scored) * 5),
        limit=state.target_hosts,
        security_only=bool(state.options.get("security_only")),
        dry_run=bool(state.options.get("dry_run")),
        no_reboot=no_reboot,
    )
    pending = await plan_store.create(plan, state.requested_by, state.source, state.user_message)
    logger.info("patch_plan_built", plan_id=pending.id, phases=len(phases), hosts=len(scored))
    return {"patch_plan": plan, "plan_id": pending.id}


# ═══════════════════════════════════════════════════════════════════════════
# 6. Recent Semaphore tasks (status requests)
# ═══════════════════════════════════════════════════════════════════════════


async def fetch_task_status(state: AgentState) -> dict[str, Any]:
    client = SemaphoreClient()
    try:
        project_id = await client.resolve_project_id()
        tasks = await client.get_recent_tasks(project_id, limit=10)
    except SemaphoreError as exc:
        return {"errors": [*state.errors, f"Could not read Semaphore tasks: {exc}"]}
    slim = [
        {
            "id": t.get("id"),
            "template": t.get("tpl_alias") or t.get("template_alias") or t.get("template_id"),
            "status": t.get("status"),
            "created": t.get("created"),
            "end": t.get("end"),
            "message": t.get("message", ""),
        }
        for t in tasks
    ]
    return {"recent_tasks": slim}


# ═══════════════════════════════════════════════════════════════════════════
# 7. Briefing
# ═══════════════════════════════════════════════════════════════════════════


def _host_summary(hosts: list[HostInfo]) -> list[dict[str, Any]]:
    # No IP addresses: they add nothing to the briefing and shouldn't leave
    # the network when a cloud model is used.
    return [
        {
            "host": h.hostname,
            "group": h.os_group,
            "os": h.os_name or None,
            "risk": h.risk_score,
            "class": RiskScorer.classify(h.risk_score),
            "updates": h.update_count,
            "security_updates": h.security_count,
            "kev": h.kev_cves[:3],
            "reboot_pending": h.reboot_required,
            "report_age_h": h.report_age_hours,
            "factors": h.risk_factors[:3],
        }
        for h in hosts[:MAX_HOSTS_IN_PROMPT]
    ]


def _plan_summary(state: AgentState) -> dict[str, Any] | None:
    if not state.patch_plan:
        return None
    p = state.patch_plan
    return {
        "plan_id": state.plan_id,
        "limit": p.limit or "all hosts",
        "security_only": p.security_only,
        "dry_run": p.dry_run,
        "no_reboot": p.no_reboot,
        "phases": [{"phase": ph.phase_number, "priority": ph.priority, "hosts": ph.hosts}
                   for ph in p.phases],
    }


def fallback_briefing(state: AgentState, reason: str = "") -> str:
    """Deterministic briefing used when the LLM fails."""
    hosts = hosts_in_scope(state)
    lines = ["## Patch status (generated without the AI model)"]
    if reason:
        lines.append(f"_Model unavailable: {reason}_")
    lines.append("")
    total_sec = sum(h.security_count for h in hosts)
    total_upd = sum(h.update_count for h in hosts)
    lines.append(f"{len(hosts)} hosts, {total_upd} pending updates, {total_sec} security updates.")
    kev_hosts = [h.hostname for h in hosts if h.kev_cves]
    if kev_hosts:
        lines.append(f"**Known exploited CVEs pending on:** {', '.join(kev_hosts)}")
    lines.append("")
    for h in sorted(hosts, key=lambda x: x.risk_score, reverse=True)[:15]:
        factors = "; ".join(h.risk_factors[:2]) or "no notable factors"
        lines.append(f"- **{h.hostname}** ({RiskScorer.classify(h.risk_score)} {h.risk_score}): {factors}")
    if state.plan_id:
        lines.append("")
        lines.append(f"Plan `{state.plan_id}` is waiting for approval.")
    if state.recent_tasks:
        lines.append("")
        lines.append("Recent Semaphore tasks:")
        for t in state.recent_tasks[:5]:
            lines.append(f"- #{t['id']} {t['template']}: {t['status']}")
    return "\n".join(lines)


async def generate_briefing(state: AgentState) -> dict[str, Any]:
    hosts = sorted(hosts_in_scope(state), key=lambda h: h.risk_score, reverse=True)
    cves = [
        {"id": c["id"], "cvss": c.get("score"), "severity": c.get("severity"),
         "known_exploited": c.get("known_exploited", False)}
        for c in state.cve_data[:MAX_CVES_IN_PROMPT]
    ]
    context = [{"id": c["id"], "cvss": c["score"], "os_group": c["os_group"]}
               for c in state.cve_context[:10]]

    plan_note = ""
    if state.plan_id:
        plan_note = (
            f"A patch plan with id {state.plan_id} was created and is WAITING FOR HUMAN APPROVAL. "
            "Nothing has been installed yet. Say so clearly and tell the user to approve it in the "
            "dashboard (or `/patch approve <id>` in Slack)."
        )

    prompt = f"""You are a senior security engineer writing a patch briefing for an operations team.
Be concise and concrete. Only state facts present in the data below; if data is missing or stale, say so.

REQUEST: {state.user_message[:1000]}
ACTION: {state.action.value}
SCOPE: {state.target_hosts or "all hosts"}

HOSTS ({len(hosts)}; highest risk first):
{json.dumps(_host_summary(hosts), indent=1)}

CVES REPORTED BY HOST PACKAGE ADVISORIES:
{json.dumps(cves, indent=1) if cves else "none reported"}

RECENT CRITICAL CVES FOR THESE OS FAMILIES (context only, not confirmed on any host):
{json.dumps(context, indent=1) if context else "none"}

PATCH PLAN: {json.dumps(_plan_summary(state)) if state.patch_plan else "none"}
{plan_note}
RECENT SEMAPHORE TASKS: {json.dumps(state.recent_tasks) if state.recent_tasks else "n/a"}
WARNINGS: {state.warnings or "none"}
ERRORS: {state.errors or "none"}

Write markdown with: a 2-3 sentence summary, critical findings (if any), recommended actions,
and a short breakdown by host group. No filler, no generic advice."""

    try:
        text = await _ask_llm("generate_briefing", prompt)
        if not text:
            raise ValueError("empty response")
    except Exception as exc:
        logger.warning("briefing_llm_failed", error=str(exc))
        text = fallback_briefing(state, reason=str(exc)[:200])
    logger.info("briefing_generated", length=len(text))
    return {"briefing": text, "ai_response": text}


# ═══════════════════════════════════════════════════════════════════════════
# 8. General questions
# ═══════════════════════════════════════════════════════════════════════════


async def handle_question(state: AgentState) -> dict[str, Any]:
    counts = {group: len(hosts) for group, hosts in state.inventory.items()}
    pending = {h.hostname: h.update_count for h in state.all_hosts if h.update_count}
    prompt = f"""You are the assistant of a patch management system built on Ansible and
Semaphore UI. It manages Ubuntu, Rocky Linux, macOS and Windows 10/11 hosts.

Inventory (hosts per group): {json.dumps(counts)}
Groups: {", ".join(state.known_groups)}
Hosts with pending updates (from the latest reports): {json.dumps(pending) if pending else "none or unknown"}

Playbooks:
- check_updates.yml: detect pending updates, write per-host reports (no changes)
- apply_patches.yml: install updates, send report (from the dashboard: only after a plan is approved)
- reboot_if_needed.yml: reboot only hosts that need it

Useful extra vars: patch_security_only=true, patch_dry_run=true, patch_reboot_allowed=false,
plus --limit <group_or_host>.

Conversation so far: {json.dumps(state.messages[-10:])}

Question: {state.user_message[:2000]}

Answer concisely in markdown. If the user wants something done, explain how; patching always
goes through a plan that a human approves."""

    try:
        text = await _ask_llm("handle_question", prompt)
        if not text:
            raise ValueError("empty response")
    except Exception as exc:
        logger.warning("qa_llm_failed", error=str(exc))
        text = (
            "The AI model is not reachable right now, so I can't answer free-form questions. "
            "Quick actions (Check Updates, Analyze Risk, Plan Patches) still work.\n\n"
            f"_Error: {str(exc)[:200]}_"
        )
    return {"ai_response": text}
