"""
Package questions: "which version of nginx do we have installed?".

The answer is built from data, not written by the LLM, so a version can't be
made up. The data comes from:

- the package inventory that Check Updates writes for every Ubuntu and Rocky
  host (reports/packages/<host>.json): immediate, as old as the last check;
- a live run of the "Package Query" template in Semaphore when the user asks
  for current data. It only reads the package database on the hosts, so, like
  "Refresh host data", it does not need an approved plan.
"""

from __future__ import annotations

import asyncio
import fnmatch
import secrets
from collections import Counter
from typing import Any

import structlog

from app.agents.intent import PACKAGE_RE
from app.agents.nodes import hosts_in_scope
from app.agents.state import AgentState
from app.config import get_settings
from app.tools.report_reader import ReportReader
from app.tools.semaphore_client import SemaphoreClient, SemaphoreError

logger = structlog.get_logger()
audit = structlog.get_logger("audit")

SUPPORTED_GROUPS = ("ubuntu_servers", "rocky_servers")
POLL_SECONDS = 3.0
MAX_MATCHES_PER_HOST = 10
FINISHED = ("success", "error", "stopped", "rejected")


def _matches(packages: dict[str, str], pattern: str) -> list[tuple[str, str]]:
    """Matching (name, version) pairs; one more than the limit so the caller can tell."""
    if "*" in pattern:
        names = sorted(n for n in packages if fnmatch.fnmatchcase(n, pattern))
    else:
        names = [pattern] if pattern in packages else []
    return [(n, packages[n]) for n in names[: MAX_MATCHES_PER_HOST + 1]]


def _age(hours: float | None) -> str:
    if hours is None or hours < 0:
        return "?"
    if hours < 1:
        return f"{round(hours * 60)} min"
    return f"{round(hours)} h" if hours < 48 else f"{round(hours / 24)} days"


async def _live_query(
    name: str, limit: str | None, hostnames: list[str], requested_by: str
) -> tuple[dict[str, list[dict[str, str]] | None] | None, str]:
    """Run the Package Query template. Returns (results per host, note); results None = not run."""
    s = get_settings()
    client = SemaphoreClient()
    query_id = secrets.token_hex(8)
    try:
        project_id = await client.resolve_project_id()
        template = await client.find_template_by_name(project_id, s.semaphore_template_packages)
        if not template:
            return None, (f"the Semaphore template '{s.semaphore_template_packages}' does not exist, "
                          "so this comes from the inventory instead")
        task = await client.run_template(
            project_id, int(template["id"]),
            extra_vars={"package_query": name, "package_query_id": query_id},
            limit=limit, message=f"Package query '{name}' by {requested_by}",
        )
    except SemaphoreError as exc:
        return None, f"the live query could not start ({str(exc)[:200]}), so this comes from the inventory"

    task_id = task.get("id")
    audit.info("package_query_started", by=requested_by, package=name, limit=limit, task_id=task_id)
    loop = asyncio.get_running_loop()
    wait = min(s.package_query_timeout, s.request_wait_max)
    deadline = loop.time() + wait
    status = ""
    while loop.time() < deadline:
        await asyncio.sleep(POLL_SECONDS)
        try:
            status = str((await client.get_task(project_id, int(task_id))).get("status", ""))
        except (SemaphoreError, TypeError, ValueError):
            continue
        if status in FINISHED:
            break
    else:
        return None, (f"the live query (Semaphore task #{task_id}) was still running after "
                      f"{int(wait)} s, so this comes from the inventory")

    reader = ReportReader()
    results = {h: reader.read_query_result(query_id, h) for h in hostnames}
    note = f"live query, Semaphore task #{task_id}"
    if status != "success":
        note += f" (ended as '{status}': hosts without an answer were unreachable or failed)"
    return results, note


async def query_packages(state: AgentState) -> dict[str, Any]:
    name = state.package_name
    if not name or not PACKAGE_RE.match(name):
        text = ("Which package? Ask for example \"which version of nginx is installed?\" or "
                "\"is openssh-server installed on ubuntu_servers?\". Names use letters, digits and "
                "`+ . _ -`; `*` works as a wildcard.")
        return {"ai_response": text, "briefing": text}

    hosts = sorted(hosts_in_scope(state), key=lambda h: h.hostname.lower())
    supported = [h for h in hosts if h.os_group in SUPPORTED_GROUPS]
    unsupported = [h.hostname for h in hosts if h.os_group not in SUPPORTED_GROUPS]
    notes: list[str] = []

    live: dict[str, list[dict[str, str]] | None] | None = None
    source = ""
    if state.package_live and supported:
        live, source = await _live_query(name, state.target_hosts, [h.hostname for h in supported],
                                         state.requested_by)
        if live is None:
            notes.append(f"Note: {source}.")
            source = ""

    reader = ReportReader()
    found: dict[str, list[tuple[str, str]]] = {}  # host -> [(package, version)]
    prefix_note = ""
    ages: dict[str, float | None] = {}
    no_data: list[str] = []
    inventory: dict[str, dict[str, str]] = {}
    for host in supported:
        if live is not None:
            answer = live.get(host.hostname)
            if answer is None:
                no_data.append(host.hostname)
                continue
            found[host.hostname] = [(m["name"], m["version"]) for m in answer][: MAX_MATCHES_PER_HOST + 1]
            ages[host.hostname] = 0.0
            continue
        entry = reader.read_packages(host.hostname)
        if entry is None:
            no_data.append(host.hostname)
            continue
        inventory[host.hostname], ages[host.hostname] = entry
        found[host.hostname] = _matches(inventory[host.hostname], name)

    # "python" is not a package on Ubuntu, "python3" is: when nothing has the
    # exact name, show what starts with it (inventory only; a live query
    # already answered the question that was asked).
    if live is None and "*" not in name and not any(found.values()) and inventory:
        prefixed = {h: _matches(p, f"{name}*") for h, p in inventory.items()}
        if any(prefixed.values()):
            found = prefixed
            prefix_note = f"No package is called exactly `{name}`; these start with it."

    capped = any(len(m) > MAX_MATCHES_PER_HOST for m in found.values())
    found = {h: m[:MAX_MATCHES_PER_HOST] for h, m in found.items()}
    with_pkg = sorted(h for h, m in found.items() if m)
    without = sorted(h for h, m in found.items() if not m)
    if not source:
        known_ages = [a for h, a in ages.items() if a is not None and a >= 0]
        source = "package inventory from the last Check Updates" + (
            f" (between {_age(min(known_ages))} and {_age(max(known_ages))} old)"
            if known_ages and _age(min(known_ages)) != _age(max(known_ages))
            else f" ({_age(known_ages[0])} old)" if known_ages else ""
        )

    lines = [f"**{name}**: installed on {len(with_pkg)} of {len(supported)} checked hosts. "
             f"Source: {source}."]
    if prefix_note:
        lines.append(prefix_note)
    if capped:
        lines.append(f"Up to {MAX_MATCHES_PER_HOST} matches per host are shown; "
                     "ask with a more precise name.")
    lines.append("")
    if with_pkg:
        lines += ["| Host | Package | Version |", "|---|---|---|"]
        for host in with_pkg:
            for pkg, version in found[host]:
                lines.append(f"| {host} | {pkg} | {version} |")
        versions = Counter(v for h in with_pkg for p, v in found[h] if p == found[h][0][0])
        if len(versions) > 1:
            lines += ["", "Versions: " + ", ".join(
                f"{v} ({n} host{'s' if n != 1 else ''})" for v, n in versions.most_common())]
        lines.append("")
    if without:
        lines.append(f"Not installed on: {', '.join(without)}.")
    if no_data:
        why = ("did not answer the live query" if live is not None
               else "no package inventory yet; run Check Updates")
        lines.append(f"No data for: {', '.join(no_data)} ({why}).")
    if unsupported:
        lines.append("Not checked (macOS/Windows have no package database to ask): "
                     f"{', '.join(unsupported)}.")
    lines += notes
    if live is None and not state.package_live:
        lines += ["", "_Ask for it \"right now\" to check the hosts live._"]
    text = "\n".join(lines).strip()
    logger.info("package_query_answered", package=name, live=live is not None,
                hosts=len(supported), installed=len(with_pkg))
    return {"ai_response": text, "briefing": text}
