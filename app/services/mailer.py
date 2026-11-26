"""
Risk report email: built from a finished analysis, sent over SMTP.

The briefing comes from an LLM, so it is treated as untrusted text: it is
HTML-escaped before the few markdown constructs it uses are turned into tags.
The host table is built from the structured risk data, not from the briefing.
"""

from __future__ import annotations

import html
import re
import smtplib
import ssl
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any

from app.agents.nodes import hosts_in_scope, risk_rows
from app.agents.state import AgentState
from app.config import Settings

# A host whose report is this much older than the newest one did not answer
# the latest Check Updates run (all reports of one run land within minutes).
MISSED_CHECK_MARGIN_HOURS = 1.0

_TABLE = "border-collapse:collapse;font-size:13px;margin:8px 0"
_TH = "border:1px solid #d1d5db;background:#f3f4f6;padding:4px 8px;text-align:left"
_TD = "border:1px solid #d1d5db;padding:4px 8px;text-align:left;vertical-align:top"
_CLASS_COLOURS = {"CRITICAL": "#dc2626", "HIGH": "#d97706", "MEDIUM": "#2563eb", "LOW": "#16a34a"}


class MailError(RuntimeError):
    pass


# ─── Markdown (subset) to HTML ────────────────────────────────────────────

_TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$")
_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_BULLET = re.compile(r"^\s*(?:[-*]|\d+\.)\s+(.*)$")


def _notes(r: dict[str, Any], sep: str) -> list[str]:
    """The Notes column of a host row."""
    out = []
    if r["kev"]:
        out.append("KEV: " + sep.join(r["kev"]))
    if r.get("kev_pro_only"):
        out.append("KEV (Ubuntu Pro): " + sep.join(r["kev_pro_only"]))
    if r.get("cves"):
        out.append(f"{r['cves']} CVE")
    if r.get("cves_pro_only"):
        out.append(f"{r['cves_pro_only']} CVE Ubuntu Pro")
    if r.get("kev_unfixed"):
        out.append("KEV, no fix: " + sep.join(r["kev_unfixed"]))
    no_fix = [f"{r[k]} {k.split('_')[1]}" for k in ("unfixed_critical", "unfixed_high") if r.get(k)]
    if no_fix:
        out.append("no fix: " + sep.join(no_fix))
    if r["reboot_required"]:
        out.append("reboot pending")
    return out


def _inline(text: str) -> str:
    """Inline markup on ALREADY ESCAPED text."""
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(^|[^*])\*([^*\n]+)\*", r"\1<em>\2</em>", text)
    return text


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def markdown_to_html(text: str) -> str:
    """Headings, lists, tables, code, bold and italics. Everything else is a paragraph."""
    lines = html.escape(text or "").split("\n")
    out: list[str] = []
    paragraph: list[str] = []
    items: list[str] = []

    def flush() -> None:
        if paragraph:
            out.append("<p>" + "<br>".join(_inline(p) for p in paragraph) + "</p>")
            paragraph.clear()
        if items:
            out.append("<ul>" + "".join(f"<li>{_inline(i)}</li>" for i in items) + "</ul>")
            items.clear()

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("```"):
            flush()
            block = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            out.append("<pre>" + "\n".join(block) + "</pre>")
        elif _TABLE_ROW.match(line) and i + 1 < len(lines) and _TABLE_SEP.match(lines[i + 1]):
            flush()
            head = _cells(line)
            rows = []
            i += 2
            while i < len(lines) and _TABLE_ROW.match(lines[i]):
                rows.append(_cells(lines[i]))
                i += 1
            i -= 1
            th = "".join(f'<th style="{_TH}">{_inline(c)}</th>' for c in head)
            body = "".join(
                "<tr>" + "".join(
                    f'<td style="{_TD}">{_inline(r[k] if k < len(r) else "")}</td>'
                    for k in range(len(head))
                ) + "</tr>"
                for r in rows
            )
            out.append(f'<table style="{_TABLE}"><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>')
        elif m := _HEADING.match(line):
            flush()
            level = max(3, min(len(m.group(1)) + 1, 6))  # h1/h2 -> h3: the email has its own h2
            out.append(f"<h{level}>{_inline(m.group(2))}</h{level}>")
        elif m := _BULLET.match(line):
            if paragraph:
                flush()
            items.append(m.group(1))
        elif not line.strip():
            flush()
        else:
            if items:
                flush()
            paragraph.append(line)
        i += 1
    flush()
    return "\n".join(out)


# ─── Report content ───────────────────────────────────────────────────────



def _age(hours: float | None) -> str:
    if hours is None:
        return "no report"
    if hours < 1:
        return f"{round(hours * 60)} min"
    if hours < 48:
        return f"{round(hours)} h"
    return f"{round(hours / 24)} days"


def missed_latest_check(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], float | None]:
    """Hosts without a report from the latest Check Updates run, and the newest report age."""
    ages = [r["report_age_hours"] for r in rows if r["report_age_hours"] is not None]
    newest = min(ages) if ages else None
    missed = [
        r for r in rows
        if r["report_age_hours"] is None
        or (newest is not None and r["report_age_hours"] > newest + MISSED_CHECK_MARGIN_HOURS)
    ]
    return missed, newest


def build_report_email(state: AgentState, settings: Settings, now: datetime) -> EmailMessage:
    rows = risk_rows(hosts_in_scope(state))
    missed, newest = missed_latest_check(rows)
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["risk_class"]] = counts.get(r["risk_class"], 0) + 1
    kev_hosts = [r["hostname"] for r in rows if r["kev"] or r.get("kev_pro_only") or r.get("kev_unfixed")]
    stale = newest is None or newest > settings.auto_analysis_fresh_hours

    # ── Subject: counts and flags only, no host names ──
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    summary = ", ".join(f"{counts[c]} {c}" for c in order if counts.get(c))
    flags = []
    if kev_hosts:
        flags.append(f"KEV on {len(kev_hosts)} host{'s' if len(kev_hosts) != 1 else ''}")
    if missed:
        flags.append(f"{len(missed)} missed the last check")
    if stale:
        flags.append("no fresh data")
    subject = (
        f"{settings.email_subject_prefix} {len(rows)} hosts"
        + (f": {summary}" if summary else "")
        + (f" ({'; '.join(flags)})" if flags else "")
        + f" · {now.strftime('%Y-%m-%d %H:%M %Z')}"
    ).strip()

    scope = state.target_hosts or "all hosts"
    notes: list[str] = []
    if newest is None:
        notes.append("No host has an update report. Has the Check Updates template ever run?")
    elif stale:
        notes.append(
            f"The newest host report is {_age(newest)} old. Check Updates probably did not run "
            "before this analysis (Semaphore schedule, or the task failed)."
        )
    if missed:
        listing = ", ".join(f"{r['hostname']} ({_age(r['report_age_hours'])})" for r in missed)
        notes.append(f"No report from the latest check (unreachable or failed): {listing}.")
    notes.extend(state.warnings)
    notes.extend(state.errors)

    # ── Plain text ──
    text_lines = [f"Patch risk report: {scope}, {now.strftime('%Y-%m-%d %H:%M %Z')}", ""]
    text_lines += [f"! {n}" for n in notes]
    if notes:
        text_lines.append("")
    text_lines.append(f"{'Host':<20} {'Risk':>6} {'Class':<9} {'Sec/Total':>10} {'Report':>9}  Notes")
    for r in rows:
        extra = _notes(r, ",")
        text_lines.append(
            f"{r['hostname'][:20]:<20} {r['risk_score']:>6} {r['risk_class']:<9} "
            f"{str(r['security_updates']) + '/' + str(r['updates']):>10} {_age(r['report_age_hours']):>9}  "
            + "; ".join(extra)
        )
    text_lines += ["", state.briefing or state.ai_response or "(no briefing)"]
    if settings.public_base_url:
        text_lines += ["", f"Dashboard: {settings.public_base_url}"]
    text = "\n".join(text_lines) + "\n"

    # ── HTML ──
    e = html.escape
    note_html = "".join(
        f'<p style="margin:4px 0;color:#92400e;background:#fef3c7;padding:6px 8px">{e(n)}</p>' for n in notes
    )
    table_rows = []
    for r in rows:
        colour = _CLASS_COLOURS.get(r["risk_class"], "#6b7280")
        extra = _notes(r, ", ")
        # Risk factors are left to the briefing: in the table they only
        # repeated the update counts.
        nw = f"{_TD};white-space:nowrap"
        table_rows.append(
            "<tr>"
            f'<td style="{nw}"><strong>{e(r["hostname"])}</strong></td>'
            f'<td style="{nw}">{e(r["os_name"] or r["os_group"])}</td>'
            f'<td style="{nw}">{r["risk_score"]}</td>'
            f'<td style="{nw};color:{colour};font-weight:600">{e(r["risk_class"])}</td>'
            f'<td style="{nw}">{r["security_updates"]} / {r["updates"]}</td>'
            f'<td style="{nw}">{e(_age(r["report_age_hours"]))}</td>'
            f'<td style="{_TD}">{e(" · ".join(extra))}</td>'
            "</tr>"
        )
    header = "".join(
        f'<th style="{_TH}">{h}</th>'
        for h in ("Host", "OS", "Risk", "Class", "Security / total", "Report", "Notes")
    )
    url = e(settings.public_base_url, quote=True)
    link = f'<p style="margin-top:16px"><a href="{url}">Open the dashboard</a></p>' if url else ""
    body_html = (
        '<!DOCTYPE html><html><body style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;'
        'font-size:14px;color:#111827;line-height:1.45">'
        f'<h2 style="margin:0 0 4px">Patch risk report</h2>'
        f'<p style="margin:0 0 12px;color:#6b7280">{e(scope)} · {e(now.strftime("%Y-%m-%d %H:%M %Z"))}</p>'
        f"{note_html}"
        f'<table style="{_TABLE}"><thead><tr>{header}</tr></thead>'
        f'<tbody>{"".join(table_rows)}</tbody></table>'
        f'<div style="margin-top:16px">{markdown_to_html(state.briefing or state.ai_response or "")}</div>'
        f"{link}</body></html>"
    )

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.email_from
    msg["To"] = ", ".join(settings.email_recipients)
    msg["Date"] = formatdate(usegmt=True)
    domain = settings.email_from.rsplit("@", 1)[-1].strip(">").strip() or None
    msg["Message-ID"] = make_msgid(domain=domain)
    msg.set_content(text)
    msg.add_alternative(body_html, subtype="html")
    return msg


# ─── Sending ──────────────────────────────────────────────────────────────


def send_email(msg: EmailMessage, settings: Settings) -> None:
    """Blocking SMTP send. Run it in a thread (asyncio.to_thread)."""
    mode = settings.smtp_secure.lower()
    context = ssl.create_default_context()
    try:
        if mode == "always":
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout, context=context
            )
        else:
            smtp = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout)
        with smtp:
            smtp.ehlo()
            if mode in ("starttls", "try"):
                if smtp.has_extn("starttls"):
                    smtp.starttls(context=context)
                    smtp.ehlo()
                elif mode == "starttls":
                    raise MailError("the SMTP server does not offer STARTTLS (set SMTP_SECURE=try or never)")
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(f"SMTP {settings.smtp_host}:{settings.smtp_port}: {exc}") from exc
