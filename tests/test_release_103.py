"""1.0.3: scheduled analysis by email, cron parser, reboot veto, prompt and lookup fixes."""

from __future__ import annotations

import asyncio
import contextlib
import email
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx
import pytest
import respx
import yaml

from app.agents.state import ActionType, AgentState
from app.services.cron import CronSchedule

AUTH = ("admin", "test-password-123")
CSRF = {"X-Requested-With": "patch-ai"}
REPO = Path(__file__).resolve().parent.parent
UTC_TZ = ZoneInfo("UTC")


@pytest.fixture
async def client(env):
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest.fixture
def mail_env(env, monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv("SMTP_HOST", "smtp.test")
    monkeypatch.setenv("SMTP_PORT", "25")
    monkeypatch.setenv("SMTP_SECURE", "never")
    monkeypatch.setenv("EMAIL_FROM", "notif@example.net")
    monkeypatch.setenv("EMAIL_TO", "ops@example.net, second@example.net")
    get_settings.cache_clear()
    return env


class FakeSMTP:
    """Records what would have been sent. STARTTLS support is configurable."""

    instances: list[FakeSMTP] = []
    offers_starttls = True
    fail_with: Exception | None = None

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port = host, port
        self.calls: list[str] = []
        self.sent: list[email.message.EmailMessage] = []
        FakeSMTP.instances.append(self)
        if FakeSMTP.fail_with:
            raise FakeSMTP.fail_with

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def has_extn(self, name):
        return name == "starttls" and FakeSMTP.offers_starttls

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(f"login:{user}")

    def send_message(self, msg):
        self.calls.append("send")
        self.sent.append(msg)


@pytest.fixture
def fake_smtp(monkeypatch):
    FakeSMTP.instances = []
    FakeSMTP.offers_starttls = True
    FakeSMTP.fail_with = None
    monkeypatch.setattr("app.services.mailer.smtplib.SMTP", FakeSMTP)
    monkeypatch.setattr("app.services.mailer.smtplib.SMTP_SSL", FakeSMTP)
    return FakeSMTP


# ─── Cron ───────────────────────────────────────────────────────────────


def test_cron_twice_a_day():
    s = CronSchedule.parse("15 12,0 * * *")
    start = datetime(2026, 11, 22, 11, 0, tzinfo=UTC_TZ)
    first = s.next_after(start, UTC_TZ)
    assert first == datetime(2026, 11, 22, 12, 15, tzinfo=UTC_TZ)
    assert s.next_after(first, UTC_TZ) == datetime(2026, 11, 23, 0, 15, tzinfo=UTC_TZ)


@pytest.mark.parametrize(("expr", "after", "expected"), [
    ("*/15 * * * *", datetime(2026, 1, 1, 10, 7), datetime(2026, 1, 1, 10, 15)),
    ("0 3 * * 7", datetime(2026, 11, 20, 12, 0), datetime(2026, 11, 22, 3, 0)),  # 7 = Sunday
    ("0 3 * * sun", datetime(2026, 11, 20, 12, 0), datetime(2026, 11, 22, 3, 0)),
    ("0 0 1 jan *", datetime(2026, 6, 1), datetime(2027, 1, 1)),
    ("30 6 1-7 * 6", datetime(2026, 11, 22), datetime(2026, 11, 28, 6, 30)),  # 1st-7th OR Saturday
    ("30 6 1-7 * 6", datetime(2026, 11, 28, 7), datetime(2026, 12, 1, 6, 30)),
    ("0 0 29 2 *", datetime(2026, 3, 1), datetime(2028, 2, 29)),
    ("5/20 * * * *", datetime(2026, 1, 1, 10, 26), datetime(2026, 1, 1, 10, 45)),
])
def test_cron_next_after(expr, after, expected):
    s = CronSchedule.parse(expr)
    assert s.next_after(after.replace(tzinfo=UTC_TZ), UTC_TZ) == expected.replace(tzinfo=UTC_TZ)


def test_utc_without_tz_database():
    from datetime import UTC as STDLIB_UTC

    from app.services.cron import resolve_tz

    assert resolve_tz("utc") is STDLIB_UTC and resolve_tz("Etc/UTC") is STDLIB_UTC


def test_cron_local_time_zone():
    madrid = ZoneInfo("Europe/Madrid")
    s = CronSchedule.parse("30 1 * * *")
    nxt = s.next_after(datetime(2026, 11, 22, 0, 0, tzinfo=UTC), madrid)
    assert (nxt.hour, nxt.minute) == (1, 30)
    assert nxt.astimezone(UTC).hour == 0  # 01:30 CET is 00:30 UTC


@pytest.mark.parametrize("expr", [
    "* * * *", "60 * * * *", "* 24 * * *", "5-1 * * * *", "*/0 * * * *", "x * * * *", "1,,2 * * * *",
])
def test_cron_rejects(expr):
    with pytest.raises(ValueError):
        CronSchedule.parse(expr)


def test_cron_that_never_matches():
    with pytest.raises(ValueError, match="never matches"):
        CronSchedule.parse("0 0 31 2 *").next_after(datetime(2026, 1, 1, tzinfo=UTC_TZ), UTC_TZ)


# ─── Configuration ──────────────────────────────────────────────────────


def _problems(monkeypatch, **values):
    from app.config import get_settings

    for key, value in values.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    return get_settings().startup_problems()


def test_schedule_config_ok(mail_env, monkeypatch):
    assert _problems(monkeypatch, AUTO_ANALYSIS_CRON="30 0,12 * * *", AUTO_ANALYSIS_TZ="Europe/Madrid") == []


@pytest.mark.parametrize(("values", "fragment"), [
    ({"AUTO_ANALYSIS_CRON": "30 0,12 * *"}, "AUTO_ANALYSIS_CRON"),
    ({"AUTO_ANALYSIS_CRON": "0 0 31 2 *"}, "never matches"),
    ({"AUTO_ANALYSIS_CRON": "30 0 * * *", "AUTO_ANALYSIS_TZ": "Mars/Olympus"}, "AUTO_ANALYSIS_TZ"),
    ({"SMTP_SECURE": "ssl"}, "SMTP_SECURE"),
    ({"EMAIL_TO": "ops@example.net\r\nBcc: x@evil.test"}, "not a valid email"),
    ({"EMAIL_FROM": "notif"}, "not a valid email"),
])
def test_schedule_config_problems(mail_env, monkeypatch, values, fragment):
    problems = _problems(monkeypatch, **values)
    assert any(fragment in p for p in problems), problems


def test_schedule_needs_email(env, monkeypatch):
    problems = _problems(monkeypatch, AUTO_ANALYSIS_CRON="30 0 * * *")
    assert any("needs SMTP_HOST" in p for p in problems)


# ─── Email content ──────────────────────────────────────────────────────


def test_markdown_to_html_escapes_and_renders():
    from app.services.mailer import markdown_to_html

    out = markdown_to_html(
        "## Summary\n**Bluma** <img src=x onerror=alert(1)>\n\n"
        "| Host | Risk |\n|---|---:|\n| Feliz | 55 |\n| <b>x</b> |\n\n- one\n- `two`"
    )
    assert "<img" not in out and "&lt;img" in out
    assert "<strong>Bluma</strong>" in out
    assert "<th" in out and ">Feliz</td>" in out and "&lt;b&gt;x&lt;/b&gt;" in out
    assert "<ul><li>one</li><li><code>two</code></li></ul>" in out


async def test_report_email_flags_missing_hosts(mail_env, fake_llm):
    from app.agents.graph import run_agent
    from app.config import get_settings
    from app.services.mailer import build_report_email

    fake_llm()
    state = await run_agent(AgentState(user_message="x", forced_action=ActionType.ANALYZE_RISK))
    msg = build_report_email(state, get_settings(), datetime(2026, 11, 22, 12, 30, tzinfo=UTC_TZ))

    subject = msg["Subject"]
    assert subject.startswith("[PATCH-AI] 5 hosts")
    # mac-build-01 (5 days old) and win-desktop-01 (no report) missed the last check.
    assert "2 missed the last check" in subject
    assert msg["To"] == "ops@example.net, second@example.net"
    text = msg.get_body(("plain",)).get_content()
    html_part = msg.get_body(("html",)).get_content()
    assert "mac-build-01 (5 days)" in text and "win-desktop-01 (no report)" in text
    assert "ubuntu-db-01" in html_part and "<h3>Briefing</h3>" in html_part
    # Highest risk first in the table.
    table = text[text.index("Sec/Total"):]
    assert table.index("rocky-app-01") < table.index("win-desktop-01")


def test_missed_latest_check():
    from app.services.mailer import missed_latest_check

    rows = [{"hostname": "a", "report_age_hours": 0.2}, {"hostname": "b", "report_age_hours": 0.5},
            {"hostname": "c", "report_age_hours": 12.4}, {"hostname": "d", "report_age_hours": None}]
    missed, newest = missed_latest_check(rows)
    assert newest == 0.2 and [r["hostname"] for r in missed] == ["c", "d"]


# ─── Sending ────────────────────────────────────────────────────────────


def _settings(monkeypatch, **values):
    from app.config import get_settings

    for key, value in values.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    return get_settings()


@pytest.mark.parametrize(("mode", "offers", "expected"), [
    ("never", True, ["ehlo", "send"]),
    ("starttls", True, ["ehlo", "starttls", "ehlo", "send"]),
    ("try", False, ["ehlo", "send"]),
    ("always", True, ["ehlo", "send"]),
])
def test_send_email_tls_modes(mail_env, fake_smtp, monkeypatch, mode, offers, expected):
    from email.message import EmailMessage

    from app.services.mailer import send_email

    fake_smtp.offers_starttls = offers
    send_email(EmailMessage(), _settings(monkeypatch, SMTP_SECURE=mode))
    assert fake_smtp.instances[-1].calls == expected


def test_send_email_starttls_required(mail_env, fake_smtp, monkeypatch):
    from email.message import EmailMessage

    from app.services.mailer import MailError, send_email

    fake_smtp.offers_starttls = False
    with pytest.raises(MailError, match="STARTTLS"):
        send_email(EmailMessage(), _settings(monkeypatch, SMTP_SECURE="starttls"))
    assert "send" not in fake_smtp.instances[-1].calls


def test_send_email_login_only_with_user(mail_env, fake_smtp, monkeypatch):
    from email.message import EmailMessage

    from app.services.mailer import send_email

    send_email(EmailMessage(), _settings(monkeypatch, SMTP_USER="relay", SMTP_PASSWORD="pw"))
    assert "login:relay" in fake_smtp.instances[-1].calls


# ─── Endpoint, dashboard and status ─────────────────────────────────────


async def test_email_report_endpoint(client, mail_env, fake_llm, fake_smtp):
    fake_llm()
    r = await client.post("/api/action/email-report", auth=AUTH, headers=CSRF)
    assert r.status_code == 200, r.text
    assert r.json()["sent"] is True and r.json()["recipients"] == 2
    sent = fake_smtp.instances[-1].sent[0]
    assert sent["From"] == "notif@example.net"
    info = (await client.get("/api/info", auth=AUTH)).json()["auto_analysis"]
    assert info["last_ok"] is True and info["last_detail"].startswith("[PATCH-AI]")


async def test_email_report_smtp_failure(client, mail_env, fake_llm, fake_smtp):
    fake_llm()
    fake_smtp.fail_with = ConnectionRefusedError(111, "Connection refused")
    r = await client.post("/api/action/email-report", auth=AUTH, headers=CSRF)
    assert r.status_code == 502 and "smtp.test:25" in r.json()["detail"]
    info = (await client.get("/api/info", auth=AUTH)).json()["auto_analysis"]
    assert info["last_ok"] is False


async def test_email_report_needs_config_and_csrf(client, fake_llm):
    fake_llm()
    assert (await client.post("/api/action/email-report", auth=AUTH)).status_code == 403
    r = await client.post("/api/action/email-report", auth=AUTH, headers=CSRF)
    assert r.status_code == 409


async def test_email_button_only_when_configured(client, monkeypatch):
    from app.config import get_settings

    assert "emailReportBtn" not in (await client.get("/", auth=AUTH)).text
    monkeypatch.setenv("SMTP_HOST", "smtp.test")
    monkeypatch.setenv("EMAIL_FROM", "a@example.net")
    monkeypatch.setenv("EMAIL_TO", "b@example.net")
    get_settings.cache_clear()
    assert "emailReportBtn" in (await client.get("/", auth=AUTH)).text


# ─── Scheduler ──────────────────────────────────────────────────────────


async def test_scheduler_runs_and_survives_failures(mail_env, monkeypatch):
    from app.services.auto_analysis import AutoAnalysis

    runner = AutoAnalysis()
    calls: list[str] = []

    async def fake_run_once(trigger):
        calls.append(trigger)
        if len(calls) == 1:
            raise RuntimeError("SMTP down")  # must not stop the schedule
        return {}

    class SoonSchedule:
        def next_after(self, moment, tz):
            return datetime.now(tz) + timedelta(milliseconds=20)

    monkeypatch.setattr(runner, "run_once", fake_run_once)
    task = asyncio.create_task(runner._loop(SoonSchedule(), UTC_TZ))
    for _ in range(100):
        if len(calls) >= 2:
            break
        await asyncio.sleep(0.02)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert calls[:2] == ["schedule", "schedule"]


async def test_scheduler_single_process(mail_env, monkeypatch, tmp_path):
    from app.config import get_settings
    from app.services import auto_analysis as mod

    monkeypatch.setattr(mod, "LOCK_PATH", str(tmp_path / "sched.lock"))
    monkeypatch.setenv("AUTO_ANALYSIS_CRON", "30 0,12 * * *")
    get_settings.cache_clear()
    first, second = mod.AutoAnalysis(), mod.AutoAnalysis()
    first.start()
    second.start()
    try:
        assert first.scheduler_here and not second.scheduler_here
        await asyncio.sleep(0)
        assert first.status()["next_run"] is not None
    finally:
        await first.stop()
        await second.stop()


# ─── Plans, Semaphore lookup, intent, prompt ────────────────────────────


def test_plan_does_not_force_reboots():
    from app.services.plans import PendingPlan

    base = dict(id="p1", created_at=0.0, expires_at=1.0, requested_by="t", source="web", request_text="x",
                limit=None, security_only=False, dry_run=False)
    assert "patch_reboot_allowed" not in PendingPlan(**base, no_reboot=False).extra_vars()
    assert PendingPlan(**base, no_reboot=True).extra_vars()["patch_reboot_allowed"] == "false"


@respx.mock
async def test_template_lookup_is_exact(env):
    from app.tools.semaphore_client import SemaphoreClient, SemaphoreError

    route = respx.get("http://semaphore.test/api/project/1/templates")
    route.mock(return_value=httpx.Response(200, json=[{"id": 3, "name": "Apply Patches (old)"},
                                                      {"id": 7, "name": " apply patches "}]))
    client = SemaphoreClient()
    assert (await client.find_template_by_name(1, "Apply Patches"))["id"] == 7
    route.mock(return_value=httpx.Response(200, json=[{"id": 3, "name": "Apply Patches (old)"}]))
    assert await client.find_template_by_name(1, "Apply Patches") is None
    route.mock(return_value=httpx.Response(200, json=[{"id": 3, "name": "Apply Patches"},
                                                      {"id": 4, "name": "Apply Patches"}]))
    with pytest.raises(SemaphoreError, match="Several templates"):
        await client.find_template_by_name(1, "Apply Patches")


@pytest.mark.parametrize(("message", "action"), [
    ("list pending patches", "check_updates"),
    ("Which hosts have pending patches?", "check_updates"),
    ("Are there updates pending on Bluma?", "check_updates"),
    ("Install pending updates on Bluma", "apply_patches"),
    ("Plan security-only patches on ubuntu_servers", "apply_patches"),
    ("patch Bluma", "apply_patches"),
])
def test_keyword_intent_reads_before_patching(message, action):
    from app.agents.intent import keyword_intent

    assert keyword_intent(message, set()).action == action


async def test_briefing_prompt_without_false_gaps(env, fake_llm):
    from app.agents.graph import run_agent

    fake = fake_llm()
    await run_agent(AgentState(user_message="risk", forced_action=ActionType.ANALYZE_RISK))
    prompt = fake.prompts["generate_briefing"][0]
    assert "RECENT SEMAPHORE TASKS" not in prompt
    assert "PATCH PLAN" not in prompt
    assert "Only Rocky Linux reports carry CVE ids" in prompt
    assert "newer than your training data" in prompt


async def test_risk_summary_fields(client, fake_llm):
    fake_llm()
    rows = (await client.post("/api/action/analyze-risk", auth=AUTH, headers=CSRF, json={})).json()["risk_summary"]
    assert len(rows) == 5
    assert {"risk_class", "os_name", "reboot_required"} <= rows[0].keys()
    assert rows == sorted(rows, key=lambda r: r["risk_score"], reverse=True)


# ─── Playbooks (static checks of the 1.0.3 rules) ───────────────────────


def _plays(name):
    return yaml.safe_load((REPO / "playbooks" / name).read_text())


def _tasks(play):
    for task in play.get("tasks", []):
        yield task
        for key in ("block", "rescue", "always"):
            yield from task.get(key, [])


def test_apply_patches_uses_effective_switches():
    plays = _plays("apply_patches.yml")
    os_plays = [p for p in plays if p["name"].startswith("Apply patches:")]
    assert len(os_plays) == 4
    for play in os_plays:
        assert "patch_do_dry_run" in play["vars"] and "patch_do_reboot" in play["vars"], play["name"]
    text = (REPO / "playbooks" / "apply_patches.yml").read_text()
    # Raw flags only appear in the switch definitions.
    assert text.count("(patch_dry_run | bool)") == 1
    assert text.count("(patch_reboot_allowed | bool)") == 1
    for play in os_plays:
        for task in _tasks(play):
            if task.get("name") == "Reboot":
                assert "patch_do_reboot | bool" in task["when"]


def test_check_updates_ignores_check_mode():
    for play in _plays("check_updates.yml"):
        assert play.get("check_mode") is False, play["name"]


def test_reboot_if_needed_honours_veto():
    for play in _plays("reboot_if_needed.yml"):
        reboots = [t for t in _tasks(play) if t.get("name") == "Reboot"]
        assert reboots and all(
            "not (patch_reboot_blocked | default(false) | bool)" in t["when"] for t in reboots
        ), play["name"]


def test_patch_reboot_blocked_not_in_group_vars_all():
    # Defined there, it would beat group vars written in hosts.yml.
    data = yaml.safe_load((REPO / "inventory" / "group_vars" / "all.yml").read_text())
    assert "patch_reboot_blocked" not in data


# ─── 1.0.4: docker_update.yml (static checks; the real runs are in CHANGELOG) ──


def test_docker_update_structure():
    plays = _plays("docker_update.yml")
    assert [p["hosts"] for p in plays] == ["docker_hosts", "docker_hosts"]
    tasks = {t["name"]: t for t in plays[0]["tasks"]}
    prune = tasks["Remove dangling images (only when every project is OK)"]
    assert any("FAILED" in cond for cond in prune["when"])  # keep old images when something failed
    project = yaml.safe_load((REPO / "playbooks" / "tasks" / "docker_project.yml").read_text())[0]
    assert project["rescue"], "a failed project must be recorded, not stop the host"
    names = [t["name"] for t in project["block"]]
    # No rollback: nothing after the failure check touches the containers.
    assert not any("down" in str(t.get("ansible.builtin.command", "")) for t in project["block"])
    assert names.index("Start the project: {{ docker_project }}") < names.index(
        "Wait until every container is running and healthy: {{ docker_project }}")


def test_docker_update_second_look():
    project = yaml.safe_load((REPO / "playbooks" / "tasks" / "docker_project.yml").read_text())[0]
    settle = next(t for t in project["block"] if t["name"].startswith("Make sure the containers stay up"))
    assert "docker_mode == 'update'" in settle["when"][0]
    names = [t["name"] for t in settle["block"]]
    assert any("restart counts again" in n for n in names)


def test_no_backslash_b_in_jinja_strings():
    # Jinja turns '\b' into a backspace inside a string, so a regex with \b never matches.
    for path in (REPO / "playbooks").rglob("*.yml"):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if "{{" in line or "search(" in line or "match(" in line:
                assert not re.search(r"'[^']*\\b[^']*'", line), f"{path.name}:{n}"
