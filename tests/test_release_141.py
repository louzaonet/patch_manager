"""1.4.1: fixes from the external review."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import respx

# Fixtures defined in other test modules.
from tests.test_agent_api import client  # noqa: F401
from tests.test_release_103 import fake_smtp, mail_env  # noqa: F401


def test_report_dated_in_the_future_is_not_fresh(env):
    from app.agents.state import HostInfo
    from app.services.mailer import missed_latest_check
    from app.tools.report_reader import ReportReader
    from app.tools.risk_scorer import RiskScorer
    from tests.conftest import _write_report

    now = datetime.now(UTC)
    _write_report(env["reports"], "ubuntu-web-01", checked_at=(now + timedelta(days=365)).isoformat())
    _write_report(env["reports"], "ubuntu-db-01", checked_at=(now + timedelta(minutes=5)).isoformat())
    hosts = [HostInfo(hostname=h, ip="x", os_group="ubuntu_servers") for h in ("ubuntu-web-01", "ubuntu-db-01")]
    ReportReader().enrich(hosts)
    future, skewed = hosts
    assert future.report_age_hours is None and future.data_stale
    assert skewed.report_age_hours == 0.0 and not skewed.data_stale       # a few minutes is clock skew
    assert "no valid date" in RiskScorer().score_host(future).risk_factors[0]

    # One bad date no longer makes every other host "missed the last check".
    rows = [{"hostname": "a", "report_age_hours": None}, {"hostname": "b", "report_age_hours": 1.0},
            {"hostname": "c", "report_age_hours": 1.2}]
    missed, newest = missed_latest_check(rows)
    assert [r["hostname"] for r in missed] == ["a"] and newest == 1.0



@pytest.mark.parametrize(("message", "action", "flags"), [
    ("no actualices, solo dime el riesgo", "analyze_risk", {}),
    ("¿cuál es el riesgo de Bluma?", "analyze_risk", {}),
    ("actualiza Bluma", "apply_patches", {}),
    ("parchea los servidores ubuntu", "apply_patches", {}),
    ("aplica solo los parches de seguridad en Feliz", "apply_patches", {"security_only": True}),
    ("instala las actualizaciones sin reiniciar", "apply_patches", {"no_reboot": True}),
    ("simula el parcheo de Bluma", "apply_patches", {"dry_run": True}),
    ("¿qué actualizaciones hay pendientes?", "check_updates", {}),
    ("¿hay parches disponibles?", "check_updates", {}),
    ("¿cuántas actualizaciones tiene Feliz?", "check_updates", {}),
    ("estado de la última tarea", "status", {}),
    ("hazme un resumen", "generate_report", {}),
    ("don't install anything, what's the risk?", "analyze_risk", {}),
    ("install pending updates on Bluma", "apply_patches", {}),
    ("Bluma no está actualizado, actualízalo", "apply_patches", {}),
    ("instálalas en Feliz", "apply_patches", {}),
    ("no las instales todavía, ¿qué riesgo tienen?", "analyze_risk", {}),
])
def test_keyword_fallback_in_spanish(message, action, flags):
    # 1.4.1: the fallback without LLM only knew English.
    from app.agents.intent import keyword_intent

    intent = keyword_intent(message, {"Bluma", "Feliz"})
    assert intent.action == action
    for flag, value in flags.items():
        assert getattr(intent, flag) is value
    if "Bluma" in message:
        assert intent.target_hosts == "Bluma"


def test_smtp_try_never_logs_in_without_tls(mail_env, fake_smtp, monkeypatch):  # noqa: F811
    # 1.4.1 (point 3): with SMTP_SECURE=try a stripped STARTTLS offer used to
    # end in a cleartext login.
    from email.message import EmailMessage

    from app.services.mailer import MailError, send_email
    from tests.test_release_103 import _settings

    fake_smtp.offers_starttls = False
    with pytest.raises(MailError, match="not sending SMTP_PASSWORD in clear"):
        send_email(EmailMessage(), _settings(monkeypatch, SMTP_SECURE="try", SMTP_USER="relay", SMTP_PASSWORD="pw"))
    assert not any(c.startswith("login") for c in fake_smtp.instances[-1].calls)
    # Without a login, try still sends in clear; with STARTTLS offered, it logs in.
    send_email(EmailMessage(), _settings(monkeypatch, SMTP_SECURE="try", SMTP_USER=""))
    assert "send" in fake_smtp.instances[-1].calls
    fake_smtp.offers_starttls = True
    send_email(EmailMessage(), _settings(monkeypatch, SMTP_SECURE="try", SMTP_USER="relay", SMTP_PASSWORD="pw"))
    assert fake_smtp.instances[-1].calls[:3] == ["ehlo", "starttls", "ehlo"]
    assert "login:relay" in fake_smtp.instances[-1].calls


@pytest.mark.parametrize(("pattern", "ok"), [
    (r"(a+)+$", False), (r"(\w*)*x", False), (r"([a-z]+){2,}", False), (r"^(x|y+)*$", False),
    (r"[a-z0-9-]{1,63}", True), (r"(foo|bar)", True), (r"^(\d+\.){3}\d+$", True), (r"[a-z]+(-[a-z]+){0,3}", True),
])
def test_manifest_patterns_that_backtrack_are_refused(pattern, ok):
    # 1.4.1 (point 9): ReDoS guard on the patterns of string parameters.
    from pydantic import ValidationError

    from app.services.capabilities import ParamSpec

    if ok:
        ParamSpec(type="string", pattern=pattern)
    else:
        with pytest.raises(ValidationError, match="repeated group"):
            ParamSpec(type="string", pattern=pattern)


@respx.mock
async def test_approval_refused_when_the_limit_now_covers_more_hosts(client, fake_llm, env):  # noqa: F811
    # 1.4.1 (point 10): a group limit resolved again at approval time.
    from tests.test_agent_api import AUTH, CSRF

    fake_llm()
    r = await client.post("/api/action/plan-patches", auth=AUTH, headers=CSRF, json={"target_hosts": "ubuntu_servers"})
    plan_id = r.json()["plan_id"]
    inv = env["tmp"] / "hosts.yml"
    inv.write_text(inv.read_text().replace("        ubuntu-db-01:\n", "        ubuntu-new-01:\n          ansible_host: 10.0.0.99\n        ubuntu-db-01:\n", 1))
    tasks = respx.post("http://semaphore.test/api/project/1/tasks")
    r = await client.post(f"/api/plans/{plan_id}/approve", auth=AUTH, headers=CSRF)
    assert r.status_code != 200 and "ubuntu-new-01" in r.text
    assert not tasks.called


async def test_slack_and_teams_user_allowlists(client, env, monkeypatch):  # noqa: F811
    # 1.4.1 (point 8): optional allowlists for reading, not only for approving.
    import base64
    import hashlib
    import hmac
    import json

    from app.config import get_settings
    from tests.test_agent_api import _slack_headers

    monkeypatch.setattr("app.api.routes._spawn", lambda coro: coro.close())
    secret = base64.b64encode(b"teams-key").decode()
    for key, value in {"SLACK_ENABLED": "true", "SLACK_SIGNING_SECRET": "s3cret", "SLACK_APPROVER_IDS": "U111",
                       "SLACK_USER_IDS": "U333", "TEAMS_ENABLED": "true", "TEAMS_OUTGOING_SECRET": secret,
                       "TEAMS_WEBHOOK_URL": "https://example.test/workflow",
                       "TEAMS_USER_IDS": "AAAA-1111"}.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()

    async def slack(user):
        body = f"text=check+updates&user_id={user}&user_name=x".encode()
        r = await client.post("/api/integrations/slack", content=body, headers=_slack_headers("s3cret", body))
        return r.json()["text"]

    assert "not allowed" in await slack("U222")
    assert "Working on it" in await slack("U333")
    assert "Working on it" in await slack("U111")          # approvers can always use it

    async def teams(sender):
        body = json.dumps({"text": "<at>Bot</at> analyze risk", "from": sender}).encode()
        sig = base64.b64encode(hmac.new(b"teams-key", body, hashlib.sha256).digest()).decode()
        r = await client.post("/api/integrations/teams", content=body,
                              headers={"Authorization": f"HMAC {sig}", "Content-Type": "application/json"})
        return r.json()["text"]

    assert "not allowed" in await teams({"name": "Eve", "aadObjectId": "bbbb-2222"})
    assert "not allowed" in await teams({"name": "Eve"})
    assert "Working on it" in await teams({"name": "Ana", "aadObjectId": "aaaa-1111"})


def test_scheduler_lock_refuses_a_planted_link(tmp_path, monkeypatch):
    # 1.4.1: O_NOFOLLOW, and the lock must be a regular file of this user.
    import os

    from app.services import auto_analysis as mod

    target = tmp_path / "elsewhere"
    target.write_text("")
    link = tmp_path / "sched.lock"
    os.symlink(target, link)
    monkeypatch.setattr(mod, "LOCK_PATH", str(link))
    assert mod.AutoAnalysis()._acquire_lock() is False

    monkeypatch.setattr(mod, "LOCK_PATH", str(tmp_path / "ok.lock"))
    sched = mod.AutoAnalysis()
    assert sched._acquire_lock() is True
    os.close(sched._lock_fd)


def test_scheduler_lock_goes_to_the_runtime_directory(monkeypatch):
    import importlib

    from app.services import auto_analysis as mod

    monkeypatch.setenv("RUNTIME_DIRECTORY", "/run/patch-ai")
    assert importlib.reload(mod).LOCK_PATH == "/run/patch-ai/patch-ai-scheduler.lock"
    monkeypatch.delenv("RUNTIME_DIRECTORY")
    importlib.reload(mod)
