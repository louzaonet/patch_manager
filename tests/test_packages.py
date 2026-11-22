"""1.0.4: "which version of X is installed?" from the inventory and from a live query."""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest
import respx
import yaml

AUTH = ("admin", "test-password-123")
CSRF = {"X-Requested-With": "patch-ai"}
REPO = Path(__file__).resolve().parent.parent
SEM = "http://semaphore.test/api/project/1"


@pytest.fixture
async def client(env):
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest.fixture
def packages(env):
    """Inventories: web has nginx, rocky has none, db has no inventory yet."""
    base = env["reports"] / "packages"
    base.mkdir(parents=True)

    def write(host, pkgs, collected="2026-11-22T10:00:00Z"):
        (base / f"{host}.json").write_text(json.dumps({"schema": 1, "host": host,
                                                       "collected_at": collected, "packages": pkgs}))

    write("ubuntu-web-01", {"nginx": "1.24.0-2ubuntu7.19", "nginx-common": "1.24.0-2ubuntu7.19",
                            "python3": "3.12.3-0ubuntu2.1", "python3-apt": "2.7.7ubuntu5",
                            "openssl": "3.0.13-0ubuntu3.16", "openssh-server": "1:9.6p1-3ubuntu13.14",
                            "bad name;": "1", "curl": "$(id)"})
    write("rocky-app-01", {"openssl": "3.2.2-6.el10", "kernel": "6.12.0-55.el10, 6.12.0-60.el10"})
    return base


async def _ask(client, message):
    r = await client.post("/api/chat", auth=AUTH, headers=CSRF, json={"message": message})
    assert r.status_code == 200, r.text
    return r.json()


# ─── Intent ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("message", "package", "live"), [
    ("dime que version de nginx tenemos instalada", "nginx", False),
    ("¿Qué versión de openssl hay ahora?", "openssl", True),
    ("which version of openssh-server is installed right now", "openssh-server", True),
    ("is curl installed on ubuntu_servers?", "curl", False),
    ("qué hosts tienen docker.io instalado", "docker.io", False),
    ("nginx version", "nginx", False),
    ("version of nginx; rm -rf /", "nginx", False),
])
def test_keyword_package_intent(message, package, live):
    from app.agents.intent import keyword_intent

    intent = keyword_intent(message, {"ubuntu_servers"})
    assert (intent.action, intent.package, intent.live) == ("package_query", package, live)


def test_llm_package_is_validated():
    from app.agents.intent import parse_intent

    assert parse_intent('{"action": "package_query", "package": "nginx; id"}').package is None
    assert parse_intent('{"action": "package_query", "package": "openssl*"}').package == "openssl*"


def test_playbook_and_service_share_the_name_rule():
    from app.agents.intent import PACKAGE_RE

    plays = yaml.safe_load((REPO / "playbooks" / "package_query.yml").read_text())
    that = plays[0]["tasks"][0]["ansible.builtin.assert"]["that"]
    rule = next(c for c in that if c.startswith("package_query is match("))
    assert re.search(r"match\('(.+)'\)", rule).group(1) == PACKAGE_RE.pattern


# ─── Answers from the inventory ─────────────────────────────────────────


async def test_answer_from_inventory(client, packages, fake_llm):
    fake = fake_llm(intent={"action": "package_query", "package": "nginx"})
    data = await _ask(client, "which version of nginx do we have?")
    text = data["response"]
    assert data["action"] == "package_query" and data["risk_summary"] is None
    assert "**nginx**: installed on 1 of 3 checked hosts" in text
    assert "| ubuntu-web-01 | nginx | 1.24.0-2ubuntu7.19 |" in text
    assert "Not installed on: rocky-app-01." in text
    assert "No data for: ubuntu-db-01 (no package inventory yet" in text
    assert "mac-build-01, win-desktop-01" in text  # not checked
    assert "generate_briefing" not in fake.prompts  # no LLM wrote the answer


async def test_keyword_fallback_without_llm(client, packages, fake_llm):
    fake_llm(fail={"classify_intent"})
    text = (await _ask(client, "qué versión de openssl tenemos"))["response"]
    assert "| rocky-app-01 | openssl | 3.2.2-6.el10 |" in text
    assert "| ubuntu-web-01 | openssl | 3.0.13-0ubuntu3.16 |" in text
    versions = next(line for line in text.splitlines() if line.startswith("Versions: "))
    assert "3.0.13-0ubuntu3.16 (1 host)" in versions and "3.2.2-6.el10 (1 host)" in versions


async def test_prefix_when_no_exact_name(client, packages, fake_llm):
    fake_llm(intent={"action": "package_query", "package": "python"})
    text = (await _ask(client, "python version"))["response"]
    assert "No package is called exactly `python`" in text
    assert "| ubuntu-web-01 | python3 | 3.12.3-0ubuntu2.1 |" in text


async def test_target_and_sanitised_inventory(client, packages, fake_llm):
    fake_llm(intent={"action": "package_query", "package": "curl", "target_hosts": "ubuntu-web-01"})
    text = (await _ask(client, "is curl installed on ubuntu-web-01?"))["response"]
    # "$(id)" is not a valid version: dropped when the inventory is read.
    assert "installed on 0 of 1 checked hosts" in text and "$(id)" not in text


async def test_no_package_name(client, packages, fake_llm):
    fake_llm(intent={"action": "package_query", "package": "$(id)"})
    with respx.mock(assert_all_called=False) as router:
        tasks = router.post(f"{SEM}/tasks")
        text = (await _ask(client, "tell me about $(id) right now"))["response"]
    assert text.startswith("Which package?") and not tasks.called


# ─── Live query through Semaphore ───────────────────────────────────────


@pytest.fixture
def fast_poll(monkeypatch):
    monkeypatch.setattr("app.agents.packages.POLL_SECONDS", 0.01)


@respx.mock
async def test_live_query(client, env, packages, fake_llm, fast_poll):
    fake_llm(intent={"action": "package_query", "package": "nginx", "live": True})
    respx.get(f"{SEM}/templates").mock(return_value=httpx.Response(
        200, json=[{"id": 9, "name": "Package Query"}, {"id": 7, "name": "Apply Patches"}]))
    sent = {}

    def start(request):
        # Stand in for package_query.yml: write the answers of two hosts.
        body = json.loads(request.content)
        sent.update(body)
        extra = json.loads(body["environment"])
        out = env["reports"] / "package-queries" / extra["package_query_id"]
        out.mkdir(parents=True)
        (out / "ubuntu-web-01.json").write_text(json.dumps(
            {"host": "ubuntu-web-01", "matches": [{"name": "nginx", "version": "1.26.0-1"}]}))
        (out / "rocky-app-01.json").write_text(json.dumps({"host": "rocky-app-01", "matches": []}))
        return httpx.Response(201, json={"id": 42, "status": "waiting"})

    respx.post(f"{SEM}/tasks").mock(side_effect=start)
    respx.get(f"{SEM}/tasks/42").mock(side_effect=[
        httpx.Response(200, json={"id": 42, "status": "running"}),
        httpx.Response(200, json={"id": 42, "status": "error"}),
    ])
    text = (await _ask(client, "which version of nginx do we have right now?"))["response"]

    extra = json.loads(sent["environment"])
    assert sent["template_id"] == 9 and extra["package_query"] == "nginx"
    assert re.fullmatch(r"[0-9a-f]{16}", extra["package_query_id"])
    assert "Source: live query, Semaphore task #42 (ended as 'error'" in text
    assert "| ubuntu-web-01 | nginx | 1.26.0-1 |" in text  # live data, not the inventory
    assert "Not installed on: rocky-app-01." in text
    assert "No data for: ubuntu-db-01 (did not answer the live query)" in text


@respx.mock
async def test_live_query_timeout_falls_back(client, env, packages, fake_llm, fast_poll, monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv("PACKAGE_QUERY_TIMEOUT", "0.05")
    get_settings.cache_clear()
    fake_llm(intent={"action": "package_query", "package": "nginx", "live": True})
    respx.get(f"{SEM}/templates").mock(return_value=httpx.Response(200, json=[{"id": 9, "name": "Package Query"}]))
    respx.post(f"{SEM}/tasks").mock(return_value=httpx.Response(201, json={"id": 43}))
    respx.get(f"{SEM}/tasks/43").mock(return_value=httpx.Response(200, json={"id": 43, "status": "running"}))
    text = (await _ask(client, "nginx version now"))["response"]
    assert "still running" in text and "| ubuntu-web-01 | nginx | 1.24.0-2ubuntu7.19 |" in text


@respx.mock
async def test_live_query_without_template(client, packages, fake_llm, fast_poll):
    fake_llm(intent={"action": "package_query", "package": "nginx", "live": True})
    respx.get(f"{SEM}/templates").mock(return_value=httpx.Response(200, json=[{"id": 7, "name": "Apply Patches"}]))
    text = (await _ask(client, "nginx version now"))["response"]
    assert "template 'Package Query' does not exist" in text
    assert "Source: package inventory" in text


# ─── Playbooks ──────────────────────────────────────────────────────────


def test_check_updates_writes_package_inventory():
    plays = yaml.safe_load((REPO / "playbooks" / "check_updates.yml").read_text())
    for os_play in ("Check pending updates: Ubuntu", "Check pending updates: Rocky Linux"):
        play = next(p for p in plays if p["name"] == os_play)
        assert any(t["name"] == "List installed packages" for t in play["tasks"])
    report = next(p for p in plays if p["name"] == "Write host reports and send summary")
    assert any("packages/" in str(t.get("ansible.builtin.copy", {}).get("dest", "")) for t in report["tasks"])


def test_package_query_never_uses_a_shell():
    text = (REPO / "playbooks" / "package_query.yml").read_text()
    assert "ansible.builtin.shell" not in text and "argv:" in text


def test_matches_report_more_than_the_cap():
    from app.agents.packages import MAX_MATCHES_PER_HOST, _matches

    pkgs = {f"python3-mod{i:02d}": "1.0" for i in range(MAX_MATCHES_PER_HOST + 5)}
    assert len(_matches(pkgs, "python3*")) == MAX_MATCHES_PER_HOST + 1  # one extra: "there is more"
    assert _matches(pkgs, "python3") == []  # no wildcard: exact name only
