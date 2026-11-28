"""1.4.2: fixes from the review of 1.4.1, OVAL time limits, host data in answers."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
import respx
import yaml

from tests.conftest import _write_report
from tests.test_agent_api import client  # noqa: F401 (fixture)

ROOT = Path(__file__).resolve().parent.parent
ANSIBLE = Path(sys.executable).with_name("ansible-playbook")
AUTH = ("admin", "test-password-123")
CSRF = {"X-Requested-With": "patch-ai"}


# ─── ReDoS: manifest patterns go through RE2 ─────────────────────────────────

# The three patterns of the review that passed the 1.4.1 guard and hang re.
SLOW = ["(a|aa)+", "(a+){10}", "a?" * 40 + "a" * 40]


@pytest.mark.parametrize("pattern", SLOW)
def test_patterns_that_hang_re_match_in_linear_time(pattern):
    from app.services.capabilities import ParamSpec

    spec = ParamSpec(type="string", pattern=pattern)
    started = time.monotonic()
    with pytest.raises(ValueError, match="does not match"):
        spec.coerce("a" * 199 + "b")
    assert time.monotonic() - started < 0.5


@pytest.mark.parametrize("pattern", [r"(a)\1", r"(?=a)a"])
def test_patterns_re2_can_not_run_are_refused(pattern):
    from pydantic import ValidationError

    from app.services.capabilities import ParamSpec

    with pytest.raises(ValidationError, match="RE2"):
        ParamSpec(type="string", pattern=pattern)


@pytest.mark.parametrize(("pattern", "ok"), [
    *[(p, False) for p in SLOW],
    (r"[0-9]+(\.[0-9]+){0,2}", False),
    (r"[a-z0-9-]{1,63}", True), (r"(foo|bar)", True), (r"(?:foo|bar)-[0-9]{1,4}", True),
])
def test_without_re2_only_simple_patterns_load(monkeypatch, pattern, ok):
    from pydantic import ValidationError

    from app.services import capabilities
    from app.services.capabilities import ParamSpec

    monkeypatch.setattr(capabilities, "_re2", None)
    if ok:
        ParamSpec(type="string", pattern=pattern)
    else:
        with pytest.raises(ValidationError, match="google-re2 is not installed"):
            ParamSpec(type="string", pattern=pattern)


# ─── check_updates: the -security simulation can't fail the check ────────────

def _ubuntu_report_task() -> dict:
    plays = yaml.safe_load((ROOT / "playbooks/check_updates.yml").read_text())
    ubuntu = next(p for p in plays if p.get("hosts") == "ubuntu_servers")
    tasks = {t["name"]: t for t in ubuntu["tasks"]}
    sim = tasks["List the security updates (simulated, -security preferred)"]
    assert sim["failed_when"] is False
    return tasks["Build host report"]


@pytest.mark.skipif(not ANSIBLE.exists(), reason="ansible-playbook not installed")
@pytest.mark.parametrize(("sim", "security", "error"), [
    ({"rc": 0, "stderr": "",
      "stdout_lines": ["Inst openssl [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [arm64])",
                       "Inst curl [8.5.0-2ubuntu10.5] (8.5.0-2ubuntu10.6 Ubuntu:24.04/noble-updates [arm64])"]},
     ["openssl"], None),
    ({"rc": 100, "stdout_lines": [],
      "stderr": "E: Unable to correct problems, you have held broken packages."},
     ["libssl3"], "apt-get simulation failed (rc 100: E: Unable to correct problems, you have held broken "
                  "packages.); security updates taken from the apt list pockets"),
])
def test_security_list_falls_back_when_the_simulation_fails(tmp_path, sim, security, error):
    task = _ubuntu_report_task()
    expressions = {"security": "{{ security }}",
                   "security_check_error": task["ansible.builtin.set_fact"]["host_report"]["security_check_error"]}
    play = tmp_path / "t.yml"
    play.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False,
        "vars": {"apt_security_sim": sim, "apt_upgradable": {"stdout_lines": [
            "libssl3/noble-updates,noble-security 3.0.13-0ubuntu3.5 arm64 [upgradable from: 3.0.13-0ubuntu3.4]",
            "curl/noble-updates 8.5.0-2ubuntu10.6 arm64 [upgradable from: 8.5.0-2ubuntu10.5]"]}},
        "tasks": [{"name": "out", "ansible.builtin.copy": {
            "content": "{{ result | to_json }}", "dest": str(tmp_path / "out.json"), "mode": "0600"},
            "vars": {**{k: v for k, v in task["vars"].items() if k in ("upgradable", "sim_ok", "security")},
                     "result": expressions}}],
    }]))
    run = subprocess.run([str(ANSIBLE), "-i", "localhost,", "-c", "local", str(play)],  # noqa: S603 (fixed arguments)
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stdout[-2000:]
    out = json.loads((tmp_path / "out.json").read_text())
    assert out["security"] == security
    assert (out["security_check_error"] or None) == error


def test_reader_and_prompt_carry_the_security_check_note(env):
    from app.agents.nodes import _host_summary, host_cards
    from app.agents.state import HostInfo
    from app.tools.report_reader import ReportReader

    _write_report(env["reports"], "ubuntu-web-01", os="Ubuntu 24.04",
                  security_check_error="apt-get simulation failed (rc 100: E: broken)")
    host = HostInfo(hostname="ubuntu-web-01", ip="x", os_group="ubuntu_servers")
    ReportReader().enrich([host])
    assert host.security_check_note.startswith("apt-get simulation failed")
    assert _host_summary([host])[0]["security_check"] == host.security_check_note
    assert host_cards([host])[0]["security_check"] == host.security_check_note


# ─── Docker Update: a service new in the compose file ────────────────────────

@pytest.mark.skipif(not ANSIBLE.exists(), reason="ansible-playbook not installed")
def test_old_image_ids_skip_a_reference_that_is_new(tmp_path):
    text = (ROOT / "playbooks/tasks/docker_project.yml").read_text()
    line = next(x for x in text.splitlines() if x.strip().startswith("old_image_ids:"))
    expression = yaml.safe_load(line.strip())["old_image_ids"]
    play = tmp_path / "t.yml"
    play.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False,
        "vars": {"before_ids": {"nginx:1": "sha256:aaa", "db:2": "sha256:bbb"},
                 "updated_images": ["nginx:1", "redis:7"]},
        "tasks": [{"name": "out", "ansible.builtin.copy": {
            "content": "{{ ids | to_json }}", "dest": str(tmp_path / "out.json"), "mode": "0600"},
            "vars": {"ids": expression}}],
    }]))
    run = subprocess.run([str(ANSIBLE), "-i", "localhost,", "-c", "local", str(play)],  # noqa: S603 (fixed arguments)
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stdout[-2000:]
    assert json.loads((tmp_path / "out.json").read_text()) == ["sha256:aaa"]


# ─── Intent fallback: "no" before a noun is not a negated verb ───────────────

@pytest.mark.parametrize(("message", "action"), [
    ("no patches pending?", "check_updates"),
    ("¿no hay parches pendientes?", "check_updates"),
    ("sin parches pendientes, ¿verdad?", "check_updates"),
    ("don't patch Bluma, what's the risk?", "analyze_risk"),
    ("no parchees Bluma, ¿qué riesgo tiene?", "analyze_risk"),
    ("no actualices, solo dime el riesgo", "analyze_risk"),
    ("no las instales todavía, ¿qué riesgo tienen?", "analyze_risk"),
])
def test_negation_keeps_nouns(message, action):
    from app.agents.intent import keyword_intent

    assert keyword_intent(message, {"Bluma"}).action == action


# ─── ISPConfig: sha256 pinned on the first download (TOFU) ───────────────────

def _ispconfig_tar(path: Path, extra: bytes = b"") -> None:
    import io
    import tarfile

    from tests.test_ispconfig import SAMPLE_333P2

    with tarfile.open(path, "w:gz") as tar:
        for name, data in [("ispconfig3_install/docs/autoinstall_samples/autoinstall.ini.sample",
                            SAMPLE_333P2.encode()), ("ispconfig3_install/README", b"readme" + extra)]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def _prepare(tmp_path: Path, **extra_vars) -> subprocess.CompletedProcess:
    play = tmp_path / "t.yml"
    play.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False,
        "vars": {"ispconfig_target": "3.3.3p2", "patch_report_dir": str(tmp_path),
                 "ispconfig_pin_file": str(tmp_path / "ispconfig-sha256.json"),
                 "ispconfig_download_url": f"file://{tmp_path}/ISPConfig-{{version}}.tar.gz",
                 **extra_vars},
        "tasks": [
            {"name": "prepare", "ansible.builtin.include_tasks": str(ROOT / "playbooks/tasks/ispconfig_prepare_update.yml")},
            {"name": "out", "ansible.builtin.copy": {
                "content": "{{ {'source': ispconfig_sha256_source, 'sha': ispconfig_download.stat.checksum} | to_json }}",
                "dest": str(tmp_path / "out.json"), "mode": "0600"}},
            {"name": "clean", "ansible.builtin.file": {"path": "{{ ispconfig_tmp.path }}", "state": "absent"}},
        ]}]))
    # The task file copies files/ispconfig_autoupdate.py from playbook_dir.
    (tmp_path / "files").mkdir(exist_ok=True)
    (tmp_path / "files" / "ispconfig_autoupdate.py").write_bytes(
        (ROOT / "playbooks/files/ispconfig_autoupdate.py").read_bytes())
    return subprocess.run([str(ANSIBLE), "-i", "localhost,", "-c", "local", str(play),  # noqa: S603 (fixed arguments)
                           "-e", f"ansible_python_interpreter={sys.executable}"],
                          capture_output=True, text=True, timeout=180)


@pytest.mark.skipif(not ANSIBLE.exists(), reason="ansible-playbook not installed")
def test_first_download_pins_the_sha256_and_a_changed_file_is_refused(tmp_path):
    import hashlib

    tar = tmp_path / "ISPConfig-3.3.3p2.tar.gz"
    _ispconfig_tar(tar)
    run = _prepare(tmp_path)
    assert run.returncode == 0, run.stdout[-3000:]
    sha = hashlib.sha256(tar.read_bytes()).hexdigest()
    assert json.loads((tmp_path / "out.json").read_text()) == {"source": "none", "sha": sha}
    assert json.loads((tmp_path / "ispconfig-sha256.json").read_text()) == {"3.3.3p2": sha}

    run = _prepare(tmp_path)                       # same file: checked against the pin
    assert run.returncode == 0, run.stdout[-3000:]
    assert json.loads((tmp_path / "out.json").read_text())["source"] == "pinned"

    _ispconfig_tar(tar, extra=b" changed upstream")
    run = _prepare(tmp_path)                       # same version, other file: refused
    assert run.returncode != 0 and "checksum" in run.stdout.lower()
    assert json.loads((tmp_path / "ispconfig-sha256.json").read_text()) == {"3.3.3p2": sha}


@pytest.mark.skipif(not ANSIBLE.exists(), reason="ansible-playbook not installed")
def test_required_sha256_is_satisfied_by_a_pin(tmp_path):
    _ispconfig_tar(tmp_path / "ISPConfig-3.3.3p2.tar.gz")
    run = _prepare(tmp_path, ispconfig_require_sha256=True)
    assert run.returncode != 0 and "neither in ispconfig_sha256 nor pinned" in run.stdout
    assert _prepare(tmp_path).returncode == 0
    assert _prepare(tmp_path, ispconfig_require_sha256=True).returncode == 0


# ─── Approval: an unreadable inventory is not "nothing changed" ──────────────

@respx.mock
async def test_approval_refused_when_the_inventory_cant_be_read(client, fake_llm, env):  # noqa: F811
    fake_llm()
    r = await client.post("/api/action/plan-patches", auth=AUTH, headers=CSRF, json={"target_hosts": "ubuntu_servers"})
    plan_id = r.json()["plan_id"]
    (env["tmp"] / "hosts.yml").write_text("all: [not, a, mapping\n")
    tasks = respx.post("http://semaphore.test/api/project/1/tasks")
    r = await client.post(f"/api/plans/{plan_id}/approve", auth=AUTH, headers=CSRF)
    assert r.status_code != 200 and "can't be read" in r.text
    assert not tasks.called


# ─── Answers carry the hosts' own data ───────────────────────────────────────

async def test_question_about_a_host_without_updates_gets_its_data(client, fake_llm, env):  # noqa: F811
    # 1.4.1 said Backup was not in the inventory: it only had counts and the
    # hosts with pending updates, and Backup had none.
    _write_report(env["reports"], "ubuntu-web-01", os="Ubuntu 24.04", update_count=0,
                  release_upgrade_to="26.04.1 LTS")
    fake = fake_llm(intent={"action": "ask_question", "target_hosts": "ubuntu-web-01"})
    r = await client.post("/api/chat", auth=AUTH, headers=CSRF,
                          json={"message": "what would a release upgrade do on ubuntu-web-01?"})
    assert r.status_code == 200
    prompt = fake.prompts["handle_question"][0]
    assert '"host":"ubuntu-web-01"' in prompt and '"release_upgrade_to":"26.04.1 LTS"' in prompt
    assert "it is still in the inventory" in prompt


async def test_question_without_target_gets_no_host_cards(client, fake_llm, env):  # noqa: F811
    fake = fake_llm()
    await client.post("/api/chat", auth=AUTH, headers=CSRF, json={"message": "how does patching work?"})
    assert "Hosts the question is about" not in fake.prompts["handle_question"][0]


async def test_action_without_reports_explains_null_and_gets_host_data(client, fake_llm, env, monkeypatch):  # noqa: F811
    from app.config import get_settings
    from app.services.capabilities import reload_registry
    from tests.test_capabilities import DEPLOY, _write

    directory = env["tmp"] / "capabilities.d"
    directory.mkdir(mode=0o750)
    directory.chmod(0o750)
    _write(directory, "widget_deploy.yml", {**DEPLOY, "reports": {"path": "widget-deploys/{host}.json"}})
    monkeypatch.setenv("CAPABILITIES_PATH", str(directory))
    get_settings.cache_clear()
    reload_registry()
    try:
        _write_report(env["reports"], "ubuntu-web-01", os="Ubuntu 24.04", release_upgrade_to="26.04.1 LTS")
        fake = fake_llm(intent={"action": "capability", "capability": "widget_deploy",
                                "target_hosts": "ubuntu-web-01"})
        r = await client.post("/api/chat", auth=AUTH, headers=CSRF, json={"message": "widget deploy on ubuntu-web-01?"})
        assert r.status_code == 200 and not r.json()["has_plan"]
        prompt = fake.prompts["handle_question"][0]
        assert '"widget_deploy" action' in prompt and "has not been run on that host" in prompt
        assert "Latest Check Updates data" in prompt and '"release_upgrade_to":"26.04.1 LTS"' in prompt
        assert "Do not ask the" in prompt
    finally:
        monkeypatch.delenv("CAPABILITIES_PATH")
        get_settings.cache_clear()
        reload_registry()


# ─── Docker Update manifest ──────────────────────────────────────────────────

def test_docker_update_example_manifest_loads(tmp_path):
    import shutil

    from app.services.capabilities import CapabilityRegistry

    directory = tmp_path / "capabilities.d"
    directory.mkdir(mode=0o750)
    directory.chmod(0o750)
    for name in ("docker_check.yml", "docker_update.yml"):
        shutil.copy(ROOT / "config/capabilities.d.example" / name, directory / name)
        (directory / name).chmod(0o640)
    status = CapabilityRegistry(str(directory)).load().status()
    assert status["errors"] == []
    update = next(c for c in status["capabilities"] if c["name"] == "docker_update")
    assert update["risk"] == "changes" and update["template"] == "Docker Update"


@pytest.mark.parametrize(("message", "capability"), [
    ("actualizar docker de joplin", "docker_update"),
    ("hay imágenes docker nuevas?", "docker_check"),
    ("docker check en joplin", "docker_check"),
])
def test_longest_keyword_picks_the_capability(message, capability):
    from app.agents.intent import capability_from_text

    caps = [("docker_check", ["docker", "docker check", "imágenes docker"]),
            ("docker_update", ["actualizar docker", "docker update"])]
    assert capability_from_text(message, caps) == capability
