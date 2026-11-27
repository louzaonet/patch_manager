"""ISPConfig helpers (playbooks/files/ispconfig_autoupdate.py) and the 1.4.0 playbooks."""

from __future__ import annotations

import importlib.util
import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "playbooks/files/ispconfig_autoupdate.py"
_spec = importlib.util.spec_from_file_location("ispconfig_autoupdate", SCRIPT)
isp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(isp)

# [update] section of docs/autoinstall_samples/autoinstall.ini.sample in
# ISPConfig-3.3.3p2.tar.gz, as printed on a real host (plus a section before
# it, as in the real file).
SAMPLE_333P2 = """[install]
language=en
install_mode=standard

[update]
do_backup=yes
mysql_root_password=ispconfig
mysql_master_hostname=master.example.com
mysql_master_port=3306
mysql_master_root_user=root
mysql_master_root_password=ispconfig
mysql_master_database=dbispconfig
reconfigure_permissions_in_master_database=no
reconfigure_services=yes
ispconfig_port=8080
create_new_ispconfig_ssl_cert=no
reconfigure_crontab=yes
create_ssl_server_certs=y
ignore_hostname_dns=n
ispconfig_postfix_ssl_symlink=y
ispconfig_pureftpd_ssl_symlink=y

; These are for service-detection (defaulting to old behaviour where all changes were automatically accepted)
svc_detect_change_mail_server=yes
svc_detect_change_web_server=yes
svc_detect_change_dns_server=yes
svc_detect_change_xmpp_server=yes
svc_detect_change_firewall_server=yes
svc_detect_change_vserver_server=yes
svc_detect_change_db_server=yes
"""

# What ispconfig_update.yml sends by default: the answers given at the
# interactive prompts of ispconfig_update.sh (all its defaults).
DEFAULT_ANSWERS = {
    "do_backup": True,
    "reconfigure_permissions_in_master_database": False,
    "reconfigure_services": True,
    "ispconfig_port": "default",
    "create_new_ispconfig_ssl_cert": False,
    "reconfigure_crontab": True,
}


@pytest.mark.parametrize(("a", "b", "result"), [
    ("3.3.2p1", "3.3.3p2", "older"),
    ("3.3.3p2", "3.3.3p2", "same"),
    ("3.3.3p2", "3.3.3p1", "newer"),
    ("3.3.3", "3.3.3p1", "older"),
    ("3.3.1b1", "3.3.1", "older"),
    ("3.3.1rc1", "3.3.1", "older"),
    ("3.3.1b2", "3.3.1rc1", "older"),
    ("3.3", "3.3.0", "same"),
    ("3.2.12p1", "3.3", "older"),
    ("3.10", "3.9.9", "newer"),
])
def test_version_order(a, b, result):
    assert isp.compare(a, b) == result


@pytest.mark.parametrize("bad", ["", "3.3.x", "v3.3.3", "3.3.3-p1", "3.3.3p", "<html>"])
def test_bad_versions_are_refused(bad):
    with pytest.raises(ValueError):
        isp.version_key(bad)


def test_ini_with_the_default_answers():
    ini = isp.build_ini(SAMPLE_333P2, DEFAULT_ANSWERS)
    lines = ini.splitlines()
    assert lines[0] == "[update]"
    values = dict(line.split("=", 1) for line in lines[1:])
    # Every key of the sample, in its order, and nothing else.
    assert list(values) == [k for k, _ in isp.update_section(SAMPLE_333P2)]
    assert values["do_backup"] == "yes"
    assert values["reconfigure_services"] == "yes"
    assert values["reconfigure_permissions_in_master_database"] == "no"
    assert values["create_new_ispconfig_ssl_cert"] == "no"
    assert values["reconfigure_crontab"] == "yes"
    # No password or example hostname from the sample survives.
    for key in isp.DEFAULT_KEYS:
        assert values[key] == "default"
    assert "ispconfig" not in {values["mysql_root_password"], values["mysql_master_root_password"]}
    # Unanswered yes/no keys keep the sample's value and spelling.
    assert values["create_ssl_server_certs"] == "y"
    assert values["ignore_hostname_dns"] == "n"
    assert values["svc_detect_change_web_server"] == "yes"


def test_flags_keep_the_spelling_of_the_sample():
    values = dict(line.split("=", 1) for line in isp.build_ini(
        SAMPLE_333P2, {"create_ssl_server_certs": False, "reconfigure_services": False}).splitlines()[1:])
    assert values["create_ssl_server_certs"] == "n"       # y/n key
    assert values["reconfigure_services"] == "no"         # yes/no key: "n" hangs update.php


def test_a_string_that_doesnt_match_the_spelling_is_refused():
    with pytest.raises(isp.IniError, match="spelling"):
        isp.build_ini(SAMPLE_333P2, {"reconfigure_permissions_in_master_database": "n"})
    with pytest.raises(isp.IniError, match="spelling"):
        isp.build_ini(SAMPLE_333P2, {"create_ssl_server_certs": "no"})
    assert "reconfigure_crontab=default" in isp.build_ini(SAMPLE_333P2, {"reconfigure_crontab": "default"})


def test_a_key_the_sample_doesnt_have_is_refused():
    with pytest.raises(isp.IniError, match="reconfigure_everything"):
        isp.build_ini(SAMPLE_333P2, {**DEFAULT_ANSWERS, "reconfigure_everything": True})


def test_sample_without_update_section_is_refused():
    with pytest.raises(isp.IniError, match="no \\[update\\]"):
        isp.build_ini("[install]\nlanguage=en\n", {})


def test_multiline_values_are_refused():
    with pytest.raises(isp.IniError, match="multi-line"):
        isp.build_ini(SAMPLE_333P2, {"ispconfig_port": "8080\nreconfigure_services=no"})


@pytest.mark.parametrize("value", ["8080 # x", "abc;def", '"quoted"', "it's", "a=b", "[x]", " 8080", "a\tb"])
def test_values_that_would_change_the_ini_are_refused(value):
    # ";" and "#" start an INI comment: the answer would be cut and update.php
    # could fall back to a prompt.
    with pytest.raises(isp.IniError, match="can't contain"):
        isp.build_ini(SAMPLE_333P2, {"ispconfig_port": value})


def test_plain_values_pass():
    ini = isp.build_ini(SAMPLE_333P2, {"ispconfig_port": "8081", "mysql_master_hostname": "db-1.example.com"})
    assert "ispconfig_port=8081" in ini and "mysql_master_hostname=db-1.example.com" in ini


def test_cli_writes_a_private_file(tmp_path):
    sample = tmp_path / "autoinstall.ini.sample"
    sample.write_text(SAMPLE_333P2)
    out = tmp_path / "autoupdate.ini"
    run = subprocess.run([sys.executable, str(SCRIPT), "ini", "--sample", str(sample), "--out", str(out),  # noqa: S603 (fixed arguments)
                          "--answers", json.dumps(DEFAULT_ANSWERS)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert out.read_text() == isp.build_ini(SAMPLE_333P2, DEFAULT_ANSWERS)
    # The file is not printed: Semaphore keeps the output.
    assert "answers" in run.stdout and "[update]" not in run.stdout

    bad = subprocess.run([sys.executable, str(SCRIPT), "ini", "--sample", str(sample), "--out",  # noqa: S603 (fixed arguments)
                          str(tmp_path / "x.ini"), "--answers", '{"nope": true}'], capture_output=True, text=True)
    assert bad.returncode == 2 and "nope" in bad.stderr and not (tmp_path / "x.ini").exists()

    cmp = subprocess.run([sys.executable, str(SCRIPT), "compare", "3.3.2p1", "3.3.3p2"],  # noqa: S603 (fixed arguments)
                         capture_output=True, text=True)
    assert cmp.stdout.strip() == "older"


def test_playbook_default_answers_match_the_tested_ones():
    # The answers the update playbook sends are the ones tested above.
    plays = yaml.safe_load((ROOT / "playbooks/ispconfig_update.yml").read_text())
    assert plays[0]["vars"]["ispconfig_default_answers"] == DEFAULT_ANSWERS


def test_release_upgrade_uses_the_same_answers():
    plays = yaml.safe_load((ROOT / "playbooks/release_upgrade.yml").read_text())
    assert plays[0]["vars"]["ispconfig_default_answers"] == DEFAULT_ANSWERS


def test_example_manifests_for_ispconfig_and_release_upgrade(env):
    import shutil

    from app.services.capabilities import CapabilityRegistry

    directory = env["tmp"] / "caps"
    directory.mkdir(mode=0o750)
    for name in ("ispconfig_check", "ispconfig_update", "release_upgrade"):
        shutil.copy(ROOT / "config/capabilities.d.example" / f"{name}.yml", directory / f"{name}.yml")
        (directory / f"{name}.yml").chmod(0o640)
    reg = CapabilityRegistry(str(directory)).load()
    assert reg.errors == []
    check, update, release = (reg.get(n) for n in ("ispconfig_check", "ispconfig_update", "release_upgrade"))
    assert check.risk == "read_only" and check.include_in_analysis
    assert check.reports.path == "ispconfig-checks/{host}.json"
    assert update.risk == "changes" and update.limit_group == "ispconfig_servers"
    assert update.validate_params({"ispconfig_force": "true"})[0] == {"ispconfig_force": True}
    assert release.risk == "changes" and release.limit_group == "ubuntu_servers" and not release.params


# ─── Release upgrade offer in the Check Updates report ──────────────────

def _host(env, **fields):
    from app.agents.state import HostInfo
    from app.tools.report_reader import ReportReader
    from tests.conftest import _write_report

    _write_report(env["reports"], "ubuntu-web-01", os="Ubuntu 24.04", cve_source="ubuntu-usn-oval", **fields)
    host = HostInfo(hostname="ubuntu-web-01", ip="x", os_group="ubuntu_servers")
    ReportReader().enrich([host])
    return host


@pytest.mark.parametrize(("value", "kept"), [
    ("26.04.1 LTS", "26.04.1 LTS"), ("26.10", "26.10"), ("24.04 LTS", "24.04 LTS"),
    ("26.04.1 LTS; rm -rf", ""), ("<b>x</b>", ""), (None, ""), (2604, ""),
])
def test_reader_takes_only_well_formed_releases(env, value, kept):
    assert _host(env, release_upgrade_to=value).release_upgrade_to == kept


async def test_release_offer_reaches_prompt_email_and_dashboard(env, fake_llm):
    from app.agents import nodes
    from app.agents.state import ActionType, AgentState
    from app.services import mailer

    h = _host(env, release_upgrade_to="26.04.1 LTS")
    assert nodes._host_summary([h])[0]["release_upgrade_to"] == "26.04.1 LTS"
    row = nodes.risk_rows([h])[0]
    assert row["release_upgrade"] == "26.04.1 LTS"
    assert "Ubuntu 26.04.1 LTS available" in mailer._notes(row, ", ")
    fake = fake_llm()
    await nodes.generate_briefing(AgentState(user_message="x", action=ActionType.ANALYZE_RISK, all_hosts=[h]))
    assert "is the next Ubuntu release do-release-upgrade offers" in fake.prompts["generate_briefing"][0]

    failed = _host(env, release_check_error="could not reach the Ubuntu release list (changelogs.ubuntu.com)")
    assert nodes._host_summary([failed])[0]["release_check"].startswith("release check failed: could not reach")
    assert "release_upgrade_to" not in nodes._host_summary([failed])[0]


# ─── Playbook pieces that run without hosts ────────────────────────────

ANSIBLE = Path(sys.executable).with_name("ansible-playbook")


@pytest.mark.skipif(not ANSIBLE.exists(), reason="ansible-playbook not installed")
def test_web_compare_flags_only_what_broke(tmp_path):
    play = tmp_path / "t.yml"
    play.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False,
        "tasks": [
            {"name": "compare", "ansible.builtin.include_tasks": str(ROOT / "playbooks/tasks/web_compare.yml"),
             "vars": {
                 "web_status_before": {"service": {"apache2": "active", "mariadb": "active", "nginx": "inactive"},
                                       "fpm": 2, "panel": "302",
                                       "site": {"a.com": "200", "b.com": "301", "c.com": "500", "d.com": "200"}},
                 "web_status_after": {"service": {"apache2": "active", "mariadb": "failed", "nginx": "inactive"},
                                      "fpm": 0, "panel": "000",
                                      "site": {"a.com": "200", "b.com": "502", "c.com": "500"}}}},
            {"name": "out", "ansible.builtin.copy": {"content": "{{ web_problems | to_json }}",
                                                     "dest": str(tmp_path / "out.json"), "mode": "0600"}},
        ]}]))
    run = subprocess.run([str(ANSIBLE), "-i", "localhost,", "-c", "local", str(play)],  # noqa: S603 (fixed arguments)
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stdout[-2000:]
    assert json.loads((tmp_path / "out.json").read_text()) == [
        "service mariadb: failed", "no php-fpm running (2 before)", "panel: 000",
        "site b.com: 502", "site d.com: gone"]
