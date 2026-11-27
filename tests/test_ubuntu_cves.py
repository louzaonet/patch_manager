"""1.3.0: CVEs for Ubuntu hosts from Canonical's USN OVAL data.

The evaluator (playbooks/files/ubuntu_oval_cves.py) runs on the Ansible
controller; the AI service reads what it adds to reports/hosts/<host>.json.
"""

from __future__ import annotations

import bz2
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("ubuntu_oval_cves", ROOT / "playbooks/files/ubuntu_oval_cves.py")
oval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oval)


# ─── Debian version comparison ──────────────────────────────────────────

# Expected results taken from `dpkg --compare-versions` (dpkg 1.22, Ubuntu 24.04).
DPKG_CASES = [
    ("1.0~rc1", "1.0", "lt"),
    ("1.0", "1.0+b1", "lt"),
    ("1:0.9", "2.0", "gt"),
    ("2.0-1~esm1", "2.0-1", "lt"),
    ("2.0-1ubuntu0.1~esm2", "2.0-1ubuntu0.1", "lt"),
    ("2.4.52-1ubuntu4.27", "2.4.52-1ubuntu4.3", "gt"),
    ("0:7.0.0-1011", "0:7.0.0-1024", "lt"),
    ("1.2.3a", "1.2.3", "gt"),
    ("1.2.3~", "1.2.3", "lt"),
    ("2:1.8.1-1build1", "2:1.8.1-1ubuntu0.1", "lt"),
    ("4.5.1+git230720-4ubuntu2.5", "4.5.1+git230720-4ubuntu2.6", "lt"),
    ("2026e-0ubuntu0.24.04.1", "2026f-0ubuntu0.24.04.1", "lt"),
    ("3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.5", "eq"),
    ("1.0", "1.0-0", "eq"),
    ("1.0.0", "1.0", "gt"),
    ("10", "9", "gt"),
    ("1.01", "1.1", "eq"),
    ("1.0-1", "1.0-1.1", "lt"),
    ("1.13.1+dfsg-1ubuntu0.1~esm1", "1.13.1+dfsg-1ubuntu0.1", "lt"),
    ("6.8.0-149.149", "6.8.0-151.151", "lt"),
    ("2.42-4ubuntu2.10", "2.42-4ubuntu2.8", "gt"),
    ("1:0.9.10-1.1build1", "1:0.9.10-1.1ubuntu0.1", "lt"),
]


@pytest.mark.parametrize("a,b,expected", DPKG_CASES)
def test_version_compare_matches_dpkg(a, b, expected):
    c = oval.version_compare(a, b)
    assert ("lt" if c < 0 else "eq" if c == 0 else "gt") == expected
    r = oval.version_compare(b, a)
    assert ("gt" if r < 0 else "eq" if r == 0 else "lt") == expected


# ─── OVAL evaluation ────────────────────────────────────────────────────

NS = ('xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" '
      'xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" '
      'xmlns:ind-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" '
      'xmlns:unix-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" '
      'xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"')
P = "oval:com.ubuntu.resolute"


def _usn(n: int, usn: str, cves: list[str], severity: str, criteria: str) -> str:
    refs = "".join(f'<reference source="CVE" ref_id="{c}" ref_url="x"/>' for c in cves)
    return f"""
    <definition id="{P}:def:{n}" class="patch" version="1">
      <metadata><title>{usn} -- test vulnerability</title>
        <reference source="USN" ref_id="{usn}" ref_url="x"/>{refs}
        <advisory from="security@ubuntu.com"><severity>{severity}</severity></advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="{P}:def:100" comment="release"/>
        {criteria}
      </criteria>
    </definition>"""


def _dpkg(n: int, names: list[str], fixed: str) -> str:
    values = "".join(f"<value>{x}</value>" for x in names)
    return f"""
    <linux-def:dpkginfo_test id="{P}:tst:{n}" version="1" check="at least one" check_existence="at_least_one_exists">
      <linux-def:object object_ref="{P}:obj:{n}"/><linux-def:state state_ref="{P}:ste:{n}"/>
    </linux-def:dpkginfo_test>
    <!--OBJ--><linux-def:dpkginfo_object id="{P}:obj:{n}" version="1">
      <linux-def:name var_ref="{P}:var:{n}" var_check="at least one"/></linux-def:dpkginfo_object>
    <!--STE--><linux-def:dpkginfo_state id="{P}:ste:{n}" version="1">
      <linux-def:evr datatype="debian_evr_string" operation="less than">{fixed}</linux-def:evr></linux-def:dpkginfo_state>
    <!--VAR--><constant_variable id="{P}:var:{n}" version="1" datatype="string">{values}</constant_variable>"""


def build_oval() -> bytes:
    defs = [
        f"""<definition id="{P}:def:100" class="inventory" version="1">
          <metadata><title>Check that Ubuntu 26.04 LTS (resolute) is installed.</title></metadata>
          <criteria><criterion test_ref="{P}:tst:100"/><criterion test_ref="{P}:tst:101"/></criteria>
        </definition>""",
        # libssh: fixed in 0.11.3-1ubuntu2, free
        _usn(1, "USN-1-1", ["CVE-2026-0001"], "Medium", f'<criterion test_ref="{P}:tst:1"/>'),
        # imagemagick: fixed only in ESM (Ubuntu Pro)
        _usn(2, "USN-2-1", ["CVE-2026-0002", "CVE-2026-0003"], "Medium", f'<criterion test_ref="{P}:tst:2"/>'),
        # openssl: already fixed on the host
        _usn(3, "USN-3-1", ["CVE-2026-0004"], "High", f'<criterion test_ref="{P}:tst:3"/>'),
        # kernel: running linux-raspi older than 7.0.0-1024
        _usn(4, "USN-4-1", ["CVE-2026-0010", "CVE-2026-0011"], "High",
             f"""<criteria operator="OR"><criteria operator="AND">
                   <criterion test_ref="{P}:tst:40"/><criterion test_ref="{P}:tst:41"/>
                 </criteria></criteria>"""),
        # livepatch notice: never applies without livepatch
        f"""<definition id="{P}:def:5" class="patch" version="1">
          <metadata><title>LSN-0001-1 -- Kernel Live Patch Security Notice</title>
            <reference source="CVE" ref_id="CVE-2026-0020" ref_url="x"/></metadata>
          <criteria operator="OR"><criteria operator="AND">
            <criterion test_ref="{P}:tst:50"/><criterion test_ref="{P}:tst:51"/></criteria></criteria>
        </definition>""",
    ]
    parts = [_dpkg(1, ["libssh-4"], "0.11.3-1ubuntu2"),
             _dpkg(2, ["libmagickcore-7.q16-10"], "8:7.1.1.43+dfsg1-1ubuntu0.1~esm1"),
             _dpkg(3, ["libssl3t64"], "3.5.3-1ubuntu1")]
    tests = "".join(p.split("<!--OBJ-->")[0] for p in parts)
    objects = "".join(p.split("<!--OBJ-->")[1].split("<!--STE-->")[0] for p in parts)
    states = "".join(p.split("<!--STE-->")[1].split("<!--VAR-->")[0] for p in parts)
    variables = "".join(p.split("<!--VAR-->")[1] for p in parts)
    tests += f"""
      <ind-def:family_test id="{P}:tst:100" version="1" check="at least one"><ind-def:object object_ref="{P}:obj:100"/></ind-def:family_test>
      <ind-def:textfilecontent54_test id="{P}:tst:101" version="1" check="at least one"><ind-def:object object_ref="{P}:obj:101"/></ind-def:textfilecontent54_test>
      <unix-def:uname_test id="{P}:tst:40" version="1" check="at least one">
        <unix-def:object object_ref="{P}:obj:200"/><unix-def:state state_ref="{P}:ste:40"/></unix-def:uname_test>
      <ind-def:variable_test id="{P}:tst:41" version="1" check="all">
        <ind-def:object object_ref="{P}:obj:210"/><ind-def:state state_ref="{P}:ste:41"/></ind-def:variable_test>
      <unix-def:file_test id="{P}:tst:50" version="1" check="all">
        <unix-def:object object_ref="{P}:obj:50"/><unix-def:state state_ref="{P}:ste:50"/></unix-def:file_test>
      <ind-def:textfilecontent54_test id="{P}:tst:51" version="1" check="all">
        <ind-def:object object_ref="{P}:obj:51"/><ind-def:state state_ref="{P}:ste:51"/></ind-def:textfilecontent54_test>"""
    objects += f"""
      <unix-def:uname_object id="{P}:obj:200" version="1"/>
      <ind-def:variable_object id="{P}:obj:210" version="1"><ind-def:var_ref>{P}:var:200</ind-def:var_ref></ind-def:variable_object>
      <unix-def:file_object id="{P}:obj:50" version="1"><unix-def:filepath>/snap/bin/canonical-livepatch</unix-def:filepath></unix-def:file_object>"""
    states += f"""
      <unix-def:uname_state id="{P}:ste:40" version="1">
        <unix-def:os_release operation="pattern match">7\\.0\\.0\\-\\d+(\\-raspi|\\-raspi\\-realtime)</unix-def:os_release></unix-def:uname_state>
      <ind-def:variable_state id="{P}:ste:41" version="1">
        <ind-def:value datatype="debian_evr_string" operation="less than">0:7.0.0-1024</ind-def:value></ind-def:variable_state>"""
    variables += f"""
      <local_variable id="{P}:var:200" version="1" datatype="debian_evr_string"><concat>
        <literal_component>0:</literal_component>
        <regex_capture pattern="^([\\d|\\.]+-\\d+)[-|\\w]+$"><object_component object_ref="{P}:obj:200" item_field="os_release"/></regex_capture>
      </concat></local_variable>"""
    xml = f"""<?xml version="1.0"?>
<oval_definitions {NS}>
  <generator><oval:timestamp>2026-11-26T08:53:49</oval:timestamp></generator>
  <definitions>{"".join(defs)}</definitions>
  <tests>{tests}</tests><objects>{objects}</objects><states>{states}</states><variables>{variables}</variables>
</oval_definitions>"""
    return xml.encode()


@pytest.fixture(scope="module")
def index():
    import io

    return oval.compile_oval(lambda: io.BytesIO(build_oval()))


PI_PACKAGES = {
    "libssh-4": "0.11.3-1ubuntu1",                          # older than the fix
    "libmagickcore-7.q16-10": "8:7.1.1.43+dfsg1-1",         # fix only in ESM
    "libssl3t64": "3.5.3-1ubuntu2",                         # already fixed
    "linux-image-7.0.0-1023-raspi": "7.0.0-1023.23",
    "linux-image-7.0.0-1024-raspi": "7.0.0-1024.24",
    "apache2": "2.4.66-2ubuntu2.8",
}


def test_index_keeps_what_the_evaluator_needs(index):
    assert index["timestamp"] == "2026-11-26T08:53:49"
    assert index["definitions"][f"{P}:def:1"]["usn"] == "USN-1-1"
    assert index["tests"][f"{P}:tst:2"]["names"] == ["libmagickcore-7.q16-10"]
    assert index["tests"][f"{P}:tst:41"]["concat"][0] == {"literal": "0:"}


def test_pending_fixes_and_pro_only_are_split(index):
    r = oval.evaluate(index, PI_PACKAGES, "7.0.0-1024-raspi", ["libssh-4", "apache2"])
    assert r["cves"] == ["CVE-2026-0001"]
    assert r["cves_pro_only"] == ["CVE-2026-0002", "CVE-2026-0003"]
    assert [n["usn"] for n in r["cve_notices"]] == ["USN-1-1", "USN-2-1"]
    assert r["cve_notices"][1]["pro_only"] is True
    # apache2 is pending but no notice covers it (newer than the OVAL data)
    assert r["security_without_notice"] == ["apache2"]
    assert r["kernel_checked"] and r["kernel_covered"]


def test_running_an_old_kernel_counts_its_cves(index):
    r = oval.evaluate(index, PI_PACKAGES, "7.0.0-1023-raspi")
    kernel = [n for n in r["cve_notices"] if n["kernel"]]
    assert [n["usn"] for n in kernel] == ["USN-4-1"]
    assert {"CVE-2026-0010", "CVE-2026-0011"} <= set(r["cves"])
    assert oval.evaluate(index, PI_PACKAGES, "7.0.0-1023-raspi-realtime")["kernel_checked"] is False


def test_containers_do_not_get_the_lxd_hosts_kernel(index):
    # An LXD container sees the host kernel in uname but has no linux-image package.
    container = {k: v for k, v in PI_PACKAGES.items() if not k.startswith("linux-image")}
    r = oval.evaluate(index, container, "7.0.0-1023-raspi")
    assert not any(n["kernel"] for n in r["cve_notices"])
    assert r["kernel_checked"] is False


def test_kernel_the_release_data_does_not_know_is_flagged(index):
    pkgs = dict(PI_PACKAGES, **{"linux-image-6.8.0-2034-raspi-realtime": "6.8.0-2034.35"})
    r = oval.evaluate(index, pkgs, "6.8.0-2034-raspi-realtime")
    assert r["kernel_checked"] is True and r["kernel_covered"] is False


def test_unsigned_kernel_images_count_as_the_hosts_own(index):
    pkgs = {k: v for k, v in PI_PACKAGES.items() if not k.startswith("linux-image")}
    pkgs["linux-image-unsigned-7.0.0-1023-raspi"] = "7.0.0-1023.23"
    assert oval.evaluate(index, pkgs, "7.0.0-1023-raspi")["kernel_checked"] is True


def test_livepatch_notices_are_ignored(index):
    r = oval.evaluate(index, PI_PACKAGES, "7.0.0-1023-raspi")
    assert "CVE-2026-0020" not in r["cves"] + r["cves_pro_only"]


def test_several_installed_versions_are_all_checked(index):
    r = oval.evaluate(index, {"libssh-4": "0.11.3-1ubuntu2, 0.11.3-1ubuntu1"}, None)
    assert r["cves"] == ["CVE-2026-0001"]


# ─── Download, cache and command line ───────────────────────────────────

class _Server:
    """Serves the test OVAL file and honours If-Modified-Since, like Canonical's server."""

    def __init__(self, body: bytes):
        outer = self
        self.requests: list[int] = []
        self.up = True

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if not self.path.endswith("com.ubuntu.resolute.usn.oval.xml.bz2"):
                    outer.requests.append(404)
                    self.send_error(404)
                    return
                if self.headers.get("If-Modified-Since"):
                    outer.requests.append(304)
                    self.send_response(304)
                    self.end_headers()
                    return
                outer.requests.append(200)
                self.send_response(200)
                self.send_header("Last-Modified", "Thu, 26 Nov 2026 08:53:49 GMT")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        # server_close() too: with only shutdown() the socket keeps accepting
        # connections and the client waits for its timeout.
        if self.up:
            self.up = False
            self.httpd.shutdown()
            self.httpd.server_close()


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    s = _Server(bz2.compress(build_oval()))
    yield s
    s.close()


def _run(tmp_path, url, hosts, capsys):
    pkgs = tmp_path / "packages"
    pkgs.mkdir(exist_ok=True)
    (pkgs / "Nina.json").write_text(json.dumps({"packages": PI_PACKAGES}))
    import io
    import sys

    stdin = sys.stdin
    sys.stdin = io.StringIO(json.dumps(hosts))
    try:
        assert oval.main(["--cache-dir", str(tmp_path / "cache"), "--packages-dir", str(pkgs),
                          "--url-base", url, "--timeout", "5"]) == 0
    finally:
        sys.stdin = stdin
    return json.loads(capsys.readouterr().out)


def test_cli_downloads_once_then_uses_the_cache(tmp_path, server, capsys):
    hosts = [{"host": "Nina", "codename": "resolute", "kernel": "7.0.0-1023-raspi"},
             {"host": "Bad", "codename": "Resolute;rm"},
             {"host": "Gone", "codename": "resolute"}]
    out = _run(tmp_path, server.url, hosts, capsys)
    nina = out["hosts"]["Nina"]
    assert nina["cve_source"] == "ubuntu-usn-oval" and nina["cve_data_at"] == "2026-11-26T08:53:49"
    assert "CVE-2026-0010" in nina["cves"]
    assert "codename" in out["errors"]["Bad"] and "package list" in out["errors"]["Gone"]
    again = _run(tmp_path, server.url, hosts[:1], capsys)
    assert server.requests == [200, 304]
    assert again["hosts"]["Nina"]["cves"] == nina["cves"]
    assert "cve_data_warning" not in again["hosts"]["Nina"]


def test_cli_refuses_a_package_list_from_another_check(tmp_path, server, capsys):
    hosts = [{"host": "Nina", "codename": "resolute", "checked_at": "2026-11-26T19:45:45Z"}]
    out = _run(tmp_path, server.url, hosts, capsys)       # the list has no collected_at
    assert out["hosts"] == {} and "not from this check" in out["errors"]["Nina"]
    (tmp_path / "packages" / "Nina.json").write_text(
        json.dumps({"collected_at": "2026-11-26T19:45:45Z", "packages": PI_PACKAGES}))
    pkgs = tmp_path / "packages"
    import io
    import sys

    stdin, sys.stdin = sys.stdin, io.StringIO(json.dumps(hosts))
    try:
        oval.main(["--cache-dir", str(tmp_path / "cache"), "--packages-dir", str(pkgs),
                   "--url-base", server.url, "--timeout", "5"])
    finally:
        sys.stdin = stdin
    assert "Nina" in json.loads(capsys.readouterr().out)["hosts"]


def test_cached_index_is_rebuilt_when_the_download_changes(tmp_path, server):
    cache = tmp_path / "cache"
    cache.mkdir()
    index, status = oval.load_release("resolute", cache, server.url, 5)
    assert index and status["downloaded"] and index["source"]["size"] > 0
    # Same file again (304): the compiled index is reused as it is.
    idx_file = cache / "com.ubuntu.resolute.usn.index.json"
    stamp = idx_file.stat().st_mtime_ns
    oval.load_release("resolute", cache, server.url, 5)
    assert idx_file.stat().st_mtime_ns == stamp
    # A different file under the same name, even with an older date: rebuilt.
    bz = cache / "com.ubuntu.resolute.usn.oval.xml.bz2"
    bz.write_bytes(bz2.compress(build_oval().replace(b"USN-1-1", b"USN-9-9")))
    import os

    os.utime(bz, (1, 1))
    server.close()
    index, status = oval.load_release("resolute", cache, server.url, 5)
    assert status["error"] and index["definitions"][f"{P}:def:1"]["usn"] == "USN-9-9"


def test_download_size_is_capped(tmp_path, server, monkeypatch):
    monkeypatch.setattr(oval, "MAX_DOWNLOAD", 100)
    index, status = oval.load_release("resolute", tmp_path, server.url, 5)
    assert index is None and "larger than" in status["error"]


def test_cli_falls_back_to_the_cache_and_says_so(tmp_path, server, capsys):
    hosts = [{"host": "Nina", "codename": "resolute", "kernel": "7.0.0-1024-raspi"}]
    _run(tmp_path, server.url, hosts, capsys)
    server.close()
    out = _run(tmp_path, server.url, hosts, capsys)
    assert out["hosts"]["Nina"]["cves"] == ["CVE-2026-0001"]
    assert "download failed" in out["hosts"]["Nina"]["cve_data_warning"]


def test_cli_without_data_reports_an_error_per_host(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    out = _run(tmp_path, "http://127.0.0.1:9", [{"host": "Nina", "codename": "resolute"}], capsys)
    assert out["hosts"] == {} and "download failed" in out["errors"]["Nina"]


@pytest.mark.parametrize("url", ["http://example.com/oval", "file:///etc", "ftp://x"])
def test_cli_refuses_plain_http_outside_localhost(tmp_path, url):
    with pytest.raises(SystemExit):
        oval.main(["--cache-dir", str(tmp_path), "--packages-dir", str(tmp_path), "--url-base", url])


# ─── AI service: reading, scoring, prompt ───────────────────────────────

def _ubuntu_report(env, **fields):
    from tests.conftest import _write_report

    _write_report(env["reports"], "ubuntu-web-01", os="Ubuntu 26.04", update_count=3, security_count=2,
                  security_packages=["libssh-4", "apache2"], **fields)


OVAL_FIELDS = {
    "cve_source": "ubuntu-usn-oval",
    "cve_data_at": "2026-11-26T08:53:49",
    "cves": ["CVE-2026-0001", "CVE-2026-0010", "bogus"],
    "cves_pro_only": ["CVE-2026-0002", "CVE-2026-0001"],
    "cve_notices": [
        {"usn": "USN-1-1", "severity": "Medium", "cves": ["CVE-2026-0001"], "pro_only": False},
        {"usn": "USN-4-1", "severity": "High", "cves": ["CVE-2026-0010", "CVE-2026-0001"], "pro_only": False},
        {"usn": "USN-2-1", "severity": "Medium", "cves": ["CVE-2026-0002"], "pro_only": True},
    ],
    "kernel_checked": True,
    "kernel_covered": True,
    "security_without_notice": ["apache2"],
}


def _read(env):
    from app.agents.state import HostInfo
    from app.tools.report_reader import ReportReader

    host = HostInfo(hostname="ubuntu-web-01", ip="x", os_group="ubuntu_servers")
    ReportReader().enrich([host])
    return host


def test_reader_takes_the_oval_fields(env):
    _ubuntu_report(env, **OVAL_FIELDS)
    host = _read(env)
    assert host.cve_ids == ["CVE-2026-0001", "CVE-2026-0010"]
    assert host.cve_pro_only_ids == ["CVE-2026-0002"]          # not duplicated with the free ones
    assert host.cve_priority == {"CVE-2026-0001": "high", "CVE-2026-0010": "high", "CVE-2026-0002": "medium"}
    assert host.cve_source == "ubuntu-usn-oval" and host.cve_data_at == "2026-11-26T08:53:49"
    assert host.security_without_notice == ["apache2"] and not host.cve_note


def test_reader_explains_missing_or_old_data(env):
    _ubuntu_report(env, cve_source=None, cve_error="download failed: <urlopen error refused>")
    assert _read(env).cve_note.startswith("no CVE data: download failed")
    _ubuntu_report(env, **dict(OVAL_FIELDS, cve_data_warning="HTTP 503 for https://x"))
    assert _read(env).cve_note.startswith("CVE data not refreshed: HTTP 503")
    _ubuntu_report(env, **dict(OVAL_FIELDS, kernel_covered=False))
    assert _read(env).kernel_not_covered
    _ubuntu_report(env)                                         # report from before 1.3.0
    host = _read(env)
    assert not host.cve_note and not host.cve_source


async def test_enrichment_uses_ubuntu_priority_without_nvd(env, monkeypatch):
    from app.agents import nodes
    from app.agents.state import AgentState

    _ubuntu_report(env, **OVAL_FIELDS)
    looked_up: list[str] = []

    async def kev(self):
        return {"CVE-2026-0002": {}}

    async def lookup(self, ids):
        looked_up.extend(ids)
        return {}

    monkeypatch.setattr("app.tools.cve_scanner.CVEScanner.get_kev_ids", kev)
    monkeypatch.setattr("app.tools.cve_scanner.CVEScanner.lookup_cves", lookup)
    monkeypatch.setattr("app.tools.cve_scanner.CVEScanner.recent_context", _no_context)
    state = AgentState(user_message="x")
    for key, value in (await nodes.load_inventory(state)).items():
        setattr(state, key, value)
    host = next(h for h in state.all_hosts if h.hostname == "ubuntu-web-01")
    await nodes.enrich_cves(state)
    assert host.kev_cves == [] and host.kev_pro_only_cves == ["CVE-2026-0002"]
    top = host.cve_matches[0]
    assert top["score"] == 7.0 and top["severity"] == "HIGH" and top["score_source"] == "ubuntu"
    assert set(looked_up) >= {"CVE-2026-0001", "CVE-2026-0010"}


async def _no_context(self, groups):
    return []


def test_scoring_keeps_pro_only_apart_unless_kev():
    from app.agents.state import HostInfo
    from app.tools.risk_scorer import RiskScorer

    base = HostInfo(hostname="h", ip="x", os_group="ubuntu_servers", report_found=True,
                    report_age_hours=1.0, security_count=1)
    with_pro = HostInfo(**{**base.__dict__, "cve_pro_only_ids": ["CVE-2026-0002"] * 1})
    s = RiskScorer()
    assert s.score_host(with_pro).risk_score == s.score_host(base).risk_score
    assert "1 CVE(s) fixable only with Ubuntu Pro (not scored)" in s.score_host(with_pro).risk_factors
    kev = HostInfo(**{**with_pro.__dict__, "kev_pro_only_cves": ["CVE-2026-0002"]})
    scored = s.score_host(kev)
    assert scored.risk_score >= 80
    assert any("fix needs Ubuntu Pro" in f for f in scored.risk_factors)


def test_scoring_names_ubuntu_priority_and_kernel_gaps():
    from app.agents.state import HostInfo
    from app.tools.risk_scorer import RiskScorer

    h = HostInfo(hostname="h", ip="x", os_group="ubuntu_servers", report_found=True, report_age_hours=1.0,
                 cve_matches=[{"id": "CVE-2026-0010", "score": 7.0, "severity": "HIGH", "score_source": "ubuntu"}],
                 kernel_not_covered=True)
    factors = RiskScorer().score_host(h).risk_factors
    assert "High-priority Ubuntu CVE pending (CVE-2026-0010)" in factors
    assert "Running kernel not covered by Canonical's CVE data" in factors


def test_prompt_and_email_carry_the_ubuntu_cve_data(env):
    from app.agents import nodes
    from app.agents.state import HostInfo
    from app.services import mailer

    h = HostInfo(hostname="Bluma", ip="x", os_group="ubuntu_servers", cve_ids=["CVE-2026-0001"],
                 cve_pro_only_ids=["CVE-2026-0002", "CVE-2026-0003"], cve_source="ubuntu-usn-oval",
                 cve_data_at="2026-11-26T08:55:48", security_without_notice=["apache2"])
    row = nodes._host_summary([h])[0]
    assert row["cves"] == 1 and row["cves_pro_only"] == 2 and row["security_updates_without_notice"] == 1
    assert row["cve_data"] == "Canonical USN data of 2026-11-26T08:55:48"
    rocky = nodes._host_summary([HostInfo(hostname="r", ip="x", os_group="rocky_servers")])[0]
    assert "cve_data" not in rocky
    notes = mailer._notes(nodes.risk_rows([h])[0], ", ")
    assert notes == ["1 CVE", "2 CVE Ubuntu Pro"]


# ─── CVEs without a fix yet (CVE OVAL) ──────────────────────────────────

def _vuln(n: int, cve: str, priority: str, criteria: str) -> str:
    return f"""
    <definition id="{P}:def:9{n}" class="vulnerability" version="1">
      <metadata><title>{cve} on Ubuntu 26.04 LTS (resolute) - {priority.lower()}</title>
        <reference source="CVE" ref_id="{cve}" ref_url="x"/>
        <advisory from="security@ubuntu.com"><severity>{priority}</severity></advisory></metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="{P}:def:100" comment="release"/>
        <criteria operator="OR">{criteria}</criteria>
      </criteria>
    </definition>"""


def build_cve_oval() -> bytes:
    xml = build_oval().decode()
    defs = (
        # wireshark installed, no fix: "might be affected and may need fixing"
        _vuln(1, "CVE-2026-1001", "High", f'<criterion test_ref="{P}:tst:901"/>')
        # libssh: fixed version exists (pending fix, the USN data covers it)
        + _vuln(2, "CVE-2026-1002", "Critical", f'<criterion test_ref="{P}:tst:1"/>')
        # not installed
        + _vuln(3, "CVE-2026-1003", "Critical", f'<criterion test_ref="{P}:tst:903"/>')
        # kernel: raspi running, no fixed version for it (left out on purpose)
        + _vuln(4, "CVE-2026-1004", "Critical", f'<criteria operator="AND"><criterion test_ref="{P}:tst:40"/></criteria>')
        # kernel: fixed in 7.0.0-1024, the host runs it
        + _vuln(5, "CVE-2026-1005", "High", f"""<criteria operator="AND">
              <criterion test_ref="{P}:tst:40"/><criterion test_ref="{P}:tst:41"/></criteria>""")
        + _vuln(6, "CVE-2026-1006", "Medium", f'<criterion test_ref="{P}:tst:901"/>')
    )
    tests = "".join(f"""
      <linux-def:dpkginfo_test id="{P}:tst:{n}" version="1" check="at least one" check_existence="at_least_one_exists">
        <linux-def:object object_ref="{P}:obj:{n}"/></linux-def:dpkginfo_test>""" for n in (901, 903))
    objects = "".join(f"""
      <linux-def:dpkginfo_object id="{P}:obj:{n}" version="1">
        <linux-def:name var_ref="{P}:var:{n}" var_check="at least one"/></linux-def:dpkginfo_object>""" for n in (901, 903))
    variables = (f'<constant_variable id="{P}:var:901" version="1" datatype="string"><value>libwireshark19</value></constant_variable>'
                 f'<constant_variable id="{P}:var:903" version="1" datatype="string"><value>nginx</value></constant_variable>')
    xml = xml.replace("</definitions>", defs + "</definitions>").replace("</tests>", tests + "</tests>")
    xml = xml.replace("</objects>", objects + "</objects>").replace("</variables>", variables + "</variables>")
    return xml.encode()


def test_unfixed_cves_are_package_ones_with_no_fixed_version():
    import io

    idx = oval.compile_oval(lambda: io.BytesIO(build_cve_oval()), unfixed_only=True)
    pkgs = dict(PI_PACKAGES, libwireshark19="4.4.9-1")
    r = oval.evaluate_unfixed(idx, pkgs)
    # 1002 has a fix, 1003 is not installed, 1004/1005 are kernel ones (left out)
    assert r["unfixed_cves"] == ["CVE-2026-1001", "CVE-2026-1006"]
    assert r["unfixed_cve_counts"] == {"negligible": 0, "low": 0, "medium": 1, "high": 1, "critical": 0}
    assert r["unfixed_cves_top"] == [
        {"cve": "CVE-2026-1001", "priority": "high", "packages": ["libwireshark19"]}]


def test_unfixed_cves_reach_the_analysis_without_scoring(env, monkeypatch):
    import asyncio

    from app.agents import nodes
    from app.agents.state import AgentState
    from app.services import mailer
    from app.tools.risk_scorer import RiskScorer

    _ubuntu_report(env, **dict(OVAL_FIELDS, unfixed_cve_counts={"critical": 1, "high": 1, "medium": 1},
                               unfixed_cves=["CVE-2026-1001", "CVE-2026-1004", "CVE-2026-1006"],
                               unfixed_cves_top=[
                                   {"cve": "CVE-2026-1004", "priority": "critical", "packages": ["libfoo1"]},
                                   {"cve": "CVE-2026-1001", "priority": "high", "packages": ["libwireshark19"]}]))

    async def kev(self):
        return {"CVE-2026-1006": {}}

    async def lookup(self, ids):
        return {}

    monkeypatch.setattr("app.tools.cve_scanner.CVEScanner.get_kev_ids", kev)
    monkeypatch.setattr("app.tools.cve_scanner.CVEScanner.lookup_cves", lookup)
    monkeypatch.setattr("app.tools.cve_scanner.CVEScanner.recent_context", _no_context)

    async def run():
        state = AgentState(user_message="x")
        for f in (nodes.load_inventory, nodes.enrich_cves):
            for key, value in (await f(state)).items():
                setattr(state, key, value)
        return state

    state = asyncio.run(run())
    host = next(h for h in state.all_hosts if h.hostname == "ubuntu-web-01")
    assert host.kev_unfixed_cves == ["CVE-2026-1006"]
    scored = RiskScorer().score_host(host)
    without = RiskScorer().score_host(type(host)(**{**host.__dict__, "kev_unfixed_cves": [],
                                                    "unfixed_counts": {}, "unfixed_top": []}))
    assert scored.risk_score == without.risk_score < 80
    assert "Known exploited, no fix yet (review exposure): CVE-2026-1006" in scored.risk_factors
    summary = nodes._unfixed_summary([host])
    assert [r["cve"] for r in summary] == ["CVE-2026-1006", "CVE-2026-1004", "CVE-2026-1001"]
    assert summary[0]["kev"] and summary[1]["priority"] == "critical"
    assert all(set(r) == {"cve", "kev", "priority", "hosts"} for r in summary)   # no package names
    notes = mailer._notes(nodes.risk_rows([scored])[0], ", ")
    assert "KEV, no fix: CVE-2026-1006" in notes and "no fix: 1 critical, 1 high" in notes


async def test_prompt_explains_unfixed_counts_without_critical_or_high(env, fake_llm):
    # 1.3.1: with only medium/low counts the model got neither the zeros nor what
    # the bands mean, and could not say "none critical or high".
    from app.agents import nodes
    from app.agents.state import ActionType, AgentState, HostInfo

    h = HostInfo(hostname="Bluma", ip="x", os_group="ubuntu_servers", cve_source="ubuntu-usn-oval",
                 unfixed_counts={"critical": 0, "high": 0, "medium": 696, "low": 43, "negligible": 19})
    assert nodes._host_summary([h])[0]["unfixed"] == {"critical": 0, "high": 0, "medium": 696,
                                                       "low": 43, "negligible": 19}
    fake = fake_llm()
    await nodes.generate_briefing(AgentState(user_message="x", action=ActionType.ANALYZE_RISK,
                                             all_hosts=[h]))
    prompt = fake.prompts["generate_briefing"][0]
    assert "by Canonical's priority" in prompt and "not a data gap" in prompt
    assert "No host has critical or high ones" in prompt
    assert "CVES WITHOUT A FIX YET" not in prompt          # nothing KEV, critical or high to list

    h.unfixed_counts = {"critical": 1, "high": 0, "medium": 2}
    fake = fake_llm()
    await nodes.generate_briefing(AgentState(user_message="x", action=ActionType.ANALYZE_RISK,
                                             all_hosts=[h]))
    assert "Hosts with critical or high ones: Bluma." in fake.prompts["generate_briefing"][0]



async def test_prompt_says_what_drives_the_risk(env, fake_llm):
    # 1.3.2: the model named Pro-only CVEs as what drove the risk, and treated an
    # empty CVE list on Ubuntu hosts with nothing pending as missing data.
    from app.agents import nodes
    from app.agents.state import ActionType, AgentState, HostInfo
    from app.tools.risk_scorer import RiskScorer

    h = RiskScorer().score_host(HostInfo(
        hostname="Bluma", ip="x", os_group="ubuntu_servers", report_found=True, report_age_hours=1.0,
        criticality="high", cve_source="ubuntu-usn-oval", cve_pro_only_ids=["CVE-2026-0002"] * 107))
    assert "107 CVE(s) fixable only with Ubuntu Pro (not scored)" in h.risk_factors
    fake = fake_llm()
    await nodes.generate_briefing(AgentState(user_message="x", action=ActionType.ANALYZE_RISK,
                                             all_hosts=[h]))
    prompt = fake.prompts["generate_briefing"][0]
    assert '"(not scored)" are context only' in prompt
    assert "no pending security updates an empty list is normal too" in prompt
    assert "ids are in each host's report file (cves_pro_only)" in prompt
