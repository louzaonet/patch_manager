#!/usr/bin/env python3
"""CVEs fixed by pending Ubuntu updates, from Canonical's USN OVAL data.

Runs on the Ansible controller (check_updates.yml), not on the hosts. For each
Ubuntu host it reads the installed package list that Check Updates already
saves (reports/packages/<host>.json) and the running kernel, and evaluates the
USN OVAL definitions of its release: a definition matches when an installed
binary package is older than the version that fixes the notice, or when the
running kernel is older than the fixed one. The CVEs of the matching notices
are the ones that patching (and, for the kernel, rebooting) would remove.

Only the standard library is used: it runs with ansible_playbook_python.

    ubuntu_oval_cves.py --cache-dir DIR --packages-dir DIR < hosts.json > result.json

hosts.json: [{"host": "Bluma", "codename": "jammy", "kernel": "5.15.0-1080-raspi",
              "checked_at": "2026-11-26T19:45:45Z", "security_packages": ["apache2", ...]}, ...]
(checked_at must match the package list's collected_at: an older list is not used)

Output: {"releases": {codename: status}, "errors": {host: message},
         "hosts": {host: fields to merge into reports/hosts/<host>.json}}

The OVAL file of each release is downloaded at most once per run, only when it
changed upstream (If-Modified-Since), and compiled into a small JSON index that
is reused until the next change. If the download fails, the cached copy is
used and the result says how old it is. Nothing here makes the playbook fail:
errors are reported per release and per host in the output.
"""

from __future__ import annotations

import argparse
import bz2
import email.utils
import json
import os
import pyexpat
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

URL_BASE = "https://security-metadata.canonical.com/oval"
INDEX_FORMAT = 3                      # bump when the compiled index layout changes
CODENAME_RE = re.compile(r"^[a-z]{3,20}\Z")
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}\Z")
MAX_CVES_PER_HOST = 2000              # a kernel notice alone can list hundreds
MAX_DOWNLOAD = 64 * 2**20             # the largest file (jammy CVE OVAL) is about 14 MB


# ═════════════════════════════════════════════════════════════════════════════
# Debian version comparison (same rules as dpkg --compare-versions)
# ═════════════════════════════════════════════════════════════════════════════

def _order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, _, revision = v.rpartition("-")
    if not upstream:                  # no "-": the whole string is the upstream version
        upstream, revision = revision, ""
    return epoch, upstream, revision


def version_compare(a: str, b: str) -> int:
    """<0, 0 or >0, as dpkg orders the two versions."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


# ═════════════════════════════════════════════════════════════════════════════
# OVAL → compact index
# ═════════════════════════════════════════════════════════════════════════════

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _criteria(el: ET.Element) -> dict[str, Any]:
    """<criteria> tree as {"op": "AND"|"OR", "neg": bool, "items": [...]}."""
    items: list[Any] = []
    for child in el:
        name = _local(child.tag)
        neg = child.get("negate") == "true"
        if name == "criteria":
            items.append(_criteria(child))
        elif name == "criterion":
            items.append({"test": child.get("test_ref"), "neg": neg})
        elif name == "extend_definition":
            items.append({"def": child.get("definition_ref"), "neg": neg})
    return {"op": el.get("operator", "AND"), "neg": el.get("negate") == "true", "items": items}


def _test_refs(node: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for item in node.get("items", []):
        if "test" in item:
            out.add(item["test"])
        elif "items" in item:
            out |= _test_refs(item)
    return out


def _definition(el: ET.Element) -> dict[str, Any] | None:
    meta = next((c for c in el if _local(c.tag) == "metadata"), None)
    crit = next((c for c in el if _local(c.tag) == "criteria"), None)
    if meta is None or crit is None:
        return None
    title = ""
    usn = None
    cves: list[str] = []
    severity = None
    for m in meta.iter():
        name = _local(m.tag)
        if name == "title":
            title = (m.text or "").strip()
        elif name == "reference":
            if m.get("source") == "USN":
                usn = m.get("ref_id")
            elif m.get("source") == "CVE" and m.get("ref_id"):
                cves.append(m.get("ref_id"))
        elif name == "severity":
            severity = (m.text or "").strip() or None
    return {"id": el.get("id"), "class": el.get("class"), "title": title, "usn": usn,
            "severity": severity, "cves": sorted(set(cves)), "criteria": _criteria(crit)}


def _entity(el: ET.Element) -> dict[str, Any]:
    """Tests, objects, states and variables, reduced to what the evaluator uses."""
    kind = _local(el.tag)
    out: dict[str, Any] = {"kind": kind}
    for child in el:
        name = _local(child.tag)
        if name in ("object", "state"):                       # inside a test
            out[name] = child.get(f"{name}_ref")
        elif name == "name":                                   # dpkginfo_object
            out["name"] = child.text.strip() if child.text else None
            out["name_var"] = child.get("var_ref")
        elif name == "var_ref":                                # variable_object
            out["var"] = (child.text or "").strip()
        elif name in ("evr", "os_release", "value"):           # states
            out["op"] = child.get("operation", "equals")
            out["value"] = (child.text or "").strip()
            out["datatype"] = child.get("datatype")
        elif kind == "constant_variable" and name == "value":
            out.setdefault("values", []).append((child.text or "").strip())
        elif kind == "local_variable" and name == "concat":
            parts: list[Any] = []
            for comp in child:
                cname = _local(comp.tag)
                if cname == "literal_component":
                    parts.append({"literal": comp.text or ""})
                elif cname == "regex_capture":
                    obj = next((c for c in comp if _local(c.tag) == "object_component"), None)
                    parts.append({"regex": comp.get("pattern"),
                                  "field": obj.get("item_field") if obj is not None else None})
            out["concat"] = parts
    if kind == "constant_variable":
        out["values"] = [(c.text or "").strip() for c in el if _local(c.tag) == "value"]
    return out


def _iterparse(stream: Any) -> Any:
    # The file comes over HTTPS from Canonical. expat never fetches external
    # entities, and from 2.4.1 it limits entity expansion ("billion laughs");
    # main() refuses to run with an older expat.
    return ET.iterparse(stream, events=("end",))  # noqa: S314


KERNEL_KINDS = ("uname_", "variable_", "local_variable", "file_")


def _parse_entities(stream: Any, definitions: dict[str, Any], entities: dict[str, Any],
                    unfixed_tests: set[str] | None) -> str | None:
    """Fill definitions and entities from the XML; returns the OVAL timestamp."""
    timestamp = None
    for _event, el in _iterparse(stream):
        name = _local(el.tag)
        if name == "timestamp" and timestamp is None:
            timestamp = (el.text or "").strip()
        elif name == "definition":
            d = _definition(el)
            keep = d and d["id"] and (
                unfixed_tests is None or d["class"] == "inventory"
                or (d["class"] == "vulnerability" and unfixed_tests & _test_refs(d["criteria"])))
            if keep:
                definitions[d["id"]] = d
            el.clear()
        elif el.get("id") and name.endswith(("_test", "_object", "_state", "_variable")):
            if unfixed_tests is None or not name.startswith(KERNEL_KINDS):
                entities[el.get("id")] = _entity(el)
            el.clear()
    return timestamp


def compile_oval(open_stream: Any, unfixed_only: bool = False) -> dict[str, Any]:
    """Parse an OVAL file (the XML is 20-60 MB) into an index.

    open_stream() returns a fresh binary stream of the XML. unfixed_only (CVE
    OVAL): keep only the definitions with an existence-only package test
    ("may need fixing") and the tests they use. A first pass finds those
    tests, so the kernel entries, most of that file, are never held in memory.
    """
    unfixed_tests: set[str] | None = None
    if unfixed_only:
        unfixed_tests = set()
        with open_stream() as stream:
            for _event, el in _iterparse(stream):
                if _local(el.tag) == "dpkginfo_test" and el.get("id"):
                    if not any(_local(c.tag) == "state" for c in el):
                        unfixed_tests.add(el.get("id"))
                if el.get("id"):
                    el.clear()

    definitions: dict[str, Any] = {}
    entities: dict[str, Any] = {}
    with open_stream() as stream:
        timestamp = _parse_entities(stream, definitions, entities, unfixed_tests)

    tests: dict[str, Any] = {}
    for tid, t in entities.items():
        if not t["kind"].endswith("_test"):
            continue
        obj = entities.get(t.get("object") or "", {})
        state = entities.get(t.get("state") or "", {})
        test: dict[str, Any] = {"kind": t["kind"]}
        if t["kind"] == "dpkginfo_test":
            names = [obj["name"]] if obj.get("name") else []
            if obj.get("name_var"):
                names = entities.get(obj["name_var"], {}).get("values", [])
            test.update(names=names, op=state.get("op"), evr=state.get("value"))
        elif t["kind"] == "uname_test":
            test.update(op=state.get("op"), pattern=state.get("value"))
        elif t["kind"] == "variable_test":
            var = entities.get(obj.get("var") or "", {})
            test.update(concat=var.get("concat"), op=state.get("op"), evr=state.get("value"))
        tests[tid] = test

    # What each definition looks at, so a host can skip the ones that can't
    # match it (the CVE OVAL has 20,000 definitions, most for absent packages).
    def refs(node: dict[str, Any], seen: set[str]) -> tuple[set[str], bool]:
        names: set[str] = set()
        kernel = False
        for item in node.get("items", []):
            if "test" in item:
                t = tests.get(item["test"], {})
                names.update(t.get("names", []))
                kernel = kernel or t.get("kind") in ("uname_test", "variable_test")
            elif "def" in item:
                d = definitions.get(item["def"])
                if d and d.get("class") != "inventory" and item["def"] not in seen:
                    n, k = refs(d["criteria"], seen | {item["def"]})
                    names |= n
                    kernel = kernel or k
            else:
                n, k = refs(item, seen)
                names |= n
                kernel = kernel or k
        return names, kernel

    for did, d in definitions.items():
        names, kernel = refs(d["criteria"], {did})
        d["names"] = sorted(names)
        d["kernel"] = kernel

    if unfixed_only:
        used = set().union(*(_test_refs(d["criteria"]) for d in definitions.values()))
        tests = {t: v for t, v in tests.items() if t in used}
    return {"format": INDEX_FORMAT, "timestamp": timestamp, "definitions": definitions, "tests": tests}


# ═════════════════════════════════════════════════════════════════════════════
# Evaluation against one host
# ═════════════════════════════════════════════════════════════════════════════

ALWAYS_TRUE = {"family_test", "textfilecontent54_test"}   # unix family / release check
# file_test only appears in livepatch notices (/snap/bin/canonical-livepatch):
# without livepatch they never apply. Anything unknown counts as false.


class Host:
    def __init__(self, packages: dict[str, str], kernel: str | None) -> None:
        # check_updates.yml joins several installed versions with ", "
        self.packages = {n: [v.strip() for v in str(vs).split(",") if v.strip()]
                         for n, vs in packages.items()}
        # Kernel notices only count where the running kernel is this host's own:
        # an LXD container reports the host's kernel in uname but has no
        # linux-image package, and those CVEs belong to the LXD host.
        own = bool(kernel) and any(f"{prefix}{kernel}" in self.packages
                                   for prefix in ("linux-image-", "linux-image-unsigned-"))
        self.kernel = kernel if own else None


def _cmp_op(op: str | None, a: str, b: str) -> bool:
    c = version_compare(a, b)
    return {"less than": c < 0, "less than or equal": c <= 0, "equals": c == 0,
            "greater than": c > 0, "greater than or equal": c >= 0}.get(op or "", False)


def _test(index: dict[str, Any], tid: str, host: Host, hits: list[dict[str, Any]]) -> bool:
    t = index["tests"].get(tid)
    if t is None:
        return False
    kind = t["kind"]
    if kind in ALWAYS_TRUE:
        # textfilecontent54 is also used for the livepatch module version; those
        # tests are always paired with a file_test, which is false.
        return True
    if kind == "dpkginfo_test":
        if not t.get("evr"):
            # Existence only: in the CVE OVAL, "might be affected and may need
            # fixing" (no fixed version yet). The USN OVAL has none of these.
            present = sorted(n for n in t.get("names", []) if host.packages.get(n))
            if present:
                hits.append({"packages": present, "fixed": None})
            return bool(present)
        matched = [(n, v) for n in t.get("names", []) for v in host.packages.get(n, [])
                   if _cmp_op(t.get("op"), v, t["evr"])]
        if matched:
            hits.append({"packages": sorted({n for n, _ in matched}), "fixed": t["evr"]})
        return bool(matched)
    if kind == "uname_test":
        running = bool(host.kernel and t.get("pattern") and re.search(t["pattern"], host.kernel))
        if running:
            hits.append({"kernel": host.kernel, "fixed": None, "running_only": True})
        return running
    if kind == "variable_test":
        value = _kernel_value(t.get("concat") or [], host.kernel)
        ok = value is not None and bool(t.get("evr")) and _cmp_op(t.get("op"), value, t["evr"])
        if ok:
            hits.append({"kernel": host.kernel, "fixed": t["evr"]})
        return ok
    return False


def _kernel_value(concat: list[dict[str, Any]], kernel: str | None) -> str | None:
    """The OVAL local variable: "0:" + regex capture of uname's os_release."""
    if not kernel or not concat:
        return None
    out = ""
    for part in concat:
        if "literal" in part:
            out += part["literal"]
        elif part.get("field") == "os_release" and part.get("regex"):
            m = re.search(part["regex"], kernel)
            if not m or not m.groups():
                return None
            out += m.group(1)
        else:
            return None
    return out


def _eval(index: dict[str, Any], node: dict[str, Any], host: Host,
          hits: list[dict[str, Any]], depth: int = 0) -> bool:
    """Evaluate a criteria tree. Only the branches that came out true add their
    hits, so a kernel "is running" test inside a failed AND leaves no trace."""
    if depth > 20:
        return False
    mine: list[dict[str, Any]] = []
    if "test" in node:
        r = _test(index, node["test"], host, mine)
    elif "def" in node:
        d = index["definitions"].get(node["def"])
        r = bool(d) and (d.get("class") == "inventory" or _eval(index, d["criteria"], host, mine, depth + 1))
    else:
        results = []
        for item in node.get("items", []):
            sub: list[dict[str, Any]] = []
            ok = _eval(index, item, host, sub, depth + 1)
            results.append(ok)
            if ok:
                mine.extend(sub)
        r = any(results) if node.get("op") == "OR" else (all(results) if results else False)
    if node.get("neg"):
        return not r                   # a negated match explains nothing
    if r:
        hits.extend(mine)
    return r


def _kernel_covered(index: dict[str, Any], kernel: str | None) -> bool:
    """Whether any kernel notice of this release recognises the running kernel."""
    return bool(kernel) and any(
        t["kind"] == "uname_test" and t.get("pattern") and re.search(t["pattern"], kernel)
        for t in index["tests"].values())


def _may_match(d: dict[str, Any], host: Host) -> bool:
    return bool((d.get("kernel") and host.kernel) or any(n in host.packages for n in d.get("names", [])))


def evaluate(index: dict[str, Any], packages: dict[str, str], kernel: str | None,
             security_packages: list[str] | None = None) -> dict[str, Any]:
    """Notices (USN OVAL) with a fix the host has not installed, or not booted."""
    host = Host(packages, kernel)
    notices: list[dict[str, Any]] = []
    for d in index["definitions"].values():
        if d.get("class") != "patch" or not d.get("usn") or not _may_match(d, host):
            continue                   # inventory checks, livepatch (LSN) notices, absent packages
        hits: list[dict[str, Any]] = []
        if not _eval(index, d["criteria"], host, hits):
            continue
        # Only hits with a fixed version say what to update; a tree that matched
        # without one (always-true tests) has nothing to fix.
        hits = [h for h in hits if h.get("fixed")]
        if not hits:
            continue
        pro_only = all("esm" in h["fixed"] for h in hits)
        notices.append({
            "usn": d["usn"],
            "title": d["title"].split(" -- ", 1)[-1][:120],
            "severity": d.get("severity"),
            "cves": d["cves"],
            "pro_only": pro_only,
            "kernel": any("kernel" in h for h in hits),
            "packages": sorted({p for h in hits for p in h.get("packages", [])})[:20],
        })
    notices.sort(key=lambda n: n["usn"])
    free = sorted({c for n in notices if not n["pro_only"] for c in n["cves"]})
    pro = sorted({c for n in notices if n["pro_only"] for c in n["cves"]} - set(free))
    # Pending security updates that no notice explains: published after the
    # OVAL file was generated, or that fix no CVE (tzdata, -dev packages).
    explained = {p for n in notices if not n["pro_only"] for p in n["packages"]}
    unexplained = sorted({p for p in (security_packages or []) if p not in explained})
    return {
        "cves": free[:MAX_CVES_PER_HOST],
        "cves_pro_only": pro[:MAX_CVES_PER_HOST],
        "cves_truncated": len(free) > MAX_CVES_PER_HOST or len(pro) > MAX_CVES_PER_HOST,
        "cve_notices": notices,
        "kernel_checked": host.kernel is not None,
        # False with kernel_checked: the running kernel is not one this
        # release's data knows (e.g. an older series), so it was not assessed.
        "kernel_covered": _kernel_covered(index, host.kernel),
        "security_without_notice": unexplained[:100],
    }


PRIORITIES = ("negligible", "low", "medium", "high", "critical")
MAX_UNFIXED_LISTED = 100              # critical and high ones, with their package


def evaluate_unfixed(index: dict[str, Any], packages: dict[str, str]) -> dict[str, Any]:
    """CVEs (CVE OVAL) in installed packages that have no fix yet.

    Canonical lists them as "might be affected and may need fixing": the
    package is installed and no fixed version exists. Patching does not
    remove them. The kernel is left out on purpose: its unfixed CVEs run to
    hundreds per flavour and would show up in every report.
    """
    host = Host(packages, None)
    found: list[dict[str, Any]] = []
    for d in index["definitions"].values():
        if d.get("class") != "vulnerability" or not _may_match(d, host):
            continue
        hits: list[dict[str, Any]] = []
        if not _eval(index, d["criteria"], host, hits) or any(h.get("fixed") for h in hits):
            continue                   # not affected, or fixed (the USN data covers those)
        prio = str(d.get("severity") or "").lower()
        pkgs = sorted({p for h in hits for p in h.get("packages", [])})
        if not pkgs:
            continue
        for cve in d["cves"]:
            found.append({"cve": cve, "priority": prio if prio in PRIORITIES else "unknown",
                          "packages": pkgs[:5]})
    counts = {p: 0 for p in PRIORITIES}
    for f in found:
        if f["priority"] in counts:
            counts[f["priority"]] += 1
    rank = {p: i for i, p in enumerate(PRIORITIES)}
    top = sorted((f for f in found if f["priority"] in ("critical", "high")),
                 key=lambda f: (-rank[f["priority"]], f["cve"]))
    ids = sorted({f["cve"] for f in found})
    return {
        "unfixed_cve_counts": counts,
        "unfixed_cves_top": top[:MAX_UNFIXED_LISTED],
        "unfixed_cves": ids[:MAX_CVES_PER_HOST],          # all of them, for the KEV check
        "unfixed_truncated": len(ids) > MAX_CVES_PER_HOST or len(top) > MAX_UNFIXED_LISTED,
    }


# ═════════════════════════════════════════════════════════════════════════════
# Download, cache and command line
# ═════════════════════════════════════════════════════════════════════════════

def _atomic_write(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def load_release(codename: str, cache: Path, url_base: str, timeout: float,
                 kind: str = "usn") -> tuple[dict | None, dict]:
    """(index or None, status) for one release and kind ("usn" or "cve");
    downloads only when the file changed upstream."""
    status: dict[str, Any] = {"downloaded": False, "error": None}
    bz = cache / f"com.ubuntu.{codename}.{kind}.oval.xml.bz2"
    idx_path = cache / f"com.ubuntu.{codename}.{kind}.index.json"
    url = f"{url_base.rstrip('/')}/com.ubuntu.{codename}.{kind}.oval.xml.bz2"
    req = urllib.request.Request(url, headers={"User-Agent": "patch-manager"})  # noqa: S310 (scheme checked in main)
    if bz.exists():
        req.add_header("If-Modified-Since", email.utils.formatdate(bz.stat().st_mtime, usegmt=True))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read(MAX_DOWNLOAD + 1)
            modified = resp.headers.get("Last-Modified")
        if len(body) > MAX_DOWNLOAD:
            raise OSError(f"{url} is larger than {MAX_DOWNLOAD // 2**20} MB")
        _atomic_write(bz, body)
        if modified:
            ts = email.utils.parsedate_to_datetime(modified).timestamp()
            os.utime(bz, (ts, ts))
        status["downloaded"] = True
    except urllib.error.HTTPError as e:
        if e.code != 304:
            status["error"] = f"HTTP {e.code} for {url}"
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        status["error"] = f"download failed: {e}"
    if not bz.exists():
        return None, status

    # The index records which download it was compiled from. Comparing mtimes
    # alone could keep an old index when a CDN serves a file late.
    source = {"mtime": bz.stat().st_mtime, "size": bz.stat().st_size}
    index = None
    if idx_path.exists():
        try:
            index = json.loads(idx_path.read_text())
            if index.get("format") != INDEX_FORMAT or index.get("source") != source:
                index = None
        except (OSError, ValueError):
            index = None
    if index is None:
        try:
            index = compile_oval(lambda: bz2.open(bz, "rb"), unfixed_only=(kind == "cve"))
        except (OSError, EOFError, ET.ParseError) as e:
            status["error"] = f"cannot read {bz.name}: {e}"
            return None, status
        index["source"] = source
        _atomic_write(idx_path, json.dumps(index, separators=(",", ":")).encode())
    status["oval_timestamp"] = index.get("timestamp")
    status["file_age_hours"] = round((time.time() - bz.stat().st_mtime) / 3600, 1)
    return index, status


def _host_result(h: dict[str, Any], index: dict | None, cve_index: dict | None,
                 releases: dict[str, Any], codename: str, args: argparse.Namespace) -> dict[str, Any] | str:
    """Fields for one host's report, or the reason there are none."""
    if index is None:
        return releases[codename]["error"] or "no OVAL data"
    try:
        pkg_report = json.loads((args.packages_dir / f"{h['host']}.json").read_text())
    except (OSError, ValueError):
        return "no installed package list (patch_collect_packages off?)"
    if h.get("checked_at") and pkg_report.get("collected_at") != h["checked_at"]:
        return "the installed package list is not from this check (patch_collect_packages off?)"
    packages = pkg_report.get("packages") or {}
    if not isinstance(packages, dict):
        return "the installed package list is not readable"
    sec = [str(p) for p in (h.get("security_packages") or [])][:500]
    result = evaluate(index, packages, h.get("kernel"), sec)
    result.update(cve_source="ubuntu-usn-oval", cve_data_at=index.get("timestamp"))
    if releases[codename].get("error"):
        # Evaluated with the cached copy: say why it was not refreshed.
        result["cve_data_warning"] = releases[codename]["error"][:300]
    if args.unfixed:
        status = releases.get(f"{codename}-cve", {})
        if cve_index is None:
            result["unfixed_error"] = (status.get("error") or "no CVE OVAL data")[:300]
        else:
            result.update(evaluate_unfixed(cve_index, packages))
            result["unfixed_data_at"] = cve_index.get("timestamp")
            if status.get("error"):
                result["unfixed_data_warning"] = status["error"][:300]
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cache-dir", required=True, type=Path)
    ap.add_argument("--packages-dir", required=True, type=Path)
    ap.add_argument("--url-base", default=URL_BASE)
    ap.add_argument("--timeout", type=float, default=120)
    ap.add_argument("--unfixed", action="store_true",
                    help="also list package CVEs without a fix yet (CVE OVAL, 5-14 MB per release)")
    args = ap.parse_args(argv)

    url = urllib.parse.urlsplit(args.url_base)
    if not (url.scheme == "https" or (url.scheme == "http" and url.hostname in ("127.0.0.1", "localhost"))):
        ap.error("--url-base must be https:// (plain http only for localhost, in tests)")
    if pyexpat.version_info < (2, 4, 1):
        ap.error(f"expat {pyexpat.EXPAT_VERSION} is too old to parse untrusted XML safely (needs 2.4.1)")

    hosts = [h for h in json.load(sys.stdin) if HOST_RE.match(str(h.get("host", "")))]
    args.cache_dir.mkdir(parents=True, exist_ok=True)
    out: dict[str, Any] = {"releases": {}, "hosts": {}, "errors": {}}

    # One release at a time, so only its indexes are in memory (the CVE one
    # of jammy is the largest).
    by_release: dict[str, list[dict[str, Any]]] = {}
    for h in hosts:
        codename = str(h.get("codename", ""))
        if CODENAME_RE.match(codename):
            by_release.setdefault(codename, []).append(h)
        else:
            out["errors"][str(h["host"])] = f"unknown Ubuntu codename {codename!r}"

    for codename, group in sorted(by_release.items()):
        index, out["releases"][codename] = load_release(codename, args.cache_dir, args.url_base, args.timeout)
        cve_index = None
        if args.unfixed and index is not None:
            cve_index, out["releases"][f"{codename}-cve"] = load_release(
                codename, args.cache_dir, args.url_base, args.timeout, kind="cve")
        for h in group:
            name = str(h["host"])
            result = _host_result(h, index, cve_index, out["releases"], codename, args)
            if isinstance(result, str):
                out["errors"][name] = result
            else:
                out["hosts"][name] = result
        del index, cve_index

    json.dump(out, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
