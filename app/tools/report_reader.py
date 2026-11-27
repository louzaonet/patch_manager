"""
Report Reader: loads the per-host JSON reports written by the playbooks and
merges them into HostInfo objects.

Layout under REPORTS_PATH:
    hosts/<inventory_hostname>.json        written by check_updates.yml
    packages/<inventory_hostname>.json     installed packages, check_updates.yml
    patch-runs/<inventory_hostname>.json   written by apply_patches.yml
    package-queries/<id>/<host>.json       live answers, package_query.yml
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from app.agents.state import HostInfo
from app.config import get_settings

logger = structlog.get_logger()

_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_QUERY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{4,40}$")
_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]{0,199}$")
# Debian and RPM versions: epochs (1:), tildes, pluses; several joined by ", ".
_PKG_VERSION_RE = re.compile(r"^[A-Za-z0-9.+:~_, -]{1,200}$")
MAX_LIST_ITEMS = 200
MAX_CVES = 2000           # one Ubuntu kernel notice alone lists over a hundred
_PRIORITIES = ("negligible", "low", "medium", "high", "critical")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?$")
# As do-release-upgrade prints it: "26.04.1 LTS", "26.10".
_RELEASE_RE = re.compile(r"^\d{2}\.\d{2}(?:\.\d{1,2})?(?: LTS)?$")
MAX_PACKAGES = 20000


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("report_unreadable", path=str(path), error=str(exc))
        return None


def _int(value: Any) -> int:
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


def _label(value: Any, max_len: int = 80) -> str:
    """
    Short printable label. The OS string comes from facts gathered on the
    managed host and ends up in LLM prompts, so keep it short and plain.
    """
    return re.sub(r"[^\w .()/+-]", "", str(value or ""))[:max_len].strip()


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value[:MAX_LIST_ITEMS]]


def _cve_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({str(c) for c in value[:MAX_CVES] if _CVE_RE.match(str(c))})


def _cve_priorities(notices: Any) -> dict[str, str]:
    """CVE -> highest Ubuntu priority among the notices (USN) that list it."""
    out: dict[str, str] = {}
    if not isinstance(notices, list):
        return out
    for n in notices[:1000]:
        if not isinstance(n, dict):
            continue
        prio = str(n.get("severity") or "").lower()
        if prio not in _PRIORITIES:
            continue
        for c in _cve_list(n.get("cves")):
            if c not in out or _PRIORITIES.index(prio) > _PRIORITIES.index(out[c]):
                out[c] = prio
    return out


class ReportReader:
    def __init__(self, base_path: str | None = None):
        self.base = Path(base_path or get_settings().reports_path)

    def _host_file(self, subdir: str, hostname: str) -> Path | None:
        # Hostnames come from the inventory, but never build paths from
        # unexpected characters.
        if not _SAFE_NAME_RE.match(hostname):
            return None
        return self.base / subdir / f"{hostname}.json"

    def enrich(self, hosts: list[HostInfo], now: datetime | None = None) -> None:
        """Fill report fields on each host in place."""
        now = now or datetime.now(UTC)
        for host in hosts:
            path = self._host_file("hosts", host.hostname)
            report = _read_json(path) if path else None
            if report:
                checked = _parse_time(report.get("checked_at"))
                host.report_found = True
                host.report_age_hours = (
                    round((now - checked).total_seconds() / 3600, 1) if checked else None
                )
                host.os_name = _label(report.get("os"))
                host.update_count = _int(report.get("update_count"))
                host.security_count = _int(report.get("security_count"))
                host.pending_updates = _str_list(report.get("packages"))
                host.security_updates = _str_list(report.get("security_packages"))
                host.cve_ids = _cve_list(report.get("cves"))
                host.reboot_required = bool(report.get("reboot_required", False))
                self._read_cve_data(host, report)

            run_path = self._host_file("patch-runs", host.hostname)
            run = _read_json(run_path) if run_path else None
            if run:
                host.last_patch_status = _label(run.get("status"), 20)
                host.last_patch_at = _label(run.get("timestamp"), 30)

    @staticmethod
    def _read_cve_data(host: HostInfo, report: dict[str, Any]) -> None:
        """Fields added by the OVAL step of check_updates.yml (Ubuntu only)."""
        if host.os_group != "ubuntu_servers":
            return
        host.cve_source = _label(report.get("cve_source"), 30)
        at = str(report.get("cve_data_at") or "")
        host.cve_data_at = at if _TIMESTAMP_RE.match(at) else ""
        host.cve_pro_only_ids = sorted(set(_cve_list(report.get("cves_pro_only"))) - set(host.cve_ids))
        host.cve_priority = _cve_priorities(report.get("cve_notices"))
        host.security_without_notice = [
            p for p in _str_list(report.get("security_without_notice")) if _PKG_NAME_RE.match(p)]
        host.kernel_not_covered = bool(report.get("kernel_checked")) and not report.get("kernel_covered")
        release = str(report.get("release_upgrade_to") or "")
        host.release_upgrade_to = release if _RELEASE_RE.match(release) else ""
        if report.get("release_check_error"):
            error = _label(report.get("release_check_error"), 120)
            host.release_check_note = f"release check failed: {error}"
        if not host.cve_source:
            # Reports from before 1.3.0 have neither field: say nothing then.
            err = report.get("cve_error")
            host.cve_note = f"no CVE data: {_label(err, 160)}" if err else ""
        elif report.get("cve_data_warning"):
            host.cve_note = f"CVE data not refreshed: {_label(report.get('cve_data_warning'), 160)}"

        counts = report.get("unfixed_cve_counts")
        if isinstance(counts, dict):
            host.unfixed_counts = {p: _int(counts.get(p)) for p in _PRIORITIES}
        top = report.get("unfixed_cves_top")
        host.unfixed_top = []
        if isinstance(top, list):
            for item in top[:100]:
                if not isinstance(item, dict) or not _CVE_RE.match(str(item.get("cve", ""))):
                    continue
                prio = str(item.get("priority", "")).lower()
                host.unfixed_top.append({
                    "cve": str(item["cve"]),
                    "priority": prio if prio in _PRIORITIES else "unknown",
                    "packages": [p for p in _str_list(item.get("packages"))[:5] if _PKG_NAME_RE.match(p)],
                })
        host.unfixed_ids = _cve_list(report.get("unfixed_cves"))
        if report.get("unfixed_error"):
            host.unfixed_note = f"no data on CVEs without a fix: {_label(report.get('unfixed_error'), 160)}"
        elif report.get("unfixed_data_warning"):
            warning = _label(report.get("unfixed_data_warning"), 160)
            host.unfixed_note = f"data on CVEs without a fix not refreshed: {warning}"

    # ─── Installed packages ──────────────────────────────────────────────

    def read_packages(
        self, hostname: str, now: datetime | None = None
    ) -> tuple[dict[str, str], float] | None:
        """Installed packages of a host and the age of that list in hours, or None."""
        path = self._host_file("packages", hostname)
        data = _read_json(path) if path else None
        if not data or not isinstance(data.get("packages"), dict):
            return None
        collected = _parse_time(data.get("collected_at"))
        now = now or datetime.now(UTC)
        age = round((now - collected).total_seconds() / 3600, 1) if collected else -1.0
        packages = {
            str(name): str(version)
            for name, version in list(data["packages"].items())[:MAX_PACKAGES]
            if _PKG_NAME_RE.match(str(name)) and _PKG_VERSION_RE.match(str(version))
        }
        return packages, age

    def read_query_result(self, query_id: str, hostname: str) -> list[dict[str, str]] | None:
        """Matches written by package_query.yml for one host, or None if it did not answer."""
        if not _QUERY_ID_RE.match(query_id) or not _SAFE_NAME_RE.match(hostname):
            return None
        data = _read_json(self.base / "package-queries" / query_id / f"{hostname}.json")
        if not data or not isinstance(data.get("matches"), list):
            return None
        return [
            {"name": str(m["name"]), "version": str(m["version"])}
            for m in data["matches"][:MAX_LIST_ITEMS]
            if isinstance(m, dict)
            and _PKG_NAME_RE.match(str(m.get("name", "")))
            and _PKG_VERSION_RE.match(str(m.get("version", "")))
        ]
