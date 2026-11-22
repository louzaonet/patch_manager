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
                host.cve_ids = sorted(
                    {c for c in _str_list(report.get("cves")) if _CVE_RE.match(c)}
                )
                host.reboot_required = bool(report.get("reboot_required", False))

            run_path = self._host_file("patch-runs", host.hostname)
            run = _read_json(run_path) if run_path else None
            if run:
                host.last_patch_status = _label(run.get("status"), 20)
                host.last_patch_at = _label(run.get("timestamp"), 30)

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
