"""
Report Reader: loads the per-host JSON reports written by the playbooks and
merges them into HostInfo objects.

Layout under REPORTS_PATH:
    hosts/<inventory_hostname>.json        written by check_updates.yml
    patch-runs/<inventory_hostname>.json   written by apply_patches.yml
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
MAX_LIST_ITEMS = 200


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
