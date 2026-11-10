"""
CVE Scanner: enriches the CVE IDs reported by hosts and gathers recent CVE
context per OS family.

Sources:
  - CISA Known Exploited Vulnerabilities (KEV) catalog: one JSON download,
    cached, used to flag CVEs that are exploited in the wild.
  - NIST NVD API 2.0: CVSS scores for specific CVE IDs, plus an optional
    keyword search for recent critical CVEs per OS family (context only;
    those are NOT attached to hosts, because a keyword hit says nothing
    about whether a given host is affected).

NVD rate limits: 5 requests / 30 s without an API key, 50 / 30 s with one.
Lookups are throttled and bounded by NVD_LOOKUP_LIMIT and
NVD_LOOKUP_BUDGET_SECONDS so a run never stalls on the NVD API.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.config import get_settings

logger = structlog.get_logger()

# Keyword per OS family for the context search. One term each: NVD
# keywordSearch ANDs all words, so long keyword lists return nothing.
OS_CONTEXT_KEYWORDS: dict[str, str] = {
    "ubuntu_servers": "Ubuntu",
    "rocky_servers": "Red Hat Enterprise Linux",
    "macos_servers": "macOS",
    "windows_servers": "Microsoft Windows",
}

_KEV_TTL = 12 * 3600
_NVD_TTL = 24 * 3600
_NVD_MISS_TTL = 6 * 3600  # CVE ID not (yet) published in the NVD
_CONTEXT_TTL = 6 * 3600
_NVD_DOWN_TTL = 300  # after a failed call, skip the NVD for a while


class _TTLCache:
    """Tiny in-process cache. Good enough for a single-worker service."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        item = self._data.get(key)
        if not item:
            return None
        expires, value = item
        if time.monotonic() > expires:
            self._data.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any, ttl: float) -> None:
        self._data[key] = (time.monotonic() + ttl, value)

    def clear(self) -> None:
        self._data.clear()


_cache = _TTLCache()
_nvd_lock = asyncio.Lock()
_nvd_last_call = 0.0


def clear_caches() -> None:
    _cache.clear()


def parse_cve_item(cve: dict[str, Any]) -> dict[str, Any]:
    """Reduce one NVD `cve` object to the fields the agent uses."""
    descriptions = cve.get("descriptions", [])
    description = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )

    metrics = cve.get("metrics", {}) or {}
    score, severity, vector = 0.0, "UNKNOWN", "UNKNOWN"
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        # Prefer the NVD's own (Primary) score when several sources exist.
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {}) or {}
        score = float(data.get("baseScore", 0.0) or 0.0)
        severity = data.get("baseSeverity") or entry.get("baseSeverity") or "UNKNOWN"
        vector = data.get("attackVector") or data.get("accessVector") or "UNKNOWN"
        break

    return {
        "id": cve.get("id", ""),
        "description": description[:400],
        "score": score,
        "severity": str(severity).upper(),
        "attack_vector": vector,
        "published": cve.get("published", ""),
    }


class CVEScanner:
    """Async client for KEV and NVD with caching and throttling."""

    def __init__(self) -> None:
        s = get_settings()
        self.settings = s
        self.headers = {"apiKey": s.nvd_api_key} if s.nvd_api_key else {}
        # Seconds between NVD calls to stay under the published rate limits.
        self.min_interval = 0.7 if s.nvd_api_key else 6.2
        self.timeout = 15.0

    # ─── KEV ────────────────────────────────────────────────────────────

    async def get_kev_ids(self) -> dict[str, dict[str, Any]]:
        """CVE ID -> KEV entry. Empty dict if disabled or unreachable."""
        if not self.settings.kev_enabled:
            return {}
        cached = _cache.get("kev")
        if cached is not None:
            return cached
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(self.settings.kev_url)
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("kev_fetch_failed", error=str(exc))
            _cache.set("kev", {}, 900)  # don't hammer it on every request
            return {}

        kev = {
            v.get("cveID"): {
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "date_added": v.get("dateAdded", ""),
                "due_date": v.get("dueDate", ""),
                "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
            }
            for v in data.get("vulnerabilities", [])
            if v.get("cveID")
        }
        _cache.set("kev", kev, _KEV_TTL)
        logger.info("kev_loaded", entries=len(kev))
        return kev

    # ─── NVD ────────────────────────────────────────────────────────────

    async def _nvd_get(self, params: dict[str, Any]) -> dict[str, Any] | None:
        """
        One throttled NVD request. Returns None on failure and opens a short
        circuit breaker, so an NVD outage costs one timeout instead of one
        per CVE and per OS family on every analysis.
        """
        global _nvd_last_call
        if _cache.get("nvd:down"):
            return None
        async with _nvd_lock:
            if _cache.get("nvd:down"):
                return None
            wait = self.min_interval - (time.monotonic() - _nvd_last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.get(
                        self.settings.nvd_api_url, params=params, headers=self.headers
                    )
                    _nvd_last_call = time.monotonic()
                    resp.raise_for_status()
                    return resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                _nvd_last_call = time.monotonic()
                _cache.set("nvd:down", True, _NVD_DOWN_TTL)
                logger.warning("nvd_request_failed", params=params, error=str(exc),
                               retry_after_seconds=_NVD_DOWN_TTL)
                return None

    async def lookup_cves(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """
        CVSS details for specific CVE IDs. Uses the cache first, then the NVD
        API within the configured count and time budget. Missing entries are
        simply absent from the result.
        """
        results: dict[str, dict[str, Any]] = {}
        todo: list[str] = []
        for cve_id in cve_ids:
            cached = _cache.get(f"nvd:{cve_id}")
            if cached is not None:
                results[cve_id] = cached
            else:
                todo.append(cve_id)

        if not self.settings.nvd_enabled or not todo:
            return results

        deadline = time.monotonic() + self.settings.nvd_lookup_budget_seconds
        for cve_id in todo[: self.settings.nvd_lookup_limit]:
            if time.monotonic() + self.min_interval > deadline:
                logger.info("nvd_budget_exhausted", remaining=len(todo))
                break
            data = await self._nvd_get({"cveId": cve_id})
            if data is None:
                break  # NVD unreachable: stop, the breaker is open
            items = data.get("vulnerabilities", [])
            if not items:
                # Unknown to the NVD (reserved or very new). Remember that,
                # so it isn't looked up again on every analysis.
                _cache.set(f"nvd:{cve_id}", {"id": cve_id, "score": 0.0, "severity": "UNKNOWN"},
                           _NVD_MISS_TTL)
            for item in items:
                parsed = parse_cve_item(item.get("cve", {}))
                if parsed["id"]:
                    _cache.set(f"nvd:{parsed['id']}", parsed, _NVD_TTL)
                    results[parsed["id"]] = parsed
        return results

    async def recent_context(self, os_groups: list[str]) -> list[dict[str, Any]]:
        """
        Recent CRITICAL CVEs mentioning each OS family. Context for the
        briefing only.
        """
        s = self.settings
        if not (s.nvd_enabled and s.nvd_context_enabled):
            return []

        end = datetime.now(UTC)
        start = end - timedelta(days=min(max(s.nvd_context_days, 1), 120))
        out: list[dict[str, Any]] = []
        for group in os_groups:
            keyword = OS_CONTEXT_KEYWORDS.get(group)
            if not keyword:
                continue
            key = f"ctx:{group}:{s.nvd_context_days}"
            cached = _cache.get(key)
            if cached is None:
                data = await self._nvd_get(
                    {
                        "keywordSearch": keyword,
                        "cvssV3Severity": "CRITICAL",
                        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        "resultsPerPage": 20,
                    }
                )
                cached = [
                    {**parse_cve_item(i.get("cve", {})), "os_group": group}
                    for i in (data or {}).get("vulnerabilities", [])
                ]
                cached.sort(key=lambda c: c["score"], reverse=True)
                if data is not None:
                    _cache.set(key, cached, _CONTEXT_TTL)
            out.extend(cached[:5])
        return out
