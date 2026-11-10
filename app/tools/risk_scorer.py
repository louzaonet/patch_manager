"""
Risk Scorer: composite 0-100 score per host, built only from data the host
actually reported (pending security updates, CVEs from the package
advisories, KEV membership) plus the criticality you assign in the inventory.

Inventory example:
    ubuntu-db-01:
      ansible_host: 192.168.1.20
      patch_criticality: high      # high | medium | low (default: medium)

Hosts without a recent report get a low-confidence score and a factor that
says so, instead of a made-up number.
"""

from __future__ import annotations

from dataclasses import replace

from app.agents.state import HostInfo


class RiskScorer:
    WEIGHTS = {
        "security_updates": 0.30,
        "known_exploited": 0.25,
        "cvss": 0.15,
        "criticality": 0.15,
        "update_backlog": 0.10,
        "reboot_pending": 0.05,
    }
    CRITICALITY_SCORE = {"high": 100.0, "medium": 50.0, "low": 15.0}

    def score_host(self, host: HostInfo) -> HostInfo:
        """Return a copy of `host` with risk_score and risk_factors set."""
        factors: list[str] = []

        if host.data_stale:
            if host.report_found:
                factors.append(f"Update data is {host.report_age_hours}h old; run Check Updates")
            else:
                factors.append("No update report yet; run Check Updates")

        sec_score = min(host.security_count * 20.0, 100.0)
        if host.security_count:
            factors.append(f"{host.security_count} pending security update(s)")

        kev_score = 100.0 if host.kev_cves else 0.0
        if host.kev_cves:
            shown = ", ".join(host.kev_cves[:3])
            factors.append(f"Known exploited (CISA KEV): {shown}")

        max_cvss = max((c.get("score", 0.0) for c in host.cve_matches), default=0.0)
        cvss_score = max_cvss * 10.0
        if max_cvss >= 9.0:
            factors.append(f"Critical CVE pending (CVSS {max_cvss})")
        elif max_cvss >= 7.0:
            factors.append(f"High-severity CVE pending (CVSS {max_cvss})")

        crit_score = self.CRITICALITY_SCORE.get(host.criticality, 50.0)
        if host.criticality == "high":
            factors.append("Marked high criticality in inventory")

        backlog_score = min(host.update_count * 4.0, 100.0)
        if host.update_count > 25:
            factors.append(f"{host.update_count} pending updates (large backlog)")

        reboot_score = 100.0 if host.reboot_required else 0.0
        if host.reboot_required:
            factors.append("Reboot pending from earlier updates")

        w = self.WEIGHTS
        composite = (
            sec_score * w["security_updates"]
            + kev_score * w["known_exploited"]
            + cvss_score * w["cvss"]
            + crit_score * w["criticality"]
            + backlog_score * w["update_backlog"]
            + reboot_score * w["reboot_pending"]
        )
        # A KEV hit on a host is urgent regardless of the other factors.
        if host.kev_cves:
            composite = max(composite, 80.0)

        return replace(host, risk_score=round(min(composite, 100.0), 1), risk_factors=factors)

    def score_all(self, hosts: list[HostInfo]) -> list[HostInfo]:
        """Score every host; highest risk first."""
        scored = [self.score_host(h) for h in hosts]
        scored.sort(key=lambda h: h.risk_score, reverse=True)
        return scored

    @staticmethod
    def classify(score: float) -> str:
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        return "LOW"
