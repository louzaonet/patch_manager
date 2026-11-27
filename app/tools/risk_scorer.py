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

Ubuntu CVEs come from Canonical's USN OVAL data (check_updates.yml). When the
NVD has no score for one, the CVSS factor uses the lowest score of the band
that matches Canonical's priority (UBUNTU_PRIORITY_SCORE). CVEs fixed only
with Ubuntu Pro are not installable without a subscription: they are listed
as a factor and only change the score when one is in KEV.
"""

from __future__ import annotations

from dataclasses import replace

from app.agents.state import HostInfo

PRIORITY_RANK = {"negligible": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Lowest CVSS of the band for each Canonical priority (critical 9.0-10, high 7.0-8.9, ...)
UBUNTU_PRIORITY_SCORE = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1, "negligible": 0.0}


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
            if host.report_found and host.report_age_hours is None:
                factors.append("Update report has no valid date (missing or in the future); "
                               "run Check Updates")
            elif host.report_found:
                factors.append(f"Update data is {host.report_age_hours}h old; run Check Updates")
            else:
                factors.append("No update report yet; run Check Updates")

        sec_score = min(host.security_count * 20.0, 100.0)
        if host.security_count:
            factors.append(f"{host.security_count} pending security update(s)")

        kev_any = host.kev_cves or host.kev_pro_only_cves
        kev_score = 100.0 if kev_any else 0.0
        if host.kev_cves:
            shown = ", ".join(host.kev_cves[:3])
            factors.append(f"Known exploited (CISA KEV): {shown}")
        if host.kev_pro_only_cves:
            shown = ", ".join(host.kev_pro_only_cves[:3])
            factors.append(f"Known exploited, fix needs Ubuntu Pro: {shown}")
        if host.kev_unfixed_cves:
            # Not scored: no update removes it. Flagged so it is seen first.
            shown = ", ".join(host.kev_unfixed_cves[:3])
            factors.append(f"Known exploited, no fix yet (review exposure): {shown}")

        top = max(host.cve_matches, key=lambda c: c.get("score", 0.0), default=None)
        max_cvss = top.get("score", 0.0) if top else 0.0
        cvss_score = max_cvss * 10.0
        if top and top.get("score_source") == "ubuntu" and max_cvss >= 7.0:
            prio = str(top.get("severity", "")).capitalize()
            factors.append(f"{prio}-priority Ubuntu CVE pending ({top['id']})")
        elif max_cvss >= 9.0:
            factors.append(f"Critical CVE pending (CVSS {max_cvss})")
        elif max_cvss >= 7.0:
            factors.append(f"High-severity CVE pending (CVSS {max_cvss})")
        if host.cve_pro_only_ids and not host.kev_pro_only_cves:
            # Listed for context; it adds nothing to the score (the model used to
            # name it as what drove the risk).
            factors.append(f"{len(host.cve_pro_only_ids)} CVE(s) fixable only with Ubuntu Pro (not scored)")
        elif host.cve_pro_only_ids:
            factors.append(f"{len(host.cve_pro_only_ids)} CVE(s) fixable only with Ubuntu Pro")
        if host.kernel_not_covered:
            factors.append("Running kernel not covered by Canonical's CVE data")
        if host.cve_note:
            factors.append(host.cve_note[:120])

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
        if kev_any:
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
