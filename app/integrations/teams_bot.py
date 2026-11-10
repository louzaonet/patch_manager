"""
Microsoft Teams integration.

Outbound (notifications): Office 365 connector webhooks were switched off in
May 2026. Create a Workflows webhook instead (Teams > Workflows > "Post to a
channel when a webhook request is received") and put its URL in
TEAMS_WEBHOOK_URL. The Adaptive Card payload below is the format that
workflow template expects.

Inbound (optional): a Teams Outgoing Webhook can send @mentions to
/api/integrations/teams. Requests are HMAC-verified with
TEAMS_OUTGOING_SECRET. Teams waits only ~5 seconds, so the route answers
immediately and the briefing is posted later through the Workflows webhook.
Plans cannot be approved from Teams; use the dashboard or Slack.
"""

from __future__ import annotations

import httpx
import structlog

from app.config import get_settings

logger = structlog.get_logger()


def _card(body: list[dict], actions: list[dict] | None = None) -> dict:
    content: dict = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    if actions:
        content["actions"] = actions
    return {
        "type": "message",
        "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": content}
        ],
    }


class TeamsBot:
    def __init__(self) -> None:
        s = get_settings()
        self.enabled = s.teams_enabled
        self.webhook_url = s.teams_webhook_url
        self.public_url = s.public_base_url.rstrip("/")
        self.timeout = 15.0

    async def send_briefing(self, briefing: str, plan_id: str | None = None) -> bool:
        if not (self.enabled and self.webhook_url):
            return False
        body: list[dict] = [
            {"type": "TextBlock", "text": "Patch Manager AI", "weight": "Bolder", "size": "Large"},
        ]
        for section in [s for s in briefing.split("\n\n") if s.strip()][:12]:
            body.append({"type": "TextBlock", "text": section.strip()[:1500], "wrap": True})
        if plan_id:
            body.append(
                {
                    "type": "TextBlock",
                    "text": f"Plan {plan_id} is waiting for approval in the dashboard.",
                    "wrap": True,
                    "color": "Warning",
                    "weight": "Bolder",
                }
            )
        actions = (
            [{"type": "Action.OpenUrl", "title": "Open dashboard", "url": self.public_url}]
            if self.public_url
            else None
        )
        return await self._post(_card(body, actions))

    async def send_alert(self, title: str, message: str, severity: str = "warning") -> bool:
        if not (self.enabled and self.webhook_url):
            return False
        style = {"critical": "attention", "high": "warning", "warning": "warning",
                 "info": "accent", "success": "good"}.get(severity, "default")
        body = [{"type": "Container", "style": style, "items": [
            {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium"},
            {"type": "TextBlock", "text": message[:2000], "wrap": True},
        ]}]
        return await self._post(_card(body))

    async def _post(self, payload: dict) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.webhook_url, json=payload)
            if resp.status_code in (200, 202):
                return True
            logger.error("teams_webhook_error", status=resp.status_code, body=resp.text[:200])
            return False
        except httpx.HTTPError as exc:
            logger.error("teams_send_error", error=str(exc))
            return False
