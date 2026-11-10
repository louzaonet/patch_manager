"""
Slack integration.

Slash command flow (/patch ...):
  1. Verify the request signature (done in the route).
  2. Answer within Slack's 3-second limit with an ephemeral "working on it".
  3. Run the agent in the background and post the result to the command's
     response_url (no bot token needed), falling back to chat.postMessage.

Approvals: `/patch approve <plan_id>` and `/patch reject <plan_id>` work only
for Slack user IDs listed in SLACK_APPROVER_IDS.
"""

from __future__ import annotations

import re

import httpx
import structlog

from app.config import get_settings

logger = structlog.get_logger()

SLACK_SECTION_LIMIT = 2900


def markdown_to_mrkdwn(text: str) -> str:
    """Convert the common bits of GitHub markdown to Slack mrkdwn."""
    out = re.sub(r"^#{1,6}\s+(.+)$", r"*\1*", text, flags=re.M)  # headers -> bold
    out = re.sub(r"\*\*(.+?)\*\*", r"*\1*", out)  # **bold** -> *bold*
    out = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r"<\2|\1>", out)  # links
    return out


def _chunks(text: str, size: int = SLACK_SECTION_LIMIT) -> list[str]:
    parts, current = [], ""
    for para in text.split("\n\n"):
        if len(current) + len(para) + 2 > size and current:
            parts.append(current)
            current = ""
        while len(para) > size:
            parts.append(para[:size])
            para = para[size:]
        current = f"{current}\n\n{para}" if current else para
    if current:
        parts.append(current)
    return parts


class SlackBot:
    def __init__(self) -> None:
        s = get_settings()
        self.enabled = s.slack_enabled
        self.signing_secret = s.slack_signing_secret or ""
        self.bot_token = s.slack_bot_token
        self.default_channel = s.slack_default_channel
        self.public_url = s.public_base_url.rstrip("/")

    def build_blocks(self, briefing: str, plan_id: str | None = None) -> list[dict]:
        blocks: list[dict] = [
            {"type": "header", "text": {"type": "plain_text", "text": "Patch Manager AI"}},
        ]
        for chunk in _chunks(markdown_to_mrkdwn(briefing))[:10]:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": chunk}})
        if plan_id:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f":warning: Plan `{plan_id}` is waiting for approval. "
                        f"Approvers: `/patch approve {plan_id}` or `/patch reject {plan_id}`.",
                    },
                }
            )
        if self.public_url:
            blocks.append(
                {"type": "context", "elements": [
                    {"type": "mrkdwn", "text": f"<{self.public_url}|Open dashboard>"}]}
            )
        return blocks

    async def respond(self, response_url: str | None, text: str, blocks: list[dict] | None = None,
                      in_channel: bool = True, channel: str | None = None) -> bool:
        """Reply via response_url when available, else chat.postMessage."""
        payload = {
            "response_type": "in_channel" if in_channel else "ephemeral",
            "text": text[:3000],
            "replace_original": False,
        }
        if blocks:
            payload["blocks"] = blocks

        if response_url and response_url.startswith("https://hooks.slack.com/"):
            try:
                async with httpx.AsyncClient(timeout=15) as client:
                    resp = await client.post(response_url, json=payload)
                if resp.status_code == 200:
                    return True
                logger.warning("slack_response_url_failed", status=resp.status_code, body=resp.text[:200])
            except httpx.HTTPError as exc:
                logger.warning("slack_response_url_error", error=str(exc))

        return await self.post_message(text, channel=channel, blocks=blocks)

    async def post_message(self, text: str, channel: str | None = None,
                           blocks: list[dict] | None = None) -> bool:
        if not self.bot_token:
            logger.warning("slack_no_bot_token")
            return False
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    "https://slack.com/api/chat.postMessage",
                    headers={"Authorization": f"Bearer {self.bot_token}"},
                    json={"channel": channel or self.default_channel, "text": text[:3000],
                          "blocks": blocks or [], "mrkdwn": True},
                )
            data = resp.json()
            if not data.get("ok"):
                logger.error("slack_post_failed", error=data.get("error"))
                return False
            return True
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("slack_post_error", error=str(exc))
            return False
