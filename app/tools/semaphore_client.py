"""
Semaphore Client: thin async wrapper over the Semaphore UI REST API.

Task creation sends extra vars through the `environment` field (a JSON
*string*, as the API expects) and the host limit through `limit` (Semaphore
splits it on commas into params.limit). Checked against Semaphore 2.19.12:
extra vars are always applied, but the limit is only honoured when the
template allows overriding it, otherwise the run silently targets every
host. run_template() therefore refuses a limited run on such a template.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

from app.config import get_settings

logger = structlog.get_logger()


class SemaphoreError(RuntimeError):
    """Raised when the Semaphore API returns an error or is unreachable."""


class SemaphoreClient:
    def __init__(self) -> None:
        s = get_settings()
        self.base_url = s.semaphore_url.rstrip("/")
        self.token = s.semaphore_api_token.strip()
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.timeout = s.semaphore_timeout
        self.configured_project_id = s.semaphore_project_id

    # ─── Lookups ────────────────────────────────────────────────────────

    async def get_projects(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/api/projects")

    async def resolve_project_id(self) -> int:
        if self.configured_project_id:
            return self.configured_project_id
        projects = await self.get_projects()
        if not projects:
            raise SemaphoreError("No Semaphore projects found (set SEMAPHORE_PROJECT_ID)")
        if len(projects) > 1:
            logger.warning(
                "semaphore_multiple_projects", using=projects[0].get("id"),
                hint="set SEMAPHORE_PROJECT_ID",
            )
        return int(projects[0]["id"])

    async def get_templates(self, project_id: int) -> list[dict[str, Any]]:
        return await self._request("GET", f"/api/project/{project_id}/templates")

    async def find_template_by_name(self, project_id: int, name: str) -> dict[str, Any] | None:
        """Exact (case-insensitive) name match first, then unique substring match."""
        templates = await self.get_templates(project_id)
        wanted = name.strip().lower()
        exact = [t for t in templates if t.get("name", "").strip().lower() == wanted]
        if exact:
            return exact[0]
        partial = [t for t in templates if wanted in t.get("name", "").lower()]
        if len(partial) == 1:
            return partial[0]
        if len(partial) > 1:
            names = ", ".join(t.get("name", "?") for t in partial)
            raise SemaphoreError(f"Template name '{name}' is ambiguous: {names}")
        return None

    # ─── Tasks ──────────────────────────────────────────────────────────

    async def run_template(
        self,
        project_id: int,
        template_id: int,
        extra_vars: dict[str, Any] | None = None,
        limit: str | None = None,
        message: str = "",
    ) -> dict[str, Any]:
        if limit:
            # Verified against Semaphore 2.19: if the template doesn't allow
            # overriding the limit, the task is accepted, the limit is stored,
            # and the playbook runs on EVERY host. Refuse instead.
            template = await self._request("GET", f"/api/project/{project_id}/templates/{template_id}")
            params = (template or {}).get("task_params") or {}
            if not params.get("allow_override_limit"):
                name = (template or {}).get("name", template_id)
                raise SemaphoreError(
                    f"Template '{name}' does not allow overriding the limit, so Semaphore would run it "
                    "on all hosts. Enable the limit override option in the template settings."
                )
        payload: dict[str, Any] = {
            "template_id": template_id,
            "debug": False,
            "dry_run": False,
            "environment": json.dumps(extra_vars or {}),
        }
        if limit:
            payload["limit"] = limit
        if message:
            payload["message"] = message[:250]
        return await self._request("POST", f"/api/project/{project_id}/tasks", json_body=payload)

    async def get_task(self, project_id: int, task_id: int) -> dict[str, Any]:
        return await self._request("GET", f"/api/project/{project_id}/tasks/{task_id}")

    async def get_recent_tasks(self, project_id: int, limit: int = 10) -> list[dict[str, Any]]:
        tasks = await self._request("GET", f"/api/project/{project_id}/tasks/last")
        return (tasks or [])[:limit]

    # ─── HTTP ───────────────────────────────────────────────────────────

    async def _request(
        self, method: str, path: str, json_body: dict[str, Any] | None = None
    ) -> Any:
        if not self.token:
            raise SemaphoreError("SEMAPHORE_API_TOKEN is not set (Semaphore > user menu > API Tokens)")
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.request(method, url, headers=self.headers, json=json_body)
        except httpx.HTTPError as exc:
            logger.error("semaphore_unreachable", method=method, path=path, error=str(exc))
            raise SemaphoreError(f"Semaphore unreachable: {exc}") from exc

        if resp.status_code >= 400:
            body = resp.text[:300]
            logger.error("semaphore_api_error", method=method, path=path,
                         status=resp.status_code, body=body)
            raise SemaphoreError(f"Semaphore {method} {path} returned {resp.status_code}: {body}")
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise SemaphoreError(f"Semaphore returned non-JSON for {path}") from exc
