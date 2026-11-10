"""Shared fixtures: isolated settings, a temp inventory and host reports."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

# Settings are read at import time by app.main, so set a sane baseline first.
os.environ["PATCH_AI_ENV_FILE"] = ""
os.environ.setdefault("LLM_DEFAULT", "openai_compat:test-model")
os.environ.setdefault("APP_AUTH_PASSWORD", "test-password-123")

INVENTORY = """
all:
  children:
    ubuntu_servers:
      hosts:
        ubuntu-web-01:
          ansible_host: 10.0.0.10
        ubuntu-db-01:
          ansible_host: 10.0.0.20
          patch_criticality: high
    rocky_servers:
      hosts:
        rocky-app-01:
          ansible_host: 10.0.0.30
    macos_servers:
      hosts:
        mac-build-01:
          ansible_host: 10.0.0.50
    windows_servers:
      children:
        win_desktops:
          hosts:
            win-desktop-01:
              ansible_host: 10.0.0.70
      vars:
        ansible_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          6162636465
    production:
      children:
        ubuntu_servers:
        rocky_servers:
"""


def _write_report(base: Path, host: str, **fields) -> None:
    (base / "hosts").mkdir(parents=True, exist_ok=True)
    data = {
        "schema": 1,
        "host": host,
        "checked_at": datetime.now(UTC).isoformat(),
        "update_count": 0,
        "security_count": 0,
        "packages": [],
        "security_packages": [],
        "cves": [],
        "reboot_required": False,
    }
    data.update(fields)
    (base / "hosts" / f"{host}.json").write_text(json.dumps(data))


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Fresh settings pointing at a temp inventory and reports dir."""
    inv = tmp_path / "hosts.yml"
    inv.write_text(INVENTORY)
    reports = tmp_path / "reports"
    _write_report(reports, "ubuntu-web-01", os="Ubuntu 24.04", update_count=12, security_count=3,
                  packages=["openssl", "curl"], security_packages=["openssl"])
    _write_report(reports, "ubuntu-db-01", os="Ubuntu 24.04", update_count=4, security_count=1,
                  cves=["CVE-2026-0001"], reboot_required=True)
    _write_report(reports, "rocky-app-01", os="Rocky Linux 10.1", update_count=30, security_count=6,
                  cves=["CVE-2026-0002", "CVE-2026-0003", "not-a-cve"])
    _write_report(reports, "mac-build-01", os="macOS 26.1", update_count=1,
                  checked_at=(datetime.now(UTC) - timedelta(days=5)).isoformat())
    # win-desktop-01 has no report on purpose.

    values = {
        "PATCH_AI_ENV_FILE": "",
        "LLM_DEFAULT": "openai_compat:test-model",
        "APP_AUTH_USER": "admin",
        "APP_AUTH_PASSWORD": "test-password-123",
        "APP_API_TOKEN": "test-token",
        "INVENTORY_PATH": str(inv),
        "REPORTS_PATH": str(reports),
        "SEMAPHORE_URL": "http://semaphore.test",
        "SEMAPHORE_API_TOKEN": "sem-token",
        "SEMAPHORE_PROJECT_ID": "1",
        "NVD_ENABLED": "false",
        "KEV_ENABLED": "false",
        "SLACK_ENABLED": "false",
        "TEAMS_ENABLED": "false",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)

    from app.config import get_settings
    from app.security import reset_auth_failures
    from app.tools import cve_scanner, llm_router

    get_settings.cache_clear()
    llm_router.clear_cache()
    cve_scanner.clear_caches()
    reset_auth_failures()
    yield {"inventory": inv, "reports": reports, "tmp": tmp_path}
    get_settings.cache_clear()
    llm_router.clear_cache()


class FakeLLM:
    """Stands in for _ask_llm: returns canned text per task, records prompts."""

    def __init__(self, intent: dict | None = None, fail: set[str] | None = None):
        self.intent = intent or {"action": "ask_question"}
        self.fail = fail or set()
        self.prompts: dict[str, list[str]] = {}

    async def __call__(self, task: str, prompt: str) -> str:
        self.prompts.setdefault(task, []).append(prompt)
        if task in self.fail:
            raise ConnectionError(f"{task} model offline")
        if task == "classify_intent":
            return "<think>hmm</think>\n```json\n" + json.dumps(self.intent) + "\n```"
        if task == "generate_briefing":
            return "## Briefing\nAll good."
        return "Answer from the model."


@pytest.fixture
def fake_llm(monkeypatch):
    def install(**kwargs) -> FakeLLM:
        fake = FakeLLM(**kwargs)
        monkeypatch.setattr("app.agents.nodes._ask_llm", fake)
        return fake

    return install
