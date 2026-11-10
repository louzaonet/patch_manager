# Changelog

## 1.0.0 (2026-11-09)

First public release.

### Automation (Ansible + Semaphore UI)

- Playbooks for Ubuntu, Rocky Linux, macOS and Windows 10/11: `check_updates.yml` (detect, no changes), `apply_patches.yml` (install, reboot where needed), `reboot_if_needed.yml`.
- Modes: full, security only (`--tags security_only` or `-e patch_security_only=true`), dry run, no reboot, batches per OS group (`-e patch_serial=25%`).
  - Ubuntu security mode installs exactly the packages offered from the `-security` pocket; an empty list installs nothing.
  - Rocky uses `updateinfo` advisories; macOS maps to `softwareupdate --recommended`; Windows uses its own category list.
- Per-host JSON reports on the controller: `reports/hosts/<host>.json` (pending and security updates, CVE IDs from Rocky advisories, reboot pending) and `reports/patch-runs/<host>.json` (result of the last run).
- A host that fails during patching is recorded as `FAILED` with the failing task and message, shows up in the report and the email, and still fails the run.
- Optional maintenance window, evaluated on the controller clock, including windows that cross midnight.
- HTML email summaries after checks and patch runs (opt-in).
- Reports and email also run when `--limit` is used.
- Group policy in `inventory/group_vars/`; `patch_criticality` per host.
- Requires ansible-core 2.20+, ansible.windows 3+, community.general 12+, ansible.posix 2+. Facts are read through `ansible_facts[...]`.

### AI service (FastAPI + LangGraph)

- Dashboard and API under `/ai/`: pending updates, risk analysis, patch plans, free-text chat, Semaphore task status.
- **Patching needs human approval.** The agent only builds plans. A plan is executed through the Semaphore API after someone approves it (dashboard, API token, or an allow-listed Slack user), with the parameters stored in the plan. Plans expire after 30 minutes.
- Risk score from reported data: pending security updates, CISA KEV membership and CVSS (NVD) of the CVEs each host reports, inventory criticality, backlog, pending reboot. Recent critical CVEs per OS family are shown as context only.
- NVD access is cached, throttled to the published rate limits, bounded by a time budget, and protected by a circuit breaker.
- LLM providers: OpenRouter, any OpenAI-compatible server (llama-swap, llama.cpp, vLLM), Ollama, OpenAI, Anthropic, selectable per node. The example configuration uses Claude Haiku 5.5 through OpenRouter.
- Works without the model: keyword intent matching and a template briefing take over when the LLM is unreachable.
- Slack slash command (`/patch ...`, `/patch approve <id>`) and Microsoft Teams (Workflows webhook for notifications, optional outgoing webhook for requests).

### Security

- HTTP Basic or bearer-token authentication on everything except the health check and the signed webhooks; the service refuses to start without a proper password. Failed logins are throttled per client address.
- CSRF header check for browser requests, strict Content-Security-Policy, no inline scripts.
- Slack signatures (with replay window) and Teams HMAC are mandatory when those integrations are enabled.
- Host limits from users or the model are validated against the inventory and sent to Semaphore as a separate field. The service refuses a limited run on a Semaphore template that does not allow overriding the limit, because Semaphore would run it on every host (checked against Semaphore 2.19.12).
- Prompts carry host names, OS versions, counts and CVE IDs; no IP addresses, package lists or credentials. Strings that originate on managed hosts are bounded before they reach a prompt.
- SSH host keys: trust on first use, changed keys are rejected. WinRM over HTTPS with Basic auth off.
- Containers: the AI service runs unprivileged, read-only, without capabilities, and never sees the Semaphore secrets.

### Deployment

- LXD: `deploy/lxd/create-container.sh` creates the container and runs `deploy/native/install.sh` (Semaphore with SQLite, AI service and nginx with TLS as systemd units). A Docker-inside-LXD mode is available.
- Docker Compose stack: nginx 1.30, Semaphore 2.19.12, PostgreSQL 18, AI service on Python 3.13.

### Tested

- 59 automated tests (fake LLM, mocked Semaphore, NVD and KEV), ruff, ansible-lint (production profile), shellcheck.
- End to end against a real Semaphore 2.19.12 and an Ubuntu 24.04 host: check, analysis, plan, approval, Semaphore task, reports, including a real security-only install and a forced failure.
- Not yet exercised on real hardware: Rocky Linux, macOS and Windows hosts (their output parsing is tested with sample output), the LXD scripts and the Docker images.
