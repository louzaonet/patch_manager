# Patch Manager: Wiki

Version 1.0 (November 2026). Release notes: [CHANGELOG.en.md](CHANGELOG.en.md).

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Requirements](#3-requirements)
4. [Installing the Server](#4-installing-the-server)
5. [Configuring Semaphore UI](#5-configuring-semaphore-ui)
6. [Connecting Ubuntu Hosts](#6-connecting-ubuntu-hosts)
7. [Connecting Rocky Linux Hosts](#7-connecting-rocky-linux-hosts)
8. [Connecting macOS Hosts](#8-connecting-macos-hosts)
9. [Connecting Windows 10/11 Hosts](#9-connecting-windows-1011-hosts)
10. [Email Notifications](#10-email-notifications)
11. [Running Playbooks from the CLI](#11-running-playbooks-from-the-cli)
12. [Running Playbooks from Semaphore](#12-running-playbooks-from-semaphore)
13. [Scheduling](#13-scheduling)
14. [LLM Configuration and Model Routing](#14-llm-configuration-and-model-routing)
15. [Using the AI Dashboard](#15-using-the-ai-dashboard)
16. [Slack Integration](#16-slack-integration)
17. [Microsoft Teams Integration](#17-microsoft-teams-integration)
18. [How the AI Agent Works](#18-how-the-ai-agent-works)
19. [Risk Analysis and CVE Data](#19-risk-analysis-and-cve-data)
20. [AI API Reference](#20-ai-api-reference)
21. [Custom Recipes](#21-custom-recipes)
22. [Managing the Inventory](#22-managing-the-inventory)
23. [Maintenance Windows](#23-maintenance-windows)
24. [Security Notes](#24-security-notes)
25. [Troubleshooting](#25-troubleshooting)
26. [Development and Tests](#26-development-and-tests)

---

## 1. Overview

Patch Manager detects, installs and reports OS updates on a mixed fleet of Ubuntu, Rocky Linux, macOS and Windows 10/11 machines. Two layers:

- **Automation**: Ansible playbooks do the deterministic work (detect updates, install, reboot, write reports, send email). Semaphore UI runs them from a browser, on a schedule or through its API.
- **AI**: a LangGraph agent behind a small FastAPI dashboard. It reads the per-host update reports, enriches the CVEs those hosts report with CISA KEV and NVD data, scores risk, writes briefings and answers questions. When someone asks to patch, it builds a **plan that a human must approve**; only then does it call Semaphore.

The LLM never decides to run anything on its own, and every node has a non-LLM fallback, so the dashboard keeps working (with plainer output) when the model is down.

---

## 2. Architecture

```
  Browser / Slack / Teams
          │
          ▼
  ┌───────────────────────── nginx (TLS :443) ─────────────────────────┐
  │   /      → Semaphore UI (:3000)        /ai/ → Patch Manager AI      │
  └────────────────────────────────────────────────────────────────────┘
          │                                        │  HTTP Basic / token
          │                                        ▼
          │                     LangGraph agent ── LLM (OpenRouter, llama-swap,
          │                     │                       Ollama, ...)
          │                     │ reads            ── CISA KEV, NIST NVD
          │                     ▼
          │      /var/lib/patch-manager/reports/hosts/*.json
          │                     ▲ writes
          ▼                     │
   Ansible (via Semaphore) ─────┘   ◄── approved plan: POST /api/project/{id}/tasks
          │ SSH / WinRM
   ┌──────┴───────┬─────────────┬──────────────┐
   Ubuntu       Rocky         macOS         Windows
```

Data flow for a typical week:

1. Semaphore runs **Check Updates** every night. Each host's result lands in `reports/hosts/<host>.json`.
2. You open the dashboard and click **Analyze risk**. The agent merges inventory + reports, checks the reported CVEs against KEV/NVD, scores and briefs.
3. You click **Plan patches** (or type "patch prod, security only"). The agent builds a plan (scope, options, hosts grouped by risk) and shows **Approve / Reject**.
4. On approval the service starts the **Apply Patches** template in Semaphore with the plan's limit and extra vars, and the dashboard polls the task until it finishes.

---

## 3. Requirements

### Management host

| Component | Notes |
|-----------|-------|
| Where | An LXD container (Ubuntu 24.04 recommended), a VM, or any Docker host. amd64 or arm64 (a Raspberry Pi 5 is enough) |
| RAM / disk | 2 GB RAM, 10 GB disk for Semaphore + AI service (the LLM runs elsewhere) |
| Network | SSH (22) to Linux/macOS hosts, WinRM (5986) to Windows, HTTPS to the LLM endpoint, `www.cisa.gov` and `services.nvd.nist.gov` |
| Software | Installed by the scripts: Python 3.11+, ansible-core 2.20+, Semaphore 2.19, nginx |

### Managed hosts

| OS | Requirements |
|----|-------------|
| Ubuntu 22.04 / 24.04 / 26.04 | SSH, Python 3, a user with passwordless sudo |
| Rocky Linux 9 / 10 | SSH, Python 3, passwordless sudo, `dnf-plugins-core` (for `dnf needs-restarting`) |
| Rocky Linux 8 | As above, plus Python 3.9+ (`dnf install python3.11`) and `ansible_python_interpreter: /usr/bin/python3.11`. ansible-core 2.20 no longer supports the default Python 3.6 |
| macOS 14 / 15 / 26 | Remote Login, Xcode Command Line Tools (Python 3), passwordless sudo. Apple silicon needs volume-owner credentials for OS updates (section 8) |
| Windows 11 / Windows 10 with ESU | WinRM over HTTPS (5986) and a local admin account, or OpenSSH |

---

## 4. Installing the Server

Pick one path.

### 4.1 LXD container, native install (recommended)

Semaphore and the AI service run as systemd units inside a normal (unprivileged) container. No Docker, no nesting.

On the LXD host, from the repository root:

```bash
./deploy/lxd/create-container.sh patchmgr ubuntu:24.04 native
```

The script launches the container, copies the repository to `/opt/patch-manager` (without local secrets) and runs `deploy/native/install.sh` inside it, which:

- installs ansible-core + pywinrm in `/opt/ansible-venv` and the collections from `requirements.yml`
- installs Semaphore from the official `.deb` (SQLite database, config in `/etc/semaphore/`)
- creates the Semaphore admin and saves its password in `/etc/semaphore/admin-password`
- installs the AI service in `/opt/patch-manager/.venv`, config in `/etc/patch-manager/ai.env` with a random dashboard password
- puts nginx with a self-signed certificate in front (`/` Semaphore, `/ai/` dashboard)

Re-running the script is safe: it keeps existing config files and secrets. To install without nginx (if you terminate TLS elsewhere, e.g. Cloudflare Tunnel): `install.sh --no-nginx`.

Then:

```bash
lxc exec patchmgr -- nano /etc/patch-manager/ai.env     # LLM settings, see section 14
lxc exec patchmgr -- systemctl restart patch-ai
lxc exec patchmgr -- journalctl -u patch-ai -f
```

Reaching the container from your LAN, for example host port 8443 to container 443:

```bash
lxc config device add patchmgr https proxy listen=tcp:0.0.0.0:8443 connect=tcp:127.0.0.1:443
```

The container must be able to reach the managed hosts and the LLM endpoint (openrouter.ai, or your own llama-swap/Ollama host).

> If `patch-ai` fails with `status=226/NAMESPACE`, the container doesn't allow the systemd sandboxing options. Comment out the `Protect*`/`Private*` lines in `/etc/systemd/system/patch-ai.service`, then `systemctl daemon-reload`.

### 4.2 LXD container with Docker

If you prefer the Docker stack inside LXD:

```bash
./deploy/lxd/create-container.sh patchmgr ubuntu:24.04 docker
```

This creates the container with `security.nesting=true` (plus the syscall interception Docker needs) and installs Docker. Continue with 4.3 inside the container. On ZFS-backed LXD storage, Docker's overlay2 driver needs ZFS 2.2 or later.

### 4.3 Docker on any host

```bash
cp config/env.example config/.env        && chmod 600 config/.env      # edit all CHANGE_ME values
cp config/ai.env.example config/ai.env   && chmod 600 config/ai.env    # LLM, dashboard password
cd docker
bash generate_certs.sh patch-manager.example.com
docker compose up -d
docker compose ps
```

Generate each Semaphore key with `head -c32 /dev/urandom | base64`. Don't reuse the example values.

| Service | URL |
|---------|-----|
| Semaphore UI | `https://<host>/` |
| AI dashboard | `https://<host>/ai/` |
| Health | `https://<host>/health` |

What the compose file does that matters:

- PostgreSQL 18 data lives in the `pgdata` volume mounted at `/var/lib/postgresql` (PostgreSQL 18 images changed the data path).
- Semaphore gets only the Ansible parts of the repository (`ansible.cfg`, `playbooks/`, `inventory/`, `collections/`), read-only. `config/` secrets are not mounted.
- `docker/semaphore/requirements.txt` adds pywinrm to Semaphore's Python at start-up.
- A one-shot `volume-init` service fixes ownership of the shared `reports` volume (Semaphore writes, the AI service reads).
- The AI container runs read-only, as an unprivileged user, with all capabilities dropped.

### TLS certificates

The self-signed certificate is for testing. Replace `server.crt`/`server.key` (Docker: `docker/nginx/certs/`, native: `/etc/ssl/patch-manager/`) with one from your ACME setup or internal CA and reload nginx. If the dashboard is only published through Cloudflare Tunnel + Access, you can keep nginx on plain HTTP inside the container and let the tunnel terminate TLS.

---

## 5. Configuring Semaphore UI

Log in as `admin` (Docker: password from `config/.env`; native: `/etc/semaphore/admin-password`).

1. **Project**: create one, e.g. "Patch Management". If you create more than one, set `SEMAPHORE_PROJECT_ID` in `ai.env`.
2. **Key Store**: an SSH private key for Linux/macOS, and a "Login with password" entry for Windows (or keep the password in Vault, see section 22).
3. **Repository**: URL `/opt/patch-manager` (a local path; branch empty).
4. **Inventory**: type **File**, path `inventory/hosts.yml`. It has to be the file in the repository, because the group variables live next to it in `inventory/group_vars/`. A pasted "static" inventory would run without them.
5. **Templates** (names must match `SEMAPHORE_TEMPLATE_*` in `ai.env`):

   | Template | Playbook | Notes |
   |----------|----------|-------|
   | Check Updates | `playbooks/check_updates.yml` | read-only on hosts, schedule it nightly |
   | Apply Patches | `playbooks/apply_patches.yml` | enable the option that lets a task **override the limit** (`allow_override_limit` in the API). Without it Semaphore accepts the limit and then runs on every host, so the AI service refuses limited runs on such a template |
   | Reboot If Needed | `playbooks/reboot_if_needed.yml` | optional |

6. **API token**: user menu → API Tokens → create. Put it in `SEMAPHORE_API_TOKEN` and restart the AI service.

Semaphore installs the collections from `collections/requirements.yml` when a task starts. The native install also pre-installs them system-wide.

---

## 6. Connecting Ubuntu Hosts

```bash
sudo systemctl enable --now ssh
sudo adduser --disabled-password --gecos "Ansible" ansible
echo "ansible ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/ansible
sudo chmod 0440 /etc/sudoers.d/ansible
# from the management host:
ssh-copy-id -i ~/.ssh/ansible_key.pub ansible@<host>
```

Add the host under `ubuntu_servers` in `inventory/hosts.yml` and test with `ansible <host> -m ping`.

Security-only mode installs exactly the packages that `apt list --upgradable` shows coming from the `-security` pocket. If there are none, nothing is installed.

---

## 7. Connecting Rocky Linux Hosts

```bash
sudo systemctl enable --now sshd
sudo useradd -m ansible
echo "ansible ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/ansible
sudo chmod 0440 /etc/sudoers.d/ansible
sudo dnf install -y dnf-plugins-core     # dnf needs-restarting
```

Rocky publishes `updateinfo` metadata, so security-only mode (`dnf --security`) works and the check playbook can collect the CVE IDs behind each pending advisory. Those CVE IDs are what the AI service enriches with KEV/NVD data.

---

## 8. Connecting macOS Hosts

Run the helper on each Mac:

```bash
sudo ./scripts/setup_macos_ssh.sh admin "ssh-ed25519 AAAA... ansible@patch-manager"
```

It enables Remote Login (on recent macOS this may need Full Disk Access for Terminal; otherwise enable it in System Settings → General → Sharing), checks for the Command Line Tools, configures passwordless sudo and installs the key.

**Apple silicon**: `softwareupdate` only installs macOS updates when it gets the credentials of a volume owner. Set them in the inventory or group vars:

```yaml
# inventory/group_vars/macos_servers.yml
patch_macos_update_user: admin
# vault_macos_update_password defined with ansible-vault encrypt_string
```

The password goes to `softwareupdate --stdinpass` on stdin and the task runs with `no_log`. For more than a handful of Macs, an MDM software update policy is the better tool.

Macs are patched one at a time. When an update needs a restart, `softwareupdate --restart` can take the Mac down before the command returns; the playbook tolerates the dropped connection and waits for the Mac to come back (up to `patch_reboot_timeout`). This path has not been exercised on real hardware yet, so do a first run on one Mac with `--limit`. Security-only mode maps to `softwareupdate --recommended`, the closest thing Apple offers.

---

## 9. Connecting Windows 10/11 Hosts

Windows 10 left mainstream support in October 2025; it only gets security updates when enrolled in ESU.

1. Create a local admin (elevated PowerShell):

   ```powershell
   $Password = Read-Host -AsSecureString "Password"
   New-LocalUser -Name "ansible_admin" -Password $Password -FullName "Ansible Admin"
   Add-LocalGroupMember -Group "Administrators" -Member "ansible_admin"
   ```

2. Enable WinRM over HTTPS: `powershell -ExecutionPolicy Bypass -File scripts\setup_winrm.ps1`. It creates a self-signed listener certificate, enables NTLM/Negotiate, keeps Basic auth **off**, and opens 5986 for Domain/Private profiles.
3. Store the password with Vault: `ansible-vault encrypt_string 'secret' --name vault_windows_password`.
4. Test: `ansible win-desktop-01 -m ansible.windows.win_ping`.

In a domain, Kerberos (`pywinrm[kerberos]`) is preferable to NTLM. Ansible also supports managing Windows over OpenSSH, which avoids WinRM altogether.

---

## 10. Email Notifications

The playbooks send an HTML summary after each check and each patch run, if enabled. SMTP settings come from environment variables on the controller:

| Variable | Example |
|----------|---------|
| `EMAIL_ENABLED` | `true` |
| `SMTP_HOST` / `SMTP_PORT` | `smtp.example.com` / `587` |
| `SMTP_SECURE` | `starttls` (or `always`, `never`, `try`) |
| `SMTP_USER` / `SMTP_PASSWORD` | |

Docker: set them in `config/.env` (Semaphore forwards them to tasks). Native: `/etc/semaphore/semaphore.env`, then `systemctl restart semaphore`. CLI: export them in your shell.

Recipients and sender are in `inventory/group_vars/all.yml` (`email_to`, `email_from`).

---

## 11. Running Playbooks from the CLI

From the repository root (`ansible.cfg` points at `inventory/hosts.yml`):

```bash
ansible-playbook playbooks/check_updates.yml                        # detect, write reports
ansible-playbook playbooks/apply_patches.yml                        # install everything
ansible-playbook playbooks/apply_patches.yml --tags security_only   # security only
ansible-playbook playbooks/apply_patches.yml -e patch_security_only=true   # same thing
ansible-playbook playbooks/apply_patches.yml --limit ubuntu_servers
ansible-playbook playbooks/apply_patches.yml -e patch_dry_run=true
ansible-playbook playbooks/apply_patches.yml -e patch_reboot_allowed=false
ansible-playbook playbooks/apply_patches.yml -e patch_serial=25%    # batches per OS group
ansible-playbook playbooks/reboot_if_needed.yml
```

Reports are written on the machine running Ansible, under `PATCH_REPORT_DIR` (default `/var/lib/patch-manager/reports`). Set it if you run the CLI elsewhere: `PATCH_REPORT_DIR=/tmp/reports ansible-playbook ...`.

The report/email steps run inside a `hosts: all` play delegated to localhost, so they still run when you use `--limit`.

---

## 12. Running Playbooks from Semaphore

Templates → Run. Use the run dialog to override the limit or add extra vars (`patch_dry_run=true`). Semaphore shows the live log; reports and email follow at the end of the run.

**Failed hosts.** If a task fails on a host during `apply_patches.yml`, the failure is recorded: the host gets a `FAILED` entry (with the failing task and message) in `reports/patch-runs/<host>.json` and in the email, and the run still ends as failed for that host, so Semaphore shows the task in red. Unreachable hosts are the exception: they only appear in the Ansible recap.

---

## 13. Scheduling

Suggested Semaphore schedules:

| Template | Cron | Why |
|----------|------|-----|
| Check Updates | `15 6 * * *` | fresh data for the dashboard every morning |
| Apply Patches (security only, `patch_security_only=true`) | `0 3 * * 6` | weekly, inside the maintenance window |
| Apply Patches (full) | `0 3 1-7 * 6` | first Saturday of the month |

Plans approved from the dashboard run immediately; the maintenance window check (section 23) still applies if enabled.

---

## 14. LLM Configuration and Model Routing

Three nodes call an LLM: `classify_intent` (short JSON answer), `generate_briefing` (summarise a few KB of JSON into markdown) and `handle_question` (free-form Q&A). Quick-action buttons skip `classify_intent` entirely.

### Providers

| Provider | Spec example | Needs |
|----------|--------------|-------|
| `openai_compat` (aliases `local`, `llamaswap`) | `openai_compat:gpt-oss-20b` | `OPENAI_COMPAT_BASE_URL` (llama-swap, llama.cpp server, vLLM, LM Studio) |
| `openrouter` | `openrouter:anthropic/claude-haiku-5.5` | `OPENROUTER_API_KEY` |
| `ollama` | `ollama:qwen3.5:9b` | `OLLAMA_BASE_URL` |
| `openai` | `openai:gpt-5-mini` | `OPENAI_API_KEY` |
| `anthropic` | `anthropic:claude-haiku-5-5` | `ANTHROPIC_API_KEY` |

`LLM_DEFAULT` is required (the example file ships with OpenRouter + Claude Haiku 5.5). `LLM_NODE_CLASSIFY_INTENT`, `LLM_NODE_GENERATE_BRIEFING` and `LLM_NODE_HANDLE_QUESTION` override it per node. If an override can't be created (missing key, typo in the provider), the node falls back to `LLM_DEFAULT` and logs it.

### llama-swap on another machine

```ini
LLM_DEFAULT=openai_compat:gpt-oss-20b
OPENAI_COMPAT_BASE_URL=http://llm-host:8080/v1
OPENAI_COMPAT_EXTRA_BODY={"chat_template_kwargs": {"reasoning_effort": "low"}}
LLM_TIMEOUT=120
```

- The model name is the key in llama-swap's `config.yaml`; list them with `curl http://llm-host:8080/v1/models`.
- Use **one** model for all nodes. With several, llama-swap unloads and loads models between nodes of the same request, which costs far more time than it saves.
- `OPENAI_COMPAT_EXTRA_BODY` is merged into every request. For gpt-oss, `reasoning_effort: low` keeps answers fast. For Qwen hybrid-thinking models use `{"chat_template_kwargs": {"enable_thinking": false}}`.
- llama-swap listens on all interfaces by default and has no auth unless you configure `apiKeys`. Restrict it to the management container's IP with a firewall, or set an API key and put it in `OPENAI_COMPAT_API_KEY`.
- The first request after a model swap is slow (model load). `LLM_TIMEOUT` covers it.

### OpenRouter

```ini
LLM_DEFAULT=openrouter:anthropic/claude-haiku-5.5
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_EXTRA_BODY={"provider": {"data_collection": "deny"}, "reasoning": {"effort": "low"}}
```

`provider.data_collection: deny` keeps requests away from providers that store or train on prompts. `reasoning.effort: low` keeps reasoning models quick. Prices move often; check the model page on openrouter.ai.

### Hybrid

```ini
LLM_DEFAULT=openai_compat:gpt-oss-20b
LLM_NODE_GENERATE_BRIEFING=openrouter:anthropic/claude-haiku-5.5
```

Intent and Q&A stay on your hardware; only briefings (which contain host names, OS versions, package names and CVE IDs, never IPs or credentials) go to the cloud.

### Temperature

`LLM_TEMPERATURE` is unset by default, so the provider's default applies. Several reasoning models refuse a custom temperature; only set it for models you know accept it.

### When the model is down

- `classify_intent` falls back to keyword matching.
- `generate_briefing` falls back to a deterministic summary (counts, KEV hosts, top risks, pending plan).
- `handle_question` returns a short "model unavailable" message.

Check the routing with `GET /api/info` (authenticated).

---

## 15. Using the AI Dashboard

`https://<host>/ai/`, HTTP Basic auth with `APP_AUTH_USER` / `APP_AUTH_PASSWORD`.

- **Pending updates**: summary of the latest reports (no host contact).
- **Analyze risk**: KEV/NVD enrichment + scoring + briefing, with a card per host.
- **Plan patches**: builds a plan for the selected target and options, lists the hosts grouped by risk and shows **Approve / Reject**. An approved plan is one Semaphore run over the whole scope with the same options for every host; the groups only show what is urgent. To patch the critical hosts first, plan them separately (pick the host or group as target). Approving asks for confirmation, starts the Semaphore task and polls it until it finishes.
- **Refresh host data**: starts the Check Updates template in Semaphore for the selected target.
- Chat: free text. Requests like "patch the web servers, security only, no reboot" produce a plan, never a direct run. The target selector and option checkboxes override what the model extracts.

Plans expire after `PLAN_TTL_MINUTES` (default 30) and are kept in memory: restarting the service drops pending plans.

---

## 16. Slack Integration

1. Create a Slack app with a slash command `/patch` pointing to `https://<host>/ai/api/integrations/slack`. A bot token (`chat:write`) is only needed as a fallback.
2. Configure:

   ```ini
   SLACK_ENABLED=true
   SLACK_SIGNING_SECRET=...
   SLACK_APPROVER_IDS=U0123ABCD,U0456EFGH
   # SLACK_BOT_TOKEN=xoxb-...   (optional)
   ```

Usage:

```
/patch analyze risk on production
/patch plan security patches for ubuntu_servers
/patch approve 3f9c1a2b7d4e
/patch reject 3f9c1a2b7d4e
```

Every request is signature-checked (5-minute window). The endpoint answers within Slack's 3-second limit and posts the result later through the command's `response_url`. Only users in `SLACK_APPROVER_IDS` can approve or reject.

---

## 17. Microsoft Teams Integration

Office 365 connector webhooks (`outlook.office.com/webhook/...`) stopped working in May 2026.

**Notifications**: in the channel, Workflows → "Post to a channel when a webhook request is received". Copy the URL into `TEAMS_WEBHOOK_URL`. The service posts Adaptive Cards in the format that template expects.

**@mentions into the app (optional)**: create an Outgoing Webhook pointing to `https://<host>/ai/api/integrations/teams` and put its security token in `TEAMS_OUTGOING_SECRET`. Requests are HMAC-verified. Teams waits only about 5 seconds, so the endpoint acknowledges immediately and the briefing arrives through the Workflows webhook.

```ini
TEAMS_ENABLED=true
TEAMS_WEBHOOK_URL=https://prod-00.westeurope.logic.azure.com/workflows/...
TEAMS_OUTGOING_SECRET=base64-token
```

Plans can't be approved from Teams; use the dashboard or Slack.

---

## 18. How the AI Agent Works

```
START → load_inventory → classify_intent ─┬─ analyze_risk / generate_report → enrich_cves → score_risks → generate_briefing → END
                                          ├─ apply_patches → enrich_cves → score_risks → build_patch_plan → generate_briefing → END
                                          ├─ check_updates → score_risks → generate_briefing → END
                                          ├─ status → fetch_task_status → generate_briefing → END
                                          └─ ask_question → handle_question → END
```

| Node | What it does | LLM |
|------|--------------|-----|
| `load_inventory` | parses `inventory/hosts.yml` (nested groups, `!vault` values) and merges the per-host reports | no |
| `classify_intent` | action + target + options; target validated against the inventory | yes, keyword fallback |
| `enrich_cves` | KEV + NVD for the CVE IDs hosts reported; recent critical CVEs per OS family as context | no |
| `score_risks` | 0-100 score per host (section 19) | no |
| `build_patch_plan` | scope + options + hosts grouped by risk, registered as a pending plan | no |
| `fetch_task_status` | last Semaphore tasks | no |
| `generate_briefing` | markdown briefing | yes, template fallback |
| `handle_question` | Q&A with inventory context | yes |

Execution is not a node. `POST /api/plans/{id}/approve` (or `/patch approve` in Slack) calls Semaphore with the parameters stored in the plan.

Targets that come from the model are validated as Ansible `--limit` expressions against the inventory (known hosts and groups, `!`/`&` prefixes, `*` wildcards). Anything else is dropped with a warning.

---

## 19. Risk Analysis and CVE Data

### Where the data comes from

| Source | What it gives |
|--------|---------------|
| `reports/hosts/<host>.json` (Check Updates) | pending updates, security updates, CVE IDs (Rocky advisories), reboot pending, report age |
| `inventory/hosts.yml` | `patch_criticality: high/medium/low` per host |
| CISA KEV | whether a reported CVE is known to be exploited in the wild |
| NIST NVD 2.0 | CVSS score for each reported CVE ID; recent critical CVEs per OS family as context |

Keyword search hits from NVD are **not** attached to hosts: a CVE that mentions "Windows" says nothing about whether a given machine is missing its fix. Only CVE IDs a host reported through its own package metadata count towards its score.

NVD allows 5 requests per 30 seconds without a key and 50 with one ([free key](https://nvd.nist.gov/developers/request-an-api-key)). Lookups are cached (24 h), throttled, capped by `NVD_LOOKUP_LIMIT` and by `NVD_LOOKUP_BUDGET_SECONDS`, KEV hits first.

### Score

| Factor | Weight | Input |
|--------|--------|-------|
| Pending security updates | 30% | 20 points each, max 100 |
| Known exploited (KEV) | 25% | 100 if any reported CVE is in KEV |
| Highest CVSS | 15% | max CVSS × 10 |
| Criticality | 15% | high 100, medium 50, low 15 |
| Update backlog | 10% | 4 points per pending update, max 100 |
| Reboot pending | 5% | 100 if a reboot is pending |

A KEV hit puts the host at 80 (CRITICAL) at least. Hosts with no report or a report older than `REPORT_MAX_AGE_HOURS` are flagged in their risk factors.

| Score | Level |
|-------|-------|
| 80-100 | CRITICAL |
| 60-79 | HIGH |
| 40-59 | MEDIUM |
| 0-39 | LOW |

A plan lists its hosts under these four levels.

---

## 20. AI API Reference

All endpoints except `/api/health` and the webhooks need HTTP Basic or `Authorization: Bearer <APP_API_TOKEN>`. POST requests authenticated with Basic must send `X-Requested-With: patch-ai`.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/chat` | `{"message", "target_hosts", "options", "history"}` |
| POST | `/api/action/check-updates` | summary of latest reports |
| POST | `/api/action/analyze-risk` | risk analysis |
| POST | `/api/action/plan-patches` | build a plan (nothing runs until it is approved) |
| POST | `/api/action/run-check` | start the Check Updates template |
| GET | `/api/plans`, `/api/plans/{id}` | list / show plans |
| POST | `/api/plans/{id}/approve` | run the plan through Semaphore |
| POST | `/api/plans/{id}/reject` | reject |
| GET | `/api/tasks/{task_id}` | Semaphore task status |
| GET | `/api/inventory` | groups and hosts |
| GET | `/api/info` | model routing, integrations |
| GET | `/api/health` | liveness, no details |
| POST | `/api/integrations/slack`, `/api/integrations/teams` | webhooks (signature/HMAC verified) |

Action endpoints take `{"target_hosts": "ubuntu_servers", "security_only": true, "dry_run": false, "no_reboot": false}`.

```bash
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target_hosts":"production","security_only":true}' \
  https://patch-manager.example.com/ai/api/action/plan-patches
```

Swagger UI at `/docs` when `APP_ENABLE_DOCS=true` (authenticated).

---

## 21. Custom Recipes

Add a playbook under `playbooks/` and a template in Semaphore:

```yaml
---
- name: Update Docker Engine
  hosts: ubuntu_servers
  become: true
  tasks:
    - name: Upgrade docker-ce
      ansible.builtin.apt:
        name: docker-ce
        state: latest
        only_upgrade: true
```

Per-group behaviour lives in `inventory/group_vars/`. Exclude kernels on Rocky:

```yaml
# inventory/group_vars/rocky_servers.yml
patch_excluded_packages:
  - kernel*
```

On Ubuntu, `patch_excluded_packages` puts packages on dpkg hold (undo with `apt-mark unhold <pkg>`).

Use `ansible_facts['...']` in new playbooks; the old injected `ansible_*` fact variables are deprecated since ansible-core 2.20 and this repository disables them in `ansible.cfg`.

---

## 22. Managing the Inventory

- One file: `inventory/hosts.yml`. Group variables: `inventory/group_vars/` (Ansible loads them because they sit next to the inventory file).
- Every managed host goes in exactly one of `ubuntu_servers`, `rocky_servers`, `macos_servers`, `windows_servers` (directly or through child groups). Logical groups like `production` are for `--limit` and appear in the dashboard target list.
- `patch_criticality: high | medium | low` per host feeds the risk score.
- Secrets: `ansible-vault encrypt_string`. Inline `!vault` values are fine; the AI service ignores them.

For large or cloud fleets, use a dynamic inventory plugin in Semaphore. The AI service reads the YAML file, so keep at least the OS groups there, or point `INVENTORY_PATH` at an exported copy (`ansible-inventory --list -y > inventory/export.yml`).

---

## 23. Maintenance Windows

```yaml
# inventory/group_vars/all.yml
maintenance_window_enabled: true
maintenance_window_start: "22:00"
maintenance_window_end: "04:00"
maintenance_window_days: [5, 6]   # 0=Monday ... 6=Sunday
```

- Evaluated with the clock of the machine running Ansible (the Semaphore container/host), not the managed hosts.
- Windows that cross midnight work: 22:00-04:00 on day 5 means Saturday 22:00 to Sunday 04:00.
- The check needs no connection to the hosts and runs before any change. Hosts outside the window are dropped from the run.
- Override: `-e maintenance_window_enabled=false`.

---

## 24. Security Notes

- **Dashboard/API auth**: HTTP Basic or bearer token, compared in constant time. Ten failed logins from one address within five minutes get that address a 429 for the rest of the window (in-process brake; add network restrictions in nginx if the dashboard is reachable from untrusted networks). The service refuses to start without `APP_AUTH_PASSWORD` (or with a placeholder/short one). `APP_AUTH_DISABLED=true` exists for local development only.
- **CSRF**: browser POSTs must carry `X-Requested-With: patch-ai`, which a cross-site form can't add.
- **Human approval**: the agent can only create plans. Execution uses the stored plan parameters, records who approved it (structlog `audit` logger) and can't be triggered by the LLM.
- **Input to Ansible**: the limit goes to Semaphore's `limit` field, extra vars to `environment` as JSON, and the limit is validated against the inventory. Nothing from the user or the model is concatenated into a command line.
- **Webhooks**: Slack signatures (with replay window) and Teams HMAC are mandatory when the integration is enabled; disabled integrations return 404.
- **Browser hardening**: strict CSP (`script-src 'self'`, no inline handlers), `X-Frame-Options: DENY`, `nosniff`, `no-store` on API responses. The markdown renderer escapes HTML before formatting.
- **SSH host keys**: `host_key_checking = True` with `StrictHostKeyChecking=accept-new`: first contact is trusted and remembered, a changed key fails the run. Pre-seed `known_hosts` if you want stricter control.
- **Secrets on disk**: `ai.env`, `.env`, `/etc/semaphore/config.json` are 0600/0640. The AI container doesn't get `config/` at all.
- **LLM privacy**: prompts contain your message, host names, groups, OS versions, update counts and CVE IDs. No IPs, package lists, credentials or keys. Use a local model if host names are sensitive, or use OpenRouter with `data_collection: deny`.
- **Semaphore**: put it behind the same TLS proxy, enable TOTP or OIDC/LDAP, and keep the `SEMAPHORE_ACCESS_KEY_ENCRYPTION` key backed up (it encrypts the key store).

---

## 25. Troubleshooting

**`patch-ai` won't start: "Invalid configuration"**
The log lists the problem: `LLM_DEFAULT` empty, weak `APP_AUTH_PASSWORD`, Slack enabled without signing secret.

**Dashboard says "No recent update reports"**
Run the Check Updates template. Check that reports appear in `/var/lib/patch-manager/reports/hosts/` and that the AI service can read them (`REPORTS_PATH`). In Docker both containers share the `reports` volume; `volume-init` gives it to uid 1001. If the task log shows "Permission denied" writing the report, compare with `docker compose exec semaphore id -u` and adjust the `chown` in `volume-init`.

**Approve fails with "SEMAPHORE_API_TOKEN is not set" / "Template ... not found"**
Set the token; make sure the template names match `SEMAPHORE_TEMPLATE_APPLY` / `SEMAPHORE_TEMPLATE_CHECK`. With several projects set `SEMAPHORE_PROJECT_ID`.

**Approve fails with "does not allow overriding the limit"**
Enable the limit override option in the Apply Patches template (section 5). The service checks this because Semaphore would otherwise run the plan on all hosts.

**Variables like `patch_windows_categories` are undefined**
Semaphore is using a static inventory. Use a File inventory pointing at `inventory/hosts.yml` so `inventory/group_vars/` is loaded.

**LLM errors / slow answers**
`journalctl -u patch-ai` (native) or `docker logs patch-manager-ai`. Check `curl http://llm-host:8080/v1/models` from the container. First request after a model swap is slow; raise `LLM_TIMEOUT`. The dashboard keeps working with fallback output meanwhile.

**Analyses take long**
NVD throttling without an API key (6 s per lookup). Add `NVD_API_KEY` or lower `NVD_LOOKUP_LIMIT`. Results are cached for 24 h.

**Host unreachable / host key changed**
`ssh -i key ansible@host`. If the key really changed (reinstall), remove the old entry from the semaphore user's `~/.ssh/known_hosts`.

**Windows: "winrm or requests is not installed"**
Docker: `docker/semaphore/requirements.txt` must be mounted; native: `/opt/ansible-venv/bin/pip install pywinrm`.

**Rocky: reboot never detected**
Install `dnf-plugins-core` (provides `dnf needs-restarting`).

**macOS: OS updates listed but never installed**
Apple silicon without `patch_macos_update_user`/password (section 8).

**Email not sent**
`EMAIL_ENABLED=true`, SMTP variables visible to the Ansible process (Docker: `config/.env`; native: `/etc/semaphore/semaphore.env`), `community.general` installed.

**nginx 502**
Upstream not ready yet or crashed: `docker compose logs semaphore patch-ai`, or `systemctl status semaphore patch-ai`.

**Verbose Ansible output**
`ansible-playbook ... -vvv`, or enable "debug" in the Semaphore run dialog.

---

## 26. Development and Tests

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest                         # unit, graph and HTTP tests (fake LLM, mocked Semaphore/NVD/KEV)
ruff check app tests
ansible-lint playbooks inventory
ansible-playbook --syntax-check playbooks/*.yml
```

Run the service locally:

```bash
cp config/ai.env.example config/ai.env   # set APP_AUTH_PASSWORD, LLM_*
uvicorn app.main:app --reload --port 8501
```
