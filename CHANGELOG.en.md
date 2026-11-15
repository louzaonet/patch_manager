# Changelog

## 1.0.2 (2026-11-15)

### Security

- Native install: the `X-Forwarded-For` fix in 1.0.1 only covered Docker. When connections reach nginx from 127.0.0.1 (the LXD proxy device described in the wiki), uvicorn trusted nginx and took the address the client had put in the header, so the failed-login throttle could be avoided the same way. nginx now sends only the address it sees. Behind the proxy device all clients share one address, and so one throttle; the nginx site ships commented settings to keep real addresses with `proxy_protocol`.
- Patch plans: a target that failed validation (a typo in a host name, a group that does not exist) was dropped and the plan was built for every host. No plan is created now. Read-only actions still fall back to all hosts with a warning.
- Patch plans: no plan either when the service sees no hosts in scope (empty or unreadable inventory). That plan had no limit and, once approved, Semaphore would have run it on every host.
- Limit validation: wildcards were checked with a hand-built regular expression that backtracks exponentially. A target with many `*` froze the service (measured: 0.2 s with 10 wildcards, 6 s with 18). It uses `fnmatch` now, as Ansible does. It required an authenticated user.
- Slack and Teams webhooks: a signature header with non-ASCII characters raised an exception and returned 500 instead of 401. It did not let anyone past the signature check.
- `create-container.sh`: Vault password files and private keys found in the working tree are no longer copied into the container (`install.sh` makes that copy readable by every user).

### Fixes

- Plans: the host list of a plan was computed by applying the limit left to right. Ansible takes the union of the plain patterns first, then the intersections (`&`), then the exclusions (`!`), so with limits such as `a,&b,c` the plan listed hosts Ansible would not touch. It now matches `ansible --list-hosts`.
- Rocky: `dnf needs-restarting -r` exits 1 when a reboot is needed, but dnf also exits 1 on any error, for instance when the plugin (`dnf-plugins-core`) is missing. That error was read as "reboot pending" and `apply_patches.yml` rebooted the host. The output message is checked as well now.
- `ansible.cfg`: with `gathering = smart` and a fact cache, a run within the next hour reused old facts. `reboot_if_needed.yml` missed Windows reboots pending since the last patch run, and reports could carry the previous OS version. Facts are now gathered on every run and not cached.
- `setup_macos_ssh.sh`: run with `sudo` and no arguments it set up root instead of the user who called sudo; sudo ignored the sudoers file of a user with a dot in the name; the file was installed before being validated; and the last step could abort the script (`head` under `pipefail`). The home directory is no longer resolved with `eval`.
- `setup_winrm.ps1`: requires an elevated console and stops at the first error. Before, a failure creating the certificate or the listener still ended with a success message.
- An inventory that is valid YAML with the wrong shape (hosts as a list, `vars` as a string) caused a 500 on every request. It is now logged and treated as an empty inventory. Same for a KEV catalogue in an unexpected format and a Slack body that is not valid UTF-8.
- Slack: the command text is capped at 4,000 characters, as in Teams.
- `.gitignore` and `.ansible-lint` were missing from the repository; they are back.

### Tested

- 86 automated tests, ruff, shellcheck, ansible-lint (production profile) and `ansible-playbook --syntax-check`.
- The native nginx site, tested with nginx 1.24 in front of the service: with the old file, 12 failed logins with a changing `X-Forwarded-For` never hit the throttle; with the new one the eleventh gets a 429.
- The Rocky check play, run against a fake `dnf` with sample output (reboot pending, no reboot, plugin missing, error).
- Not tested: real Rocky, macOS and Windows hosts; the macOS and PowerShell scripts were not run; the LXD scripts and the Docker images; `proxy_protocol` with a real LXD device (only the nginx syntax was checked).

## 1.0.1 (2026-11-10)

### Security

- Teams webhook: the regular expressions that strip mentions and HTML tags took quadratic time on input such as `<<<<...` or `<at><at>...` (about 5 s for 80,000 characters) and blocked the service meanwhile. They are now linear, and the raw HTML is capped at 20,000 characters before processing. Exploiting it required a valid Teams HMAC. Closes CodeQL alerts `py/polynomial-redos` #1 and #2.
- Docker: nginx forwarded the client's own `X-Forwarded-For` header to the AI service, and uvicorn, started with `--forwarded-allow-ips "*"`, used the first address in it. Changing the header on every attempt got around the failed-login throttle. nginx now sends only the real client address. The native install was not affected.

### Fixes

- `install.sh`: on a first install, the `umask 077` used to save the Semaphore password applied to the rest of the script, the AI service venv ended up 0700 root and the `patchai` user could not start it. Running the script again fixed it. The `umask` now runs in a subshell.
- Teams: message text reached the agent with HTML entities still encoded (`&nbsp;`, `&amp;`), which could stop host names and the "plans can't be approved from Teams" check from matching. Entities are now decoded and whitespace is normalised.

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
