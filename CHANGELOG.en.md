# Changelog

## 1.3.0 (2026-11-26)

### New

- Ubuntu: Check Updates reports carry the CVEs that the pending updates fix. The controller checks each host's installed package list and running kernel against Canonical's USN OVAL data for its release (`playbooks/files/ubuntu_oval_cves.py`, standard library only). Nothing runs on or is installed on the hosts, and only the package list from the same run is used. Each release's file is downloaded only when it changed (`If-Modified-Since`) and kept compiled in `reports/oval-cache`. If the download fails, the cached copy is used and the report says so (`cve_data_warning`); with no copy, the report gets `cve_error` and Check Updates still finishes. New optional variables: `patch_ubuntu_cves`, `patch_oval_url_base` and `patch_oval_cache_dir`. The controller needs HTTPS access to `security-metadata.canonical.com`.
- Kernel: what counts is the running kernel, not the installed one, so a fixed kernel waiting for a reboot still adds its CVEs. It is only checked on hosts that have that kernel's `linux-image` installed: an LXD container sees its host's kernel in `uname`, and those CVEs belong to the LXD host. If the release data doesn't know the running kernel (an older series left installed), the report flags it instead of calling it clean.
- Ubuntu Pro: CVEs fixed only with Ubuntu Pro (`esm` versions) are kept apart in `cves_pro_only`. They don't raise the score unless one is in KEV, and then they count like any KEV hit.
- CVEs with no fix yet: with `patch_ubuntu_unfixed_cves` (on by default) the CVE OVAL, 5 to 14 MB per release, is read too, and the CVEs of installed packages that have no fixed version yet are listed. The kernel is left out: its unfixed CVEs run to hundreds per flavour (153 critical and high in the 26.04 `linux-raspi` kernel in testing) and would show up in every report. The report keeps the count per priority, the critical and high ones with their package, and every id for the KEV check. They are not part of the risk score, since patching doesn't remove them. The analysis gives them their own section, KEV ones first, and the email and dashboard show them in each host's notes.
- Severity: when the NVD has no score for an Ubuntu CVE (because of `NVD_LOOKUP_LIMIT`, or none published yet), the lowest score of the CVSS band matching Canonical's priority is used: critical 9.0, high 7.0, medium 4.0. The factor says so ("High-priority Ubuntu CVE pending"). NVD lookups go to KEV hits first, then by Canonical priority.
- `security_without_notice`: pending security updates that no notice explains, either because they came out after Canonical generated the OVAL file or because they fix no CVE (tzdata, `-dev` packages). The model is told not to treat them as a data error.
- Email and dashboard: number of pending CVEs and Pro-only CVEs per host, KEV with no fix, and the count of critical and high CVEs with no fix. The subject also flags KEV in Pro-only or unfixed CVEs.

### Changes

- The briefing prompt no longer says Ubuntu has no CVEs. It explains where they come from, what `score_source: "ubuntu"` means, and that an empty list is still normal for macOS and Windows. Unfixed CVEs go without package names: prompts still carry no package lists.
- Ubuntu reports also carry `os_codename` and `kernel`.

### Tests

- 47 new tests (258 in total): version comparison against results from `dpkg --compare-versions`, a test OVAL file with packages, kernel, Pro and livepatch entries, containers, a package list from another run, download, cache, 304, an index that must be rebuilt, the size limit and network failure against a local server, report reading, scoring, prompt and email.
- With the real jammy, noble and resolute OVAL files of 26 November and the package lists of four hosts: 3,351 version comparisons identical to `dpkg`'s. On an x86 machine, compiling the USN OVAL takes 0.7 to 2.1 s with under 60 MB of memory; the resolute CVE OVAL, 10.7 s and 59 MB, since it is read twice to keep the kernel entries out of memory. With the cache, the whole step takes under half a second.
- `check_updates.yml` against a local Ubuntu 24.04 with the noble OVAL served locally: first run, cached run (304), offline with and without a cached copy, the option turned off and a non-HTTPS URL. ansible-lint (production profile) and `--syntax-check`.

## 1.2.1 (2026-11-24)

### Fixes

- Capabilities: the AI summary gets the requested target and the hosts it covers ("Requested target: lxd_hosts... Hosts it matched: Archie, Logan, Nina, Ran"). It used to see only the reports and could answer that it didn't know which hosts were the LXD ones, even when that was exactly what had been queried.
- Capabilities: the model no longer works out totals itself. It gives a total only when the report has one (a field such as `count`, `total`, `lines` or `updates`); otherwise it lists the items without counting them. In testing it said "50 packages" about a table of 46.

### Tests

- One new test and extra assertions in another (211 in total) on the target and the counting rule in the summary prompt.

## 1.2.0 (2026-11-24)

### New

- Capabilities: `run.on_request: true` (only for `read_only` ones) makes every request run it, questions included. It is for on-demand queries, where the last report may be old or from another command; without it, since 1.1.1 a question is answered from the latest reports.
- Capabilities: `required: true` on a parameter. When the value is missing the request is refused before calling Semaphore, instead of starting a playbook that will fail its own validation. It can't be combined with `default`.
- The AI answers in the language of the question in free answers and in capability summaries. The scheduled report is unchanged.

### Security

- Capabilities: no string parameter accepts `{{`, `{%` or `{#`, whatever its pattern allows, and neither do `enum` values. Ansible renders Jinja in extra vars on the controller when they are used, so a value like `{{ lookup('pipe', ...) }}` ran inside the service container even if the playbook rejected the value afterwards. Checked with ansible-core 2.22. It could not happen with the example patterns, none of which allow `{`, but a manifest with a broad pattern was exposed.

### Tests

- 8 new tests (210 in total): `on_request` with a question, `on_request` on a `changes` capability, a missing required parameter, Jinja markers in a broad-pattern parameter and in an `enum`, and the language instruction in both prompts.

## 1.1.1 (2026-11-23)

### Fixes

- Capabilities: a question about the results ("are there new docker images?") made the model run the capability instead of answering from the latest reports. The intent prompt now asks for `run: true` only when the user explicitly asks to run, launch, execute or refresh it. With a `changes` capability this would have created a plan nobody asked for.
- Capabilities: the AI summary could contradict the actual run status ("I couldn't run the task" under "Ran now"). The service shows the status and no longer passes it to the model, which is told not to talk about whether the check ran; each report's age (`age_h`) still tells how fresh the data is.

### Tests

- New assertions on both prompts (202 tests in total). Both cases were reproduced from the dashboard with the production model before the change.

## 1.1.0 (2026-11-23)

### New

- Capabilities: the AI can use new playbooks without code changes. Each one is declared by a YAML manifest in `CAPABILITIES_PATH` (`/etc/patch-manager/capabilities.d` by default) that gives the Semaphore template, whether it only reads or changes something (`risk: read_only | changes`), the host group it may target (`limit_group`, required with `changes`), the parameters the AI may set (`bool`, `int` with min and max, `enum`, `string` with a mandatory pattern) and where its per-host reports go (`reports.path`, with `{host}`). Read-only ones start when asked and, with `run.wait: true`, the answer uses the reports they just wrote. `changes` ones only create a plan that somebody has to approve, like patching, and the dashboard shows it with the template, scope and values. When not asked to run it, the AI answers from the latest reports. With `include_in_analysis: true` those reports go into the scheduled analysis and **Analyze risk**. Without an LLM they are picked by their `keywords`. `GET /api/capabilities` lists the loaded and rejected ones, with the reason, and `POST /api/capabilities/reload` reads them again. Commented example in `config/capabilities.d.example/docker_check.yml`; documentation in section 21 of the wiki.
- `playbooks/docker_check.yml`: tells which Docker Compose projects of `docker_hosts` have a newer image in their registry by comparing digests with `docker buildx imagetools`, without pulling or restarting anything. It checks the same projects as `docker_update.yml` (`docker_compose_projects`) and writes `reports/docker-checks/<host>.json`. Images pinned with `@sha256` are reported as `pinned`. It is the example capability.
- `install.sh` creates `/etc/patch-manager/capabilities.d` (`root:patchai 0750`). For Docker there is a commented line in `docker/docker-compose.yml` to mount it into the AI container.

### Security

- The model only picks a loaded capability, the scope and parameter values; template, group, report path and allowed parameters come from the manifest. An unknown parameter is dropped with a warning, and an invalid value stops the run. Parameters starting with `ansible_` and Ansible magic variables (`hostvars`, `groups`, `playbook_dir`...) are refused: as extra vars they could change the interpreter or the shell used on the hosts.
- A manifest is rejected when the file or the directory is writable by group or others, when it is a symlink, or when its owner is neither root nor the service user, so the service can't add capabilities to itself.
- Reports are only read inside `REPORTS_PATH`, with a size cap per file (`reports.max_bytes`), and reach the model as host data, with the instruction to ignore anything that looks like an order.
- Approving a capability plan reads the manifest again: if it was removed, now points at another template or group, or the stored parameters are no longer valid, the plan fails instead of running something else.

### Tests

- 37 new tests (202 in total): loading and rejecting manifests (names, reserved parameters, paths with `..` or absolute, permissions, symlinks, duplicates, `changes` without a group), parameter validation, intent with and without an LLM, answers from reports, runs against a mocked Semaphore, scope outside the group, plan and approval, plan with a changed manifest, reports in the analysis and the API. ruff and ansible-lint (production profile, offline) clean on the new code.
- `docker_check.yml` run against a local Docker 29 with no registry access: an image pinned by digest, an image that can't be queried and a missing directory, with the JSON report and the host ending red. The same digest comparison was run by hand on four hosts with Compose 5.8 and buildx 0.39 against GHCR and Docker Hub, where it found two newer images that `docker_update.yml` then updated.

## 1.0.4 (2026-11-22)

### New

- Package questions: "which version of nginx is installed?", "¿está openssh-server instalado en ubuntu_servers?". The AI answers with a host, package and version table built from the data, not written by the model, plus the hosts without the package and those without data. By default it uses the package inventory that Check Updates now keeps for Ubuntu and Rocky hosts (`reports/packages/<host>.json`, turned off with `patch_collect_packages: false`); when asked for data "right now" or "live", it starts the new `package_query.yml` playbook (**Package Query** template in Semaphore), waits up to `PACKAGE_QUERY_TIMEOUT` seconds (180) and answers with what the hosts returned. It only reads, like **Refresh host data**, and does not go through plan approval. The package name is validated by the service and again by the playbook, and reaches the hosts as an argument, with no shell. It also works without an LLM (Spanish and English keywords) and accepts `*` as a wildcard. macOS and Windows are not queried.
- `playbooks/docker_update.yml`: updates the Docker Compose projects of the hosts in `docker_hosts`. Each host lists its directories in `docker_compose_projects`. For every project it runs `docker compose pull` and `up -d`, which only recreates containers whose image changed and starts any that were stopped, then waits until every container is `running` and, if it has a healthcheck, `healthy` (20 tries of 15 s by default). It then looks again 20 s later and checks that none restarted in between, so a container without a healthcheck that restarts in a loop isn't taken as fine. A project that doesn't get there is recorded as `FAILED`, with no rollback; the playbook moves on to the next project and the host ends red. Dangling images are only pruned on hosts where everything went well, so the previous image is still there for a manual rollback. `-e docker_pull_only=true` only downloads, and `--check` only reports the state. Writes one report per host to `reports/docker-runs/<host>.json` with the updated images and the state of each container.

### Tested

- Run against a local Docker 29 with Compose 5.7, test images and a simulated `docker compose pull`: unchanged project, new image (the container is recreated with it and the old one is pruned), failing healthcheck, stopped container, container restarting in a loop, missing directory, directory without a compose file, `--check` and `docker_pull_only`. The older Compose JSON format (an array) was tested separately.
- Package questions, end to end with a real Semaphore 2.19.12 and a local Ubuntu 24.04: the AI starts **Package Query**, the playbook writes the result and the answer carries the real nginx version; an unreachable host shows as "did not answer". With a limit (`is nginx installed on <host> right now?`) and from the inventory after a Check Updates started by the service. The test host's package inventory (1,049 packages, 37 KB) matches `dpkg-query`. A name with `;` or starting with `-` is refused by the playbook before any host is touched.
- ansible-lint (production profile), `--syntax-check` and 165 tests.
- Not tested: Docker against a real registry, on real hosts and with Compose releases older than 5; the package inventory and queries on Rocky (`rpm`).

## 1.0.3 (2026-11-22)

### New

- Scheduled report by email: the AI service runs the risk analysis on its own cron (`AUTO_ANALYSIS_CRON`, `AUTO_ANALYSIS_TZ`) and emails over SMTP a table of every host plus the AI briefing. The subject flags KEV CVEs, hosts that missed the latest check and reports that were not refreshed. It can be run by hand with the **Email report now** button or `POST /api/action/email-report`, and `/api/info` shows the next run and the outcome of the last one. New `ai.env` variables: `AUTO_ANALYSIS_*`, `SMTP_*`, `EMAIL_FROM`, `EMAIL_TO`, `EMAIL_SUBJECT_PREFIX`. No new dependencies: the service parses cron itself.
- Dashboard: the risk overview is now one row of cards that scrolls sideways, with counts per level, a fold button and a host's details when its card is tapped. With about 20 hosts the old grid pushed the input box off the screen. The dashboard shows every host in scope, up to 200 (it used to stop at 24 cards).
- Dashboard: markdown tables in AI answers render as tables; they used to come out on a single line.
- Inventory: `patch_reboot_blocked: true` stops every playbook from rebooting that host, whatever `patch_reboot_allowed` says. Meant for LXD or VM hosts and for the host that runs Semaphore.
- `install.sh` links `ansible`, `ansible-playbook` and the other commands from `/opt/ansible-venv/bin` into `/usr/local/bin`.

### Security

- Approved plans always sent `patch_reboot_allowed=true` as an extra var, which beats any inventory value, so a group with `patch_reboot_allowed: false` in `group_vars` was rebooted anyway. It is now only sent when `false` ("Prevent reboots"), and the `patch_reboot_blocked` veto is honoured in every case.
- Semaphore templates: when no template had the exact name, the only one whose name contained it was used, so "Apply Patches (old)" could receive approved plans. Only the exact name (ignoring case) counts now, and two templates with the same name are an error.
- `install.sh` checks the SHA-256 of the Semaphore `.deb` before installing it: against values pinned in the script for the default version, or against the release's checksums file for another version. It downloads into its own temporary directory instead of a fixed `/tmp` path.

### Fixes

- nginx (native and Docker): passed `Host $host` to Semaphore, which drops the port. Behind a port other than 443, such as the LXD proxy device, Semaphore refused every change with "cross-origin request blocked". It now uses `$http_host`.
- `apply_patches.yml`: Semaphore's **Dry Run** box (`--check`) was not treated as a simulation. Install tasks showed `changed` without installing anything, the listing before patching did not run and no run record was written. `--check` now equals `patch_dry_run=true`: it lists what is pending, installs and reboots nothing, and records the run as `DRY-RUN`.
- `check_updates.yml` under `--check` finished green without writing any report. As it only reads the hosts, it now ignores check mode. `reboot_if_needed.yml` also reads `dnf needs-restarting` in check mode.
- AI briefing: the prompt sent "Semaphore tasks: n/a", "patch plan: none" and "CVE: none" even when irrelevant, and the model reported them as missing data in every analysis. Those sections are only sent when they apply; the prompt explains that Ubuntu, macOS and Windows reports normally carry no CVE ids, and that the model must not question OS versions it doesn't know (Ubuntu 26.04).
- Without an LLM, keyword matching turned questions such as "list pending patches" or "which hosts have pending patches?" into a patch request (which created a plan). Read-only questions are now recognised first.
- `setup_winrm.ps1` created a new certificate on every run and left the old ones in the store. It now reuses its own while it has more than 30 days left, deletes the ones it made before, and lists (without deleting) self-signed certificates that older versions may have left.
- `create-container.sh` and the wiki suggested host port 8443 for the proxy device, which is the LXD API port. They now suggest 9443 and explain that it isn't needed when the container has its own LAN address.
- Wiki: macvlan (the LXD host and its containers can't reach each other), upgrading without losing the inventory, Semaphore's **Limit** box, the precedence of `group_vars/all.yml` over group vars in `hosts.yml`, and new troubleshooting entries.

### Tested

- 142 automated tests (56 new), ruff, shellcheck, ansible-lint (production profile), `ansible-playbook --syntax-check`, `nginx -t` on both sites and `node --check` on the dashboard JavaScript.
- `apply_patches.yml` and `check_updates.yml` run with `--check` against a local Ubuntu 24.04: nothing is installed, the run record says `DRY-RUN` with the pending updates, and the check report is written. With the 1.0.2 files both runs finish without writing a report.
- The reboot veto, evaluated with `ansible-playbook` in six combinations (no vars, `patch_reboot_allowed=true/false`, `--check`, `patch_dry_run=true`, `patch_reboot_blocked=false`); `reboot_if_needed.yml --check` skips the blocked host.
- nginx 1.24 in front of a server that echoes the header it receives: with 1.0.3 it gets `Host: 10.40.50.230:9443`; with 1.0.2, without the port.
- Email: a real send to a local SMTP server (aiosmtpd, no TLS) with a 19-host inventory; the message arrives with text and HTML parts, and the HTML was checked in a browser. The `starttls`, `always` and `try` modes and the login were tested with a fake SMTP client, not against a real TLS server.
- Dashboard: headless Chrome (Playwright) with 19 hosts at 1158×798 and 820×1100: the input box stays visible, the arrows scroll the row, folding works and tables render. Not tested on a real iPad.
- The `install.sh` checksum step, tested on its own with the real Semaphore 2.19.12 `.deb` files (amd64 and arm64) and with a file that doesn't match.
- Not tested: `setup_winrm.ps1` (no PowerShell here), a full `install.sh` run, the wiki's macvlan setup after a host reboot, and real Rocky, macOS and Windows hosts.

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
