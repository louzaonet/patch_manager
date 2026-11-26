# Patch Manager

[Versión en español](README.md)

Update detection, patching and reporting for Ubuntu, Rocky Linux, macOS and Windows 10/11, built on **Ansible** + **Semaphore UI**, with an AI layer (**LangGraph** + **FastAPI**) for risk analysis, briefings and natural-language requests. Patching from the AI side always goes through a plan that a human approves.

| Layer | Component | Purpose |
|-------|-----------|---------|
| Automation | Ansible playbooks | detect, install, reboot, per-host JSON reports, email |
| Web management | Semaphore UI | run and schedule playbooks, key store, API |
| AI | LangGraph + FastAPI (`/ai/`) | Ubuntu CVEs from Canonical's OVAL data (pending, Pro-only and unfixed), KEV/NVD enrichment, risk scoring, briefings, chat, package versions per host, patch plans with approval, your own playbooks declared by a manifest |
| Notifications | Email, Slack, Teams | HTML reports from the playbooks, scheduled AI risk report, `/patch` slash command, Workflows cards |

```
  Dashboard / Slack / Teams ──► AI service ──► LLM (llama-swap or OpenRouter)
                                   │  reads reports, builds plans
                                   │  approved plan ──► Semaphore API
  Semaphore ──► Ansible ──► hosts (SSH / WinRM) ──► reports/hosts/*.json
```

## Quick start

**LXD container (native systemd services, recommended):**

```bash
./deploy/lxd/create-container.sh patchmgr ubuntu:24.04 native
lxc exec patchmgr -- nano /etc/patch-manager/ai.env    # LLM settings
lxc exec patchmgr -- systemctl restart patch-ai
```

**Docker:**

```bash
cp config/env.example config/.env && cp config/ai.env.example config/ai.env   # fill in secrets
cd docker && bash generate_certs.sh patch-manager.example.com && docker compose up -d
```

Then configure Semaphore (repository `/opt/patch-manager`, File inventory `inventory/hosts.yml`, templates "Check Updates" and "Apply Patches", API token): [WIKI section 5](https://github.com/louzaonet/patch_manager/wiki/Home-EN#5-configuring-semaphore-ui).

| URL | |
|-----|--|
| `https://<host>/` | Semaphore UI |
| `https://<host>/ai/` | AI dashboard (HTTP Basic) |

## Capabilities: your own playbooks for the AI (1.1.0)

The AI can use new playbooks without code changes. You write the playbook, create its Semaphore template and drop a YAML manifest in `/etc/patch-manager/capabilities.d` that says:

- which template to run and whether it only reads (`read_only`) or changes something (`changes`);
- which host group it may target;
- which parameters the AI may set and with which values (`bool`, `int` with bounds, `enum`, `string` with a pattern);
- where the playbook writes its per-host JSON, so the AI can read it and, if you want, add it to the scheduled analysis.

Then you ask for it in the chat by name or by what it does. Read-only ones run when asked; the ones that change something create a plan that has to be approved, like patching. The AI only picks the capability, the target and the values, and everything is validated against the manifest. A manifest the service could write (group or other write permissions, symlinks, another owner) is not loaded.

It ships with an example, `playbooks/docker_check.yml`, which tells which containers have a newer image by comparing digests with the registry, without pulling anything, and its manifest in `config/capabilities.d.example/docker_check.yml`. Details in [section 21 of the WIKI](https://github.com/louzaonet/patch_manager/wiki/Home-EN#21-custom-recipes).

```bash
sudo install -o root -g patchai -m 0640 config/capabilities.d.example/docker_check.yml /etc/patch-manager/capabilities.d/
curl -s -u admin:... -H 'X-Requested-With: patch-ai' -X POST https://<host>/ai/api/capabilities/reload
```

## CLI

```bash
ansible-playbook playbooks/check_updates.yml                        # detect + reports
ansible-playbook playbooks/apply_patches.yml --tags security_only   # security only
ansible-playbook playbooks/apply_patches.yml --limit ubuntu_servers -e patch_dry_run=true
ansible-playbook playbooks/reboot_if_needed.yml
ansible-playbook playbooks/docker_update.yml --limit photos-01      # Docker Compose containers
ansible-playbook playbooks/docker_check.yml                          # newer images? (changes nothing)
```

## LLM

Any of `openai_compat` (llama-swap, llama.cpp, vLLM), `openrouter`, `ollama`, `openai`, `anthropic`, per node if you want:

```ini
LLM_DEFAULT=openrouter:anthropic/claude-haiku-5.5
OPENROUTER_API_KEY=sk-or-...
# or a local server: LLM_DEFAULT=openai_compat:gpt-oss-20b + OPENAI_COMPAT_BASE_URL=http://llm-host:8080/v1
```

If the model is unreachable the dashboard still works with keyword intent matching and a template briefing. Details in [WIKI section 14](https://github.com/louzaonet/patch_manager/wiki/Home-EN#14-llm-configuration-and-model-routing).

## Layout

```
ansible.cfg, requirements.yml        Ansible config and collections
inventory/hosts.yml                  hosts (OS groups + logical groups)
inventory/group_vars/                per-group policy (must sit next to the inventory)
playbooks/                           check_updates, apply_patches, reboot_if_needed, package_query, docker_update, docker_check (+ email templates)
collections/requirements.yml         same collections, path Semaphore looks at
scripts/                             WinRM and macOS host setup
app/                                 AI service (FastAPI, LangGraph graph, tools, integrations, UI)
config/*.example                     environment templates
config/capabilities.d.example/       example capability manifest (docker_check)
docker/                              compose stack, Dockerfile, nginx
deploy/lxd/, deploy/native/          LXD launcher, native installer, systemd units, nginx site
tests/                               pytest suite (fake LLM, mocked Semaphore/NVD/KEV)
```

## Docs

- [Wiki](https://github.com/louzaonet/patch_manager/wiki/Home-EN): installation, host setup, Semaphore, LLM routing, risk model, API, security, troubleshooting
- [CHANGELOG.en.md](CHANGELOG.en.md): release notes
