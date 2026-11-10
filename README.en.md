# Patch Manager

[Versión en español](README.md)

Update detection, patching and reporting for Ubuntu, Rocky Linux, macOS and Windows 10/11, built on **Ansible** + **Semaphore UI**, with an AI layer (**LangGraph** + **FastAPI**) for risk analysis, briefings and natural-language requests. Patching from the AI side always goes through a plan that a human approves.

| Layer | Component | Purpose |
|-------|-----------|---------|
| Automation | Ansible playbooks | detect, install, reboot, per-host JSON reports, email |
| Web management | Semaphore UI | run and schedule playbooks, key store, API |
| AI | LangGraph + FastAPI (`/ai/`) | KEV/NVD enrichment, risk scoring, briefings, chat, patch plans with approval |
| Notifications | Email, Slack, Teams | HTML reports, `/patch` slash command, Workflows cards |

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

Then configure Semaphore (repository `/opt/patch-manager`, File inventory `inventory/hosts.yml`, templates "Check Updates" and "Apply Patches", API token): [WIKI section 5](https://github.com/louzaonet/patch-manager/wiki/Home-EN#5-configuring-semaphore-ui).

| URL | |
|-----|--|
| `https://<host>/` | Semaphore UI |
| `https://<host>/ai/` | AI dashboard (HTTP Basic) |

## CLI

```bash
ansible-playbook playbooks/check_updates.yml                        # detect + reports
ansible-playbook playbooks/apply_patches.yml --tags security_only   # security only
ansible-playbook playbooks/apply_patches.yml --limit ubuntu_servers -e patch_dry_run=true
ansible-playbook playbooks/reboot_if_needed.yml
```

## LLM

Any of `openai_compat` (llama-swap, llama.cpp, vLLM), `openrouter`, `ollama`, `openai`, `anthropic`, per node if you want:

```ini
LLM_DEFAULT=openrouter:anthropic/claude-haiku-5.5
OPENROUTER_API_KEY=sk-or-...
# or a local server: LLM_DEFAULT=openai_compat:gpt-oss-20b + OPENAI_COMPAT_BASE_URL=http://llm-host:8080/v1
```

If the model is unreachable the dashboard still works with keyword intent matching and a template briefing. Details in [WIKI section 14](https://github.com/louzaonet/patch-manager/wiki/Home-EN#14-llm-configuration-and-model-routing).

## Layout

```
ansible.cfg, requirements.yml        Ansible config and collections
inventory/hosts.yml                  hosts (OS groups + logical groups)
inventory/group_vars/                per-group policy (must sit next to the inventory)
playbooks/                           check_updates, apply_patches, reboot_if_needed (+ email templates)
collections/requirements.yml         same collections, path Semaphore looks at
scripts/                             WinRM and macOS host setup
app/                                 AI service (FastAPI, LangGraph graph, tools, integrations, UI)
config/*.example                     environment templates
docker/                              compose stack, Dockerfile, nginx
deploy/lxd/, deploy/native/          LXD launcher, native installer, systemd units, nginx site
tests/                               pytest suite (fake LLM, mocked Semaphore/NVD/KEV)
```

## Docs

- [Wiki](https://github.com/louzaonet/patch-manager/wiki/Home-EN): installation, host setup, Semaphore, LLM routing, risk model, API, security, troubleshooting
- [CHANGELOG.en.md](CHANGELOG.en.md): release notes
