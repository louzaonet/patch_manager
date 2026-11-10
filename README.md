# Patch Manager

[English version](README.en.md)

Detección de actualizaciones, parcheo e informes para Ubuntu, Rocky Linux, macOS y Windows 10/11, construido sobre **Ansible** + **Semaphore UI**, con una capa de IA (**LangGraph** + **FastAPI**) para análisis de riesgo, resúmenes y peticiones en lenguaje natural. Cualquier parcheo que se lance desde la parte de IA pasa siempre por un plan que aprueba una persona.

| Capa | Componente | Para qué sirve |
|------|------------|----------------|
| Automatización | Playbooks de Ansible | detectar, instalar, reiniciar, informes JSON por host, correo |
| Gestión web | Semaphore UI | lanzar y programar playbooks, almacén de claves, API |
| IA | LangGraph + FastAPI (`/ai/`) | enriquecimiento con KEV/NVD, puntuación de riesgo, resúmenes, chat, planes de parcheo con aprobación |
| Notificaciones | Correo, Slack, Teams | informes HTML, comando `/patch`, tarjetas de Workflows |

```
  Panel / Slack / Teams ──► servicio de IA ──► LLM (llama-swap u OpenRouter)
                                 │  lee informes, prepara planes
                                 │  plan aprobado ──► API de Semaphore
  Semaphore ──► Ansible ──► hosts (SSH / WinRM) ──► reports/hosts/*.json
```

## Puesta en marcha rápida

**Contenedor LXD (servicios systemd nativos, recomendado):**

```bash
./deploy/lxd/create-container.sh patchmgr ubuntu:24.04 native
lxc exec patchmgr -- nano /etc/patch-manager/ai.env    # ajustes del LLM
lxc exec patchmgr -- systemctl restart patch-ai
```

**Docker:**

```bash
cp config/env.example config/.env && cp config/ai.env.example config/ai.env   # rellena los secretos
cd docker && bash generate_certs.sh patch-manager.example.com && docker compose up -d
```

Después configura Semaphore (repositorio `/opt/patch-manager`, inventario de tipo File `inventory/hosts.yml`, plantillas "Check Updates" y "Apply Patches", token de API): [sección 5 de la WIKI](https://github.com/louzaonet/patch-manager/wiki/Home#5-configuración-de-semaphore-ui).

| URL | |
|-----|--|
| `https://<host>/` | Semaphore UI |
| `https://<host>/ai/` | Panel de IA (HTTP Basic) |

## CLI

```bash
ansible-playbook playbooks/check_updates.yml                        # detectar + informes
ansible-playbook playbooks/apply_patches.yml --tags security_only   # solo seguridad
ansible-playbook playbooks/apply_patches.yml --limit ubuntu_servers -e patch_dry_run=true
ansible-playbook playbooks/reboot_if_needed.yml
```

## LLM

Cualquiera de `openai_compat` (llama-swap, llama.cpp, vLLM), `openrouter`, `ollama`, `openai` o `anthropic`, y si quieres, uno distinto por nodo:

```ini
LLM_DEFAULT=openrouter:anthropic/claude-haiku-5.5
OPENROUTER_API_KEY=sk-or-...
# o un servidor local: LLM_DEFAULT=openai_compat:gpt-oss-20b + OPENAI_COMPAT_BASE_URL=http://llm-host:8080/v1
```

Si el modelo no responde, el panel sigue funcionando con detección de intención por palabras clave y un resumen generado con plantilla. Detalles en la [sección 14 de la WIKI](https://github.com/louzaonet/patch-manager/wiki/Home#14-configuración-del-llm-y-enrutado-de-modelos).

## Estructura

```
ansible.cfg, requirements.yml        configuración de Ansible y colecciones
inventory/hosts.yml                  hosts (grupos por SO + grupos lógicos)
inventory/group_vars/                política por grupo (tiene que estar junto al inventario)
playbooks/                           check_updates, apply_patches, reboot_if_needed (+ plantillas de correo)
collections/requirements.yml         las mismas colecciones, en la ruta que busca Semaphore
scripts/                             preparación de hosts WinRM y macOS
app/                                 servicio de IA (FastAPI, grafo LangGraph, herramientas, integraciones, interfaz)
config/*.example                     plantillas de variables de entorno
docker/                              stack de compose, Dockerfile, nginx
deploy/lxd/, deploy/native/          lanzador LXD, instalador nativo, unidades systemd, sitio nginx
tests/                               tests de pytest (LLM simulado, Semaphore/NVD/KEV simulados)
```

## Documentación

- [Wiki](https://github.com/louzaonet/patch-manager/wiki): instalación, preparación de hosts, Semaphore, enrutado de LLM, modelo de riesgo, API, seguridad y resolución de problemas
- [CHANGELOG.md](CHANGELOG.md): notas de la versión
