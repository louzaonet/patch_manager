# Patch Manager: Wiki

Versión 1.0 (noviembre de 2026). Notas de la versión: [CHANGELOG.md](CHANGELOG.md).

## Índice

1. [Visión general](#1-visión-general)
2. [Arquitectura](#2-arquitectura)
3. [Requisitos](#3-requisitos)
4. [Instalación del servidor](#4-instalación-del-servidor)
5. [Configuración de Semaphore UI](#5-configuración-de-semaphore-ui)
6. [Conectar hosts Ubuntu](#6-conectar-hosts-ubuntu)
7. [Conectar hosts Rocky Linux](#7-conectar-hosts-rocky-linux)
8. [Conectar hosts macOS](#8-conectar-hosts-macos)
9. [Conectar hosts Windows 10/11](#9-conectar-hosts-windows-1011)
10. [Notificaciones por correo](#10-notificaciones-por-correo)
11. [Ejecutar playbooks desde la CLI](#11-ejecutar-playbooks-desde-la-cli)
12. [Ejecutar playbooks desde Semaphore](#12-ejecutar-playbooks-desde-semaphore)
13. [Programación](#13-programación)
14. [Configuración del LLM y enrutado de modelos](#14-configuración-del-llm-y-enrutado-de-modelos)
15. [Uso del panel de IA](#15-uso-del-panel-de-ia)
16. [Integración con Slack](#16-integración-con-slack)
17. [Integración con Microsoft Teams](#17-integración-con-microsoft-teams)
18. [Cómo funciona el agente de IA](#18-cómo-funciona-el-agente-de-ia)
19. [Análisis de riesgo y datos de CVE](#19-análisis-de-riesgo-y-datos-de-cve)
20. [Referencia de la API de IA](#20-referencia-de-la-api-de-ia)
21. [Recetas propias](#21-recetas-propias)
22. [Gestión del inventario](#22-gestión-del-inventario)
23. [Ventanas de mantenimiento](#23-ventanas-de-mantenimiento)
24. [Notas de seguridad](#24-notas-de-seguridad)
25. [Resolución de problemas](#25-resolución-de-problemas)
26. [Desarrollo y pruebas](#26-desarrollo-y-pruebas)

---

## 1. Visión general

Patch Manager detecta, instala e informa de las actualizaciones del sistema operativo en un parque mixto de máquinas Ubuntu, Rocky Linux, macOS y Windows 10/11. Tiene dos capas:

- **Automatización**: los playbooks de Ansible hacen el trabajo determinista (detectar actualizaciones, instalar, reiniciar, escribir informes, enviar correo). Semaphore UI los lanza desde el navegador, según una programación o a través de su API.
- **IA**: un agente de LangGraph detrás de un pequeño panel en FastAPI. Lee los informes de actualizaciones de cada host, enriquece los CVE que esos hosts reportan con datos de CISA KEV y NVD, puntúa el riesgo, redacta resúmenes y responde preguntas. Cuando alguien pide parchear, prepara un **plan que tiene que aprobar una persona**; solo entonces llama a Semaphore.

El LLM nunca decide ejecutar nada por su cuenta, y todos los nodos tienen una alternativa sin LLM, así que el panel sigue funcionando (con una salida más sencilla) cuando el modelo no está disponible.

---

## 2. Arquitectura

```
  Navegador / Slack / Teams
          │
          ▼
  ┌───────────────────────── nginx (TLS :443) ─────────────────────────┐
  │   /      → Semaphore UI (:3000)        /ai/ → Patch Manager AI      │
  └────────────────────────────────────────────────────────────────────┘
          │                                        │  HTTP Basic / token
          │                                        ▼
          │                     agente LangGraph ── LLM (OpenRouter, llama-swap,
          │                     │                        Ollama, ...)
          │                     │ lee              ── CISA KEV, NIST NVD
          │                     ▼
          │      /var/lib/patch-manager/reports/hosts/*.json
          │                     ▲ escribe
          ▼                     │
   Ansible (vía Semaphore) ─────┘   ◄── plan aprobado: POST /api/project/{id}/tasks
          │ SSH / WinRM
   ┌──────┴───────┬─────────────┬──────────────┐
   Ubuntu       Rocky         macOS         Windows
```

Flujo de datos en una semana normal:

1. Semaphore ejecuta **Check Updates** cada noche. El resultado de cada host se guarda en `reports/hosts/<host>.json`.
2. Abres el panel y pulsas **Analyze risk**. El agente cruza inventario e informes, comprueba los CVE reportados contra KEV/NVD, puntúa y redacta el resumen.
3. Pulsas **Plan patches** (o escribes "patch prod, security only"). El agente prepara un plan (alcance, opciones y hosts agrupados por riesgo) y muestra **Approve / Reject**.
4. Al aprobarlo, el servicio lanza la plantilla **Apply Patches** en Semaphore con el límite y las variables extra del plan, y el panel consulta el estado de la tarea hasta que termina.

---

## 3. Requisitos

### Host de gestión

| Componente | Notas |
|------------|-------|
| Dónde | Un contenedor LXD (se recomienda Ubuntu 24.04), una VM o cualquier host con Docker. amd64 o arm64 (una Raspberry Pi 5 basta) |
| RAM / disco | 2 GB de RAM y 10 GB de disco para Semaphore + servicio de IA (el LLM se ejecuta en otro sitio) |
| Red | SSH (22) a los hosts Linux/macOS, WinRM (5986) a Windows, HTTPS al endpoint del LLM, `www.cisa.gov` y `services.nvd.nist.gov` |
| Software | Lo instalan los scripts: Python 3.11+, ansible-core 2.20+, Semaphore 2.19, nginx |

### Hosts gestionados

| SO | Requisitos |
|----|------------|
| Ubuntu 22.04 / 24.04 / 26.04 | SSH, Python 3 y un usuario con sudo sin contraseña |
| Rocky Linux 9 / 10 | SSH, Python 3, sudo sin contraseña y `dnf-plugins-core` (para `dnf needs-restarting`) |
| Rocky Linux 8 | Lo anterior, más Python 3.9+ (`dnf install python3.11`) y `ansible_python_interpreter: /usr/bin/python3.11`. ansible-core 2.20 ya no admite el Python 3.6 que trae por defecto |
| macOS 14 / 15 / 26 | Remote Login, Xcode Command Line Tools (Python 3) y sudo sin contraseña. En Apple silicon hacen falta las credenciales de un propietario del volumen para las actualizaciones del sistema (sección 8) |
| Windows 11 / Windows 10 con ESU | WinRM por HTTPS (5986) y una cuenta de administrador local, o bien OpenSSH |

---

## 4. Instalación del servidor

Elige un camino.

### 4.1 Contenedor LXD, instalación nativa (recomendada)

Semaphore y el servicio de IA se ejecutan como unidades de systemd dentro de un contenedor normal (sin privilegios). Sin Docker y sin anidamiento.

En el host LXD, desde la raíz del repositorio:

```bash
./deploy/lxd/create-container.sh patchmgr ubuntu:24.04 native
```

El script lanza el contenedor, copia el repositorio a `/opt/patch-manager` (sin secretos locales) y ejecuta dentro `deploy/native/install.sh`, que:

- instala ansible-core + pywinrm en `/opt/ansible-venv` y las colecciones de `requirements.yml`
- instala Semaphore desde el `.deb` oficial (base de datos SQLite, configuración en `/etc/semaphore/`)
- crea el administrador de Semaphore y guarda su contraseña en `/etc/semaphore/admin-password`
- instala el servicio de IA en `/opt/patch-manager/.venv`, con la configuración en `/etc/patch-manager/ai.env` y una contraseña aleatoria para el panel
- pone delante nginx con un certificado autofirmado (`/` Semaphore, `/ai/` panel)

Puedes volver a ejecutar el script sin problema: conserva los ficheros de configuración y los secretos que ya existan. Para instalar sin nginx (si terminas el TLS en otro sitio, por ejemplo con Cloudflare Tunnel): `install.sh --no-nginx`.

Después:

```bash
lxc exec patchmgr -- nano /etc/patch-manager/ai.env     # ajustes del LLM, ver sección 14
lxc exec patchmgr -- systemctl restart patch-ai
lxc exec patchmgr -- journalctl -u patch-ai -f
```

Para llegar al contenedor desde tu red local, por ejemplo del puerto 8443 del host al 443 del contenedor:

```bash
lxc config device add patchmgr https proxy listen=tcp:0.0.0.0:8443 connect=tcp:127.0.0.1:443
```

El contenedor tiene que poder llegar a los hosts gestionados y al endpoint del LLM (openrouter.ai, o tu propio host con llama-swap/Ollama).

> Si `patch-ai` falla con `status=226/NAMESPACE`, el contenedor no admite las opciones de aislamiento de systemd. Comenta las líneas `Protect*`/`Private*` de `/etc/systemd/system/patch-ai.service` y ejecuta `systemctl daemon-reload`.

### 4.2 Contenedor LXD con Docker

Si prefieres el stack de Docker dentro de LXD:

```bash
./deploy/lxd/create-container.sh patchmgr ubuntu:24.04 docker
```

Esto crea el contenedor con `security.nesting=true` (más la interceptación de syscalls que necesita Docker) e instala Docker. Sigue con el apartado 4.3 dentro del contenedor. Si el almacenamiento de LXD es ZFS, el driver overlay2 de Docker necesita ZFS 2.2 o posterior.

### 4.3 Docker en cualquier host

```bash
cp config/env.example config/.env        && chmod 600 config/.env      # cambia todos los valores CHANGE_ME
cp config/ai.env.example config/ai.env   && chmod 600 config/ai.env    # LLM, contraseña del panel
cd docker
bash generate_certs.sh patch-manager.example.com
docker compose up -d
docker compose ps
```

Genera cada clave de Semaphore con `head -c32 /dev/urandom | base64`. No reutilices los valores de ejemplo.

| Servicio | URL |
|----------|-----|
| Semaphore UI | `https://<host>/` |
| Panel de IA | `https://<host>/ai/` |
| Health | `https://<host>/health` |

Lo importante del fichero de compose:

- Los datos de PostgreSQL 18 están en el volumen `pgdata`, montado en `/var/lib/postgresql` (las imágenes de PostgreSQL 18 cambiaron la ruta de datos).
- Semaphore recibe solo las partes del repositorio que usa Ansible (`ansible.cfg`, `playbooks/`, `inventory/`, `collections/`), en solo lectura. Los secretos de `config/` no se montan.
- `docker/semaphore/requirements.txt` añade pywinrm al Python de Semaphore al arrancar.
- Un servicio de un solo uso, `volume-init`, ajusta el propietario del volumen compartido `reports` (Semaphore escribe y el servicio de IA lee).
- El contenedor de IA se ejecuta en solo lectura, con un usuario sin privilegios y sin ninguna capability.

### Certificados TLS

El certificado autofirmado es para pruebas. Sustituye `server.crt`/`server.key` (Docker: `docker/nginx/certs/`; nativo: `/etc/ssl/patch-manager/`) por uno de tu sistema ACME o de tu CA interna y recarga nginx. Si el panel solo se publica a través de Cloudflare Tunnel + Access, puedes dejar nginx en HTTP plano dentro del contenedor y que el túnel termine el TLS.

---

## 5. Configuración de Semaphore UI

Entra como `admin` (Docker: contraseña de `config/.env`; nativo: `/etc/semaphore/admin-password`).

1. **Project**: crea uno, por ejemplo "Patch Management". Si creas más de uno, define `SEMAPHORE_PROJECT_ID` en `ai.env`.
2. **Key Store**: una clave privada SSH para Linux/macOS y una entrada "Login with password" para Windows (o guarda la contraseña en Vault, ver sección 22).
3. **Repository**: URL `/opt/patch-manager` (una ruta local; rama vacía).
4. **Inventory**: tipo **File**, ruta `inventory/hosts.yml`. Tiene que ser el fichero del repositorio, porque las variables de grupo están a su lado, en `inventory/group_vars/`. Un inventario "static" pegado a mano se ejecutaría sin ellas.
5. **Templates** (los nombres tienen que coincidir con `SEMAPHORE_TEMPLATE_*` de `ai.env`):

   | Plantilla | Playbook | Notas |
   |-----------|----------|-------|
   | Check Updates | `playbooks/check_updates.yml` | solo lectura en los hosts; prográmala cada noche |
   | Apply Patches | `playbooks/apply_patches.yml` | activa la opción que permite a una tarea **sobrescribir el límite** (`allow_override_limit` en la API). Sin ella, Semaphore acepta el límite y luego ejecuta en todos los hosts, así que el servicio de IA rechaza ejecuciones limitadas sobre esa plantilla |
   | Reboot If Needed | `playbooks/reboot_if_needed.yml` | opcional |

6. **Token de API**: menú de usuario → API Tokens → crear. Ponlo en `SEMAPHORE_API_TOKEN` y reinicia el servicio de IA.

Semaphore instala las colecciones de `collections/requirements.yml` al empezar cada tarea. La instalación nativa, además, las deja preinstaladas para todo el sistema.

---

## 6. Conectar hosts Ubuntu

```bash
sudo systemctl enable --now ssh
sudo adduser --disabled-password --gecos "Ansible" ansible
echo "ansible ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/ansible
sudo chmod 0440 /etc/sudoers.d/ansible
# desde el host de gestión:
ssh-copy-id -i ~/.ssh/ansible_key.pub ansible@<host>
```

Añade el host bajo `ubuntu_servers` en `inventory/hosts.yml` y pruébalo con `ansible <host> -m ping`.

El modo solo seguridad instala exactamente los paquetes que `apt list --upgradable` muestra como procedentes del pocket `-security`. Si no hay ninguno, no se instala nada.

---

## 7. Conectar hosts Rocky Linux

```bash
sudo systemctl enable --now sshd
sudo useradd -m ansible
echo "ansible ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/ansible
sudo chmod 0440 /etc/sudoers.d/ansible
sudo dnf install -y dnf-plugins-core     # dnf needs-restarting
```

Rocky publica metadatos `updateinfo`, así que el modo solo seguridad (`dnf --security`) funciona y el playbook de comprobación puede recoger los IDs de CVE de cada aviso pendiente. Esos IDs de CVE son los que el servicio de IA enriquece con datos de KEV/NVD.

---

## 8. Conectar hosts macOS

Ejecuta el script auxiliar en cada Mac:

```bash
sudo ./scripts/setup_macos_ssh.sh admin "ssh-ed25519 AAAA... ansible@patch-manager"
```

Activa Remote Login (en versiones recientes de macOS puede necesitar acceso total al disco para Terminal; si no, actívalo en Ajustes del Sistema → General → Compartir), comprueba que estén las Command Line Tools, configura sudo sin contraseña e instala la clave.

**Apple silicon**: `softwareupdate` solo instala actualizaciones de macOS si recibe las credenciales de un propietario del volumen. Ponlas en el inventario o en las variables de grupo:

```yaml
# inventory/group_vars/macos_servers.yml
patch_macos_update_user: admin
# vault_macos_update_password definida con ansible-vault encrypt_string
```

La contraseña se pasa a `softwareupdate --stdinpass` por la entrada estándar y la tarea se ejecuta con `no_log`. Para más de unos pocos Macs, una política de actualizaciones por MDM es mejor herramienta.

Los Macs se parchean de uno en uno. Cuando una actualización necesita reinicio, `softwareupdate --restart` puede apagar el Mac antes de que el comando termine; el playbook tolera la conexión cortada y espera a que el Mac vuelva (hasta `patch_reboot_timeout`). Este camino aún no se ha probado en hardware real, así que haz una primera ejecución sobre un solo Mac con `--limit`. El modo solo seguridad se traduce a `softwareupdate --recommended`, lo más parecido que ofrece Apple.

---

## 9. Conectar hosts Windows 10/11

Windows 10 salió del soporte general en octubre de 2025; solo recibe actualizaciones de seguridad si está inscrito en ESU.

1. Crea un administrador local (PowerShell con privilegios elevados):

   ```powershell
   $Password = Read-Host -AsSecureString "Password"
   New-LocalUser -Name "ansible_admin" -Password $Password -FullName "Ansible Admin"
   Add-LocalGroupMember -Group "Administrators" -Member "ansible_admin"
   ```

2. Activa WinRM por HTTPS: `powershell -ExecutionPolicy Bypass -File scripts\setup_winrm.ps1`. Crea un certificado autofirmado para el listener, activa NTLM/Negotiate, deja la autenticación Basic **desactivada** y abre el 5986 para los perfiles Dominio y Privado.
3. Guarda la contraseña con Vault: `ansible-vault encrypt_string 'secreto' --name vault_windows_password`.
4. Prueba: `ansible win-desktop-01 -m ansible.windows.win_ping`.

En un dominio es preferible Kerberos (`pywinrm[kerberos]`) a NTLM. Ansible también permite gestionar Windows por OpenSSH, lo que evita WinRM por completo.

---

## 10. Notificaciones por correo

Si están activadas, los playbooks envían un resumen en HTML tras cada comprobación y cada parcheo. La configuración SMTP sale de variables de entorno del controlador:

| Variable | Ejemplo |
|----------|---------|
| `EMAIL_ENABLED` | `true` |
| `SMTP_HOST` / `SMTP_PORT` | `smtp.example.com` / `587` |
| `SMTP_SECURE` | `starttls` (o `always`, `never`, `try`) |
| `SMTP_USER` / `SMTP_PASSWORD` | |

Docker: defínelas en `config/.env` (Semaphore las pasa a las tareas). Nativo: `/etc/semaphore/semaphore.env` y luego `systemctl restart semaphore`. CLI: expórtalas en tu shell.

Los destinatarios y el remitente están en `inventory/group_vars/all.yml` (`email_to`, `email_from`).

---

## 11. Ejecutar playbooks desde la CLI

Desde la raíz del repositorio (`ansible.cfg` apunta a `inventory/hosts.yml`):

```bash
ansible-playbook playbooks/check_updates.yml                        # detectar, escribir informes
ansible-playbook playbooks/apply_patches.yml                        # instalar todo
ansible-playbook playbooks/apply_patches.yml --tags security_only   # solo seguridad
ansible-playbook playbooks/apply_patches.yml -e patch_security_only=true   # lo mismo
ansible-playbook playbooks/apply_patches.yml --limit ubuntu_servers
ansible-playbook playbooks/apply_patches.yml -e patch_dry_run=true
ansible-playbook playbooks/apply_patches.yml -e patch_reboot_allowed=false
ansible-playbook playbooks/apply_patches.yml -e patch_serial=25%    # por lotes en cada grupo de SO
ansible-playbook playbooks/reboot_if_needed.yml
```

Los informes se escriben en la máquina que ejecuta Ansible, bajo `PATCH_REPORT_DIR` (por defecto `/var/lib/patch-manager/reports`). Cámbiala si ejecutas la CLI en otro sitio: `PATCH_REPORT_DIR=/tmp/reports ansible-playbook ...`.

Los pasos de informe y correo van dentro de un play `hosts: all` delegado en localhost, así que también se ejecutan cuando usas `--limit`.

---

## 12. Ejecutar playbooks desde Semaphore

Templates → Run. En el diálogo de ejecución puedes sobrescribir el límite o añadir variables extra (`patch_dry_run=true`). Semaphore muestra el log en directo; los informes y el correo llegan al final de la ejecución.

**Hosts que fallan.** Si una tarea falla en un host durante `apply_patches.yml`, el fallo queda registrado: el host aparece como `FAILED` (con la tarea que falló y su mensaje) en `reports/patch-runs/<host>.json` y en el correo, y la ejecución sigue terminando como fallida para ese host, así que Semaphore muestra la tarea en rojo. La excepción son los hosts inalcanzables: solo aparecen en el resumen final de Ansible.

---

## 13. Programación

Programaciones sugeridas en Semaphore:

| Plantilla | Cron | Motivo |
|-----------|------|--------|
| Check Updates | `15 6 * * *` | datos frescos en el panel cada mañana |
| Apply Patches (solo seguridad, `patch_security_only=true`) | `0 3 * * 6` | semanal, dentro de la ventana de mantenimiento |
| Apply Patches (completo) | `0 3 1-7 * 6` | primer sábado de cada mes |

Los planes aprobados desde el panel se ejecutan en el momento; la comprobación de ventana de mantenimiento (sección 23) se sigue aplicando si está activada.

---

## 14. Configuración del LLM y enrutado de modelos

Tres nodos llaman a un LLM: `classify_intent` (respuesta JSON corta), `generate_briefing` (resumir unos pocos KB de JSON en markdown) y `handle_question` (preguntas y respuestas libres). Los botones de acción rápida se saltan `classify_intent` por completo.

### Proveedores

| Proveedor | Ejemplo | Necesita |
|-----------|---------|----------|
| `openai_compat` (alias `local`, `llamaswap`) | `openai_compat:gpt-oss-20b` | `OPENAI_COMPAT_BASE_URL` (llama-swap, servidor de llama.cpp, vLLM, LM Studio) |
| `openrouter` | `openrouter:anthropic/claude-haiku-5.5` | `OPENROUTER_API_KEY` |
| `ollama` | `ollama:qwen3.5:9b` | `OLLAMA_BASE_URL` |
| `openai` | `openai:gpt-5-mini` | `OPENAI_API_KEY` |
| `anthropic` | `anthropic:claude-haiku-5-5` | `ANTHROPIC_API_KEY` |

`LLM_DEFAULT` es obligatoria (el fichero de ejemplo viene con OpenRouter + Claude Haiku 5.5). `LLM_NODE_CLASSIFY_INTENT`, `LLM_NODE_GENERATE_BRIEFING` y `LLM_NODE_HANDLE_QUESTION` la sustituyen para cada nodo. Si un modelo de nodo no se puede crear (falta la clave, errata en el proveedor), ese nodo vuelve a `LLM_DEFAULT` y lo deja en el log.

### llama-swap en otra máquina

```ini
LLM_DEFAULT=openai_compat:gpt-oss-20b
OPENAI_COMPAT_BASE_URL=http://llm-host:8080/v1
OPENAI_COMPAT_EXTRA_BODY={"chat_template_kwargs": {"reasoning_effort": "low"}}
LLM_TIMEOUT=120
```

- El nombre del modelo es la clave en el `config.yaml` de llama-swap; puedes listarlos con `curl http://llm-host:8080/v1/models`.
- Usa **un solo** modelo para todos los nodos. Con varios, llama-swap descarga y carga modelos entre nodos de la misma petición, y eso cuesta mucho más tiempo del que ahorra.
- `OPENAI_COMPAT_EXTRA_BODY` se añade a todas las peticiones. Con gpt-oss, `reasoning_effort: low` mantiene las respuestas rápidas. Con los modelos Qwen de razonamiento híbrido usa `{"chat_template_kwargs": {"enable_thinking": false}}`.
- Por defecto, llama-swap escucha en todas las interfaces y no tiene autenticación salvo que configures `apiKeys`. Restríngelo a la IP del contenedor de gestión con un cortafuegos, o configura una clave de API y ponla en `OPENAI_COMPAT_API_KEY`.
- La primera petición tras cambiar de modelo es lenta (carga del modelo). `LLM_TIMEOUT` lo cubre.

### OpenRouter

```ini
LLM_DEFAULT=openrouter:anthropic/claude-haiku-5.5
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_EXTRA_BODY={"provider": {"data_collection": "deny"}, "reasoning": {"effort": "low"}}
```

`provider.data_collection: deny` evita los proveedores que guardan los prompts o entrenan con ellos. `reasoning.effort: low` mantiene rápidos los modelos de razonamiento. Los precios cambian a menudo; consulta la página del modelo en openrouter.ai.

### Híbrido

```ini
LLM_DEFAULT=openai_compat:gpt-oss-20b
LLM_NODE_GENERATE_BRIEFING=openrouter:anthropic/claude-haiku-5.5
```

La intención y las preguntas se quedan en tu hardware; solo los resúmenes (con nombres de host, versiones de SO, recuentos e IDs de CVE, nunca IPs ni credenciales) van a la nube.

### Temperatura

`LLM_TEMPERATURE` no tiene valor por defecto, así que se aplica el del proveedor. Varios modelos de razonamiento rechazan una temperatura personalizada; defínela solo para modelos que sepas que la aceptan.

### Cuando el modelo no está disponible

- `classify_intent` recurre a la detección por palabras clave.
- `generate_briefing` recurre a un resumen determinista (recuentos, hosts con KEV, riesgos principales, plan pendiente).
- `handle_question` devuelve un mensaje breve de "modelo no disponible".

Comprueba el enrutado con `GET /api/info` (requiere autenticación).

---

## 15. Uso del panel de IA

`https://<host>/ai/`, autenticación HTTP Basic con `APP_AUTH_USER` / `APP_AUTH_PASSWORD`.

- **Pending updates**: resumen de los últimos informes (no contacta con los hosts).
- **Analyze risk**: enriquecimiento con KEV/NVD + puntuación + resumen, con una tarjeta por host.
- **Plan patches**: prepara un plan para el destino y las opciones seleccionados, lista los hosts agrupados por riesgo y muestra **Approve / Reject**. Un plan aprobado es una sola ejecución de Semaphore sobre todo el alcance, con las mismas opciones para todos los hosts; los grupos solo indican qué es urgente. Para parchear primero los críticos, planifícalos por separado (elige ese host o grupo como destino). Al aprobar se pide confirmación, se lanza la tarea en Semaphore y se consulta su estado hasta que termina.
- **Refresh host data**: lanza la plantilla Check Updates en Semaphore para el destino seleccionado.
- Chat: texto libre. Peticiones como "patch the web servers, security only, no reboot" generan un plan, nunca una ejecución directa. El selector de destino y las casillas de opciones prevalecen sobre lo que extraiga el modelo.

Los planes caducan a los `PLAN_TTL_MINUTES` (30 por defecto) y se guardan en memoria: al reiniciar el servicio se pierden los planes pendientes.

---

## 16. Integración con Slack

1. Crea una app de Slack con un comando de barra `/patch` que apunte a `https://<host>/ai/api/integrations/slack`. El token de bot (`chat:write`) solo hace falta como alternativa.
2. Configura:

   ```ini
   SLACK_ENABLED=true
   SLACK_SIGNING_SECRET=...
   SLACK_APPROVER_IDS=U0123ABCD,U0456EFGH
   # SLACK_BOT_TOKEN=xoxb-...   (opcional)
   ```

Uso:

```
/patch analyze risk on production
/patch plan security patches for ubuntu_servers
/patch approve 3f9c1a2b7d4e
/patch reject 3f9c1a2b7d4e
```

Todas las peticiones se verifican por firma (ventana de 5 minutos). El endpoint responde dentro del límite de 3 segundos de Slack y publica el resultado después mediante el `response_url` del comando. Solo los usuarios de `SLACK_APPROVER_IDS` pueden aprobar o rechazar.

---

## 17. Integración con Microsoft Teams

Los webhooks de conectores de Office 365 (`outlook.office.com/webhook/...`) dejaron de funcionar en mayo de 2026.

**Notificaciones**: en el canal, Workflows → "Post to a channel when a webhook request is received". Copia la URL en `TEAMS_WEBHOOK_URL`. El servicio publica Adaptive Cards en el formato que espera esa plantilla.

**Menciones a la app (opcional)**: crea un Outgoing Webhook que apunte a `https://<host>/ai/api/integrations/teams` y pon su token de seguridad en `TEAMS_OUTGOING_SECRET`. Las peticiones se verifican por HMAC. Teams solo espera unos 5 segundos, así que el endpoint confirma al momento y el resumen llega después por el webhook de Workflows.

```ini
TEAMS_ENABLED=true
TEAMS_WEBHOOK_URL=https://prod-00.westeurope.logic.azure.com/workflows/...
TEAMS_OUTGOING_SECRET=token-en-base64
```

Los planes no se pueden aprobar desde Teams; usa el panel o Slack.

---

## 18. Cómo funciona el agente de IA

```
START → load_inventory → classify_intent ─┬─ analyze_risk / generate_report → enrich_cves → score_risks → generate_briefing → END
                                          ├─ apply_patches → enrich_cves → score_risks → build_patch_plan → generate_briefing → END
                                          ├─ check_updates → score_risks → generate_briefing → END
                                          ├─ status → fetch_task_status → generate_briefing → END
                                          └─ ask_question → handle_question → END
```

| Nodo | Qué hace | LLM |
|------|----------|-----|
| `load_inventory` | analiza `inventory/hosts.yml` (grupos anidados, valores `!vault`) y añade los informes de cada host | no |
| `classify_intent` | acción + destino + opciones; el destino se valida contra el inventario | sí, con alternativa por palabras clave |
| `enrich_cves` | KEV + NVD para los IDs de CVE que reportan los hosts; CVE críticos recientes por familia de SO como contexto | no |
| `score_risks` | puntuación de 0 a 100 por host (sección 19) | no |
| `build_patch_plan` | alcance + opciones + hosts agrupados por riesgo, registrado como plan pendiente | no |
| `fetch_task_status` | últimas tareas de Semaphore | no |
| `generate_briefing` | resumen en markdown | sí, con alternativa por plantilla |
| `handle_question` | preguntas y respuestas con el contexto del inventario | sí |

La ejecución no es un nodo. `POST /api/plans/{id}/approve` (o `/patch approve` en Slack) llama a Semaphore con los parámetros guardados en el plan.

Los destinos que propone el modelo se validan como expresiones `--limit` de Ansible contra el inventario (hosts y grupos conocidos, prefijos `!`/`&`, comodines `*`). Cualquier otra cosa se descarta con un aviso.

---

## 19. Análisis de riesgo y datos de CVE

### De dónde salen los datos

| Fuente | Qué aporta |
|--------|------------|
| `reports/hosts/<host>.json` (Check Updates) | actualizaciones pendientes, actualizaciones de seguridad, IDs de CVE (avisos de Rocky), reinicio pendiente, antigüedad del informe |
| `inventory/hosts.yml` | `patch_criticality: high/medium/low` por host |
| CISA KEV | si un CVE reportado se está explotando activamente |
| NIST NVD 2.0 | puntuación CVSS de cada ID de CVE reportado; CVE críticos recientes por familia de SO como contexto |

Los resultados de búsqueda por palabra clave en NVD **no** se asignan a los hosts: que un CVE mencione "Windows" no dice nada sobre si a una máquina concreta le falta el parche. Solo cuentan para la puntuación de un host los IDs de CVE que ese host ha reportado a través de los metadatos de sus propios paquetes.

NVD permite 5 peticiones cada 30 segundos sin clave y 50 con ella ([clave gratuita](https://nvd.nist.gov/developers/request-an-api-key)). Las consultas se cachean (24 h), se limitan en frecuencia, se acotan con `NVD_LOOKUP_LIMIT` y `NVD_LOOKUP_BUDGET_SECONDS`, y se hacen primero las que están en KEV.

### Puntuación

| Factor | Peso | Entrada |
|--------|------|---------|
| Actualizaciones de seguridad pendientes | 30 % | 20 puntos cada una, máximo 100 |
| Explotado activamente (KEV) | 25 % | 100 si algún CVE reportado está en KEV |
| CVSS más alto | 15 % | CVSS máximo × 10 |
| Criticidad | 15 % | high 100, medium 50, low 15 |
| Actualizaciones acumuladas | 10 % | 4 puntos por actualización pendiente, máximo 100 |
| Reinicio pendiente | 5 % | 100 si hay un reinicio pendiente |

Un CVE en KEV deja al host como mínimo en 80 (CRITICAL). Los hosts sin informe, o con un informe más antiguo que `REPORT_MAX_AGE_HOURS`, quedan marcados en sus factores de riesgo.

| Puntuación | Nivel |
|------------|-------|
| 80-100 | CRITICAL |
| 60-79 | HIGH |
| 40-59 | MEDIUM |
| 0-39 | LOW |

Un plan lista sus hosts agrupados en estos cuatro niveles.

---

## 20. Referencia de la API de IA

Todos los endpoints salvo `/api/health` y los webhooks requieren HTTP Basic o `Authorization: Bearer <APP_API_TOKEN>`. Las peticiones POST autenticadas con Basic tienen que enviar `X-Requested-With: patch-ai`.

| Método | Ruta | Para qué |
|--------|------|----------|
| POST | `/api/chat` | `{"message", "target_hosts", "options", "history"}` |
| POST | `/api/action/check-updates` | resumen de los últimos informes |
| POST | `/api/action/analyze-risk` | análisis de riesgo |
| POST | `/api/action/plan-patches` | preparar un plan (no se ejecuta nada hasta que se aprueba) |
| POST | `/api/action/run-check` | lanzar la plantilla Check Updates |
| GET | `/api/plans`, `/api/plans/{id}` | listar / ver planes |
| POST | `/api/plans/{id}/approve` | ejecutar el plan mediante Semaphore |
| POST | `/api/plans/{id}/reject` | rechazar |
| GET | `/api/tasks/{task_id}` | estado de una tarea de Semaphore |
| GET | `/api/inventory` | grupos y hosts |
| GET | `/api/info` | enrutado de modelos, integraciones |
| GET | `/api/health` | comprobación de vida, sin detalles |
| POST | `/api/integrations/slack`, `/api/integrations/teams` | webhooks (verificados por firma/HMAC) |

Los endpoints de acción aceptan `{"target_hosts": "ubuntu_servers", "security_only": true, "dry_run": false, "no_reboot": false}`.

```bash
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target_hosts":"production","security_only":true}' \
  https://patch-manager.example.com/ai/api/action/plan-patches
```

Swagger UI en `/docs` cuando `APP_ENABLE_DOCS=true` (requiere autenticación).

---

## 21. Recetas propias

Añade un playbook en `playbooks/` y una plantilla en Semaphore:

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

El comportamiento por grupo está en `inventory/group_vars/`. Para excluir los kernels en Rocky:

```yaml
# inventory/group_vars/rocky_servers.yml
patch_excluded_packages:
  - kernel*
```

En Ubuntu, `patch_excluded_packages` pone los paquetes en hold de dpkg (se deshace con `apt-mark unhold <paquete>`).

En los playbooks nuevos usa `ansible_facts['...']`; las antiguas variables de facts `ansible_*` inyectadas están obsoletas desde ansible-core 2.20 y este repositorio las desactiva en `ansible.cfg`.

---

## 22. Gestión del inventario

- Un solo fichero: `inventory/hosts.yml`. Variables de grupo: `inventory/group_vars/` (Ansible las carga porque están junto al fichero de inventario).
- Cada host gestionado va en uno y solo uno de `ubuntu_servers`, `rocky_servers`, `macos_servers`, `windows_servers` (directamente o a través de grupos hijos). Los grupos lógicos como `production` sirven para `--limit` y aparecen en la lista de destinos del panel.
- `patch_criticality: high | medium | low` por host alimenta la puntuación de riesgo.
- Secretos: `ansible-vault encrypt_string`. Los valores `!vault` en línea no dan problemas; el servicio de IA los ignora.

Para parques grandes o en la nube, usa un plugin de inventario dinámico en Semaphore. El servicio de IA lee el fichero YAML, así que mantén ahí al menos los grupos por SO, o apunta `INVENTORY_PATH` a una copia exportada (`ansible-inventory --list -y > inventory/export.yml`).

---

## 23. Ventanas de mantenimiento

```yaml
# inventory/group_vars/all.yml
maintenance_window_enabled: true
maintenance_window_start: "22:00"
maintenance_window_end: "04:00"
maintenance_window_days: [5, 6]   # 0=lunes ... 6=domingo
```

- Se evalúa con el reloj de la máquina que ejecuta Ansible (el contenedor o host de Semaphore), no con el de los hosts gestionados.
- Las ventanas que cruzan la medianoche funcionan: 22:00-04:00 el día 5 significa del sábado a las 22:00 al domingo a las 04:00.
- La comprobación no necesita conectarse a los hosts y se hace antes de cualquier cambio. Los hosts fuera de la ventana se excluyen de la ejecución.
- Para saltársela: `-e maintenance_window_enabled=false`.

---

## 24. Notas de seguridad

- **Autenticación del panel y la API**: HTTP Basic o token bearer, comparados en tiempo constante. Diez intentos fallidos desde una misma dirección en cinco minutos hacen que esa dirección reciba un 429 durante el resto de la ventana (freno dentro del proceso; añade restricciones de red en nginx si el panel es accesible desde redes que no controlas). El servicio no arranca sin `APP_AUTH_PASSWORD` (ni con una de ejemplo o demasiado corta). `APP_AUTH_DISABLED=true` existe solo para desarrollo local.
- **CSRF**: los POST del navegador tienen que llevar `X-Requested-With: patch-ai`, que un formulario de otro sitio no puede añadir.
- **Aprobación humana**: el agente solo puede crear planes. La ejecución usa los parámetros guardados en el plan, registra quién lo aprobó (logger `audit` de structlog) y el LLM no puede lanzarla.
- **Entrada hacia Ansible**: el límite va en el campo `limit` de Semaphore, las variables extra en `environment` como JSON, y el límite se valida contra el inventario. Nada de lo que escriban el usuario o el modelo se concatena en una línea de comandos.
- **Webhooks**: las firmas de Slack (con ventana anti-repetición) y el HMAC de Teams son obligatorios cuando la integración está activada; las integraciones desactivadas devuelven 404.
- **Endurecimiento en el navegador**: CSP estricta (`script-src 'self'`, sin manejadores en línea), `X-Frame-Options: DENY`, `nosniff` y `no-store` en las respuestas de la API. El renderizador de markdown escapa el HTML antes de dar formato.
- **Claves de host SSH**: `host_key_checking = True` con `StrictHostKeyChecking=accept-new`: el primer contacto se acepta y se recuerda, y una clave que cambia hace fallar la ejecución. Precarga `known_hosts` si quieres un control más estricto.
- **Secretos en disco**: `ai.env`, `.env` y `/etc/semaphore/config.json` tienen permisos 0600/0640. El contenedor de IA no recibe `config/` en absoluto.
- **Privacidad con el LLM**: los prompts contienen tu mensaje, nombres de host, grupos, versiones de SO, recuentos de actualizaciones e IDs de CVE. Ni IPs, ni listas de paquetes, ni credenciales, ni claves. Usa un modelo local si los nombres de host son sensibles, o usa OpenRouter con `data_collection: deny`.
- **Semaphore**: ponlo detrás del mismo proxy TLS, activa TOTP u OIDC/LDAP y guarda copia de la clave `SEMAPHORE_ACCESS_KEY_ENCRYPTION` (cifra el almacén de claves).

---

## 25. Resolución de problemas

**`patch-ai` no arranca: "Invalid configuration"**
El log indica el problema: `LLM_DEFAULT` vacía, `APP_AUTH_PASSWORD` débil, Slack activado sin signing secret.

**El panel dice "No recent update reports"**
Ejecuta la plantilla Check Updates. Comprueba que aparecen informes en `/var/lib/patch-manager/reports/hosts/` y que el servicio de IA puede leerlos (`REPORTS_PATH`). En Docker, los dos contenedores comparten el volumen `reports`; `volume-init` se lo asigna al uid 1001. Si el log de la tarea muestra "Permission denied" al escribir el informe, compáralo con `docker compose exec semaphore id -u` y ajusta el `chown` de `volume-init`.

**La aprobación falla con "SEMAPHORE_API_TOKEN is not set" / "Template ... not found"**
Define el token y comprueba que los nombres de las plantillas coinciden con `SEMAPHORE_TEMPLATE_APPLY` / `SEMAPHORE_TEMPLATE_CHECK`. Si tienes varios proyectos, define `SEMAPHORE_PROJECT_ID`.

**La aprobación falla con "does not allow overriding the limit"**
Activa la opción de sobrescribir el límite en la plantilla Apply Patches (sección 5). El servicio lo comprueba porque, si no, Semaphore ejecutaría el plan en todos los hosts.

**Variables como `patch_windows_categories` aparecen sin definir**
Semaphore está usando un inventario estático. Usa un inventario de tipo File que apunte a `inventory/hosts.yml` para que se cargue `inventory/group_vars/`.

**Errores del LLM / respuestas lentas**
`journalctl -u patch-ai` (nativo) o `docker logs patch-manager-ai`. Prueba `curl http://llm-host:8080/v1/models` desde el contenedor. La primera petición tras cambiar de modelo es lenta; sube `LLM_TIMEOUT`. Mientras tanto, el panel sigue funcionando con la salida alternativa.

**Los análisis tardan mucho**
Limitación de NVD sin clave de API (6 s por consulta). Añade `NVD_API_KEY` o baja `NVD_LOOKUP_LIMIT`. Los resultados se cachean 24 h.

**Host inalcanzable / la clave del host ha cambiado**
`ssh -i clave ansible@host`. Si la clave ha cambiado de verdad (reinstalación), borra la entrada antigua del `~/.ssh/known_hosts` del usuario semaphore.

**Windows: "winrm or requests is not installed"**
Docker: tiene que estar montado `docker/semaphore/requirements.txt`; nativo: `/opt/ansible-venv/bin/pip install pywinrm`.

**Rocky: nunca detecta que hace falta reiniciar**
Instala `dnf-plugins-core` (aporta `dnf needs-restarting`).

**macOS: aparecen actualizaciones del sistema pero nunca se instalan**
Apple silicon sin `patch_macos_update_user`/contraseña (sección 8).

**No se envía el correo**
`EMAIL_ENABLED=true`, variables SMTP visibles para el proceso de Ansible (Docker: `config/.env`; nativo: `/etc/semaphore/semaphore.env`) y `community.general` instalada.

**nginx devuelve 502**
El servicio de detrás aún no está listo o se ha caído: `docker compose logs semaphore patch-ai`, o `systemctl status semaphore patch-ai`.

**Salida detallada de Ansible**
`ansible-playbook ... -vvv`, o activa "debug" en el diálogo de ejecución de Semaphore.

---

## 26. Desarrollo y pruebas

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest                         # tests unitarios, del grafo y HTTP (LLM simulado, Semaphore/NVD/KEV simulados)
ruff check app tests
ansible-lint playbooks inventory
ansible-playbook --syntax-check playbooks/*.yml
```

Para ejecutar el servicio en local:

```bash
cp config/ai.env.example config/ai.env   # define APP_AUTH_PASSWORD y LLM_*
uvicorn app.main:app --reload --port 8501
```
