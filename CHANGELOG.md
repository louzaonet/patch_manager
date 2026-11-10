# Registro de cambios

## 1.0.0 (2026-11-09)

Primera versión pública.

### Automatización (Ansible + Semaphore UI)

- Playbooks para Ubuntu, Rocky Linux, macOS y Windows 10/11: `check_updates.yml` (detecta, no cambia nada), `apply_patches.yml` (instala y reinicia donde haga falta) y `reboot_if_needed.yml`.
- Modos: completo, solo seguridad (`--tags security_only` o `-e patch_security_only=true`), simulación (dry run), sin reinicio y por lotes dentro de cada grupo de SO (`-e patch_serial=25%`).
  - En Ubuntu, el modo seguridad instala exactamente los paquetes que llegan del pocket `-security`; si la lista está vacía, no instala nada.
  - Rocky usa los avisos de `updateinfo`; macOS lo traduce a `softwareupdate --recommended`; Windows usa su propia lista de categorías.
- Informes JSON por host en el controlador: `reports/hosts/<host>.json` (actualizaciones pendientes y de seguridad, IDs de CVE de los avisos de Rocky, reinicio pendiente) y `reports/patch-runs/<host>.json` (resultado de la última ejecución).
- Un host que falla durante el parcheo queda registrado como `FAILED` con la tarea que falló y su mensaje, aparece en el informe y en el correo, y la ejecución sigue marcándose como fallida.
- Ventana de mantenimiento opcional, evaluada con el reloj del controlador, incluidas las ventanas que cruzan la medianoche.
- Resúmenes HTML por correo tras las comprobaciones y los parcheos (hay que activarlos).
- Los informes y el correo también se generan cuando se usa `--limit`.
- Política por grupo en `inventory/group_vars/`; `patch_criticality` por host.
- Requiere ansible-core 2.20+, ansible.windows 3+, community.general 12+ y ansible.posix 2+. Los facts se leen mediante `ansible_facts[...]`.

### Servicio de IA (FastAPI + LangGraph)

- Panel y API bajo `/ai/`: actualizaciones pendientes, análisis de riesgo, planes de parcheo, chat libre y estado de las tareas de Semaphore.
- **Parchear requiere aprobación humana.** El agente solo prepara planes. Un plan se ejecuta mediante la API de Semaphore después de que alguien lo apruebe (desde el panel, con un token de API o un usuario de Slack autorizado), con los parámetros guardados en el plan. Los planes caducan a los 30 minutos.
- Puntuación de riesgo calculada con datos reportados: actualizaciones de seguridad pendientes, presencia en el catálogo KEV de CISA y CVSS (NVD) de los CVE que reporta cada host, criticidad en el inventario, acumulación de actualizaciones y reinicio pendiente. Los CVE críticos recientes de cada familia de SO se muestran solo como contexto.
- El acceso a NVD está cacheado, limitado a las tasas publicadas, acotado por un presupuesto de tiempo y protegido por un cortocircuito (circuit breaker).
- Proveedores de LLM: OpenRouter, cualquier servidor compatible con OpenAI (llama-swap, llama.cpp, vLLM), Ollama, OpenAI y Anthropic, configurables por nodo. La configuración de ejemplo usa Claude Haiku 5.5 a través de OpenRouter.
- Funciona sin el modelo: si el LLM no responde, entran en juego la detección de intención por palabras clave y un resumen generado con plantilla.
- Comando de barra de Slack (`/patch ...`, `/patch approve <id>`) y Microsoft Teams (webhook de Workflows para notificaciones y webhook saliente opcional para peticiones).

### Seguridad

- Autenticación HTTP Basic o por token bearer en todo salvo el health check y los webhooks firmados; el servicio no arranca sin una contraseña adecuada. Los intentos de acceso fallidos se frenan por dirección de cliente.
- Comprobación de cabecera anti-CSRF en las peticiones del navegador, Content-Security-Policy estricta y sin scripts en línea.
- Las firmas de Slack (con ventana anti-repetición) y el HMAC de Teams son obligatorios cuando esas integraciones están activadas.
- Los límites de hosts que vienen del usuario o del modelo se validan contra el inventario y se envían a Semaphore en un campo aparte. El servicio rechaza una ejecución limitada sobre una plantilla de Semaphore que no permita sobrescribir el límite, porque Semaphore la lanzaría contra todos los hosts (comprobado con Semaphore 2.19.12).
- Los prompts llevan nombres de host, versiones de SO, recuentos e IDs de CVE; nada de direcciones IP, listas de paquetes ni credenciales. Las cadenas que se originan en los hosts gestionados se acotan antes de llegar a un prompt.
- Claves de host SSH: se confía en el primer uso y se rechazan las claves que cambian. WinRM por HTTPS con la autenticación Basic desactivada.
- Contenedores: el servicio de IA se ejecuta sin privilegios, en solo lectura, sin capabilities y sin acceso a los secretos de Semaphore.

### Despliegue

- LXD: `deploy/lxd/create-container.sh` crea el contenedor y ejecuta `deploy/native/install.sh` (Semaphore con SQLite, servicio de IA y nginx con TLS como unidades de systemd). También hay un modo con Docker dentro de LXD.
- Stack de Docker Compose: nginx 1.30, Semaphore 2.19.12, PostgreSQL 18 y el servicio de IA sobre Python 3.13.

### Pruebas

- 59 tests automáticos (LLM simulado; Semaphore, NVD y KEV simulados), ruff, ansible-lint (perfil production) y shellcheck.
- Prueba de punta a punta contra un Semaphore 2.19.12 real y un host Ubuntu 24.04: comprobación, análisis, plan, aprobación, tarea de Semaphore e informes, incluida una instalación real solo de seguridad y un fallo forzado.
- Aún sin probar en hardware real: hosts Rocky Linux, macOS y Windows (el análisis de su salida está probado con salidas de ejemplo), los scripts de LXD y las imágenes de Docker.
