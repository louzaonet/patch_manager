# Registro de cambios

## 1.0.3 (2026-11-22)

### Novedades

- Informe programado por correo: el servicio de IA hace el análisis de riesgo con su propio cron (`AUTO_ANALYSIS_CRON`, `AUTO_ANALYSIS_TZ`) y envía por SMTP una tabla con todos los hosts y el resumen de la IA. El asunto avisa de CVE en KEV, de hosts que no respondieron a la última comprobación y de informes sin refrescar. Se puede lanzar a mano con el botón **Email report now** o con `POST /api/action/email-report`, y `/api/info` muestra la próxima ejecución y el resultado de la última. Variables nuevas en `ai.env`: `AUTO_ANALYSIS_*`, `SMTP_*`, `EMAIL_FROM`, `EMAIL_TO`, `EMAIL_SUBJECT_PREFIX`. Sin dependencias nuevas: el cron lo interpreta el propio servicio.
- Panel: el resumen de riesgo es ahora una fila de tarjetas que se desplaza en horizontal, con recuento por nivel, plegable y con el detalle de un host al tocar su tarjeta. Con unos 20 hosts la rejilla anterior empujaba el cuadro de texto fuera de la pantalla. El panel muestra todos los hosts del alcance, hasta 200 (antes, como mucho 24 tarjetas).
- Panel: las tablas markdown de las respuestas de la IA se muestran como tablas; antes salían en una sola línea.
- Inventario: `patch_reboot_blocked: true` impide que cualquier playbook reinicie ese host, diga lo que diga `patch_reboot_allowed`. Pensado para hosts LXD o de máquinas virtuales y para el host que ejecuta Semaphore.
- `install.sh` enlaza `ansible`, `ansible-playbook` y el resto de comandos de `/opt/ansible-venv/bin` en `/usr/local/bin`.

### Seguridad

- Planes aprobados: enviaban siempre `patch_reboot_allowed=true` como variable extra, que gana a cualquier valor del inventario, así que un grupo con `patch_reboot_allowed: false` en `group_vars` se reiniciaba igual. Ahora solo se envía cuando es `false` ("Prevent reboots"), y el veto `patch_reboot_blocked` se respeta en todos los casos.
- Plantillas de Semaphore: si no había una con el nombre exacto, se usaba la única cuyo nombre lo contuviera, de modo que "Apply Patches (old)" podía recibir los planes aprobados. Ahora solo vale el nombre exacto (sin distinguir mayúsculas) y dos plantillas con el mismo nombre dan un error.
- `install.sh` comprueba el SHA-256 del `.deb` de Semaphore antes de instalarlo: contra valores fijados en el script para la versión por defecto, o contra el fichero de checksums de la release si se elige otra versión. Se descarga en un directorio temporal propio en vez de en una ruta fija de `/tmp`.

### Correcciones

- nginx (nativo y Docker): pasaba a Semaphore `Host $host`, que quita el puerto. Detrás de un puerto distinto del 443, como el dispositivo proxy de LXD, Semaphore rechazaba cualquier cambio con "cross-origin request blocked". Ahora usa `$http_host`.
- `apply_patches.yml`: la casilla **Dry Run** de Semaphore (`--check`) no se trataba como simulación. Las tareas de instalación salían como `changed` sin instalar nada, el listado previo no se ejecutaba y no quedaba informe de la ejecución. Ahora `--check` equivale a `patch_dry_run=true`: lista lo pendiente, no instala ni reinicia y deja el informe como `DRY-RUN`.
- `check_updates.yml` con `--check` terminaba en verde sin escribir ningún informe. Como solo lee los hosts, ahora ignora el modo check. `reboot_if_needed.yml` también lee `dnf needs-restarting` en modo check.
- Resumen de la IA: el prompt mandaba "Semaphore tasks: n/a", "patch plan: none" y "CVE: none" aunque no vinieran al caso, y el modelo los presentaba como datos que faltan en cada análisis. Esas secciones solo se envían cuando aplican, el prompt explica que en Ubuntu, macOS y Windows es normal no tener IDs de CVE, y que no debe dudar de versiones de SO que no conozca (Ubuntu 26.04).
- Sin LLM, la detección por palabras clave convertía preguntas como "list pending patches" o "which hosts have pending patches?" en una petición de parcheo (que creaba un plan). Las preguntas de consulta se reconocen ahora antes.
- `setup_winrm.ps1` creaba un certificado nuevo en cada ejecución y dejaba los anteriores en el almacén. Ahora reutiliza el suyo si le quedan más de 30 días, borra los que creó antes y lista, sin borrarlos, los autofirmados que pudieran quedar de versiones anteriores.
- `create-container.sh` y la wiki proponían el puerto 8443 del host para el dispositivo proxy, que es el de la API de LXD. Ahora proponen el 9443 y explican que, si el contenedor tiene IP propia en la LAN, no hace falta.
- Wiki: macvlan (el host LXD y sus contenedores no se ven), cómo actualizar sin perder el inventario, la casilla **Limit** de Semaphore, la precedencia de `group_vars/all.yml` sobre las variables de grupo de `hosts.yml`, y nuevas entradas de resolución de problemas.

### Pruebas

- 142 tests automáticos (56 nuevos), ruff, shellcheck, ansible-lint (perfil production), `ansible-playbook --syntax-check`, `nginx -t` de los dos sitios y `node --check` del JavaScript del panel.
- `apply_patches.yml` y `check_updates.yml` ejecutados con `--check` contra un Ubuntu 24.04 local: no se instala nada, el informe de la ejecución queda como `DRY-RUN` con las actualizaciones pendientes, y el de comprobación se escribe. Con los ficheros de la 1.0.2, las dos ejecuciones terminan sin escribir informe.
- El veto de reinicio, evaluado con `ansible-playbook` en seis combinaciones (sin variables, `patch_reboot_allowed=true/false`, `--check`, `patch_dry_run=true`, `patch_reboot_blocked=false`); `reboot_if_needed.yml` con `--check` salta el host bloqueado.
- nginx 1.24 delante de un servidor que devuelve la cabecera recibida: con la 1.0.3 llega `Host: 10.40.50.230:9443`; con la 1.0.2, sin el puerto.
- Correo: envío real a un servidor SMTP local (aiosmtpd, sin TLS) con un inventario de 19 hosts; el mensaje llega con las partes de texto y HTML, y el HTML se ha revisado en un navegador. Los modos `starttls`, `always`, `try` y el login se han probado con un cliente SMTP simulado, no contra un servidor real con TLS.
- Panel: Chrome sin interfaz (Playwright) con 19 hosts a 1158×798 y 820×1100: el cuadro de texto queda a la vista, las flechas desplazan la fila, el plegado funciona y las tablas se pintan. No probado en un iPad real.
- La comprobación del checksum de `install.sh`, probada aparte con los `.deb` reales de Semaphore 2.19.12 (amd64 y arm64) y con un fichero que no corresponde.
- Sin probar: `setup_winrm.ps1` (no hay PowerShell aquí), una ejecución completa de `install.sh`, la configuración macvlan de la wiki tras un reinicio del host, y hosts reales Rocky, macOS y Windows.

## 1.0.2 (2026-11-15)

### Seguridad

- Instalación nativa: el arreglo de `X-Forwarded-For` de la 1.0.1 solo cubría Docker. Cuando las conexiones llegan a nginx desde 127.0.0.1 (el dispositivo proxy de LXD que describe la wiki), uvicorn se fiaba de nginx y tomaba la dirección que el cliente había puesto en la cabecera, así que el límite de intentos de login fallidos se evitaba igual. nginx manda ahora solo la dirección que ve. Detrás del dispositivo proxy todos los clientes comparten dirección y, por tanto, el mismo límite; el sitio de nginx trae comentados los ajustes para conservar las direcciones reales con `proxy_protocol`.
- Planes de parcheo: un destino que no pasaba la validación (una errata en el nombre de un host, un grupo que no existe) se descartaba y el plan se preparaba para todos los hosts. Ahora no se crea ningún plan. Las acciones de solo lectura siguen usando todos los hosts con un aviso.
- Planes de parcheo: tampoco se crea un plan cuando el servicio no ve ningún host en el alcance (inventario vacío o ilegible). Ese plan no llevaba límite y, al aprobarlo, Semaphore lo habría ejecutado en todos los hosts.
- Validación de límites: los comodines se comprobaban con una expresión regular hecha a mano que retrocede de forma exponencial. Un destino con muchos `*` dejaba el servicio bloqueado (medido: 0,2 s con 10 comodines, 6 s con 18). Ahora se usa `fnmatch`, como Ansible. Hacía falta estar autenticado.
- Webhooks de Slack y Teams: una cabecera de firma con caracteres no ASCII provocaba una excepción y un 500 en lugar de un 401. No permitía saltarse la firma.
- `create-container.sh`: los ficheros de contraseña de Vault y las claves privadas que haya en el directorio de trabajo ya no se copian al contenedor (`install.sh` deja esa copia legible para todos los usuarios).

### Correcciones

- Planes: la lista de hosts de un plan se calculaba aplicando el límite de izquierda a derecha. Ansible une primero los patrones normales, luego aplica las intersecciones (`&`) y al final las exclusiones (`!`), así que con límites como `a,&b,c` el plan mostraba hosts que Ansible no iba a tocar. Ahora coincide con `ansible --list-hosts`.
- Rocky: `dnf needs-restarting -r` devuelve 1 cuando hace falta reiniciar, pero dnf también devuelve 1 ante cualquier error, por ejemplo si falta el plugin (`dnf-plugins-core`). Ese error se leía como "reinicio pendiente" y `apply_patches.yml` reiniciaba el host. Ahora se comprueba además el mensaje de salida.
- `ansible.cfg`: con `gathering = smart` y caché de facts, una ejecución dentro de la hora siguiente reutilizaba facts antiguos. `reboot_if_needed.yml` no veía en Windows los reinicios pendientes desde el último parcheo y los informes podían llevar la versión de SO anterior. Los facts se recogen ahora en cada ejecución y no se cachean.
- `setup_macos_ssh.sh`: ejecutado con `sudo` y sin argumentos configuraba al usuario root en vez de al que llamaba a sudo; el fichero de sudoers de un usuario con punto en el nombre lo ignoraba sudo; el fichero se instalaba antes de validarlo; y el paso final podía abortar el script (`head` con `pipefail`). El directorio personal ya no se obtiene con `eval`.
- `setup_winrm.ps1`: exige una consola de administrador y se detiene en el primer error. Antes, si fallaba la creación del certificado o del listener, terminaba diciendo que todo había ido bien.
- Un inventario con YAML válido pero con forma incorrecta (hosts como lista, `vars` como texto) provocaba un 500 en todas las peticiones. Ahora se registra el error y se trata como inventario vacío. Lo mismo con un catálogo KEV con formato inesperado y con un cuerpo de Slack que no sea UTF-8 válido.
- Slack: el texto del comando se recorta a 4.000 caracteres, como en Teams.
- `.gitignore` y `.ansible-lint` no estaban en el repositorio; vuelven a estar.

### Pruebas

- 86 tests automáticos, ruff, shellcheck, ansible-lint (perfil production) y `ansible-playbook --syntax-check`.
- El sitio nativo de nginx, probado con nginx 1.24 delante del servicio: con el fichero anterior, 12 logins fallidos cambiando `X-Forwarded-For` no llegaban al bloqueo; con el nuevo, el undécimo recibe un 429.
- El play de comprobación de Rocky, ejecutado contra un `dnf` simulado con salidas de ejemplo (reinicio pendiente, sin reinicio, plugin ausente, error).
- Sin probar: hosts reales Rocky, macOS y Windows; los scripts de macOS y PowerShell no se han ejecutado; los scripts de LXD y las imágenes de Docker; `proxy_protocol` con un dispositivo LXD real (solo se ha validado la sintaxis de nginx).

## 1.0.1 (2026-11-10)

### Seguridad

- Webhook de Teams: las expresiones regulares que quitan menciones y etiquetas HTML tardaban un tiempo cuadrático con entradas como `<<<<...` o `<at><at>...` (unos 5 s con 80.000 caracteres) y bloqueaban el servicio mientras tanto. Ahora son lineales y el HTML se recorta a 20.000 caracteres antes de procesarlo. Hacía falta un HMAC válido de Teams para explotarlo. Cierra las alertas de CodeQL `py/polynomial-redos` #1 y #2.
- Docker: nginx pasaba al servicio de IA la cabecera `X-Forwarded-For` que mandaba el cliente y uvicorn, con `--forwarded-allow-ips "*"`, usaba la primera dirección de esa cabecera. Cambiando la cabecera en cada intento se evitaba el límite de intentos de login fallidos. Ahora nginx manda solo la dirección real del cliente. La instalación nativa no estaba afectada.

### Correcciones

- `install.sh`: en la primera instalación el `umask 077` usado para guardar la contraseña de Semaphore se aplicaba al resto del script, el venv del servicio de IA quedaba como 0700 de root y el usuario `patchai` no podía arrancarlo. Una segunda ejecución lo arreglaba. El `umask` va ahora en un subshell.
- Teams: el texto del mensaje llegaba al agente con entidades HTML sin decodificar (`&nbsp;`, `&amp;`), lo que podía impedir reconocer nombres de host y el aviso de que los planes no se aprueban desde Teams. Ahora se decodifican y los espacios se normalizan.

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
