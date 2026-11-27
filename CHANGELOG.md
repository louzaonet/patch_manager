# Registro de cambios

## 1.4.1 (2026-11-27)

Correcciones de una revisión externa de seguridad y robustez, más un fallo visto en la primera actualización real de ISPConfig.

### Seguridad

- ISPConfig: un valor de `ispconfig_update_answers` con `;`, `#`, comillas, `=`, corchetes o espacios al principio o al final se rechaza. `;` y `#` empiezan un comentario en el fichero de respuestas: la respuesta se cortaba y `update.php` podía volver a preguntar. El fichero ya no se escribe en la salida de la tarea, que Semaphore guarda, por si alguna respuesta lleva una contraseña.
- ISPConfig: `ispconfig_sha256` (versión → sha256) comprueba el tar.gz descargado, y `ispconfig_require_sha256: true` no instala una versión sin suma. No hemos encontrado sumas publicadas por ISPConfig: las fijas tú.
- Correo: con `SMTP_SECURE=try` y usuario, si el servidor no ofrece STARTTLS (o alguien en medio quita la oferta) ya no se inicia sesión en claro y el envío falla. Lo mismo en los correos de los playbooks. Solo `never` manda la contraseña en claro. El servicio avisa al arrancar de `try` con usuario.
- Docker: patch-ai solo acepta `X-Forwarded-For` de la dirección fija de nginx (`PATCH_PROXY_IP`, subred fija `PATCH_NET_SUBNET`, por defecto 172.31.250.10 y 172.31.250.0/24). Antes confiaba en cualquier contenedor de `patch-net`, que podía elegir su dirección y esquivar el freno de intentos fallidos. Hay que recrear la red: `docker compose down && docker compose up -d`.
- Informes: los directorios se crean 2750 y los ficheros 0640 (`patch_report_dir_mode`, `patch_report_file_mode`). En la instalación nativa son del grupo `patchreports` por el setgid del directorio; `install.sh` corrige permisos y grupo de lo que dejaron versiones anteriores. En Docker siguen en 0755/0644, porque patch-ai corre con otro uid.
- Aprobación de planes: el límite se vuelve a resolver contra el inventario al aprobar, y si ahora abarca hosts que el plan no listaba, el plan se rechaza.
- Slack y Teams: `SLACK_USER_IDS` y `TEAMS_USER_IDS` (Object ID de Entra ID) limitan quién puede usar el bot, no solo quién aprueba. Vacíos, todo sigue como antes.
- Manifiestos: un `pattern` de más de 200 caracteres, o con un grupo con cuantificador repetido sin límite (`(a+)+`), se rechaza al cargar, porque puede bloquear el servicio.
- WinRM: el inventario de ejemplo valida el certificado del listener (`validate` y `ansible_winrm_ca_trust_path`). `setup_winrm.ps1` acepta `-DnsNames`, hace el certificado para esos nombres y lo exporta a `C:\ProgramData\patch-manager\winrm-<EQUIPO>.pem`.
- Lock del planificador: se abre con `O_NOFOLLOW` y tiene que ser un fichero normal del usuario del servicio. En la instalación nativa va en `/run/patch-ai` (`RuntimeDirectory=`).

### Correcciones

- ISPConfig Update comprueba también las unidades de systemd que fallan después de la actualización, como ya hacía Release Upgrade. Una caída de Postfix o Dovecot pasaba como correcta.
- ISPConfig Update y Release Upgrade: si algo falla en las comprobaciones posteriores, esperan `post_recheck_delay` segundos (60) y vuelven a mirar antes de restaurar la snapshot. Un servicio que tardaba en arrancar provocaba una restauración completa.
- ISPConfig Update y Release Upgrade: el final de la salida de `update.php` y del log de `do-release-upgrade` se guarda como lista de líneas (`output_tail`, `ispconfig_output_tail`, `upgrader_log_tail`). Antes un `\n` quedaba escrito como texto, el recorte a 40 líneas no funcionaba y se guardaba la salida entera. Los mensajes de error toman de verdad la última línea de la salida de errores.
- Ubuntu, solo seguridad: las actualizaciones de seguridad salen de una actualización simulada con el pocket `-security` preferido (`apt-get -s -t <versión>-security dist-upgrade`) y se instalan con esa preferencia. Antes se miraba el pocket del candidato en `apt list`: una corrección en `-security` se perdía si `-updates` tenía una versión más nueva, y se podía instalar esa versión más nueva que no es de seguridad. Check Updates cuenta igual.
- Ubuntu: los holds de `patch_excluded_packages` se apuntan en `/var/lib/patch-manager/held-packages` del host, y un paquete que sale de la lista se libera en la siguiente ejecución. Antes quedaban en hold para siempre. Los holds puestos a mano no se tocan; los de versiones anteriores hay que quitarlos una vez con `apt-mark unhold`.
- Docker Update borra solo las imágenes que ha sustituido, no todas las huérfanas del host.
- Inventario: un grupo que se contiene a sí mismo mediante anchors de YAML hacía fallar todas las peticiones con `RecursionError`. Ahora se recorre una vez y se avisa en el log.
- Informes con fecha en el futuro: contaban como recientes para siempre y hacían que el resto de hosts saliera en el correo como "missed the last check". Más de 15 minutos en el futuro cuenta como fecha no válida.
- OVAL: una cabecera `Last-Modified` malformada hacía fallar el paso entero, y todos los hosts salían con `cve_error`. Una salida que empezaba por `{` pero no era JSON válido hacía fallar el informe de todos los hosts.
- Esperas de las peticiones (capacidades con `wait`, consultas de paquetes en vivo): como mucho `REQUEST_WAIT_MAX` segundos (270), por debajo del corte de 300 s de nginx. Antes un manifiesto con `timeout: 3600` acababa en un 504 con la tarea en marcha.
- Sin LLM, la intención por palabras clave entiende también español ("actualiza Bluma", "¿qué actualizaciones hay pendientes?", "solo seguridad", "sin reiniciar"), y un verbo negado ("no actualices, solo dime el riesgo", "don't install") ya no se toma como petición de parchear.

### Cambios

- Dependencias: `requirements.lock` con las versiones exactas con las que pasan los tests (Python 3.12 y 3.13) y el hash de cada fichero. `install.sh` y el Dockerfile instalan desde él con `--require-hashes`; si no sirve para el Python del sistema, `install.sh` avisa y usa `requirements.txt`.
- macOS: documentado que el recuento de actualizaciones de seguridad es el de las recomendadas, una aproximación.

### Notas

- Los avisos `PHP Warning: Undefined array key "install"` (también `"ssl_cert"` y `"expert"`) que da `update.php` con un fichero de respuestas que solo tiene `[update]` son normales: el propio `update.php` crea esas secciones vacías en la línea siguiente.
- Sin cambios, por ser de bajo impacto: el cliente HTTP se sigue creando en cada petición, y los datos que envían los hosts siguen llegando al prompt (tratados como datos, escapados en el panel y el correo, y sin que nada se ejecute a partir de lo que escriba el modelo).

### Pruebas

- 42 tests nuevos (337 en total), que pasan con Python 3.13 y, con las versiones del lock, con Python 3.12.
- En el entorno de pruebas, con ISPConfig, `lxc` y `systemctl` simulados: suma correcta, suma incorrecta y suma obligatoria que falta; una unidad que falla y sigue fallando (se restaura), una que falla unos segundos (no se restaura) y una que ya fallaba antes (no cuenta); ficheros de informe en 2750/0640.
- Check Updates con una salida OVAL que no es JSON válido (todos los informes se escriben, con `cve_error`) y la detección de actualizaciones de seguridad, que da los mismos paquetes que antes cuando no hay diferencias entre pockets. Holds de `apply_patches.yml`: se ponen, se liberan al salir de la lista y los manuales se quedan.

## 1.4.0 (2026-11-27)

### Novedades

- ISPConfig: `playbooks/ispconfig_check.yml` compara la versión instalada con la que publica ISPConfig (el mismo fichero que lee su actualizador) y deja `reports/ispconfig-checks/<host>.json`. No cambia nada. Su capacidad, `ispconfig_check`, entra en el análisis programado.
- ISPConfig: `playbooks/ispconfig_update.yml` actualiza los hosts de `ispconfig_servers` de uno en uno y se para en el primero que falle. Lee el estado de la pila web (servicios, php-fpm, panel y cada web de `sites-enabled`, pedida a 127.0.0.1 siguiendo las redirecciones), descarga la versión y prepara el fichero de respuestas sin cambiar nada, y solo entonces hace una snapshot LXD. Después ejecuta `update.php --autoinstall` con un tiempo máximo, comprueba la versión y que todo lo que respondía siga respondiendo, y si algo falla vuelve a la snapshot. Las respuestas por defecto son las del actualizador interactivo cuando se acepta todo, reconfigurar servicios incluido. El fichero de respuestas se genera en el host a partir del ejemplo que trae el tar.gz de esa versión (`playbooks/files/ispconfig_autoupdate.py`), con las mismas claves y la misma forma de cada sí/no, porque una clave que falta o un `n` donde se espera `no` deja a `update.php` esperando para siempre. La contraseña de MariaDB va como `default` y la lee el propio `update.php` en el host. Para cambiar alguna respuesta basta con poner esa clave en `ispconfig_update_answers` en el inventario. `ispconfig_force=true` reinstala la misma versión. Capacidad `ispconfig_update`, con aprobación.
- Ubuntu: Check Updates guarda en cada informe la versión a la que `do-release-upgrade` ofrece ir (`release_upgrade_to`, p. ej. "26.04.1 LTS"), o `release_check_error` si no se pudo saber. No puntúa. La IA lo menciona y el correo y el panel lo ponen en las notas. Se desactiva con `patch_release_check: false`.
- Ubuntu: `playbooks/release_upgrade.yml` hace el salto, un host y una versión por ejecución. Pone al día la versión actual, anota las unidades que ya fallaban y el estado de la pila web, hace la snapshot y ejecuta `do-release-upgrade -f DistUpgradeViewNonInteractive` con un tiempo máximo. Luego reinicia, comprueba la versión, reinstala ISPConfig en los hosts que lo tienen y comprueba que no falla nada nuevo. Si algo falla, guarda el final del log del actualizador y vuelve a la snapshot. Los repositorios de terceros que desactiva el actualizador en esa ejecución salen en el informe y no se reactivan. Por defecto rechaza los hosts con `patch_reboot_blocked`, los de `ispconfig_servers` y los que no tienen snapshot posible, las versiones que no son LTS y las ejecuciones con más de un host, para que un plan aprobado para un grupo entero no los actualice todos seguidos (`patch_release_upgrade_many: true` lo permite). Capacidad `release_upgrade`, con aprobación.
- Snapshots LXD (`playbooks/tasks/lxd_snapshot.yml`, `lxd_restore.yml`, `lxd_snapshot_prune.yml`): el inventario dice en qué host LXD corre cada contenedor (`lxd_host`) y, si no coincide, su nombre en LXD (`lxd_instance`). Tras una ejecución correcta se borran las snapshots anteriores del mismo tipo y se queda la última.

### Cambios

- Prompt: los CVE sin corrección no tienen parche, y el modelo ya no debe recomendar parchearlos. La explicación de la nota de riesgo aclara que un KEV sin corrección no puntúa.

### Pruebas

- 35 tests nuevos (295 en total): orden de versiones de ISPConfig, fichero de respuestas a partir del ejemplo real de la 3.3.3p2, claves y formas rechazadas, permisos del fichero, respuestas de los dos playbooks, manifiestos, lectura de `release_upgrade_to`, prompt, correo y la comparación del estado de la pila web ejecutada con Ansible.
- ISPConfig Check y Update contra un ISPConfig simulado servido en local: actualización, versión ya al día, `ispconfig_force`, `--check`, una respuesta cambiada desde el inventario, una clave que no existe y una descarga que falla (las dos sin snapshot ni restauración), fallo de `update.php` y un `update.php` que se queda esperando, cortado al llegar al tiempo máximo y con el directorio temporal borrado. Con un `lxc` simulado: snapshot, borrado de las anteriores del mismo tipo (las demás se quedan) y, al fallar, parada, restauración y arranque.
- Detección de versión en Check Updates contra una lista de versiones de Ubuntu servida en local: versión ofrecida, ninguna y sin red. `release_upgrade.yml` en modo `--check`: los bloqueos, versión no LTS, ninguna ofrecida y sin red; y con dos hosts sin `--check`, rechazada antes de cambiar nada. La búsqueda de repositorios desactivados, contra ficheros `.list` y `.sources` de prueba. ansible-lint (perfil production).

## 1.3.2 (2026-11-27)

### Correcciones

- El factor de riesgo de los CVE solo con Ubuntu Pro lleva "(not scored)" cuando ninguno está en KEV, y el prompt explica de dónde sale la nota y que esos factores son solo contexto. El resumen decía que el riesgo venía de los CVE solo con Pro, cuando lo que separaba unos hosts de otros era la criticidad del inventario.
- Prompt: en un host Ubuntu sin actualizaciones de seguridad pendientes, una lista de CVE vacía es lo normal, y los identificadores de los CVE solo con Pro están en el informe de cada host (`cves_pro_only`). El modelo presentaba las dos cosas como datos que faltaban.

### Pruebas

- 1 test nuevo (260 en total) con un host de criticidad alta sin nada pendiente y 107 CVE solo con Pro.

## 1.3.1 (2026-11-26)

### Correcciones

- Prompt del informe: el recuento de CVE sin corrección de cada host lleva siempre `critical` y `high`, aunque sean 0. Antes los ceros se quitaban, y con hosts que solo tenían prioridades media y baja el modelo no podía decir que no había ninguno crítico ni alto.
- El prompt explica qué es `unfixed` siempre que hay recuentos (prioridad de Canonical, paquetes instalados sin versión corregida, kernel fuera) y que los identificadores están en el informe de cada host, no en el prompt. Antes esa explicación solo iba cuando había algún KEV, crítico o alto, y el modelo pedía "obtener la lista de CVE" como si faltara un dato. Si ningún host tiene críticos ni altos, el prompt lo dice; si los hay, nombra los hosts.

### Pruebas

- 1 test nuevo (259 en total) con un host que solo tiene CVE sin corrección de prioridad media, baja y negligible, y el mismo host con uno crítico.

## 1.3.0 (2026-11-26)

### Novedades

- Ubuntu: los informes de Check Updates traen los CVE que corrigen las actualizaciones pendientes. El controlador cruza la lista de paquetes instalados de cada host y el kernel que está corriendo con el OVAL USN de Canonical de su versión (`playbooks/files/ubuntu_oval_cves.py`, solo biblioteca estándar). No toca los hosts ni instala nada en ellos, y solo usa la lista de paquetes de la misma ejecución. El fichero de cada versión se descarga solo si ha cambiado (`If-Modified-Since`) y se guarda compilado en `reports/oval-cache`. Si la descarga falla se usa la copia guardada y el informe lo dice (`cve_data_warning`); si no hay copia, el informe lleva `cve_error` y Check Updates termina igual. Variables nuevas, opcionales: `patch_ubuntu_cves`, `patch_oval_url_base` y `patch_oval_cache_dir`. El controlador necesita salida HTTPS a `security-metadata.canonical.com`.
- Kernel: cuenta el que está corriendo, no el instalado, así que un kernel corregido pendiente de reinicio sigue sumando sus CVE. Solo se mira en hosts que tienen instalado el `linux-image` de ese kernel: un contenedor LXD ve el kernel de su host en `uname` y esos CVE son del host LXD. Si la versión de Ubuntu no reconoce el kernel que corre (una serie anterior que quedó instalada), el informe lo marca en lugar de darlo por limpio.
- Ubuntu Pro: los CVE que solo corrige Ubuntu Pro (versiones `esm`) van aparte, en `cves_pro_only`. No suben la nota salvo que alguno esté en KEV, y entonces cuentan como cualquier KEV.
- CVE sin corrección: con `patch_ubuntu_unfixed_cves` (activado por defecto) también se lee el OVAL CVE, de 5 a 14 MB por versión, y se listan los CVE de paquetes instalados que aún no tienen versión corregida. El kernel se deja fuera: sus CVE sin corrección son cientos por variante (153 críticos y altos en el `linux-raspi` de 26.04 en las pruebas) y saldrían en todos los informes. Se guardan el recuento por prioridad, los críticos y altos con su paquete, y todos los identificadores para cruzarlos con KEV. No entran en la nota de riesgo, porque parchear no los quita. El análisis los pone en una sección propia, los que están en KEV primero, y el correo y el panel los muestran en las notas de cada host.
- Gravedad: cuando NVD no tiene nota de un CVE de Ubuntu (por `NVD_LOOKUP_LIMIT` o porque no la ha publicado), se usa la nota más baja del tramo de CVSS que corresponde a la prioridad de Canonical: crítica 9.0, alta 7.0, media 4.0. El factor lo dice ("High-priority Ubuntu CVE pending"). Las consultas a NVD se hacen primero para los KEV y después por prioridad de Canonical.
- `security_without_notice`: actualizaciones de seguridad pendientes que ningún aviso explica, porque salieron después de que Canonical generara el OVAL o porque no corrigen ningún CVE (tzdata, paquetes `-dev`). El modelo tiene instrucciones de no tratarlas como un error de datos.
- Correo y panel: número de CVE pendientes y de CVE solo con Pro por host, KEV sin corrección y recuento de CVE críticos y altos sin corrección. El asunto avisa también de KEV en CVE solo con Pro o sin corrección.

### Cambios

- El prompt del informe ya no dice que en Ubuntu no hay CVE. Explica de dónde salen, qué es `score_source: "ubuntu"` y que en macOS y Windows una lista vacía sigue siendo lo normal. Los CVE sin corrección van sin nombres de paquete: los prompts siguen sin llevar listas de paquetes.
- Los informes de Ubuntu llevan además `os_codename` y `kernel`.

### Pruebas

- 47 tests nuevos (258 en total): la comparación de versiones contra resultados de `dpkg --compare-versions`, un OVAL de prueba con paquetes, kernel, Pro y livepatch, contenedores, lista de paquetes de otra ejecución, descarga, caché, 304, índice que hay que recompilar, límite de tamaño y fallo de red con un servidor local, lectura de los informes, puntuación, prompt y correo.
- Con los OVAL reales de jammy, noble y resolute del 26 de noviembre y las listas de paquetes de cuatro hosts: 3.351 comparaciones de versiones idénticas a las de `dpkg`. En un equipo x86, compilar el OVAL USN tarda de 0,7 a 2,1 s, con menos de 60 MB de memoria; el OVAL CVE de resolute, 10,7 s y 59 MB, porque se lee dos veces para no cargar en memoria las entradas del kernel. Con la caché, el paso entero tarda menos de medio segundo.
- `check_updates.yml` contra un Ubuntu 24.04 local con el OVAL de noble servido en local: primera ejecución, ejecución con caché (304), sin red con caché y sin ella, la opción desactivada y una URL no HTTPS. ansible-lint (perfil production) y `--syntax-check`.

## 1.2.1 (2026-11-24)

### Correcciones

- Capacidades: el resumen de la IA recibe el destino pedido y los hosts que abarca ("Requested target: lxd_hosts... Hosts it matched: Archie, Logan, Nina, Ran"). Antes solo veía los informes y podía contestar que no sabía cuáles eran los hosts LXD aunque fuera justo lo que se había consultado.
- Capacidades: el modelo ya no calcula totales por su cuenta. Solo da un total si el informe lo trae (un campo como `count`, `total`, `lines` o `updates`); si no, lista los elementos sin contarlos. En las pruebas dijo "50 paquetes" sobre una tabla de 46.

### Pruebas

- Un test nuevo y aserciones en otro (211 en total) sobre el destino y la regla de recuentos en el prompt del resumen.

## 1.2.0 (2026-11-24)

### Novedades

- Capacidades: `run.on_request: true` (solo para las de `read_only`) hace que cualquier petición la ejecute, también las preguntas. Es para consultas bajo demanda, donde el último informe puede ser viejo o de otro comando; sin esta opción, una pregunta se responde con los últimos informes desde la 1.1.1.
- Capacidades: `required: true` en un parámetro. Si falta el valor, la petición se rechaza antes de llamar a Semaphore, en vez de lanzar un playbook que fallará en su validación. No se puede combinar con `default`.
- La IA responde en el idioma de la pregunta en las respuestas libres y en los resúmenes de las capacidades. El informe programado no cambia.

### Seguridad

- Capacidades: ningún parámetro de texto acepta `{{`, `{%` ni `{#`, permita lo que permita su patrón, y tampoco los valores de un `enum`. Ansible evalúa las plantillas Jinja de las variables extra en el controlador al usarlas, así que un valor como `{{ lookup('pipe', ...) }}` se ejecutaba en el contenedor del servicio aunque el playbook rechazara después el valor. Comprobado con ansible-core 2.22. Con los patrones del ejemplo no se podía dar, porque ninguno admite `{`, pero un manifiesto con un patrón amplio quedaba expuesto.

### Pruebas

- 8 tests nuevos (210 en total): `on_request` con una pregunta, `on_request` en una capacidad de tipo `changes`, parámetro obligatorio que falta, marcas de Jinja en un parámetro con patrón amplio y en un `enum`, e instrucción de idioma en los dos prompts.

## 1.1.1 (2026-11-23)

### Correcciones

- Capacidades: una pregunta sobre los resultados ("¿hay imágenes de docker nuevas?") hacía que el modelo lanzara la capacidad en vez de responder con los últimos informes. El prompt de intención pide ahora `run: true` solo cuando se pide expresamente lanzarla, ejecutarla o refrescarla. Con una capacidad de tipo `changes` esto habría creado un plan sin pedirlo.
- Capacidades: el resumen de la IA podía contradecir el estado real de la ejecución ("no pude lanzar la tarea" debajo de "Ran now"). El estado lo muestra el servicio y ya no se pasa al modelo, que tiene instrucciones de no hablar de si se ejecutó; la antigüedad de cada informe (`age_h`) sigue indicando lo frescos que son los datos.

### Pruebas

- Tests nuevos sobre los dos prompts (202 en total). Los dos casos se reprodujeron con el modelo de producción desde el panel antes del cambio.

## 1.1.0 (2026-11-23)

### Novedades

- Capacidades: la IA puede usar playbooks nuevos sin cambiar el código. Cada uno se declara con un manifiesto YAML en `CAPABILITIES_PATH` (por defecto `/etc/patch-manager/capabilities.d`) que indica la plantilla de Semaphore, si es de solo lectura o cambia algo (`risk: read_only | changes`), el grupo de hosts al que puede apuntar (`limit_group`, obligatorio con `changes`), los parámetros que la IA puede dar (`bool`, `int` con mínimo y máximo, `enum`, `string` con patrón obligatorio) y dónde deja sus informes por host (`reports.path`, con `{host}`). Las de solo lectura se lanzan al pedirlas y, con `run.wait: true`, la respuesta usa los informes recién escritos. Las de tipo `changes` solo crean un plan que alguien tiene que aprobar, como los parches, y el panel lo muestra con la plantilla, el alcance y los valores. Si no se pide que se lance, la IA responde con los últimos informes. Con `include_in_analysis: true` esos informes entran en el análisis programado y en **Analyze risk**. Sin LLM se eligen por las palabras de `keywords`. `GET /api/capabilities` lista las cargadas y las rechazadas con el motivo, y `POST /api/capabilities/reload` las vuelve a leer. Ejemplo comentado en `config/capabilities.d.example/docker_check.yml`; documentación en la sección 21 de la wiki.
- `playbooks/docker_check.yml`: dice qué proyectos de Docker Compose de `docker_hosts` tienen imagen nueva en su registro comparando digests con `docker buildx imagetools`, sin descargar ni reiniciar nada. Revisa los mismos proyectos que `docker_update.yml` (`docker_compose_projects`) y deja `reports/docker-checks/<host>.json`. Las imágenes fijadas con `@sha256` salen como `pinned`. Es la capacidad de ejemplo.
- `install.sh` crea `/etc/patch-manager/capabilities.d` (`root:patchai 0750`). En Docker hay una línea comentada en `docker/docker-compose.yml` para montarlo en el contenedor de IA.

### Seguridad

- El modelo solo elige una capacidad cargada, el alcance y valores de parámetros; la plantilla, el grupo, la ruta de informes y los parámetros permitidos salen del manifiesto. Un parámetro desconocido se descarta con un aviso y uno con un valor no válido impide la ejecución. No se aceptan parámetros que empiecen por `ansible_` ni variables mágicas de Ansible (`hostvars`, `groups`, `playbook_dir`...), porque como variables extra podrían cambiar el intérprete o la shell que se usa en los hosts.
- Un manifiesto se rechaza si el fichero o el directorio se pueden escribir por el grupo u otros, si es un enlace simbólico o si su dueño no es root ni el usuario del servicio. Así el servicio no puede añadirse capacidades a sí mismo.
- Los informes solo se leen dentro de `REPORTS_PATH`, con un tamaño máximo por fichero (`reports.max_bytes`), y llegan al modelo como datos de los hosts, con la instrucción de ignorar lo que parezcan órdenes.
- Al aprobar el plan de una capacidad se vuelve a leer el manifiesto: si se ha borrado, si apunta a otra plantilla u otro grupo, o si los parámetros guardados ya no son válidos, el plan falla en vez de ejecutar otra cosa.

### Pruebas

- 37 tests nuevos (202 en total): carga y rechazo de manifiestos (nombres, parámetros reservados, rutas con `..` o absolutas, permisos, enlaces, duplicados, `changes` sin grupo), validación de parámetros, intención con y sin LLM, respuesta desde informes, lanzamiento con Semaphore simulado, alcance fuera del grupo, plan y aprobación, plan con el manifiesto cambiado, informes en el análisis y la API. ruff y ansible-lint (perfil production, sin conexión) sin avisos en lo nuevo.
- `docker_check.yml` ejecutado contra un Docker 29 local sin acceso a registros: imagen fijada por digest, imagen que no se puede consultar y directorio inexistente, con el informe JSON y el host en rojo. La misma comparación de digests se probó a mano en cuatro hosts con Compose 5.8 y buildx 0.39 contra GHCR y Docker Hub, donde encontró dos imágenes nuevas que después actualizó `docker_update.yml`.

## 1.0.4 (2026-11-22)

### Novedades

- Preguntas sobre paquetes: "¿qué versión de nginx tenemos instalada?", "is openssh-server installed on ubuntu_servers?". La IA responde con una tabla host, paquete y versión, construida a partir de los datos y no redactada por el modelo, además de los hosts donde no está instalado y los que no tienen datos. Por defecto usa el inventario de paquetes que ahora guarda Check Updates en Ubuntu y Rocky (`reports/packages/<host>.json`, desactivable con `patch_collect_packages: false`); si se pide "ahora" o "actualizado", lanza el playbook nuevo `package_query.yml` (plantilla **Package Query** en Semaphore), espera hasta `PACKAGE_QUERY_TIMEOUT` segundos (180) y responde con lo que contestaron los hosts. Es de solo lectura, como **Refresh host data**, y no pasa por la aprobación de planes. El nombre del paquete se valida en el servicio y otra vez en el playbook, y llega a los hosts como argumento, sin shell. Funciona también sin LLM (palabras clave en español e inglés) y admite `*` como comodín. macOS y Windows no se consultan.
- `playbooks/docker_update.yml`: actualiza los proyectos de Docker Compose de los hosts del grupo `docker_hosts`. Cada host lista sus directorios en `docker_compose_projects`. Por cada proyecto hace `docker compose pull` y `up -d`, que solo recrea los contenedores cuya imagen cambió y arranca los que estuvieran parados, y espera hasta que todos los contenedores estén `running` y, si tienen healthcheck, `healthy` (por defecto 20 intentos de 15 s). Después vuelve a mirar a los 20 s y comprueba que ninguno se ha reiniciado entre medias, para no dar por bueno un contenedor sin healthcheck que se reinicia en bucle. Un proyecto que no llega a ese estado queda como `FAILED`, sin rollback; el playbook sigue con el siguiente proyecto y el host termina en rojo. Las imágenes huérfanas solo se borran en los hosts donde todo ha ido bien, para que la anterior siga disponible si hay que volver atrás a mano. Con `-e docker_pull_only=true` solo descarga, y con `--check` solo informa del estado. Deja un informe por host en `reports/docker-runs/<host>.json` con las imágenes actualizadas y el estado de cada contenedor.

### Pruebas

- Ejecutado contra un Docker 29 con Compose 5.7 local, con imágenes de prueba y un `docker compose pull` simulado: proyecto sin cambios, imagen nueva (el contenedor se recrea con ella y la antigua se borra), healthcheck que falla, contenedor parado, contenedor que se reinicia en bucle, directorio inexistente, directorio sin compose, `--check` y `docker_pull_only`. El formato JSON de Compose antiguo (un array) se ha probado aparte.
- Consultas de paquetes, de extremo a extremo con un Semaphore 2.19.12 real y un Ubuntu 24.04 local: la IA lanza **Package Query**, el playbook escribe el resultado y la respuesta trae la versión real de nginx; un host inalcanzable sale como "no contestó". Con límite (`is nginx installed on <host> right now?`) y desde el inventario después de un Check Updates lanzado por el servicio. El inventario de paquetes del host de prueba (1.049 paquetes, 37 KB) coincide con `dpkg-query`. Un nombre con `;` o que empieza por `-` se rechaza en el playbook antes de tocar ningún host.
- ansible-lint (perfil production), `--syntax-check` y 165 tests.
- Sin probar: Docker contra un registro real, en hosts reales y con versiones de Compose anteriores a la 5; el inventario y las consultas de paquetes en Rocky (`rpm`).

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
