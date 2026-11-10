#!/usr/bin/env bash
# =============================================================================
# install.sh: native install of Patch Manager inside an Ubuntu LXD container
# =============================================================================
# Run as root inside the container, with the repository at /opt/patch-manager:
#   bash /opt/patch-manager/deploy/native/install.sh
#
# Installs:
#   - Ansible (venv at /opt/ansible-venv) + collections + pywinrm
#   - Semaphore UI (official .deb, SQLite database, systemd unit, 127.0.0.1:3000)
#   - Patch Manager AI (venv at /opt/patch-manager/.venv, systemd unit, 127.0.0.1:8501)
#   - nginx with TLS on :443 in front of both (skip with --no-nginx)
#
# Idempotent: re-running keeps existing config files and secrets.
# =============================================================================
set -euo pipefail

SEMAPHORE_VERSION="${SEMAPHORE_VERSION:-2.19.12}"
APP_DIR=/opt/patch-manager
ANSIBLE_VENV=/opt/ansible-venv
REPORTS_DIR=/var/lib/patch-manager/reports
SEM_HOME=/var/lib/semaphore
WITH_NGINX=1

for arg in "$@"; do
  case "$arg" in
    --no-nginx) WITH_NGINX=0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
[[ -f "$APP_DIR/app/main.py" ]] || { echo "Repository not found at $APP_DIR" >&2; exit 1; }

log() { printf '\n==> %s\n' "$*"; }
rand() { head -c32 /dev/urandom | base64; }

# ─── Packages ────────────────────────────────────────────────────────────────
log "Installing OS packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-venv python3-pip git openssh-client sshpass \
  curl ca-certificates openssl
[[ $WITH_NGINX -eq 1 ]] && apt-get install -y -q nginx

# ─── Users and directories ──────────────────────────────────────────────────
log "Creating users and directories"
getent group patchreports >/dev/null || groupadd --system patchreports
id semaphore >/dev/null 2>&1 || useradd --system --home-dir "$SEM_HOME" --create-home \
  --shell /usr/sbin/nologin --groups patchreports semaphore
id patchai >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --no-create-home \
  --shell /usr/sbin/nologin --groups patchreports patchai

install -d -o semaphore -g patchreports -m 2775 "$REPORTS_DIR" "$REPORTS_DIR/hosts" "$REPORTS_DIR/patch-runs"
install -d -o semaphore -g semaphore -m 0750 "$SEM_HOME" "$SEM_HOME/tmp"
install -d -o semaphore -g semaphore -m 0700 "$SEM_HOME/.ssh"
install -d -o root -g patchai -m 0750 /etc/patch-manager
install -d -o root -g semaphore -m 0750 /etc/semaphore

# Repository readable by both services; secrets in config/ are not used here.
chown -R root:root "$APP_DIR"
chmod -R u=rwX,go=rX "$APP_DIR"
chmod 0700 "$APP_DIR/config"

# ─── Ansible ────────────────────────────────────────────────────────────────
log "Installing Ansible into $ANSIBLE_VENV"
[[ -d "$ANSIBLE_VENV" ]] || python3 -m venv "$ANSIBLE_VENV"
"$ANSIBLE_VENV/bin/pip" install -q --upgrade pip
"$ANSIBLE_VENV/bin/pip" install -q "ansible-core>=2.20" "pywinrm>=0.5"
"$ANSIBLE_VENV/bin/ansible-galaxy" collection install -r "$APP_DIR/requirements.yml" \
  -p /usr/share/ansible/collections --upgrade
"$ANSIBLE_VENV/bin/ansible" --version | head -1

# ─── Semaphore ──────────────────────────────────────────────────────────────
log "Installing Semaphore $SEMAPHORE_VERSION"
ARCH="$(dpkg --print-architecture)"   # amd64 | arm64
if ! command -v semaphore >/dev/null || ! semaphore version 2>/dev/null | grep -q "$SEMAPHORE_VERSION"; then
  DEB="semaphore_${SEMAPHORE_VERSION}_linux_${ARCH}.deb"
  curl -fsSL -o "/tmp/$DEB" \
    "https://github.com/semaphoreui/semaphore/releases/download/v${SEMAPHORE_VERSION}/${DEB}"
  dpkg -i "/tmp/$DEB"
  rm -f "/tmp/$DEB"
fi

if [[ ! -f /etc/semaphore/config.json ]]; then
  cat > /etc/semaphore/config.json <<EOF
{
  "dialect": "sqlite",
  "sqlite": { "host": "$SEM_HOME/database.sqlite" },
  "tmp_path": "$SEM_HOME/tmp",
  "cookie_hash": "$(rand)",
  "cookie_encryption": "$(rand)",
  "access_key_encryption": "$(rand)",
  "forwarded_env_vars": ["EMAIL_ENABLED", "SMTP_HOST", "SMTP_PORT", "SMTP_USER",
                         "SMTP_PASSWORD", "SMTP_SECURE", "PATCH_REPORT_DIR"]
}
EOF
  chown root:semaphore /etc/semaphore/config.json
  chmod 0640 /etc/semaphore/config.json
fi

if [[ ! -f /etc/semaphore/semaphore.env ]]; then
  cat > /etc/semaphore/semaphore.env <<EOF
# Environment for Semaphore and the Ansible tasks it runs
PATCH_REPORT_DIR=$REPORTS_DIR
EMAIL_ENABLED=false
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=starttls
SMTP_USER=
SMTP_PASSWORD=
EOF
  chown root:semaphore /etc/semaphore/semaphore.env
  chmod 0640 /etc/semaphore/semaphore.env
fi

install -m 0644 "$APP_DIR/deploy/native/semaphore.service" /etc/systemd/system/semaphore.service
systemctl daemon-reload
systemctl enable --now semaphore
sleep 3

SEM_ADMIN_PASS_FILE=/etc/semaphore/admin-password
if [[ ! -f "$SEM_ADMIN_PASS_FILE" ]]; then
  SEM_PASS="$(head -c18 /dev/urandom | base64 | tr -d '/+=')"
  if runuser -u semaphore -- semaphore user add --config /etc/semaphore/config.json --admin \
       --login admin --name "Administrator" --email admin@localhost --password "$SEM_PASS"; then
    umask 077; echo "$SEM_PASS" > "$SEM_ADMIN_PASS_FILE"
    echo "Semaphore admin password saved in $SEM_ADMIN_PASS_FILE"
  else
    echo "WARNING: could not create the Semaphore admin user (exists already?)" >&2
  fi
fi

# ─── Patch Manager AI ───────────────────────────────────────────────────────
log "Installing Patch Manager AI"
[[ -d "$APP_DIR/.venv" ]] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

if [[ ! -f /etc/patch-manager/ai.env ]]; then
  APP_PASS="$(head -c18 /dev/urandom | base64 | tr -d '/+=')"
  sed -e "s|^APP_AUTH_PASSWORD=.*|APP_AUTH_PASSWORD=$APP_PASS|" \
      -e "s|^SEMAPHORE_URL=.*|SEMAPHORE_URL=http://127.0.0.1:3000|" \
      -e "s|^INVENTORY_PATH=.*|INVENTORY_PATH=$APP_DIR/inventory/hosts.yml|" \
      -e "s|^REPORTS_PATH=.*|REPORTS_PATH=$REPORTS_DIR|" \
      "$APP_DIR/config/ai.env.example" > /etc/patch-manager/ai.env
  chown root:patchai /etc/patch-manager/ai.env
  chmod 0640 /etc/patch-manager/ai.env
  echo "Dashboard user 'admin', password in /etc/patch-manager/ai.env (APP_AUTH_PASSWORD)"
fi

install -m 0644 "$APP_DIR/deploy/native/patch-ai.service" /etc/systemd/system/patch-ai.service
systemctl daemon-reload
systemctl enable patch-ai
systemctl restart patch-ai || true

# ─── nginx (TLS) ────────────────────────────────────────────────────────────
if [[ $WITH_NGINX -eq 1 ]]; then
  log "Configuring nginx"
  install -d -m 0755 /etc/ssl/patch-manager
  if [[ ! -f /etc/ssl/patch-manager/server.crt ]]; then
    CN="$(hostname -f 2>/dev/null || hostname)"
    openssl req -x509 -nodes -newkey rsa:3072 -days 825 \
      -keyout /etc/ssl/patch-manager/server.key -out /etc/ssl/patch-manager/server.crt \
      -subj "/CN=$CN" -addext "subjectAltName=DNS:$CN,DNS:localhost,IP:127.0.0.1" 2>/dev/null
    chmod 0600 /etc/ssl/patch-manager/server.key
  fi
  install -m 0644 "$APP_DIR/deploy/native/nginx-patch-manager.conf" /etc/nginx/sites-available/patch-manager
  ln -sfn /etc/nginx/sites-available/patch-manager /etc/nginx/sites-enabled/patch-manager
  rm -f /etc/nginx/sites-enabled/default
  nginx -t && systemctl reload nginx
fi

log "Done"
cat <<EOF
Next steps:
  1. Edit /etc/patch-manager/ai.env: set OPENROUTER_API_KEY (or point LLM_DEFAULT at a
     local server), then SEMAPHORE_API_TOKEN once Semaphore is set up.
  2. Semaphore (https://<container>/ , user admin, password in $SEM_ADMIN_PASS_FILE):
       - Key Store: SSH key for Linux/macOS, login/password for Windows
       - Repository: URL $APP_DIR (local path)
       - Inventory: type File, path inventory/hosts.yml
       - Templates: "Check Updates" (playbooks/check_updates.yml) and
         "Apply Patches" (playbooks/apply_patches.yml), allow CLI args / limit override
       - User menu > API Tokens: create one for SEMAPHORE_API_TOKEN
  3. systemctl restart patch-ai && journalctl -u patch-ai -f
  4. Dashboard: https://<container>/ai/
EOF
