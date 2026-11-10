#!/usr/bin/env bash
# =============================================================================
# create-container.sh: create an LXD container and install Patch Manager in it
# =============================================================================
# Run on the LXD host from the repository root:
#   ./deploy/lxd/create-container.sh [name] [image] [native|docker]
#
#   native (default): Semaphore + AI service as systemd units (recommended)
#   docker:           Docker inside the container (security.nesting=true),
#                     then "docker compose up" from docker/
# =============================================================================
set -euo pipefail

NAME="${1:-patchmgr}"
IMAGE="${2:-ubuntu:24.04}"
MODE="${3:-native}"
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

command -v lxc >/dev/null || { echo "lxc not found" >&2; exit 1; }

if lxc info "$NAME" >/dev/null 2>&1; then
  echo "Container $NAME already exists; pushing code and re-running the installer."
else
  if [[ "$MODE" == "docker" ]]; then
    lxc launch "$IMAGE" "$NAME" -c boot.autostart=true -c security.nesting=true \
      -c security.syscalls.intercept.mknod=true -c security.syscalls.intercept.setxattr=true
  else
    lxc launch "$IMAGE" "$NAME" -c boot.autostart=true
  fi
fi

echo "Waiting for the container to finish booting..."
lxc exec "$NAME" -- cloud-init status --wait >/dev/null 2>&1 || sleep 10

echo "Copying the repository to /opt/patch-manager (without local secrets)..."
tar -C "$REPO_DIR" \
  --exclude=.git --exclude=.venv --exclude='__pycache__' \
  --exclude=config/.env --exclude=config/ai.env --exclude='docker/nginx/certs/*' \
  -czf - . | lxc exec "$NAME" -- bash -c 'mkdir -p /opt/patch-manager && tar -C /opt/patch-manager -xzf -'

if [[ "$MODE" == "docker" ]]; then
  lxc exec "$NAME" -- bash -c 'apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io docker-compose-v2'
  cat <<MSG
Docker installed in $NAME. Next:
  lxc exec $NAME -- bash
  cd /opt/patch-manager
  cp config/env.example config/.env && cp config/ai.env.example config/ai.env   # edit both
  cd docker && bash generate_certs.sh \$(hostname) && docker compose up -d
MSG
else
  lxc exec "$NAME" -- bash /opt/patch-manager/deploy/native/install.sh
fi

cat <<MSG

Expose it on the host's LAN (optional), e.g. host port 8443 -> container 443:
  lxc config device add $NAME https proxy listen=tcp:0.0.0.0:8443 connect=tcp:127.0.0.1:443
The container also needs to reach your hosts (SSH 22, WinRM 5986) and
your LLM endpoint (openrouter.ai, or a local llama-swap/Ollama host).
MSG
