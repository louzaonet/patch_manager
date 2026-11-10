#!/bin/bash
# =============================================================================
# setup_macos_ssh.sh: Prepare macOS for Ansible management
# =============================================================================
# Run on each Mac as a user with admin privileges:
#   chmod +x setup_macos_ssh.sh
#   sudo ./setup_macos_ssh.sh
# =============================================================================

set -euo pipefail

echo "=== Configuring macOS for Ansible ==="

# 1. Enable Remote Login (SSH)
echo "[1/5] Enabling SSH (Remote Login)..."
# On recent macOS this needs Full Disk Access for the terminal app. If it
# fails, enable it in System Settings > General > Sharing > Remote Login.
if ! sudo systemsetup -setremotelogin on 2>/dev/null; then
    echo "  -> Could not enable Remote Login from the CLI."
    echo "     Turn it on in System Settings > General > Sharing > Remote Login, then re-run."
fi

# 2. Verify Python 3 is available
echo "[2/5] Verifying Python 3..."
# /usr/bin/python3 exists even without the Command Line Tools (it is a stub
# that pops up an installer), so check for the tools themselves.
if ! xcode-select -p &> /dev/null; then
    echo "  → Installing Xcode Command Line Tools (includes Python 3)..."
    xcode-select --install 2>/dev/null || true
    echo "  → Wait for the installation to complete, then re-run this script."
    exit 1
else
    PYTHON_VERSION=$(python3 --version)
    echo "  → $PYTHON_VERSION available"
fi

# 3. Configure passwordless sudo for the Ansible user
ANSIBLE_USER="${1:-$(whoami)}"
echo "[3/5] Configuring sudo NOPASSWD for '$ANSIBLE_USER'..."

SUDOERS_FILE="/etc/sudoers.d/ansible_${ANSIBLE_USER}"
if [ ! -f "$SUDOERS_FILE" ]; then
    echo "${ANSIBLE_USER} ALL=(ALL) NOPASSWD: ALL" | sudo tee "$SUDOERS_FILE" > /dev/null
    sudo chmod 0440 "$SUDOERS_FILE"
    sudo visudo -cf "$SUDOERS_FILE"
    echo "  → Sudoers file created: $SUDOERS_FILE"
else
    echo "  → Already exists: $SUDOERS_FILE"
fi

# 4. Install SSH key (if provided as second argument)
PUB_KEY="${2:-}"
if [ -n "$PUB_KEY" ]; then
    echo "[4/5] Installing SSH public key..."
    ANSIBLE_HOME=$(eval echo "~${ANSIBLE_USER}")
    SSH_DIR="${ANSIBLE_HOME}/.ssh"
    AUTH_KEYS="${SSH_DIR}/authorized_keys"

    sudo mkdir -p "$SSH_DIR"
    sudo chmod 700 "$SSH_DIR"

    if ! sudo grep -qxF "$PUB_KEY" "$AUTH_KEYS" 2>/dev/null; then
        echo "$PUB_KEY" | sudo tee -a "$AUTH_KEYS" > /dev/null
        echo "  → Key added"
    else
        echo "  → Key already present"
    fi

    sudo chmod 600 "$AUTH_KEYS"
    sudo chown -R "${ANSIBLE_USER}:staff" "$SSH_DIR"
else
    echo "[4/5] No SSH key provided (pass as second argument)"
    echo "  → Usage: $0 [user] [ssh_public_key]"
fi

# 5. Verify non-interactive softwareupdate access
echo "[5/5] Verifying softwareupdate access..."
softwareupdate --list 2>&1 | head -5
echo "  → softwareupdate accessible"

echo ""
echo "=== Verification ==="
echo "SSH enabled:       $(sudo systemsetup -getremotelogin)"
echo "Python 3:          $(python3 --version)"
echo "Ansible user:      ${ANSIBLE_USER}"
echo ""
echo "Test connection from the Ansible server:"
echo "  ansible macos_servers -m ping -i inventory/hosts.yml"
echo ""
echo "✅ macOS configured successfully for Ansible"
