#!/bin/bash
# =============================================================================
# setup_macos_ssh.sh: Prepare macOS for Ansible management
# =============================================================================
# Run on each Mac as a user with admin privileges:
#   chmod +x setup_macos_ssh.sh
#   sudo ./setup_macos_ssh.sh [user] ["ssh public key"]
#
# user defaults to the account that called sudo.
# =============================================================================

set -euo pipefail

# Under sudo, whoami is root: take the account that invoked it.
ANSIBLE_USER="${1:-${SUDO_USER:-$(whoami)}}"
PUB_KEY="${2:-}"

if [[ ! "$ANSIBLE_USER" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] || ! id "$ANSIBLE_USER" >/dev/null 2>&1; then
    echo "User '$ANSIBLE_USER' does not exist. Usage: sudo $0 [user] [ssh_public_key]" >&2
    exit 1
fi
if [ "$ANSIBLE_USER" = "root" ]; then
    echo "Refusing to set up root. Usage: sudo $0 [user] [ssh_public_key]" >&2
    exit 1
fi

echo "=== Configuring macOS for Ansible (user: $ANSIBLE_USER) ==="

# 1. Enable Remote Login (SSH)
echo "[1/5] Enabling SSH (Remote Login)..."
# On recent macOS this needs Full Disk Access for the terminal app. If it
# fails, enable it in System Settings > General > Sharing > Remote Login.
if ! sudo systemsetup -setremotelogin on 2>/dev/null; then
    echo "  → Could not enable Remote Login from the CLI."
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
echo "[3/5] Configuring sudo NOPASSWD for '$ANSIBLE_USER'..."

# sudo ignores files in sudoers.d whose name contains a dot.
SUDOERS_FILE="/etc/sudoers.d/ansible_${ANSIBLE_USER//./_}"
if [ ! -f "$SUDOERS_FILE" ]; then
    # Validate a temporary copy first: a broken file in sudoers.d locks sudo.
    SUDOERS_TMP="$(mktemp)"
    echo "${ANSIBLE_USER} ALL=(ALL) NOPASSWD: ALL" > "$SUDOERS_TMP"
    if sudo visudo -cf "$SUDOERS_TMP" >/dev/null; then
        sudo install -m 0440 -o root -g wheel "$SUDOERS_TMP" "$SUDOERS_FILE"
        rm -f "$SUDOERS_TMP"
        echo "  → Sudoers file created: $SUDOERS_FILE"
    else
        rm -f "$SUDOERS_TMP"
        echo "  → visudo rejected the sudoers entry; nothing was installed." >&2
        exit 1
    fi
else
    echo "  → Already exists: $SUDOERS_FILE"
fi

# 4. Install SSH key (if provided as second argument)
if [ -n "$PUB_KEY" ]; then
    echo "[4/5] Installing SSH public key..."
    ANSIBLE_HOME="$(dscl . -read "/Users/${ANSIBLE_USER}" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')"
    if [ -z "$ANSIBLE_HOME" ] || [ ! -d "$ANSIBLE_HOME" ]; then
        echo "  → Home directory of '$ANSIBLE_USER' not found." >&2
        exit 1
    fi
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
    sudo chown -R "${ANSIBLE_USER}:$(id -gn "$ANSIBLE_USER")" "$SSH_DIR"
else
    echo "[4/5] No SSH key provided (pass as second argument)"
    echo "  → Usage: sudo $0 [user] [ssh_public_key]"
fi

# 5. Verify non-interactive softwareupdate access
echo "[5/5] Verifying softwareupdate access..."
# sed reads all the output; "head -5" closes the pipe early and, with
# pipefail, the SIGPIPE in softwareupdate aborted the script here.
if softwareupdate --list 2>&1 | sed -n '1,5p'; then
    echo "  → softwareupdate accessible"
else
    echo "  → softwareupdate --list failed; check it by hand."
fi

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
