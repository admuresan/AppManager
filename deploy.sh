#!/bin/bash
# Deployment script for AppManager
# Copies files to BlackGrid. No sudo for dirs if /BlackGrid exists.
# Sudo only for sudoers setup (journalctl/systemctl) - requires password in config.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECTS_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
CENTRAL_SSH="$PROJECTS_ROOT/ssh"
SSH_KEY="$CENTRAL_SSH/ssh-key-2025-12-26.key"
DEPLOY_DIR="/BlackGrid/appmanager"

# Config (same as DeltaBooks)
SERVER_IP="192.168.2.86"
SERVER_USER="remoteterminal"
SUDO_PASS=""
for cfg in "$CENTRAL_SSH/deploy_config" "$CENTRAL_SSH/deploy_config.json"; do
    [ -f "$cfg" ] || continue
    SERVER_IP=$(python3 -c "import json; d=json.load(open('$cfg')); print(d.get('internalIP','192.168.2.86'))" 2>/dev/null) || true
    SERVER_USER=$(python3 -c "import json; d=json.load(open('$cfg')); print(d.get('username','remoteterminal'))" 2>/dev/null) || true
    SUDO_PASS=$(python3 -c "import json; d=json.load(open('$cfg')); print(d.get('password',''))" 2>/dev/null) || true
    [ -z "$SUDO_PASS" ] && SUDO_PASS=$(grep -oE '"password"[[:space:]]*:[[:space:]]*"[^"]*"' "$cfg" 2>/dev/null | sed -n 's/.*"\([^"]*\)"$/\1/p')
    break
done
SERVER_IP="${SERVER_IP:-192.168.2.86}"
SERVER_USER="${SERVER_USER:-remoteterminal}"

SSH="ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SCP="scp -i $SSH_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

echo "=========================================="
echo "AppManager Deployment (files + setup)"
echo "=========================================="
echo "Server: $SERVER_USER@$SERVER_IP"
echo ""

[ ! -f "$SSH_KEY" ] && { echo "❌ SSH key not found"; exit 1; }
chmod 600 "$SSH_KEY"

# Create dirs (no sudo - same as other apps)
$SSH "$SERVER_USER@$SERVER_IP" "mkdir -p $DEPLOY_DIR $DEPLOY_DIR/instance/uploads/logos $DEPLOY_DIR/backups" || { echo "❌ Failed (ensure /BlackGrid exists - run DeltaBooks first)"; exit 1; }

# Backup instance if exists
$SSH "$SERVER_USER@$SERVER_IP" "DEPLOY_DIR='$DEPLOY_DIR' bash -s" << 'ENDBACKUP'
if [ -d "$DEPLOY_DIR/instance" ]; then
  BACKUP="$DEPLOY_DIR/backups/$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$BACKUP"
  cp -r "$DEPLOY_DIR/instance/"* "$BACKUP/" 2>/dev/null || true
fi
ENDBACKUP

# Upload files (same pattern as DeltaBooks)
cd "$SCRIPT_DIR"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT
tar --exclude='AMvenv' --exclude='__pycache__' --exclude='*.pyc' --exclude='.git' \
    --exclude='instance' --exclude='*.log' --exclude='.env' \
    --exclude='oci_ssh/*.pem' --exclude='oci_ssh/*.key' --exclude='backups' \
    -czf "$TEMP_DIR/appmanager.tar.gz" .

$SCP "$TEMP_DIR/appmanager.tar.gz" "$SERVER_USER@$SERVER_IP:/tmp/"
$SSH "$SERVER_USER@$SERVER_IP" "cd $DEPLOY_DIR && tar -xzf /tmp/appmanager.tar.gz && rm /tmp/appmanager.tar.gz && chmod +x *.sh 2>/dev/null || true"

# Restore config from latest backup
$SSH "$SERVER_USER@$SERVER_IP" "DEPLOY_DIR='$DEPLOY_DIR' bash -s" << 'ENDRESTORE'
LATEST=$(ls -td "$DEPLOY_DIR/backups/"* 2>/dev/null | head -1)
[ -n "$LATEST" ] && [ -d "$LATEST" ] && cp -r "$LATEST"/* "$DEPLOY_DIR/instance/" 2>/dev/null || true
mkdir -p "$DEPLOY_DIR/instance/uploads/logos"
chmod -R 755 "$DEPLOY_DIR/instance" 2>/dev/null || true
ENDRESTORE

# Sudoers (needs sudo - skip if no password)
if [ -n "$SUDO_PASS" ]; then
  echo "Configuring sudo permissions..."
  SUDO_B64=$(printf '%s' "$SUDO_PASS" | base64 -w 0 2>/dev/null || printf '%s' "$SUDO_PASS" | base64 | tr -d '\n')
  $SSH "$SERVER_USER@$SERVER_IP" "SUDO_B64='$SUDO_B64' SUDOERS_USER='$SERVER_USER' DEPLOY_DIR='$DEPLOY_DIR' bash -s" << 'ENDSUDO'
SUDOERS_FILE="/etc/sudoers.d/appmanager-${SUDOERS_USER}"
RUN="sudo"
[ -n "$SUDO_B64" ] && SUDO_PASS=$(echo "$SUDO_B64" | base64 -d 2>/dev/null || echo "$SUDO_B64" | base64 -D 2>/dev/null) && [ -n "$SUDO_PASS" ] && RUN="printf '%s\n' \"\$SUDO_PASS\" | sudo -S"
cat > /tmp/am_sudoers << EOF
${SUDOERS_USER} ALL=(ALL) NOPASSWD: /usr/bin/journalctl
${SUDOERS_USER} ALL=(ALL) NOPASSWD: /bin/journalctl
${SUDOERS_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart *
${SUDOERS_USER} ALL=(ALL) NOPASSWD: /bin/systemctl restart *
${SUDOERS_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *
${SUDOERS_USER} ALL=(ALL) NOPASSWD: /bin/systemctl status *
${SUDOERS_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl show *
${SUDOERS_USER} ALL=(ALL) NOPASSWD: /bin/systemctl show *
${SUDOERS_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl list-units *
${SUDOERS_USER} ALL=(ALL) NOPASSWD: /bin/systemctl list-units *
${SUDOERS_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active *
${SUDOERS_USER} ALL=(ALL) NOPASSWD: /bin/systemctl is-active *
EOF
$RUN visudo -c -f /tmp/am_sudoers 2>/dev/null && $RUN cp /tmp/am_sudoers "$SUDOERS_FILE" && $RUN chmod 0440 "$SUDOERS_FILE" && $RUN chown root:root "$SUDOERS_FILE" 2>/dev/null || true
rm -f /tmp/am_sudoers
ENDSUDO
else
  echo "Skipping sudoers (no password in config)"
fi

# Restart AppManager so it loads new code (templates, etc.)
echo "Restarting AppManager service..."
$SSH "$SERVER_USER@$SERVER_IP" "sudo systemctl restart appmanager.service 2>/dev/null || echo 'Note: Restart appmanager.service manually to pick up changes'"

echo "✅ Deployment complete!"
