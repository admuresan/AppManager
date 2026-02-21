#!/bin/bash
# Deploy AppManager to a LAN server.
# Reads server address and credentials from ../ssh/deploy_config.json
#   (internalIP, username, password). For password auth you need sshpass (e.g. apt install sshpass).
#   Alternatively put an SSH key in ../ssh/ (e.g. ssh-key-2025-12-26.key) and the script will use it.
# Deploys to /BlackGrid/appmanager, runs app on 8080, Nginx on 80/443 with HTTPS (Let's Encrypt).
# Optional: ddns_address (for SSL and Nginx server_name), noip_username/noip_password (No-IP DDNS),
#   letsencrypt_email (for certbot). Only ports 80 and 443 are exposed (UFW); router should forward only those.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ROOT="$SCRIPT_DIR"
# Deploy config and optional SSH key: sibling folder "ssh" (e.g. Projects/ssh)
SSH_DIR="$APP_ROOT/../ssh"
CONFIG_JSON="${DEPLOY_CONFIG:-$SSH_DIR/deploy_config.json}"
DEPLOY_DIR="/BlackGrid/appmanager"
SERVICE_NAME="appmanager"
VENV_NAME="AMvenv"
APP_PORT="8080"

echo "========================================"
echo "AppManager Deploy"
echo "========================================"

# --- Read deploy config ---
if [ ! -f "$CONFIG_JSON" ]; then
    echo "ERROR: Deploy config not found: $CONFIG_JSON"
    echo "Create it with: internalIP, username, password"
    exit 1
fi

# Parse JSON (Python one-liner for portability); output lines: IP, user, password, ddns_address, noip_user, noip_pass, letsencrypt_email
CONFIG_OUT=$(python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
print(d.get('internalIP',''))
print(d.get('username',''))
print(d.get('password',''))
print(d.get('ddns_address',''))
print(d.get('noip_username',''))
print(d.get('noip_password',''))
print(d.get('letsencrypt_email',''))
" "$CONFIG_JSON" 2>/dev/null) || CONFIG_OUT=$(python -c "
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
print(d.get('internalIP',''))
print(d.get('username',''))
print(d.get('password',''))
print(d.get('ddns_address',''))
print(d.get('noip_username',''))
print(d.get('noip_password',''))
print(d.get('letsencrypt_email',''))
" "$CONFIG_JSON")
SERVER_IP=$(echo "$CONFIG_OUT" | sed -n '1p')
SERVER_USER=$(echo "$CONFIG_OUT" | sed -n '2p')
SERVER_PASSWORD=$(echo "$CONFIG_OUT" | sed -n '3p')
DDNS_ADDRESS=$(echo "$CONFIG_OUT" | sed -n '4p')
NOIP_USER=$(echo "$CONFIG_OUT" | sed -n '5p')
NOIP_PASS=$(echo "$CONFIG_OUT" | sed -n '6p')
LETSENCRYPT_EMAIL=$(echo "$CONFIG_OUT" | sed -n '7p')

if [ -z "$SERVER_IP" ] || [ -z "$SERVER_USER" ]; then
    echo "ERROR: deploy_config.json must contain internalIP and username"
    exit 1
fi
if [ -z "$DDNS_ADDRESS" ]; then
    echo "ERROR: deploy_config.json must contain ddns_address (e.g. blackgrid.ddns.net) for HTTPS"
    exit 1
fi

echo "Target: $SERVER_USER@$SERVER_IP"
echo "Deploy dir: $DEPLOY_DIR"
echo "DDNS / HTTPS hostname: $DDNS_ADDRESS"
echo ""

# --- SSH/SCP helpers (password or key) ---
SSH_KEY=""
for k in "$SSH_DIR"/ssh-key-*.key "$SSH_DIR"/*.key; do
    [ -f "$k" ] && SSH_KEY="$k" && break
done 2>/dev/null

ssh_cmd() {
    if [ -n "$SSH_KEY" ]; then
        ssh -o StrictHostKeyChecking=accept-new -i "$SSH_KEY" "$SERVER_USER@$SERVER_IP" "$@"
    elif command -v sshpass &>/dev/null && [ -n "$SERVER_PASSWORD" ]; then
        sshpass -p "$SERVER_PASSWORD" ssh -o StrictHostKeyChecking=accept-new "$SERVER_USER@$SERVER_IP" "$@"
    else
        echo "ERROR: No SSH key found in $SSH_DIR and no sshpass (or no password in config). Install sshpass or add a key."
        exit 1
    fi
}

scp_cmd() {
    local src="$1"
    local dest="$2"
    if [ -n "$SSH_KEY" ]; then
        scp -o StrictHostKeyChecking=accept-new -i "$SSH_KEY" "$src" "$SERVER_USER@$SERVER_IP:$dest"
    elif command -v sshpass &>/dev/null && [ -n "$SERVER_PASSWORD" ]; then
        sshpass -p "$SERVER_PASSWORD" scp -o StrictHostKeyChecking=accept-new "$src" "$SERVER_USER@$SERVER_IP:$dest"
    else
        echo "ERROR: No SSH key or sshpass."
        exit 1
    fi
}

# --- Build archive (exclude git, venvs, instance, cache) ---
ARCHIVE="/tmp/appmanager_deploy_$$.tar.gz"
echo "[1/9] Creating archive..."
cd "$APP_ROOT"
tar -czf "$ARCHIVE" \
    --exclude='.git' \
    --exclude='venv' \
    --exclude='AMvenv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='instance' \
    --exclude='.env' \
    --exclude='*.log' \
    .
echo "Archive: $ARCHIVE"

# --- Upload ---
echo "[2/9] Uploading to $SERVER_IP..."
scp_cmd "$ARCHIVE" "/tmp/appmanager_deploy.tar.gz"
rm -f "$ARCHIVE"

# --- Remote setup ---
echo "[3/9] Creating directory and extracting..."
ssh_cmd "echo $SERVER_PASSWORD | sudo -S bash -c 'mkdir -p $DEPLOY_DIR && chown $SERVER_USER:$SERVER_USER $DEPLOY_DIR'"

# Backup existing instance if present, then extract
ssh_cmd "
mkdir -p $DEPLOY_DIR/backups
if [ -d $DEPLOY_DIR/instance ]; then
    BACKUP=$DEPLOY_DIR/backups/\$(date +%Y%m%d_%H%M%S)
    mkdir -p \$BACKUP
    cp -a $DEPLOY_DIR/instance \$BACKUP/ 2>/dev/null || true
fi
cd $DEPLOY_DIR && tar -xzf /tmp/appmanager_deploy.tar.gz && rm -f /tmp/appmanager_deploy.tar.gz
"

# --- Venv and dependencies ---
echo "[4/9] Setting up virtual environment and dependencies..."
ssh_cmd "
cd $DEPLOY_DIR
if [ ! -d $VENV_NAME ]; then
    python3 -m venv $VENV_NAME
fi
$DEPLOY_DIR/$VENV_NAME/bin/pip install -q --upgrade pip
$DEPLOY_DIR/$VENV_NAME/bin/pip install -q -r requirements.txt
"

# --- Systemd service (run on 8080, restart always) ---
echo "[5/9] Installing systemd service..."
SERVICE_FILE="$APP_ROOT/deploy/appmanager.service"
# Substitute user in service file
sed "s/^User=.*/User=$SERVER_USER/" "$SERVICE_FILE" | sed "s/^Group=.*/Group=$SERVER_USER/" > "$APP_ROOT/deploy/appmanager.service.tmp"
scp_cmd "$APP_ROOT/deploy/appmanager.service.tmp" "/tmp/appmanager.service"
rm -f "$APP_ROOT/deploy/appmanager.service.tmp"

ssh_cmd "
echo $SERVER_PASSWORD | sudo -S bash -c '
    cp /tmp/appmanager.service /etc/systemd/system/appmanager.service
    rm -f /tmp/appmanager.service
    systemctl daemon-reload
    systemctl enable appmanager
    systemctl restart appmanager
'
"

# --- No-IP DDNS updater (keeps ddns hostname pointed at current public IP) ---
echo "[6/9] Setting up No-IP DDNS updater (optional)..."
if [ -n "$NOIP_USER" ] && [ -n "$NOIP_PASS" ]; then
    scp_cmd "$APP_ROOT/deploy/noip-update.sh" "/tmp/noip-update.sh"
    ssh_cmd "
        echo $SERVER_PASSWORD | sudo -S bash -c '
            chmod +x /tmp/noip-update.sh
            echo \"hostname=$DDNS_ADDRESS\" > /etc/noip-ddns-config
            echo \"NOIP_USER=$NOIP_USER\" > /etc/noip-ddns-credentials
            echo \"NOIP_PASS=$NOIP_PASS\" >> /etc/noip-ddns-credentials
            chmod 600 /etc/noip-ddns-credentials
            mv /tmp/noip-update.sh /usr/local/bin/noip-update.sh
            NOIP_CREDENTIALS_FILE=/etc/noip-ddns-credentials NOIP_CONFIG_FILE=/etc/noip-ddns-config /usr/local/bin/noip-update.sh
            (crontab -l 2>/dev/null | grep -v noip-update; echo \"*/10 * * * * NOIP_CREDENTIALS_FILE=/etc/noip-ddns-credentials NOIP_CONFIG_FILE=/etc/noip-ddns-config /usr/local/bin/noip-update.sh\") | crontab -
        '
    "
    echo "  No-IP DDNS: credentials installed; root cron every 10 min; update run once."
else
    echo "  No-IP credentials not in config (noip_username/noip_password). Add them so $DDNS_ADDRESS stays pointed at your IP."
fi

# --- Nginx: HTTP first (for certbot), then HTTPS ---
echo "[7/9] Installing Nginx and ACME webroot..."
sed "s/__DDNS_ADDRESS__/$DDNS_ADDRESS/g" "$APP_ROOT/deploy/nginx-http-for-certbot.conf" > "$APP_ROOT/deploy/nginx-http-for-certbot.tmp"
scp_cmd "$APP_ROOT/deploy/nginx-http-for-certbot.tmp" "/tmp/nginx-appmanager.conf"
rm -f "$APP_ROOT/deploy/nginx-http-for-certbot.tmp"

ssh_cmd "
echo $SERVER_PASSWORD | sudo -S bash -c '
    which nginx >/dev/null 2>&1 || (apt-get update && apt-get install -y nginx)
    mkdir -p /var/www/appmanager-acme
    chown -R www-data:www-data /var/www/appmanager-acme
    cp /tmp/nginx-appmanager.conf /etc/nginx/sites-available/appmanager
    ln -sf /etc/nginx/sites-available/appmanager /etc/nginx/sites-enabled/appmanager
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl enable nginx && systemctl reload nginx
    rm -f /tmp/nginx-appmanager.conf
'
"

# --- Let's Encrypt certificate (must have port 80 reachable and DDNS pointing here) ---
# Email is optional: with it you get expiry notices; without it we use --register-unsafely-without-email.
echo "[8/9] Obtaining SSL certificate (Let'\''s Encrypt)..."
ssh_cmd "
    echo $SERVER_PASSWORD | sudo -S bash -c '
        which certbot >/dev/null 2>&1 || (apt-get update && apt-get install -y certbot)
        if [ -n \"$LETSENCRYPT_EMAIL\" ]; then
            certbot certonly --webroot -w /var/www/appmanager-acme -d $DDNS_ADDRESS --non-interactive --agree-tos -m $LETSENCRYPT_EMAIL
        else
            certbot certonly --webroot -w /var/www/appmanager-acme -d $DDNS_ADDRESS --non-interactive --agree-tos --register-unsafely-without-email
        fi
    '
" && CERT_OK=1 || CERT_OK=0
if [ "$CERT_OK" = "0" ]; then
    echo "  Certbot failed (e.g. port 80 not reachable or $DDNS_ADDRESS not pointing here). Fix and re-run deploy."
fi

if [ "$CERT_OK" = "1" ]; then
    sed "s/__DDNS_ADDRESS__/$DDNS_ADDRESS/g" "$APP_ROOT/deploy/nginx-https.conf" > "$APP_ROOT/deploy/nginx-https.tmp"
    scp_cmd "$APP_ROOT/deploy/nginx-https.tmp" "/tmp/nginx-appmanager-https.conf"
    rm -f "$APP_ROOT/deploy/nginx-https.tmp"
    ssh_cmd "
        echo $SERVER_PASSWORD | sudo -S bash -c '
            cp /tmp/nginx-appmanager-https.conf /etc/nginx/sites-available/appmanager
            nginx -t && systemctl reload nginx
            rm -f /tmp/nginx-appmanager-https.conf
        '
    "
    echo "  HTTPS enabled; HTTP redirects to HTTPS."
fi

# --- Firewall: only SSH, HTTP, HTTPS (only AppManager exposed) ---
echo "[9/9] Configuring firewall (only ports 22, 80, 443)..."
ssh_cmd "
    echo $SERVER_PASSWORD | sudo -S bash -c '
        ufw allow 22/tcp
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw --force enable 2>/dev/null || true
    '
" 2>/dev/null || true
echo "  UFW rules: 22, 80, 443 allowed. Other ports blocked so only this app is exposed."

echo "Checking service..."
ssh_cmd "sleep 2; systemctl is-active --quiet appmanager && echo 'AppManager service is running.' || (echo 'Service may still be starting. Check: sudo journalctl -u appmanager -f')"

echo ""
echo "========================================"
echo "Deploy complete."
echo "Local:  http://${SERVER_IP}"
echo "Public: https://${DDNS_ADDRESS}  (ensure router forwards 80/443 to $SERVER_IP)"
echo "Only ports 22, 80, 443 are open (AppManager only)."
echo "Logs:   ssh $SERVER_USER@$SERVER_IP 'sudo journalctl -u appmanager -f'"
echo "========================================"
