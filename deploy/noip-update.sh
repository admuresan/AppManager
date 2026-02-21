#!/bin/bash
# No-IP Dynamic DNS updater. Run on the server (e.g. via cron every 5–10 min).
# Keeps the configured hostname pointed at this machine's current public IP.
# Requires: credentials file with NOIP_USER and NOIP_PASS (or use --user/--pass).

set -e

CREDENTIALS_FILE="${NOIP_CREDENTIALS_FILE:-/etc/noip-ddns-credentials}"
CONFIG_FILE="${NOIP_CONFIG_FILE:-/BlackGrid/appmanager/deploy/noip-config}"

# Optional: pass hostname as first arg, else read from config
HOSTNAME=""
if [ -n "$1" ]; then
    HOSTNAME="$1"
fi

if [ -z "$HOSTNAME" ] && [ -f "$CONFIG_FILE" ]; then
    # Format: hostname=blackgrid.ddns.net (one line)
    HOSTNAME=$(grep -E '^hostname=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2-)
fi

if [ -z "$HOSTNAME" ]; then
    echo "Usage: $0 <hostname>   OR set hostname= in $CONFIG_FILE"
    exit 1
fi

# Prefer env vars, then credentials file
USER="${NOIP_USER:-}"
PASS="${NOIP_PASS:-}"
if [ -z "$USER" ] && [ -f "$CREDENTIALS_FILE" ]; then
    # shellcheck source=/dev/null
    . "$CREDENTIALS_FILE"
    USER="${NOIP_USER:-}"
    PASS="${NOIP_PASS:-}"
fi

if [ -z "$USER" ] || [ -z "$PASS" ]; then
    echo "No-IP credentials not set. Set NOIP_USER and NOIP_PASS in $CREDENTIALS_FILE or env."
    exit 1
fi

# No-IP update API (legacy, still supported)
# https://www.noip.com/integrate/request
RESPONSE=$(curl -s -u "$USER:$PASS" \
    "https://dynupdate.no-ip.com/nic/update?hostname=$HOSTNAME" 2>/dev/null || true)

# Good responses: "good <ip>" or "nochg <ip>"
case "$RESPONSE" in
    good*|nochg*) echo "No-IP OK: $RESPONSE" ;;
    *)            echo "No-IP response: $RESPONSE" ;;
esac
