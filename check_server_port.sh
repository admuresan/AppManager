#!/bin/bash
# Script to check port 6002 on the server

SERVER_IP="40.233.70.245"
SERVER_USER="ubuntu"
SSH_KEY_DIR="ssh"
SSH_KEY_FILE="ssh-key-2025-12-26.key"
PORT=6002

echo "Checking port $PORT on server $SERVER_IP..."
echo "=========================================="
echo ""

# Check if SSH key exists
if [ ! -f "$SSH_KEY_DIR/$SSH_KEY_FILE" ]; then
    echo "ERROR: SSH key not found at $SSH_KEY_DIR/$SSH_KEY_FILE"
    exit 1
fi

# Set SSH key permissions
chmod 600 "$SSH_KEY_DIR/$SSH_KEY_FILE"

# Build SSH command
SSH_CMD="ssh -i $SSH_KEY_DIR/$SSH_KEY_FILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

echo "1. Testing if port $PORT is listening (socket test)..."
$SSH_CMD ${SERVER_USER}@${SERVER_IP} "python3 -c \"
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1)
result = sock.connect_ex(('localhost', $PORT))
sock.close()
if result == 0:
    print('  [OK] Port $PORT is listening')
else:
    print('  [FAIL] Port $PORT is NOT listening')
\"" || echo "  [ERROR] Could not test port"

echo ""
echo "2. Checking what's using port $PORT..."
$SSH_CMD ${SERVER_USER}@${SERVER_IP} "sudo ss -tlnp | grep :$PORT || echo '  Port $PORT not found in ss output'"

echo ""
echo "3. Checking with netstat..."
$SSH_CMD ${SERVER_USER}@${SERVER_IP} "sudo netstat -tlnp 2>/dev/null | grep :$PORT || echo '  Port $PORT not found in netstat output'"

echo ""
echo "4. Checking with psutil (if available)..."
$SSH_CMD ${SERVER_USER}@${SERVER_IP} "python3 -c \"
import psutil
found = False
for conn in psutil.net_connections(kind='inet'):
    if conn.status == 'LISTEN' and conn.laddr.port == $PORT:
        print('  [OK] Port $PORT found: PID=' + str(conn.pid))
        try:
            proc = psutil.Process(conn.pid)
            print('  Process: ' + proc.name())
            cmdline = proc.cmdline()
            print('  Command: ' + ' '.join(cmdline[:3]) + '...')
        except:
            pass
        found = True
        break
if not found:
    print('  [FAIL] Port $PORT not found with psutil')
\"" || echo "  [ERROR] Could not check with psutil"

echo ""
echo "5. Checking all listening ports (to see if $PORT is in the list)..."
$SSH_CMD ${SERVER_USER}@${SERVER_IP} "sudo ss -tln | grep LISTEN | grep -E ':(600[0-9]|601[0-9]|602[0-9])' | head -20"

echo ""
echo "=========================================="
echo "Check complete!"

