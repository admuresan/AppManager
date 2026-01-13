#!/bin/bash
# Script to check server logs for AppManager and DeltaBooks app

echo "=========================================="
echo "Checking AppManager logs (last 50 lines)"
echo "=========================================="
sudo journalctl -u appmanager -n 50 --no-pager | grep -i "deltabooks\|6002\|500\|error" || echo "No relevant logs found"

echo ""
echo "=========================================="
echo "Checking DeltaBooks app logs (app-6002.service)"
echo "=========================================="
sudo journalctl -u app-6002.service -n 50 --no-pager || echo "Service app-6002.service not found or no logs"

echo ""
echo "=========================================="
echo "Checking Nginx error logs (last 50 lines)"
echo "=========================================="
sudo tail -n 50 /var/log/nginx/error.log | grep -i "deltabooks\|6002\|500\|error" || echo "No relevant logs found"

echo ""
echo "=========================================="
echo "Testing direct connection to port 6002"
echo "=========================================="
curl -v http://localhost:6002/ 2>&1 | head -30

echo ""
echo "=========================================="
echo "Testing proxy connection"
echo "=========================================="
curl -v http://localhost/deltabooks/ 2>&1 | head -50

