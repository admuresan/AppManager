#!/bin/bash
# Script to check AppManager logs for proxy errors related to deltabooks

echo "=========================================="
echo "Checking AppManager logs for proxy errors (last 100 lines)"
echo "=========================================="
sudo journalctl -u appmanager -n 100 --no-pager | grep -i "proxy\|deltabooks\|6002\|error\|exception" || echo "No relevant logs found"

echo ""
echo "=========================================="
echo "Checking for recent 500 errors"
echo "=========================================="
sudo journalctl -u appmanager -n 200 --no-pager | grep -i "500\|internal\|server error" || echo "No 500 errors found"

echo ""
echo "=========================================="
echo "Full recent AppManager logs (last 50 lines)"
echo "=========================================="
sudo journalctl -u appmanager -n 50 --no-pager

echo ""
echo "=========================================="
echo "Testing direct connection to port 6002"
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://localhost:6002/ || echo "Connection failed"

echo ""
echo "=========================================="
echo "Testing proxy route (if AppManager is running)"
echo "=========================================="
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://localhost/deltabooks/ 2>&1 | head -5 || echo "Proxy test failed"

