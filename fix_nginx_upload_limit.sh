#!/bin/bash
# Quick fix script to update nginx client_max_body_size for existing deployments
# Run this on the server or via SSH

SERVER_IP="40.233.70.245"
SERVER_USER="ubuntu"
SSH_KEY_DIR="ssh"
SSH_KEY_FILE="ssh-key-2025-12-26.key"

# Build SSH command with key
SSH_CMD="ssh -i $SSH_KEY_DIR/$SSH_KEY_FILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

echo "Updating nginx configuration to allow 20MB uploads..."

$SSH_CMD ${SERVER_USER}@${SERVER_IP} << 'ENDSSH'
    # Backup current nginx config
    if [ -f /etc/nginx/sites-available/appmanager ]; then
        sudo cp /etc/nginx/sites-available/appmanager /etc/nginx/sites-available/appmanager.backup.$(date +%Y%m%d_%H%M%S)
        echo "Backed up existing nginx config"
    fi
    
    # Check if client_max_body_size already exists
    if grep -q "client_max_body_size" /etc/nginx/sites-available/appmanager; then
        echo "Updating existing client_max_body_size setting..."
        sudo sed -i 's/client_max_body_size.*/client_max_body_size 20m;/' /etc/nginx/sites-available/appmanager
    else
        echo "Adding client_max_body_size setting..."
        # Find the line with security headers and add client_max_body_size before it
        sudo sed -i '/# Security headers/i\    # Increase upload size limit (for logo uploads up to 20MB)\n    client_max_body_size 20m;\n' /etc/nginx/sites-available/appmanager
    fi
    
    # Test nginx configuration
    if sudo nginx -t; then
        echo "Nginx configuration is valid. Reloading nginx..."
        sudo systemctl reload nginx
        echo "✓ Nginx reloaded successfully!"
        echo "Upload limit is now set to 20MB"
    else
        echo "ERROR: Nginx configuration test failed!"
        sudo nginx -t
        echo "Restoring backup..."
        LATEST_BACKUP=$(ls -t /etc/nginx/sites-available/appmanager.backup.* 2>/dev/null | head -1)
        if [ -n "$LATEST_BACKUP" ]; then
            sudo cp "$LATEST_BACKUP" /etc/nginx/sites-available/appmanager
            echo "Backup restored"
        fi
        exit 1
    fi
ENDSSH

echo ""
echo "Done! The nginx upload limit has been updated to 20MB."
echo "You can now upload image files up to 20MB in size."


