#!/bin/bash
# Deployment script for AppManager
# Deploys to server at http://40.233.70.245/

set -e  # Exit on error

# Configuration
SERVER_IP="40.233.70.245"
SERVER_DOMAIN="blackgrid.ddns.net"
SERVER_USER="ubuntu"  # Server username
DEPLOY_DIR="/opt/appmanager"
SSH_KEY_DIR="ssh"
SSH_KEY_FILE="ssh-key-2025-12-26.key"  # Private key (not git-backed)
VENV_NAME="AMvenv"
SERVICE_NAME="appmanager"
APP_PORT="5000"  # AppManager will run on port 5000, nginx will proxy to it

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}AppManager Deployment Script${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if SSH key exists
if [ ! -f "$SSH_KEY_DIR/$SSH_KEY_FILE" ]; then
    echo -e "${RED}ERROR: SSH key not found at $SSH_KEY_DIR/$SSH_KEY_FILE${NC}"
    echo "Please ensure the SSH private key is in the ssh/ directory"
    echo "(This file should NOT be git-backed)"
    exit 1
fi

# Set SSH key permissions
chmod 600 "$SSH_KEY_DIR/$SSH_KEY_FILE"

# Build SSH command with key
SSH_CMD="ssh -i $SSH_KEY_DIR/$SSH_KEY_FILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SCP_CMD="scp -i $SSH_KEY_DIR/$SSH_KEY_FILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

echo -e "${YELLOW}[1/10] Testing SSH connection...${NC}"
if ! $SSH_CMD ${SERVER_USER}@${SERVER_IP} "echo 'SSH connection successful'"; then
    echo -e "${RED}ERROR: Failed to connect to server${NC}"
    exit 1
fi
echo -e "${GREEN}✓ SSH connection successful${NC}"
echo ""

# Create deployment directory structure on server
echo -e "${YELLOW}[2/10] Setting up deployment directory...${NC}"
$SSH_CMD ${SERVER_USER}@${SERVER_IP} << ENDSSH
    sudo mkdir -p /opt/appmanager
    sudo mkdir -p /opt/appmanager/instance
    sudo mkdir -p /opt/appmanager/instance/uploads/logos
    sudo mkdir -p /opt/appmanager/backups
    sudo chown -R ${SERVER_USER}:${SERVER_USER} /opt/appmanager
    chmod -R 755 /opt/appmanager/instance
ENDSSH
echo -e "${GREEN}✓ Directory structure created${NC}"
echo ""

# Backup existing instance folder if it exists
echo -e "${YELLOW}[3/10] Backing up existing configuration...${NC}"
$SSH_CMD ${SERVER_USER}@${SERVER_IP} << 'ENDSSH'
    if [ -d /opt/appmanager/instance ]; then
        BACKUP_DIR="/opt/appmanager/backups/$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp -r /opt/appmanager/instance/* "$BACKUP_DIR/" 2>/dev/null || true
        echo "Configuration backed up to $BACKUP_DIR"
    else
        echo "No existing configuration to backup"
    fi
ENDSSH
echo -e "${GREEN}✓ Configuration backed up${NC}"
echo ""

# Create temporary directory for deployment files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo -e "${YELLOW}[4/10] Preparing deployment files...${NC}"
# Create tar archive excluding unnecessary files
cd "$(dirname "$0")"
tar --exclude='AMvenv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.git' \
    --exclude='instance' \
    --exclude='*.log' \
    --exclude='.env' \
    --exclude='ssh/*.key' \
    --exclude='backups' \
    -czf "$TEMP_DIR/appmanager.tar.gz" .

# Upload tar archive
$SCP_CMD "$TEMP_DIR/appmanager.tar.gz" ${SERVER_USER}@${SERVER_IP}:/tmp/

# Extract on server
$SSH_CMD ${SERVER_USER}@${SERVER_IP} << ENDSSH
    cd ${DEPLOY_DIR}
    tar -xzf /tmp/appmanager.tar.gz
    rm /tmp/appmanager.tar.gz
    chmod +x *.sh 2>/dev/null || true
ENDSSH

echo -e "${GREEN}✓ Files uploaded${NC}"
echo ""

# Restore instance folder (preserve configurations)
echo -e "${YELLOW}[5/10] Restoring configuration...${NC}"
$SSH_CMD ${SERVER_USER}@${SERVER_IP} << 'ENDSSH'
    # Restore instance folder from backup if it exists
    LATEST_BACKUP=$(ls -td /opt/appmanager/backups/* 2>/dev/null | head -1)
    if [ -n "$LATEST_BACKUP" ] && [ -d "$LATEST_BACKUP" ]; then
        cp -r "$LATEST_BACKUP"/* /opt/appmanager/instance/ 2>/dev/null || true
        echo "Configuration restored from backup"
    else
        echo "No backup found, using fresh configuration"
    fi
    
    # Ensure instance directory structure exists
    mkdir -p /opt/appmanager/instance/uploads/logos
    chmod -R 755 /opt/appmanager/instance
ENDSSH
echo -e "${GREEN}✓ Configuration restored${NC}"
echo ""

# Check and update virtual environment
echo -e "${YELLOW}[6/10] Checking virtual environment...${NC}"
$SSH_CMD ${SERVER_USER}@${SERVER_IP} << ENDSSH
    cd ${DEPLOY_DIR}
    
    # Check if virtual environment exists
    if [ ! -d "${VENV_NAME}" ]; then
        echo "Virtual environment not found. Creating new one..."
        python3 -m venv ${VENV_NAME}
        source ${VENV_NAME}/bin/activate
        pip install --upgrade pip
        pip install -r requirements.txt
        
        # Save requirements file used to create venv
        cp requirements.txt ${VENV_NAME}/requirements_installed.txt
        echo "Virtual environment created"
    else
        echo "Virtual environment exists. Checking if update is needed..."
        
        # Compare current requirements.txt with the one used to create venv
        if [ -f "${VENV_NAME}/requirements_installed.txt" ]; then
            if ! cmp -s requirements.txt ${VENV_NAME}/requirements_installed.txt; then
                echo "Requirements changed. Updating virtual environment..."
                source ${VENV_NAME}/bin/activate
                pip install --upgrade pip
                pip install -r requirements.txt
                
                # Update saved requirements file
                cp requirements.txt ${VENV_NAME}/requirements_installed.txt
                echo "Virtual environment updated"
            else
                echo "Requirements unchanged. Virtual environment is up to date."
            fi
        else
            # No saved requirements file, update to be safe
            echo "No saved requirements file found. Updating virtual environment..."
            source ${VENV_NAME}/bin/activate
            pip install --upgrade pip
            pip install -r requirements.txt
            
            # Save requirements file
            cp requirements.txt ${VENV_NAME}/requirements_installed.txt
            echo "Virtual environment updated"
        fi
    fi
ENDSSH
echo -e "${GREEN}✓ Virtual environment ready${NC}"
echo ""

# Set up OCI configuration
echo -e "${YELLOW}[6.5/10] Setting up OCI configuration...${NC}"

# Check if OCID config file exists locally
OCID_CONFIG_FILE="oci_ssh/OCID_config.json"
if [ ! -f "$OCID_CONFIG_FILE" ]; then
    echo -e "${YELLOW}Warning: OCID_config.json not found at $OCID_CONFIG_FILE${NC}"
    echo "OCI configuration will use placeholders. Please update manually after deployment."
fi

$SSH_CMD ${SERVER_USER}@${SERVER_IP} << ENDSSH
    cd ${DEPLOY_DIR}
    
    # Create .oci directory if it doesn't exist
    mkdir -p ~/.oci
    mkdir -p instance
    
    # Check if SSH private key exists (using the key file name from deployment)
    SSH_KEY_NAME="ssh-key-2025-12-26.key"
    if [ -f "ssh/\${SSH_KEY_NAME}" ]; then
        echo "Found SSH private key, setting up OCI API key..."
        
        # Copy private key to .oci directory as API key
        cp ssh/\${SSH_KEY_NAME} ~/.oci/oci_api_key.pem
        chmod 600 ~/.oci/oci_api_key.pem
        
        # Generate fingerprint from public key
        FINGERPRINT=""
        if [ -f "ssh/\${SSH_KEY_NAME}.pub" ]; then
            # Extract fingerprint from public key (for RSA keys)
            FINGERPRINT=\$(ssh-keygen -lf ssh/\${SSH_KEY_NAME}.pub 2>/dev/null | awk '{print \$2}' || echo "")
            
            if [ -n "\$FINGERPRINT" ]; then
                echo "API key fingerprint: \$FINGERPRINT"
                # Export for Python script
                export FINGERPRINT
            else
                echo "Warning: Could not generate fingerprint from public key"
            fi
        else
            echo "Warning: Public key not found, cannot generate fingerprint"
        fi
        
        # Check if OCID_config.json exists and load values
        USER_OCID=""
        TENANCY_OCID=""
        REGION=""
        COMPARTMENT_OCID=""
        VCN_OCID=""
        
        if [ -f "oci_ssh/OCID_config.json" ]; then
            echo "Found OCID_config.json, loading OCI configuration values..."
            
            # Extract values from JSON (using Python for reliable JSON parsing)
            USER_OCID=\$(python3 -c "import json; f=open('oci_ssh/OCID_config.json'); d=json.load(f); print(d.get('USER_OCID_PLACEHOLDER', ''))" 2>/dev/null || echo "")
            TENANCY_OCID=\$(python3 -c "import json; f=open('oci_ssh/OCID_config.json'); d=json.load(f); print(d.get('TENANCY_OCID_PLACEHOLDER', ''))" 2>/dev/null || echo "")
            REGION=\$(python3 -c "import json; f=open('oci_ssh/OCID_config.json'); d=json.load(f); print(d.get('REGION_PLACEHOLDER', ''))" 2>/dev/null || echo "")
            COMPARTMENT_OCID=\$(python3 -c "import json; f=open('oci_ssh/OCID_config.json'); d=json.load(f); print(d.get('COMPARTMENT_OCID_PLACEHOLDER', ''))" 2>/dev/null || echo "")
            VCN_OCID=\$(python3 -c "import json; f=open('oci_ssh/OCID_config.json'); d=json.load(f); print(d.get('VCN_OCID_PLACEHOLDER', ''))" 2>/dev/null || echo "")
            
            if [ -n "\$USER_OCID" ] && [ -n "\$TENANCY_OCID" ] && [ -n "\$REGION" ]; then
                echo "Successfully loaded OCI configuration from OCID_config.json"
                echo "  User OCID: \${USER_OCID:0:50}..."
                echo "  Tenancy OCID: \${TENANCY_OCID:0:50}..."
                echo "  Region: \$REGION"
                echo "  Compartment OCID: \${COMPARTMENT_OCID:0:50}..."
                echo "  VCN OCID: \${VCN_OCID:0:50}..."
            else
                echo "Warning: Some values missing from OCID_config.json, using placeholders"
            fi
        else
            echo "OCID_config.json not found, using placeholders"
        fi
        
        # Create OCI config in instance folder (JSON format) using Python
        python3 << 'PYTHONSCRIPT' > instance/oci_config.json
import json
import os

# Read values from OCID_config.json if it exists
ocid_config_path = 'oci_ssh/OCID_config.json'
user_ocid = "USER_OCID_PLACEHOLDER"
tenancy_ocid = "TENANCY_OCID_PLACEHOLDER"
region = "REGION_PLACEHOLDER"
compartment_ocid = "COMPARTMENT_OCID_PLACEHOLDER"
vcn_ocid = "VCN_OCID_PLACEHOLDER"

if os.path.exists(ocid_config_path):
    try:
        with open(ocid_config_path, 'r') as f:
            ocid_data = json.load(f)
        user_ocid = ocid_data.get('USER_OCID_PLACEHOLDER', user_ocid)
        tenancy_ocid = ocid_data.get('TENANCY_OCID_PLACEHOLDER', tenancy_ocid)
        region = ocid_data.get('REGION_PLACEHOLDER', region)
        compartment_ocid = ocid_data.get('COMPARTMENT_OCID_PLACEHOLDER', compartment_ocid)
        vcn_ocid = ocid_data.get('VCN_OCID_PLACEHOLDER', vcn_ocid)
    except:
        pass

# Get fingerprint from environment (set above in bash)
fingerprint = os.environ.get('FINGERPRINT', 'FINGERPRINT_PLACEHOLDER')

config = {
    "user": user_ocid,
    "fingerprint": fingerprint,
    "tenancy": tenancy_ocid,
    "region": region,
    "key_file": "~/.oci/oci_api_key.pem",
    "compartment_id": compartment_ocid,
    "vcn_id": vcn_ocid
}

print(json.dumps(config, indent=4))
PYTHONSCRIPT
        
        # Create standard OCI config file format
        cat > ~/.oci/config << 'OCICONFIGFILE'
[DEFAULT]
user=USER_OCID_VALUE
fingerprint=FINGERPRINT_VALUE
tenancy=TENANCY_OCID_VALUE
region=REGION_VALUE
key_file=~/.oci/oci_api_key.pem
OCICONFIGFILE
        
        # Replace placeholders with actual values
        if [ -n "\$USER_OCID" ] && [ "\$USER_OCID" != "USER_OCID_PLACEHOLDER" ]; then
            sed -i "s|USER_OCID_VALUE|\${USER_OCID}|g" ~/.oci/config
        else
            sed -i "s|USER_OCID_VALUE|USER_OCID_PLACEHOLDER|g" ~/.oci/config
        fi
        
        if [ -n "\$FINGERPRINT" ] && [ "\$FINGERPRINT" != "FINGERPRINT_PLACEHOLDER" ]; then
            sed -i "s|FINGERPRINT_VALUE|\${FINGERPRINT}|g" ~/.oci/config
        else
            sed -i "s|FINGERPRINT_VALUE|FINGERPRINT_PLACEHOLDER|g" ~/.oci/config
        fi
        
        if [ -n "\$TENANCY_OCID" ] && [ "\$TENANCY_OCID" != "TENANCY_OCID_PLACEHOLDER" ]; then
            sed -i "s|TENANCY_OCID_VALUE|\${TENANCY_OCID}|g" ~/.oci/config
        else
            sed -i "s|TENANCY_OCID_VALUE|TENANCY_OCID_PLACEHOLDER|g" ~/.oci/config
        fi
        
        if [ -n "\$REGION" ] && [ "\$REGION" != "REGION_PLACEHOLDER" ]; then
            sed -i "s|REGION_VALUE|\${REGION}|g" ~/.oci/config
        else
            sed -i "s|REGION_VALUE|REGION_PLACEHOLDER|g" ~/.oci/config
        fi
        
        chmod 600 ~/.oci/config
        
        # Verify configuration
        if [ -n "\$USER_OCID" ] && [ -n "\$TENANCY_OCID" ] && [ -n "\$REGION" ] && [ -n "\$FINGERPRINT" ]; then
            echo ""
            echo "✓ OCI configuration complete and ready to use!"
            echo "  Configuration files created:"
            echo "    - ~/.oci/config"
            echo "    - instance/oci_config.json"
        else
            echo ""
            echo "⚠ OCI configuration created with placeholders"
            echo "  Please update the following files with your OCI details:"
            echo "    - ~/.oci/config"
            echo "    - instance/oci_config.json"
            echo ""
            echo "  Required values:"
            echo "    - USER_OCID_PLACEHOLDER: Your OCI user OCID"
            echo "    - TENANCY_OCID_PLACEHOLDER: Your OCI tenancy OCID"
            echo "    - REGION_PLACEHOLDER: Your OCI region (e.g., ca-toronto-1)"
            echo "    - FINGERPRINT_PLACEHOLDER: API key fingerprint"
            echo "    - COMPARTMENT_OCID_PLACEHOLDER: Your compartment OCID"
            echo "    - VCN_OCID_PLACEHOLDER: Your VCN OCID"
        fi
    else
        echo "SSH private key not found, skipping OCI setup"
        echo "To set up OCI later:"
        echo "  1. Copy your OCI API private key to ~/.oci/oci_api_key.pem"
        echo "  2. Create ~/.oci/config with your OCI credentials"
        echo "  3. Create instance/oci_config.json with compartment_id and vcn_id"
    fi
ENDSSH
echo -e "${GREEN}✓ OCI configuration setup complete${NC}"
echo ""

# Create or update systemd service
echo -e "${YELLOW}[7/10] Setting up systemd service...${NC}"
$SSH_CMD ${SERVER_USER}@${SERVER_IP} << ENDSSH
    # Create systemd service file
    cat > /tmp/${SERVICE_NAME}.service << EOFSERVICE
[Unit]
Description=AppManager Gateway Application
After=network.target

[Service]
Type=simple
User=${SERVER_USER}
Group=${SERVER_USER}
WorkingDirectory=${DEPLOY_DIR}
Environment="SECRET_KEY=\${SECRET_KEY:-dev-secret-key-change-in-production}"
Environment="PORT=${APP_PORT}"
Environment="FLASK_ENV=production"
Environment="SERVER_ADDRESS=${SERVER_IP}"
Environment="SERVER_DOMAIN=blackgrid.ddns.net"
ExecStart=${DEPLOY_DIR}/${VENV_NAME}/bin/python ${DEPLOY_DIR}/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOFSERVICE
    
    # Install service file
    sudo mv /tmp/${SERVICE_NAME}.service /etc/systemd/system/${SERVICE_NAME}.service
    sudo chmod 644 /etc/systemd/system/${SERVICE_NAME}.service
    
    # Reload systemd and restart service
    sudo systemctl daemon-reload
    sudo systemctl enable ${SERVICE_NAME}
    sudo systemctl restart ${SERVICE_NAME}
    
    # Wait a moment for service to start
    sleep 2
    
    # Check service status
    if sudo systemctl is-active --quiet ${SERVICE_NAME}; then
        echo "Service started successfully"
    else
        echo "WARNING: Service may not have started properly"
        sudo systemctl status ${SERVICE_NAME} --no-pager || true
    fi
ENDSSH
echo -e "${GREEN}✓ Service configured and started${NC}"
echo ""

# Configure SSL certificates and nginx
echo -e "${YELLOW}[8/10] Configuring SSL certificates and nginx...${NC}"

# Create nginx config entirely on remote server (simplified approach like quizia)
$SSH_CMD ${SERVER_USER}@${SERVER_IP} << ENDSSH
    SERVER_IP="${SERVER_IP}"
    SERVER_DOMAIN="${SERVER_DOMAIN}"
    APP_PORT="${APP_PORT}"
    
    # Determine SSL certificate paths
    SSL_CERT=""
    SSL_KEY=""
    USE_LETSENCRYPT=false
    
    # Check for Let's Encrypt certificates (preferred - check domain first, then IP)
    # Also check if certbot is available and try to set up Let's Encrypt automatically
    USE_LETSENCRYPT=false
    
    # Use sudo to check certificate files (they're in protected directory)
    if sudo [ -d "/etc/letsencrypt/live/\${SERVER_DOMAIN}" ] && sudo [ -f "/etc/letsencrypt/live/\${SERVER_DOMAIN}/fullchain.pem" ] && sudo [ -f "/etc/letsencrypt/live/\${SERVER_DOMAIN}/privkey.pem" ]; then
        SSL_CERT="/etc/letsencrypt/live/\${SERVER_DOMAIN}/fullchain.pem"
        SSL_KEY="/etc/letsencrypt/live/\${SERVER_DOMAIN}/privkey.pem"
        USE_LETSENCRYPT=true
        echo "Using Let's Encrypt certificates (domain-based)"
    elif sudo [ -d "/etc/letsencrypt/live/\${SERVER_IP}" ] && sudo [ -f "/etc/letsencrypt/live/\${SERVER_IP}/fullchain.pem" ] && sudo [ -f "/etc/letsencrypt/live/\${SERVER_IP}/privkey.pem" ]; then
        SSL_CERT="/etc/letsencrypt/live/\${SERVER_IP}/fullchain.pem"
        SSL_KEY="/etc/letsencrypt/live/\${SERVER_IP}/privkey.pem"
        USE_LETSENCRYPT=true
        echo "Using Let's Encrypt certificates (IP-based)"
    elif command -v certbot > /dev/null && [ "\${SERVER_DOMAIN}" != "localhost" ] && [ "\${SERVER_DOMAIN}" != "127.0.0.1" ]; then
        # Try to obtain Let's Encrypt certificate automatically
        echo "Let's Encrypt certificate not found. Attempting to obtain certificate for \${SERVER_DOMAIN}..."
        
        # Stop nginx temporarily to free port 80 for standalone certbot
        if sudo systemctl is-active --quiet nginx; then
            sudo systemctl stop nginx 2>/dev/null || true
            nginx_was_running=true
        else
            nginx_was_running=false
        fi
        
        # Check if certificate already exists first (use sudo to check protected directory)
        if sudo [ -f "/etc/letsencrypt/live/\${SERVER_DOMAIN}/fullchain.pem" ] && sudo [ -f "/etc/letsencrypt/live/\${SERVER_DOMAIN}/privkey.pem" ]; then
            SSL_CERT="/etc/letsencrypt/live/\${SERVER_DOMAIN}/fullchain.pem"
            SSL_KEY="/etc/letsencrypt/live/\${SERVER_DOMAIN}/privkey.pem"
            USE_LETSENCRYPT=true
            echo "✓ Let's Encrypt certificate already exists for \${SERVER_DOMAIN}"
            echo "Certificate location: \$SSL_CERT"
        else
            # Try to get certificate using standalone mode (doesn't require nginx config)
            # This will fail gracefully if domain doesn't resolve or port 80 is not accessible
            echo "Attempting to obtain new Let's Encrypt certificate..."
            CERTBOT_OUTPUT=\$(sudo certbot certonly --standalone -d \${SERVER_DOMAIN} --non-interactive --agree-tos --register-unsafely-without-email --preferred-challenges http 2>&1)
            CERTBOT_EXIT_CODE=\$?
            
            # Check if certificate exists after certbot run (use sudo to check)
            # Certbot might say "not yet due for renewal" (exit 0) which means cert already exists
            if sudo [ -f "/etc/letsencrypt/live/\${SERVER_DOMAIN}/fullchain.pem" ] && sudo [ -f "/etc/letsencrypt/live/\${SERVER_DOMAIN}/privkey.pem" ]; then
                SSL_CERT="/etc/letsencrypt/live/\${SERVER_DOMAIN}/fullchain.pem"
                SSL_KEY="/etc/letsencrypt/live/\${SERVER_DOMAIN}/privkey.pem"
                USE_LETSENCRYPT=true
                if echo "\$CERTBOT_OUTPUT" | grep -q "Successfully received certificate"; then
                    echo "✓ Successfully obtained new Let's Encrypt certificate for \${SERVER_DOMAIN}"
                elif echo "\$CERTBOT_OUTPUT" | grep -q "not yet due for renewal"; then
                    echo "✓ Let's Encrypt certificate already exists (not due for renewal)"
                else
                    echo "✓ Using existing Let's Encrypt certificate for \${SERVER_DOMAIN}"
                fi
                echo "Certificate location: \$SSL_CERT"
            elif [ \$CERTBOT_EXIT_CODE -eq 0 ] && echo "\$CERTBOT_OUTPUT" | grep -q "not yet due for renewal"; then
                # Certbot said cert exists - trust certbot and use it even if we can't directly verify files
                # This handles the case where certbot confirms cert exists but we can't access the directory
                SSL_CERT="/etc/letsencrypt/live/\${SERVER_DOMAIN}/fullchain.pem"
                SSL_KEY="/etc/letsencrypt/live/\${SERVER_DOMAIN}/privkey.pem"
                USE_LETSENCRYPT=true
                echo "✓ Let's Encrypt certificate exists (certbot confirmed - not due for renewal)"
                echo "Certificate location: \$SSL_CERT"
            else
                echo "Could not obtain Let's Encrypt certificate"
                echo "Exit code: \$CERTBOT_EXIT_CODE"
                echo "Certbot output: \$CERTBOT_OUTPUT"
                echo ""
                echo "Common reasons:"
                echo "  - Domain \${SERVER_DOMAIN} does not resolve to this server's IP"
                echo "  - Port 80 is not accessible from the internet"
                echo "  - Rate limited by Let's Encrypt (too many requests)"
                echo ""
                echo "You can set it up manually later with:"
                echo "  sudo certbot certonly --standalone -d \${SERVER_DOMAIN} --non-interactive --agree-tos --register-unsafely-without-email"
            fi
        fi
        
        # Restart nginx if it was running
        if [ "\$nginx_was_running" = "true" ]; then
            sudo systemctl start nginx 2>/dev/null || true
        fi
    fi
    
    # Require Let's Encrypt certificate - no fallback to self-signed
    if [ "\$USE_LETSENCRYPT" != "true" ]; then
        echo ""
        echo "ERROR: Let's Encrypt certificate is required but could not be obtained."
        echo ""
        echo "To set up Let's Encrypt manually, run on the server:"
        echo "  sudo certbot certonly --standalone -d \${SERVER_DOMAIN} --non-interactive --agree-tos --register-unsafely-without-email"
        echo ""
        echo "Requirements:"
        echo "  - Domain \${SERVER_DOMAIN} must resolve to this server's IP (\${SERVER_IP})"
        echo "  - Port 80 must be accessible from the internet"
        echo "  - certbot must be installed (sudo apt-get install certbot)"
        echo ""
        echo "After obtaining the certificate, run this deployment script again."
        exit 1
    fi
    
    # Verify SSL certificate and key are set
    if [ -z "\$SSL_CERT" ] || [ -z "\$SSL_KEY" ]; then
        echo "ERROR: SSL certificate or key not set!"
        exit 1
    fi
    
    # Verify certificate files actually exist (use sudo for protected directories)
    if ! sudo [ -f "\$SSL_CERT" ] || ! sudo [ -f "\$SSL_KEY" ]; then
        echo "ERROR: SSL certificate files not found!"
        echo "Expected certificate: \$SSL_CERT"
        echo "Expected key: \$SSL_KEY"
        echo ""
        echo "Checking certificate location..."
        sudo ls -la \$(dirname "\$SSL_CERT") 2>&1 || echo "Could not list certificate directory"
        exit 1
    fi
    
    echo "SSL Certificate: \$SSL_CERT"
    echo "SSL Key: \$SSL_KEY"
    echo "Certificate verified and ready to use"
    
    # Create nginx config file directly on server using placeholders
    # Use domain as primary, IP as fallback (removed _ catch-all to avoid conflicts)
    sudo tee /tmp/appmanager_nginx.conf > /dev/null << 'NGINXCONF'
# HTTP server - redirect to HTTPS
server {
    listen 80;
    server_name DOMAIN_PLACEHOLDER SERVER_IP_PLACEHOLDER;
    
    # Allow Let's Encrypt ACME challenge
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }
    
    # Redirect all other HTTP to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

# HTTPS server - proxy to AppManager
server {
    listen 443 ssl http2;
    server_name DOMAIN_PLACEHOLDER SERVER_IP_PLACEHOLDER;

    # SSL certificates (will be replaced with actual paths)
    ssl_certificate CERT_PLACEHOLDER;
    ssl_certificate_key KEY_PLACEHOLDER;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
NGINXCONF
    
    # Replace placeholders with actual values
    sudo sed -i "s|DOMAIN_PLACEHOLDER|\${SERVER_DOMAIN}|g" /tmp/appmanager_nginx.conf
    sudo sed -i "s|SERVER_IP_PLACEHOLDER|\${SERVER_IP}|g" /tmp/appmanager_nginx.conf
    sudo sed -i "s|CERT_PLACEHOLDER|\${SSL_CERT}|g" /tmp/appmanager_nginx.conf
    sudo sed -i "s|KEY_PLACEHOLDER|\${SSL_KEY}|g" /tmp/appmanager_nginx.conf
    
    # Add OCSP stapling if using Let's Encrypt
    if [ "\$USE_LETSENCRYPT" = "true" ]; then
        # Determine Let's Encrypt path (prefer domain, fallback to IP)
        # Use sudo to check directory (protected location)
        if sudo [ -d "/etc/letsencrypt/live/\${SERVER_DOMAIN}" ]; then
            LE_CHAIN="/etc/letsencrypt/live/\${SERVER_DOMAIN}/chain.pem"
        elif sudo [ -d "/etc/letsencrypt/live/\${SERVER_IP}" ]; then
            LE_CHAIN="/etc/letsencrypt/live/\${SERVER_IP}/chain.pem"
        else
            LE_CHAIN=""
        fi
        
        # Only add OCSP stapling if chain file exists
        if [ -n "\$LE_CHAIN" ] && sudo [ -f "\$LE_CHAIN" ]; then
            sudo tee -a /tmp/appmanager_nginx.conf > /dev/null << OCSPCONF
    # OCSP stapling (Let's Encrypt)
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate \$LE_CHAIN;
OCSPCONF
        fi
    fi
    
    # Add security headers and proxy configuration
    sudo tee -a /tmp/appmanager_nginx.conf > /dev/null << 'PROXYCONF'
    
    # Increase upload size limit (for logo uploads up to 20MB)
    client_max_body_size 20m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Proxy to AppManager
    location / {
        proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
PROXYCONF
    
    # Replace APP_PORT placeholder
    sudo sed -i "s|APP_PORT_PLACEHOLDER|\${APP_PORT}|g" /tmp/appmanager_nginx.conf
    
    # Backup existing nginx config
    if [ -f /etc/nginx/sites-enabled/default ]; then
        sudo cp /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.backup.\$(date +%Y%m%d_%H%M%S)
    fi
    
    # Move config to final location
    sudo mv /tmp/appmanager_nginx.conf /etc/nginx/sites-available/appmanager
    
    # Remove any existing configs that might conflict with our server_name
    # Check for configs using the same IP or domain
    for config in /etc/nginx/sites-enabled/*; do
        if [ -f "\$config" ] && [ "\$config" != "/etc/nginx/sites-enabled/appmanager" ]; then
            # Check if this config uses the same server_name
            if grep -q "server_name.*\${SERVER_IP}" "\$config" 2>/dev/null || grep -q "server_name.*\${SERVER_DOMAIN}" "\$config" 2>/dev/null; then
                echo "Removing conflicting nginx config: \$(basename \$config)"
                sudo rm -f "\$config"
            fi
        fi
    done
    
    # Enable the site
    sudo ln -sf /etc/nginx/sites-available/appmanager /etc/nginx/sites-enabled/appmanager
    
    # Disable old calculator site if it exists
    if [ -f /etc/nginx/sites-enabled/calculator ]; then
        sudo rm /etc/nginx/sites-enabled/calculator
        echo "Disabled old calculator nginx site"
    fi
    
    # Remove old default site if it exists and is different
    if [ -f /etc/nginx/sites-enabled/default ] && [ ! -L /etc/nginx/sites-enabled/default ]; then
        sudo rm /etc/nginx/sites-enabled/default
    fi
    
    # Test nginx configuration
    if sudo nginx -t; then
        sudo systemctl reload nginx
        echo "Nginx configured and reloaded successfully"
        if [ "\$USE_LETSENCRYPT" = "true" ]; then
            echo "Using Let's Encrypt certificates (auto-renewing)"
        else
            echo "ERROR: Let's Encrypt certificate is required but not available"
            exit 1
        fi
    else
        echo "ERROR: Nginx configuration test failed"
        sudo nginx -t
        exit 1
    fi
    
    # Ensure firewall allows HTTP and HTTPS
    echo "Configuring firewall for HTTP and HTTPS..."
    sudo ufw allow 80/tcp 2>/dev/null || sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || echo "Firewall rule for port 80 may need manual configuration"
    sudo ufw allow 443/tcp 2>/dev/null || sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || echo "Firewall rule for port 443 may need manual configuration"
    echo "Firewall configured for ports 80 and 443"
ENDSSH
echo -e "${GREEN}✓ Nginx configured with SSL${NC}"
echo ""

# Offer to set up Let's Encrypt if not already configured
echo -e "${YELLOW}SSL Certificate Setup:${NC}"
$SSH_CMD ${SERVER_USER}@${SERVER_IP} << ENDSSH
    SERVER_DOMAIN="${SERVER_DOMAIN}"
    SERVER_IP="${SERVER_IP}"
    
    if [ ! -d "/etc/letsencrypt/live/\${SERVER_DOMAIN}" ] && [ ! -d "/etc/letsencrypt/live/\${SERVER_IP}" ]; then
        if command -v certbot > /dev/null; then
            echo ""
            echo "Let's Encrypt is available but not configured."
            echo ""
            echo -e "${YELLOW}Attempting to set up Let's Encrypt certificate for \${SERVER_DOMAIN}...${NC}"
            echo ""
            
            # Attempt automatic Let's Encrypt setup using --nginx mode (requires nginx to be configured)
            CERTBOT_RESULT=\$(sudo certbot --nginx -d \${SERVER_DOMAIN} --non-interactive --agree-tos --register-unsafely-without-email 2>&1)
            CERTBOT_EXIT=\$?
            
            # Check if certificate was successfully obtained
            if [ \$CERTBOT_EXIT -eq 0 ] && [ -f "/etc/letsencrypt/live/\${SERVER_DOMAIN}/fullchain.pem" ]; then
                echo ""
                echo -e "${GREEN}✓ Let's Encrypt certificate successfully obtained!${NC}"
                echo "Reloading nginx to use the new certificate..."
                sudo systemctl reload nginx
                echo -e "${GREEN}✓ SSL certificate is now trusted by browsers!${NC}"
            else
                echo ""
                echo -e "${YELLOW}Automatic Let's Encrypt setup failed.${NC}"
                echo "Exit code: \$CERTBOT_EXIT"
                echo "Output: \$CERTBOT_RESULT"
                echo ""
                echo "This is normal if:"
                echo "  - The domain doesn't point to this server yet"
                echo "  - Port 80 is not accessible from the internet"
                echo "  - DNS propagation hasn't completed"
                echo "  - Rate limited by Let's Encrypt"
                echo ""
                echo "To set up Let's Encrypt manually later, SSH into the server and run:"
                echo "  sudo certbot certonly --standalone -d \${SERVER_DOMAIN} --non-interactive --agree-tos --register-unsafely-without-email"
                echo ""
                echo "Or visit the admin panel and use the SSL certificate setup feature."
            fi
        else
            echo ""
            echo "certbot is not installed. To install it, run on the server:"
            echo "  sudo apt-get update && sudo apt-get install -y certbot python3-certbot-nginx"
            echo ""
            echo "Then set up Let's Encrypt with:"
            echo "  sudo certbot --nginx -d \${SERVER_DOMAIN}"
        fi
    else
        echo -e "${GREEN}✓ Let's Encrypt certificate is already configured!${NC}"
    fi
ENDSSH
echo ""

# Test website accessibility using domain name
echo -e "${YELLOW}[9/10] Testing website accessibility...${NC}"
echo ""

# Initialize test result variables
HTTP_WORKING=false
HTTPS_WORKING=false
ADMIN_WORKING=false
CERT_TYPE="unknown"

# Test HTTP using domain name
echo -e "${YELLOW}Testing HTTP via ${SERVER_DOMAIN} (should redirect to HTTPS)...${NC}"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 --insecure http://${SERVER_DOMAIN}/ 2>/dev/null || echo "000")
HTTP_REDIRECT=$(curl -s -o /dev/null -w "%{redirect_url}" --max-time 10 --insecure -L http://${SERVER_DOMAIN}/ 2>/dev/null || echo "")

if [ "$HTTP_STATUS" = "301" ] || [ "$HTTP_STATUS" = "302" ] || [ "$HTTP_STATUS" = "200" ]; then
    echo -e "${GREEN}✓ HTTP is accessible via ${SERVER_DOMAIN} (status: $HTTP_STATUS)${NC}"
    HTTP_WORKING=true
    if [ -n "$HTTP_REDIRECT" ]; then
        echo "  Redirects to: $HTTP_REDIRECT"
    fi
else
    echo -e "${YELLOW}⚠ HTTP test via ${SERVER_DOMAIN} returned status: $HTTP_STATUS${NC}"
    echo "  (This may be normal if the server is still starting up or DNS hasn't propagated)"
fi

echo ""

# Test HTTPS using domain name
echo -e "${YELLOW}Testing HTTPS via ${SERVER_DOMAIN}...${NC}"
HTTPS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 --insecure https://${SERVER_DOMAIN}/ 2>/dev/null || echo "000")

if [ "$HTTPS_STATUS" = "200" ]; then
    echo -e "${GREEN}✓ HTTPS is accessible via ${SERVER_DOMAIN} (status: $HTTPS_STATUS)${NC}"
    HTTPS_WORKING=true
    HTTPS_CONTENT=$(curl -s --max-time 10 --insecure https://${SERVER_DOMAIN}/ 2>/dev/null | head -c 100 || echo "")
    if echo "$HTTPS_CONTENT" | grep -q -i "appmanager\|welcome\|html"; then
        echo -e "${GREEN}✓ Website content is being served correctly${NC}"
    fi
elif [ "$HTTPS_STATUS" = "000" ]; then
    echo -e "${RED}✗ HTTPS connection via ${SERVER_DOMAIN} failed (timeout or connection refused)${NC}"
    echo "  This may indicate:"
    echo "    - Nginx is not running"
    echo "    - SSL certificate issue"
    echo "    - Firewall blocking port 443"
    echo "    - DNS not resolving to server IP"
    echo "    - Service is still starting up"
else
    echo -e "${YELLOW}⚠ HTTPS via ${SERVER_DOMAIN} returned status: $HTTPS_STATUS${NC}"
    echo "  (This may indicate an issue with the application or configuration)"
fi

echo ""

# Test admin endpoint using domain name
echo -e "${YELLOW}Testing admin endpoint via ${SERVER_DOMAIN}...${NC}"
ADMIN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 --insecure https://${SERVER_DOMAIN}/admin/login 2>/dev/null || echo "000")
if [ "$ADMIN_STATUS" = "200" ]; then
    echo -e "${GREEN}✓ Admin login page is accessible via ${SERVER_DOMAIN}${NC}"
    ADMIN_WORKING=true
else
    echo -e "${YELLOW}⚠ Admin login page via ${SERVER_DOMAIN} returned status: $ADMIN_STATUS${NC}"
fi

echo ""

# Check certificate type (use sudo for protected directories)
echo -e "${YELLOW}Checking SSL certificate type...${NC}"
CERT_TYPE_INFO=$($SSH_CMD ${SERVER_USER}@${SERVER_IP} << ENDSSH
    if sudo [ -f "/etc/letsencrypt/live/${SERVER_DOMAIN}/fullchain.pem" ]; then
        echo "letsencrypt"
    elif sudo [ -f "/etc/letsencrypt/live/${SERVER_IP}/fullchain.pem" ]; then
        echo "letsencrypt-ip"
    else
        echo "none"
    fi
ENDSSH
)

CERT_TYPE=$(echo "$CERT_TYPE_INFO" | tail -1 | tr -d '[:space:]')

case "$CERT_TYPE" in
    letsencrypt)
        echo -e "${GREEN}✓ Using Let's Encrypt certificate (trusted by browsers)${NC}"
        ;;
    letsencrypt-ip)
        echo -e "${GREEN}✓ Using Let's Encrypt certificate (IP-based)${NC}"
        ;;
    *)
        echo -e "${RED}✗ No Let's Encrypt certificate found${NC}"
        echo -e "${YELLOW}  SSL certificate is required - set up Let's Encrypt to continue${NC}"
        ;;
esac

echo ""

# Final status check
echo -e "${YELLOW}Checking deployment status...${NC}"
$SSH_CMD ${SERVER_USER}@${SERVER_IP} << ENDSSH
    echo "Service status:"
    sudo systemctl status ${SERVICE_NAME} --no-pager -l || true
    echo ""
    echo "Recent logs:"
    sudo journalctl -u ${SERVICE_NAME} -n 20 --no-pager || true
ENDSSH

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Final Summary
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}DEPLOYMENT SUMMARY${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}Connection Tests:${NC}"
if [ "$HTTP_WORKING" = "true" ]; then
    echo -e "  ${GREEN}✓ HTTP via ${SERVER_DOMAIN} - Working${NC}"
else
    echo -e "  ${RED}✗ HTTP via ${SERVER_DOMAIN} - Not accessible${NC}"
fi

if [ "$HTTPS_WORKING" = "true" ]; then
    echo -e "  ${GREEN}✓ HTTPS via ${SERVER_DOMAIN} - Working${NC}"
else
    echo -e "  ${RED}✗ HTTPS via ${SERVER_DOMAIN} - Not accessible${NC}"
fi

if [ "$ADMIN_WORKING" = "true" ]; then
    echo -e "  ${GREEN}✓ Admin endpoint via ${SERVER_DOMAIN} - Working${NC}"
else
    echo -e "  ${YELLOW}⚠ Admin endpoint via ${SERVER_DOMAIN} - May need checking${NC}"
fi

echo ""
echo -e "${YELLOW}SSL Certificate:${NC}"
case "$CERT_TYPE" in
    letsencrypt)
        echo -e "  ${GREEN}✓ Let's Encrypt (Domain-based) - Trusted by browsers${NC}"
        ;;
    letsencrypt-ip)
        echo -e "  ${GREEN}✓ Let's Encrypt (IP-based) - Trusted by browsers${NC}"
        ;;
    *)
        echo -e "  ${RED}✗ No Let's Encrypt certificate found - SSL will not work${NC}"
        echo -e "  ${YELLOW}  Set up Let's Encrypt certificate to continue${NC}"
        ;;
esac

echo ""
echo -e "${YELLOW}Access URLs:${NC}"
echo -e "  Main site: ${GREEN}https://${SERVER_DOMAIN}${NC}"
echo -e "  Admin login: ${GREEN}https://${SERVER_DOMAIN}/admin/login${NC}"
echo ""
echo -e "  ${YELLOW}(Also accessible via IP: https://${SERVER_IP})${NC}"
echo ""

echo -e "${YELLOW}Admin Credentials:${NC}"
echo "  Username: LastTerminal"
echo "  Password: WhiteMage"
echo ""

if [ "$HTTPS_WORKING" = "true" ] && [ "$CERT_TYPE" = "letsencrypt" ]; then
    echo -e "${GREEN}✓✓✓ All systems operational with trusted SSL certificate! ✓✓✓${NC}"
elif [ "$HTTPS_WORKING" = "true" ] && [ "$CERT_TYPE" = "letsencrypt-ip" ]; then
    echo -e "${GREEN}✓ Deployment successful - HTTPS is working with Let's Encrypt (IP-based)${NC}"
elif [ "$HTTPS_WORKING" = "true" ]; then
    # HTTPS is working but certificate type couldn't be determined (likely permission issue)
    echo -e "${GREEN}✓ Deployment successful - HTTPS is working${NC}"
    echo -e "${YELLOW}  Note: Certificate type detection had issues, but HTTPS is functioning correctly${NC}"
else
    echo -e "${YELLOW}⚠ Deployment completed but HTTPS is not accessible${NC}"
    echo -e "${YELLOW}  Check firewall rules, DNS configuration, and Let's Encrypt certificate setup${NC}"
fi

echo ""
echo -e "${YELLOW}Useful Commands:${NC}"
echo "  Check service status:"
echo "    ssh -i $SSH_KEY_DIR/$SSH_KEY_FILE ${SERVER_USER}@${SERVER_IP} 'sudo systemctl status ${SERVICE_NAME}'"
echo ""
echo "  View logs:"
echo "    ssh -i $SSH_KEY_DIR/$SSH_KEY_FILE ${SERVER_USER}@${SERVER_IP} 'sudo journalctl -u ${SERVICE_NAME} -f'"
echo ""
echo "  Set up Let's Encrypt (if not already done):"
echo "    ssh -i $SSH_KEY_DIR/$SSH_KEY_FILE ${SERVER_USER}@${SERVER_IP} 'sudo certbot --nginx -d ${SERVER_DOMAIN}'"
echo ""

