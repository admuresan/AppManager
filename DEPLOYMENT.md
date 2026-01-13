# Deployment Guide for AppManager

This guide covers deploying AppManager to a production server.

## Prerequisites

- Ubuntu/Debian server (or similar Linux distribution)
- Python 3.8+
- sudo/root access
- SSH access to the server

## Step 1: Server Setup

### Install System Dependencies

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv nginx git
```

## Step 2: Deploy Application

### Clone or Upload Application

```bash
cd /opt
sudo git clone <your-repo-url> appmanager
# OR upload via SCP/FTP
```

### Set Permissions

```bash
sudo chown -R $USER:$USER /opt/appmanager
cd /opt/appmanager
```

### Create Virtual Environment (Optional but Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Step 3: Configure Application

### Set Environment Variables

Create a `.env` file or export variables:

```bash
export SECRET_KEY="your-very-secure-secret-key-here"
export PORT=80
export FLASK_ENV=production
```

### Initialize Instance Folder

The instance folder will be created automatically, but ensure it has proper permissions:

```bash
mkdir -p instance/uploads/logos
chmod 755 instance
chmod 755 instance/uploads
chmod 755 instance/uploads/logos
```

### Change Default Admin Password

After first run, edit `instance/admin_config.json` or use the admin panel to change the password.

## Step 4: Create Systemd Service

Create `/etc/systemd/system/appmanager.service`:

```ini
[Unit]
Description=AppManager Gateway Application
After=network.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/appmanager
Environment="SECRET_KEY=your-secret-key-here"
Environment="PORT=80"
Environment="FLASK_ENV=production"
ExecStart=/usr/bin/python3 /opt/appmanager/run.py
# OR if using venv:
# ExecStart=/opt/appmanager/venv/bin/python /opt/appmanager/run.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Enable and Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable appmanager
sudo systemctl start appmanager
sudo systemctl status appmanager
```

## Step 5: Configure Nginx (Optional - for HTTPS)

If you want to use HTTPS or have AppManager behind Nginx:

### Install Certbot (for Let's Encrypt)

```bash
sudo apt-get install -y certbot python3-certbot-nginx
```

### Configure Nginx

Create `/etc/nginx/sites-available/appmanager`:

```nginx
# HTTP - redirect to HTTPS
server {
    listen 80;
    server_name your-domain.com;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Increase upload size limit (for logo uploads)
    client_max_body_size 20m;
    
    # Proxy to AppManager
    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Enable Site and Get SSL Certificate

```bash
sudo ln -s /etc/nginx/sites-available/appmanager /etc/nginx/sites-enabled/
sudo nginx -t
sudo certbot --nginx -d your-domain.com
sudo systemctl reload nginx
```

## Step 6: Configure Firewall

```bash
# Allow HTTP
sudo ufw allow 80/tcp

# Allow HTTPS (if using)
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable
```

## Step 7: Adding Your Apps

1. Ensure your Flask apps are running on their internal ports (e.g., 5001, 6005, 6002)
2. Log in to AppManager admin panel at `http://your-server/admin/login`
3. Add each app with:
   - App name
   - Internal port
   - Service name (if using systemd)
   - Optional logo

## Step 8: Verify Deployment

1. Visit `http://your-server` - should see welcome page
2. Log in to admin panel - should see dashboard
3. Add a test app and verify it appears on welcome page
4. Select an app and verify proxy routing works

## Troubleshooting

### Check Logs

```bash
# Application logs
sudo journalctl -u appmanager -f

# Nginx logs
sudo tail -f /var/log/nginx/error.log
sudo tail -f /var/log/nginx/access.log
```

### Common Issues

1. **Port 80 already in use**: Change AppManager port or stop conflicting service
2. **Permission denied**: Check file ownership and service user
3. **Apps not accessible**: Verify apps are running on their configured ports
4. **Restart not working**: Ensure service name is correct and sudo permissions are configured

## Updating Application

```bash
cd /opt/appmanager
git pull  # or upload new files
sudo systemctl restart appmanager
```

## Backup

Important files to backup:
- `instance/admin_config.json` - Admin credentials
- `instance/apps_config.json` - App configurations
- `instance/uploads/` - Uploaded logos

```bash
tar -czf appmanager-backup-$(date +%Y%m%d).tar.gz instance/
```

