# Instructions for Deploying Apps

This guide is for developers and deployment agents writing scripts to deploy applications that will be managed by AppManager. Follow these instructions to ensure your apps integrate smoothly with the AppManager system.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [App Requirements](#app-requirements)
4. [Port Selection](#port-selection)
5. [Deployment Steps](#deployment-steps)
6. [Systemd Service Setup](#systemd-service-setup)
7. [Firewall Configuration](#firewall-configuration)
8. [SSL/HTTPS Configuration](#sslhttps-configuration)
9. [Registering with AppManager](#registering-with-appmanager)
10. [Testing and Verification](#testing-and-verification)
11. [Troubleshooting](#troubleshooting)
12. [Best Practices](#best-practices)

---

## Overview

AppManager is a gateway application that manages and proxies requests to multiple Flask applications running on a server. When deploying an app for AppManager to manage, you need to:

1. Deploy your application to run on a specific internal port
2. Ensure the app is listening and accessible on localhost
3. Optionally set up a systemd service for process management
4. Register the app with AppManager through the admin dashboard
5. AppManager will automatically handle firewall rules and SSL/HTTPS setup

---

## Prerequisites

### Server Requirements

- **Linux server** (Ubuntu/Debian recommended) with systemd
- **Python 3.8+** installed
- **AppManager** already deployed and running
- **Sudo access** for firewall and service management
- **Port availability** - ensure your chosen port is not in use

### Application Requirements

Your application must:
- Be a web application (Flask, Django, FastAPI, or any HTTP server)
- Listen on a specific port (not 80, 443, or 5000 - these are reserved)
- Be accessible on `localhost` or `127.0.0.1`
- Respond to HTTP requests on the configured port
- Be running **before** registering with AppManager

---

## App Requirements

### Port Binding

Your app **must** bind to `localhost` (127.0.0.1) or `0.0.0.0`. AppManager will proxy requests to your app, so it doesn't need to be publicly accessible.

**Example Flask app:**
```python
from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello from my app!"

if __name__ == '__main__':
    # Bind to localhost - AppManager will handle external access
    app.run(host='127.0.0.1', port=5001, debug=False)
```

**Example with environment variable:**
```python
import os
from flask import Flask

app = Flask(__name__)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='127.0.0.1', port=port, debug=False)
```

### Health Check Endpoint (Recommended)

While not required, having a health check endpoint helps with monitoring:

```python
@app.route('/health')
def health():
    return {'status': 'healthy'}, 200
```

---

## Port Selection

### Reserved Ports

The following ports are **reserved** and should not be used:
- **80** - HTTP (AppManager or web server)
- **443** - HTTPS (AppManager or web server)
- **5000** - AppManager itself
- **Ports 1-1023** - System ports (require root)

### Recommended Port Ranges

- **5001-5999** - Recommended for Flask apps
- **6000-6999** - Alternative range
- **8000-8999** - Common for development/production apps
- **9000-9999** - Additional range

### Port Conflict Check

Before deploying, verify the port is available:

```bash
# Check if port is in use
sudo netstat -tlnp | grep :5001
# OR
sudo ss -tlnp | grep :5001

# Check what's using a port
sudo lsof -i :5001
```

---

## Deployment Steps

### Step 1: Prepare Your Application

1. **Ensure your app binds to localhost:**
   ```python
   app.run(host='127.0.0.1', port=YOUR_PORT)
   ```

2. **Set up environment variables** (if needed):
   ```bash
   export PORT=5001
   export FLASK_ENV=production
   export SECRET_KEY=your-secret-key
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Step 2: Test Locally

Before deploying, test that your app runs and listens on the correct port:

```bash
# Start your app
python app.py

# In another terminal, test it's listening
curl http://127.0.0.1:5001

# Or check with netstat
netstat -tlnp | grep :5001
```

### Step 3: Deploy to Server

Upload your application files to the server:

```bash
# Example: Upload via SCP
scp -r /local/app/path user@server:/opt/myapp

# Or use git
cd /opt/myapp
git pull origin main
```

### Step 4: Set Up Virtual Environment (Recommended)

```bash
cd /opt/myapp
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Systemd Service Setup

### Why Use Systemd?

Setting up a systemd service provides:
- **Automatic startup** on server reboot
- **Process management** (restart on failure)
- **Logging** via journalctl
- **Restart functionality** in AppManager admin panel

### Create Service File

Create `/etc/systemd/system/myapp.service`:

```ini
[Unit]
Description=My Application
After=network.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/myapp
Environment="PORT=5001"
Environment="FLASK_ENV=production"
Environment="SECRET_KEY=your-secret-key-here"
ExecStart=/opt/myapp/venv/bin/python /opt/myapp/app.py
# OR if not using venv:
# ExecStart=/usr/bin/python3 /opt/myapp/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### Service File Variables

- **Description**: Human-readable name for your service
- **User/Group**: User account to run the service (usually `ubuntu` or your server user)
- **WorkingDirectory**: Full path to your application directory
- **Environment**: Environment variables your app needs
- **ExecStart**: Full path to Python executable and your app entry point
- **Restart**: `always` means restart on failure or server reboot
- **RestartSec**: Wait 10 seconds before restarting

### Enable and Start Service

```bash
# Reload systemd to recognize new service
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable myapp.service

# Start the service
sudo systemctl start myapp.service

# Check status
sudo systemctl status myapp.service

# View logs
sudo journalctl -u myapp.service -f
```

### Service Name Convention

Use a consistent naming pattern:
- `{appname}.service` (e.g., `calculator.service`, `quizia.service`)
- Lowercase, no spaces
- Descriptive but concise

**Important**: Note the exact service name - you'll need it when registering with AppManager.

---

## Firewall Configuration

### Automatic Configuration

AppManager **automatically configures firewall rules** when you register an app:
- **UFW (Uncomplicated Firewall)** rules are added automatically
- **OCI Security Lists** are updated if OCI is configured
- Both HTTP and HTTPS ports are opened

### Manual Configuration (If Needed)

If you need to manually configure firewall:

```bash
# Allow HTTP port
sudo ufw allow 5001/tcp

# Allow HTTPS port (port + 10000)
sudo ufw allow 15001/tcp

# Check firewall status
sudo ufw status
```

### Port Ranges

- **HTTP Port**: Your app's internal port (e.g., 5001)
- **HTTPS Port**: HTTP port + 10000 (e.g., 15001)

---

## SSL/HTTPS Configuration

### Automatic SSL Setup

AppManager **automatically sets up SSL/HTTPS** for registered apps:
- Uses Let's Encrypt certificates
- HTTPS is available on port `{app_port} + 10000`
- Example: App on port 5001 → HTTPS on port 15001

### Requirements

- **Let's Encrypt certificate** must be configured for AppManager
- **Server domain** must be set in AppManager configuration
- **DNS** must point to the server

### Accessing Your App

After registration:
- **HTTP**: `http://server-domain:5001` (internal, proxied through AppManager)
- **HTTPS**: `https://server-domain:15001` (direct, with SSL)

**Note**: Users typically access apps through AppManager's welcome page, which handles routing automatically.

---

## Registering with AppManager

### Prerequisites

Before registering, ensure:
1. ✅ Your app is **running** and listening on its port
2. ✅ Port is **not in use** by another application
3. ✅ App responds to HTTP requests on localhost
4. ✅ Systemd service is set up (if using restart functionality)

### Registration Steps

1. **Access AppManager Admin Panel:**
   ```
   http://your-server/admin/login
   ```

2. **Log in** with admin credentials:
   - Default username: `LastTerminal`
   - Default password: `WhiteMage`
   - ⚠️ **Change these after first login!**

3. **Click "Add App"** button on the dashboard

4. **Fill in the form:**
   - **App Name**: Display name (e.g., "Calculator", "My App")
     - This appears on the welcome page
     - Must be unique (no duplicate names)
   - **Port**: Internal port your app listens on (e.g., 5001)
     - Must be a number
     - App **must be running** on this port
   - **Service Name** (optional): Systemd service name (e.g., `myapp.service`)
     - Only needed if you want restart functionality
     - Leave blank if not using systemd
     - Format: `{name}.service` or just `{name}`
   - **Folder Path** (optional): Path to app directory (e.g., `/opt/myapp`)
     - Used for reference/logging
   - **Logo** (optional): Upload an image file
     - Displayed on the welcome page button
     - Max size: 20MB
     - Formats: PNG, JPG, JPEG, GIF, SVG

5. **Click "Save"**

### What Happens During Registration

1. ✅ AppManager **tests** if the port is listening
2. ✅ If port is not listening, registration **fails** with error message
3. ✅ Firewall rules are **automatically configured** (UFW + OCI)
4. ✅ SSL/HTTPS is **automatically set up** (if Let's Encrypt is configured)
5. ✅ App configuration is **saved** to `instance/apps_config.json`
6. ✅ App appears on the **welcome page** immediately

### Registration Errors

**"Port {port} is not listening"**
- **Solution**: Start your app before registering
- Verify: `curl http://127.0.0.1:{port}` or `netstat -tlnp | grep :{port}`

**"An app with a similar name already exists"**
- **Solution**: Choose a different app name
- App names are converted to URL slugs (lowercase, hyphens)

**Firewall/SSL warnings**
- These are **warnings**, not errors
- App is still registered successfully
- Check firewall/SSL configuration separately

---

## Testing and Verification

### 1. Verify App is Running

```bash
# Check if app is listening
sudo netstat -tlnp | grep :5001
# OR
sudo ss -tlnp | grep :5001

# Test HTTP response
curl http://127.0.0.1:5001

# Check service status (if using systemd)
sudo systemctl status myapp.service
```

### 2. Test Through AppManager

1. **Test Port**: In admin dashboard, click "⋯" → "Test"
   - Verifies port is listening
   - Shows connection status

2. **Access via Welcome Page**:
   - Go to `http://your-server/`
   - Your app should appear in the list
   - Click the app button to access it

3. **Test Restart** (if service name configured):
   - In admin dashboard, click "⋯" → "Restart"
   - App should restart successfully
   - Check logs: `sudo journalctl -u myapp.service -f`

### 3. Verify Firewall Rules

```bash
# Check UFW rules
sudo ufw status | grep 5001

# Should show:
# 5001/tcp                   ALLOW       Anywhere
# 15001/tcp                  ALLOW       Anywhere
```

### 4. Verify SSL/HTTPS (if configured)

```bash
# Test HTTPS endpoint
curl -k https://your-server:15001

# Check certificate
openssl s_client -connect your-server:15001 -servername your-domain.com
```

---

## Troubleshooting

### App Not Appearing on Welcome Page

**Check:**
1. App is registered in admin dashboard
2. `serve_app` is set to `true` (default)
3. App is running and listening on the port
4. Refresh the welcome page

**Solution:**
- In admin dashboard, verify app exists
- Check "Serve App" toggle is enabled
- Restart AppManager: `sudo systemctl restart appmanager`

### Port Already in Use

**Error**: "Port {port} is not listening" or port conflict

**Check:**
```bash
# Find what's using the port
sudo lsof -i :5001
sudo netstat -tlnp | grep :5001
```

**Solution:**
- Stop the conflicting application
- Choose a different port
- Update your app configuration

### Restart Not Working

**Check:**
1. Service name is correct: `sudo systemctl status {service-name}`
2. AppManager user has sudo access
3. Service exists: `ls /etc/systemd/system/{service-name}`

**Solution:**
```bash
# Verify service name
sudo systemctl list-units --type=service | grep myapp

# Test restart manually
sudo systemctl restart myapp.service

# Check sudo permissions
sudo visudo
# Add line: username ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart *
```

### Firewall Not Opening Port

**Check:**
```bash
# UFW status
sudo ufw status

# Check if rule exists
sudo ufw status numbered | grep 5001
```

**Solution:**
```bash
# Manually add rule
sudo ufw allow 5001/tcp
sudo ufw allow 15001/tcp
sudo ufw reload
```

### SSL/HTTPS Not Working

**Check:**
1. Let's Encrypt certificate is configured for AppManager
2. Server domain is set correctly
3. DNS points to server

**Solution:**
- Verify Let's Encrypt setup in AppManager
- Check SSL certificate status in admin dashboard
- Ensure domain is accessible

### App Not Accessible After Registration

**Check:**
1. App is running: `curl http://127.0.0.1:5001`
2. Port is correct in AppManager
3. AppManager proxy is working

**Solution:**
```bash
# Test app directly
curl http://127.0.0.1:5001

# Test through AppManager
curl http://your-server/app/{app-slug}

# Check AppManager logs
sudo journalctl -u appmanager -f
```

---

## Best Practices

### 1. Port Management

- **Document** which ports are used by which apps
- **Use consistent ranges** (e.g., 5001-5099 for Flask apps)
- **Check availability** before deploying
- **Avoid** ports 80, 443, 5000, and system ports (1-1023)

### 2. Service Naming

- Use **lowercase** service names
- Follow pattern: `{appname}.service`
- Keep names **descriptive but concise**
- **Document** service names for your team

### 3. Environment Variables

- Use **environment variables** for configuration
- Store secrets in environment variables, not code
- Set variables in systemd service file
- **Never commit** secrets to version control

### 4. Logging

- Use **journalctl** for systemd service logs
- Log to files for application-specific logs
- Set up log rotation
- Monitor logs regularly

### 5. Security

- **Bind to localhost** (127.0.0.1), not 0.0.0.0
- Use **HTTPS** for production (AppManager handles this)
- Keep dependencies **up to date**
- Use **strong secret keys**
- **Change default admin password** in AppManager

### 6. Deployment Scripts

When writing deployment scripts, include:

```bash
#!/bin/bash
# Example deployment script structure

# 1. Check prerequisites
echo "Checking prerequisites..."
# Verify port availability, dependencies, etc.

# 2. Deploy application
echo "Deploying application..."
# Upload files, install dependencies, etc.

# 3. Set up systemd service
echo "Setting up systemd service..."
# Create service file, enable, start

# 4. Verify deployment
echo "Verifying deployment..."
# Test port, check service status

# 5. Instructions for registration
echo "Next steps:"
echo "1. Ensure app is running: sudo systemctl status myapp.service"
echo "2. Test port: curl http://127.0.0.1:5001"
echo "3. Register in AppManager: http://server/admin/login"
echo "   - App Name: My App"
echo "   - Port: 5001"
echo "   - Service Name: myapp.service"
```

### 7. Documentation

For each app, document:
- **App name** and purpose
- **Port number** used
- **Service name** (if using systemd)
- **Deployment path** on server
- **Environment variables** required
- **Dependencies** and installation steps
- **Health check endpoint** (if available)

---

## Quick Reference

### Deployment Checklist

- [ ] App binds to `127.0.0.1` or `localhost`
- [ ] Port is available and not reserved
- [ ] App runs successfully on chosen port
- [ ] Dependencies installed (requirements.txt)
- [ ] Systemd service created (if using)
- [ ] Service enabled and started
- [ ] App responds to HTTP requests
- [ ] App registered in AppManager admin panel
- [ ] App appears on welcome page
- [ ] Firewall rules configured (automatic)
- [ ] SSL/HTTPS working (if configured)

### Common Commands

```bash
# Check port availability
sudo netstat -tlnp | grep :PORT

# Start app manually
python app.py

# Create systemd service
sudo nano /etc/systemd/system/myapp.service
sudo systemctl daemon-reload
sudo systemctl enable myapp.service
sudo systemctl start myapp.service

# Check service status
sudo systemctl status myapp.service

# View logs
sudo journalctl -u myapp.service -f

# Test app
curl http://127.0.0.1:PORT

# Check firewall
sudo ufw status

# Restart app
sudo systemctl restart myapp.service
```

### AppManager Admin URLs

- **Login**: `http://your-server/admin/login`
- **Dashboard**: `http://your-server/admin/dashboard`
- **Welcome Page**: `http://your-server/`

---

## Upstream Proxy Configuration (Optional)

If you have an upstream proxy (e.g., nginx) in front of AppManager that handles SSL termination or additional routing, you may need to configure it to set the appropriate X-Forwarded-* headers.

### AppManager Routes

AppManager's own routes are prefixed with `/blackgrid`:
- Welcome page: `/blackgrid/`
- Admin panel: `/blackgrid/admin/`

If your upstream proxy forwards requests to AppManager, it should set the `X-Forwarded-Prefix` header for AppManager routes:

**Example nginx configuration:**

```nginx
# Forward AppManager routes with prefix
location /blackgrid {
    proxy_pass http://localhost:5000;  # AppManager port
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Port $server_port;
    proxy_set_header X-Forwarded-Prefix /blackgrid;  # Important for AppManager routes
}

# Forward all other routes (individual apps) to AppManager
location / {
    proxy_pass http://localhost:5000;  # AppManager port
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Port $server_port;
    # Note: X-Forwarded-Prefix is set by AppManager for individual apps
}
```

### Request Flow

1. **Client** → `https://blackgrid.ddns.net/{app_name}/path`
2. **Upstream Proxy (nginx)** → Forwards to AppManager on port 80/443 or internal port
3. **AppManager** → Proxies to `localhost:{port}/path` with X-Forwarded-* headers
4. **Individual App** → Processes request using ProxyFix middleware

**Note:** If AppManager is directly listening on ports 80/443 (no upstream proxy), no additional configuration is needed. AppManager handles all routing internally.

---

## Additional Resources

- **SERVICE_NAME_GUIDE.md** - Detailed guide on finding and using service names
- **DEPLOYMENT.md** - Guide for deploying AppManager itself
- **README.md** - General AppManager documentation
- **SETUP_INSTRUCTIONS.md** - Initial setup instructions

---

## Support

If you encounter issues:

1. Check the **Troubleshooting** section above
2. Review **AppManager logs**: `sudo journalctl -u appmanager -f`
3. Review **app logs**: `sudo journalctl -u myapp.service -f`
4. Verify **port status**: `sudo netstat -tlnp | grep :PORT`
5. Test **direct access**: `curl http://127.0.0.1:PORT`

For deployment script templates and examples, refer to the AppManager repository's deployment examples.

