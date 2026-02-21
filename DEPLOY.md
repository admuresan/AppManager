# Deployment Guide

## Prerequisites

1. **SSH Access**: Private SSH key must be placed in `ssh/ssh-key-2025-12-26.key`
   - This file is NOT git-backed (excluded in .gitignore)
   - Ensure the key has correct permissions: `chmod 600 ssh/ssh-key-2025-12-26.key`

   **Deploy config**: `ssh/deploy_config.json` (JSON) with `internalIP`, `username`, and `password` (sudo). The script reads this file as JSON only.

2. **OCI API Key (for automatic OCI Security List port rules)**:
   - AppManager updates OCI **Security List ingress rules** via the OCI API (not via SSH).
   - During deploy, `deploy.sh` will install your OCI API private key on the server at:
     - `~/.oci/oci_api_key.pem` (for the `ubuntu` user that runs `appmanager`)
   - Provide the key in one of these ways:
     - Place the private key in `oci_ssh/` as a `.pem` file (public-key files like `*_public.pem` are ignored), OR
     - Set `OCI_PRIVATE_KEY_FILE=/path/to/oci_api_key.pem` when running deploy.
   - If you do **not** provide the key, AppManager will still deploy, but OCI port automation may be disabled until the key is present server-side.

3. **Server Requirements**:
   - Ubuntu/Debian Linux server
   - Python 3.8+ installed
   - sudo/root access
   - Port 80 available (or change PORT in deploy.sh)

4. **Local Requirements**:
   - bash shell
   - tar command
   - ssh/scp commands
   - SSH key file in `ssh/` directory

## Quick Deploy

```bash
./deploy.sh
```

## What the Script Does

1. **Creates Directory Structure** - Sets up `/BlackGrid/appmanager` on server
2. **Backs Up Configuration** - Saves existing `instance/` folder
3. **Uploads Code** - Transfers application files (excluding venv, cache, etc.)
4. **Restores Configuration** - Preserves app configs and admin settings
5. **Virtual Environment** - Creates `AMvenv` if missing and runs `pip install -r requirements.txt`
6. **Systemd Service** - Installs `appmanager.service` (User/Group from deploy config, PORT=8080), enables and starts it
7. **Nginx** - Installs Nginx if needed, configures port 80 → 8080 so you can use `http://YOUR_IP` without `:8080`
8. **Sudoers** - Configures passwordless sudo for journalctl/systemctl (if password provided in config)
9. **Restart** - Restarts AppManager to load new code

No manual steps: after `./deploy.sh` you can open `http://YOUR_SERVER_IP` and use AppManager.

## Configuration Persistence

The following are preserved across deployments:
- `instance/admin_config.json` - Admin credentials
- `instance/apps_config.json` - App configurations
- `instance/uploads/logos/` - Uploaded logos

These are automatically backed up before each deployment.

## Environment Variables

The systemd service uses these environment variables (set in deploy.sh):
- `SECRET_KEY` - Flask secret key (defaults to dev key if not set)
- `PORT` - App port (default: 8080; Nginx listens on 80 and forwards to 8080)
- `FLASK_ENV` - Set to `production`
- `SERVER_ADDRESS` - Set to server IP (40.233.70.245)

To set a custom SECRET_KEY on the server:
```bash
sudo systemctl edit appmanager
# Add:
[Service]
Environment="SECRET_KEY=your-secure-secret-key-here"
```

Then restart:
```bash
sudo systemctl daemon-reload
sudo systemctl restart appmanager
```

## Manual Service Management

```bash
# Check status
sudo systemctl status appmanager

# View logs
sudo journalctl -u appmanager -f

# Restart service
sudo systemctl restart appmanager

# Stop service
sudo systemctl stop appmanager

# Start service
sudo systemctl start appmanager
```

## Troubleshooting

### SSH Connection Fails
- Verify SSH key exists: `ls -la ssh/ssh-key-2025-12-26.key`
- Check key permissions: `chmod 600 ssh/ssh-key-2025-12-26.key`
- Test manual connection: `ssh -i ssh/ssh-key-2025-12-26.key root@40.233.70.245`

### Service Fails to Start
- Check logs: `sudo journalctl -u appmanager -n 50`
- Verify Python path: `which python3`
- Check virtual environment: `ls -la /BlackGrid/appmanager/AMvenv/bin/python`
- Verify port 80 is available: `sudo netstat -tlnp | grep :80`

### Virtual Environment Issues
- Manually recreate: `cd /BlackGrid/appmanager && python3 -m venv AMvenv && source AMvenv/bin/activate && pip install -r requirements.txt`
- Check requirements: `cat /BlackGrid/appmanager/AMvenv/requirements_installed.txt`

### Configuration Lost
- Check backups: `ls -la /BlackGrid/appmanager/backups/`
- Restore from backup: `cp -r /BlackGrid/appmanager/backups/YYYYMMDD_HHMMSS/* /BlackGrid/appmanager/instance/`

## Customization

Edit `deploy.sh` to change:
- `SERVER_IP` - Target server IP address
- `SERVER_USER` - SSH username (default: root)
- `DEPLOY_DIR` - Deployment directory (default: /BlackGrid/appmanager)
- `VENV_NAME` - Virtual environment name (default: AMvenv)
- `SERVICE_NAME` - Systemd service name (default: appmanager)



