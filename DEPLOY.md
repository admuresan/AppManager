# Deployment Guide

## Prerequisites

1. **SSH Access**: Private SSH key must be placed in `ssh/ssh-key-2025-12-26.key`
   - This file is NOT git-backed (excluded in .gitignore)
   - Ensure the key has correct permissions: `chmod 600 ssh/ssh-key-2025-12-26.key`

2. **Server Requirements**:
   - Ubuntu/Debian Linux server
   - Python 3.8+ installed
   - sudo/root access
   - Port 80 available (or change PORT in deploy.sh)

3. **Local Requirements**:
   - bash shell
   - tar command
   - ssh/scp commands
   - SSH key file in `ssh/` directory

## Quick Deploy

```bash
./deploy.sh
```

## What the Script Does

1. **Tests SSH Connection** - Verifies access to the server
2. **Creates Directory Structure** - Sets up `/opt/appmanager` on server
3. **Backs Up Configuration** - Saves existing `instance/` folder
4. **Uploads Code** - Transfers application files (excluding venv, cache, etc.)
5. **Restores Configuration** - Preserves app configs and admin settings
6. **Manages Virtual Environment**:
   - Creates venv if it doesn't exist
   - Compares `requirements.txt` with saved version
   - Updates venv only if requirements changed
   - Saves current requirements.txt to venv folder for future comparison
7. **Sets Up Systemd Service** - Creates and starts `appmanager.service`
8. **Verifies Deployment** - Shows service status and recent logs

## Configuration Persistence

The following are preserved across deployments:
- `instance/admin_config.json` - Admin credentials
- `instance/apps_config.json` - App configurations
- `instance/uploads/logos/` - Uploaded logos

These are automatically backed up before each deployment.

## Environment Variables

The systemd service uses these environment variables (set in deploy.sh):
- `SECRET_KEY` - Flask secret key (defaults to dev key if not set)
- `PORT` - Server port (default: 80)
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
- Check virtual environment: `ls -la /opt/appmanager/AMvenv/bin/python`
- Verify port 80 is available: `sudo netstat -tlnp | grep :80`

### Virtual Environment Issues
- Manually recreate: `cd /opt/appmanager && python3 -m venv AMvenv && source AMvenv/bin/activate && pip install -r requirements.txt`
- Check requirements: `cat /opt/appmanager/AMvenv/requirements_installed.txt`

### Configuration Lost
- Check backups: `ls -la /opt/appmanager/backups/`
- Restore from backup: `cp -r /opt/appmanager/backups/YYYYMMDD_HHMMSS/* /opt/appmanager/instance/`

## Customization

Edit `deploy.sh` to change:
- `SERVER_IP` - Target server IP address
- `SERVER_USER` - SSH username (default: root)
- `DEPLOY_DIR` - Deployment directory (default: /opt/appmanager)
- `VENV_NAME` - Virtual environment name (default: AMvenv)
- `SERVICE_NAME` - Systemd service name (default: appmanager)


