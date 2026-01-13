# Service Name Guide

## What is a Service Name?

The **Service Name** is the systemd service name used to manage your Flask apps on Linux servers. It's only needed if you want to use the "Restart" functionality in the AppManager admin panel.

**Note**: Service name is **optional**. You can leave it blank if:
- You're running apps locally (not as systemd services)
- You don't need the restart functionality
- You're on Windows (systemd is Linux-only)

## How to Find Your Service Name

### On Linux Server

1. **List all systemd services**:
   ```bash
   sudo systemctl list-units --type=service | grep -E "calculator|quizia|deltabooks"
   ```

2. **Check specific service**:
   ```bash
   sudo systemctl status calculator.service
   sudo systemctl status quizia.service
   sudo systemctl status deltabooks.service
   ```

3. **Find service files**:
   ```bash
   ls /etc/systemd/system/*.service
   ```

### Common Service Name Formats

Based on your existing apps, service names typically follow this pattern:
- `{app-name}.service` (e.g., `calculator.service`)
- `{app-name}` (without .service extension)

### Examples from Your Apps

Based on your deployment scripts:

- **Calculator**: `calculator.service` (runs on port 5001)
- **Quizia**: `quizia.service` (runs on port 6005)
- **DeltaBooks**: `deltabooks.service` (runs on port 6002)

## How to Check if a Service Exists

```bash
# Check if service exists and is active
sudo systemctl status calculator.service

# List all services
sudo systemctl list-units --type=service --all

# Search for your app
sudo systemctl list-units --type=service | grep calculator
```

## Using Service Name in AppManager

1. **When adding an app**:
   - Enter the app name (e.g., "Calculator")
   - Enter the port (e.g., 5001)
   - **Optionally** enter the service name (e.g., `calculator.service`)
   - Leave blank if you don't need restart functionality

2. **Testing the restart**:
   - After adding an app with a service name
   - Click the "⋯" menu on the app row
   - Click "Restart"
   - It will run: `sudo systemctl restart {service-name}`

## Troubleshooting

### "Service not found" error
- Verify the service name is correct: `sudo systemctl status {service-name}`
- Check spelling (case-sensitive)
- Ensure the service exists: `ls /etc/systemd/system/{service-name}`

### "Permission denied" error
- AppManager needs sudo access to restart services
- On the server, ensure the AppManager user can run `sudo systemctl restart`
- You may need to configure sudoers: `sudo visudo`

### Service name not working
- Try without `.service` extension
- Check the exact name in `/etc/systemd/system/`
- Verify the service is enabled: `sudo systemctl is-enabled {service-name}`

## Local Development (Windows)

If you're running apps locally on Windows:
- **Leave service name blank** - systemd doesn't exist on Windows
- The restart functionality won't work locally
- You can still use the "Test" function to check if apps are running

## Creating a Service (If Needed)

If your app doesn't have a systemd service yet, create one:

```bash
sudo nano /etc/systemd/system/your-app.service
```

Example service file:
```ini
[Unit]
Description=Your Flask App
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/path/to/your/app
Environment="PORT=5001"
ExecStart=/usr/bin/python3 /path/to/your/app/run.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Then enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable your-app.service
sudo systemctl start your-app.service
```

