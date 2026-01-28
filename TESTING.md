# Local Testing Guide

This guide explains how to test AppManager locally with multiple Flask apps running on different ports.

## Setup for Local Testing

### 1. Start Your Flask Apps

Open multiple terminal windows and start each app on its designated port:

**Terminal 1 - Calculator (port 5001)**:
```bash
cd ../Calculator
export PORT=5001
python run_production.py
# Or: python -m app.backend.app (depending on your app structure)
```

**Terminal 2 - Quizia (port 6005)**:
```bash
cd ../quizia
python run.py
# App should start on port 6005
```

**Terminal 3 - DeltaBooks (port 6002)**:
```bash
cd ../DeltaBooks
export PORT=6002
python run.py
# App should start on port 6002
```

### 2. Start AppManager

**Terminal 4 - AppManager (port 5000)**:
```bash
cd AppManager
python run.py
```

AppManager will start on `http://localhost:5000` by default.

### 3. Configure Apps in AppManager

1. Visit http://localhost:5000/admin/login
2. Log in with:
   - Credentials from `instance/admin_config.json` (not git-backed)
   - If this is the first run, initialize via `APP_MANAGER_ADMIN_PASSWORD` (and optionally `APP_MANAGER_ADMIN_USERNAME`) before starting.
3. Click "Add App" and add each app:
   - **Calculator**: Port 5001
   - **Quizia**: Port 6005
   - **DeltaBooks**: Port 6002
4. Use the "Test" button to verify each app is accessible

### 4. Test the Gateway

1. Visit http://localhost:5000 (welcome page)
2. Click on any app card
3. You should be redirected and see the app's interface
4. Try different apps in different browser tabs - each maintains its own session

## Testing Scenarios

### Scenario 1: Multiple Users/Tabs
- Open two browser tabs
- In tab 1, select Calculator
- In tab 2, select Quizia
- Both should work independently

### Scenario 2: App Not Running
- Stop one of your Flask apps (e.g., Calculator)
- Try to access it through AppManager
- You should see an error message that the app is not responding

### Scenario 3: Admin Functions
- Test adding a new app
- Test editing an app's configuration
- Test deleting an app
- Test the "Test" function to check port connectivity
- Test the "Restart" function (if you have systemd services set up)

## Troubleshooting

### App Not Responding
- Verify the app is running: `curl http://localhost:{port}`
- Check the app's logs for errors
- Ensure the port matches what you configured in AppManager

### Port Already in Use
- Find what's using the port: `netstat -ano | findstr :5000` (Windows) or `lsof -i :5000` (Linux/Mac)
- Kill the process or use a different port

### Session Issues
- Clear browser cookies if sessions aren't working
- Check that cookies are enabled in your browser

### Proxy Errors
- Check AppManager logs for detailed error messages
- Verify the target app is accessible at `http://localhost:{port}`
- Check firewall settings if on Windows

## Production vs Local

| Setting | Local Development | Production Server |
|---------|------------------|------------------|
| AppManager Port | 5000 (default) | 80 or 443 |
| Host | 127.0.0.1 | 0.0.0.0 |
| Debug Mode | Enabled | Disabled |
| Internal Apps | localhost:5001, etc. | localhost:5001, etc. |

The proxy always uses `localhost` to connect to internal apps, which works the same way locally and on the server since it's connecting to apps on the same machine.

