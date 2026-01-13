# Quick Start Guide

## Local Development

1. **Set up virtual environment and install dependencies**:

   **Windows**:
   ```cmd
   setup.bat
   ```

   **Linux/Mac**:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

2. **Activate the virtual environment**:

   **Windows**:
   ```cmd
   AMvenv\Scripts\activate.bat
   ```

   **Linux/Mac**:
   ```bash
   source AMvenv/bin/activate
   ```

3. **Run the application**:
   ```bash
   # Default runs on port 5000 for local development
   python app.py
   
   # Or use the run script (Windows: run.bat, Linux/Mac: ./run.sh)
   ```

   **Note**: You'll know the virtual environment is activated when you see `(AMvenv)` at the beginning of your command prompt.

3. **Access the application**:
- Welcome page: http://localhost:5000
- Admin login: http://localhost:5000/admin/login
  - Username: `LastTerminal`
  - Password: `WhiteMage`

**Note**: The app defaults to port 5000 for local development. On the server, set `PORT=80` or `PORT=443` for production use.

## First Steps

1. **Log in to admin panel** using the default credentials
2. **Add your first app**:
   - Click "Add App"
   - Enter app name (e.g., "Calculator")
   - Enter port (e.g., 5001)
   - Optionally add service name (e.g., "calculator.service")
   - Optionally upload a logo
   - Click "Save"

3. **Test the app**:
   - Click the "⋯" menu on the app row
   - Click "Test" to verify the app is listening on its port
   - If the app is running, you'll see a success message

4. **Use the app**:
   - Go back to the welcome page
   - Click on your app
   - You'll be redirected and can interact with the app through AppManager

## Testing Locally with Multiple Apps

To test AppManager locally with your existing apps:

1. **Start your Flask apps on their internal ports**:
   ```bash
   # Terminal 1: Start Calculator on port 5001
   cd ../Calculator
   python run_production.py  # or your run script
   
   # Terminal 2: Start Quizia on port 6005
   cd ../quizia
   python run.py  # or your run script
   
   # Terminal 3: Start DeltaBooks on port 6002
   cd ../DeltaBooks
   python run.py  # or your run script
   ```

2. **Start AppManager on port 5000**:
   ```bash
   # Terminal 4: Start AppManager
   cd AppManager
   python run.py
   ```

3. **Configure apps in AppManager**:
   - Visit http://localhost:5000/admin/login
   - Add each app with its port number
   - Test each app to verify connectivity

4. **Use the apps**:
   - Visit http://localhost:5000
   - Click on any app to use it through AppManager
   - Each browser tab maintains its own app selection

## Production Deployment

For production on the server, set the PORT environment variable:

```bash
# For HTTP (port 80)
export PORT=80
python run.py

# Or use a production WSGI server like Gunicorn
gunicorn -w 4 -b 0.0.0.0:80 run:app
```

The app will automatically use `0.0.0.0` as the host in production mode (when `FLASK_ENV != 'development'`).

## Changing Admin Password

After first login, you can change the password by editing `instance/admin_config.json`:

```json
{
  "username": "LastTerminal",
  "password_hash": "<new-hash-here>"
}
```

To generate a new password hash, use Python:

```python
from werkzeug.security import generate_password_hash
print(generate_password_hash('your-new-password'))
```

Then replace the `password_hash` value in the config file.

## Adding Multiple Apps

You can add as many apps as you need. Each app should:
- Run on a unique internal port
- Be accessible at `http://localhost:{port}`

Example apps:
- Calculator on port 5001
- Quizia on port 6005
- DeltaBooks on port 6002

Users can select different apps in different browser tabs, and each will maintain its own session.

