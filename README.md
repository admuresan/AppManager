# AppManager

A gateway application that acts as a meta application, allowing multiple Flask apps to run on the same server and be accessed through a single entry point.

## Overview

AppManager runs on standard HTTP/HTTPS ports (80/443) and provides:
- A welcome page where users can select which app to use
- Session-based routing - each user can select different apps independently
- An admin interface for managing registered apps
- Reverse proxy functionality to forward requests to internal apps running on different ports

## Features

### User Features
- **Welcome Page**: Browse and select from available applications
- **Session Management**: Each user session maintains its own app selection
- **Seamless Experience**: Interact with selected apps as if they were running on the main ports

### Admin Features
- **Authentication**: Secure login system (credentials stored in `instance/admin_config.json`, not git-backed)
- **App Management**: CRUD operations for managing apps
  - Add new apps with name, port, optional logo, and service name
  - Edit existing app configurations
  - Delete apps
  - Test if apps are listening on their ports
  - Restart app services via systemd

## Installation

### Prerequisites
- Python 3.8+
- pip

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd AppManager
```

2. **Run the setup script** to create virtual environment and install dependencies:

   **Windows**:
   ```cmd
   setup.bat
   ```

   **Linux/Mac**:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. **Activate the virtual environment**:

   **Windows**:
   ```cmd
   AMvenv\Scripts\activate.bat
   ```

   **Linux/Mac**:
   ```bash
   source AMvenv/bin/activate
   ```

4. **Run the application**:

   **Windows**:
   ```cmd
   python app.py
   ```
   Or use: `run.bat`

   **Linux/Mac**:
   ```bash
   python app.py
   ```
   Or use: `./run.sh`

   The app will start on port 5000 by default for local development.

See `SETUP_INSTRUCTIONS.md` for detailed setup and activation instructions.

**Port Configuration**:
- **Local Development**: Defaults to port 5000 (runs on `127.0.0.1`)
- **Production**: Set `PORT=80` or `PORT=443` (runs on `0.0.0.0`)

The app automatically detects the environment based on `FLASK_ENV` or defaults to development mode.

## Configuration

### Admin Credentials
Admin credentials are stored in `instance/admin_config.json` (not git-backed).

For first-time setup (when `instance/admin_config.json` does not exist), initialize credentials via environment variables:

- `APP_MANAGER_ADMIN_USERNAME` (defaults to `admin` if omitted)
- `APP_MANAGER_ADMIN_PASSWORD` (required for first-time setup)  
  or `APP_MANAGER_ADMIN_PASSWORD_HASH`

### App Configuration
App configurations are stored in `instance/apps_config.json` (not git-backed). This file persists across restarts and deployments.

### Adding Apps

1. Log in to the admin panel at `/admin/login`
2. Click "Add App" on the dashboard
3. Fill in:
   - **App Name**: Display name shown on the welcome page
   - **Port**: Internal port the app is running on (e.g., 5001, 6005)
   - **Service Name** (optional): Systemd service name for restart functionality (e.g., `calculator.service`)
     - Only needed if you want to use the restart feature on Linux servers
     - Leave blank for local development or if not using systemd
     - See `SERVICE_NAME_GUIDE.md` for help finding service names
   - **Logo** (optional): Upload an image to display on the app button

## Deployment

### Production Setup

For production deployment, you'll want to:

1. **Set a secure SECRET_KEY**:
```bash
export SECRET_KEY="your-secure-secret-key-here"
```

2. **Run with a production WSGI server** (e.g., Gunicorn):
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:80 run:app
```

3. **Set up systemd service** (example):
```ini
[Unit]
Description=AppManager Gateway
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/AppManager
Environment="SECRET_KEY=your-secret-key"
ExecStart=/usr/bin/python3 /path/to/AppManager/run.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

4. **Configure Nginx** (if needed for HTTPS):
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## How It Works

1. **Welcome Page**: Users visit the root URL and see a list of configured apps
2. **App Selection**: When a user clicks an app, their session stores the selected app ID and port
3. **Proxy Routing**: All subsequent requests are proxied to `http://localhost:{selected_port}/{path}`
4. **Session Isolation**: Each browser tab/user maintains their own session and can select different apps

## File Structure

```
AppManager/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── models/
│   │   ├── user.py          # User authentication model
│   │   └── app_config.py    # App configuration model
│   ├── routes/
│   │   ├── welcome.py       # Welcome page routes
│   │   ├── admin.py         # Admin panel routes
│   │   └── proxy.py         # Reverse proxy routes
│   ├── templates/           # Jinja2 templates
│   ├── static/              # Static files (CSS, etc.)
│   └── utils/
│       └── app_manager.py   # Utility functions (test, restart)
├── instance/                # Not git-backed
│   ├── admin_config.json    # Admin credentials
│   ├── apps_config.json     # App configurations
│   └── uploads/             # Uploaded logos
├── run.py                   # Application entry point
├── requirements.txt         # Python dependencies
└── README.md
```

## Security Notes

- Passwords are hashed using Werkzeug's password hashing (not stored in plaintext)
- Admin routes require authentication
- Instance folder (containing configs and uploads) is not git-backed
- Change default credentials before production deployment

## Troubleshooting

### App not responding
- Use the "Test" function in the admin panel to check if the app is listening on its port
- Verify the app is running: `curl http://localhost:{port}`

### Restart not working
- Ensure the service name is correct in the app configuration
- Check that the AppManager process has permission to run `sudo systemctl restart`
- Verify systemd is available on the system

### Logo not displaying
- Check that the logo file was uploaded successfully
- Verify file permissions in `instance/uploads/logos/`
- Ensure the file is a valid image format

## License

[Your License Here]
