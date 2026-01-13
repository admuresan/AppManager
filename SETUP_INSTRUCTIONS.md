# Setup Instructions for AppManager

This guide will help you set up the AppManager virtual environment and run the application.

## Quick Setup

### Windows

1. **Run the setup script**:
   ```cmd
   setup.bat
   ```
   This will:
   - Create a virtual environment named `AMvenv`
   - Install all Python dependencies

2. **Activate the virtual environment**:
   ```cmd
   AMvenv\Scripts\activate.bat
   ```

3. **Run the application**:
   ```cmd
   python app.py
   ```
   Or simply use:
   ```cmd
   run.bat
   ```

### Linux/Mac

1. **Make scripts executable** (if needed):
   ```bash
   chmod +x setup.sh run.sh
   ```

2. **Run the setup script**:
   ```bash
   ./setup.sh
   ```
   This will:
   - Create a virtual environment named `AMvenv`
   - Install all Python dependencies

3. **Activate the virtual environment**:
   ```bash
   source AMvenv/bin/activate
   ```

4. **Run the application**:
   ```bash
   python app.py
   ```
   Or simply use:
   ```bash
   ./run.sh
   ```

## Manual Setup (Alternative)

If you prefer to set up manually:

### Windows
```cmd
python -m venv AMvenv
AMvenv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

### Linux/Mac
```bash
python3 -m venv AMvenv
source AMvenv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

## Virtual Environment Activation

### Windows
```cmd
AMvenv\Scripts\activate.bat
```

### Linux/Mac
```bash
source AMvenv/bin/activate
```

### PowerShell (Windows)
```powershell
AMvenv\Scripts\Activate.ps1
```

**Note**: You'll know the virtual environment is activated when you see `(AMvenv)` at the beginning of your command prompt.

## Deactivating the Virtual Environment

When you're done working, you can deactivate the virtual environment:

```bash
deactivate
```

## Running the Application

### Basic Run
```bash
python app.py
```

### With Custom Port
```bash
# Windows
set PORT=8080
python app.py

# Linux/Mac
export PORT=8080
python app.py
```

### Production Mode
```bash
# Windows
set FLASK_ENV=production
set PORT=80
python app.py

# Linux/Mac
export FLASK_ENV=production
export PORT=80
python app.py
```

## Accessing the Application

After starting the app:

- **Welcome Page**: http://localhost:5000
- **Admin Login**: http://localhost:5000/admin/login
  - Username: `LastTerminal`
  - Password: `WhiteMage`

## Troubleshooting

### Virtual Environment Not Found
If you get an error about the virtual environment not existing:
- Run `setup.bat` (Windows) or `./setup.sh` (Linux/Mac) first

### Python Not Found
- Ensure Python 3.8+ is installed
- Verify Python is in your system PATH
- Try using `python3` instead of `python` on Linux/Mac

### Permission Denied (Linux/Mac)
- Make scripts executable: `chmod +x setup.sh run.sh`
- Or run with: `bash setup.sh` and `bash run.sh`

### Port Already in Use
- Change the port: `export PORT=8080` (or `set PORT=8080` on Windows)
- Or stop the process using the port

### Dependencies Installation Fails
- Ensure you have internet connection
- Try upgrading pip: `python -m pip install --upgrade pip`
- Check that you're in the virtual environment (should see `(AMvenv)` in prompt)

## File Structure After Setup

```
AppManager/
├── AMvenv/              # Virtual environment (created by setup script)
│   ├── bin/              # Linux/Mac executables
│   ├── Scripts/          # Windows executables
│   └── lib/              # Installed packages
├── app/                  # Application code
├── instance/             # Config files (created on first run)
├── app.py                # Application entry point
├── requirements.txt      # Python dependencies
├── setup.bat             # Windows setup script
├── setup.sh              # Linux/Mac setup script
├── run.bat               # Windows run script
└── run.sh                # Linux/Mac run script
```

## Next Steps

After setup:
1. Run the application
2. Log in to the admin panel
3. Add your Flask apps (Calculator, Quizia, DeltaBooks, etc.)
4. Test the gateway functionality

See `QUICKSTART.md` for more detailed usage instructions.

