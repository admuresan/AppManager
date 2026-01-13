@echo off
REM Setup script for AppManager - Windows
REM Creates virtual environment named AMvenv and installs dependencies

echo ========================================
echo AppManager Setup Script
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

echo [1/3] Creating virtual environment 'AMvenv'...
python -m venv AMvenv
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)

echo [2/3] Activating virtual environment...
call AMvenv\Scripts\activate.bat

echo [3/3] Installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt

if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo To activate the virtual environment, run:
echo   AMvenv\Scripts\activate.bat
echo.
echo To run the application, use:
echo   python app.py
echo.
echo Or use the run script:
echo   run.bat
echo.
pause


