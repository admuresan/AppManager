@echo off
REM Run script for AppManager - Windows
REM Activates virtual environment and runs the app

echo Activating virtual environment...
call AMvenv\Scripts\activate.bat

if not exist AMvenv\Scripts\activate.bat (
    echo ERROR: Virtual environment not found!
    echo Please run setup.bat first to create the virtual environment.
    pause
    exit /b 1
)

echo Starting AppManager...
python app.py

pause


