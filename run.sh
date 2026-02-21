#!/bin/bash
# Run script for AppManager - Linux/Mac/Windows Git Bash
# Activates virtual environment and runs the app

# Check if virtual environment exists
if [ ! -d "AMvenv" ]; then
    echo "ERROR: Virtual environment not found!"
    echo "Please run ./setup.sh first to create the virtual environment."
    exit 1
fi

echo "Activating virtual environment..."

# Detect OS and use appropriate activation script
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" || "$OSTYPE" == "cygwin" ]]; then
    # Windows Git Bash
    source venv/Scripts/activate
else
    # Linux/Mac
    source venv/bin/activate
fi

echo "Starting AppManager..."
python app.py

