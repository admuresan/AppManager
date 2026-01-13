#!/bin/bash
# Setup script for AppManager - Linux/Mac/Windows Git Bash
# Creates virtual environment named AMvenv and installs dependencies

set -e  # Exit on error

echo "========================================"
echo "AppManager Setup Script"
echo "========================================"
echo ""

# Check if Python is installed (try python3 first, then python)
# Actually test if the command works, not just if it exists
PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    if python3 --version &> /dev/null 2>&1; then
        PYTHON_CMD="python3"
    fi
fi

if [ -z "$PYTHON_CMD" ] && command -v python &> /dev/null; then
    if python --version &> /dev/null 2>&1; then
        PYTHON_CMD="python"
    fi
fi

if [ -z "$PYTHON_CMD" ]; then
    echo "ERROR: Python is not installed or not in PATH"
    echo "Please install Python 3.8+ and try again"
    echo ""
    echo "On Windows, make sure Python is added to PATH during installation"
    echo "Or use setup.bat instead for Windows Command Prompt"
    echo ""
    echo "Trying to find Python..."
    which python3 2>&1 || echo "python3 not found"
    which python 2>&1 || echo "python not found"
    exit 1
fi

echo "Using Python: $PYTHON_CMD"
$PYTHON_CMD --version
echo ""

echo "[1/3] Creating virtual environment 'AMvenv'..."
$PYTHON_CMD -m venv AMvenv

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create virtual environment"
    exit 1
fi

echo "[2/3] Activating virtual environment..."

# Detect OS and use appropriate activation script
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" || "$OSTYPE" == "cygwin" ]]; then
    # Windows Git Bash
    source AMvenv/Scripts/activate
else
    # Linux/Mac
    source AMvenv/bin/activate
fi

echo "[3/3] Installing dependencies..."
python -m pip install --upgrade pip
pip install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install dependencies"
    exit 1
fi

echo ""
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo ""

# Show activation command based on OS
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" || "$OSTYPE" == "cygwin" ]]; then
    echo "To activate the virtual environment, run:"
    echo "  source AMvenv/Scripts/activate"
else
    echo "To activate the virtual environment, run:"
    echo "  source AMvenv/bin/activate"
fi

echo ""
echo "To run the application, use:"
echo "  python app.py"
echo ""
echo "Or use the run script:"
echo "  ./run.sh"
echo ""

