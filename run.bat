@echo off
setlocal
cd /d "%~dp0"
title Nota Vless - Control Center

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python was not found!
    echo Please install Python 3.10+ and check Add Python to PATH.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\activate.bat" (
    echo [*] Creating virtual environment...
    python -m venv .venv
)

call .venv\Scripts\activate.bat
pip install -r requirements.txt --quiet
python cli.py menu

endlocal
