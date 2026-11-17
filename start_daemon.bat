@echo off
setlocal
cd /d "%~dp0"
title Nota Vless - Starting Daemon

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python was not found!
    pause
    exit /b 1
)

if not exist ".venv\Scripts\pythonw.exe" (
    echo [*] Setting up virtual environment...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    pip install -r requirements.txt --quiet
)

if exist "daemon.pid" (
    set /p OLD_PID=<daemon.pid
    taskkill /PID %OLD_PID% /F >nul 2>nul
    del /f /q daemon.pid >nul 2>nul
)

echo [*] Starting Nota Vless background daemon...
start /B "" ".venv\Scripts\pythonw.exe" cli.py daemon --interval 7200 --log-file daemon.log

echo [+] Daemon launched successfully!
echo [*] Subscriptions will update automatically every 2 hours.
echo [*] Logs: daemon.log
ping 127.0.0.1 -n 2 >nul
exit /b 0
