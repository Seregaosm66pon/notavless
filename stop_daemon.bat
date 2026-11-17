@echo off
setlocal
cd /d "%~dp0"
title Nota Vless - Stopping Daemon

if exist "daemon.pid" (
    set /p DPID=<daemon.pid
    taskkill /PID %DPID% /F >nul 2>nul
    del /f /q daemon.pid >nul 2>nul
    echo [+] Daemon process PID %DPID% stopped.
) else (
    taskkill /IM pythonw.exe /F >nul 2>nul
    echo [+] Daemon stopped.
)

ping 127.0.0.1 -n 2 >nul
exit /b 0
