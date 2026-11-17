@echo off
setlocal
cd /d "%~dp0"
title Nota Vless - Remove Scheduled Task

echo ===================================================
echo     Nota Vless - Remove Auto-Update Task
echo ===================================================
schtasks /delete /tn "NotaVlessAutoUpdate" /f >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [+] SUCCESS! Task 'NotaVlessAutoUpdate' removed from Windows Task Scheduler.
) else (
    echo [*] Task was not found or already removed.
)
echo ===================================================
pause
