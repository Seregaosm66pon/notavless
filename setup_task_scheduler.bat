@echo off
setlocal
cd /d "%~dp0"
title Nota Vless - Setup Windows Task Scheduler

echo ===================================================
echo     Nota Vless - 2-Hour Auto-Update Task Setup
echo ===================================================
echo [*] Installing scheduled task in Windows Task Scheduler...
echo [*] Runs every 2 hours silently in the background.

schtasks /create /tn NotaVlessAutoUpdate /tr "wscript.exe \"%~dp0run_update_silent.vbs\"" /sc HOURLY /mo 2 /f >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [+] SUCCESS! Task 'NotaVlessAutoUpdate' installed.
    echo [*] Subscriptions will update every 2 hours automatically.
    echo [*] Notification will be posted to your Telegram channel on each update.
) else (
    schtasks /create /tn NotaVlessAutoUpdate /tr "wscript.exe %~dp0run_update_silent.vbs" /sc HOURLY /mo 2 /f >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        echo [+] SUCCESS! Task 'NotaVlessAutoUpdate' installed.
        echo [*] Subscriptions will update every 2 hours automatically.
    ) else (
        echo [-] Failed to install scheduled task. Try running as Administrator.
    )
)

echo ===================================================
pause
