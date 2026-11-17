@echo off
setlocal
cd /d "%~dp0"
title Nota Vless - Daemon Status

echo ===================================================
echo           Nota Vless - Daemon Status
echo ===================================================

powershell -ExecutionPolicy Bypass -Command "$pidFile = 'daemon.pid'; if (Test-Path $pidFile) { $pidVal = (Get-Content $pidFile).Trim(); if ($pidVal -and (Get-Process -Id $pidVal -ErrorAction SilentlyContinue)) { Write-Host ('[STATUS] Daemon is RUNNING (PID: ' + $pidVal + ')') } else { Write-Host '[STATUS] Daemon is STOPPED' } } else { Write-Host '[STATUS] Daemon is NOT running.' }"

echo.
if exist "daemon.log" (
    echo --- Last 15 lines from daemon.log ---
    powershell -Command "Get-Content daemon.log -Tail 15"
)

echo ===================================================
pause
