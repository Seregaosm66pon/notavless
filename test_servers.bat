@echo off
setlocal
cd /d "%~dp0"
title Nota Vless - Tester and Latency Benchmark

if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found. Please run run.bat first!
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat
python cli.py bench
pause
endlocal
