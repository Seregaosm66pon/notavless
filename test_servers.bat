@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
title Nota Vless - Ultimate High-Speed Tester & DPI Benchmark

if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found. Please run run.bat first!
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat
python tester.py
pause
endlocal
