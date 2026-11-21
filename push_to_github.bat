@echo off
setlocal
cd /d "%~dp0"
title Nota Vless - GitHub Push

echo ===================================================
echo     Nota Vless - GitHub Sync and Upload
echo ===================================================
echo [*] Checking git repository...

git status >nul 2>nul
if %ERRORLEVEL% neq 0 (
    git init
    git remote add origin https://github.com/Seregaosm66pon/notavless.git >nul 2>nul
)

echo [*] Staging all files...
git add -A
git commit -m "Update subscriptions: mega_sub, vless, trojan, hy2" >nul 2>nul

echo [*] Pushing to https://github.com/Seregaosm66pon/notavless ...
echo [*] Opening browser sign-in if needed...
echo.

git push -u origin main

echo.
if %ERRORLEVEL% equ 0 (
    echo ===================================================
    echo [+] SUCCESS! All files uploaded to GitHub!
    echo [+] Link: https://raw.githubusercontent.com/Seregaosm66pon/notavless/main/mega_sub.txt
    echo ===================================================
) else (
    echo ===================================================
    echo [-] Push failed or was rejected.
    echo [*] If the remote has different commits, try force push:
    echo ===================================================
    choice /m "Try git push --force?"
    if errorlevel 2 goto end
    if errorlevel 1 git push -u origin main --force
)

:end
echo.
echo Press any key to exit.
pause >nul
