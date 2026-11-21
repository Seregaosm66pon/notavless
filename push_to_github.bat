@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
title Nota Vless - GitHub Push

echo ===================================================
echo     Nota Vless - GitHub Sync & Upload
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
echo [*] If a browser window opens, click Authorize to complete sign-in.
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
    echo [-] Push failed or was cancelled.
    echo [*] If you need to force push:
    echo ===================================================
    choice /m "Try git push --force?"
    if errorlevel 2 goto end
    if errorlevel 1 git push -u origin main --force
)

:end
pause
