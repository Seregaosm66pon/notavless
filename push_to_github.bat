@echo off
setlocal
cd /d "%~dp0"
title Nota Vless - Push to GitHub

echo ===================================================
echo     Nota Vless - Загрузка подписок на GitHub
echo ===================================================
echo [*] Проверяем Git и статус репозитория...

git status >nul 2>nul
if %ERRORLEVEL% neq 0 (
    git init
    git remote add origin https://github.com/Seregaosm66pon/notavless.git >nul 2>nul
)

echo [*] Добавляем все файлы и подписки...
git add -A
git commit -m "Update subscriptions (mega_sub, vless, trojan, hy2)" >nul 2>nul

echo [*] Отправляем файлы в репозиторий https://github.com/Seregaosm66pon/notavless ...
echo [*] ВНИМАНИЕ: Если сейчас появится всплывающее окно входа GitHub в браузере:
echo [*] Нажмите зеленую кнопку "Authorize" (вход выполняется один раз).
echo.

git push -u origin main

echo.
if %ERRORLEVEL% equ 0 (
    echo ===================================================
    echo [+] УСПЕШНО! Все файлы залиты на GitHub!
    echo [+] Ссылка https://raw.githubusercontent.com/Seregaosm66pon/notavless/main/mega_sub.txt теперь работает (код 200)!
    echo ===================================================
) else (
    echo ===================================================
    echo [-] Отправка не удалась. Возможные причины:
    echo     1. Требуется войти в GitHub в браузере
    echo     2. Либо в ветке main на GitHub есть конфликты. Попробуем git push --force:
    echo ===================================================
    set /p RETRY="Попробовать форсированный push (y/n)? "
    if /i "%RETRY%"=="y" (
        git push -u origin main --force
    )
)

pause
