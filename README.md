# УСКОРИТЕЛЬ ИНТЕРНЕТА "Nota Vless" ⚡

**Nota Vless** — мощный мультипротокольный комбайн для сбора, валидации, фильтрации и авто-обновления VPN-конфигураций для обхода любых блокировок.

Поддерживает протоколы **VLESS (Reality / Vision / WebSocket / gRPC / xHTTP)**, **Trojan** и **Hysteria 2 (hy2)**.

Автоматически тестирует порты на доступность, отсеивает мертвые узлы, ведет учет контрибьюторов и каждые **2 часа** публикует свежие подписки в Telegram-канал и GitHub.

Огромный респект автору канала [#РКП](https://t.me/rkp_channel). Мы не кролики — мы люди.

---

## 🌐 Ссылки на подписки (Автообновление каждые 2 часа)

### 🌟 1. МЕГА-САБКА (Universal Config — Все протоколы + WiFi + LTE):
* **Raw (Прямые ссылки):**
  `https://raw.githubusercontent.com/Seregaosm66pon/notavless/refs/heads/main/mega_sub.txt`
* **Base64:**
  `https://raw.githubusercontent.com/Seregaosm66pon/notavless/refs/heads/main/mega_sub_base64.txt`

### 📱 2. Мобильный интернет (LTE / WhiteLists / gRPC / xHTTP):
* **Raw:** `https://raw.githubusercontent.com/Seregaosm66pon/notavless/refs/heads/main/vless_lte.txt`
* **Base64:** `https://raw.githubusercontent.com/Seregaosm66pon/notavless/refs/heads/main/vless_lte_base64.txt`

### 📶 3. Домашний интернет (WiFi):
* **Raw:** `https://raw.githubusercontent.com/Seregaosm66pon/notavless/refs/heads/main/vless_wifi.txt`
* **Base64:** `https://raw.githubusercontent.com/Seregaosm66pon/notavless/refs/heads/main/vless_wifi_base64.txt`

### 🛡 4. Раздельно по протоколам:
* **VLESS All:** `https://raw.githubusercontent.com/Seregaosm66pon/notavless/refs/heads/main/vlessall.txt`
* **Trojan:** `https://raw.githubusercontent.com/Seregaosm66pon/notavless/refs/heads/main/trojan.txt`
* **Hysteria 2:** `https://raw.githubusercontent.com/Seregaosm66pon/notavless/refs/heads/main/hysteria2.txt`

---

## 🛠 Удобная CLI-утилита (`cli.py`)

Управляйте базой, источниками и серверами через встроенный CLI:

```bash
# Разовое обновление подписок с чеком портов и пушем
python cli.py update

# Фоновый демон: авто-обновление каждые 2 часа (7200 сек)
python cli.py daemon --interval 7200

# Добавить свой конфиг или URL-источник с учетом автора
python cli.py add "vless://uuid@host:443?..." --by @username --note "Мой сервак"
python cli.py add "https://example.com/sub.txt" --by @username

# Посмотреть дашборд статистики и топ контрибьюторов
python cli.py stats

# Список всех подключенных источников
python cli.py sources

# Экспресс-тест узла или IP:port на доступность
python cli.py test "1.1.1.1:443"
```

Для пользователей Windows доступно интерактивное меню в один клик: просто запустите **`run.bat`**!

---

## 🚀 Фоновый режим (Daemon в 1 клик)

* **[start_daemon.bat](file:///c:/Users/user/Documents/notavless-main/start_daemon.bat)** — запускает процесс в фоне через `pythonw.exe`. Окно открывается на секунду и сразу закрывается. Каждые 2 часа бот собирает конфиги и шлет апдейты в канал.
* **[stop_daemon.bat](file:///c:/Users/user/Documents/notavless-main/stop_daemon.bat)** — останавливает фоновый процесс в один клик.
* **[status_daemon.bat](file:///c:/Users/user/Documents/notavless-main/status_daemon.bat)** — проверяет статус и выводит последние логи из `daemon.log`.

---

## 🤖 Telegram Бот и Формат Уведомлений

1. **Токен бота:** `8740400260:AAGeOM6eO27VfziUjmYGYeXgCVmQAF6eN-Y`
2. **Канал для уведомлений:** задается в `.env` переменной `TG_NOTIFY_CHANNEL=@ваш_канал`.
3. Каждые 2 часа бот отправляет точное сообщение с реальными числами и цитатой мега-конфига:

```text
New update:3
> servers amount:3308
> lte amount:672
> wifi amount:2636
> changed:true

> Universal config: https://raw.githubusercontent.com/Seregaosm66pon/notavless/refs/heads/main/mega_sub.txt
```

### Настройка в GitHub Actions:
Workflow `.github/workflows/update.yml` настроен на запуск по cron каждые 2 часа (`0 */2 * * *`). Добавьте в GitHub Secrets:
* `TG_NOTIFY_CHANNEL` — ваш канал (например `@notavless`)
* `TG_BOT_TOKEN` — токен бота (уже предустановлен дефолтом)

---

## 📱 Рекомендуемые клиенты

* **Android:** [v2rayNG](https://github.com/2dust/v2rayNG/releases) (рекомендуется), [Hiddify](https://github.com/hiddify/hiddify-app/releases), [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases)
* **iOS (iPhone/iPad):** [Streisand](https://apps.apple.com/app/streisand/id6450534064) (рекомендуется), [Hiddify](https://apps.apple.com/app/hiddify-proxy-vpn/id6596777532), [FoXray](https://apps.apple.com/app/foxray/id6448366569)
* **Windows:** [v2rayN](https://github.com/2dust/v2rayN/releases) (рекомендуется), [Hiddify](https://github.com/hiddify/hiddify-app/releases), [Throne](https://github.com/throneproj/Throne/releases)
* **Linux / Mac:** [v2rayA](https://github.com/v2rayA/v2rayA/releases), [Hiddify](https://github.com/hiddify/hiddify-app/releases), [Streisand](https://apps.apple.com/app/streisand/id6450534064)

> ⚠️ *Предостережение: Не используйте Happ из-за утечек ключей шифрования.*
