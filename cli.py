"""
CLI Interface for Nota Vless.
Manage sources, contributors, subscriptions, daemon auto-updates, and network tests.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from config import (
    MEGA_SUBSCRIPTION_OUTPUT,
    MEGA_SUBSCRIPTION_URL,
    REPO_ROOT,
    SOURCES_FILE,
    UPDATE_INTERVAL_SECONDS,
    VPN_SUBSCRIPTION_OUTPUT,
    VPN_SUBSCRIPTION_OUTPUT_LTE,
    VPN_SUBSCRIPTION_OUTPUT_WIFI,
)
from contributors import (
    get_contributor_stats,
    get_custom_nodes,
    load_contributions,
    read_sources_with_contributors,
    record_custom_node,
    record_source,
)
from checker import benchmark_nodes, build_health_report, check_node_advanced
from protocols import parse_any_proxy_url
from refresh_vless_repo import check_node, check_tcp_port, run_update_pipeline


def print_banner() -> None:
    print(
        r"""
 _   _       _          __     ___               
| \ | | ___ | |_ __ _   \ \   / / | ___  ___ ___ 
|  \| |/ _ \| __/ _` |   \ \ / /| |/ _ \/ __/ __|
| |\  | (_) | || (_| |    \ V / | |  __/\__ \__ \
|_| \_|\___/ \__\__,_|     \_/  |_|\___||___/___/
        Multi-Protocol Russia Bypass & Sub Manager
"""
    )


def cmd_update(args: argparse.Namespace) -> None:
    print("[*] Starting one-time subscription update pipeline...")
    start_time = time.time()
    try:
        stats = asyncio.run(run_update_pipeline())
        elapsed = time.time() - start_time
        print(f"\n[+] Update finished in {elapsed:.1f}s!")
        print(f"    - Live Mega nodes:    {stats['live_mega']}")
        print(f"    - VLESS nodes:        {stats['vless']}")
        print(f"    - Trojan nodes:       {stats['trojan']}")
        print(f"    - Hysteria 2 nodes:   {stats['hy2']}")
        print(f"    - LTE nodes:          {stats['lte']}")
        print(f"    - WiFi nodes:         {stats['wifi']}")
        print(f"    - Files changed:      {stats['changed']}")
        print(f"    - Git status:         {stats['git_status']}")
        print(f"\n[>] Universal config: {MEGA_SUBSCRIPTION_URL}\n")
    except Exception as exc:
        print(f"[-] Update failed: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_daemon(args: argparse.Namespace) -> None:
    interval = getattr(args, "interval", None) or UPDATE_INTERVAL_SECONDS
    hours = interval / 3600.0

    # Handle background pythonw.exe or log-file redirection
    log_file_path = getattr(args, "log_file", "") or (REPO_ROOT / "daemon.log")
    if sys.stdout is None or getattr(args, "log_file", ""):
        log_file = open(log_file_path, "a", encoding="utf-8", buffering=1)
        sys.stdout = log_file
        sys.stderr = log_file

    pid_path = REPO_ROOT / "daemon.pid"
    try:
        pid_path.write_text(str(os.getpid()), encoding="ascii")
    except Exception:
        pass

    print_banner()
    print(f"[*] Starting Nota Vless Daemon (updating every {hours:.1f} hours / {interval}s)")
    print(f"[*] PID: {os.getpid()} | Log: {log_file_path}")
    print(f"[*] Press Ctrl+C to stop.\n", flush=True)

    iteration = 1
    try:
        while True:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"--- [Run #{iteration} at {now_str}] ---", flush=True)
            try:
                stats = asyncio.run(run_update_pipeline())
                print(
                    f"[+] Run #{iteration} complete: {stats['live_mega']} live nodes "
                    f"(VLESS: {stats['vless']}, Trojan: {stats['trojan']}, Hy2: {stats['hy2']})",
                    flush=True,
                )
            except Exception as exc:
                print(f"[-] Run #{iteration} encountered error: {exc}", file=sys.stderr, flush=True)

            next_run = datetime.now() + timedelta(seconds=interval)
            print(f"[*] Next update scheduled at {next_run.strftime('%Y-%m-%d %H:%M:%S')}\n", flush=True)

            status_data = {
                "pid": os.getpid(),
                "status": "running",
                "last_run": now_str,
                "next_run": next_run.strftime("%Y-%m-%d %H:%M:%S"),
                "interval_hours": hours,
                "iteration": iteration,
                "stats": stats if "stats" in locals() and stats else {},
            }
            try:
                (REPO_ROOT / "daemon_status.json").write_text(
                    json.dumps(status_data, indent=2, ensure_ascii=False), encoding="utf-8"
                )
            except Exception:
                pass

            iteration += 1

            try:
                time.sleep(interval)
            except KeyboardInterrupt:
                print("\n[*] Daemon stopped by user. Goodbye!", flush=True)
                break
    finally:
        if pid_path.exists():
            try:
                pid_path.unlink()
            except Exception:
                pass


def cmd_add(args: argparse.Namespace) -> None:
    target = getattr(args, "target", "").strip()
    author = getattr(args, "by", "@community").strip() or "@community"
    note = getattr(args, "note", "").strip()

    if not target:
        print("[-] Target cannot be empty.")
        return

    lower = target.lower()
    if lower.startswith("http://") or lower.startswith("https://"):
        sources_path = Path(SOURCES_FILE)
        current_lines = sources_path.read_text(encoding="utf-8").splitlines() if sources_path.exists() else []

        for line in current_lines:
            if target in line:
                print(f"[-] Source already exists in {SOURCES_FILE}")
                return

        new_line = f"{target} # added_by: {author}" + (f" ({note})" if note else "")
        with open(sources_path, "a", encoding="utf-8") as f:
            f.write(f"\n{new_line}")

        record_source(target, added_by=author, note=note)
        print(f"[+] Successfully added source from {author}:")
        print(f"    URL:  {target}")
        print(f"    Note: {note or 'N/A'}")
        print(f"    Appended to {SOURCES_FILE}")
    elif any(lower.startswith(p) for p in ("vless://", "trojan://", "hysteria2://", "hy2://")):
        parsed = parse_any_proxy_url(target, added_by=author)
        if not parsed:
            print("[-] Invalid proxy URL. Failed to parse protocol/host/port.")
            return

        success = record_custom_node(target, added_by=author, note=note)
        if success:
            print(f"[+] Successfully recorded custom {parsed.protocol.upper()} node from {author}!")
            print(f"    Host: {parsed.host}:{parsed.port}")
            print(f"    Remark: {parsed.remark or 'N/A'}")
        else:
            print("[-] Node already recorded in contributions registry.")
    else:
        print("[-] Unrecognized format. Please provide a URL (http/https) or proxy config (vless/trojan/hy2).")


def cmd_sources(args: argparse.Namespace) -> None:
    sources_path = Path(SOURCES_FILE)
    if not sources_path.exists():
        print(f"[-] Sources file not found: {SOURCES_FILE}")
        return

    items = read_sources_with_contributors(sources_path)
    print(f"\n=== Active Sources in {SOURCES_FILE} ({len(items)}) ===")
    for idx, (url, author) in enumerate(items, 1):
        print(f"[{idx:02d}] {url}")
        print(f"     Contributor: {author}")
    print()


def cmd_stats(args: argparse.Namespace) -> None:
    print_banner()
    print("=== Nota Vless Subscriptions Overview ===")

    def count_file_lines(filename: str) -> int:
        p = REPO_ROOT / filename
        if not p.exists():
            return 0
        lines = p.read_text(encoding="utf-8").splitlines()
        prefixes = ("vless://", "trojan://", "hysteria2://", "hy2://")
        return sum(1 for line in lines if any(line.strip().lower().startswith(x) for x in prefixes))

    mega_count = count_file_lines(MEGA_SUBSCRIPTION_OUTPUT)
    vless_count = count_file_lines(VPN_SUBSCRIPTION_OUTPUT)
    lte_count = count_file_lines(VPN_SUBSCRIPTION_OUTPUT_LTE)
    wifi_count = count_file_lines(VPN_SUBSCRIPTION_OUTPUT_WIFI)
    trojan_count = count_file_lines("trojan.txt")
    hy2_count = count_file_lines("hysteria2.txt")

    print(f"  • Universal Mega sub:  {mega_count} nodes ({MEGA_SUBSCRIPTION_OUTPUT})")
    print(f"  • VLESS All sub:       {vless_count} nodes ({VPN_SUBSCRIPTION_OUTPUT})")
    print(f"  • LTE / Whitelist sub: {lte_count} nodes ({VPN_SUBSCRIPTION_OUTPUT_LTE})")
    print(f"  • WiFi Home sub:       {wifi_count} nodes ({VPN_SUBSCRIPTION_OUTPUT_WIFI})")
    print(f"  • Trojan sub:          {trojan_count} nodes (trojan.txt)")
    print(f"  • Hysteria 2 sub:      {hy2_count} nodes (hysteria2.txt)")

    stats = get_contributor_stats()
    print("\n=== Top Contributors (Учет добавивших) ===")
    if not stats:
        print("  No contributor records yet.")
    else:
        sorted_stats = sorted(stats.items(), key=lambda x: x[1], reverse=True)
        for rank, (author, count) in enumerate(sorted_stats, 1):
            print(f"  {rank}. {author:<20} : {count} contributions")

    custom_nodes = get_custom_nodes()
    print(f"\n  Custom standalone nodes saved: {len(custom_nodes)}")
    print(f"\n[>] Universal config: {MEGA_SUBSCRIPTION_URL}\n")


def cmd_test(args: argparse.Namespace) -> None:
    target = getattr(args, "target", "").strip()
    if not target:
        try:
            target = input("Введите ссылку (vless/trojan/hy2) или host:port: ").strip()
        except (KeyboardInterrupt, EOFError):
            return

    if not target:
        print("[-] Цель не указана.")
        return

    print(f"\n[*] Диагностика узла: {target[:70]}...")

    parsed = parse_any_proxy_url(target)
    if parsed:
        print(f"    Протокол:       {parsed.protocol.upper()} ({parsed.security or 'none'})")
        print(f"    Хост:           {parsed.host}:{parsed.port}")
        if parsed.sni:
            print(f"    SNI:            {parsed.sni}")
        if parsed.remark:
            print(f"    Имя:            {parsed.remark}")

        print("    [~] Измерение точного RTT пинга и проверка TLS/DPI...")
        res = asyncio.run(check_node_advanced(parsed, timeout=3.5))
        if res.alive:
            print(f"\n[+] СТАТУС:       🟢 РАБОТАЕТ! (ONLINE)")
            print(f"    Локация:      {res.country_flag} {res.country_code.upper()}")
            print(f"    Пинг (RTT):   {res.latency_ms:.1f} ms [{res.quality_tier}]")
            print(f"    TLS / DPI:    {'✅ ОБХОДИТ ТСПУ / TLS OK' if res.tls_ok else '⚠️ TLS с ошибкой'}")
        else:
            print(f"\n[-] СТАТУС:       💀 НЕ РАБОТАЕТ (OFFLINE)")
            print(f"    Причина:      {res.error_msg or 'Timeout / Host unreachable'}")
        print()
        return

    if ":" in target and not target.startswith("http"):
        parts = target.split(":")
        host = parts[0].strip()
        try:
            port = int(parts[1].strip())
            t0 = time.perf_counter()
            alive = asyncio.run(check_tcp_port(host, port, timeout=3.5))
            rtt = (time.perf_counter() - t0) * 1000.0
            if alive:
                print(f"[+] TCP порт {host}:{port} ОТКРЫТ! Пинг: {rtt:.1f} ms")
            else:
                print(f"[-] TCP порт {host}:{port} ЗАКРЫТ или недоступен.")
            return
        except ValueError:
            pass

    print("[-] Неверный формат. Введите ссылку vless://, trojan://, hy2:// или ip:port.")


def cmd_benchmark(args: argparse.Namespace) -> None:
    print("\n=======================================================")
    print("      БЕНЧМАРК И АУДИТ СКОРОСТИ СЕРВЕРОВ NOTA VLESS    ")
    print("=======================================================")
    print(" [1] Экспресс-аудит (топ-50 серверов)")
    print(" [2] Глубокий бенчмарк (все серверы из mega_sub.txt)")
    print(" [3] Проверить один конкретный узел")
    print(" [0] Назад")
    try:
        sub = input("Выберите режим [0-3]: ").strip()
    except (KeyboardInterrupt, EOFError):
        return

    limit = 50
    if sub == "1":
        limit = 50
    elif sub == "2":
        limit = 0  # all
    elif sub == "3":
        cmd_test(argparse.Namespace(target=""))
        return
    elif sub in ("0", "q", "exit"):
        return

    sub_file = REPO_ROOT / MEGA_SUBSCRIPTION_OUTPUT
    if not sub_file.exists():
        print(f"[-] Файл {MEGA_SUBSCRIPTION_OUTPUT} не найден. Сначала запустите Update.")
        return

    lines = sub_file.read_text(encoding="utf-8").splitlines()
    configs = []
    for line in lines:
        p = parse_any_proxy_url(line)
        if p:
            configs.append(p)
            if limit and len(configs) >= limit:
                break

    if not configs:
        print("[-] Нет валидных серверов для теста.")
        return

    print(f"\n[*] Запуск тестирования {len(configs)} серверов...")
    print("[*] Замер точного RTT пинга, TLS-рукопожатия и геопозиции...\n")

    def progress(done: int, total: int, last_res) -> None:
        pct = int(done / total * 100)
        bar_len = 25
        filled = int(bar_len * done / total)
        bar = "█" * filled + "░" * (bar_len - filled)
        tag = last_res.display_tag if last_res else ""
        print(f"\r  [{bar}] {pct:>3}% ({done}/{total}) | {tag:<28}", end="", flush=True)

    results = asyncio.run(benchmark_nodes(configs, concurrency=32, progress_callback=progress))
    print("\n")

    rep = build_health_report(results)

    print("=======================================================")
    print(f"  📊 ОБЩЕЕ ЗДОРОВЬЕ ПУЛА:  {rep['success_rate_pct']}% ЖИВЫХ ({rep['alive']}/{rep['total']})")
    print(f"  ⚡ СРЕДНИЙ ПИНГ:         {rep['avg_ping_ms']} ms")
    print(f"  ⏱  ДИАПАЗОН:            {rep['min_ping_ms']} ms ... {rep['max_ping_ms']} ms")
    print("-------------------------------------------------------")
    print(f"  ⚡ Ультра (<85ms):      {rep['tiers']['ultra']} серверов")
    print(f"  🟢 Быстрые (85-180ms):  {rep['tiers']['fast']} серверов")
    print(f"  🟡 Обычные (180-350ms): {rep['tiers']['normal']} серверов")
    print(f"  🔴 Медленные (>350ms):  {rep['tiers']['slow']} серверов")
    print(f"  💀 Мертвые / Таймаут:   {rep['dead']} серверов")
    print("-------------------------------------------------------")
    print("  🌍 ТОП ЛОКАЦИЙ С ЛУЧШИМ ПИНГОМ:")
    for c in rep["top_countries"]:
        print(f"     {c['name']:<16} : {c['count']:>3} шт. (ср. {c['avg_latency']} ms)")
    print("-------------------------------------------------------")
    print("  🏆 ТОП-10 САМЫХ БЫСТРЫХ СЕРВЕРОВ:")
    for rank, n in enumerate(rep["fastest_nodes"], 1):
        rem = f"({n['remark']})" if n["remark"] else ""
        print(f"  {rank:>2}. {n['flag']} {n['protocol'].upper():<7} {n['host']:<18}:{n['port']:<5} {n['latency_ms']:>5.1f} ms [{n['tier']}] {rem}")
    print("=======================================================\n")

    alive_res = [r for r in results if r.alive]
    if alive_res:
        fastest_file = REPO_ROOT / "mega_sub_fastest.txt"
        top_lines = [r.config.raw_url for r in alive_res[:100]]
        fastest_file.write_text("\n".join(top_lines) + "\n", encoding="utf-8")
        print(f"[+] Топ-100 самых быстрых серверов сохранены в {fastest_file.name}!")


def save_env_var(key: str, value: str) -> None:
    env_path = REPO_ROOT / ".env"
    lines = []
    found = False
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith(f"{key}="):
                lines.append(f"{key}={value}")
                found = True
            else:
                lines.append(line)
    if not found:
        lines.append(f"{key}={value}")
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.environ[key] = value


def cmd_config(args: argparse.Namespace | None = None) -> None:
    from config import TG_API_ENDPOINT, TG_NOTIFY_CHANNEL, TG_NOTIFY_TOKEN, TG_PROXY_URL

    print("\n--- [Настройки Telegram & Прокси] ---")
    masked_token = (
        (TG_NOTIFY_TOKEN[:10] + "..." + TG_NOTIFY_TOKEN[-6:])
        if len(TG_NOTIFY_TOKEN) > 16
        else TG_NOTIFY_TOKEN
    )
    print(f"1. Токен бота:        {masked_token}")
    print(f"2. Канал (username):  {TG_NOTIFY_CHANNEL}")
    print(f"3. Прокси (HTTP/S):   {TG_PROXY_URL or '(автопоиск: 7890, 10809, 10808, 2334)'}")
    print(f"4. API Endpoint:      {TG_API_ENDPOINT or 'https://api.telegram.org'}")
    print("---------------------------------------")
    print("Что вы хотите изменить?")
    print(" [1] Канал (TG_NOTIFY_CHANNEL)")
    print(" [2] Прокси (TG_PROXY_URL)")
    print(" [3] Токен бота (TG_NOTIFY_TOKEN)")
    print(" [4] Реверс-прокси URL (TG_API_ENDPOINT)")
    print(" [0] Назад")
    try:
        sub = input("Ваш выбор [0-4]: ").strip()
    except (KeyboardInterrupt, EOFError):
        return

    if sub == "1":
        new_ch = input("Введите @username канала (например, @mychannel или -100...): ").strip()
        if new_ch:
            save_env_var("TG_NOTIFY_CHANNEL", new_ch)
            print(f"[+] Сохранено: TG_NOTIFY_CHANNEL={new_ch}")
    elif sub == "2":
        new_pr = input("Введите адрес прокси (например, http://127.0.0.1:7890 или пусто для авто): ").strip()
        save_env_var("TG_PROXY_URL", new_pr)
        print(f"[+] Сохранено: TG_PROXY_URL={new_pr}")
    elif sub == "3":
        new_tok = input("Введите токен бота: ").strip()
        if new_tok:
            save_env_var("TG_NOTIFY_TOKEN", new_tok)
            save_env_var("TG_BOT_TOKEN", new_tok)
            print("[+] Сохранено: новый токен бота")
    elif sub == "4":
        new_ep = input("Введите endpoint (например, https://my-worker.workers.dev): ").strip()
        if new_ep:
            save_env_var("TG_API_ENDPOINT", new_ep)
            print(f"[+] Сохранено: TG_API_ENDPOINT={new_ep}")


def cmd_post(args: argparse.Namespace) -> None:
    from config import TG_NOTIFY_CHANNEL, TG_NOTIFY_TOKEN
    import refresh_vless_repo

    channel = getattr(args, "channel", "").strip()
    if not channel:
        default_chan = TG_NOTIFY_CHANNEL or "@notavless"
        prompt_str = f"Введите @канал для отправки [Enter для '{default_chan}']: "
        try:
            user_in = input(prompt_str).strip()
        except (KeyboardInterrupt, EOFError):
            return
        channel = user_in if user_in else default_chan
        if user_in and user_in != default_chan:
            save_env_var("TG_NOTIFY_CHANNEL", user_in)
            print(f"[+] Канал сохранен в .env: {user_in}")

    def count_file_lines(filename: str) -> int:
        p = REPO_ROOT / filename
        if not p.exists():
            return 0
        lines = p.read_text(encoding="utf-8").splitlines()
        prefixes = ("vless://", "trojan://", "hysteria2://", "hy2://")
        return sum(1 for line in lines if any(line.strip().lower().startswith(x) for x in prefixes))

    mega_count = count_file_lines(MEGA_SUBSCRIPTION_OUTPUT)
    lte_count = count_file_lines(VPN_SUBSCRIPTION_OUTPUT_LTE)
    wifi_count = count_file_lines(VPN_SUBSCRIPTION_OUTPUT_WIFI)

    msg = (
        "New update:3\n"
        f"> servers amount:{mega_count}\n"
        f"> lte amount:{lte_count}\n"
        f"> wifi amount:{wifi_count}\n"
        f"> changed:true\n\n"
        f"> Universal config: {MEGA_SUBSCRIPTION_URL}"
    )

    print(f"\n[*] Публикация в канал {channel} через бота...")
    print(f"[*] Текст поста:\n----------------------------------------\n{msg}\n----------------------------------------")

    old_chan = refresh_vless_repo.TG_NOTIFY_CHANNEL
    refresh_vless_repo.TG_NOTIFY_CHANNEL = channel
    try:
        ok, detail = refresh_vless_repo._send_notification_sync(msg)
        if ok:
            print(f"\n[+] УСПЕШНО! Пост опубликован в {channel}!\n")
        else:
            print(f"\n[-] Ошибка отправки: {detail}\n")
            if "timed out" in detail.lower():
                print("[!] Подсказка: В РФ api.telegram.org блокируется провайдерами.")
                print("    - Если у вас запущен VPN (Amnezia, Koala Clash, Hiddify) - скрипт автоматически использует их локальный порт.")
                print("    - Либо в пункте 10 меню настройте прокси или Cloudflare Worker endpoint.")
                print("    - В GitHub Actions (облачный запуск): Telegram не блокируется и постит автоматически!")
            elif "chat not found" in detail.lower():
                print(f"[!] Подсказка: Канал '{channel}' не найден. Проверьте правильность @юзернейма или -100... ID.")
            elif "not a member" in detail.lower() or "administrator" in detail.lower() or "forbidden" in detail.lower():
                print(f"[!] ВАЖНО: Добавьте бота в администраторы канала '{channel}' с правом публикации сообщений!")
    finally:
        refresh_vless_repo.TG_NOTIFY_CHANNEL = old_chan


def cmd_menu(args: argparse.Namespace | None = None) -> None:
    while True:
        pid_file = REPO_ROOT / "daemon.pid"
        daemon_running = False
        current_pid = ""
        if pid_file.exists():
            try:
                current_pid = pid_file.read_text(encoding="ascii").strip()
                daemon_running = bool(current_pid)
            except Exception:
                pass

        status_text = f"АКТИВЕН (PID {current_pid})" if daemon_running else "ВЫКЛЮЧЕН"
        timing_info = ""
        status_file = REPO_ROOT / "daemon_status.json"
        if status_file.exists():
            try:
                sdata = json.loads(status_file.read_text(encoding="utf-8"))
                last_r = sdata.get("last_run", "-")
                next_r = sdata.get("next_run", "-")
                mega_n = sdata.get("stats", {}).get("live_mega", 0)
                timing_info = f"\n   Последний прогон: {last_r} (Живых серверов: {mega_n})\n   Следующий авто-прогон: {next_r}"
            except Exception:
                pass

        print_banner()
        print("===================================================")
        print("           Nota Vless - Control Center")
        print(f"       Фоновый демон авто-обновления: {status_text}{timing_info}")
        print("===================================================")
        print(" 1. Обновить все подписки прямо сейчас (Update)")
        print(" 2. Запустить демона в фоне (откроется на сек и свернется)")
        print(" 3. Остановить фонового демона (Stop)")
        print(" 4. Посмотреть статус демона и логи (Logs)")
        print(" 5. Опубликовать пост в Telegram-канал прямо сейчас (Post)")
        print(" 6. Посмотреть статистику и контрибьюторов (Stats)")
        print(" 7. Список активных источников (Sources)")
        print(" 8. Добавить свой узел или источник (Add)")
        print(" 9. Проверка скорости и аудит пула (Benchmark / Speed Test)")
        print(" 10. Настройки Telegram & Прокси (Config)")
        print(" 11. Установить авто-обновление каждые 2ч в Планировщик Windows")
        print(" 0. Выход")
        print("===================================================")
        try:
            choice = input("Выберите действие [0-11]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nВыход.")
            break

        if choice == "1":
            cmd_update(argparse.Namespace())
            input("\nНажмите Enter для продолжения...")
        elif choice == "2":
            subprocess.run([str(REPO_ROOT / "start_daemon.bat")], shell=True)
            print("[+] Фоновый демон запущен! Работает каждые 2 часа.")
            input("\nНажмите Enter для продолжения...")
        elif choice == "3":
            subprocess.run([str(REPO_ROOT / "stop_daemon.bat")], shell=True)
            print("[+] Фоновый демон остановлен.")
            input("\nНажмите Enter для продолжения...")
        elif choice == "4":
            subprocess.run([str(REPO_ROOT / "status_daemon.bat")], shell=True)
        elif choice == "5":
            cmd_post(argparse.Namespace())
            input("\nНажмите Enter для продолжения...")
        elif choice == "6":
            cmd_stats(argparse.Namespace())
            input("\nНажмите Enter для продолжения...")
        elif choice == "7":
            cmd_sources(argparse.Namespace())
            input("\nНажмите Enter для продолжения...")
        elif choice == "8":
            target = input("Введите ссылку (http/https) или конфиг (vless/trojan/hy2): ").strip()
            author = input("Введите ваш Telegram ник (например, @username): ").strip() or "@community"
            note = input("Примечание (необязательно): ").strip()
            cmd_add(argparse.Namespace(target=target, by=author, note=note))
            input("\nНажмите Enter для продолжения...")
        elif choice == "9":
            cmd_benchmark(argparse.Namespace())
            input("\nНажмите Enter для продолжения...")
        elif choice == "10":
            cmd_config(argparse.Namespace())
            input("\nНажмите Enter для продолжения...")
        elif choice == "11":
            subprocess.run([str(REPO_ROOT / "setup_task_scheduler.bat")], shell=True)
            input("\nНажмите Enter для продолжения...")
        elif choice in ("0", "q", "exit"):
            print("До свидания!")
            break
        else:
            print("[!] Неверный ввод, повторите попытку.\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="notavless",
        description="Nota Vless - Modern Multi-Protocol Proxy Aggregator & Subscription Manager",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # menu
    subparsers.add_parser("menu", help="Interactive control menu")

    # update
    subparsers.add_parser("update", help="Run subscription update once")

    # daemon
    daemon_parser = subparsers.add_parser("daemon", help="Run background daemon (updates every 2 hours)")
    daemon_parser.add_argument(
        "--interval",
        type=int,
        default=UPDATE_INTERVAL_SECONDS,
        help=f"Update interval in seconds (default: {UPDATE_INTERVAL_SECONDS}s = 2h)",
    )
    daemon_parser.add_argument(
        "--log-file",
        default="",
        help="Optional path to write daemon log output (defaults to daemon.log)",
    )

    # add
    add_parser = subparsers.add_parser("add", help="Add a new source URL or custom proxy node with attribution")
    add_parser.add_argument("target", nargs="?", default="", help="URL (http/https) or config string (vless/trojan/hy2)")
    add_parser.add_argument("--by", default="@community", help="Author/contributor username (e.g. @serega)")
    add_parser.add_argument("--note", default="", help="Optional note or description")

    # sources
    subparsers.add_parser("sources", help="List all configured sources and contributors")

    # stats
    subparsers.add_parser("stats", help="Display overview statistics and contributor leaderboard")

    # post
    post_parser = subparsers.add_parser("post", help="Publish update message to Telegram channel immediately")
    post_parser.add_argument("--channel", default="", help="Target Telegram channel (e.g. @mychannel)")

    # test
    test_parser = subparsers.add_parser("test", help="Test connectivity of a node or host:port")
    test_parser.add_argument("target", nargs="?", default="", help="Proxy URL or host:port")

    # benchmark / audit
    subparsers.add_parser("bench", help="Run latency benchmark across nodes")
    subparsers.add_parser("audit", help="Run latency benchmark and health audit")

    # config
    subparsers.add_parser("config", help="Configure Telegram token, channel, proxy and API endpoint")

    args = parser.parse_args()

    if not args.command or args.command == "menu":
        cmd_menu(args)
    elif args.command == "update":
        cmd_update(args)
    elif args.command == "daemon":
        cmd_daemon(args)
    elif args.command in ("bench", "audit"):
        cmd_benchmark(args)
    elif args.command == "post":
        cmd_post(args)
    elif args.command == "config":
        cmd_config(args)
    elif args.command == "add":
        if not args.target:
            target = input("Введите ссылку (http/https) или конфиг (vless/trojan/hy2): ").strip()
            author = input("Введите ваш Telegram ник (например, @username): ").strip() or "@community"
            note = input("Примечание (необязательно): ").strip()
            cmd_add(argparse.Namespace(target=target, by=author, note=note))
        else:
            cmd_add(args)
    elif args.command == "sources":
        cmd_sources(args)
    elif args.command == "stats":
        cmd_stats(args)
    elif args.command == "test":
        if not args.target:
            target = input("Введите узел (vless/trojan/hy2) или host:port: ").strip()
            cmd_test(argparse.Namespace(target=target))
        else:
            cmd_test(args)


if __name__ == "__main__":
    main()
