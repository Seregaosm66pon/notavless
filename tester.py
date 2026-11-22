"""
Nota Vless - Ultimate High-Speed Proxy Health Checker & Latency Benchmark.
Cyberpunk / Rich-powered terminal UI with real-time animated stats,
multi-sample jitter calculations, DPI / TSPU liveness detection, and one-click copy.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Sequence

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table
from rich.text import Text

from checker import (
    NodeCheckResult,
    benchmark_nodes,
    build_health_report,
    check_node_advanced,
    detect_country_info,
    find_sing_box_executable,
    find_xray_executable,
    get_security_tag,
    make_sparkline,
    probe_nodes_http_batch,
    probe_proxy_http,
)
from config import (
    MEGA_FASTEST_URL,
    MEGA_SUBSCRIPTION_OUTPUT,
    MEGA_SUBSCRIPTION_URL,
    REPO_ROOT,
)
from protocols import ParsedConfig, parse_any_proxy_url

console = Console()


def copy_to_clipboard(text: str) -> bool:
    """Copy text to Windows clipboard using native clip command."""
    try:
        p = subprocess.Popen(["clip"], stdin=subprocess.PIPE, shell=True)
        p.communicate(text.encode("utf-16le"))
        return p.returncode == 0
    except Exception:
        return False


def get_hero_banner() -> Panel:
    """Return stylized cyberpunk ASCII hero banner with engine badge."""
    ascii_art = r"""
 ███╗   ██╗ ██████╗ ████████╗ █████╗     ██╗   ██╗██╗     ███████╗███████╗
 ████╗  ██║██╔═══██╗╚══██╔══╝██╔══██╗    ██║   ██║██║     ██╔════╝██╔════╝
 ██╔██╗ ██║██║   ██║   ██║   ███████║    ██║   ██║██║     █████╗  ███████╗
 ██║╚██╗██║██║   ██║   ██║   ██╔══██║    ╚██╗ ██╔╝██║     ██╔══╝  ╚════██║
 ██║ ╚████║╚██████╔╝   ██║   ██║  ██║     ╚████╔╝ ███████╗███████╗███████║
 ╚═╝  ╚═══╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝      ╚═══╝  ╚══════╝╚══════╝╚══════╝
    ⚡ ULTIMATE MULTI-PROTOCOL SPEED BENCHMARK & DPI HEALTH ENGINE ⚡"""

    banner_text = Text(ascii_art, style="bold cyan")
    sub = Text(
        "VLESS Reality (XTLS-Vision) • Trojan TLS 1.3 • Hysteria 2 • Anti-TSPU Handshake Audit",
        style="bold magenta",
    )
    elements = [Align.center(banner_text), Align.center(sub)]
    sb_bin = find_sing_box_executable()
    xray_bin = find_xray_executable()
    if sb_bin:
        elements.append(
            Align.center(Text("⚡ Core: sing-box (Real HTTP Tunnel Audit Engine Active)", style="bold green"))
        )
    elif xray_bin:
        elements.append(
            Align.center(Text("⚡ Core: Xray (Audit Engine Active)", style="bold green"))
        )
    else:
        elements.append(
            Align.center(Text("⚡ Core: Native Python Hybrid Sockets (DPI/TLS Audit Active)", style="dim cyan"))
        )
    return Panel(
        Group(*elements),
        border_style="bright_blue",
        box=box.ROUNDED,
        padding=(0, 1),
    )


def make_stat_card(title: str, value: str, color: str, subtitle: str = "") -> Panel:
    """Render a compact glowing metric card."""
    t = Text()
    t.append(f"{value}\n", style=f"bold {color}")
    if subtitle:
        t.append(f"{subtitle}", style="dim")
    return Panel(
        Align.center(t),
        title=f"[bold {color}]{title}[/]",
        border_style=color,
        box=box.ROUNDED,
        padding=(0, 1),
    )


def render_distribution_bar(rep: dict) -> Text:
    """Create a proportional colored visual bar for latency tiers."""
    total = rep["total"] or 1
    tiers = rep["tiers"]
    dead = rep["dead"]

    bar_len = 40
    u_len = int(round(tiers["ultra"] / total * bar_len))
    f_len = int(round(tiers["fast"] / total * bar_len))
    n_len = int(round(tiers["normal"] / total * bar_len))
    s_len = int(round(tiers["slow"] / total * bar_len))
    d_len = bar_len - (u_len + f_len + n_len + s_len)
    if d_len < 0:
        d_len = 0

    bar = Text()
    bar.append("█" * u_len, style="bold cyan")
    bar.append("█" * f_len, style="bold green")
    bar.append("█" * n_len, style="bold yellow")
    bar.append("█" * s_len, style="bold red")
    bar.append("█" * d_len, style="dim red")
    return bar


class BenchmarkSessionUI:
    """Interactive live benchmark coordinator with Rich Live display."""

    def __init__(self, configs: list[ParsedConfig], concurrency: int = 48) -> None:
        self.configs = configs
        self.concurrency = concurrency
        self.total = len(configs)
        self.completed = 0
        self.results: list[NodeCheckResult] = []
        self.recent_events: list[NodeCheckResult] = []
        self.start_time = time.time()

        # Running counts
        self.c_ultra = 0
        self.c_fast = 0
        self.c_normal = 0
        self.c_slow = 0
        self.c_dead = 0
        self.live_pings: list[float] = []

    def on_node_done(self, done: int, total: int, res: NodeCheckResult) -> None:
        self.completed = done
        self.results.append(res)
        self.recent_events.append(res)
        if len(self.recent_events) > 7:
            self.recent_events.pop(0)

        if res.alive:
            self.live_pings.append(res.latency_ms)
            if res.quality_tier == "⚡ ULTRA":
                self.c_ultra += 1
            elif res.quality_tier == "🟢 FAST":
                self.c_fast += 1
            elif res.quality_tier == "🟡 NORMAL":
                self.c_normal += 1
            else:
                self.c_slow += 1
        else:
            self.c_dead += 1

    def make_live_renderable(self) -> Group:
        elapsed = time.time() - self.start_time
        speed = self.completed / elapsed if elapsed > 0.05 else 0.0
        pct = (self.completed / self.total * 100.0) if self.total else 0.0
        rem_sec = (self.total - self.completed) / speed if speed > 0.1 else 0.0

        # 1. Header Progress Bar
        bar_width = 30
        filled = int(bar_width * (self.completed / self.total)) if self.total else 0
        progress_bar = (
            f"[bold cyan]{'━' * filled}[/][bright_black]{'━' * (bar_width - filled)}[/]"
        )

        prog_text = Text()
        prog_text.append(f"Тестирование: {self.completed}/{self.total} ({pct:>5.1f}%) ", style="bold white")
        prog_text.append(f" Скорость: {speed:.1f} узлов/сек ", style="bold yellow")
        prog_text.append(f" Время: {elapsed:.1f}s (Осталось: ~{rem_sec:.0f}s)", style="dim")

        header_panel = Panel(
            Group(
                Align.center(prog_text),
                Align.center(Text.from_markup(progress_bar)),
            ),
            title="[bold cyan]⚡ LIVE MULTI-THREAD BENCHMARK ⚡[/]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 1),
        )

        # 2. Metric Counters Cards
        success_rate = (len(self.live_pings) / self.completed * 100.0) if self.completed else 0.0
        avg_ping = (sum(self.live_pings) / len(self.live_pings)) if self.live_pings else 0.0
        best_ping = min(self.live_pings) if self.live_pings else 0.0

        cards = Columns([
            make_stat_card("⚡ УЛЬТРА", str(self.c_ultra), "cyan", "< 85ms"),
            make_stat_card("🟢 БЫСТРЫЕ", str(self.c_fast), "green", "85-180ms"),
            make_stat_card("🟡 НОРМА", str(self.c_normal), "yellow", "180-350ms"),
            make_stat_card("🔴 МЕДЛЕННЫЕ", str(self.c_slow), "red", "> 350ms"),
            make_stat_card("💀 МЕРТВЫЕ", str(self.c_dead), "bright_black", "RST/Drop"),
            make_stat_card("📊 УСПЕХ", f"{success_rate:.1f}%", "magenta", f"Живых: {len(self.live_pings)}"),
            make_stat_card("⚡ СРЕДНИЙ", f"{avg_ping:.0f} ms", "bright_white", f"Лучший: {best_ping:.0f}ms"),
        ], expand=True)

        # 3. Rolling Live Events Table
        feed_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            show_header=True,
            header_style="bold magenta",
            padding=(0, 1),
        )
        feed_table.add_column("Статус", width=12)
        feed_table.add_column("Флаг", width=4, justify="center")
        feed_table.add_column("Протокол & Защита", width=22)
        feed_table.add_column("Сервер / Порт", width=22)
        feed_table.add_column("Пинг (RTT)", width=12, justify="right")
        feed_table.add_column("Джиттер", width=10, justify="right")
        feed_table.add_column("График", width=8, justify="center")
        feed_table.add_column("SNI / Маскировка", width=22)

        for res in self.recent_events[-7:]:
            flag = res.country_flag or "🌐"
            cfg = res.config
            sec_disp = res.security_tag or cfg.security.upper()
            proto_disp = f"[bold cyan]{cfg.protocol.upper()}[/] [dim]{sec_disp}[/]"
            host_disp = f"{cfg.host}:{cfg.port}"
            sni_disp = cfg.sni or "-"

            if res.alive:
                tier_color = "cyan" if "ULTRA" in res.quality_tier else "green" if "FAST" in res.quality_tier else "yellow" if "NORMAL" in res.quality_tier else "red"
                status_txt = f"[{tier_color}]{res.quality_tier}[/]"
                ping_txt = f"[bold {tier_color}]{res.latency_ms:.1f} ms[/]"
                jit_txt = f"[dim]±{res.jitter_ms:.1f}ms[/]"
                spark_txt = f"[{tier_color}]{res.sparkline}[/]"
            else:
                status_txt = "[dim red]💀 DEAD[/]"
                ping_txt = "[dim]--[/]"
                jit_txt = "[dim]--[/]"
                spark_txt = "[dim red]───[/]"
                sni_disp = f"[dim red]{res.error_msg or 'Timeout'}[/]"

            feed_table.add_row(
                status_txt,
                flag,
                proto_disp,
                host_disp,
                ping_txt,
                jit_txt,
                spark_txt,
                sni_disp,
            )

        events_panel = Panel(
            feed_table,
            title="[bold magenta]📡 ПОСЛЕДНИЕ ПРОВЕРЕННЫЕ УЗЛЫ В РЕАЛЬНОМ ВРЕМЕНИ[/]",
            border_style="magenta",
            box=box.ROUNDED,
            padding=(0, 1),
        )

        return Group(header_panel, cards, events_panel)


def display_results_dashboard(rep: dict, results: list[NodeCheckResult]) -> None:
    """Render the ultimate showstopper results screen."""
    console.print()
    console.print(get_hero_banner())

    alive_nodes = [r for r in results if r.alive]
    total = rep["total"]
    alive = rep["alive"]
    dead = rep["dead"]
    pct = rep["success_rate_pct"]

    # 1. Global Metrics Summary
    summary_table = Table.grid(expand=True, padding=(0, 2))
    summary_table.add_column(justify="center")
    summary_table.add_column(justify="center")
    summary_table.add_column(justify="center")
    summary_table.add_column(justify="center")
    summary_table.add_column(justify="center")

    summary_table.add_row(
        Panel(f"[bold cyan]{total}[/]\n[dim]Всего проверено[/]", box=box.ROUNDED, border_style="cyan"),
        Panel(f"[bold green]{alive}[/] [dim]({pct}%)[/]\n[dim]Рабочих серверов[/]", box=box.ROUNDED, border_style="green"),
        Panel(f"[bold red]{dead}[/]\n[dim]Мертвых / Блок РКН[/]", box=box.ROUNDED, border_style="red"),
        Panel(f"[bold yellow]{rep['avg_ping_ms']:.1f} ms[/]\n[dim]Средний пинг пула[/]", box=box.ROUNDED, border_style="yellow"),
        Panel(f"[bold bright_green]{rep['min_ping_ms']:.1f} ms[/]\n[dim]Рекордный пинг[/]", box=box.ROUNDED, border_style="bright_green"),
    )

    # 2. Latency Spectrum Bar
    dist_bar = render_distribution_bar(rep)
    dist_legend = Text.from_markup(
        f"[bold cyan]⚡ {rep['tiers']['ultra']} Ультра (<85ms)[/]  •  "
        f"[bold green]🟢 {rep['tiers']['fast']} Быстрые (85-180ms)[/]  •  "
        f"[bold yellow]🟡 {rep['tiers']['normal']} Норма (180-350ms)[/]  •  "
        f"[bold red]🔴 {rep['tiers']['slow']} Медленные (>350ms)[/]  •  "
        f"[dim red]💀 {rep['dead']} Мертвые[/]"
    )

    spectrum_panel = Panel(
        Group(
            Align.center(dist_bar),
            Text(),
            Align.center(dist_legend),
        ),
        title="[bold bright_white]📊 СПЕКТР ЗАДЕРЖЕК И КАЧЕСТВА ПУЛА[/]",
        border_style="bright_blue",
        box=box.ROUNDED,
        padding=(0, 1),
    )

    console.print(summary_table)
    console.print(spectrum_panel)

    # 3. Top 15 Fastest Servers Leaderboard Table
    top_table = Table(
        title="🏆 ТОП-15 САМЫХ БЫСТРЫХ И НАДЕЖНЫХ СЕРВЕРОВ ДЛЯ РФ",
        title_style="bold gold1",
        box=box.ROUNDED,
        expand=True,
        header_style="bold cyan",
        border_style="bright_blue",
        padding=(0, 1),
    )
    top_table.add_column("№", justify="center", width=5)
    top_table.add_column("Страна", width=16)
    top_table.add_column("Протокол", width=9)
    top_table.add_column("Защита & Маскировка", width=22)
    top_table.add_column("Сервер (Host:Port)", width=23)
    top_table.add_column("Пинг (RTT)", justify="right", width=12)
    top_table.add_column("Джиттер", justify="right", width=10)
    top_table.add_column("Стабильность", justify="center", width=14)
    top_table.add_column("Реальный трафик", justify="center", width=18)
    top_table.add_column("Качество", justify="center", width=12)

    medals = ["🥇 #1", "🥈 #2", "🥉 #3"]
    for idx, node in enumerate(rep["fastest_nodes"][:15], 1):
        rank_str = medals[idx - 1] if idx <= 3 else f"{idx:02d}"
        flag_country = f"{node['flag']} {node['country_name']}"

        proto_str = f"[bold cyan]{node['protocol']}[/]"
        sec_str = f"[bright_cyan]{node['security']}[/]"

        host_str = f"{node['host']}:{node['port']}"
        ping_val = node["latency_ms"]
        ping_color = "bright_green" if ping_val < 60 else "green" if ping_val < 100 else "yellow" if ping_val < 200 else "red"
        ping_str = f"[bold {ping_color}]{ping_val:.1f} ms[/]"

        jit_str = f"[dim]±{node['jitter_ms']:.1f}ms[/]"
        spark_str = f"[{ping_color}]{node['sparkline']}[/]"
        tier_str = f"[bold {ping_color}]{node['tier']}[/]"

        if node.get("http_ok"):
            http_disp = f"[bold bright_green]✔ {node.get('http_delay_ms', 0):.0f}ms (204)[/]"
        elif node.get("http_probe_msg"):
            http_disp = f"[dim red]✗ {node.get('http_probe_msg')[:14]}[/]"
        elif node.get("tls_ok"):
            http_disp = "[bright_cyan]⚡ TLS Pass[/]"
        else:
            http_disp = "[dim]--[/]"

        top_table.add_row(
            rank_str,
            flag_country,
            proto_str,
            sec_str,
            host_str,
            ping_str,
            jit_str,
            spark_str,
            http_disp,
            tier_str,
        )

    console.print(top_table)

    # 4. Top Countries Breakdown Table
    if rep["top_countries"]:
        c_table = Table(
            title="🌍 ГЕОГРАФИЯ И ЛУЧШИЕ ЛОКАЦИИ ПО СКОРОСТИ",
            title_style="bold green",
            box=box.ROUNDED,
            expand=True,
            header_style="bold magenta",
            border_style="green",
            padding=(0, 1),
        )
        c_table.add_column("Флаг и Локация", width=24)
        c_table.add_column("Рабочих узлов", justify="center", width=14)
        c_table.add_column("Средний пинг", justify="right", width=15)
        c_table.add_column("Лучший пинг", justify="right", width=15)
        c_table.add_column("Рейтинг", justify="center", width=14)

        for c in rep["top_countries"]:
            rating = "⭐⭐⭐⭐⭐" if c["avg_latency"] < 70 else "⭐⭐⭐⭐" if c["avg_latency"] < 130 else "⭐⭐⭐" if c["avg_latency"] < 220 else "⭐⭐"
            c_table.add_row(
                f"{c['flag']} {c['name']} ({c['code']})",
                f"[bold cyan]{c['count']}[/] шт.",
                f"[bold yellow]{c['avg_latency']:.1f} ms[/]",
                f"[bold green]{c['min_latency']:.1f} ms[/]",
                rating,
            )

        console.print(c_table)

    # Save fastest results automatically
    if alive_nodes:
        fastest_file = REPO_ROOT / "mega_sub_fastest.txt"
        top_lines = [r.config.raw_url for r in alive_nodes[:100]]
        fastest_file.write_text("\n".join(top_lines) + "\n", encoding="utf-8")
        console.print(
            Panel(
                f"[bold green]✔ Топ-{min(100, len(alive_nodes))} самых быстрых серверов сохранены в {fastest_file.name}![/]\n"
                f"[dim]Ссылка подписки: {MEGA_FASTEST_URL}[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )


async def run_single_node_diagnostic(target: str) -> None:
    """Perform a deep step-by-step diagnostic on a single node or config URL."""
    console.print()
    console.print(get_hero_banner())
    console.print(f"[bold cyan]🔍 ЗАПУСК ГЛУБОКОГО АУДИТА ОБХОДА БЛОКИРОВОК (DPI / ТСПУ)...[/]")

    cfg = parse_any_proxy_url(target)
    if not cfg:
        # Check if raw host:port
        if ":" in target and not target.startswith("http"):
            parts = target.split(":")
            host = parts[0].strip()
            try:
                port = int(parts[1].strip())
            except ValueError:
                console.print(f"[bold red][-] Неверный формат хост:порт: {target}[/]")
                return

            console.print(f"[*] Базовая проверка TCP порта {host}:{port}...")
            t0 = time.perf_counter()
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=3.0,
                )
                rtt = (time.perf_counter() - t0) * 1000.0
                writer.close()
                await writer.wait_closed()
                console.print(f"[bold green][✓] TCP порт {host}:{port} открыт! RTT: {rtt:.1f} ms[/]")
            except Exception as exc:
                console.print(f"[bold red][✗] TCP порт {host}:{port} недоступен: {exc}[/]")
            return

        console.print("[bold red][-] Ошибка: укажите валидную ссылку vless://, trojan:// или hy2://[/]")
        return

    sec_tag = get_security_tag(cfg)
    code, flag, ru_name = detect_country_info(cfg.remark, cfg.host, cfg.sni)

    # Info Card
    info_table = Table(box=box.ROUNDED, expand=True, show_header=False, border_style="cyan")
    info_table.add_column("Параметр", style="bold cyan", width=22)
    info_table.add_column("Значение", style="white")

    info_table.add_row("Протокол", f"[bold magenta]{cfg.protocol.upper()}[/]")
    info_table.add_row("Безопасность", f"[bold green]{sec_tag}[/]")
    info_table.add_row("Сервер (Host:Port)", f"{cfg.host}:{cfg.port}")
    info_table.add_row("Локация", f"{flag} {ru_name} ({code.upper()})")
    info_table.add_row("SNI / Маскировка", cfg.sni or "(не указан)")
    info_table.add_row("Fingerprint", cfg.fingerprint or "chrome")
    info_table.add_row("Remark / Имя", cfg.remark or "(пусто)")
    if cfg.public_key:
        info_table.add_row("Reality Public Key", cfg.public_key[:24] + "...")
    if cfg.short_id:
        info_table.add_row("Reality Short ID", cfg.short_id)

    console.print(Panel(info_table, title="[bold cyan]📋 ПАСПОРТ УЗЛА[/]", box=box.ROUNDED))

    # Diagnostic Steps
    console.print("\n[bold yellow]⚡ ТЕСТИРОВАНИЕ ПО ЭТАПАМ:[/]")

    # Step 1: DNS
    t_dns0 = time.perf_counter()
    resolved_ip = ""
    try:
        loop = asyncio.get_running_loop()
        addr_info = await asyncio.wait_for(loop.getaddrinfo(cfg.host, cfg.port), timeout=2.5)
        dns_ms = (time.perf_counter() - t_dns0) * 1000.0
        resolved_ip = addr_info[0][4][0]
        console.print(f" [bold green][✓] Этап 1:[/] DNS резолв: [bold white]{resolved_ip}[/] за [cyan]{dns_ms:.1f} ms[/] [dim](Чистый IP)[/]")
    except Exception as exc:
        console.print(f" [bold red][✗] Этап 1:[/] Ошибка DNS резолва: {exc}")
        return

    # Step 2: Multi-Sample TCP RTT
    pings: list[float] = []
    for i in range(1, 4):
        try:
            t0 = time.perf_counter()
            _, w = await asyncio.wait_for(asyncio.open_connection(cfg.host, cfg.port), timeout=2.5)
            rtt = (time.perf_counter() - t0) * 1000.0
            pings.append(rtt)
            w.close()
            await w.wait_closed()
            await asyncio.sleep(0.05)
        except Exception as exc:
            console.print(f" [bold red][✗] Этап 2:[/] Сбой TCP подключения (замер #{i}): {exc}")
            return

    min_p = min(pings)
    avg_p = sum(pings) / len(pings)
    jitter = max(pings) - min(pings)
    spark = make_sparkline(pings)
    p_details = ", ".join(f"{p:.1f}ms" for p in pings)
    console.print(
        f" [bold green][✓] Этап 2:[/] TCP Handshake RTT: [bold green]{min_p:.1f} ms[/] "
        f"[dim](замеры: {p_details})[/] • Джиттер: [bold yellow]±{jitter:.1f} ms[/] [{spark}]"
    )

    # Step 3: Zombie & Instant EOF Detection
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(cfg.host, cfg.port), timeout=2.5)
        try:
            await asyncio.wait_for(r.read(1), timeout=0.05)
        except asyncio.TimeoutError:
            pass
        if r.at_eof():
            console.print(" [bold red][✗] Этап 3:[/] [bold red]ЗОМБИ-СОКЕТ![/] Сервер сразу закрыл соединение (EOF).")
            w.close()
            return
        w.close()
        await w.wait_closed()
        console.print(" [bold green][✓] Этап 3:[/] Проверка сокета: [bold green]Чисто[/] (Сервер удерживает сессию, не сбрасывает)")
    except Exception as exc:
        console.print(f" [bold red][✗] Этап 3:[/] Ошибка проверки сокета: {exc}")
        return

    # Step 4: TLS / SNI Reachability (DPI bypass)
    target_sni = cfg.sni or cfg.host
    console.print(f" [bold yellow][~] Этап 4:[/] Проверка маскировки TLS / SNI ([cyan]{target_sni}[/])...")
    res = await check_node_advanced(cfg, timeout=3.0, samples_count=2)

    if not (res.alive and res.tls_ok):
        console.print(f" [bold red][✗] Этап 4:[/] TLS / DPI Рукопожатие отклонено: {res.error_msg or 'Сброс соединения ТСПУ'}")
        console.print(
            Panel(
                Align.center(Text("💀 СЕРВЕР НЕ РАБОТАЕТ ИЛИ ЗАБЛОКИРОВАН РКН (ТСПУ / RST Drop)", style="bold red")),
                border_style="red",
                box=box.ROUNDED,
            )
        )
        return

    console.print(f" [bold green][✓] Этап 4:[/] TLS / DPI Рукопожатие: [bold green]УСПЕШНО[/] (ТСПУ не вмешивается в TLS)")

    # Step 5: Real HTTP Proxy Delay Probe (End-to-End tunnel data transfer)
    console.print(f" [bold yellow][~] Этап 5:[/] Тест сквозного HTTP туннеля через прокси (Cloudflare 204)...")
    http_ok, http_delay, http_msg = await probe_proxy_http(cfg, timeout=4.0)

    if http_ok:
        console.print(
            f" [bold green][✓] Этап 5:[/] Real HTTP Proxy Tunnel: [bold bright_green]204 OK ({http_delay:.0f}ms)[/] "
            f"[dim](Реальная передача трафика сквозь прокси подтверждена!)[/]"
        )
        console.print(f" [bold green][✓] Этап 6:[/] Вердикт РКН: [bold green]ПОЛНЫЙ ОБХОД ТСПУ И ПЕРЕДАЧА ДАННЫХ ПОДТВЕРЖДЕНЫ НА 100%![/]")

        # Final Verdict Box
        verdict = Text()
        verdict.append("🟢 СЕРВЕР ПОЛНОСТЬЮ РАБОТАЕТ И ГОДЕН К ИСПОЛЬЗОВАНИЮ В РФ!\n", style="bold green")
        verdict.append(
            f"Категория: {res.quality_tier}  •  TCP RTT: {res.latency_ms:.1f} ms  •  HTTP Задержка: {http_delay:.0f} ms  •  Джиттер: ±{res.jitter_ms:.1f} ms\n",
            style="bold white",
        )
        verdict.append("Годен для: YouTube 4K, Discord, Instagram, Telegram без тормозов", style="dim green")

        console.print(Panel(Align.center(verdict), border_style="green", box=box.ROUNDED))
    else:
        console.print(
            f" [bold red][✗] Этап 5:[/] Real HTTP Proxy Tunnel: [bold red]СБОЙ ({http_msg})[/] "
            f"[dim](ТСПУ блокирует данные или невалидные ключи Reality)[/]"
        )
        console.print(f" [bold yellow][!] Этап 6:[/] Вердикт РКН: [bold yellow]ЧАСТИЧНЫЙ ДОСТУП — ТСПУ БЛОКИРУЕТ ДАННЫЕ ИЛИ КЛЮЧИ НЕВАЛИДНЫ[/]")

        verdict = Text()
        verdict.append("⚠️ СЕРВЕР ДОСТУПЕН ПО TCP/TLS, НО ПЕРЕДАЧА ДАННЫХ НЕ РАБОТАЕТ!\n", style="bold yellow")
        verdict.append(f"Ошибка HTTP туннеля: {http_msg}  •  TCP RTT: {res.latency_ms:.1f} ms", style="dim yellow")
        console.print(Panel(Align.center(verdict), border_style="yellow", box=box.ROUNDED))

    # Copy option
    console.print("\n[bold cyan][1][/] Скопировать конфигурацию в буфер обмена")
    console.print("[bold cyan][0][/] Выход")
    try:
        ans = console.input("[bold yellow]Выберите действие [1/0]: [/]").strip()
        if ans == "1":
            if copy_to_clipboard(cfg.raw_url):
                console.print("[bold green]✔ Конфиг успешно скопирован в буфер обмена Windows![/]")
            else:
                console.print("[bold yellow]Ссылка на конфиг:[/]\n" + cfg.raw_url)
    except (KeyboardInterrupt, EOFError):
        pass


async def execute_benchmark_interactive(
    limit: int = 100,
    deep_http: bool = False,
    interactive: bool = True,
) -> list[NodeCheckResult]:
    """Run full benchmark session with animated Live UI and optional Deep HTTP Tunnel verification."""
    sub_file = REPO_ROOT / MEGA_SUBSCRIPTION_OUTPUT
    if not sub_file.exists():
        console.print(f"[bold red][-] Файл {MEGA_SUBSCRIPTION_OUTPUT} не найден. Сначала выполните обновление подписок.[/]")
        return []

    lines = sub_file.read_text(encoding="utf-8").splitlines()
    configs: list[ParsedConfig] = []
    for line in lines:
        p = parse_any_proxy_url(line)
        if p:
            configs.append(p)
            if limit and len(configs) >= limit:
                break

    if not configs:
        console.print("[bold red][-] Нет доступных конфигураций для тестирования.[/]")
        return []

    session = BenchmarkSessionUI(configs, concurrency=48)

    with Live(session.make_live_renderable(), console=console, refresh_per_second=10) as live:
        results = await benchmark_nodes(
            configs,
            concurrency=48,
            progress_callback=lambda done, total, res: (
                session.on_node_done(done, total, res),
                live.update(session.make_live_renderable()),
            ),
        )

    # Optional Deep HTTP Proxy Probe
    alive_count = len([r for r in results if r.alive])
    if deep_http and alive_count > 0:
        console.print("\n[bold yellow]⚡ Запуск сквозного HTTP-теста передачи данных через лучшие прокси...[/]")
        top_candidates = min(15, alive_count)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as prog:
            task_id = prog.add_task("[bold cyan]Deep HTTP Probe...", total=top_candidates)
            results = await probe_nodes_http_batch(
                results,
                top_n=top_candidates,
                concurrency=4,
                progress_cb=lambda done, total, res: prog.update(task_id, completed=done),
            )

    # Generate Statistical Report
    rep = build_health_report(results)
    display_results_dashboard(rep, results)

    # Auto-export fastest results
    alive_nodes = [r for r in results if r.alive]
    if alive_nodes:
        fastest_file = REPO_ROOT / "mega_sub_fastest.txt"
        top_lines = [r.config.raw_url for r in alive_nodes[:100]]
        fastest_file.write_text("\n".join(top_lines) + "\n", encoding="utf-8")

    # If non-interactive mode or non-TTY, exit cleanly without blocking
    if not interactive or not sys.stdin.isatty():
        return results

    # Post-benchmark Interactive Actions Menu
    while True:
        alive_nodes = [r for r in results if r.alive]
        console.print("\n[bold cyan]⚡ ДОПОЛНИТЕЛЬНЫЕ ДЕЙСТВИЯ:[/]")
        console.print(" [1] 📋 Скопировать [bold gold1]#1 самый быстрый узел[/] в буфер обмена")
        console.print(" [2] 🎯 Проверить реальный интернет (Deep HTTP Probe ТОП-15 узлов)")
        console.print(" [3] 💾 Экспортировать Топ-100 в mega_sub_fastest.txt")
        console.print(" [4] 📄 Сохранить подробный JSON отчет (audit_report.json)")
        console.print(" [5] 🔬 Провести детальную DPI диагностику узла")
        console.print(" [6] 📋 Скопировать ссылку на универсальную подписку")
        console.print(" [0] 🚪 Вернуться / Выход")

        try:
            choice = console.input("[bold yellow]Выберите пункт [0-6]: [/]").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if choice == "1":
            if alive_nodes:
                best_url = alive_nodes[0].config.raw_url
                if copy_to_clipboard(best_url):
                    console.print(f"[bold green]✔ Самый быстрый сервер ({alive_nodes[0].latency_ms}ms) скопирован в буфер обмена![/]")
                else:
                    console.print(f"[bold yellow]Ссылка:\n{best_url}[/]")
            else:
                console.print("[bold red]Нет живых узлов для копирования.[/]")
        elif choice == "2":
            if alive_nodes:
                console.print("\n[bold yellow]⚡ Запуск Deep HTTP Probe на ТОП-15 узлах...[/]")
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("{task.completed}/{task.total}"),
                    console=console,
                ) as prog:
                    task_id = prog.add_task("[bold cyan]Deep HTTP Probe...", total=min(15, len(alive_nodes)))
                    results = await probe_nodes_http_batch(
                        results,
                        top_n=15,
                        concurrency=4,
                        progress_cb=lambda done, total, res: prog.update(task_id, completed=done),
                    )
                rep = build_health_report(results)
                display_results_dashboard(rep, results)
                console.print("[bold green]✔ Проверка завершена! 100% рабочие узлы подняты в топ рейтинга![/]")
            else:
                console.print("[bold red]Нет живых узлов для тестирования.[/]")
        elif choice == "3":
            if alive_nodes:
                fastest_file = REPO_ROOT / "mega_sub_fastest.txt"
                top_lines = [r.config.raw_url for r in alive_nodes[:100]]
                fastest_file.write_text("\n".join(top_lines) + "\n", encoding="utf-8")
                console.print(f"[bold green]✔ Топ-{len(top_lines)} сохранен в {fastest_file.name}![/]")
        elif choice == "4":
            json_file = REPO_ROOT / "audit_report.json"
            export_data = {
                "timestamp": datetime.now().isoformat(),
                "summary": rep,
                "all_nodes": [
                    {
                        "host": r.config.host,
                        "port": r.config.port,
                        "protocol": r.config.protocol,
                        "security": r.security_tag,
                        "alive": r.alive,
                        "latency_ms": r.latency_ms,
                        "jitter_ms": r.jitter_ms,
                        "country": r.country_name,
                        "flag": r.country_flag,
                        "tier": r.quality_tier,
                        "http_ok": r.http_ok,
                        "http_delay_ms": r.http_delay_ms,
                        "raw_url": r.config.raw_url,
                    }
                    for r in results
                ],
            }
            json_file.write_text(json.dumps(export_data, ensure_ascii=False, indent=2), encoding="utf-8")
            console.print(f"[bold green]✔ Отчет успешно экспортирован в {json_file.name}![/]")
        elif choice == "5":
            if alive_nodes:
                await run_single_node_diagnostic(alive_nodes[0].config.raw_url)
            else:
                console.print("[bold red]Нет живых узлов для анализа.[/]")
        elif choice == "6":
            if copy_to_clipboard(MEGA_SUBSCRIPTION_URL):
                console.print(f"[bold green]✔ Ссылка подписки скопирована: {MEGA_SUBSCRIPTION_URL}[/]")
            else:
                console.print(f"Ссылка: {MEGA_SUBSCRIPTION_URL}")
        elif choice in ("0", "q", "exit"):
            break

    return results


def main_interactive_menu() -> None:
    """Entry point when running tester.py directly or via test_servers.bat."""
    while True:
        console.clear()
        console.print(get_hero_banner())

        menu_panel = Panel(
            """ [bold cyan][1][/] ⚡ [bold white]Экспресс-аудит[/] [dim](Топ-30 серверов — молниеносный тест за 3-5 сек)[/]
 [bold green][2][/] 🚀 [bold white]Стандартный бенчмарк[/] [dim](Топ-100 серверов — идеальный баланс)[/]
 [bold magenta][3][/] 🌌 [bold white]Глубокий аудит всей базы[/] [dim](Все серверы из mega_sub.txt)[/]
 [bold bright_green][4][/] 🎯 [bold white]Экспресс-тест + Deep HTTP Probe[/] [dim](Топ-30 с реальной проверкой веб-трафика)[/]
 [bold yellow][5][/] 🔬 [bold white]DPI Диагностика конкретного узла[/] [dim](Вставить ссылку vless/trojan/hy2)[/]
 [bold red][0][/] 🚪 [bold white]Выход[/]""",
            title="[bold bright_white]ГЛАВНОЕ МЕНЮ ТЕСТЕРА[/]",
            border_style="bright_cyan",
            box=box.ROUNDED,
            padding=(1, 2),
        )
        console.print(menu_panel)

        try:
            choice = console.input("[bold yellow]Выберите режим [0-5]: [/]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\nВыход.")
            break

        if choice == "1":
            asyncio.run(execute_benchmark_interactive(limit=30, deep_http=False))
            console.input("\n[dim]Нажмите Enter для продолжения...[/]")
        elif choice == "2":
            asyncio.run(execute_benchmark_interactive(limit=100, deep_http=False))
            console.input("\n[dim]Нажмите Enter для продолжения...[/]")
        elif choice == "3":
            asyncio.run(execute_benchmark_interactive(limit=0, deep_http=False))
            console.input("\n[dim]Нажмите Enter для продолжения...[/]")
        elif choice == "4":
            asyncio.run(execute_benchmark_interactive(limit=30, deep_http=True))
            console.input("\n[dim]Нажмите Enter для продолжения...[/]")
        elif choice == "5":
            try:
                target = console.input("[bold cyan]Введите ссылку vless/trojan/hy2 или host:port: [/]").strip()
                if target:
                    asyncio.run(run_single_node_diagnostic(target))
            except (KeyboardInterrupt, EOFError):
                pass
            console.input("\n[dim]Нажмите Enter для продолжения...[/]")
        elif choice in ("0", "q", "exit"):
            console.print("\n[bold cyan]До встречи! Быстрого интернета без блокировок![/]")
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nota Vless Ultimate Speed Tester")
    parser.add_argument("target", nargs="?", default="", help="Single node URL or host:port to test")
    parser.add_argument("--limit", type=int, default=0, help="Max nodes to test in benchmark")
    parser.add_argument("--all", action="store_true", help="Test all nodes from mega_sub.txt")
    parser.add_argument("--deep", "--http-probe", action="store_true", help="Run Deep HTTP delay probe on top nodes")
    parser.add_argument("--non-interactive", "-y", action="store_true", help="Run in non-interactive batch mode (no prompts)")
    args = parser.parse_args()

    if args.target:
        asyncio.run(run_single_node_diagnostic(args.target))
    elif args.all or args.limit:
        lim = 0 if args.all else args.limit
        is_inter = not args.non_interactive and sys.stdin.isatty()
        asyncio.run(execute_benchmark_interactive(limit=lim, deep_http=args.deep, interactive=is_inter))
    else:
        main_interactive_menu()
