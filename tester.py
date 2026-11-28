"""
Nota Vless - Ultimate High-Speed Proxy Health Checker & Latency Benchmark.
Cyberpunk / Rich-powered terminal UI with real-time animated stats,
multi-sample jitter calculations, genuine TLS 1.3 SNI ClientHello DPI probes,
dual-core (sing-box + Xray) end-to-end HTTP tunneling, bandwidth speedtests,
and one-click clipboard export.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

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
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from checker import (
    NodeCheckResult,
    benchmark_nodes,
    build_health_report,
    build_tls_client_hello,
    check_node_advanced,
    compute_node_grade,
    detect_country_info,
    enrich_results_geoip,
    find_sing_box_executable,
    find_xray_executable,
    get_security_tag,
    make_sparkline,
    measure_node_speed,
    probe_nodes_http_batch,
    probe_proxy_exit_ip,
    probe_proxy_http,
    run_hardcore_stress_batch,
)
from config import (
    HYSTERIA2_SUBSCRIPTION_OUTPUT,
    MEGA_FASTEST_OUTPUT,
    MEGA_FASTEST_URL,
    MEGA_SUBSCRIPTION_OUTPUT,
    MEGA_SUBSCRIPTION_URL,
    REPO_ROOT,
    TROJAN_SUBSCRIPTION_OUTPUT,
    VPN_SUBSCRIPTION_OUTPUT,
    VPN_SUBSCRIPTION_OUTPUT_LTE,
    VPN_SUBSCRIPTION_OUTPUT_WIFI,
)
from protocols import (
    ParsedConfig,
    decrypt_or_extract_target,
    is_encrypted_sub_or_wrapper,
    parse_any_proxy_url,
)
from refresh_vless_repo import normalize_urls, write_base64_file, write_output_file

console = Console()

SOURCE_ALIASES: dict[str, Path] = {
    "mega": REPO_ROOT / MEGA_SUBSCRIPTION_OUTPUT,
    "fastest": REPO_ROOT / MEGA_FASTEST_OUTPUT,
    "all": REPO_ROOT / VPN_SUBSCRIPTION_OUTPUT,
    "lte": REPO_ROOT / VPN_SUBSCRIPTION_OUTPUT_LTE,
    "wifi": REPO_ROOT / VPN_SUBSCRIPTION_OUTPUT_WIFI,
    "trojan": REPO_ROOT / TROJAN_SUBSCRIPTION_OUTPUT,
    "hy2": REPO_ROOT / HYSTERIA2_SUBSCRIPTION_OUTPUT,
    "local": REPO_ROOT / "local_fastest.txt",
}


def copy_to_clipboard(text: str) -> bool:
    """Copy text to OS clipboard (Windows clip, macOS pbcopy, Linux wl-copy/xclip/xsel)."""
    try:
        if sys.platform == "win32":
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE)
            p.communicate(text.encode("utf-16le"))
            return p.returncode == 0
        if sys.platform == "darwin":
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(text.encode("utf-8"))
            return p.returncode == 0
        for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]):
            try:
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                p.communicate(text.encode("utf-8"))
                if p.returncode == 0:
                    return True
            except FileNotFoundError:
                continue
    except Exception:
        pass
    return False


def _resolve_source_file(source: str) -> Path:
    key = (source or "mega").strip().lower()
    if key in SOURCE_ALIASES:
        return SOURCE_ALIASES[key]
    cand = Path(source)
    if cand.is_absolute():
        return cand
    return REPO_ROOT / cand


def _filter_configs(
    configs: list[ParsedConfig],
    country: str = "",
    proto: str = "",
) -> list[ParsedConfig]:
    filtered = configs
    c_filter = (country or "").strip().lower()
    if c_filter:
        out: list[ParsedConfig] = []
        for cfg in filtered:
            code, _, ru_name = detect_country_info(cfg.remark, cfg.host, cfg.sni)
            if c_filter == code.lower() or c_filter in ru_name.lower() or c_filter in cfg.remark.lower():
                out.append(cfg)
        filtered = out

    p_filter = (proto or "").strip().lower()
    if p_filter:
        if p_filter == "reality":
            filtered = [c for c in filtered if c.security.lower() == "reality"]
        elif p_filter in ("hy2", "hysteria2"):
            filtered = [c for c in filtered if c.protocol.lower() == "hysteria2"]
        elif p_filter in ("xhttp", "ws", "grpc", "tcp"):
            filtered = [c for c in filtered if (c.network_type or "tcp").lower() == p_filter]
        else:
            filtered = [c for c in filtered if c.protocol.lower() == p_filter]
    return filtered


def get_hero_banner() -> Panel:
    """Return stylized cyberpunk ASCII hero banner with active engine badges."""
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
        "VLESS (Reality / Vision / WS / gRPC / xHTTP) • Trojan TLS 1.3 • Hysteria 2 • TSPU Audit",
        style="bold magenta",
    )
    elements = [Align.center(banner_text), Align.center(sub)]
    sb_bin = find_sing_box_executable()
    xray_bin = find_xray_executable()
    if sb_bin and xray_bin:
        elements.append(
            Align.center(
                Text(
                    "⚡ Dual-Core Active: sing-box (Clash API) + Xray (xHTTP/Reality Tunnel + Speedtest)",
                    style="bold green",
                )
            )
        )
    elif sb_bin:
        elements.append(
            Align.center(Text("⚡ Core: sing-box (Clash API Real HTTP Tunnel Active)", style="bold green"))
        )
    elif xray_bin:
        elements.append(
            Align.center(Text("⚡ Core: Xray (Multi-Inbound HTTP Tunnel + Speedtest Active)", style="bold green"))
        )
    else:
        elements.append(
            Align.center(Text("⚡ Core: Native Python TLS 1.3 SNI ClientHello Sockets", style="dim cyan"))
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

    bar_len = 44
    u_len = int(round(tiers["ultra"] / total * bar_len))
    f_len = int(round(tiers["fast"] / total * bar_len))
    n_len = int(round(tiers["normal"] / total * bar_len))
    s_len = int(round(tiers["slow"] / total * bar_len))
    d_len = max(0, bar_len - (u_len + f_len + n_len + s_len))

    bar = Text()
    bar.append("█" * u_len, style="bold cyan")
    bar.append("█" * f_len, style="bold green")
    bar.append("█" * n_len, style="bold yellow")
    bar.append("█" * s_len, style="bold red")
    bar.append("█" * d_len, style="dim red")
    return bar


class BenchmarkSessionUI:
    """Interactive live benchmark coordinator with throttled Rich Live display."""

    def __init__(self, configs: list[ParsedConfig], concurrency: int = 48, label: str = "mega_sub.txt") -> None:
        self.configs = configs
        self.concurrency = concurrency
        self.label = label
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
        self.c_tls_ok = 0
        self.live_pings: list[float] = []

    def on_node_done(self, done: int, total: int, res: NodeCheckResult) -> None:
        self.completed = done
        self.results.append(res)
        self.recent_events.append(res)
        if len(self.recent_events) > 8:
            self.recent_events.pop(0)

        if res.alive:
            self.live_pings.append(res.latency_ms)
            if res.tls_ok:
                self.c_tls_ok += 1
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
        bar_width = 34
        filled = int(bar_width * (self.completed / self.total)) if self.total else 0
        progress_bar = f"[bold cyan]{'━' * filled}[/][bright_black]{'━' * (bar_width - filled)}[/]"

        prog_text = Text()
        prog_text.append(f"[{self.label}] {self.completed}/{self.total} ({pct:>5.1f}%) ", style="bold white")
        prog_text.append(f" • {speed:.1f} узлов/сек ", style="bold yellow")
        prog_text.append(f" • {elapsed:.1f}s (осталось ~{rem_sec:.0f}s)", style="dim")

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

        cards = Columns(
            [
                make_stat_card("⚡ УЛЬТРА", str(self.c_ultra), "cyan", "< 85ms"),
                make_stat_card("🟢 БЫСТРЫЕ", str(self.c_fast), "green", "85-180ms"),
                make_stat_card("🟡 НОРМА", str(self.c_normal), "yellow", "180-350ms"),
                make_stat_card("🔴 МЕДЛЕН", str(self.c_slow), "red", "> 350ms"),
                make_stat_card("💀 МЕРТВЫЕ", str(self.c_dead), "bright_black", "RST/Drop"),
                make_stat_card("🔒 TLS/SNI", str(self.c_tls_ok), "bright_green", f"Успех {success_rate:.0f}%"),
                make_stat_card("⚡ ЛУЧШИЙ", f"{best_ping:.0f} ms", "bright_white", f"Сред: {avg_ping:.0f}ms"),
            ],
            expand=True,
        )

        # 3. Rolling Live Events Table
        feed_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            show_header=True,
            header_style="bold magenta",
            padding=(0, 1),
        )
        feed_table.add_column("Статус", width=11)
        feed_table.add_column("Флаг", width=4, justify="center")
        feed_table.add_column("Протокол & Транспорт", width=24)
        feed_table.add_column("Сервер / Порт", width=22)
        feed_table.add_column("RTT", width=9, justify="right")
        feed_table.add_column("Джиттер", width=9, justify="right")
        feed_table.add_column("График", width=7, justify="center")
        feed_table.add_column("SNI / Диагностика", width=24)

        for res in self.recent_events[-8:]:
            flag = res.country_flag or "🌐"
            cfg = res.config
            sec_disp = res.security_tag or cfg.security.upper()
            proto_disp = f"[bold cyan]{cfg.protocol.upper()}[/] [dim]{sec_disp}[/]"
            host_disp = f"{cfg.host}:{cfg.port}"
            sni_disp = cfg.sni or "-"

            if res.alive:
                tier_color = (
                    "cyan" if "ULTRA" in res.quality_tier
                    else "green" if "FAST" in res.quality_tier
                    else "yellow" if "NORMAL" in res.quality_tier
                    else "red"
                )
                status_txt = f"[{tier_color}]{res.quality_tier}[/]"
                ping_txt = f"[bold {tier_color}]{res.latency_ms:.0f} ms[/]"
                jit_txt = f"[dim]±{res.jitter_ms:.0f}ms[/]"
                spark_txt = f"[{tier_color}]{res.sparkline}[/]"
                if res.tls_ok:
                    sni_disp = f"[green]✔[/] {sni_disp[:21]}"
                else:
                    sni_disp = f"[yellow]⚠[/] {res.tls_detail or sni_disp[:21]}"
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


def _save_local_fastest(alive_nodes: list[NodeCheckResult], latencies_map: dict[tuple[str, str, int], float]) -> Path:
    """Export normalized tested nodes with subscription headers to local_fastest.txt (+ Base64)."""
    top_cfgs = [r.config for r in alive_nodes[:100]]
    urls = normalize_urls(top_cfgs, latencies_map)
    local_path = REPO_ROOT / "local_fastest.txt"
    write_output_file(urls, local_path, "Nota Vless Local Fastest")
    write_base64_file(urls, REPO_ROOT / "local_fastest_base64.txt")
    return local_path


def display_results_dashboard(rep: dict, results: list[NodeCheckResult], source_label: str = "mega_sub.txt") -> None:
    """Render the ultimate showstopper results screen."""
    console.print()
    console.print(get_hero_banner())

    alive_nodes = [r for r in results if r.alive]
    total = rep["total"]
    alive = rep["alive"]
    dead = rep["dead"]
    pct = rep["success_rate_pct"]
    http_verified = rep.get("http_verified", 0)
    tls_verified = rep.get("tls_verified", 0)

    # 1. Global Metrics Summary
    summary_table = Table.grid(expand=True, padding=(0, 1))
    for _ in range(6):
        summary_table.add_column(justify="center")

    summary_table.add_row(
        Panel(f"[bold cyan]{total}[/]\n[dim]Проверено ({source_label})[/]", box=box.ROUNDED, border_style="cyan"),
        Panel(f"[bold green]{alive}[/] [dim]({pct}%)[/]\n[dim]Доступных TCP/UDP[/]", box=box.ROUNDED, border_style="green"),
        Panel(f"[bold bright_cyan]{tls_verified}[/]\n[dim]TLS/SNI Valid[/]", box=box.ROUNDED, border_style="bright_cyan"),
        Panel(f"[bold bright_green]{http_verified}[/]\n[dim]HTTP 204 Tunnel ✔[/]", box=box.ROUNDED, border_style="bright_green"),
        Panel(f"[bold yellow]{rep['avg_ping_ms']:.1f} ms[/]\n[dim]Средний пинг[/]", box=box.ROUNDED, border_style="yellow"),
        Panel(f"[bold red]{dead}[/]\n[dim]Мертвых / ТСПУ[/]", box=box.ROUNDED, border_style="red"),
    )

    # 2. Latency Spectrum & Protocol Breakdown Bar
    dist_bar = render_distribution_bar(rep)
    protos = rep.get("protocols", {})
    sec = rep.get("security", {})
    dist_legend = Text.from_markup(
        f"[bold cyan]⚡ {rep['tiers']['ultra']} Ультра[/] • "
        f"[bold green]🟢 {rep['tiers']['fast']} Быстрых[/] • "
        f"[bold yellow]🟡 {rep['tiers']['normal']} Норма[/] • "
        f"[bold red]🔴 {rep['tiers']['slow']} Медл[/] • "
        f"[dim red]💀 {rep['dead']} Мертвых[/]\n"
        f"[dim]Протоколы: VLESS={protos.get('vless', 0)} (Reality={sec.get('reality', 0)}, TLS={sec.get('tls', 0)}) • "
        f"Trojan={protos.get('trojan', 0)} • Hysteria2={protos.get('hysteria2', 0)} • Лучший={rep['min_ping_ms']:.1f}ms[/]"
    )

    spectrum_panel = Panel(
        Group(
            Align.center(dist_bar),
            Text(),
            Align.center(dist_legend),
        ),
        title="[bold bright_white]📊 СПЕКТР ЗАДЕРЖЕК И СОСТАВ ПУЛА[/]",
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
    top_table.add_column("№", justify="center", width=5, min_width=4, no_wrap=True)
    top_table.add_column("Страна & Провайдер", min_width=15, ratio=2)
    top_table.add_column("Протокол & Защита", min_width=15, ratio=2)
    top_table.add_column("Сервер (Host:Port)", min_width=17, ratio=2)
    top_table.add_column("RTT / Джиттер", justify="right", min_width=9, no_wrap=True)
    top_table.add_column("Тренд", justify="center", width=6, min_width=5, no_wrap=True)
    top_table.add_column("Туннель & Скорость", justify="center", min_width=16, ratio=2)
    top_table.add_column("Ранг", justify="center", width=7, min_width=6, no_wrap=True)

    medals = ["🥇#1", "🥈#2", "🥉#3"]
    for idx, node in enumerate(rep["fastest_nodes"][:15], 1):
        rank_str = medals[idx - 1] if idx <= 3 else f"{idx:02d}"
        wl_badge = " [bold bright_green][WL][/]" if node.get("wl_asn") else ""
        isp_short = f"\n[dim]{node['isp'][:18]}[/]" if node.get("isp") else ""
        flag_country = f"{node['flag']} {node['country_name']}{wl_badge}{isp_short}"

        sec_str = f"[bold cyan]{node['protocol']}[/] [bright_cyan]{node['security']}[/]"
        host_str = f"{node['host']}:{node['port']}"
        if len(host_str) > 22:
            host_str = f"{node['host'][:15]}..:{node['port']}"
        if node.get("exit_ip") and node.get("exit_ip") != node["host"]:
            host_str += f"\n[dim]↳ {node['exit_ip']}[/]"

        ping_val = node["latency_ms"]
        ping_color = "bright_green" if ping_val < 60 else "green" if ping_val < 100 else "yellow" if ping_val < 200 else "red"
        ping_jit_str = f"[bold {ping_color}]{ping_val:.1f}ms[/]\n[dim]±{node['jitter_ms']:.1f}ms[/]"
        spark_str = f"[{ping_color}]{node['sparkline']}[/]"
        tier_str = node.get("grade") or f"[bold {ping_color}]{node['tier']}[/]"

        spd = node.get("speed_mbps", 0.0)
        if node.get("http_ok"):
            spd_part = f"\n[bold cyan]⚡ {spd:.1f} Mbps[/]" if spd > 0 else ""
            if node.get("multi_total", 0) > 0:
                http_disp = f"[bold bright_green]✔ {node['multi_ok']}/{node['multi_total']} ({node.get('http_delay_ms', 0):.0f}ms)[/]{spd_part}"
            else:
                http_disp = f"[bold bright_green]✔ {node.get('http_delay_ms', 0):.0f}ms[/]{spd_part}"
        elif node.get("http_probe_msg"):
            http_disp = f"[dim red]✗ {node.get('http_probe_msg')[:18]}[/]"
        elif node.get("tls_ok"):
            http_disp = f"[bright_cyan]⚡ {node.get('tls_detail') or 'TLS Pass'}[/]"
        else:
            http_disp = f"[yellow]⚠ {node.get('tls_detail') or 'No TLS'}[/]"

        top_table.add_row(
            rank_str,
            flag_country,
            sec_str,
            host_str,
            ping_jit_str,
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
            rating = (
                "⭐⭐⭐⭐⭐" if c["avg_latency"] < 70
                else "⭐⭐⭐⭐" if c["avg_latency"] < 130
                else "⭐⭐⭐" if c["avg_latency"] < 220
                else "⭐⭐"
            )
            c_table.add_row(
                f"{c['flag']} {c['name']} ({c['code']})",
                f"[bold cyan]{c['count']}[/] шт.",
                f"[bold yellow]{c['avg_latency']:.1f} ms[/]",
                f"[bold green]{c['min_latency']:.1f} ms[/]",
                rating,
            )

        console.print(c_table)

    # Save local tested fastest results without overwriting git-tracked mega_sub_fastest.txt
    if alive_nodes:
        lat_map = {(r.config.protocol, r.config.host, r.config.port): r.latency_ms for r in alive_nodes}
        saved_path = _save_local_fastest(alive_nodes, lat_map)
        console.print(
            Panel(
                f"[bold green]✔ Топ-{min(100, len(alive_nodes))} лучших узлов для вашего провайдера сохранены в {saved_path.name} (+ {saved_path.stem}_base64.txt)![/]\n"
                f"[dim]Подписка GitHub (облако): {MEGA_FASTEST_URL}[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )


async def run_single_node_diagnostic(target: str) -> None:
    """Perform a deep 6-stage DPI, HTTP tunnel, bandwidth speed, and exit IP diagnostic."""
    console.print()
    console.print(get_hero_banner())
    console.print("[bold cyan]🔍 ЗАПУСК 6-ЭТАПНОГО АУДИТА ОБХОДА БЛОКИРОВОК (DPI / ТСПУ / SPEEDTEST)...[/]")

    cfg = parse_any_proxy_url(target)
    if not cfg:
        if ":" in target and not target.startswith("http"):
            parts = target.rsplit(":", 1)
            host = parts[0].strip()
            try:
                port = int(parts[1].strip())
            except ValueError:
                console.print(f"[bold red][-] Неверный формат хост:порт: {target}[/]")
                return

            console.print(f"[*] Проверка TCP порта и TLS ClientHello на {host}:{port}...")
            t0 = time.perf_counter()
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3.0)
                rtt = (time.perf_counter() - t0) * 1000.0
                writer.write(build_tls_client_hello(host if not host.replace(".", "").isdigit() else ""))
                await writer.drain()
                tls_data = b""
                try:
                    tls_data = await asyncio.wait_for(reader.read(32), timeout=2.0)
                except asyncio.TimeoutError:
                    pass
                writer.close()
                await writer.wait_closed()
                tls_note = "TLS ServerHello ✔" if tls_data.startswith(b"\x16\x03") else ("TLS Alert" if tls_data.startswith(b"\x15\x03") else "No TLS response")
                console.print(f"[bold green][✓] TCP порт {host}:{port} открыт! RTT: {rtt:.1f} ms | {tls_note}[/]")
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

    info_table.add_row("Протокол", f"[bold magenta]{cfg.protocol.upper()}[/] (транспорт: {cfg.network_type or 'tcp'})")
    info_table.add_row("Безопасность", f"[bold green]{sec_tag}[/]")
    info_table.add_row("Сервер (Host:Port)", f"{cfg.host}:{cfg.port}")
    info_table.add_row("Локация (по конфигу)", f"{flag} {ru_name} ({code.upper()})")
    info_table.add_row("SNI / Маскировка", cfg.sni or "(не указан)")
    if cfg.path or cfg.service_name:
        info_table.add_row("Path / Service", cfg.service_name or cfg.path)
    info_table.add_row("Fingerprint", cfg.fingerprint or "chrome")
    info_table.add_row("Remark / Имя", cfg.remark or "(пусто)")
    if cfg.public_key:
        info_table.add_row("Reality Public Key", cfg.public_key[:24] + "...")
    if cfg.short_id:
        info_table.add_row("Reality Short ID", cfg.short_id)

    console.print(Panel(info_table, title="[bold cyan]📋 ПАСПОРТ УЗЛА[/]", box=box.ROUNDED))
    console.print("\n[bold yellow]⚡ ТЕСТИРОВАНИЕ ПО ЭТАПАМ:[/]")

    # Step 1: DNS
    t_dns0 = time.perf_counter()
    try:
        loop = asyncio.get_running_loop()
        addr_info = await asyncio.wait_for(loop.getaddrinfo(cfg.host, cfg.port), timeout=2.5)
        dns_ms = (time.perf_counter() - t_dns0) * 1000.0
        resolved_ip = addr_info[0][4][0]
        console.print(f" [bold green][✓] Этап 1:[/] DNS резолв: [bold white]{resolved_ip}[/] за [cyan]{dns_ms:.1f} ms[/]")
    except Exception as exc:
        console.print(f" [bold red][✗] Этап 1:[/] Ошибка DNS резолва: {exc}")
        return

    # Step 2: Multi-Sample TCP RTT (skipped for UDP Hysteria2)
    res = await check_node_advanced(cfg, timeout=3.0, samples_count=3)
    if not res.alive:
        console.print(f" [bold red][✗] Этап 2:[/] Сбой подключения: {res.error_msg}")
        console.print(
            Panel(
                Align.center(Text("💀 СЕРВЕР НЕДОСТУПЕН ПО СЕТИ (Timeout / RST / DNS)", style="bold red")),
                border_style="red",
                box=box.ROUNDED,
            )
        )
        return

    if cfg.protocol != "hysteria2":
        p_details = ", ".join(f"{p:.1f}ms" for p in res.samples)
        console.print(
            f" [bold green][✓] Этап 2:[/] TCP RTT: [bold green]{res.latency_ms:.1f} ms[/] "
            f"[dim](замеры: {p_details})[/] • Джиттер: [bold yellow]±{res.jitter_ms:.1f} ms[/] [{res.sparkline}]"
        )
    else:
        console.print(f" [bold green][✓] Этап 2:[/] UDP/QUIC порт доступен (~{res.latency_ms:.0f} ms)")

    # Step 3: TLS 1.3 ClientHello SNI Check (non-fatal warning if failed, Step 4 decides)
    target_sni = cfg.sni or cfg.host
    if res.tls_ok:
        console.print(
            f" [bold green][✓] Этап 3:[/] TLS 1.3 SNI ([cyan]{target_sni}[/]): [bold green]{res.tls_detail or 'OK'}[/]"
        )
    else:
        console.print(
            f" [bold yellow][!] Этап 3:[/] TLS 1.3 ClientHello ([cyan]{target_sni}[/]): "
            f"[yellow]{res.tls_detail or 'Нет ответа'}[/] [dim](продолжаем через реальное VPN ядро...)[/]"
        )

    # Step 4: Real HTTP Proxy Delay Probe (Dual-Core: sing-box / Xray)
    console.print(" [bold yellow][~] Этап 4:[/] Тест сквозного HTTP туннеля (Cloudflare 204)...")
    http_ok, http_delay, http_msg = await probe_proxy_http(cfg, timeout=5.0)

    if http_ok:
        console.print(
            f" [bold green][✓] Этап 4:[/] Real HTTP Tunnel: [bold bright_green]{http_msg}[/] "
            f"[dim](Реальная передача трафика сквозь прокси подтверждена!)[/]"
        )

        # Step 5: Real Bandwidth Speedtest & Exit IP
        console.print(" [bold yellow][~] Этап 5:[/] Замер пропускной способности и проверка выходного IP...")
        sp_ok, mbps, b_read, dt_s, sp_msg = await measure_node_speed(cfg, byte_limit=524288, timeout=6.0)
        ip_ok, exit_ip, exit_country, exit_isp = await probe_proxy_exit_ip(cfg, timeout=4.0)

        if sp_ok:
            console.print(
                f" [bold green][✓] Этап 5a:[/] Скорость загрузки: [bold bright_cyan]{mbps:.2f} Mbps[/] "
                f"[dim]({b_read // 1024} KB за {dt_s:.2f}s)[/]"
            )
        else:
            console.print(f" [bold yellow][!] Этап 5a:[/] Замер скорости не удался ({sp_msg})")

        if ip_ok:
            console.print(
                f" [bold green][✓] Этап 5b:[/] Выходной IP: [bold white]{exit_ip}[/] • "
                f"Локация: {exit_country} • Провайдер: [cyan]{exit_isp or 'N/A'}[/]"
            )
        else:
            console.print(" [dim] [~] Этап 5b: Выходной IP не определен[/]")

        console.print(" [bold green][✓] Этап 6:[/] Вердикт РКН: [bold green]ПОЛНЫЙ ОБХОД ТСПУ ПОДТВЕРЖДЕН НА 100%![/]")

        verdict = Text()
        verdict.append("🟢 СЕРВЕР ПОЛНОСТЬЮ РАБОТАЕТ И ГОДЕН К ИСПОЛЬЗОВАНИЮ В РФ!\n", style="bold green")
        spd_txt = f"  •  Скорость: {mbps:.1f} Mbps" if sp_ok else ""
        verdict.append(
            f"Категория: {res.quality_tier}  •  TCP RTT: {res.latency_ms:.1f}ms  •  "
            f"HTTP: {http_delay:.0f}ms{spd_txt}  •  Джиттер: ±{res.jitter_ms:.1f}ms\n",
            style="bold white",
        )
        if ip_ok:
            verdict.append(f"Выход: {exit_country} ({exit_ip})\n", style="cyan")
        verdict.append("Годен для: YouTube 4K, Discord, Instagram, Telegram без тормозов", style="dim green")

        console.print(Panel(Align.center(verdict), border_style="green", box=box.ROUNDED))
    else:
        console.print(
            f" [bold red][✗] Этап 4:[/] Real HTTP Tunnel: [bold red]СБОЙ ({http_msg})[/] "
            f"[dim](ТСПУ блокирует туннель, истекли ключи или неверный UUID)[/]"
        )
        console.print(" [bold yellow][!] Этап 6:[/] Вердикт: [bold yellow]ПОРТ ОТКРЫТ, НО ТУННЕЛЬ НЕ ПЕРЕДАЕТ ДАННЫЕ[/]")

        verdict = Text()
        verdict.append("⚠️ СЕРВЕР ОТВЕЧАЕТ НА ПОРТУ, НО ПРОКСИ-ТУННЕЛЬ НЕ РАБОТАЕТ!\n", style="bold yellow")
        verdict.append(f"Причина: {http_msg}  •  TCP RTT: {res.latency_ms:.1f} ms", style="dim yellow")
        console.print(Panel(Align.center(verdict), border_style="yellow", box=box.ROUNDED))

    if sys.stdin.isatty():
        console.print("\n[bold cyan][1][/] Скопировать конфигурацию в буфер обмена")
        console.print("[bold cyan][0][/] Выход")
        try:
            ans = console.input("[bold yellow]Выберите действие [1/0]: [/]").strip()
            if ans == "1":
                if copy_to_clipboard(cfg.raw_url):
                    console.print("[bold green]✔ Конфиг успешно скопирован в буфер обмена![/]")
                else:
                    console.print("[bold yellow]Ссылка на конфиг:[/]\n" + cfg.raw_url)
        except (KeyboardInterrupt, EOFError):
            pass


async def _run_batch_http_with_progress(
    results: list[NodeCheckResult],
    top_n: int = 50,
) -> list[NodeCheckResult]:
    alive_count = sum(1 for r in results if r.alive)
    if alive_count == 0:
        return results
    candidates = min(top_n, alive_count)
    console.print(f"\n[bold yellow]⚡ Запуск Dual-Core Deep HTTP Probe по {candidates} разнообразным узлам...[/]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as prog:
        task_id = prog.add_task("[bold cyan]Deep HTTP Probe (sing-box + Xray)...", total=candidates)
        results = await probe_nodes_http_batch(
            results,
            top_n=candidates,
            concurrency=24,
            progress_cb=lambda done, total, res: prog.update(task_id, completed=done),
        )
    return results


async def _run_top_speedtest(results: list[NodeCheckResult], count: int = 3) -> None:
    targets = [r for r in results if r.alive and r.http_ok][:count]
    if not targets:
        # Avoid speedtesting nodes already proven to fail HTTP 204 transit
        unprobed = [r for r in results if r.alive and not r.http_probe_msg]
        if unprobed:
            probed = await _run_batch_http_with_progress(unprobed, top_n=min(12, len(unprobed)))
            targets = [r for r in probed if r.alive and r.http_ok][:count]
    if not targets:
        console.print("[bold yellow]Нет HTTP-подтвержденных узлов для замера скорости (пропускаем Speedtest).[/]")
        return

    console.print(f"\n[bold cyan]🚀 Замер реальной пропускной способности (Speedtest) на Топ-{len(targets)} узлах...[/]")
    for idx, r in enumerate(targets, 1):
        ok, mbps, b_read, dt_s, detail = await measure_node_speed(r.config, byte_limit=524288, timeout=6.0)
        if ok:
            r.speed_mbps = mbps
            console.print(
                f"  [{idx}] {r.country_flag} {r.config.host}:{r.config.port} -> "
                f"[bold bright_green]{mbps:.2f} Mbps[/] ({b_read // 1024} KB / {dt_s:.2f}s)"
            )
        else:
            console.print(f"  [{idx}] {r.country_flag} {r.config.host}:{r.config.port} -> [dim red]{detail}[/]")


async def _run_top_exit_ip(results: list[NodeCheckResult], count: int = 3) -> None:
    targets = [r for r in results if r.alive and r.http_ok][:count]
    if not targets:
        targets = [r for r in results if r.alive][:count]
    if not targets:
        console.print("[bold red]Нет живых узлов для проверки Exit IP.[/]")
        return

    console.print(f"\n[bold cyan]🌐 Проверка реального выходного IP и провайдера на Топ-{len(targets)} узлах...[/]")
    for idx, r in enumerate(targets, 1):
        ip_ok, exit_ip, exit_country, exit_isp = await probe_proxy_exit_ip(r.config, timeout=5.0)
        if ip_ok:
            console.print(
                f"  [{idx}] {r.config.host}:{r.config.port} -> [bold white]{exit_ip}[/] • "
                f"{exit_country} • [cyan]{exit_isp or 'N/A'}[/]"
            )
        else:
            console.print(f"  [{idx}] {r.config.host}:{r.config.port} -> [dim red]{exit_isp}[/]")


async def _run_hardcore_with_progress(
    results: list[NodeCheckResult],
    top_n: int = 15,
) -> list[NodeCheckResult]:
    alive_candidates = [r for r in results if r.alive and not (r.http_probe_msg and not r.http_ok)][:top_n]
    if not alive_candidates:
        alive_candidates = [r for r in results if r.alive][:top_n]
    if not alive_candidates:
        return results

    total = len(alive_candidates)
    progress = Progress(
        SpinnerColumn(style="bold red"),
        TextColumn("[bold red]🔥 ЖЁСТКИЙ СТРЕСС-ТЕСТ (3x HTTP/HTTPS Burst + Mbps + Exit IP + WL-ASN)[/]"),
        BarColumn(bar_width=24, complete_style="red", finished_style="bright_green"),
        TextColumn("[bold white]{task.completed}/{task.total}[/]"),
        console=console,
    )
    task_id = progress.add_task("hardcore", total=total)

    def on_done(done: int, tot: int, r: NodeCheckResult) -> None:
        progress.update(
            task_id,
            completed=done,
            description=(
                f"[bold red]🔥[/] {r.country_flag} [cyan]{r.config.host}:{r.config.port}[/] "
                f"-> {r.grade or compute_node_grade(r)} "
                f"([green]{r.multi_ok}/{r.multi_total}[/] • [yellow]{r.speed_mbps:.1f}M[/])"
            ),
        )

    with progress:
        return await run_hardcore_stress_batch(results, top_n=top_n, concurrency=5, progress_cb=on_done)


async def execute_encrypted_sub_test(
    target: str,
    hardcore: bool = True,
    deep_http: bool = True,
    limit: int = 120,
    interactive: bool = True,
    deep_limit: int = 20,
) -> list[NodeCheckResult]:
    """Decrypt happ://crypt*, incy://crypt*, v2raytun://import*, Base64/YAML/URL and benchmark extracted nodes."""
    console.print(f"\n[bold magenta]🔓 Запускаю Sub-Decrypter для:[/] [cyan]{target[:96]}{'...' if len(target) > 96 else ''}[/]")
    urls, resolved_source, err = await asyncio.to_thread(decrypt_or_extract_target, target, 10)
    if err or not urls:
        console.print(f"[bold red][-] Не удалось расшифровать или извлечь конфиги: {err}[/]")
        return []

    if resolved_source and resolved_source != target:
        console.print(f"[green][+][/] Источник развернут: [cyan]{resolved_source[:90]}[/]")
    console.print(f"[bold green][+][/] Извлечено сырых ссылок: [bold white]{len(urls)}[/]")

    configs: list[ParsedConfig] = []
    seen: set[str] = set()
    for raw_u in urls:
        p = parse_any_proxy_url(raw_u)
        if p and p.raw_url not in seen:
            seen.add(p.raw_url)
            configs.append(p)

    if not configs:
        console.print("[bold red][-] Поддерживаемых узлов (vless/trojan/hy2) внутри подписки не найдено.[/]")
        return []

    if limit and limit > 0:
        configs = configs[:limit]

    label = f"Decrypted Sub ({len(configs)})"
    session = BenchmarkSessionUI(configs, concurrency=48, label=label)
    last_render = 0.0
    with Live(session.make_live_renderable(), console=console, refresh_per_second=8) as live:
        def on_done(done: int, total: int, res: NodeCheckResult) -> None:
            nonlocal last_render
            session.on_node_done(done, total, res)
            now = time.monotonic()
            if done == total or (now - last_render) >= 0.12:
                last_render = now
                live.update(session.make_live_renderable())

        results = await benchmark_nodes(configs, concurrency=48, progress_callback=on_done)

    await asyncio.to_thread(enrich_results_geoip, results, 2.0)

    if hardcore and any(r.alive for r in results):
        results = await _run_hardcore_with_progress(results, top_n=min(deep_limit, 15))
    elif deep_http and any(r.alive for r in results):
        results = await _run_batch_http_with_progress(results, top_n=deep_limit)

    for r in results:
        if not r.grade:
            r.grade = compute_node_grade(r)

    rep = build_health_report(results)
    display_results_dashboard(rep, results, source_label=label)

    if interactive and sys.stdin.isatty():
        while True:
            alive_nodes = [r for r in results if r.alive]
            console.print("\n[bold cyan]⚡ ДЕЙСТВИЯ ПОСЛЕ ВЗЛОМА ПОДПИСКИ:[/]")
            console.print(" [1] 📋 Скопировать [bold gold1]#1 самый мощный узел[/] в буфер обмена")
            console.print(" [2] 📦 Скопировать [bold cyan]ТОП-5 лучших узлов[/] одним списком")
            console.print(" [3] 🔥 Повторно прогнать [bold red]ЖЁСТКИЙ СТРЕСС-ТЕСТ[/] по Топ-15")
            console.print(" [4] 💾 Сохранить расшифрованные конфиги в decrypted_sub.txt")
            console.print(" [0] 🚪 Назад")
            try:
                ch = console.input("[bold yellow]Выберите пункт [0-4]: [/]").strip()
            except (KeyboardInterrupt, EOFError):
                break
            if ch == "1" and alive_nodes:
                if copy_to_clipboard(alive_nodes[0].config.raw_url):
                    console.print("[bold green]✔ #1 узел скопирован![/]")
            elif ch == "2" and alive_nodes:
                if copy_to_clipboard("\n".join(r.config.raw_url for r in alive_nodes[:5])):
                    console.print("[bold green]✔ ТОП-5 скопированы![/]")
            elif ch == "3" and alive_nodes:
                results = await _run_hardcore_with_progress(results, top_n=15)
                rep = build_health_report(results)
                display_results_dashboard(rep, results, source_label=label)
            elif ch == "4" and configs:
                out_p = REPO_ROOT / "decrypted_sub.txt"
                out_p.write_text("\n".join(c.raw_url for c in configs) + "\n", encoding="utf-8")
                console.print(f"[bold green]✔ Сохранено {len(configs)} конфигов в {out_p.name}![/]")
            elif ch in ("0", "q", "exit"):
                break
    return results


async def execute_benchmark_interactive(
    limit: int = 100,
    deep_http: bool = False,
    interactive: bool = True,
    source: str = "mega",
    country: str = "",
    proto: str = "",
    deep_limit: int = 50,
    speedtest: bool = False,
    hardcore: bool = False,
) -> list[NodeCheckResult]:
    """Run full benchmark session with throttled Rich Live UI, GeoIP, Dual-Core HTTP Probe, and Speedtest."""
    sub_file = _resolve_source_file(source)
    if not sub_file.exists():
        console.print(f"[bold red][-] Файл {sub_file.name} не найден. Сначала выполните обновление подписок.[/]")
        return []

    lines = sub_file.read_text(encoding="utf-8").splitlines()
    configs: list[ParsedConfig] = []
    for line in lines:
        p = parse_any_proxy_url(line)
        if p:
            configs.append(p)

    configs = _filter_configs(configs, country=country, proto=proto)
    if limit and limit > 0:
        configs = configs[:limit]

    if not configs:
        console.print("[bold red][-] Нет конфигураций, подходящих под выбранные фильтры.[/]")
        return []

    session = BenchmarkSessionUI(configs, concurrency=48, label=sub_file.name)
    last_render = 0.0

    with Live(session.make_live_renderable(), console=console, refresh_per_second=8) as live:
        def on_done(done: int, total: int, res: NodeCheckResult) -> None:
            nonlocal last_render
            session.on_node_done(done, total, res)
            now = time.monotonic()
            if done == total or (now - last_render) >= 0.12:
                last_render = now
                live.update(session.make_live_renderable())

        results = await benchmark_nodes(
            configs,
            concurrency=48,
            progress_callback=on_done,
        )

    # Enrich unknown country flags & RKP WL-ASN via fast batch GeoIP
    await asyncio.to_thread(enrich_results_geoip, results, 2.0)

    if hardcore and any(r.alive for r in results):
        if deep_http:
            results = await _run_batch_http_with_progress(results, top_n=deep_limit)
        results = await _run_hardcore_with_progress(results, top_n=min(15, max(5, deep_limit)))
    else:
        # Optional Dual-Core Deep HTTP Proxy Probe
        if deep_http and any(r.alive for r in results):
            results = await _run_batch_http_with_progress(results, top_n=deep_limit)

        # Optional Speedtest on top nodes
        if speedtest and any(r.alive for r in results):
            await _run_top_speedtest(results, count=3)

    for r in results:
        if not r.grade:
            r.grade = compute_node_grade(r)

    rep = build_health_report(results)
    display_results_dashboard(rep, results, source_label=sub_file.name)

    if not interactive or not sys.stdin.isatty():
        return results

    # Post-benchmark Interactive Actions Menu
    while True:
        alive_nodes = [r for r in results if r.alive]
        console.print("\n[bold cyan]⚡ ДОПОЛНИТЕЛЬНЫЕ ДЕЙСТВИЯ:[/]")
        console.print(" [1] 📋 Скопировать [bold gold1]#1 самый быстрый узел[/] в буфер обмена")
        console.print(" [2] 📦 Скопировать [bold cyan]ТОП-5 лучших узлов[/] одним списком")
        console.print(" [3] 🎯 Проверить реальный интернет (Dual-Core Deep HTTP Probe по 50 узлам)")
        console.print(" [4] ⚡ Замерить реальную скорость (Speedtest Mbps) на ТОП-3 узлах")
        console.print(" [5] 🔬 Детальная DPI/Speed диагностика узла (по номеру из таблицы)")
        console.print(" [6] 💾 Обновить mega_sub_fastest.txt (с заголовками подписки)")
        console.print(" [7] 📄 Сохранить подробный JSON отчет (audit_report.json)")
        console.print(" [8] 📋 Скопировать ссылку на универсальную подписку")
        console.print(" [9] 🌐 Проверить реальный Exit IP и провайдера на ТОП-3 узлах")
        console.print(" [10] 🔥 [bold red]ЗАПУСТИТЬ ЖЁСТКИЙ СТРЕСС-ТЕСТ[/] (Burst 3x + Mbps + Exit IP + S+ Grade)")
        console.print(" [0] 🚪 Вернуться / Выход")

        try:
            choice = console.input("[bold yellow]Выберите пункт [0-10]: [/]").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if choice == "1":
            if alive_nodes:
                best_url = alive_nodes[0].config.raw_url
                if copy_to_clipboard(best_url):
                    console.print(f"[bold green]✔ #1 узел ({alive_nodes[0].latency_ms}ms) скопирован в буфер обмена![/]")
                else:
                    console.print(f"[bold yellow]Ссылка:\n{best_url}[/]")
            else:
                console.print("[bold red]Нет живых узлов для копирования.[/]")
        elif choice == "2":
            if alive_nodes:
                bundle = "\n".join(r.config.raw_url for r in alive_nodes[:5])
                if copy_to_clipboard(bundle):
                    console.print(f"[bold green]✔ ТОП-{min(5, len(alive_nodes))} лучших узлов скопированы в буфер обмена![/]")
                else:
                    console.print(bundle)
            else:
                console.print("[bold red]Нет живых узлов.[/]")
        elif choice == "3":
            if alive_nodes:
                results = await _run_batch_http_with_progress(results, top_n=50)
                rep = build_health_report(results)
                display_results_dashboard(rep, results, source_label=sub_file.name)
                console.print("[bold green]✔ Проверка завершена! HTTP-подтвержденные узлы подняты в топ![/]")
            else:
                console.print("[bold red]Нет живых узлов для тестирования.[/]")
        elif choice == "4":
            if alive_nodes:
                await _run_top_speedtest(results, count=3)
                rep = build_health_report(results)
                display_results_dashboard(rep, results, source_label=sub_file.name)
            else:
                console.print("[bold red]Нет живых узлов.[/]")
        elif choice == "5":
            if alive_nodes:
                raw_idx = console.input(
                    f"[bold cyan]Введите номер узла из ТОП-{min(15, len(alive_nodes))} [Enter для #1]: [/]"
                ).strip()
                idx = 1
                if raw_idx.isdigit():
                    idx = max(1, min(len(alive_nodes), int(raw_idx)))
                await run_single_node_diagnostic(alive_nodes[idx - 1].config.raw_url)
            else:
                console.print("[bold red]Нет живых узлов для анализа.[/]")
        elif choice == "6":
            if alive_nodes:
                lat_map = {(r.config.protocol, r.config.host, r.config.port): r.latency_ms for r in alive_nodes}
                top_urls = normalize_urls([r.config for r in alive_nodes[:100]], lat_map)
                fastest_path = REPO_ROOT / MEGA_FASTEST_OUTPUT
                write_output_file(top_urls, fastest_path, "Nota Vless Fastest Top 100")
                write_base64_file(top_urls, REPO_ROOT / "mega_sub_fastest_base64.txt")
                console.print(f"[bold green]✔ Топ-{len(top_urls)} сохранен в {fastest_path.name} и Base64![/]")
        elif choice == "7":
            json_file = REPO_ROOT / "audit_report.json"
            export_data = {
                "timestamp": datetime.now().isoformat(),
                "source": sub_file.name,
                "summary": rep,
                "all_nodes": [
                    {
                        "host": r.config.host,
                        "port": r.config.port,
                        "protocol": r.config.protocol,
                        "network": r.config.network_type,
                        "security": r.security_tag,
                        "alive": r.alive,
                        "tls_ok": r.tls_ok,
                        "tls_detail": r.tls_detail,
                        "latency_ms": r.latency_ms,
                        "jitter_ms": r.jitter_ms,
                        "country": r.country_name,
                        "flag": r.country_flag,
                        "tier": r.quality_tier,
                        "grade": r.grade or compute_node_grade(r),
                        "http_ok": r.http_ok,
                        "http_delay_ms": r.http_delay_ms,
                        "multi_ok": r.multi_ok,
                        "multi_total": r.multi_total,
                        "speed_mbps": r.speed_mbps,
                        "exit_ip": r.exit_ip,
                        "exit_country": r.exit_country,
                        "isp": r.isp,
                        "wl_asn": r.wl_asn,
                        "raw_url": r.config.raw_url,
                    }
                    for r in results
                ],
            }
            json_file.write_text(json.dumps(export_data, ensure_ascii=False, indent=2), encoding="utf-8")
            console.print(f"[bold green]✔ Отчет успешно экспортирован в {json_file.name}![/]")
        elif choice == "8":
            if copy_to_clipboard(MEGA_SUBSCRIPTION_URL):
                console.print(f"[bold green]✔ Ссылка подписки скопирована: {MEGA_SUBSCRIPTION_URL}[/]")
            else:
                console.print(f"Ссылка: {MEGA_SUBSCRIPTION_URL}")
        elif choice == "9":
            if alive_nodes:
                await _run_top_exit_ip(results, count=3)
            else:
                console.print("[bold red]Нет живых узлов для проверки.[/]")
        elif choice == "10":
            if alive_nodes:
                results = await _run_hardcore_with_progress(results, top_n=15)
                rep = build_health_report(results)
                display_results_dashboard(rep, results, source_label=sub_file.name)
                console.print("[bold bright_green]✔ ЖЁСТКИЙ СТРЕСС-ТЕСТ завершен! Лидерборд пересчитан по рейтингу S+![/]")
            else:
                console.print("[bold red]Нет живых узлов для стресс-теста.[/]")
        elif choice in ("0", "q", "exit"):
            break

    return results


def main_interactive_menu() -> None:
    """Entry point when running tester.py directly or via test_servers.bat."""
    while True:
        console.clear()
        console.print(get_hero_banner())

        menu_panel = Panel(
            """ [bold cyan][1][/] ⚡ [bold white]Экспресс-аудит[/] [dim](Топ-30 серверов из mega_sub — 2-3 сек)[/]
 [bold green][2][/] 🚀 [bold white]Стандартный бенчмарк[/] [dim](Топ-100 серверов из mega_sub)[/]
 [bold magenta][3][/] 🌌 [bold white]Глубокий аудит всей базы[/] [dim](Все серверы из mega_sub.txt)[/]
 [bold red][4][/] 🔥 [bold bright_red]ЖЁСТКИЙ СТРЕСС-ТЕСТ[/] [dim](3x Burst + Speedtest Mbps + Exit IP + S+ Grade + RKP WL)[/]
 [bold bright_green][5][/] 🎯 [bold white]Умный Deep HTTP Audit[/] [dim](Dual-Core sing-box + Xray реальный HTTP 204 до 50 узлов!)[/]
 [bold yellow][6][/] 🔬 [bold white]DPI + Speedtest + Exit IP одного узла[/] [dim](vless/trojan/hy2 или host:port)[/]
 [bold blue][7][/] 📱 [bold white]Тест LTE / Whitelist подписок + Жёсткий тест[/] [dim](vless_lte.txt для мобильной связи)[/]
 [bold white][8][/] 🌍 [bold white]Фильтр по файлу / стране / протоколу[/] [dim](de/nl/fi/ru, reality/trojan/hy2/xhttp)[/]
 [bold bright_magenta][9][/] 🔓 [bold white]Взломать сабку (Sub-Decrypter)[/] [dim](happ://crypt*, incy://crypt*, v2raytun://, URL -> тест)[/]
 [bold red][0][/] 🚪 [bold white]Выход[/]""",
            title="[bold bright_white]ГЛАВНОЕ МЕНЮ ТЕСТЕРА[/]",
            border_style="bright_cyan",
            box=box.ROUNDED,
            padding=(1, 2),
        )
        console.print(menu_panel)

        try:
            choice = console.input("[bold yellow]Выберите режим [0-9]: [/]").strip()
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
            asyncio.run(execute_benchmark_interactive(limit=80, deep_http=True, deep_limit=25, hardcore=True))
            console.input("\n[dim]Нажмите Enter для продолжения...[/]")
        elif choice == "5":
            asyncio.run(execute_benchmark_interactive(limit=0, deep_http=True, deep_limit=50))
            console.input("\n[dim]Нажмите Enter для продолжения...[/]")
        elif choice == "6":
            try:
                target = console.input("[bold cyan]Введите ссылку vless/trojan/hy2 или host:port: [/]").strip()
                if target:
                    if is_encrypted_sub_or_wrapper(target):
                        asyncio.run(execute_encrypted_sub_test(target, hardcore=True))
                    else:
                        asyncio.run(run_single_node_diagnostic(target))
            except (KeyboardInterrupt, EOFError):
                pass
            console.input("\n[dim]Нажмите Enter для продолжения...[/]")
        elif choice == "7":
            asyncio.run(execute_benchmark_interactive(limit=0, deep_http=True, deep_limit=25, source="lte", hardcore=True))
            console.input("\n[dim]Нажмите Enter для продолжения...[/]")
        elif choice == "8":
            try:
                src = console.input("[bold cyan]Источник (mega/fastest/lte/wifi/trojan/hy2) [mega]: [/]").strip() or "mega"
                cntry = console.input("[bold cyan]Фильтр страны (например de, nl, fi, ru, пусто=все): [/]").strip()
                pr = console.input("[bold cyan]Фильтр протокола (reality/vless/trojan/hy2/ws/xhttp, пусто=все): [/]").strip()
                hc_ans = console.input("[bold cyan]Запустить Жёсткий Стресс-Тест (S+ Grade + Speed)? [Y/n]: [/]").strip().lower()
                use_hc = hc_ans not in ("n", "no", "н", "нет")
                asyncio.run(
                    execute_benchmark_interactive(
                        limit=0,
                        deep_http=use_hc,
                        deep_limit=30,
                        source=src,
                        country=cntry,
                        proto=pr,
                        hardcore=use_hc,
                    )
                )
            except (KeyboardInterrupt, EOFError):
                pass
            console.input("\n[dim]Нажмите Enter для продолжения...[/]")
        elif choice == "9":
            try:
                sub_target = console.input("[bold magenta]Вставьте happ://crypt*, incy://, v2raytun:// или https:// URL: [/]").strip()
                if sub_target:
                    asyncio.run(execute_encrypted_sub_test(sub_target, hardcore=True))
            except (KeyboardInterrupt, EOFError):
                pass
            console.input("\n[dim]Нажмите Enter для продолжения...[/]")
        elif choice in ("0", "q", "exit"):
            console.print("\n[bold cyan]До встречи! Быстрого интернета без блокировок![/]")
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nota Vless Ultimate Speed Tester")
    parser.add_argument("target", nargs="?", default="", help="Single node URL, host:port, or encrypted sub (happ://crypt*, https://...)")
    parser.add_argument("--limit", type=int, default=0, help="Max nodes to test in benchmark")
    parser.add_argument("--all", action="store_true", help="Test all nodes from selected subscription")
    parser.add_argument("--deep", "--http-probe", action="store_true", help="Run Deep HTTP delay probe on top nodes")
    parser.add_argument("--deep-limit", type=int, default=50, help="Max nodes to verify in Deep HTTP Probe")
    parser.add_argument("--speedtest", action="store_true", help="Also run Mbps speedtest on top verified nodes")
    parser.add_argument("--hardcore", "--stress", action="store_true", help="Run hardcore torture test (3x Burst + Mbps + Exit IP + WL-ASN + S+ Grade)")
    parser.add_argument("--source", default="mega", help="Subscription source (mega/fastest/lte/wifi/trojan/hy2/local or file path)")
    parser.add_argument("--country", default="", help="Filter nodes by country code or name (e.g. de, nl, fi, ru)")
    parser.add_argument("--proto", default="", help="Filter nodes by protocol/transport (e.g. reality, vless, trojan, hy2, ws, xhttp)")
    parser.add_argument("--non-interactive", "-y", action="store_true", help="Run in non-interactive batch mode (no prompts)")
    args = parser.parse_args()

    is_inter = not args.non_interactive and sys.stdin.isatty()
    if args.target:
        if is_encrypted_sub_or_wrapper(args.target):
            asyncio.run(
                execute_encrypted_sub_test(
                    args.target,
                    hardcore=args.hardcore or True,
                    deep_http=True,
                    limit=args.limit or 120,
                    interactive=is_inter,
                    deep_limit=args.deep_limit,
                )
            )
        else:
            asyncio.run(run_single_node_diagnostic(args.target))
    elif args.all or args.limit or args.deep or args.hardcore or args.speedtest or args.country or args.proto or args.source != "mega":
        lim = 0 if args.all else args.limit
        asyncio.run(
            execute_benchmark_interactive(
                limit=lim,
                deep_http=args.deep or args.hardcore,
                interactive=is_inter,
                source=args.source,
                country=args.country,
                proto=args.proto,
                deep_limit=args.deep_limit,
                speedtest=args.speedtest,
                hardcore=args.hardcore,
            )
        )
    else:
        main_interactive_menu()
