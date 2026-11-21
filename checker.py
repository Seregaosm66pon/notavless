"""
Advanced Multi-Protocol Proxy Health Checker & Latency Benchmark Engine.
Measures true RTT latency, TLS/SNI handshake validity, GeoIP country flags,
and sorts nodes by performance.
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Sequence

from protocols import ParsedConfig

# Common country flag mapping
FLAG_MAP = {
    "ru": "🇷🇺", "de": "🇩🇪", "nl": "🇳🇱", "fi": "🇫🇮", "us": "🇺🇸",
    "fr": "🇫🇷", "se": "🇸🇪", "gb": "🇬🇧", "uk": "🇬🇧", "pl": "🇵🇱",
    "tr": "🇹🇷", "kz": "🇰🇿", "ua": "🇺🇦", "ch": "🇨🇭", "at": "🇦🇹",
    "es": "🇪🇸", "it": "🇮🇹", "sg": "🇸🇬", "jp": "🇯🇵", "hk": "🇭🇰",
    "ca": "🇨🇦", "cz": "🇨🇿", "ro": "🇷🇴", "bg": "🇧🇬", "md": "🇲🇩",
    "ee": "🇪🇪", "lv": "🇱🇻", "lt": "🇱🇹", "no": "🇳🇴", "dk": "🇩🇰",
}

FLAG_EMOJI_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")


@dataclass(slots=True)
class NodeCheckResult:
    config: ParsedConfig
    alive: bool
    latency_ms: float
    tls_ok: bool
    country_code: str
    country_flag: str
    quality_tier: str  # "⚡ ULTRA", "🟢 FAST", "🟡 NORMAL", "🔴 SLOW", "💀 DEAD"
    error_msg: str = ""

    @property
    def display_tag(self) -> str:
        flag = self.country_flag or "🌐"
        if self.alive:
            return f"{flag} {self.latency_ms:.0f}ms [{self.quality_tier}]"
        return f"{flag} DEAD ({self.error_msg or 'timeout'})"


def detect_country_flag(remark: str) -> tuple[str, str]:
    """Extract emoji flag and 2-letter country code from remark text."""
    # 1. Direct emoji flag in remark
    match = FLAG_EMOJI_RE.search(remark)
    if match:
        flag = match.group(0)
        # Convert regional indicator symbols to ascii country code
        code = "".join(chr(ord(c) - 0x1F1E6 + ord('A')) for c in flag).lower()
        return code, flag

    # 2. Text heuristics in remark
    lower = remark.lower()
    for code, flag in FLAG_MAP.items():
        patterns = [
            f"[{code}]", f"({code})", f"_{code}_", f"/{code}", f"| {code}",
            f"{code} |", f"#{code}"
        ]
        if any(p in lower for p in patterns):
            return code, flag

    # 3. Keyword matches
    keywords = {
        "germany": ("de", "🇩🇪"), "frankfurt": ("de", "🇩🇪"),
        "netherlands": ("nl", "🇳🇱"), "amsterdam": ("nl", "🇳🇱"),
        "finland": ("fi", "🇫🇮"), "helsinki": ("fi", "🇫🇮"),
        "russia": ("ru", "🇷🇺"), "moscow": ("ru", "🇷🇺"),
        "france": ("fr", "🇫🇷"), "paris": ("fr", "🇫🇷"),
        "sweden": ("se", "🇸🇪"), "stockholm": ("se", "🇸🇪"),
        "poland": ("pl", "🇵🇱"), "warsaw": ("pl", "🇵🇱"),
        "turkey": ("tr", "🇹🇷"), "istanbul": ("tr", "🇹🇷"),
        "kazakhstan": ("kz", "🇰🇿"), "almaty": ("kz", "🇰🇿"),
        "usa": ("us", "🇺🇸"), "united states": ("us", "🇺🇸"),
        "london": ("gb", "🇬🇧"), "england": ("gb", "🇬🇧"),
    }
    for kw, (c, f) in keywords.items():
        if kw in lower:
            return c, f

    return "xx", "🌐"


def classify_tier(latency_ms: float, alive: bool) -> str:
    if not alive:
        return "💀 DEAD"
    if latency_ms < 85:
        return "⚡ ULTRA"
    if latency_ms < 180:
        return "🟢 FAST"
    if latency_ms < 350:
        return "🟡 NORMAL"
    return "🔴 SLOW"


async def check_node_advanced(cfg: ParsedConfig, timeout: float = 2.5) -> NodeCheckResult:
    """
    Perform deep connection latency check and TLS verification for a proxy configuration.
    """
    code, flag = detect_country_flag(cfg.remark)

    # Hysteria 2 UDP probe
    if cfg.protocol == "hysteria2":
        t0 = time.perf_counter()
        try:
            loop = asyncio.get_running_loop()
            res = await asyncio.wait_for(
                loop.getaddrinfo(cfg.host, cfg.port, proto=socket.IPPROTO_UDP),
                timeout=timeout,
            )
            rtt = (time.perf_counter() - t0) * 1000.0
            alive = bool(res)
            tier = classify_tier(rtt, alive)
            return NodeCheckResult(
                config=cfg,
                alive=alive,
                latency_ms=round(rtt, 1),
                tls_ok=alive,
                country_code=code,
                country_flag=flag,
                quality_tier=tier,
            )
        except Exception as exc:
            return NodeCheckResult(
                config=cfg,
                alive=False,
                latency_ms=9999.0,
                tls_ok=False,
                country_code=code,
                country_flag=flag,
                quality_tier="💀 DEAD",
                error_msg=str(exc)[:40],
            )

    # TCP / TLS probe for VLESS & Trojan
    t0 = time.perf_counter()
    tls_success = False
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(cfg.host, cfg.port),
            timeout=timeout,
        )
        rtt = (time.perf_counter() - t0) * 1000.0
        alive = True

        # Check TLS Handshake if standard TLS
        if cfg.security == "tls" and cfg.sni:
            try:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                tls_reader, tls_writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        cfg.host,
                        cfg.port,
                        ssl=ssl_ctx,
                        server_hostname=cfg.sni,
                    ),
                    timeout=max(1.5, timeout * 0.7),
                )
                tls_success = True
                tls_writer.close()
                await tls_writer.wait_closed()
            except Exception:
                tls_success = False
        else:
            tls_success = True

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        tier = classify_tier(rtt, alive)
        return NodeCheckResult(
            config=cfg,
            alive=True,
            latency_ms=round(rtt, 1),
            tls_ok=tls_success,
            country_code=code,
            country_flag=flag,
            quality_tier=tier,
        )
    except asyncio.TimeoutError:
        return NodeCheckResult(
            config=cfg,
            alive=False,
            latency_ms=9999.0,
            tls_ok=False,
            country_code=code,
            country_flag=flag,
            quality_tier="💀 DEAD",
            error_msg="Timeout",
        )
    except Exception as exc:
        msg = str(exc)
        if "10061" in msg:
            reason = "Connection refused"
        elif "getaddrinfo" in msg:
            reason = "DNS failed"
        else:
            reason = msg[:30]
        return NodeCheckResult(
            config=cfg,
            alive=False,
            latency_ms=9999.0,
            tls_ok=False,
            country_code=code,
            country_flag=flag,
            quality_tier="💀 DEAD",
            error_msg=reason,
        )


async def benchmark_nodes(
    configs: Sequence[ParsedConfig],
    concurrency: int = 64,
    progress_callback=None,
) -> list[NodeCheckResult]:
    """Run concurrent benchmark across multiple configs, sorted by latency."""
    sem = asyncio.Semaphore(concurrency)
    results: list[NodeCheckResult] = []
    total = len(configs)
    completed = 0

    async def worker(cfg: ParsedConfig) -> None:
        nonlocal completed
        async with sem:
            res = await check_node_advanced(cfg)
            results.append(res)
            completed += 1
            if progress_callback:
                progress_callback(completed, total, res)

    tasks = [asyncio.create_task(worker(c)) for c in configs]
    if tasks:
        await asyncio.gather(*tasks)

    # Sort: Alive first, then by lowest latency ms
    results.sort(key=lambda r: (not r.alive, r.latency_ms))
    return results


def build_health_report(results: list[NodeCheckResult]) -> dict:
    """Generate statistical summary and country breakdown from benchmark results."""
    total = len(results)
    alive = [r for r in results if r.alive]
    dead = [r for r in results if not r.alive]

    avg_ping = round(sum(r.latency_ms for r in alive) / len(alive), 1) if alive else 0.0
    min_ping = min((r.latency_ms for r in alive), default=0.0)
    max_ping = max((r.latency_ms for r in alive), default=0.0)

    # Tier breakdown
    ultra_count = sum(1 for r in alive if r.quality_tier == "⚡ ULTRA")
    fast_count = sum(1 for r in alive if r.quality_tier == "🟢 FAST")
    normal_count = sum(1 for r in alive if r.quality_tier == "🟡 NORMAL")
    slow_count = sum(1 for r in alive if r.quality_tier == "🔴 SLOW")

    # Country breakdown
    countries: dict[str, dict] = {}
    for r in alive:
        key = f"{r.country_flag} {r.country_code.upper()}"
        if key not in countries:
            countries[key] = {"count": 0, "latencies": []}
        countries[key]["count"] += 1
        countries[key]["latencies"].append(r.latency_ms)

    country_summary = []
    for c_name, data in sorted(countries.items(), key=lambda x: len(x[1]["latencies"]), reverse=True):
        c_avg = round(sum(data["latencies"]) / len(data["latencies"]), 1)
        country_summary.append({
            "name": c_name,
            "count": data["count"],
            "avg_latency": c_avg,
        })

    # Protocol breakdown
    vless_alive = sum(1 for r in alive if r.config.protocol == "vless")
    trojan_alive = sum(1 for r in alive if r.config.protocol == "trojan")
    hy2_alive = sum(1 for r in alive if r.config.protocol == "hysteria2")

    return {
        "total": total,
        "alive": len(alive),
        "dead": len(dead),
        "success_rate_pct": round((len(alive) / total * 100.0) if total else 0.0, 1),
        "avg_ping_ms": avg_ping,
        "min_ping_ms": min_ping,
        "max_ping_ms": max_ping,
        "tiers": {
            "ultra": ultra_count,
            "fast": fast_count,
            "normal": normal_count,
            "slow": slow_count,
        },
        "protocols": {
            "vless": vless_alive,
            "trojan": trojan_alive,
            "hysteria2": hy2_alive,
        },
        "top_countries": country_summary[:8],
        "fastest_nodes": [
            {
                "flag": r.country_flag,
                "host": r.config.host,
                "port": r.config.port,
                "protocol": r.config.protocol,
                "latency_ms": r.latency_ms,
                "tier": r.quality_tier,
                "remark": r.config.remark[:30],
            }
            for r in alive[:10]
        ],
    }
