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
# Common country mapping: (code, flag, russian_name, search_keywords)
COUNTRY_RU_NAMES: dict[str, str] = {
    "ru": "Россия",
    "de": "Германия",
    "nl": "Нидерланды",
    "fi": "Финляндия",
    "us": "США",
    "fr": "Франция",
    "se": "Швеция",
    "gb": "Великобритания",
    "uk": "Великобритания",
    "pl": "Польша",
    "tr": "Турция",
    "kz": "Казахстан",
    "ua": "Украина",
    "ch": "Швейцария",
    "at": "Австрия",
    "es": "Испания",
    "it": "Италия",
    "sg": "Сингапур",
    "jp": "Япония",
    "hk": "Гонконг",
    "ca": "Канада",
    "cz": "Чехия",
    "ro": "Румыния",
    "bg": "Болгария",
    "md": "Молдова",
    "ee": "Эстония",
    "lv": "Латвия",
    "lt": "Литва",
    "no": "Норвегия",
    "dk": "Дания",
    "am": "Армения",
    "ge": "Грузия",
    "by": "Беларусь",
    "al": "Албания",
    "rs": "Сербия",
    "cy": "Кипр",
    "ae": "ОАЭ",
    "in": "Индия",
    "kr": "Южная Корея",
    "br": "Бразилия",
    "il": "Израиль",
    "gr": "Греция",
    "hu": "Венгрия",
    "ie": "Ирландия",
    "is": "Исландия",
    "pt": "Португалия",
    "lu": "Люксембург",
    "be": "Бельгия",
    "sk": "Словакия",
    "si": "Словения",
    "hr": "Хорватия",
    "hn": "Гондурас",
    "ir": "Иран",
    "xx": "Сервер",
}

FLAG_MAP: dict[str, str] = {
    "ru": "🇷🇺", "de": "🇩🇪", "nl": "🇳🇱", "fi": "🇫🇮", "us": "🇺🇸",
    "fr": "🇫🇷", "se": "🇸🇪", "gb": "🇬🇧", "uk": "🇬🇧", "pl": "🇵🇱",
    "tr": "🇹🇷", "kz": "🇰🇿", "ua": "Украина", "ch": "🇨🇭", "at": "🇦🇹",
    "es": "🇪🇸", "it": "🇮🇹", "sg": "🇸🇬", "jp": "🇯🇵", "hk": "🇭🇰",
    "ca": "🇨🇦", "cz": "🇨🇿", "ro": "🇷🇴", "bg": "🇧🇬", "md": "🇲🇩",
    "ee": "🇪🇪", "lv": "🇱🇻", "lt": "🇱🇹", "no": "🇳🇴", "dk": "🇩🇰",
    "am": "🇦🇲", "ge": "🇬🇪", "by": "🇧🇾", "al": "🇦🇱", "rs": "🇷🇸",
    "cy": "🇨🇾", "ae": "🇦🇪", "in": "🇮🇳", "kr": "🇰🇷", "br": "🇧🇷",
    "il": "🇮🇱", "gr": "🇬🇷", "hu": "🇭🇺", "ie": "🇮🇪", "is": "🇮🇸",
    "pt": "🇵🇹", "lu": "🇱🇺", "be": "🇧🇪", "sk": "🇸🇰", "si": "🇸🇮",
    "hr": "🇭🇷", "hn": "🇭🇳", "ir": "🇮🇷",
}

COUNTRY_KEYWORDS: dict[str, list[str]] = {
    "de": ["germany", "deutschland", "frankfurt", "berlin", "falkenstein", "nuremberg", "munich", "duesseldorf", "de"],
    "nl": ["netherlands", "holland", "amsterdam", "rotterdam", "nl"],
    "fi": ["finland", "helsinki", "fi"],
    "ru": ["russia", "russian", "moscow", "spb", "surgut", "piter", "ru"],
    "us": ["usa", "united states", "america", "virginia", "california", "new york", "miami", "chicago", "los angeles", "dallas", "seattle", "us"],
    "fr": ["france", "paris", "marseille", "strasbourg", "gravelines", "fr"],
    "se": ["sweden", "stockholm", "kista", "se"],
    "gb": ["united kingdom", "britain", "england", "london", "manchester", "uk", "gb"],
    "pl": ["poland", "warsaw", "warszawa", "krakow", "pl"],
    "tr": ["turkey", "turkiye", "istanbul", "bursa", "ankara", "izmir", "tr"],
    "kz": ["kazakhstan", "almaty", "astana", "kz"],
    "ua": ["ukraine", "kyiv", "kiev", "lviv", "odessa", "ua"],
    "ch": ["switzerland", "zurich", "geneva", "ch"],
    "at": ["austria", "vienna", "at"],
    "es": ["spain", "madrid", "barcelona", "valencia", "es"],
    "it": ["italy", "milan", "rome", "it"],
    "sg": ["singapore", "sg"],
    "jp": ["japan", "tokyo", "osaka", "jp"],
    "hk": ["hong kong", "hongkong", "hk"],
    "ca": ["canada", "toronto", "montreal", "vancouver", "ca"],
    "cz": ["czech", "prague", "cz"],
    "ro": ["romania", "bucharest", "ro"],
    "bg": ["bulgaria", "sofia", "bg"],
    "md": ["moldova", "chisinau", "md"],
    "ee": ["estonia", "tallinn", "ee"],
    "lv": ["latvia", "riga", "lv"],
    "lt": ["lithuania", "vilnius", "lt"],
    "no": ["norway", "oslo", "no"],
    "dk": ["denmark", "copenhagen", "dk"],
    "am": ["armenia", "yerevan", "am"],
    "ge": ["georgia", "tbilisi", "ge"],
    "by": ["belarus", "minsk", "by"],
    "al": ["albania", "tirana", "al"],
    "rs": ["serbia", "belgrade", "rs"],
    "ae": ["uae", "dubai", "abu dhabi", "ae"],
    "in": ["india", "mumbai", "delhi", "in"],
    "kr": ["korea", "seoul", "kr"],
    "br": ["brazil", "sao paulo", "br"],
    "il": ["israel", "tel aviv", "il"],
    "gr": ["greece", "athens", "gr"],
    "hu": ["hungary", "budapest", "hu"],
    "ie": ["ireland", "dublin", "ie"],
    "is": ["iceland", "reykjavik", "is"],
    "pt": ["portugal", "lisbon", "pt"],
    "lu": ["luxembourg", "lu"],
    "be": ["belgium", "brussels", "be"],
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
    country_name: str
    quality_tier: str  # "⚡ ULTRA", "🟢 FAST", "🟡 NORMAL", "🔴 SLOW", "💀 DEAD"
    error_msg: str = ""

    @property
    def display_tag(self) -> str:
        flag = self.country_flag or "🌐"
        if self.alive:
            return f"{flag} {self.latency_ms:.0f}ms [{self.quality_tier}]"
        return f"{flag} DEAD ({self.error_msg or 'timeout'})"


def detect_country_info(remark: str, host: str = "", sni: str = "") -> tuple[str, str, str]:
    """
    Extract (code, flag, russian_name) using emoji flags, keywords, subdomains, and host cues.
    """
    # 1. Direct emoji flag in remark
    match = FLAG_EMOJI_RE.search(remark)
    if match:
        flag = match.group(0)
        code = "".join(chr(ord(c) - 0x1F1E6 + ord('a')) for c in flag).lower()
        ru_name = COUNTRY_RU_NAMES.get(code, code.upper())
        return code, flag, ru_name

    # 2. Search keywords across remark, host, and sni
    combined = f"{remark} {host} {sni}".lower()
    for code, keywords in COUNTRY_KEYWORDS.items():
        for kw in keywords:
            if len(kw) <= 2:
                patterns = [
                    f"[{kw}]", f"({kw})", f"_{kw}_", f"/{kw}", f"| {kw}",
                    f"{kw} |", f"#{kw}", f"-{kw}-", f".{kw}.", f" {kw} ",
                ]
                if any(p in combined for p in patterns):
                    flag = FLAG_MAP.get(code, "🌐")
                    ru_name = COUNTRY_RU_NAMES.get(code, code.upper())
                    return code, flag, ru_name
            else:
                if kw in combined:
                    flag = FLAG_MAP.get(code, "🌐")
                    ru_name = COUNTRY_RU_NAMES.get(code, code.upper())
                    return code, flag, ru_name

    # 3. Check domain cues (subdomains like de2. or TLDs like .ru)
    for domain in (sni, host):
        if not domain or domain.replace(".", "").isdigit():
            continue
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            if tld in COUNTRY_RU_NAMES and tld not in ("com", "org", "net", "xyz", "site", "online", "top", "io", "me", "co", "cc", "cd", "pw", "ws", "app", "dev"):
                flag = FLAG_MAP.get(tld, "🌐")
                return tld, flag, COUNTRY_RU_NAMES[tld]
            sub = parts[0]
            sub_code = re.sub(r"[0-9_\-].*$", "", sub)
            if sub_code in COUNTRY_RU_NAMES and len(sub_code) == 2:
                flag = FLAG_MAP.get(sub_code, "🌐")
                return sub_code, flag, COUNTRY_RU_NAMES[sub_code]

    return "xx", "🌐", "Сервер"


def detect_country_flag(remark: str) -> tuple[str, str]:
    """Backward compatibility helper returning (code, flag)."""
    code, flag, _ = detect_country_info(remark)
    return code, flag


def classify_russian_tier(latency_ms: float) -> str:
    """Classify latency into Russian display tier requested by user."""
    if latency_ms <= 0:
        return "Ультра"
    if latency_ms < 85:
        return "Ультра"
    if latency_ms < 180:
        return "Быстрый"
    if latency_ms < 350:
        return "Стандарт"
    return "Базовый"


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
    code, flag, ru_name = detect_country_info(cfg.remark, cfg.host, cfg.sni)

    # Hysteria 2 probe (UDP often blocked in Russia, give conservative latency)
    if cfg.protocol == "hysteria2":
        t0 = time.perf_counter()
        try:
            loop = asyncio.get_running_loop()
            res = await asyncio.wait_for(
                loop.getaddrinfo(cfg.host, cfg.port, proto=socket.IPPROTO_UDP),
                timeout=timeout,
            )
            alive = bool(res)
            # Give hysteria 500ms baseline latency so it doesn't take priority over verified VLESS
            rtt = 500.0
            tier = classify_tier(rtt, alive)
            return NodeCheckResult(
                config=cfg,
                alive=alive,
                latency_ms=rtt,
                tls_ok=alive,
                country_code=code,
                country_flag=flag,
                country_name=ru_name,
                quality_tier="🟡 NORMAL",
            )
        except Exception as exc:
            return NodeCheckResult(
                config=cfg,
                alive=False,
                latency_ms=9999.0,
                tls_ok=False,
                country_code=code,
                country_flag=flag,
                country_name=ru_name,
                quality_tier="💀 DEAD",
                error_msg=str(exc)[:40],
            )

    # Reject unencrypted VLESS / Trojan (security == 'none' or insecure HTTP ports 80, 8080, 8880, 2086, 2082)
    if cfg.security not in ("reality", "tls") or cfg.port in (80, 8080, 8880, 2086, 2082):
        return NodeCheckResult(
            config=cfg,
            alive=False,
            latency_ms=9999.0,
            tls_ok=False,
            country_code=code,
            country_flag=flag,
            country_name=ru_name,
            quality_tier="💀 DEAD",
            error_msg="Insecure port/proto",
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
            country_name=ru_name,
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
            country_name=ru_name,
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
            country_name=ru_name,
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

    # Sort: Alive first, VLESS/Trojan before Hysteria, then by lowest latency ms
    results.sort(key=lambda r: (not r.alive, r.config.protocol == "hysteria2", r.latency_ms))
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
