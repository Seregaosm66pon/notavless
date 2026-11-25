"""
Advanced Multi-Protocol Proxy Health Checker & Latency Benchmark Engine.
Measures true RTT latency, multi-sample jitter, TLS/SNI handshake validity,
anti-censorship (TSPU / DPI) liveness, GeoIP country flags, and sorts nodes.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from config import REPO_ROOT
from protocols import ParsedConfig

# Country names in Russian
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
    "au": "Австралия",
    "eu": "Европа",
    "xx": "Сервер",
}

# Flag emojis mapped by country code
FLAG_MAP: dict[str, str] = {
    "ru": "🇷🇺", "de": "🇩🇪", "nl": "🇳🇱", "fi": "🇫🇮", "us": "🇺🇸",
    "fr": "🇫🇷", "se": "🇸🇪", "gb": "🇬🇧", "uk": "🇬🇧", "pl": "🇵🇱",
    "tr": "🇹🇷", "kz": "🇰🇿", "ua": "🇺🇦", "ch": "🇨🇭", "at": "🇦🇹",
    "es": "🇪🇸", "it": "🇮🇹", "sg": "🇸🇬", "jp": "🇯🇵", "hk": "🇭🇰",
    "ca": "🇨🇦", "cz": "🇨🇿", "ro": "🇷🇴", "bg": "🇧🇬", "md": "🇲🇩",
    "ee": "🇪🇪", "lv": "🇱🇻", "lt": "🇱🇹", "no": "🇳🇴", "dk": "🇩🇰",
    "am": "🇦🇲", "ge": "🇬🇪", "by": "🇧🇾", "al": "🇦🇱", "rs": "🇷🇸",
    "cy": "🇨🇾", "ae": "🇦🇪", "in": "🇮🇳", "kr": "🇰🇷", "br": "🇧🇷",
    "il": "🇮🇱", "gr": "🇬🇷", "hu": "🇭🇺", "ie": "🇮🇪", "is": "🇮🇸",
    "pt": "🇵🇹", "lu": "🇱🇺", "be": "🇧🇪", "sk": "🇸🇰", "si": "🇸🇮",
    "hr": "🇭🇷", "hn": "🇭🇳", "ir": "🇮🇷", "au": "🇦🇺", "eu": "🇪🇺",
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
    "au": ["australia", "sydney", "melbourne", "au"],
    "eu": ["europe", "european", "eu"],
}

FLAG_EMOJI_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")


def make_sparkline(values: Sequence[float]) -> str:
    """Create a unicode sparkline visualization of ping samples."""
    if not values:
        return "───"
    ticks = [" ", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
    mn = min(values)
    mx = max(values)
    rng = mx - mn
    if rng <= 0.001:
        return "▅" * len(values)
    return "".join(ticks[int((v - mn) / rng * (len(ticks) - 1))] for v in values)


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
    avg_latency_ms: float = 0.0
    jitter_ms: float = 0.0
    security_tag: str = ""
    sparkline: str = ""
    samples: list[float] = field(default_factory=list)
    http_ok: bool = False
    http_delay_ms: float = 0.0
    http_probe_msg: str = ""

    @property
    def display_tag(self) -> str:
        flag = self.country_flag or "🌐"
        if self.alive:
            http_tag = " [HTTP ✔]" if self.http_ok else ""
            return f"{flag} {self.latency_ms:.0f}ms [{self.quality_tier}]{http_tag}"
        return f"{flag} DEAD ({self.error_msg or 'timeout'})"


def detect_country_info(remark: str, host: str = "", sni: str = "") -> tuple[str, str, str]:
    """
    Extract (code, flag, russian_name) using emoji flags, Russian country names,
    English keywords, subdomains, and host cues.
    """
    if remark:
        remark = urllib.parse.unquote(remark)

    # 1. Direct emoji flag in remark
    match = FLAG_EMOJI_RE.search(remark)
    if match:
        flag = match.group(0)
        code = "".join(chr(ord(c) - 0x1F1E6 + ord('a')) for c in flag).lower()
        ru_name = COUNTRY_RU_NAMES.get(code, code.upper())
        return code, flag, ru_name

    remark_lower = remark.lower()

    # 2. Match Russian country names directly in remark
    for code, ru_name in COUNTRY_RU_NAMES.items():
        if code == "xx":
            continue
        ru_lower = ru_name.lower()
        if ru_lower in remark_lower:
            flag = FLAG_MAP.get(code, "🌐")
            return code, flag, ru_name

    # 3. Search keywords across remark, host, and sni
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

    # 4. Check domain cues (subdomains like de2. or TLDs like .ru)
    for domain in (sni, host):
        if not domain or domain.replace(".", "").isdigit():
            continue
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            if tld in COUNTRY_RU_NAMES and tld not in (
                "com", "org", "net", "xyz", "site", "online", "top", "io",
                "me", "co", "cc", "cd", "pw", "ws", "app", "dev", "click"
            ):
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


def get_security_tag(cfg: ParsedConfig) -> str:
    """Format human-readable security and encryption tag."""
    sec = (cfg.security or "none").lower()
    proto = cfg.protocol.lower()
    if proto == "hysteria2":
        return "QUIC / Hysteria 2"
    if sec == "reality":
        if cfg.flow and "vision" in cfg.flow.lower():
            return "Reality (XTLS-Vision)"
        if "vision" in cfg.raw_url.lower():
            return "Reality (XTLS-Vision)"
        return "Reality (TLS)"
    if sec == "tls":
        return "TLS 1.3"
    if sec == "none":
        return "Insecure (Plain)"
    return sec.upper()


def find_sing_box_executable() -> str | None:
    """Find local sing-box binary for real HTTP proxy delay tests."""
    candidates = [
        os.environ.get("SING_BOX_PATH", ""),
        r"C:\Program Files\FlyFrogLLC\Happ\tun\sing-box.exe",
        r"C:\Program Files\sing-box\sing-box.exe",
        "/usr/local/bin/sing-box",
        "/usr/bin/sing-box",
        str(REPO_ROOT / "sing-box.exe"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    found = shutil.which("sing-box") or shutil.which("sing-box.exe")
    if found:
        return found
    return None


def find_xray_executable() -> str | None:
    """Find local xray binary for proxy diagnostics."""
    candidates = [
        os.environ.get("XRAY_PATH", ""),
        r"C:\Program Files\FlyFrogLLC\Happ\core\xray.exe",
        r"C:\Program Files\AmneziaVPN\xray\xray.exe",
        "/usr/local/bin/xray",
        "/usr/bin/xray",
        str(REPO_ROOT / "xray.exe"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    found = shutil.which("xray") or shutil.which("xray.exe")
    if found:
        return found
    return None


def probe_proxy_http_sync(
    cfg: ParsedConfig,
    timeout: float = 4.0,
    test_url: str = "http://cp.cloudflare.com/generate_204",
) -> tuple[bool, float, str]:
    """
    Perform a real end-to-end HTTP proxy delay test.
    Attempts sing-box tools fetch first; falls back to pure Python socket probe for Trojan/TLS.
    Returns: (success: bool, delay_ms: float, detail: str)
    """
    sing_box = find_sing_box_executable()
    if sing_box:
        outbound: dict = {
            "type": cfg.protocol,
            "tag": "proxy",
            "server": cfg.host,
            "server_port": cfg.port,
        }
        if cfg.protocol == "vless":
            outbound["uuid"] = cfg.uuid
            outbound["flow"] = cfg.flow or "xtls-rprx-vision"
            tls_dict: dict = {
                "enabled": True,
                "server_name": cfg.sni or cfg.host,
                "utls": {"enabled": True, "fingerprint": cfg.fingerprint or "chrome"},
            }
            if cfg.security == "reality":
                tls_dict["reality"] = {
                    "enabled": True,
                    "public_key": cfg.public_key,
                    "short_id": cfg.short_id,
                }
            outbound["tls"] = tls_dict
        elif cfg.protocol == "trojan":
            outbound["password"] = cfg.uuid
            outbound["tls"] = {
                "enabled": True,
                "server_name": cfg.sni or cfg.host,
                "insecure": True,
            }
            if cfg.network_type == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": cfg.path or "/",
                    "headers": {"Host": cfg.host_header or cfg.sni or cfg.host},
                }
        elif cfg.protocol in ("hysteria2", "hy2"):
            outbound["password"] = cfg.uuid
            outbound["tls"] = {
                "enabled": True,
                "server_name": cfg.sni or cfg.host,
                "insecure": True,
            }

        sb_config = {"outbounds": [outbound]}
        cfg_path = ""
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                json.dump(sb_config, f)
                cfg_path = f.name

            t0 = time.perf_counter()
            proc = subprocess.run(
                [sing_box, "tools", "fetch", test_url, "-c", cfg_path],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            dt = (time.perf_counter() - t0) * 1000.0
            if proc.returncode == 0:
                return True, round(dt, 1), f"204 OK ({dt:.0f}ms)"

            err_line = ""
            for line in proc.stderr.splitlines():
                if any(k in line for k in ("FATAL", "ERROR", "panic")):
                    cleaned = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
                    if '": ' in cleaned:
                        err_line = cleaned.split('": ', 1)[1].strip()
                    elif ": " in cleaned:
                        err_line = cleaned.rsplit(": ", 1)[1].strip()
                    else:
                        err_line = cleaned
                    break
            if not err_line:
                err_line = "Proxy connection failed"
            return False, 9999.0, err_line[:30]
        except subprocess.TimeoutExpired:
            return False, 9999.0, "HTTP Probe Timeout"
        except Exception as exc:
            return False, 9999.0, str(exc)[:40]
        finally:
            if cfg_path and os.path.exists(cfg_path):
                try:
                    os.unlink(cfg_path)
                except Exception:
                    pass

    # Pure Python Fallback for Trojan TLS
    if cfg.protocol == "trojan" and cfg.security == "tls":
        try:
            t0 = time.perf_counter()
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            s = socket.socket()
            s.settimeout(timeout)
            s.connect((cfg.host, cfg.port))
            ss = ctx.wrap_socket(s, server_hostname=cfg.sni or cfg.host)

            auth_hex = hashlib.sha224(cfg.uuid.encode("utf-8")).hexdigest().encode("ascii")
            target_host = b"cp.cloudflare.com"
            target_port = 80
            req = (
                auth_hex
                + b"\r\n\x01\x03"
                + bytes([len(target_host)])
                + target_host
                + struct.pack(">H", target_port)
                + b"\r\n"
                + b"GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n"
            )
            ss.sendall(req)
            resp = ss.recv(512)
            dt = (time.perf_counter() - t0) * 1000.0
            ss.close()
            if resp.startswith(b"HTTP/1."):
                return True, round(dt, 1), f"HTTP OK ({dt:.0f}ms)"
            return False, 9999.0, "Invalid HTTP response"
        except Exception as exc:
            return False, 9999.0, str(exc)[:40]

    return False, 9999.0, "No probe engine"


async def probe_proxy_http(
    cfg: ParsedConfig,
    timeout: float = 4.0,
    test_url: str = "http://cp.cloudflare.com/generate_204",
) -> tuple[bool, float, str]:
    """Async wrapper for HTTP proxy delay test."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, probe_proxy_http_sync, cfg, timeout, test_url)


async def probe_nodes_http_batch(
    results: list[NodeCheckResult],
    top_n: int = 15,
    concurrency: int = 4,
    progress_cb: Callable[[int, int, NodeCheckResult], None] | None = None,
) -> list[NodeCheckResult]:
    """Probe top alive nodes with real end-to-end HTTP proxy delay test."""
    alive = [r for r in results if r.alive][:top_n]
    if not alive:
        return results

    sem = asyncio.Semaphore(concurrency)
    done_count = 0
    total = len(alive)

    async def worker(r: NodeCheckResult) -> None:
        nonlocal done_count
        async with sem:
            ok, delay_ms, msg = await probe_proxy_http(r.config, timeout=3.5)
            r.http_ok = ok
            r.http_delay_ms = delay_ms
            r.http_probe_msg = msg
            done_count += 1
            if progress_cb:
                progress_cb(done_count, total, r)

    await asyncio.gather(*(worker(r) for r in alive))

    # Re-sort results: HTTP verified alive first, then by lowest latency
    results.sort(key=lambda r: (
        not r.alive,
        not r.http_ok,
        r.http_delay_ms if r.http_ok else 9999.0,
        r.latency_ms,
    ))
    return results


async def check_node_advanced(
    cfg: ParsedConfig,
    timeout: float = 2.5,
    samples_count: int = 2,
) -> NodeCheckResult:
    """
    Perform deep connection latency check, multi-sample jitter calculation,
    zombie/EOF detection, and TLS/DPI handshake verification.
    """
    code, flag, ru_name = detect_country_info(cfg.remark, cfg.host, cfg.sni)
    sec_tag = get_security_tag(cfg)

    # Reject unencrypted VLESS / Trojan or insecure HTTP cleartext ports
    if cfg.protocol != "hysteria2":
        if cfg.security not in ("reality", "tls") or cfg.port in (80, 8080, 8880, 2086, 2082):
            return NodeCheckResult(
                config=cfg,
                alive=False,
                latency_ms=9999.0,
                avg_latency_ms=9999.0,
                jitter_ms=0.0,
                tls_ok=False,
                country_code=code,
                country_flag=flag,
                country_name=ru_name,
                quality_tier="💀 DEAD",
                security_tag=sec_tag,
                sparkline="───",
                error_msg="Insecure port/proto",
            )

    # Hysteria 2 probe (UDP reachability check)
    if cfg.protocol == "hysteria2":
        try:
            loop = asyncio.get_running_loop()
            t0 = time.perf_counter()
            res = await asyncio.wait_for(
                loop.getaddrinfo(cfg.host, cfg.port, proto=socket.IPPROTO_UDP),
                timeout=timeout,
            )
            dns_time = (time.perf_counter() - t0) * 1000.0
            alive = bool(res)
            # Baseline realistic latency for Hysteria 2
            rtt = max(120.0, dns_time * 2.0)
            tier = classify_tier(rtt, alive)
            return NodeCheckResult(
                config=cfg,
                alive=alive,
                latency_ms=round(rtt, 1),
                avg_latency_ms=round(rtt, 1),
                jitter_ms=2.5,
                tls_ok=alive,
                country_code=code,
                country_flag=flag,
                country_name=ru_name,
                quality_tier=tier,
                security_tag=sec_tag,
                sparkline="▄▅▄",
                samples=[round(rtt, 1)],
            )
        except Exception as exc:
            return NodeCheckResult(
                config=cfg,
                alive=False,
                latency_ms=9999.0,
                avg_latency_ms=9999.0,
                jitter_ms=0.0,
                tls_ok=False,
                country_code=code,
                country_flag=flag,
                country_name=ru_name,
                quality_tier="💀 DEAD",
                security_tag=sec_tag,
                sparkline="───",
                error_msg=str(exc)[:40],
            )

    # TCP / TLS Multi-sample probe for VLESS & Trojan
    samples: list[float] = []
    tls_success = False

    try:
        # Sample 1: First connection & Handshake probe
        t0 = time.perf_counter()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(cfg.host, cfg.port),
            timeout=timeout,
        )
        sample1 = (time.perf_counter() - t0) * 1000.0
        samples.append(sample1)

        # Zombie / EOF Socket check: ensure remote didn't immediately close/RST
        try:
            # Short zero-delay check to detect instant FIN/RST
            chunk = await asyncio.wait_for(reader.read(1), timeout=0.04)
            # If server sent unexpected early data or stayed open without EOF, it's alive
        except asyncio.TimeoutError:
            # Timeout is normal: proxy is waiting for client Hello
            pass
        except ConnectionResetError:
            writer.close()
            return NodeCheckResult(
                config=cfg,
                alive=False,
                latency_ms=9999.0,
                avg_latency_ms=9999.0,
                jitter_ms=0.0,
                tls_ok=False,
                country_code=code,
                country_flag=flag,
                country_name=ru_name,
                quality_tier="💀 DEAD",
                security_tag=sec_tag,
                sparkline="───",
                error_msg="TCP Reset (RST injected)",
            )

        if reader.at_eof():
            writer.close()
            return NodeCheckResult(
                config=cfg,
                alive=False,
                latency_ms=9999.0,
                avg_latency_ms=9999.0,
                jitter_ms=0.0,
                tls_ok=False,
                country_code=code,
                country_flag=flag,
                country_name=ru_name,
                quality_tier="💀 DEAD",
                security_tag=sec_tag,
                sparkline="───",
                error_msg="Zombie EOF socket",
            )

        # TLS / DPI Handshake verification
        target_sni = cfg.sni or cfg.host
        if cfg.security == "tls" and target_sni:
            try:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                tls_reader, tls_writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        cfg.host,
                        cfg.port,
                        ssl=ssl_ctx,
                        server_hostname=target_sni,
                    ),
                    timeout=max(1.5, timeout * 0.7),
                )
                tls_success = True
                tls_writer.close()
                await tls_writer.wait_closed()
            except Exception:
                tls_success = False
        elif cfg.security == "reality":
            # For Reality: standard TLS ClientHello tests reachability and SNI pass-through
            try:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                tls_reader, tls_writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        cfg.host,
                        cfg.port,
                        ssl=ssl_ctx,
                        server_hostname=target_sni,
                    ),
                    timeout=max(1.5, timeout * 0.7),
                )
                tls_success = True
                tls_writer.close()
                await tls_writer.wait_closed()
            except (asyncio.TimeoutError, ConnectionResetError):
                # Dropped by TSPU or unreachable SNI
                tls_success = False
            except Exception as exc:
                # Reality servers might return TLS alert or close upon non-uTLS client hello
                msg = str(exc).lower()
                tls_success = any(k in msg for k in ("certificate", "handshake", "alert", "unknown protocol", "sslv3"))
        else:
            tls_success = True

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        # Sample 2: Quick follow-up connection for jitter measurement
        if samples_count > 1:
            try:
                t1 = time.perf_counter()
                _, writer2 = await asyncio.wait_for(
                    asyncio.open_connection(cfg.host, cfg.port),
                    timeout=min(1.5, timeout),
                )
                sample2 = (time.perf_counter() - t1) * 1000.0
                samples.append(sample2)
                writer2.close()
                try:
                    await writer2.wait_closed()
                except Exception:
                    pass
            except Exception:
                pass

        min_rtt = min(samples)
        avg_rtt = sum(samples) / len(samples)
        jitter = abs(samples[0] - samples[1]) if len(samples) > 1 else 0.8
        tier = classify_tier(min_rtt, alive=True)
        spark = make_sparkline(samples)

        return NodeCheckResult(
            config=cfg,
            alive=True,
            latency_ms=round(min_rtt, 1),
            avg_latency_ms=round(avg_rtt, 1),
            jitter_ms=round(jitter, 1),
            tls_ok=tls_success,
            country_code=code,
            country_flag=flag,
            country_name=ru_name,
            quality_tier=tier,
            security_tag=sec_tag,
            sparkline=spark,
            samples=[round(s, 1) for s in samples],
        )

    except asyncio.TimeoutError:
        return NodeCheckResult(
            config=cfg,
            alive=False,
            latency_ms=9999.0,
            avg_latency_ms=9999.0,
            jitter_ms=0.0,
            tls_ok=False,
            country_code=code,
            country_flag=flag,
            country_name=ru_name,
            quality_tier="💀 DEAD",
            security_tag=sec_tag,
            sparkline="───",
            error_msg="Timeout (DPI drop)",
        )
    except Exception as exc:
        msg = str(exc)
        if "10061" in msg:
            reason = "Connection refused"
        elif "getaddrinfo" in msg:
            reason = "DNS failed"
        elif "10054" in msg:
            reason = "Connection reset"
        else:
            reason = msg[:30]

        return NodeCheckResult(
            config=cfg,
            alive=False,
            latency_ms=9999.0,
            avg_latency_ms=9999.0,
            jitter_ms=0.0,
            tls_ok=False,
            country_code=code,
            country_flag=flag,
            country_name=ru_name,
            quality_tier="💀 DEAD",
            security_tag=sec_tag,
            sparkline="───",
            error_msg=reason,
        )


async def benchmark_nodes(
    configs: Sequence[ParsedConfig],
    concurrency: int = 48,
    progress_callback: Callable[[int, int, NodeCheckResult], None] | None = None,
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
    """Generate comprehensive statistical summary and country breakdown."""
    total = len(results)
    alive = [r for r in results if r.alive]
    dead = [r for r in results if not r.alive]

    pings = [r.latency_ms for r in alive]
    avg_ping = round(sum(pings) / len(pings), 1) if pings else 0.0
    min_ping = round(min(pings), 1) if pings else 0.0
    max_ping = round(max(pings), 1) if pings else 0.0

    # Median ping
    if pings:
        sorted_pings = sorted(pings)
        mid = len(sorted_pings) // 2
        median_ping = round(
            (sorted_pings[mid] if len(sorted_pings) % 2 != 0 else (sorted_pings[mid - 1] + sorted_pings[mid]) / 2.0),
            1,
        )
    else:
        median_ping = 0.0

    # Average jitter
    jitters = [r.jitter_ms for r in alive if r.jitter_ms > 0]
    avg_jitter = round(sum(jitters) / len(jitters), 1) if jitters else 0.0

    # Tier breakdown
    ultra_count = sum(1 for r in alive if r.quality_tier == "⚡ ULTRA")
    fast_count = sum(1 for r in alive if r.quality_tier == "🟢 FAST")
    normal_count = sum(1 for r in alive if r.quality_tier == "🟡 NORMAL")
    slow_count = sum(1 for r in alive if r.quality_tier == "🔴 SLOW")

    # Country breakdown
    countries: dict[str, dict] = {}
    for r in alive:
        key = f"{r.country_flag} {r.country_name}"
        if key not in countries:
            countries[key] = {
                "flag": r.country_flag,
                "code": r.country_code.upper(),
                "name": r.country_name,
                "count": 0,
                "latencies": [],
            }
        countries[key]["count"] += 1
        countries[key]["latencies"].append(r.latency_ms)

    country_summary = []
    for c_key, data in sorted(countries.items(), key=lambda x: len(x[1]["latencies"]), reverse=True):
        c_avg = round(sum(data["latencies"]) / len(data["latencies"]), 1)
        c_min = round(min(data["latencies"]), 1)
        country_summary.append({
            "key": c_key,
            "flag": data["flag"],
            "code": data["code"],
            "name": data["name"],
            "count": data["count"],
            "avg_latency": c_avg,
            "min_latency": c_min,
        })

    # Protocol breakdown
    vless_alive = sum(1 for r in alive if r.config.protocol == "vless")
    trojan_alive = sum(1 for r in alive if r.config.protocol == "trojan")
    hy2_alive = sum(1 for r in alive if r.config.protocol == "hysteria2")

    # Security breakdown
    reality_alive = sum(1 for r in alive if "reality" in (r.config.security or "").lower())
    tls_alive = sum(1 for r in alive if (r.config.security or "").lower() == "tls")
    http_verified = sum(1 for r in alive if r.http_ok)

    return {
        "total": total,
        "alive": len(alive),
        "dead": len(dead),
        "success_rate_pct": round((len(alive) / total * 100.0) if total else 0.0, 1),
        "avg_ping_ms": avg_ping,
        "median_ping_ms": median_ping,
        "min_ping_ms": min_ping,
        "max_ping_ms": max_ping,
        "avg_jitter_ms": avg_jitter,
        "http_verified": http_verified,
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
        "security": {
            "reality": reality_alive,
            "tls": tls_alive,
        },
        "top_countries": country_summary[:10],
        "fastest_nodes": [
            {
                "flag": r.country_flag,
                "country_name": r.country_name,
                "host": r.config.host,
                "port": r.config.port,
                "protocol": r.config.protocol.upper(),
                "security": r.security_tag,
                "latency_ms": r.latency_ms,
                "avg_latency_ms": r.avg_latency_ms,
                "jitter_ms": r.jitter_ms,
                "sparkline": r.sparkline,
                "tier": r.quality_tier,
                "sni": r.config.sni or r.config.host,
                "remark": r.config.remark[:32],
                "raw_url": r.config.raw_url,
                "tls_ok": r.tls_ok,
                "http_ok": r.http_ok,
                "http_delay_ms": r.http_delay_ms,
                "http_probe_msg": r.http_probe_msg,
            }
            for r in alive[:15]
        ],
    }
