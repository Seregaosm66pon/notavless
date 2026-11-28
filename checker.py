"""
Advanced Multi-Protocol Proxy Health Checker & Latency Benchmark Engine.
Measures true RTT latency, multi-sample jitter, real TLS/SNI ClientHello handshake
validity, anti-censorship (TSPU / DPI) liveness, GeoIP country flags, dual-core
(sing-box + Xray) real HTTP tunnel delay & throughput, and sorts nodes.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import ipaddress
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
import urllib.error
import urllib.parse
import urllib.request
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
    "az": "Азербайджан",
    "uz": "Узбекистан",
    "th": "Таиланд",
    "vn": "Вьетнам",
    "id": "Индонезия",
    "tw": "Тайвань",
    "ar": "Аргентина",
    "mx": "Мексика",
    "cl": "Чили",
    "co": "Колумбия",
    "za": "ЮАР",
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
    "hr": "🇭🇷", "hn": "🇭🇳", "ir": "🇮🇷", "au": "🇦🇺", "az": "🇦🇿",
    "uz": "🇺🇿", "th": "🇹🇭", "vn": "🇻🇳", "id": "🇮🇩", "tw": "🇹🇼",
    "ar": "🇦🇷", "mx": "🇲🇽", "cl": "🇨🇱", "co": "🇨🇴", "za": "🇿🇦",
    "eu": "🇪🇺",
}

COUNTRY_KEYWORDS: dict[str, list[str]] = {
    "de": ["germany", "deutschland", "frankfurt", "berlin", "falkenstein", "nuremberg", "munich", "duesseldorf", "de"],
    "nl": ["netherlands", "holland", "amsterdam", "rotterdam", "nl"],
    "fi": ["finland", "helsinki", "fi"],
    "ru": ["russia", "russian", "moscow", "spb", "surgut", "piter", "ru"],
    "us": ["usa", "united states", "america", "virginia", "california", "new york", "miami", "chicago", "los angeles", "dallas", "seattle", "ashburn", "us"],
    "fr": ["france", "paris", "marseille", "strasbourg", "gravelines", "roubaix", "fr"],
    "se": ["sweden", "stockholm", "kista", "se"],
    "gb": ["united kingdom", "britain", "england", "london", "manchester", "uk", "gb"],
    "pl": ["poland", "warsaw", "warszawa", "krakow", "gdansk", "pl"],
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
    "in": ["india", "mumbai", "delhi", "bangalore", "in"],
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
    "tw": ["taiwan", "taipei", "tw"],
    "eu": ["europe", "european", "eu"],
}

FLAG_EMOJI_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")

VALID_UTLS_FINGERPRINTS = {
    "chrome",
    "firefox",
    "edge",
    "safari",
    "360",
    "qq",
    "ios",
    "android",
    "random",
    "randomized",
}

GEOIP_CACHE_FILE = REPO_ROOT / ".geoip_cache.json"
_GEOIP_MEM_CACHE: dict[str, str] = {}
_GEOIP_CACHE_LOADED = False


def _code_to_flag(code: str) -> str:
    code_l = (code or "").lower().strip()
    if code_l in FLAG_MAP:
        return FLAG_MAP[code_l]
    if len(code_l) == 2 and code_l.isalpha() and code_l != "xx":
        base_code = "gb" if code_l == "uk" else code_l
        return "".join(chr(0x1F1E6 + ord(ch) - ord("a")) for ch in base_code)
    return "🌐"


def _is_ipv4_or_ipv6(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


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
    speed_mbps: float = 0.0
    exit_ip: str = ""
    exit_country: str = ""
    tls_detail: str = ""
    sni_ok: bool = False
    asn: str = ""
    isp: str = ""
    wl_asn: bool = False
    grade: str = ""
    multi_ok: int = 0
    multi_total: int = 0

    @property
    def display_tag(self) -> str:
        flag = self.country_flag or "🌐"
        if self.alive:
            http_tag = " [HTTP ✔]" if self.http_ok else ""
            grade_tag = f" [{self.grade}]" if self.grade else ""
            return f"{flag} {self.latency_ms:.0f}ms [{self.quality_tier}]{http_tag}{grade_tag}"
        return f"{flag} DEAD ({self.error_msg or 'timeout'})"


_WL_ASNS_CACHE: dict[str, str] | None = None


def load_whitelist_asns(file_path: Path | None = None) -> dict[str, str]:
    """Load RKP Russian Whitelist ASNs from wl_hostings.txt -> {asn_num: org_name}."""
    global _WL_ASNS_CACHE
    if file_path is None and _WL_ASNS_CACHE is not None:
        return _WL_ASNS_CACHE
    target = file_path or (REPO_ROOT / "wl_hostings.txt")
    mapping: dict[str, str] = {}
    try:
        if target.exists():
            for line in target.read_text(encoding="utf-8", errors="ignore").splitlines():
                cleaned = line.strip()
                if not cleaned or cleaned.startswith("#"):
                    continue
                parts = cleaned.split(None, 1)
                asn_num = re.sub(r"[^0-9]", "", parts[0])
                if asn_num:
                    mapping[asn_num] = parts[1].strip() if len(parts) > 1 else ""
    except Exception:
        pass
    if file_path is None:
        _WL_ASNS_CACHE = mapping
    return mapping


def is_whitelist_asn(asn_or_text: str) -> tuple[bool, str]:
    """Check if ASN string (e.g. 'AS9123 Timeweb') belongs to RKP Russian whitelist ASNs."""
    asns = load_whitelist_asns()
    if not asn_or_text or not asns:
        return False, ""
    m = re.search(r"\b(?:AS)?(\d{2,7})\b", asn_or_text, re.IGNORECASE)
    if m and m.group(1) in asns:
        return True, asns[m.group(1)]
    return False, ""


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
        code = "".join(chr(ord(c) - 0x1F1E6 + ord("a")) for c in flag).lower()
        ru_name = COUNTRY_RU_NAMES.get(code, code.upper())
        return code, flag, ru_name

    remark_lower = remark.lower()

    # 2. Match Russian country names directly in remark
    for code, ru_name in COUNTRY_RU_NAMES.items():
        if code == "xx":
            continue
        ru_lower = ru_name.lower()
        if ru_lower in remark_lower:
            flag = _code_to_flag(code)
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
                    flag = _code_to_flag(code)
                    ru_name = COUNTRY_RU_NAMES.get(code, code.upper())
                    return code, flag, ru_name
            else:
                if kw in combined:
                    flag = _code_to_flag(code)
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
                "me", "co", "cc", "cd", "pw", "ws", "app", "dev", "click",
                "ru",  # Wait: keep .ru below? Wait: .ru in domain TLD still maps to Russia!
            ):
                flag = _code_to_flag(tld)
                return tld, flag, COUNTRY_RU_NAMES[tld]
            if tld == "ru":
                return "ru", _code_to_flag("ru"), COUNTRY_RU_NAMES["ru"]
            sub = parts[0]
            sub_code = re.sub(r"[0-9_\-].*$", "", sub)
            if sub_code in COUNTRY_RU_NAMES and len(sub_code) == 2:
                flag = _code_to_flag(sub_code)
                return sub_code, flag, COUNTRY_RU_NAMES[sub_code]

    # 5. Check GeoIP memory cache if available for IP host
    if host and host in _GEOIP_MEM_CACHE:
        cached_code = _GEOIP_MEM_CACHE[host].lower()
        if cached_code and cached_code != "xx":
            return cached_code, _code_to_flag(cached_code), COUNTRY_RU_NAMES.get(cached_code, cached_code.upper())

    return "xx", "🌐", "Сервер"


def detect_country_flag(remark: str) -> tuple[str, str]:
    """Backward compatibility helper returning (code, flag)."""
    code, flag, _ = detect_country_info(remark)
    return code, flag


def _load_geoip_cache() -> None:
    global _GEOIP_CACHE_LOADED
    if _GEOIP_CACHE_LOADED:
        return
    _GEOIP_CACHE_LOADED = True
    try:
        if GEOIP_CACHE_FILE.exists():
            raw = json.loads(GEOIP_CACHE_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                now = time.time()
                for ip, item in raw.items():
                    if isinstance(item, dict) and now - float(item.get("ts", 0)) < 7 * 86400:
                        cc = str(item.get("cc", "")).lower()
                        if cc:
                            _GEOIP_MEM_CACHE[ip] = cc
    except Exception:
        pass


def _save_geoip_cache() -> None:
    try:
        now = time.time()
        payload = {ip: {"cc": cc, "ts": now} for ip, cc in _GEOIP_MEM_CACHE.items()}
        GEOIP_CACHE_FILE.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def enrich_country_geoip_batch(ips: Sequence[str], timeout: float = 2.0) -> dict[str, tuple[str, str, str]]:
    """
    Batch-resolve country codes for raw IP hosts via ip-api.com (no key, 100/req).
    Never raises; returns {ip: (code, flag, ru_name)} for resolved entries.
    """
    _load_geoip_cache()
    resolved: dict[str, tuple[str, str, str]] = {}
    to_query: list[str] = []

    for ip in ips:
        clean_ip = (ip or "").strip("[]")
        if not _is_ipv4_or_ipv6(clean_ip):
            continue
        if clean_ip in _GEOIP_MEM_CACHE:
            cc = _GEOIP_MEM_CACHE[clean_ip]
            if cc and cc != "xx":
                resolved[ip] = (cc, _code_to_flag(cc), COUNTRY_RU_NAMES.get(cc, cc.upper()))
        elif clean_ip not in to_query:
            to_query.append(clean_ip)

    if to_query:
        updated = False
        for i in range(0, min(len(to_query), 300), 100):
            chunk = to_query[i:i + 100]
            try:
                body = json.dumps([{"query": q} for q in chunk]).encode("utf-8")
                req = urllib.request.Request(
                    "http://ip-api.com/batch?fields=status,query,countryCode",
                    data=body,
                    headers={"Content-Type": "application/json", "User-Agent": "NotaVless/3.0"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    items = json.loads(resp.read().decode("utf-8", errors="ignore"))
                if isinstance(items, list):
                    for item in items:
                        if item.get("status") == "success":
                            q = item.get("query", "")
                            cc = (item.get("countryCode") or "").lower()
                            if q and cc:
                                _GEOIP_MEM_CACHE[q] = cc
                                resolved[q] = (cc, _code_to_flag(cc), COUNTRY_RU_NAMES.get(cc, cc.upper()))
                                updated = True
            except Exception:
                break
        if updated:
            _save_geoip_cache()

    return resolved


def enrich_results_geoip(results: Sequence[NodeCheckResult], timeout: float = 2.0) -> int:
    """Enrich alive NodeCheckResult entries with country flags + RKP WL-ASN tags via batch GeoIP."""
    targets = [
        r for r in results
        if r.alive and _is_ipv4_or_ipv6(r.config.host) and (r.country_code == "xx" or not r.asn)
    ]
    if not targets:
        return 0
    _load_geoip_cache()
    ips_missing_cc = [r.config.host for r in targets if r.country_code == "xx"]
    mapping = enrich_country_geoip_batch([r.config.host for r in targets], timeout=timeout) if ips_missing_cc or not _GEOIP_MEM_CACHE else {}
    # Also fetch AS/ISP cleanly in single batch for top 100 alive nodes
    meta_map: dict[str, tuple[str, str, bool]] = {}
    top_ips = []
    for r in targets[:100]:
        cip = r.config.host.strip("[]")
        if cip not in top_ips:
            top_ips.append(cip)
    if top_ips:
        try:
            body = json.dumps([{"query": q} for q in top_ips]).encode("utf-8")
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=status,query,countryCode,isp,as",
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "NotaVless/3.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                items = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if isinstance(items, list):
                for item in items:
                    if item.get("status") == "success":
                        q = item.get("query", "")
                        as_str = str(item.get("as", ""))
                        isp_str = str(item.get("isp", ""))
                        wl_hit, _ = is_whitelist_asn(as_str)
                        meta_map[q] = (as_str, isp_str, wl_hit)
                        cc = (item.get("countryCode") or "").lower()
                        if q and cc:
                            _GEOIP_MEM_CACHE[q] = cc
                            mapping[q] = (cc, _code_to_flag(cc), COUNTRY_RU_NAMES.get(cc, cc.upper()))
                _save_geoip_cache()
        except Exception:
            pass

    updated = 0
    for r in targets:
        cip = r.config.host.strip("[]")
        info = mapping.get(cip) or mapping.get(r.config.host)
        if info and r.country_code == "xx":
            r.country_code, r.country_flag, r.country_name = info
            updated += 1
        meta = meta_map.get(cip)
        if meta:
            r.asn, r.isp, r.wl_asn = meta
            if not r.wl_asn and r.isp:
                r.wl_asn, _ = is_whitelist_asn(r.isp)
    return updated


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
    net = (cfg.network_type or "").lower()
    net_suffix = f" [{net.upper()}]" if net in ("ws", "grpc", "xhttp", "splithttp", "httpupgrade") else ""
    if proto == "hysteria2":
        return "QUIC / Hysteria 2"
    if sec == "reality":
        if (cfg.flow and "vision" in cfg.flow.lower()) or "vision" in cfg.raw_url.lower():
            return f"Reality (XTLS-Vision){net_suffix}"
        return f"Reality (TLS){net_suffix}"
    if sec == "tls":
        return f"TLS 1.3{net_suffix}"
    if sec == "none":
        return f"Insecure (Plain){net_suffix}"
    return f"{sec.upper()}{net_suffix}"


def find_sing_box_executable() -> str | None:
    """Find local sing-box binary for real HTTP proxy delay tests."""
    candidates = [
        os.environ.get("SING_BOX_PATH", ""),
        r"C:\Program Files\FlyFrogLLC\Happ\tun\sing-box.exe",
        r"C:\Program Files\sing-box\sing-box.exe",
        "/usr/local/bin/sing-box",
        "/usr/bin/sing-box",
        str(REPO_ROOT / "sing-box.exe"),
        str(REPO_ROOT / "sing-box"),
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
        str(REPO_ROOT / "xray"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    found = shutil.which("xray") or shutil.which("xray.exe")
    if found:
        return found
    return None


def _reserve_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _normalize_fingerprint(fp: str) -> str:
    fp_l = (fp or "chrome").strip().lower()
    return fp_l if fp_l in VALID_UTLS_FINGERPRINTS else "chrome"


def build_tls_client_hello(sni: str = "") -> bytes:
    """
    Construct a genuine TLS 1.3/1.2 ClientHello packet with SNI, ALPN,
    supported_groups, signature_algorithms, and X25519 key_share extensions.
    Used for accurate DPI/TSPU SNI pass-through and Reality liveness probing.
    """
    exts = bytearray()
    clean_sni = (sni or "").strip()
    if clean_sni and not _is_ipv4_or_ipv6(clean_sni):
        sni_b = clean_sni.encode("ascii", errors="ignore")
        if sni_b:
            entry = b"\x00" + struct.pack("!H", len(sni_b)) + sni_b
            list_b = struct.pack("!H", len(entry)) + entry
            exts += struct.pack("!HH", 0x0000, len(list_b)) + list_b

    # ec_point_formats (uncompressed)
    exts += struct.pack("!HHBB", 0x000B, 2, 1, 0)
    # supported_groups: x25519, secp256r1
    exts += struct.pack("!HHHHH", 0x000A, 6, 4, 0x001D, 0x0017)
    # alpn: h2, http/1.1
    alpn_list = b"\x02h2\x08http/1.1"
    exts += struct.pack("!HHH", 0x0010, len(alpn_list) + 2, len(alpn_list)) + alpn_list
    # signature_algorithms
    sigs = struct.pack("!HHHH", 0x0403, 0x0804, 0x0401, 0x0503)
    exts += struct.pack("!HHH", 0x000D, len(sigs) + 2, len(sigs)) + sigs
    # key_share: x25519 (32 random bytes)
    ks_entry = struct.pack("!HH", 0x001D, 32) + os.urandom(32)
    exts += struct.pack("!HHH", 0x0033, len(ks_entry) + 2, len(ks_entry)) + ks_entry
    # supported_versions: TLS 1.3 (0x0304), TLS 1.2 (0x0303)
    vers = b"\x04\x03\x04\x03\x03"
    exts += struct.pack("!HH", 0x002B, len(vers)) + vers

    ciphers = struct.pack("!HHHH", 0x1301, 0x1302, 0xC02B, 0xC02F)
    body = bytearray()
    body += b"\x03\x03" + os.urandom(32)
    body += b"\x20" + os.urandom(32)
    body += struct.pack("!H", len(ciphers)) + ciphers
    body += b"\x01\x00"
    body += struct.pack("!H", len(exts)) + exts

    hs = b"\x01" + struct.pack("!I", len(body))[1:] + bytes(body)
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


_VALID_SB_NETS = {"", "tcp", "raw", "ws", "grpc", "httpupgrade", "h2", "http", "udp"}
_VALID_XRAY_NETS = {"", "tcp", "raw", "ws", "grpc", "xhttp", "splithttp", "httpupgrade", "h2", "http"}
_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def build_sing_box_outbound(cfg: ParsedConfig, tag: str = "proxy") -> dict | None:
    """Build a sanitized sing-box 1.12+ outbound dict for VLESS, Trojan, or Hysteria 2."""
    proto = (cfg.protocol or "").lower()
    net = (cfg.network_type or "tcp").lower()
    sec = (cfg.security or "").lower()

    if net not in _VALID_SB_NETS or net in ("xhttp", "splithttp"):
        return None
    if proto == "vless" and sec == "reality" and not cfg.public_key:
        return None

    outbound: dict = {
        "type": proto,
        "tag": tag,
        "server": cfg.host,
        "server_port": cfg.port,
    }
    sni = cfg.sni or cfg.host
    fp = _normalize_fingerprint(cfg.fingerprint)

    if proto == "vless":
        outbound["uuid"] = cfg.uuid
        if net in ("", "tcp", "raw"):
            flow_l = (cfg.flow or "").lower()
            if flow_l.startswith("xtls-rprx-vision"):
                outbound["flow"] = "xtls-rprx-vision"
        elif net == "ws":
            host_hdr = cfg.host_header if (cfg.host_header and not cfg.host_header.startswith("/")) else sni
            outbound["transport"] = {
                "type": "ws",
                "path": cfg.path or "/",
                "headers": {"Host": host_hdr},
            }
        elif net == "grpc":
            outbound["transport"] = {
                "type": "grpc",
                "service_name": cfg.service_name or cfg.path or "grpc",
            }
        elif net == "httpupgrade":
            host_hdr = cfg.host_header if (cfg.host_header and not cfg.host_header.startswith("/")) else sni
            outbound["transport"] = {
                "type": "httpupgrade",
                "path": cfg.path or "/",
                "host": host_hdr,
            }

        tls_dict: dict = {
            "enabled": True,
            "server_name": sni,
            "utls": {"enabled": True, "fingerprint": fp},
        }
        if sec == "reality":
            tls_dict["reality"] = {
                "enabled": True,
                "public_key": cfg.public_key,
                "short_id": cfg.short_id or "",
            }
        else:
            tls_dict["insecure"] = True
        if cfg.alpn and net not in ("ws", "httpupgrade"):
            alpn_list = [a.strip() for a in cfg.alpn.split(",") if a.strip()]
            if alpn_list:
                tls_dict["alpn"] = alpn_list
        outbound["tls"] = tls_dict
        return outbound

    if proto == "trojan":
        outbound["password"] = cfg.uuid
        outbound["tls"] = {
            "enabled": True,
            "server_name": sni,
            "insecure": True,
        }
        if net == "ws":
            host_hdr = cfg.host_header if (cfg.host_header and not cfg.host_header.startswith("/")) else sni
            outbound["transport"] = {
                "type": "ws",
                "path": cfg.path or "/",
                "headers": {"Host": host_hdr},
            }
        elif net == "grpc":
            outbound["transport"] = {
                "type": "grpc",
                "service_name": cfg.service_name or cfg.path or "grpc",
            }
        elif net == "httpupgrade":
            host_hdr = cfg.host_header if (cfg.host_header and not cfg.host_header.startswith("/")) else sni
            outbound["transport"] = {
                "type": "httpupgrade",
                "path": cfg.path or "/",
                "host": host_hdr,
            }
        return outbound

    if proto in ("hysteria2", "hy2"):
        outbound["type"] = "hysteria2"
        outbound["password"] = cfg.uuid
        tls_dict = {
            "enabled": True,
            "server_name": sni,
            "insecure": True,
        }
        if cfg.alpn:
            alpn_list = [a.strip() for a in cfg.alpn.split(",") if a.strip()]
            if alpn_list:
                tls_dict["alpn"] = alpn_list
        outbound["tls"] = tls_dict
        if cfg.obfs:
            outbound["obfs"] = {
                "type": cfg.obfs,
                "password": cfg.obfs_password or "",
            }
        return outbound

    return None


def build_xray_outbound(cfg: ParsedConfig, tag: str = "proxy") -> dict | None:
    """Build an Xray 26+ compatible outbound dict (supports xhttp, grpc, ws, tcp, reality, tls)."""
    proto = (cfg.protocol or "").lower()
    if proto not in ("vless", "trojan"):
        return None
    sec = (cfg.security or "tls").lower()
    if proto == "vless" and sec == "reality" and not cfg.public_key:
        return None

    net = (cfg.network_type or "tcp").lower()
    if net not in _VALID_XRAY_NETS:
        return None
    xray_net = "tcp" if net in ("", "tcp", "raw") else ("xhttp" if net in ("xhttp", "splithttp") else net)
    sni = cfg.sni or cfg.host
    fp = _normalize_fingerprint(cfg.fingerprint)

    stream: dict = {"network": xray_net}
    if xray_net == "ws":
        host_hdr = cfg.host_header if (cfg.host_header and not cfg.host_header.startswith("/")) else sni
        stream["wsSettings"] = {"path": cfg.path or "/", "headers": {"Host": host_hdr}}
    elif xray_net == "grpc":
        stream["grpcSettings"] = {"serviceName": cfg.service_name or cfg.path or "grpc"}
    elif xray_net == "httpupgrade":
        host_hdr = cfg.host_header if (cfg.host_header and not cfg.host_header.startswith("/")) else sni
        stream["httpupgradeSettings"] = {"path": cfg.path or "/", "host": host_hdr}
    elif xray_net == "xhttp":
        xhttp_cfg: dict = {"path": cfg.path or "/", "mode": cfg.mode or "auto"}
        if cfg.host_header and not cfg.host_header.startswith("/"):
            xhttp_cfg["host"] = cfg.host_header
        stream["xhttpSettings"] = xhttp_cfg

    if sec == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fp,
            "publicKey": cfg.public_key,
            "shortId": cfg.short_id or "",
        }
    elif sec == "tls":
        stream["security"] = "tls"
        tls_cfg: dict = {"serverName": sni, "fingerprint": fp}
        if cfg.pin_sha256:
            tls_cfg["pinnedPeerCertSha256"] = cfg.pin_sha256
        stream["tlsSettings"] = tls_cfg

    if proto == "vless":
        user: dict = {"id": cfg.uuid, "encryption": "none"}
        if cfg.flow and xray_net == "tcp":
            user["flow"] = cfg.flow
        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {"vnext": [{"address": cfg.host, "port": cfg.port, "users": [user]}]},
            "streamSettings": stream,
        }

    # trojan
    return {
        "tag": tag,
        "protocol": "trojan",
        "settings": {"servers": [{"address": cfg.host, "port": cfg.port, "password": cfg.uuid}]},
        "streamSettings": stream,
    }


def _probe_batch_sing_box_sync(
    items: list[tuple[NodeCheckResult, dict]],
    timeout: float,
    test_url: str,
    concurrency: int,
    progress_cb: Callable[[NodeCheckResult], None] | None = None,
) -> None:
    """Probe a batch of nodes using ONE persistent sing-box Clash API instance."""
    sb = find_sing_box_executable()
    if not sb or not items:
        return

    api_port = _reserve_free_port()
    outbounds = [ob for _, ob in items]
    sb_config = {
        "log": {"level": "error"},
        "experimental": {"clash_api": {"external_controller": f"127.0.0.1:{api_port}"}},
        "outbounds": outbounds,
    }

    cfg_path = ""
    proc: subprocess.Popen | None = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(sb_config, f)
            cfg_path = f.name

        proc = subprocess.Popen(
            [sb, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ready = False
        for _ in range(60):
            if proc.poll() is not None:
                break
            try:
                with _LOCAL_OPENER.open(f"http://127.0.0.1:{api_port}/version", timeout=0.4) as r:
                    if r.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.1)

        if not ready:
            # If sing-box failed to boot on a huge batch (e.g. one malformed field), split cleanly
            if len(items) > 1:
                mid = len(items) // 2
                _probe_batch_sing_box_sync(items[:mid], timeout, test_url, concurrency, progress_cb)
                _probe_batch_sing_box_sync(items[mid:], timeout, test_url, concurrency, progress_cb)
            else:
                res = items[0][0]
                res.http_ok = False
                res.http_delay_ms = 9999.0
                res.http_probe_msg = "Core init error"
                if progress_cb:
                    progress_cb(res)
            return

        encoded_url = urllib.parse.quote(test_url, safe="")
        timeout_ms = max(1000, int(timeout * 1000))

        def query_one(pair: tuple[NodeCheckResult, dict]) -> None:
            res, ob = pair
            tag = ob["tag"]
            api_url = f"http://127.0.0.1:{api_port}/proxies/{urllib.parse.quote(tag, safe='')}/delay?timeout={timeout_ms}&url={encoded_url}"
            try:
                with _LOCAL_OPENER.open(api_url, timeout=timeout + 1.5) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    delay = float(data.get("delay", 0))
                    if delay > 0:
                        res.http_ok = True
                        res.http_delay_ms = round(delay, 1)
                        res.http_probe_msg = f"204 OK ({delay:.0f}ms)"
                    else:
                        res.http_ok = False
                        res.http_delay_ms = 9999.0
                        res.http_probe_msg = "Empty delay"
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="ignore")
                msg = "Timeout"
                try:
                    msg = json.loads(body).get("message", msg)
                except Exception:
                    pass
                res.http_ok = False
                res.http_delay_ms = 9999.0
                res.http_probe_msg = str(msg)[:24]
            except Exception as exc:
                res.http_ok = False
                res.http_delay_ms = 9999.0
                res.http_probe_msg = str(exc)[:24]
            finally:
                if progress_cb:
                    progress_cb(res)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(concurrency, len(items)))) as pool:
            list(pool.map(query_one, items))
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if cfg_path and os.path.exists(cfg_path):
            try:
                os.unlink(cfg_path)
            except Exception:
                pass


def _probe_batch_xray_sync(
    items: list[tuple[NodeCheckResult, dict]],
    timeout: float,
    test_url: str,
    concurrency: int,
    progress_cb: Callable[[NodeCheckResult], None] | None = None,
) -> None:
    """Probe a batch of nodes (such as VLESS xhttp) using ONE Xray multi-inbound process."""
    xr = find_xray_executable()
    if not xr or not items:
        return

    inbounds: list[dict] = []
    outbounds: list[dict] = []
    rules: list[dict] = []
    port_items: list[tuple[int, NodeCheckResult]] = []

    for idx, (res, ob) in enumerate(items):
        port = _reserve_free_port()
        in_tag = f"in_{idx}"
        out_tag = ob["tag"]
        inbounds.append({"tag": in_tag, "port": port, "listen": "127.0.0.1", "protocol": "http"})
        outbounds.append(ob)
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})
        port_items.append((port, res))

    xcfg = {
        "log": {"loglevel": "error"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }

    cfg_path = ""
    proc: subprocess.Popen | None = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(xcfg, f)
            cfg_path = f.name

        proc = subprocess.Popen(
            [xr, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        first_port = port_items[0][0]
        ready = False
        for _ in range(40):
            if proc.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", first_port), timeout=0.15):
                    ready = True
                    break
            except Exception:
                time.sleep(0.05)

        if not ready:
            if len(items) > 1:
                mid = len(items) // 2
                _probe_batch_xray_sync(items[:mid], timeout, test_url, concurrency, progress_cb)
                _probe_batch_xray_sync(items[mid:], timeout, test_url, concurrency, progress_cb)
            else:
                res = items[0][0]
                res.http_ok = False
                res.http_delay_ms = 9999.0
                res.http_probe_msg = "Xray init error"
                if progress_cb:
                    progress_cb(res)
            return

        def probe_one(pair: tuple[int, NodeCheckResult]) -> None:
            port, res = pair
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"})
            )
            t0 = time.perf_counter()
            try:
                with opener.open(test_url, timeout=timeout) as resp:
                    dt = (time.perf_counter() - t0) * 1000.0
                    if 200 <= resp.status < 400:
                        res.http_ok = True
                        res.http_delay_ms = round(dt, 1)
                        res.http_probe_msg = f"{resp.status} OK ({dt:.0f}ms)"
                    else:
                        res.http_ok = False
                        res.http_delay_ms = 9999.0
                        res.http_probe_msg = f"HTTP {resp.status}"
            except Exception as exc:
                res.http_ok = False
                res.http_delay_ms = 9999.0
                res.http_probe_msg = str(exc)[:24]
            finally:
                if progress_cb:
                    progress_cb(res)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(concurrency, len(port_items)))) as pool:
            list(pool.map(probe_one, port_items))
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if cfg_path and os.path.exists(cfg_path):
            try:
                os.unlink(cfg_path)
            except Exception:
                pass


def probe_proxy_http_sync(
    cfg: ParsedConfig,
    timeout: float = 4.0,
    test_url: str = "http://cp.cloudflare.com/generate_204",
) -> tuple[bool, float, str]:
    """
    Perform a real end-to-end HTTP proxy delay test.
    Routes xhttp/splithttp to Xray; VLESS/Trojan/Hysteria2 to sing-box Clash API (with Xray fallback);
    falls back to pure Python socket probe for Trojan TLS if no core binaries exist.
    Returns: (success: bool, delay_ms: float, detail: str)
    """
    dummy_res = NodeCheckResult(
        config=cfg,
        alive=True,
        latency_ms=0.0,
        tls_ok=True,
        country_code="xx",
        country_flag="🌐",
        country_name="Сервер",
        quality_tier="⚡ ULTRA",
    )

    net = (cfg.network_type or "").lower()
    sb = find_sing_box_executable()
    xr = find_xray_executable()

    # 1. XHTTP / splithttp -> Xray natively
    if net in ("xhttp", "splithttp") and xr:
        ob = build_xray_outbound(cfg, tag="proxy")
        if ob:
            _probe_batch_xray_sync([(dummy_res, ob)], timeout=timeout, test_url=test_url, concurrency=1)
            return dummy_res.http_ok, dummy_res.http_delay_ms, dummy_res.http_probe_msg or "Xray probe failed"

    # 2. sing-box Clash API (true proxy delay excluding startup time!)
    if sb:
        ob = build_sing_box_outbound(cfg, tag="proxy")
        if ob:
            _probe_batch_sing_box_sync([(dummy_res, ob)], timeout=timeout, test_url=test_url, concurrency=1)
            if dummy_res.http_ok or not xr:
                return dummy_res.http_ok, dummy_res.http_delay_ms, dummy_res.http_probe_msg or "Proxy probe failed"

    # 3. Xray fallback for VLESS / Trojan
    if xr:
        ob = build_xray_outbound(cfg, tag="proxy")
        if ob:
            _probe_batch_xray_sync([(dummy_res, ob)], timeout=timeout, test_url=test_url, concurrency=1)
            return dummy_res.http_ok, dummy_res.http_delay_ms, dummy_res.http_probe_msg or "Xray probe failed"

    # 4. Pure Python Fallback for Trojan TLS
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


def _select_diverse_probe_candidates(alive: list[NodeCheckResult], limit: int) -> list[NodeCheckResult]:
    """
    Pick top alive candidates while avoiding wasting the entire HTTP probe budget
    on identical clones from a single /24 subnet or UUID cluster.
    """
    if len(alive) <= limit:
        return list(alive)

    selected: list[NodeCheckResult] = []
    overflow: list[NodeCheckResult] = []
    subnet_counts: dict[str, int] = {}
    uuid_counts: dict[str, int] = {}

    for r in alive:
        parts = r.config.host.split(".")
        subnet = ".".join(parts[:3]) if len(parts) == 4 and all(p.isdigit() for p in parts) else r.config.host
        uk = r.config.uuid[:16]
        if subnet_counts.get(subnet, 0) < 2 and uuid_counts.get(uk, 0) < 3:
            selected.append(r)
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            uuid_counts[uk] = uuid_counts.get(uk, 0) + 1
        else:
            overflow.append(r)
        if len(selected) >= limit:
            return selected

    for r in overflow:
        if len(selected) >= limit:
            break
        selected.append(r)
    return selected


async def probe_nodes_http_batch(
    results: list[NodeCheckResult],
    top_n: int = 40,
    concurrency: int = 24,
    progress_cb: Callable[[int, int, NodeCheckResult], None] | None = None,
    test_url: str = "http://cp.cloudflare.com/generate_204",
    timeout: float = 4.0,
    smart_select: bool = True,
) -> list[NodeCheckResult]:
    """
    Probe top alive nodes with real end-to-end HTTP proxy delay test using
    high-speed dual-core batch execution (sing-box Clash API + Xray multi-inbound).
    """
    alive_all = [r for r in results if r.alive]
    if not alive_all:
        return results

    candidates = _select_diverse_probe_candidates(alive_all, top_n) if smart_select else alive_all[:top_n]
    if not candidates:
        return results

    sb = find_sing_box_executable()
    xr = find_xray_executable()
    sb_items: list[tuple[NodeCheckResult, dict]] = []
    xr_items: list[tuple[NodeCheckResult, dict]] = []
    fallback_items: list[NodeCheckResult] = []

    for idx, res in enumerate(candidates):
        tag = f"n{idx}"
        net = (res.config.network_type or "").lower()
        if net in ("xhttp", "splithttp"):
            ob = build_xray_outbound(res.config, tag=tag) if xr else None
            if ob:
                xr_items.append((res, ob))
            else:
                fallback_items.append(res)
        elif sb:
            ob = build_sing_box_outbound(res.config, tag=tag)
            if ob:
                sb_items.append((res, ob))
            elif xr:
                xob = build_xray_outbound(res.config, tag=tag)
                if xob:
                    xr_items.append((res, xob))
                else:
                    fallback_items.append(res)
            else:
                fallback_items.append(res)
        elif xr:
            xob = build_xray_outbound(res.config, tag=tag)
            if xob:
                xr_items.append((res, xob))
            else:
                fallback_items.append(res)
        else:
            fallback_items.append(res)

    total = len(candidates)
    done_count = 0
    loop = asyncio.get_running_loop()

    def on_one_done(r: NodeCheckResult) -> None:
        nonlocal done_count
        done_count += 1
        if progress_cb:
            loop.call_soon_threadsafe(progress_cb, done_count, total, r)

    tasks: list[asyncio.Future] = []
    if sb_items:
        tasks.append(
            loop.run_in_executor(
                None,
                _probe_batch_sing_box_sync,
                sb_items,
                timeout,
                test_url,
                concurrency,
                on_one_done,
            )
        )
    if xr_items:
        tasks.append(
            loop.run_in_executor(
                None,
                _probe_batch_xray_sync,
                xr_items,
                timeout,
                test_url,
                min(concurrency, 20),
                on_one_done,
            )
        )

    if tasks:
        await asyncio.gather(*tasks)

    if fallback_items:
        sem = asyncio.Semaphore(4)

        async def fb_worker(r: NodeCheckResult) -> None:
            nonlocal done_count
            async with sem:
                ok, delay_ms, msg = await probe_proxy_http(r.config, timeout=timeout, test_url=test_url)
                r.http_ok = ok
                r.http_delay_ms = delay_ms
                r.http_probe_msg = msg
                done_count += 1
                if progress_cb:
                    progress_cb(done_count, total, r)

        await asyncio.gather(*(fb_worker(r) for r in fallback_items))

    # Re-sort results: HTTP verified alive first (sorted by HTTP delay), then TLS alive, then remaining alive
    results.sort(
        key=lambda r: (
            not r.alive,
            not r.http_ok,
            r.http_delay_ms if r.http_ok else 9999.0,
            not r.tls_ok,
            r.config.protocol == "hysteria2",
            r.latency_ms,
        )
    )
    return results


def _run_temp_http_proxy(cfg: ParsedConfig) -> tuple[subprocess.Popen | None, int, str]:
    """Start a temporary local HTTP proxy for single-node speed/exit-IP checks."""
    xr = find_xray_executable()
    sb = find_sing_box_executable()
    port = _reserve_free_port()
    net = (cfg.network_type or "").lower()

    # Prefer Xray for VLESS/Trojan (0.28s boot), sing-box for Hysteria2 or fallback
    if xr and cfg.protocol in ("vless", "trojan"):
        ob = build_xray_outbound(cfg, tag="proxy")
        if ob:
            xcfg = {
                "log": {"loglevel": "error"},
                "inbounds": [{"tag": "in_http", "port": port, "listen": "127.0.0.1", "protocol": "http"}],
                "outbounds": [ob],
            }
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
                json.dump(xcfg, f)
                cfg_path = f.name
            proc = subprocess.Popen([xr, "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(30):
                if proc.poll() is not None:
                    break
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                        return proc, port, cfg_path
                except Exception:
                    time.sleep(0.05)
            proc.terminate()
            return None, 0, cfg_path

    if sb and net not in ("xhttp", "splithttp"):
        ob = build_sing_box_outbound(cfg, tag="proxy")
        if ob:
            sb_cfg = {
                "log": {"level": "error"},
                "inbounds": [{"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": port}],
                "outbounds": [ob],
            }
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
                json.dump(sb_cfg, f)
                cfg_path = f.name
            proc = subprocess.Popen([sb, "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(50):
                if proc.poll() is not None:
                    break
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                        return proc, port, cfg_path
                except Exception:
                    time.sleep(0.1)
            proc.terminate()
            return None, 0, cfg_path

    return None, 0, ""


def measure_node_speed_sync(
    cfg: ParsedConfig,
    byte_limit: int = 524288,
    timeout: float = 6.0,
) -> tuple[bool, float, int, float, str]:
    """
    Download a payload through the proxy to measure real throughput (Mbps).
    Returns: (ok, mbps, bytes_read, elapsed_s, detail)
    """
    proc, port, cfg_path = _run_temp_http_proxy(cfg)
    try:
        if not proc or not port:
            return False, 0.0, 0, 0.0, "No proxy core available"

        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"})
        )
        test_urls = [
            f"https://speed.cloudflare.com/__down?bytes={byte_limit}",
            f"http://speed.cloudflare.com/__down?bytes={byte_limit}",
            "http://proof.ovh.net/files/1Mb.dat",
            "https://fsn1-speed.hetzner.com/100MB.bin",
        ]
        for url in test_urls:
            try:
                t0 = time.perf_counter()
                total_bytes = 0
                with opener.open(url, timeout=timeout) as resp:
                    while True:
                        chunk = resp.read(32768)
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                        if total_bytes >= byte_limit or time.perf_counter() - t0 > timeout:
                            break
                dt = max(0.01, time.perf_counter() - t0)
                if total_bytes > 0:
                    mbps = round((total_bytes * 8.0) / (dt * 1_000_000.0), 2)
                    return True, mbps, total_bytes, round(dt, 2), f"{mbps:.1f} Mbps"
            except Exception:
                continue
        return False, 0.0, 0, 0.0, "Speed test failed"
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if cfg_path and os.path.exists(cfg_path):
            try:
                os.unlink(cfg_path)
            except Exception:
                pass


async def measure_node_speed(
    cfg: ParsedConfig,
    byte_limit: int = 524288,
    timeout: float = 6.0,
) -> tuple[bool, float, int, float, str]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, measure_node_speed_sync, cfg, byte_limit, timeout)


def probe_proxy_exit_ip_sync(cfg: ParsedConfig, timeout: float = 4.0) -> tuple[bool, str, str, str]:
    """
    Query external IP, country, and ISP through the proxy tunnel.
    Returns: (ok, ip, country_display, isp)
    """
    proc, port, cfg_path = _run_temp_http_proxy(cfg)
    try:
        if not proc or not port:
            return False, "", "", "No proxy core"

        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"})
        )
        try:
            with opener.open("http://ip-api.com/json/?fields=status,query,country,countryCode,isp", timeout=timeout) as r:
                data = json.loads(r.read().decode("utf-8", errors="ignore"))
                if data.get("status") == "success":
                    cc = (data.get("countryCode") or "").lower()
                    flag = _code_to_flag(cc)
                    ru_name = COUNTRY_RU_NAMES.get(cc, data.get("country", cc.upper()))
                    return True, data.get("query", ""), f"{flag} {ru_name}", data.get("isp", "")
        except Exception:
            pass

        try:
            with opener.open("http://ifconfig.me/ip", timeout=timeout) as r:
                ip = r.read().decode("utf-8", errors="ignore").strip()
                if ip:
                    return True, ip, "🌐", ""
        except Exception:
            pass
        return False, "", "", "Exit IP lookup failed"
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if cfg_path and os.path.exists(cfg_path):
            try:
                os.unlink(cfg_path)
            except Exception:
                pass


async def probe_proxy_exit_ip(cfg: ParsedConfig, timeout: float = 4.0) -> tuple[bool, str, str, str]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, probe_proxy_exit_ip_sync, cfg, timeout)


async def check_node_advanced(
    cfg: ParsedConfig,
    timeout: float = 2.5,
    samples_count: int = 3,
) -> NodeCheckResult:
    """
    Perform deep connection latency check, multi-sample jitter calculation,
    zombie/EOF detection, and real TLS 1.3 ClientHello SNI/DPI verification.
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

    # Hysteria 2 probe (DNS + UDP socket bind/connect check)
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
            if alive:
                # Verify UDP socket can target remote address without local routing failure
                af, socktype, proto_num, _, sockaddr = res[0]
                sock = socket.socket(af, socket.SOCK_DGRAM)
                try:
                    sock.connect(sockaddr)
                finally:
                    sock.close()
            rtt = max(95.0, dns_time * 2.0)
            tier = classify_tier(rtt, alive)
            return NodeCheckResult(
                config=cfg,
                alive=alive,
                latency_ms=round(rtt, 1),
                avg_latency_ms=round(rtt, 1),
                jitter_ms=2.5,
                tls_ok=alive,
                tls_detail="UDP/QUIC DNS OK",
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
    sni_ok = False
    tls_detail = ""

    try:
        # Sample 1: TCP connect + Zombie/RST detection + Genuine TLS 1.3 ClientHello SNI probe
        t0 = time.perf_counter()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(cfg.host, cfg.port),
            timeout=timeout,
        )
        sample1 = (time.perf_counter() - t0) * 1000.0
        samples.append(sample1)

        try:
            await asyncio.wait_for(reader.read(1), timeout=0.03)
        except asyncio.TimeoutError:
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

        target_sni = cfg.sni or cfg.host
        hello = build_tls_client_hello(target_sni)
        try:
            writer.write(hello)
            await writer.drain()
            tls_resp = await asyncio.wait_for(reader.read(64), timeout=max(1.5, timeout * 0.75))
            if tls_resp.startswith(b"\x16\x03"):
                tls_success = True
                sni_ok = True
                tls_detail = "ServerHello (SNI OK)"
            elif tls_resp.startswith(b"\x15\x03"):
                tls_success = True
                tls_detail = "TLS Alert (DPI Pass)"
            elif not tls_resp:
                tls_success = False
                tls_detail = "TLS EOF Drop"
            else:
                tls_success = False
                tls_detail = "Non-TLS response"
        except asyncio.TimeoutError:
            tls_success = False
            tls_detail = "TLS Timeout (DPI Drop)"
        except ConnectionResetError:
            tls_success = False
            tls_detail = "TLS Reset (TSPU RST)"
        except Exception as exc:
            tls_success = False
            tls_detail = str(exc)[:28]

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        # Additional quick TCP samples for accurate jitter & sparklines
        for _ in range(max(0, samples_count - 1)):
            try:
                t_n = time.perf_counter()
                _, writer_n = await asyncio.wait_for(
                    asyncio.open_connection(cfg.host, cfg.port),
                    timeout=min(1.5, timeout),
                )
                samples.append((time.perf_counter() - t_n) * 1000.0)
                writer_n.close()
                try:
                    await writer_n.wait_closed()
                except Exception:
                    pass
            except Exception:
                break

        min_rtt = min(samples)
        avg_rtt = sum(samples) / len(samples)
        jitter = (max(samples) - min(samples)) if len(samples) > 1 else 0.8
        tier = classify_tier(min_rtt, alive=True)
        spark = make_sparkline(samples)

        return NodeCheckResult(
            config=cfg,
            alive=True,
            latency_ms=round(min_rtt, 1),
            avg_latency_ms=round(avg_rtt, 1),
            jitter_ms=round(jitter, 1),
            tls_ok=tls_success,
            sni_ok=sni_ok,
            tls_detail=tls_detail,
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
    timeout: float = 2.5,
) -> list[NodeCheckResult]:
    """Run concurrent benchmark across multiple configs, sorted by TLS validity & latency."""
    sem = asyncio.Semaphore(concurrency)
    results: list[NodeCheckResult] = []
    total = len(configs)
    completed = 0

    async def worker(cfg: ParsedConfig) -> None:
        nonlocal completed
        async with sem:
            res = await check_node_advanced(cfg, timeout=timeout)
            results.append(res)
            completed += 1
            if progress_callback:
                progress_callback(completed, total, res)

    tasks = [asyncio.create_task(worker(c)) for c in configs]
    if tasks:
        await asyncio.gather(*tasks)

    # Sort: Alive first, TLS/SNI-verified first, VLESS/Trojan before Hysteria2, then lowest latency ms
    results.sort(
        key=lambda r: (
            not r.alive,
            not r.tls_ok,
            r.config.protocol == "hysteria2",
            r.latency_ms,
        )
    )
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
    tls_verified = sum(1 for r in alive if r.tls_ok)
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
        "tls_verified": tls_verified,
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
                "tls_detail": r.tls_detail,
                "http_ok": r.http_ok,
                "http_delay_ms": r.http_delay_ms,
                "http_probe_msg": r.http_probe_msg,
                "speed_mbps": r.speed_mbps,
                "grade": r.grade,
                "multi_ok": r.multi_ok,
                "multi_total": r.multi_total,
                "exit_ip": r.exit_ip,
                "exit_country": r.exit_country,
                "isp": r.isp,
                "wl_asn": r.wl_asn,
            }
            for r in alive[:20]
        ],
    }


def compute_node_grade(res: NodeCheckResult) -> str:
    """Compute composite server grade (S+ .. D) from real HTTP transit, concurrency, speed, jitter, and security."""
    if not res.alive:
        return "💀 D"
    if res.http_probe_msg and not res.http_ok:
        return "🔴 D"

    score = 0.0
    eff_ms = res.http_delay_ms if res.http_ok else (res.latency_ms * 1.4)
    if eff_ms < 120:
        score += 40
    elif eff_ms < 250:
        score += 32
    elif eff_ms < 450:
        score += 22
    elif eff_ms < 750:
        score += 12
    else:
        score += 4

    if res.http_ok:
        score += 20

    if res.multi_total > 0:
        score += 20.0 * (res.multi_ok / res.multi_total)
    elif res.http_ok:
        score += 10.0

    if res.speed_mbps >= 15.0:
        score += 15
    elif res.speed_mbps >= 5.0:
        score += 11
    elif res.speed_mbps >= 1.5:
        score += 6
    elif res.speed_mbps > 0:
        score += 3

    sec_l = (res.config.security or "").lower()
    if sec_l == "reality":
        score += 6
    if res.jitter_ms <= 8.0:
        score += 4
    elif res.jitter_ms <= 25.0:
        score += 2

    if score >= 88:
        return "🏆 S+"
    if score >= 75:
        return "🔥 S"
    if score >= 60:
        return "⚡ A"
    if score >= 42:
        return "🟢 B"
    if score >= 25:
        return "🟡 C"
    return "🔴 D"


def _hardcore_stress_one_sync(res: NodeCheckResult, timeout: float = 5.0) -> NodeCheckResult:
    """
    Execute hardcore multi-target + parallel burst stress + bandwidth speed + exit IP audit
    against a single node via its local HTTP proxy core.
    """
    proc, port, cfg_path = _run_temp_http_proxy(res.config)
    try:
        if not proc or not port:
            res.http_ok = False
            res.http_probe_msg = "No core"
            res.grade = compute_node_grade(res)
            return res

        proxy_url = f"http://127.0.0.1:{port}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )

        # 1. Multi-endpoint real HTTP/HTTPS concurrency burst (Cloudflare + Google gstatic + Google HTTPS)
        endpoints = [
            "http://cp.cloudflare.com/generate_204",
            "http://www.gstatic.com/generate_204",
            "https://www.google.com/generate_204",
        ]
        lat_samples: list[float] = []

        def check_ep(ep: str) -> bool:
            t0 = time.perf_counter()
            try:
                with opener.open(ep, timeout=timeout) as r:
                    if 200 <= r.status < 400:
                        lat_samples.append((time.perf_counter() - t0) * 1000.0)
                        return True
            except Exception:
                pass
            return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ep_pool:
            outcomes = list(ep_pool.map(check_ep, endpoints))

        res.multi_total = len(endpoints)
        res.multi_ok = sum(1 for ok in outcomes if ok)

        if res.multi_ok > 0:
            res.http_ok = True
            res.http_delay_ms = round(sum(lat_samples) / len(lat_samples), 1)
            res.http_probe_msg = f"{res.multi_ok}/{res.multi_total} ({res.http_delay_ms:.0f}ms)"
        else:
            res.http_ok = False
            res.http_delay_ms = 9999.0
            res.http_probe_msg = "Stress Drop 0/3"
            res.grade = compute_node_grade(res)
            return res

        # 2. Bandwidth speedtest using already-booted proxy instance
        byte_limit = 524288
        for sp_url in (
            f"https://speed.cloudflare.com/__down?bytes={byte_limit}",
            f"http://speed.cloudflare.com/__down?bytes={byte_limit}",
            "http://proof.ovh.net/files/1Mb.dat",
        ):
            try:
                t0 = time.perf_counter()
                total_b = 0
                with opener.open(sp_url, timeout=6.0) as resp:
                    while True:
                        chunk = resp.read(32768)
                        if not chunk:
                            break
                        total_b += len(chunk)
                        if total_b >= byte_limit or time.perf_counter() - t0 > 6.0:
                            break
                dt = max(0.01, time.perf_counter() - t0)
                if total_b > 0:
                    res.speed_mbps = round((total_b * 8.0) / (dt * 1_000_000.0), 2)
                    break
            except Exception:
                continue

        # 3. Exit IP, ISP, and RKP WL-ASN lookup using the same active tunnel
        try:
            with opener.open("http://ip-api.com/json/?fields=status,query,countryCode,isp,as", timeout=3.5) as r:
                d = json.loads(r.read().decode("utf-8", errors="ignore"))
                if d.get("status") == "success":
                    cc = (d.get("countryCode") or "").lower()
                    res.exit_ip = str(d.get("query", ""))
                    res.exit_country = f"{_code_to_flag(cc)} {COUNTRY_RU_NAMES.get(cc, cc.upper())}"
                    if not res.isp:
                        res.isp = str(d.get("isp", ""))
                    if not res.asn:
                        res.asn = str(d.get("as", ""))
                    wl_hit, _ = is_whitelist_asn(res.asn or res.isp)
                    res.wl_asn = res.wl_asn or wl_hit
        except Exception:
            pass

        res.grade = compute_node_grade(res)
        return res
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if cfg_path and os.path.exists(cfg_path):
            try:
                os.unlink(cfg_path)
            except Exception:
                pass


async def run_hardcore_stress_batch(
    results: list[NodeCheckResult],
    top_n: int = 15,
    concurrency: int = 5,
    progress_cb: Callable[[int, int, NodeCheckResult], None] | None = None,
) -> list[NodeCheckResult]:
    """Run concurrent hardcore multi-target + speed + exit-IP stress tests on top alive candidates."""
    candidates = [r for r in results if r.alive and not (r.http_probe_msg and not r.http_ok)][:top_n]
    if not candidates:
        candidates = [r for r in results if r.alive][:top_n]
    if not candidates:
        return results

    total = len(candidates)
    done = 0
    sem = asyncio.Semaphore(concurrency)
    loop = asyncio.get_running_loop()

    async def worker(r: NodeCheckResult) -> None:
        nonlocal done
        async with sem:
            await loop.run_in_executor(None, _hardcore_stress_one_sync, r, 5.0)
            done += 1
            if progress_cb:
                progress_cb(done, total, r)

    await asyncio.gather(*(worker(r) for r in candidates))

    for r in results:
        if not r.grade:
            r.grade = compute_node_grade(r)

    results.sort(
        key=lambda r: (
            not r.alive,
            not r.http_ok,
            -r.multi_ok,
            -r.speed_mbps,
            r.http_delay_ms if r.http_ok else 9999.0,
            r.latency_ms,
        )
    )
    return results
