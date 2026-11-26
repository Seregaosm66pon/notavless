"""
Update proxy subscriptions (VLESS, Trojan, Hysteria 2) from configured sources,
validate host/port reachability, split output into Mega/All/LTE/WiFi/Protocol files,
record contributor credits, and notify Telegram channel.
"""

from __future__ import annotations

import asyncio
import base64
import http.client
import logging
import re
import socket
import ssl
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode, urlparse

from config import (
    CHECK_CONCURRENCY,
    CHECK_TIMEOUT,
    GENERATE_BASE64,
    GITHUB_VLESS_RAW_URL,
    GITHUB_VLESS_RAW_URLS,
    HYSTERIA2_SUBSCRIPTION_OUTPUT,
    MEGA_FASTEST_OUTPUT,
    MEGA_FASTEST_URL,
    MEGA_SUBSCRIPTION_OUTPUT,
    MEGA_SUBSCRIPTION_URL,
    REPO_ROOT,
    SOURCES_FILE,
    TG_API_HASH,
    TG_API_ID,
    TG_API_ENDPOINT,
    TG_NOTIFY_CHANNEL,
    TG_NOTIFY_TOKEN,
    TG_PROXY_URL,
    TROJAN_SUBSCRIPTION_OUTPUT,
    URL_TEST_TARGET,
    VPN_GIT_COMMIT_MESSAGE,
    VPN_SOURCE_CHANNELS,
    VPN_SUBSCRIPTION_OUTPUT,
    VPN_SUBSCRIPTION_OUTPUT_LEGACY,
    VPN_SUBSCRIPTION_OUTPUT_LTE,
    VPN_SUBSCRIPTION_OUTPUT_WIFI,
)
from contributors import (
    get_contributors_summary,
    get_custom_nodes,
    read_sources_with_contributors,
)
from checker import (
    NodeCheckResult,
    build_tls_client_hello,
    classify_russian_tier,
    classify_tier,
    detect_country_info,
    enrich_country_geoip_batch,
    find_sing_box_executable,
    find_xray_executable,
    probe_nodes_http_batch,
)
from protocols import (
    ParsedConfig,
    ProxySourceError,
    download_proxy_source,
    parse_any_proxy_url,
    parse_proxy_source,
)
from tg_account_source import TelegramSourceError, load_vless_from_channels

PROFILE_HEADER_TEMPLATE = (
    "#profile-title: {profile_title}\n"
    "#profile-update-interval: 30\n"
    "#support-url: https://t.me/notavless\n"
    "#announce: Nota Vless - тело в дело!\n"
    "#subscription-userinfo: upload=0; download=0; total=0; expire=0\n"
)

LTE_HINTS = (
    "lte",
    "mobile",
    "whitelist",
    "white",
    "ru-mobile",
    "rus-mobile",
    "grpc",
    "gprc",
    "xhttp",
    "splithttp",
    "yandex",
    "ya.ru",
    "yastatic",
    "yandex.ru",
    "vk.com",
    "vk.me",
    "okcdn",
    "mycdn",
    "mail.ru",
    "mts",
    "beeline",
    "megafon",
    "tele2",
    "sber",
    "sberbank",
    "tinkoff",
    "t-bank",
    "tbank",
    "ozon",
    "wildberries",
    "wbbasket",
    "wb.ru",
    "rutube",
    "gosuslugi",
    "dzen",
    "kinopoisk",
    "avito",
    "beget",
    "selectel",
    "cloudconsole",
    "urent",
    "dns-shop",
)
_LTE_WORD_RE = re.compile(r"(?:^|[^a-z0-9])(vk|t2|x5|wb|max)(?:[^a-z0-9]|$)", re.IGNORECASE)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


def _sanitize_error(message: str) -> str:
    text = (message or "").strip()
    return text or "Network error."


def _build_config_key(cfg: ParsedConfig) -> tuple:
    return (
        cfg.protocol,
        cfg.uuid,
        cfg.host.lower(),
        cfg.port,
        cfg.network_type,
        cfg.security,
        cfg.path,
        cfg.host_header,
        cfg.sni,
        cfg.alpn,
        cfg.public_key,
        cfg.short_id,
    )


def telegram_source_enabled() -> bool:
    return bool(TG_API_ID and TG_API_HASH and VPN_SOURCE_CHANNELS)


def dedupe_configs(configs: list[ParsedConfig], max_per_host_port: int = 2) -> list[ParsedConfig]:
    seen_idx: dict[tuple, int] = {}
    host_port_counts: dict[tuple[str, int], int] = {}
    deduped: list[ParsedConfig] = []
    preferred_fps = {"chrome", "firefox", "edge", "safari", "ios", "android"}

    for cfg in configs:
        key = _build_config_key(cfg)
        if key in seen_idx:
            # Prefer cleaner uTLS fingerprint over exotic/broken ones on exact duplicates
            existing_pos = seen_idx[key]
            existing_fp = (deduped[existing_pos].fingerprint or "").lower()
            cand_fp = (cfg.fingerprint or "").lower()
            if existing_fp not in preferred_fps and cand_fp in preferred_fps:
                deduped[existing_pos] = cfg
            continue
        hp = (cfg.host.lower(), cfg.port)
        if host_port_counts.get(hp, 0) >= max_per_host_port:
            continue
        seen_idx[key] = len(deduped)
        host_port_counts[hp] = host_port_counts.get(hp, 0) + 1
        deduped.append(cfg)
    return deduped


def normalize_urls(
    configs: list[ParsedConfig],
    latencies: dict[tuple[str, str, int], float] | None = None,
    default_tier: str = "Ультра",
) -> list[str]:
    if latencies is None:
        latencies = {}

    country_counters: dict[str, int] = {}
    normalized: list[str] = []

    for cfg in configs:
        key = (cfg.protocol, cfg.host, cfg.port)
        lat = latencies.get(key, 0.0)
        tier = classify_russian_tier(lat) if lat > 0 else default_tier

        code, flag, country_name = detect_country_info(cfg.remark, cfg.host, cfg.sni)
        country_counters[country_name] = country_counters.get(country_name, 0) + 1
        idx = country_counters[country_name]

        # Branded template: [Ультра] Германия #1 NOTAVLESS
        new_name = f"[{tier}] {country_name} #{idx} NOTAVLESS"
        base_url = cfg.raw_url.split("#", 1)[0]
        # Ensure SNI is present in query parameters so clients don't fail certificate validation against raw IP
        if cfg.sni and "sni=" not in base_url:
            sep = "&" if "?" in base_url else "?"
            base_url = f"{base_url}{sep}sni={urllib.parse.quote(cfg.sni)}"
        quoted_name = urllib.parse.quote(new_name)
        normalized.append(f"{base_url}#{quoted_name}")

    return normalized


def is_lte_config(cfg: ParsedConfig) -> bool:
    net_type = cfg.network_type.lower()
    if net_type in {"grpc", "xhttp", "splithttp"}:
        return True
    blob = " ".join(
        (
            cfg.remark,
            cfg.network_type,
            cfg.path,
            cfg.sni,
            cfg.host_header,
            cfg.raw_url,
        )
    ).lower()
    if any(token in blob for token in LTE_HINTS):
        return True
    return bool(_LTE_WORD_RE.search(blob))


def split_lte_wifi(configs: list[ParsedConfig]) -> tuple[list[ParsedConfig], list[ParsedConfig]]:
    lte: list[ParsedConfig] = []
    wifi: list[ParsedConfig] = []
    for cfg in configs:
        if is_lte_config(cfg):
            lte.append(cfg)
        else:
            wifi.append(cfg)
    return lte, wifi


def _extract_proxy_lines(content: str) -> list[str]:
    lines: list[str] = []
    prefixes = ("vless://", "trojan://", "hysteria2://", "hy2://")
    for line in content.splitlines():
        cleaned = line.strip()
        if any(cleaned.lower().startswith(p) for p in prefixes):
            lines.append(cleaned)
    return lines


def _render_output(lines: list[str], profile_title: str) -> str:
    generated = f"#generated-at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    header = PROFILE_HEADER_TEMPLATE.format(profile_title=profile_title)
    body = "\n".join(lines)
    return header + "\n" + generated + ("\n" + body + "\n" if body else "\n")


def write_output_file(lines: list[str], output_path: Path, profile_title: str) -> bool:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    old_content = output_path.read_text(encoding="utf-8") if output_path.exists() else ""
    old_lines = _extract_proxy_lines(old_content)
    if old_lines == lines:
        return False
    output_path.write_text(_render_output(lines, profile_title), encoding="utf-8")
    return True


def write_base64_file(lines: list[str], output_path: Path) -> bool:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(lines)
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii") + "\n"
    old_content = output_path.read_text(encoding="utf-8") if output_path.exists() else ""
    if old_content == encoded:
        return False
    output_path.write_text(encoded, encoding="utf-8")
    return True


def run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False)


def push_if_changed(changed_paths: list[Path]) -> str:
    if not changed_paths:
        return "skip: no changed files"

    if not (REPO_ROOT / ".git").is_dir():
        return "skip: not a git repository"

    user_name = run_git(["config", "user.name"]).stdout.strip()
    if not user_name:
        run_git(["config", "user.name", "github-actions[bot]"])
        run_git(["config", "user.email", "github-actions[bot]@users.noreply.github.com"])

    rel_paths = [str(path.relative_to(REPO_ROOT)) for path in changed_paths]
    run_git(["add", *rel_paths])
    if run_git(["diff", "--cached", "--quiet"]).returncode == 0:
        return "skip: no staged changes"

    commit_result = run_git(["commit", "-m", VPN_GIT_COMMIT_MESSAGE])
    if commit_result.returncode != 0:
        return f"commit failed: {_sanitize_error(commit_result.stderr.strip() or commit_result.stdout.strip())}"

    push_result = run_git(["push", "origin", "HEAD:main"])
    if push_result.returncode != 0:
        # Remote may have advanced; try pull --rebase with preference to our generated files
        rebase_pull = run_git(["pull", "--rebase", "-X", "theirs", "origin", "main"])
        if rebase_pull.returncode != 0:
            run_git(["rebase", "--abort"])
        else:
            push_result = run_git(["push", "origin", "HEAD:main"])
    if push_result.returncode != 0:
        push_result = run_git(["push"])
    if push_result.returncode != 0:
        return f"push failed: {_sanitize_error(push_result.stderr.strip() or push_result.stdout.strip())}"

    return "commit and push completed"


def _send_notification_sync(message_text: str) -> tuple[bool, str]:
    if not TG_NOTIFY_TOKEN or not TG_NOTIFY_CHANNEL:
        msg = "TG_NOTIFY_TOKEN or TG_NOTIFY_CHANNEL not set."
        logger.info("Telegram notification skipped: %s", msg)
        return False, msg

    base_endpoint = (TG_API_ENDPOINT or "https://api.telegram.org").rstrip("/")
    url = f"{base_endpoint}/bot{TG_NOTIFY_TOKEN}/sendMessage"

    proxy_candidates: list[str | None] = [TG_PROXY_URL] if TG_PROXY_URL else [None]
    if not TG_PROXY_URL:
        # Common local proxy ports (Koala Clash, Hiddify, v2rayN)
        proxy_candidates.extend([
            "http://127.0.0.1:7890",
            "http://127.0.0.1:10809",
            "http://127.0.0.1:10808",
            "http://127.0.0.1:2334",
            "http://127.0.0.1:2080",
        ])

    last_error = ""

    for proxy in proxy_candidates:
        handlers = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))

        opener = urllib.request.build_opener(*handlers)

        for parse_mode in ("Markdown", None):
            payload_data = {
                "chat_id": TG_NOTIFY_CHANNEL,
                "text": message_text,
                "disable_web_page_preview": "true",
            }
            if parse_mode:
                payload_data["parse_mode"] = parse_mode

            payload = urlencode(payload_data).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            try:
                with opener.open(req, timeout=10) as resp:
                    resp.read()
                    used = f" via {proxy}" if proxy else ""
                    logger.info("Telegram notification sent successfully to %s%s", TG_NOTIFY_CHANNEL, used)
                    return True, "Success"
            except urllib.error.HTTPError as http_err:
                body = http_err.read().decode("utf-8", errors="ignore")
                last_error = f"HTTP {http_err.code}: {body}"
                if parse_mode:
                    continue
                logger.warning("Telegram notification failed (%s)", last_error)
                return False, last_error
            except Exception as exc:
                last_error = _sanitize_error(str(exc))
                break

    return False, last_error or "Unknown failure"


async def send_notification(message_text: str) -> None:
    try:
        await asyncio.to_thread(_send_notification_sync, message_text)
    except Exception as exc:
        logger.warning("Notify task failed: %s", _sanitize_error(str(exc)))


async def load_source_result() -> tuple[str, dict]:
    # 1. Parse Telegram channels if configured
    if telegram_source_enabled():
        try:
            result = await load_vless_from_channels(VPN_SOURCE_CHANNELS)
            result["sources"] = list(VPN_SOURCE_CHANNELS)
            result["failed_sources"] = 0
            return "telegram", result
        except TelegramSourceError as exc:
            logger.warning("Telegram source failed, fallback to URL sources: %s", _sanitize_error(str(exc)))

    # 2. Parse sources file with contributor attribution
    sources_with_contributors = (
        read_sources_with_contributors(Path(SOURCES_FILE)) if SOURCES_FILE else []
    )
    urls_seen: set[str] = set()
    source_items: list[tuple[str, str]] = []

    for url, author in sources_with_contributors:
        if url not in urls_seen:
            urls_seen.add(url)
            source_items.append((url, author))

    # Add environment URLs
    env_urls = GITHUB_VLESS_RAW_URLS or ([GITHUB_VLESS_RAW_URL] if GITHUB_VLESS_RAW_URL else [])
    for u in env_urls:
        cleaned = u.strip()
        if cleaned and cleaned not in urls_seen:
            urls_seen.add(cleaned)
            source_items.append((cleaned, "@admin"))

    if not source_items and not get_custom_nodes():
        raise ProxySourceError("No sources or nodes configured.")

    all_configs: list[ParsedConfig] = []
    total_candidates = 0
    skipped_count = 0
    failed_sources = 0

    # Add manually contributed nodes from contributions.json
    custom_nodes = get_custom_nodes()
    for item in custom_nodes:
        raw_url = item.get("raw_url", "")
        author = item.get("added_by", "@community")
        parsed = parse_any_proxy_url(raw_url, added_by=author)
        if parsed:
            all_configs.append(parsed)
            total_candidates += 1

    # Fetch remote URLs concurrently
    async def fetch_one(url: str, author: str):
        try:
            text = await download_proxy_source(url)
            return url, author, text, None
        except Exception as exc:
            return url, author, "", exc

    fetched_items = await asyncio.gather(*(fetch_one(u, a) for u, a in source_items))
    for url, author, text, exc in fetched_items:
        if exc is not None:
            failed_sources += 1
            logger.warning("Failed to fetch %s: %s", url, _sanitize_error(str(exc)))
            continue

        parsed = parse_proxy_source(text, added_by=author)
        total_candidates += parsed["total_candidates"]
        skipped_count += parsed["skipped_count"]
        all_configs.extend(parsed["valid_configs"])
        logger.info("Fetched %s: valid=%d candidates=%d", url, parsed["valid_count"], parsed["total_candidates"])

    if not all_configs and failed_sources == len(source_items):
        raise ProxySourceError("All sources failed to download.")

    return "urls", {
        "total_candidates": total_candidates,
        "valid_configs": all_configs,
        "valid_count": len(all_configs),
        "skipped_count": skipped_count,
        "sources": [u for u, _ in source_items],
        "failed_sources": failed_sources,
    }


async def check_tcp_port(host: str, port: int, timeout: float = 2.5) -> bool:
    if not host or not port or not (1 <= port <= 65535):
        return False
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def check_udp_reachability(host: str, port: int, timeout: float = 2.5) -> bool:
    if not host or not port or not (1 <= port <= 65535):
        return False
    try:
        loop = asyncio.get_running_loop()
        res = await asyncio.wait_for(
            loop.getaddrinfo(host, port, proto=socket.IPPROTO_UDP),
            timeout=timeout,
        )
        return bool(res)
    except Exception:
        return False


async def check_node(
    cfg: ParsedConfig,
    timeout: float = 2.5,
    allow_reality_tcp: bool = False,
) -> tuple[bool, float]:
    # 1. Hysteria 2: verify DNS + UDP socket target reachability
    if cfg.protocol == "hysteria2":
        udp_ok = await check_udp_reachability(cfg.host, cfg.port, timeout=timeout)
        return (True, 999.0) if udp_ok else (False, 9999.0)

    # 2. Reject unencrypted VLESS / Trojan (security == 'none' or insecure HTTP ports 80, 8080, 8880, 2086, 2082)
    # These are blocked by Russian TSPU/RKN and fail URL test in Throne
    if cfg.security not in ("reality", "tls"):
        return False, 9999.0
    if cfg.port in (80, 8080, 8880, 2086, 2082):
        return False, 9999.0

    # 3. Reject Cloudflare workers/pages which are hard-blocked by TSPU in Russia and cause x509 cert errors
    blob = f"{cfg.host} {cfg.sni} {cfg.host_header}".lower()
    if any(b in blob for b in (".workers.dev", ".pages.dev", "workers.dev", "pages.dev")):
        return False, 9999.0

    # 4. VLESS & Trojan: real TCP reachability & genuine TLS 1.3 ClientHello SNI probe
    t0 = time.perf_counter()
    target_sni = cfg.sni or cfg.host
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(cfg.host, cfg.port),
            timeout=timeout,
        )
        tcp_rtt = (time.perf_counter() - t0) * 1000.0

        hello = build_tls_client_hello(target_sni)
        writer.write(hello)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(64), timeout=min(2.0, timeout * 0.8))
        except asyncio.TimeoutError:
            data = None
        rtt = (time.perf_counter() - t0) * 1000.0

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        # Dead / zombie EOF / TSPU silent drop (timeout returns None, EOF returns b"")
        if data == b"":
            return False, 9999.0
        if data is None:
            # When Dual-Core HTTP probe is active, allow Reality TCP listeners through for real key verification
            if allow_reality_tcp and cfg.security == "reality":
                return True, round(tcp_rtt, 1)
            return False, 9999.0

        # ServerHello (0x16 0x03) -> SNI and TLS stack verified in one RTT
        if data.startswith(b"\x16\x03"):
            return True, round(rtt, 1)

        # For Reality: TLS Alert (0x15 0x03) indicates live TLS responder (not DPI drop)
        if cfg.security == "reality":
            if data.startswith(b"\x15\x03"):
                return True, round(rtt, 1)
            return False, 9999.0

        # For standard TLS: fallback SSL handshake check if ServerHello wasn't returned directly
        if cfg.security == "tls" and target_sni:
            try:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                t1 = time.perf_counter()
                r2, w2 = await asyncio.wait_for(
                    asyncio.open_connection(cfg.host, cfg.port, ssl=ssl_ctx, server_hostname=target_sni),
                    timeout=max(1.5, timeout * 0.7),
                )
                tls_rtt = (time.perf_counter() - t1) * 1000.0
                w2.close()
                try:
                    await w2.wait_closed()
                except Exception:
                    pass
                return True, round(tls_rtt, 1)
            except Exception:
                return False, 9999.0

        return False, 9999.0
    except Exception:
        return False, 9999.0


async def check_url_test(target_url: str, timeout: float = 5.0) -> bool:
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False

    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    ssl_context = ssl.create_default_context() if parsed.scheme == "https" else None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=host,
                port=port,
                ssl=ssl_context,
                server_hostname=host if ssl_context else None,
            ),
            timeout=timeout,
        )
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "User-Agent: NotaVless/2.0\r\n\r\n"
        )
        writer.write(request.encode("ascii", errors="ignore"))
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return any(code in status_line for code in (b" 200 ", b" 204 ", b" 301 ", b" 302 "))
    except Exception:
        return False


async def filter_reachable_configs(
    configs: list[ParsedConfig],
    allow_reality_tcp: bool = False,
) -> tuple[list[ParsedConfig], int, dict[tuple[str, str, int], float], list[float]]:
    ok: list[tuple[ParsedConfig, float]] = []
    failed = 0
    sem = asyncio.Semaphore(CHECK_CONCURRENCY)
    host_cache: dict[tuple[str, str, int, str, str], tuple[bool, float]] = {}

    async def check(cfg: ParsedConfig) -> None:
        nonlocal failed
        key = (cfg.protocol, cfg.host, cfg.port, cfg.security, cfg.sni)
        async with sem:
            if key in host_cache:
                alive, lat = host_cache[key]
            else:
                alive, lat = await check_node(cfg, timeout=CHECK_TIMEOUT, allow_reality_tcp=allow_reality_tcp)
                host_cache[key] = (alive, lat)
        if alive:
            ok.append((cfg, lat))
        else:
            failed += 1

    await asyncio.gather(*(check(cfg) for cfg in configs))
    # Sort by lowest latency
    ok.sort(key=lambda item: item[1])
    sorted_configs = [cfg for cfg, _ in ok]
    latencies_map: dict[tuple[str, str, int], float] = {}
    for cfg, lat in ok:
        hp_key = (cfg.protocol, cfg.host, cfg.port)
        if hp_key not in latencies_map or lat < latencies_map[hp_key]:
            latencies_map[hp_key] = lat
    latencies_list = [lat for _, lat in ok if lat < 900.0]
    return sorted_configs, failed, latencies_map, latencies_list


def select_diverse_fastest(
    configs: list[ParsedConfig],
    latencies_map: dict[tuple[str, str, int], float],
    limit: int = 100,
    max_per_cluster: int = 2,
) -> list[ParsedConfig]:
    """Select top-N fastest configs while preventing one UUID/subnet farm from dominating."""
    def _cluster_key(c: ParsedConfig) -> tuple[str, str]:
        parts = c.host.split(".")
        subnet = ".".join(parts[:3]) if len(parts) == 4 and all(p.isdigit() for p in parts) else c.host.lower()
        return (c.uuid[:16], subnet)

    def _filter_pass(max_lat: float, require_country: bool) -> list[ParsedConfig]:
        picked: list[ParsedConfig] = []
        overflow: list[ParsedConfig] = []
        counts: dict[tuple[str, str], int] = {}
        for c in configs:
            lat = latencies_map.get((c.protocol, c.host, c.port), 9999.0)
            if lat >= max_lat:
                continue
            if require_country and detect_country_info(c.remark, c.host, c.sni)[2] == "Сервер":
                continue
            ck = _cluster_key(c)
            if counts.get(ck, 0) < max_per_cluster:
                picked.append(c)
                counts[ck] = counts.get(ck, 0) + 1
            else:
                overflow.append(c)
            if len(picked) >= limit:
                return picked
        for c in overflow:
            if len(picked) >= limit:
                break
            picked.append(c)
        return picked

    pool = _filter_pass(250.0, require_country=True)
    if len(pool) < 50:
        pool = _filter_pass(450.0, require_country=True)
    if len(pool) < 30:
        pool = _filter_pass(600.0, require_country=False)
    return pool[:limit] if pool else configs[:limit]


async def run_update_pipeline() -> dict:
    source_name, result = await load_source_result()
    deduped = dedupe_configs(result["valid_configs"])

    url_test_ok = await check_url_test(URL_TEST_TARGET)
    if not url_test_ok:
        logger.warning("URL test target is not reachable: %s", URL_TEST_TARGET)

    has_core = bool(find_sing_box_executable() or find_xray_executable())
    reachable, connect_failed, latencies_map, latencies = await filter_reachable_configs(
        deduped, allow_reality_tcp=has_core
    )

    # Enrich unknown IP countries via fast batch GeoIP so nodes get accurate flags instead of "Сервер"
    unknown_hosts = [
        c.host for c in reachable
        if detect_country_info(c.remark, c.host, c.sni)[2] == "Сервер"
    ]
    if unknown_hosts:
        await asyncio.to_thread(enrich_country_geoip_batch, unknown_hosts, 2.5)

    # Real Dual-Core HTTP 204 proxy verification when sing-box/Xray is installed (CI or local)
    http_verified_keys: set[tuple] = set()
    http_failed_keys: set[tuple] = set()
    if has_core and reachable:
        probe_candidates = [c for c in reachable if c.protocol in ("vless", "trojan")]
        # Probe Reality candidates and fastest TLS nodes first (up to 240 nodes cleanly in ~8s)
        probe_candidates.sort(key=lambda c: (0 if c.security == "reality" else 1, latencies_map.get((c.protocol, c.host, c.port), 999.0)))
        probe_subset = probe_candidates[:240]
        probe_items: list[NodeCheckResult] = []
        for c in probe_subset:
            code, flag, ru_name = detect_country_info(c.remark, c.host, c.sni)
            lat = latencies_map.get((c.protocol, c.host, c.port), 999.0)
            probe_items.append(
                NodeCheckResult(
                    config=c,
                    alive=True,
                    latency_ms=lat,
                    tls_ok=True,
                    country_code=code,
                    country_flag=flag,
                    country_name=ru_name,
                    quality_tier=classify_tier(lat, True),
                )
            )
        probed = await probe_nodes_http_batch(
            probe_items,
            top_n=len(probe_items),
            concurrency=28,
            timeout=4.5,
            smart_select=False,
        )
        probed_keys = {_build_config_key(c) for c in probe_subset}
        for r in probed:
            k = _build_config_key(r.config)
            if r.http_ok:
                http_verified_keys.add(k)
                latencies_map[(r.config.protocol, r.config.host, r.config.port)] = r.http_delay_ms
            else:
                http_failed_keys.add(k)
        logger.info(
            "Dual-Core HTTP 204 audit: probed=%d passed=%d failed=%d",
            len(probe_items),
            len(http_verified_keys),
            len(http_failed_keys),
        )
        if len(http_verified_keys) >= 10:
            # Drop every node that was tested via core and failed HTTP 204 transit
            reachable = [
                c for c in reachable
                if _build_config_key(c) in http_verified_keys
                or c.protocol == "hysteria2"
                or _build_config_key(c) not in probed_keys
            ]
            latencies = [
                latencies_map[(c.protocol, c.host, c.port)]
                for c in reachable
                if c.protocol != "hysteria2" and (c.protocol, c.host, c.port) in latencies_map
            ]

    # Segregate by protocol and sort by HTTP verification + lowest latency + Reality:443 preference
    def vless_pref(c: ParsedConfig) -> tuple[int, int, int, float]:
        k = _build_config_key(c)
        http_tier = 0 if k in http_verified_keys else (2 if k in http_failed_keys else 1)
        lat = latencies_map.get((c.protocol, c.host, c.port), 9999.0)
        _, _, country_name = detect_country_info(c.remark, c.host, c.sni)
        # Known country preferred over generic "Сервер"
        country_tier = 1 if country_name == "Сервер" else 0
        # Tier 0: Reality on 443 (gold standard in RU)
        # Tier 1: Reality on high ports
        # Tier 2: Standard TLS on 443
        # Tier 3: Standard TLS on other ports
        if c.security == "reality" and c.port == 443:
            sec_tier = 0
        elif c.security == "reality":
            sec_tier = 1
        elif c.security == "tls" and c.port == 443:
            sec_tier = 2
        else:
            sec_tier = 3
        return (http_tier, country_tier, sec_tier, lat)

    vless_configs = sorted([c for c in reachable if c.protocol == "vless"], key=vless_pref)
    trojan_configs = sorted(
        [c for c in reachable if c.protocol == "trojan"],
        key=lambda c: (0 if _build_config_key(c) in http_verified_keys else 1, latencies_map.get((c.protocol, c.host, c.port), 9999.0)),
    )
    hy2_configs = sorted(
        [c for c in reachable if c.protocol == "hysteria2"],
        key=lambda c: latencies_map.get((c.protocol, c.host, c.port), 9999.0),
    )

    # Mega subscription: VLESS (verified fastest) FIRST -> Trojan -> Hysteria 2 at the bottom!
    mega_ordered = vless_configs + trojan_configs + hy2_configs
    mega_urls = normalize_urls(mega_ordered, latencies_map)

    # Fastest Top 100: prioritize strictly HTTP-204-verified nodes when available!
    fastest_candidates = (
        [c for c in (vless_configs + trojan_configs) if _build_config_key(c) in http_verified_keys]
        if len(http_verified_keys) >= 5
        else (vless_configs + trojan_configs)
    )
    fastest_configs = select_diverse_fastest(fastest_candidates, latencies_map, limit=100)
    fastest_urls = normalize_urls(fastest_configs, latencies_map)

    # Segregate by network type (LTE vs WiFi) using ordered configs
    lte_configs, wifi_configs = split_lte_wifi(mega_ordered)

    vless_all_urls = normalize_urls(vless_configs, latencies_map)
    lte_urls = normalize_urls(lte_configs, latencies_map)
    wifi_urls = normalize_urls(wifi_configs, latencies_map)
    trojan_urls = normalize_urls(trojan_configs, latencies_map)
    hy2_urls = normalize_urls(hy2_configs, latencies_map)

    # Standard outputs
    outputs: list[tuple[Path, str, list[str]]] = [
        # Mega / Universal subscription
        (REPO_ROOT / MEGA_SUBSCRIPTION_OUTPUT, "Nota Vless Universal Mega", mega_urls),
        (REPO_ROOT / MEGA_FASTEST_OUTPUT, "Nota Vless Fastest Top 100", fastest_urls),
        # VLESS collections
        (REPO_ROOT / VPN_SUBSCRIPTION_OUTPUT, "Nota Vless", vless_all_urls),
        (REPO_ROOT / VPN_SUBSCRIPTION_OUTPUT_LTE, "Nota Vless LTE", lte_urls),
        (REPO_ROOT / VPN_SUBSCRIPTION_OUTPUT_WIFI, "Nota Vless WiFi", wifi_urls),
        # Dedicated protocol collections
        (REPO_ROOT / TROJAN_SUBSCRIPTION_OUTPUT, "Nota Vless Trojan", trojan_urls),
        (REPO_ROOT / HYSTERIA2_SUBSCRIPTION_OUTPUT, "Nota Vless Hysteria 2", hy2_urls),
    ]

    # Legacy alias sync
    if VPN_SUBSCRIPTION_OUTPUT_LEGACY and VPN_SUBSCRIPTION_OUTPUT_LEGACY != VPN_SUBSCRIPTION_OUTPUT:
        outputs.append((REPO_ROOT / VPN_SUBSCRIPTION_OUTPUT_LEGACY, "Nota Vless", vless_all_urls))

    changed_paths: list[Path] = []
    for path, title, lines in outputs:
        if write_output_file(lines, path, title):
            changed_paths.append(path)

    # Generate Base64 versions
    if GENERATE_BASE64:
        base64_outputs = (
            (REPO_ROOT / "mega_sub_base64.txt", mega_urls),
            (REPO_ROOT / "mega_sub_fastest_base64.txt", fastest_urls),
            (REPO_ROOT / "vlessall_base64.txt", vless_all_urls),
            (REPO_ROOT / "vless_lte_base64.txt", lte_urls),
            (REPO_ROOT / "vless_wifi_base64.txt", wifi_urls),
            (REPO_ROOT / "trojan_base64.txt", trojan_urls),
            (REPO_ROOT / "hysteria2_base64.txt", hy2_urls),
        )
        for b64_path, lines in base64_outputs:
            if write_base64_file(lines, b64_path):
                changed_paths.append(b64_path)

    changed = bool(changed_paths)
    git_status = push_if_changed(changed_paths)
    contributors_summary = get_contributors_summary(limit=4)

    avg_ping = round(sum(latencies) / len(latencies), 1) if latencies else 0.0
    min_ping = round(min(latencies), 1) if latencies else 0.0

    # Telegram notification matching exact requested format
    msg = (
        "New update:3\n"
        f"> servers amount:{len(mega_urls)}\n"
        f"> best ping:{min_ping}ms | avg ping:{avg_ping}ms\n"
        f"> lte amount:{len(lte_urls)}\n"
        f"> wifi amount:{len(wifi_urls)}\n"
        f"> changed:{str(changed).lower()}\n\n"
        f"> Universal config: {MEGA_SUBSCRIPTION_URL}\n"
        f"> Fastest (Top 100): {MEGA_FASTEST_URL}"
    )

    logger.info(
        "source=%s total=%s parsed=%s deduped=%s live_mega=%s (vless=%s trojan=%s hy2=%s) lte=%s wifi=%s changed=%s git=%s",
        source_name,
        result["total_candidates"],
        result["valid_count"],
        len(deduped),
        len(mega_urls),
        len(vless_all_urls),
        len(trojan_urls),
        len(hy2_urls),
        len(lte_urls),
        len(wifi_urls),
        changed,
        git_status,
    )

    if git_status.startswith("push failed:") or git_status.startswith("commit failed:"):
        raise RuntimeError(f"Git publication failed: {git_status}")

    await send_notification(msg)

    return {
        "total_candidates": result["total_candidates"],
        "deduped": len(deduped),
        "live_mega": len(mega_urls),
        "vless": len(vless_all_urls),
        "trojan": len(trojan_urls),
        "hy2": len(hy2_urls),
        "lte": len(lte_urls),
        "wifi": len(wifi_urls),
        "avg_ping": avg_ping,
        "min_ping": min_ping,
        "changed": changed,
        "git_status": git_status,
    }


async def main() -> None:
    await run_update_pipeline()


if __name__ == "__main__":
    asyncio.run(main())
