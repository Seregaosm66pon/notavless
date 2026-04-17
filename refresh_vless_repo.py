"""
Update VLESS subscriptions from configured sources, validate hosts,
split output into all/LTE/WiFi files, and push updates to GitHub.
"""

from __future__ import annotations

import asyncio
import http.client
import logging
import ssl
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode, urlparse

from config import (
    GITHUB_VLESS_RAW_URL,
    GITHUB_VLESS_RAW_URLS,
    REPO_ROOT,
    SOURCES_FILE,
    TG_API_HASH,
    TG_API_ID,
    TG_NOTIFY_CHANNEL,
    TG_NOTIFY_TOKEN,
    URL_TEST_TARGET,
    VPN_GIT_COMMIT_MESSAGE,
    VPN_SOURCE_CHANNELS,
    VPN_SUBSCRIPTION_OUTPUT,
    VPN_SUBSCRIPTION_OUTPUT_LTE,
    VPN_SUBSCRIPTION_OUTPUT_WIFI,
)
from tg_account_source import TelegramSourceError, load_vless_from_channels
from vless import ParsedVlessConfig, VlessSourceError, download_vless_source, parse_vless_source

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
    "grpc",
    "gprc",
    "yandex",
    "ya.ru",
    "yastatic",
    "yandex.ru",
    "max",
    "vk",
    "mail.ru",
    "mts",
    "beeline",
    "megafon",
    "tele2",
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


def _sanitize_error(message: str) -> str:
    text = (message or "").strip()
    return text or "Network error."


def _build_config_key(cfg: ParsedVlessConfig) -> tuple:
    return (
        cfg.uuid,
        cfg.host,
        cfg.port,
        cfg.network_type,
        cfg.security,
        cfg.path,
        cfg.host_header,
        cfg.sni,
        cfg.alpn,
        cfg.fingerprint,
        cfg.public_key,
        cfg.short_id,
    )


def _unique_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _read_sources_file(path: str) -> list[str]:
    file_path = Path(path)
    if not file_path.exists():
        return []
    lines: list[str] = []
    for line in file_path.read_text(encoding="utf-8").splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        lines.append(cleaned)
    return lines


def telegram_source_enabled() -> bool:
    return bool(TG_API_ID and TG_API_HASH and VPN_SOURCE_CHANNELS)


def dedupe_configs(configs: list[ParsedVlessConfig]) -> list[ParsedVlessConfig]:
    seen: set[tuple] = set()
    deduped: list[ParsedVlessConfig] = []
    for cfg in configs:
        key = _build_config_key(cfg)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(cfg)
    return deduped


def normalize_urls(configs: list[ParsedVlessConfig]) -> list[str]:
    return [cfg.raw_url for cfg in configs]


def is_lte_config(cfg: ParsedVlessConfig) -> bool:
    if cfg.network_type.lower() == "grpc":
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
    return any(token in blob for token in LTE_HINTS)


def split_lte_wifi(configs: list[ParsedVlessConfig]) -> tuple[list[ParsedVlessConfig], list[ParsedVlessConfig]]:
    lte: list[ParsedVlessConfig] = []
    wifi: list[ParsedVlessConfig] = []
    for cfg in configs:
        if is_lte_config(cfg):
            lte.append(cfg)
        else:
            wifi.append(cfg)
    return lte, wifi


def _extract_vless_lines(content: str) -> list[str]:
    lines: list[str] = []
    for line in content.splitlines():
        cleaned = line.strip()
        if cleaned.lower().startswith("vless://"):
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
    old_lines = _extract_vless_lines(old_content)
    if old_lines == lines:
        return False
    output_path.write_text(_render_output(lines, profile_title), encoding="utf-8")
    return True


def run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False)


def push_if_changed(changed_paths: list[Path]) -> str:
    if not changed_paths:
        return "skip: no changed files"

    rel_paths = [str(path.relative_to(REPO_ROOT)) for path in changed_paths]
    run_git(["add", *rel_paths])
    if run_git(["diff", "--cached", "--quiet"]).returncode == 0:
        return "skip: no staged changes"

    commit_result = run_git(["commit", "-m", VPN_GIT_COMMIT_MESSAGE])
    if commit_result.returncode != 0:
        return f"commit failed: {_sanitize_error(commit_result.stderr.strip() or commit_result.stdout.strip())}"

    push_result = run_git(["push"])
    if push_result.returncode != 0:
        return f"push failed: {_sanitize_error(push_result.stderr.strip() or push_result.stdout.strip())}"

    return "commit and push completed"


def _send_notification_sync(message: str) -> None:
    if not TG_NOTIFY_TOKEN or not TG_NOTIFY_CHANNEL:
        return
    payload = urlencode(
        {
            "chat_id": TG_NOTIFY_CHANNEL,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": "true",
        }
    )
    connection = http.client.HTTPSConnection("api.telegram.org", timeout=20)
    try:
        connection.request(
            "POST",
            f"/bot{TG_NOTIFY_TOKEN}/sendMessage",
            body=payload.encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response = connection.getresponse()
        if response.status >= 400:
            body = response.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {response.status}: {body}")
        response.read()
    finally:
        connection.close()


async def send_notification(message: str) -> None:
    try:
        await asyncio.to_thread(_send_notification_sync, message)
    except Exception as exc:
        logger.warning("Notify failed: %s", _sanitize_error(str(exc)))


async def load_source_result() -> tuple[str, dict]:
    if telegram_source_enabled():
        try:
            result = await load_vless_from_channels(VPN_SOURCE_CHANNELS)
            result["sources"] = list(VPN_SOURCE_CHANNELS)
            result["failed_sources"] = 0
            return "telegram", result
        except TelegramSourceError as exc:
            logger.warning("Telegram source failed, fallback to URL sources: %s", _sanitize_error(str(exc)))

    urls = _read_sources_file(SOURCES_FILE) if SOURCES_FILE else []
    env_urls = GITHUB_VLESS_RAW_URLS or ([GITHUB_VLESS_RAW_URL] if GITHUB_VLESS_RAW_URL else [])
    urls.extend(env_urls)
    urls = _unique_preserve_order([item.strip() for item in urls if item and item.strip()])

    if not urls:
        raise VlessSourceError("No source configured.")

    all_configs: list[ParsedVlessConfig] = []
    total_candidates = 0
    skipped_count = 0
    failed_sources = 0

    for url in urls:
        try:
            text = await download_vless_source(url)
        except Exception as exc:
            failed_sources += 1
            logger.warning("Failed to fetch %s: %s", url, _sanitize_error(str(exc)))
            continue

        parsed = parse_vless_source(text)
        total_candidates += parsed["total_candidates"]
        skipped_count += parsed["skipped_count"]
        all_configs.extend(parsed["valid_configs"])

    if not all_configs and failed_sources == len(urls):
        raise VlessSourceError("All sources failed to download.")

    return "urls", {
        "total_candidates": total_candidates,
        "valid_configs": all_configs,
        "valid_count": len(all_configs),
        "skipped_count": skipped_count,
        "sources": urls,
        "failed_sources": failed_sources,
    }


async def check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    if not host or not port:
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
            "User-Agent: NotaVless/1.1\r\n\r\n"
        )
        writer.write(request.encode("ascii", errors="ignore"))
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return b" 204 " in status_line or status_line.startswith(b"HTTP/1.1 204")
    except Exception:
        return False


async def filter_reachable_configs(configs: list[ParsedVlessConfig]) -> tuple[list[ParsedVlessConfig], int]:
    ok: list[ParsedVlessConfig] = []
    failed = 0
    sem = asyncio.Semaphore(128)
    host_cache: dict[tuple[str, int], bool] = {}

    async def check(cfg: ParsedVlessConfig) -> None:
        nonlocal failed
        key = (cfg.host, cfg.port)
        async with sem:
            if key in host_cache:
                alive = host_cache[key]
            else:
                alive = await check_port(cfg.host, cfg.port)
                host_cache[key] = alive
        if alive:
            ok.append(cfg)
        else:
            failed += 1

    await asyncio.gather(*(check(cfg) for cfg in configs))
    return ok, failed


async def main() -> None:
    source_name, result = await load_source_result()
    deduped = dedupe_configs(result["valid_configs"])

    url_test_ok = await check_url_test(URL_TEST_TARGET)
    if not url_test_ok:
        logger.warning("URL test target is not reachable right now: %s", URL_TEST_TARGET)

    reachable, connect_failed = await filter_reachable_configs(deduped)
    lte_configs, wifi_configs = split_lte_wifi(reachable)

    all_urls = normalize_urls(reachable)
    lte_urls = normalize_urls(lte_configs)
    wifi_urls = normalize_urls(wifi_configs)

    outputs = (
        (REPO_ROOT / VPN_SUBSCRIPTION_OUTPUT, "Nota Vless", all_urls),
        (REPO_ROOT / VPN_SUBSCRIPTION_OUTPUT_LTE, "Nota Vless LTE", lte_urls),
        (REPO_ROOT / VPN_SUBSCRIPTION_OUTPUT_WIFI, "Nota Vless WiFi", wifi_urls),
    )

    changed_paths: list[Path] = []
    for path, title, lines in outputs:
        if write_output_file(lines, path, title):
            changed_paths.append(path)

    changed = bool(changed_paths)
    git_status = push_if_changed(changed_paths)

    msg = (
        "New update:3\n"
        f"> servers amount:{len(all_urls)}\n"
        f"> lte amount:{len(lte_urls)}\n"
        f"> wifi amount:{len(wifi_urls)}\n"
        f"> changed:{str(changed).lower()}"
    )

    logger.info(
        "source=%s total=%s parsed=%s deduped=%s failed_connect=%s url_test=%s changed=%s git=%s",
        source_name,
        result["total_candidates"],
        result["valid_count"],
        len(deduped),
        connect_failed,
        url_test_ok,
        changed,
        git_status,
    )
    await send_notification(msg)


if __name__ == "__main__":
    asyncio.run(main())
