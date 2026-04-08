"""
Обновляет VLESS-конфиги из каналов или GitHub, пингует хосты, пишет файл и пушит в репозиторий.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from pathlib import Path

from datetime import datetime

from config import (
    GITHUB_VLESS_RAW_URL,
    GITHUB_VLESS_RAW_URLS,
    SOURCES_FILE,
    REPO_ROOT,
    TG_API_HASH,
    TG_API_ID,
    VPN_GIT_COMMIT_MESSAGE,
    VPN_SOURCE_CHANNELS,
    VPN_SUBSCRIPTION_OUTPUT,
)
from tg_account_source import TelegramSourceError, load_vless_from_channels
from vless import VlessSourceError, download_vless_source, parse_vless_source

PROFILE_HEADER = (
    "#profile-title: Nota Vless\n"
    "#profile-update-interval: 30\n"
    "#support-url: https://t.me/notavless\n"
    "#announce: Nota Vless - тело в дело!\n"
    "#subscription-userinfo: upload=0; download=0; total=0; expire=0\n"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


def telegram_source_enabled() -> bool:
    return bool(TG_API_ID and TG_API_HASH and VPN_SOURCE_CHANNELS)


def normalize_urls(result: dict) -> list[str]:
    seen = set()
    urls = []
    for cfg in result["valid_configs"]:
        if cfg.raw_url in seen:
            continue
        seen.add(cfg.raw_url)
        urls.append(cfg.raw_url)
    return urls


def write_output_file(lines: list[str], output_path: Path) -> bool:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    header = PROFILE_HEADER
    generated = f"#generated-at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    body = "\n".join(lines)
    new_content = header + "\n" + generated + ("\n" + body + "\n" if body else "\n")
    old_content = output_path.read_text(encoding="utf-8") if output_path.exists() else None
    if old_content == new_content:
        return False
    output_path.write_text(new_content, encoding="utf-8")
    return True


def run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False)


def push_if_changed(output_path: Path) -> str:
    rel_path = str(output_path.relative_to(REPO_ROOT))
    run_git(["add", rel_path])
    if run_git(["diff", "--cached", "--quiet"]).returncode == 0:
        return "skip: no staged changes"
    commit_result = run_git(["commit", "-m", VPN_GIT_COMMIT_MESSAGE])
    if commit_result.returncode != 0:
        return f"commit failed: {commit_result.stderr.strip() or commit_result.stdout.strip()}"
    push_result = run_git(["push"])
    if push_result.returncode != 0:
        return f"push failed: {push_result.stderr.strip() or push_result.stdout.strip()}"
    return "commit and push completed"


async def load_source_result() -> tuple[str, dict]:
    urls: list[str] = []
    if SOURCES_FILE and Path(SOURCES_FILE).exists():
        urls.extend([u.strip() for u in Path(SOURCES_FILE).read_text(encoding="utf-8").splitlines() if u.strip()])

    if telegram_source_enabled():
        try:
            return "telegram", await load_vless_from_channels(VPN_SOURCE_CHANNELS)
        except TelegramSourceError as exc:
            logger.warning("Не удалось загрузить из каналов, fallback на GitHub: %s", exc)

    env_urls = GITHUB_VLESS_RAW_URLS or ([GITHUB_VLESS_RAW_URL] if GITHUB_VLESS_RAW_URL else [])
    urls.extend(env_urls)
    urls = [u for u in urls if u]
    if not urls:
        raise VlessSourceError("No source configured.")

    texts, failed = [], 0
    for url in urls:
        try:
            texts.append(await download_vless_source(url))
        except Exception as exc:
            failed += 1
            logger.warning("Failed to fetch %s: %s", url, exc)
    if not texts:
        raise VlessSourceError("All sources failed to download")

    combined = "\n".join(texts)
    parsed = parse_vless_source(combined)
    parsed["sources"] = urls
    parsed["failed_sources"] = failed
    return "github", parsed


async def ping_host(host: str, timeout_ms: int = 800) -> bool:
    if not host:
        return False
    proc = await asyncio.create_subprocess_exec(
        "ping", "-n", "1", "-w", str(timeout_ms), host,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        await asyncio.wait_for(proc.communicate(), timeout=timeout_ms / 1000 + 1)
    except asyncio.TimeoutError:
        proc.kill()
        return False
    return proc.returncode == 0


async def filter_by_ping(configs: list) -> tuple[list, int]:
    ok, failed = [], 0
    sem = asyncio.Semaphore(64)

    async def check(cfg):
        nonlocal failed
        async with sem:
            if await ping_host(cfg.host):
                ok.append(cfg)
            else:
                failed += 1

    await asyncio.gather(*(check(cfg) for cfg in configs))
    return ok, failed


async def main():
    source_name, result = await load_source_result()
    ok_configs, ping_failed = await filter_by_ping(result["valid_configs"])
    result["valid_configs"] = ok_configs
    result["valid_count"] = len(ok_configs)
    result["ping_failed"] = ping_failed

    urls = normalize_urls(result)
    output_path = REPO_ROOT / VPN_SUBSCRIPTION_OUTPUT
    changed = write_output_file(urls, output_path)
    git_status = "skip: file unchanged"
    if changed:
        git_status = push_if_changed(output_path)

    logger.info(
        "refresh complete source=%s total=%s valid=%s skipped=%s ping_failed=%s changed=%s git=%s output=%s",
        source_name,
        result["total_candidates"],
        result["valid_count"],
        result["skipped_count"],
        result.get("ping_failed", 0),
        changed,
        git_status,
        output_path,
    )


if __name__ == "__main__":
    asyncio.run(main())
