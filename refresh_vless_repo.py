"""
Refresh VLESS configs from Telegram channels or a GitHub fallback and push updates to this repo.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from pathlib import Path

from config import (
    GITHUB_VLESS_RAW_URL,
    REPO_ROOT,
    TG_API_HASH,
    TG_API_ID,
    VPN_GIT_COMMIT_MESSAGE,
    VPN_SOURCE_CHANNELS,
    VPN_SUBSCRIPTION_OUTPUT,
)
from tg_account_source import TelegramSourceError, load_vless_from_channels
from vless import VlessSourceError, download_vless_source, parse_vless_source

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


def telegram_source_enabled() -> bool:
    return bool(TG_API_ID and TG_API_HASH and VPN_SOURCE_CHANNELS)


def normalize_urls(result: dict) -> list[str]:
    unique_urls: list[str] = []
    seen_urls: set[str] = set()
    for item in result["valid_configs"]:
        if item.raw_url in seen_urls:
            continue
        seen_urls.add(item.raw_url)
        unique_urls.append(item.raw_url)
    return unique_urls


def write_output_file(lines: list[str], output_path: Path) -> bool:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    new_content = ("\n".join(lines) + "\n") if lines else ""
    old_content = output_path.read_text(encoding="utf-8") if output_path.exists() else None
    if old_content == new_content:
        return False
    output_path.write_text(new_content, encoding="utf-8")
    return True


def run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def push_if_changed(output_path: Path) -> str:
    rel_path = str(output_path.relative_to(REPO_ROOT))
    run_git(["add", rel_path])

    diff_result = run_git(["diff", "--cached", "--quiet"])
    if diff_result.returncode == 0:
        return "skip: no staged changes"

    commit_result = run_git(["commit", "-m", VPN_GIT_COMMIT_MESSAGE])
    if commit_result.returncode != 0:
        return f"commit failed: {commit_result.stderr.strip() or commit_result.stdout.strip()}"

    push_result = run_git(["push"])
    if push_result.returncode != 0:
        return f"push failed: {push_result.stderr.strip() or push_result.stdout.strip()}"

    return "commit and push completed"


async def load_source_result() -> tuple[str, dict]:
    if telegram_source_enabled():
        try:
            return "telegram", await load_vless_from_channels(VPN_SOURCE_CHANNELS)
        except TelegramSourceError as exc:
            logger.warning("Telegram source failed, fallback to GitHub: %s", exc)
            if not GITHUB_VLESS_RAW_URL:
                raise

    if not GITHUB_VLESS_RAW_URL:
        raise VlessSourceError("No source configured.")

    source_text = await download_vless_source(GITHUB_VLESS_RAW_URL)
    return "github", parse_vless_source(source_text)


async def main():
    source_name, result = await load_source_result()
    urls = normalize_urls(result)
    output_path = REPO_ROOT / VPN_SUBSCRIPTION_OUTPUT
    changed = write_output_file(urls, output_path)
    git_status = "skip: file unchanged"

    if changed:
        git_status = push_if_changed(output_path)

    logger.info(
        "refresh complete source=%s total=%s valid=%s skipped=%s changed=%s git=%s output=%s",
        source_name,
        result["total_candidates"],
        result["valid_count"],
        result["skipped_count"],
        changed,
        git_status,
        output_path,
    )


if __name__ == "__main__":
    asyncio.run(main())
