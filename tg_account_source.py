"""
Load VLESS configs from Telegram channels using a Telegram account via Telethon.
"""

from __future__ import annotations

from collections.abc import Iterable

from telethon import TelegramClient
from telethon.sessions import StringSession

from config import (
    TG_API_HASH,
    TG_API_ID,
    TG_SESSION_NAME,
    TG_SESSION_STRING,
    VPN_CHANNEL_MESSAGE_LIMIT,
)
from vless import parse_vless_source


class TelegramSourceError(Exception):
    """Raised when Telegram channel loading fails."""


def _build_client() -> TelegramClient:
    if not TG_API_ID or not TG_API_HASH:
        raise TelegramSourceError("Missing TG_API_ID or TG_API_HASH.")
    session = StringSession(TG_SESSION_STRING) if TG_SESSION_STRING else TG_SESSION_NAME
    return TelegramClient(session, TG_API_ID, TG_API_HASH)


async def load_vless_from_channels(
    channels: Iterable[str],
    message_limit: int | None = None,
) -> dict:
    channel_list = [item.strip() for item in channels if item and item.strip()]
    if not channel_list:
        raise TelegramSourceError("VPN_SOURCE_CHANNELS is empty.")

    limit = message_limit or VPN_CHANNEL_MESSAGE_LIMIT
    parts: list[str] = []
    scanned_messages = 0

    try:
        async with _build_client() as client:
            for channel in channel_list:
                async for msg in client.iter_messages(channel, limit=limit):
                    scanned_messages += 1
                    text = (msg.raw_text or "").strip()
                    if text:
                        parts.append(text)
    except Exception as exc:
        raise TelegramSourceError(str(exc)) from exc

    result = parse_vless_source("\n".join(parts))
    result["source_channels"] = channel_list
    result["scanned_messages"] = scanned_messages
    return result
