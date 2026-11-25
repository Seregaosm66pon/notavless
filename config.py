"""
Runtime configuration for the Nota Vless parser/updater.
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

REPO_ROOT = Path(__file__).resolve().parent

if load_dotenv:
    load_dotenv()
    load_dotenv(REPO_ROOT / ".env")

# Telegram Bot Token & Channel for auto updates
DEFAULT_BOT_TOKEN = "8740400260:AAGeOM6eO27VfziUjmYGYeXgCVmQAF6eN-Y"


def _get_str(key: str, default: str = "") -> str:
    val = os.getenv(key)
    if val is None:
        return default
    val = val.strip()
    return val if val else default


def _get_int(key: str, default: int) -> int:
    val = os.getenv(key)
    if val is None:
        return default
    val = val.strip()
    if not val:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _get_float(key: str, default: float) -> float:
    val = os.getenv(key)
    if val is None:
        return default
    val = val.strip()
    if not val:
        return default
    try:
        return float(val)
    except ValueError:
        return default


def _get_bool(key: str, default: bool = True) -> bool:
    val = os.getenv(key)
    if val is None:
        return default
    val = val.strip().lower()
    if not val:
        return default
    return val in ("true", "1", "yes")


TG_BOT_TOKEN = _get_str("TG_BOT_TOKEN", DEFAULT_BOT_TOKEN)
TG_NOTIFY_TOKEN = _get_str("TG_NOTIFY_TOKEN", TG_BOT_TOKEN)
TG_NOTIFY_CHANNEL = _get_str("TG_NOTIFY_CHANNEL", "@notavless")
TG_PROXY_URL = _get_str("TG_PROXY_URL", "")
TG_API_ENDPOINT = _get_str("TG_API_ENDPOINT", "https://api.telegram.org").rstrip("/")

# Update schedule settings
UPDATE_INTERVAL_HOURS = _get_int("UPDATE_INTERVAL_HOURS", 2)
UPDATE_INTERVAL_SECONDS = UPDATE_INTERVAL_HOURS * 3600

# Telegram Userbot settings (optional for private channels)
TG_API_ID = _get_int("TG_API_ID", 0)
TG_API_HASH = _get_str("TG_API_HASH", "")
TG_SESSION_NAME = _get_str("TG_SESSION_NAME", "vpn_userbot")
TG_SESSION_STRING = _get_str("TG_SESSION_STRING", "")
VPN_SOURCE_CHANNELS = [
    item.strip()
    for item in _get_str("VPN_SOURCE_CHANNELS", "").split(",")
    if item.strip()
]
VPN_CHANNEL_MESSAGE_LIMIT = _get_int("VPN_CHANNEL_MESSAGE_LIMIT", 50)

GITHUB_VLESS_RAW_URL = _get_str("GITHUB_VLESS_RAW_URL", "")
_raw_urls_val = _get_str("GITHUB_VLESS_RAW_URLS", "") or GITHUB_VLESS_RAW_URL
GITHUB_VLESS_RAW_URLS = [
    item.strip()
    for item in _raw_urls_val.split(",")
    if item.strip()
]
SOURCES_FILE = _get_str("SOURCES_FILE", str(REPO_ROOT / "sources.txt"))

# Subscription output filenames
# 1. Mega / Universal subscription (WiFi + LTE, all protocols)
MEGA_SUBSCRIPTION_OUTPUT = _get_str("MEGA_SUBSCRIPTION_OUTPUT", "mega_sub.txt")
MEGA_SUBSCRIPTION_URL = _get_str(
    "MEGA_SUBSCRIPTION_URL",
    "https://raw.githubusercontent.com/Seregaosm66pon/notavless/main/mega_sub.txt",
)
MEGA_FASTEST_OUTPUT = _get_str("MEGA_FASTEST_OUTPUT", "mega_sub_fastest.txt")
MEGA_FASTEST_URL = _get_str(
    "MEGA_FASTEST_URL",
    "https://raw.githubusercontent.com/Seregaosm66pon/notavless/main/mega_sub_fastest.txt",
)

# 2. VLESS files (All / Legacy / LTE / WiFi)
VPN_SUBSCRIPTION_OUTPUT = _get_str("VPN_SUBSCRIPTION_OUTPUT", "vlessall.txt")
VPN_SUBSCRIPTION_OUTPUT_LEGACY = _get_str("VPN_SUBSCRIPTION_OUTPUT_LEGACY", "vless_subscription.txt")
VPN_SUBSCRIPTION_OUTPUT_LTE = _get_str("VPN_SUBSCRIPTION_OUTPUT_LTE", "vless_lte.txt")
VPN_SUBSCRIPTION_OUTPUT_WIFI = _get_str("VPN_SUBSCRIPTION_OUTPUT_WIFI", "vless_wifi.txt")

# 3. Protocol specific files
TROJAN_SUBSCRIPTION_OUTPUT = _get_str("TROJAN_SUBSCRIPTION_OUTPUT", "trojan.txt")
HYSTERIA2_SUBSCRIPTION_OUTPUT = _get_str("HYSTERIA2_SUBSCRIPTION_OUTPUT", "hysteria2.txt")

# Base64 output toggle
GENERATE_BASE64 = _get_bool("GENERATE_BASE64", True)

# Health check settings
CHECK_CONCURRENCY = _get_int("CHECK_CONCURRENCY", 64)
CHECK_TIMEOUT = _get_float("CHECK_TIMEOUT", 2.5)

VPN_GIT_COMMIT_MESSAGE = _get_str("VPN_GIT_COMMIT_MESSAGE", "Update VLESS/Trojan/Hy2 subscriptions")
URL_TEST_TARGET = _get_str("URL_TEST_TARGET", "http://www.gstatic.com/generate_204")
