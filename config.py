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
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", DEFAULT_BOT_TOKEN).strip()
TG_NOTIFY_TOKEN = os.getenv("TG_NOTIFY_TOKEN", TG_BOT_TOKEN).strip()
TG_NOTIFY_CHANNEL = os.getenv("TG_NOTIFY_CHANNEL", "@notavless").strip()
TG_PROXY_URL = os.getenv("TG_PROXY_URL", "").strip()
TG_API_ENDPOINT = os.getenv("TG_API_ENDPOINT", "https://api.telegram.org").strip().rstrip("/")

# Update schedule settings
UPDATE_INTERVAL_HOURS = int(os.getenv("UPDATE_INTERVAL_HOURS", "2"))
UPDATE_INTERVAL_SECONDS = UPDATE_INTERVAL_HOURS * 3600

# Telegram Userbot settings (optional for private channels)
TG_API_ID = int(os.getenv("TG_API_ID", "0"))
TG_API_HASH = os.getenv("TG_API_HASH", "").strip()
TG_SESSION_NAME = os.getenv("TG_SESSION_NAME", "vpn_userbot").strip()
TG_SESSION_STRING = os.getenv("TG_SESSION_STRING", "").strip()
VPN_SOURCE_CHANNELS = [
    item.strip()
    for item in os.getenv("VPN_SOURCE_CHANNELS", "").split(",")
    if item.strip()
]
VPN_CHANNEL_MESSAGE_LIMIT = int(os.getenv("VPN_CHANNEL_MESSAGE_LIMIT", "50"))

GITHUB_VLESS_RAW_URL = os.getenv("GITHUB_VLESS_RAW_URL", "").strip()
GITHUB_VLESS_RAW_URLS = [
    item.strip()
    for item in os.getenv("GITHUB_VLESS_RAW_URLS", os.getenv("GITHUB_VLESS_RAW_URL", "")).split(",")
    if item.strip()
]
SOURCES_FILE = os.getenv("SOURCES_FILE", str(REPO_ROOT / "sources.txt"))

# Subscription output filenames
# 1. Mega / Universal subscription (WiFi + LTE, all protocols)
MEGA_SUBSCRIPTION_OUTPUT = os.getenv("MEGA_SUBSCRIPTION_OUTPUT", "mega_sub.txt").strip()
MEGA_SUBSCRIPTION_URL = os.getenv(
    "MEGA_SUBSCRIPTION_URL",
    "https://raw.githubusercontent.com/Seregaosm66pon/notavless/main/mega_sub.txt",
).strip()

# 2. VLESS files (All / Legacy / LTE / WiFi)
VPN_SUBSCRIPTION_OUTPUT = os.getenv("VPN_SUBSCRIPTION_OUTPUT", "vlessall.txt").strip()
VPN_SUBSCRIPTION_OUTPUT_LEGACY = os.getenv("VPN_SUBSCRIPTION_OUTPUT_LEGACY", "vless_subscription.txt").strip()
VPN_SUBSCRIPTION_OUTPUT_LTE = os.getenv("VPN_SUBSCRIPTION_OUTPUT_LTE", "vless_lte.txt").strip()
VPN_SUBSCRIPTION_OUTPUT_WIFI = os.getenv("VPN_SUBSCRIPTION_OUTPUT_WIFI", "vless_wifi.txt").strip()

# 3. Protocol specific files
TROJAN_SUBSCRIPTION_OUTPUT = os.getenv("TROJAN_SUBSCRIPTION_OUTPUT", "trojan.txt").strip()
HYSTERIA2_SUBSCRIPTION_OUTPUT = os.getenv("HYSTERIA2_SUBSCRIPTION_OUTPUT", "hysteria2.txt").strip()

# Base64 output toggle
GENERATE_BASE64 = os.getenv("GENERATE_BASE64", "true").lower() in ("true", "1", "yes")

# Health check settings
CHECK_CONCURRENCY = int(os.getenv("CHECK_CONCURRENCY", "64"))
CHECK_TIMEOUT = float(os.getenv("CHECK_TIMEOUT", "2.5"))

VPN_GIT_COMMIT_MESSAGE = os.getenv("VPN_GIT_COMMIT_MESSAGE", "Update VLESS/Trojan/Hy2 subscriptions").strip()
URL_TEST_TARGET = os.getenv("URL_TEST_TARGET", "http://www.gstatic.com/generate_204").strip()
