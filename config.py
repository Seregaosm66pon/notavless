"""
Runtime configuration for the VLESS parser/updater.
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
VPN_SUBSCRIPTION_OUTPUT = os.getenv("VPN_SUBSCRIPTION_OUTPUT", "vless_subscription.txt").strip()
VPN_SUBSCRIPTION_OUTPUT_LTE = os.getenv("VPN_SUBSCRIPTION_OUTPUT_LTE", "vless_lte.txt").strip()
VPN_SUBSCRIPTION_OUTPUT_WIFI = os.getenv("VPN_SUBSCRIPTION_OUTPUT_WIFI", "vless_wifi.txt").strip()
VPN_GIT_COMMIT_MESSAGE = os.getenv("VPN_GIT_COMMIT_MESSAGE", "Update VLESS subscription").strip()
URL_TEST_TARGET = os.getenv("URL_TEST_TARGET", "http://www.gstatic.com/generate_204").strip()
TG_NOTIFY_TOKEN = os.getenv("TG_NOTIFY_TOKEN", "").strip()
TG_NOTIFY_CHANNEL = os.getenv("TG_NOTIFY_CHANNEL", "").strip()
