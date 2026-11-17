"""
VLESS parser and backward-compatibility wrapper.
Imports modern multi-protocol parser from protocols.py.
"""

from __future__ import annotations

from protocols import (
    ANY_PROXY_URL_RE,
    HYSTERIA2_URL_RE,
    TROJAN_URL_RE,
    VLESS_URL_RE,
    ParsedConfig,
    ParsedVlessConfig,
    ProxySourceError,
    VlessSourceError,
    decode_maybe_base64,
    download_proxy_source,
    download_vless_source,
    extract_all_proxy_urls,
    parse_any_proxy_url,
    parse_hysteria2_url,
    parse_proxy_source,
    parse_trojan_url,
    parse_vless_source,
    parse_vless_url,
    sanitize_proxy_url,
)

__all__ = [
    "ANY_PROXY_URL_RE",
    "HYSTERIA2_URL_RE",
    "TROJAN_URL_RE",
    "VLESS_URL_RE",
    "ParsedConfig",
    "ParsedVlessConfig",
    "ProxySourceError",
    "VlessSourceError",
    "decode_maybe_base64",
    "download_proxy_source",
    "download_vless_source",
    "extract_all_proxy_urls",
    "parse_any_proxy_url",
    "parse_hysteria2_url",
    "parse_proxy_source",
    "parse_trojan_url",
    "parse_vless_source",
    "parse_vless_url",
    "sanitize_proxy_url",
]
