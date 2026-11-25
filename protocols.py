"""
Universal proxy protocol parser and utilities.
Supports VLESS, Trojan, and Hysteria 2 (hy2) configs.
"""

from __future__ import annotations

import asyncio
import base64
import html
import re
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse, urlsplit
from uuid import UUID

VLESS_URL_RE = re.compile(r"vless://[^\s<>'\"`]+", re.IGNORECASE)
TROJAN_URL_RE = re.compile(r"trojan://[^\s<>'\"`]+", re.IGNORECASE)
HYSTERIA2_URL_RE = re.compile(r"(?:hysteria2|hy2)://[^\s<>'\"`]+", re.IGNORECASE)
ANY_PROXY_URL_RE = re.compile(r"(?:vless|trojan|hysteria2|hy2)://[^\s<>'\"`]+", re.IGNORECASE)


class ProxySourceError(Exception):
    """Raised when a remote proxy source cannot be loaded."""


@dataclass(slots=True)
class ParsedConfig:
    protocol: str  # "vless", "trojan", "hysteria2"
    uuid: str  # UUID for VLESS, password/auth for Trojan/Hy2
    host: str
    port: int
    remark: str
    security: str
    network_type: str
    path: str
    host_header: str
    sni: str
    alpn: str
    fingerprint: str
    public_key: str
    short_id: str
    raw_url: str
    flow: str = ""
    added_by: str = ""


# Backward compatibility alias
ParsedVlessConfig = ParsedConfig
VlessSourceError = ProxySourceError


def _first_value(params: dict[str, list[str]], key: str) -> str:
    values = params.get(key)
    return values[0].strip() if values else ""


def decode_maybe_base64(text: str) -> str:
    """Detect and decode Base64 subscriptions if raw proxy links are not immediately found."""
    lower_text = text.lower()
    if any(prefix in lower_text for prefix in ("vless://", "trojan://", "hysteria2://", "hy2://")):
        return text

    cleaned = re.sub(r"[^A-Za-z0-9+/=_-]", "", text.strip())
    if not cleaned or len(cleaned) < 16:
        return text

    for pad in (0, 1, 2, 3):
        padded = cleaned + "=" * pad
        for decode_fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decode_fn(padded.encode("ascii")).decode("utf-8", errors="ignore")
                lower_dec = decoded.lower()
                if any(p in lower_dec for p in ("vless://", "trojan://", "hysteria2://", "hy2://")):
                    return decoded
            except Exception:
                pass
    return text


def sanitize_proxy_url(match_str: str) -> str:
    cleaned = match_str.rstrip(".,);]>\"'*_~\\")
    cleaned = html.unescape(cleaned).replace("&amp;", "&")
    return cleaned


def extract_all_proxy_urls(text: str) -> list[str]:
    text = html.unescape(text or "")
    text = decode_maybe_base64(text)

    urls: list[str] = []
    for match in ANY_PROXY_URL_RE.findall(text):
        cleaned = sanitize_proxy_url(match)
        if cleaned:
            urls.append(cleaned)
    return urls


def parse_vless_url(raw_url: str, added_by: str = "") -> ParsedConfig | None:
    raw_url = raw_url.strip()
    if not raw_url.lower().startswith("vless://"):
        return None

    try:
        parsed = urlparse(raw_url)
        user_id = (parsed.username or "").strip()
        host = (parsed.hostname or "").strip()
        port = parsed.port
        if not user_id or not host or not port:
            return None
        if not (1 <= port <= 65535):
            return None
        if any(bad in host for bad in ("&", "=", "?", "/", " ", "\\", "#", ";")):
            return None
        # Reject Iranian intranet hosts
        if host.lower().endswith(".ir"):
            return None
        # Reject corrupt spam query parameters
        query_lower = parsed.query.lower()
        if any(spam in query_lower for spam in ("---@", "vpsave", "fear_config")):
            return None

        try:
            UUID(user_id)
        except ValueError:
            if len(user_id) < 8:
                return None

        params = parse_qs(parsed.query, keep_blank_values=True)
        sni = _first_value(params, "sni")
        host_header = _first_value(params, "host")
        if not sni and host_header and "." in host_header and not host_header.replace(".", "").isdigit():
            sni = host_header
        elif not sni and "." in host and not host.replace(".", "").isdigit():
            sni = host

        return ParsedConfig(
            protocol="vless",
            uuid=user_id,
            host=host,
            port=port,
            remark=unquote(parsed.fragment or "").strip(),
            security=_first_value(params, "security"),
            network_type=_first_value(params, "type"),
            path=unquote(_first_value(params, "path")),
            host_header=host_header,
            sni=sni,
            alpn=_first_value(params, "alpn"),
            fingerprint=_first_value(params, "fp"),
            public_key=_first_value(params, "pbk"),
            short_id=_first_value(params, "sid"),
            raw_url=raw_url,
            flow=_first_value(params, "flow"),
            added_by=added_by,
        )
    except (ValueError, TypeError):
        return None


def parse_trojan_url(raw_url: str, added_by: str = "") -> ParsedConfig | None:
    raw_url = raw_url.strip()
    if not raw_url.lower().startswith("trojan://"):
        return None

    try:
        parsed = urlparse(raw_url)
        password = unquote((parsed.username or "").strip())
        host = (parsed.hostname or "").strip()
        port = parsed.port
        if not password or not host or not port:
            return None
        if not (1 <= port <= 65535):
            return None
        if any(bad in host for bad in ("&", "=", "?", "/", " ", "\\", "#", ";")):
            return None
        # Reject Iranian intranet hosts
        if host.lower().endswith(".ir"):
            return None
        # Reject corrupt spam query parameters
        query_lower = parsed.query.lower()
        if any(spam in query_lower for spam in ("---@", "vpsave", "fear_config")):
            return None

        params = parse_qs(parsed.query, keep_blank_values=True)
        security = _first_value(params, "security") or "tls"
        network_type = _first_value(params, "type") or "tcp"

        return ParsedConfig(
            protocol="trojan",
            uuid=password,
            host=host,
            port=port,
            remark=unquote(parsed.fragment or "").strip(),
            security=security,
            network_type=network_type,
            path=unquote(_first_value(params, "path")),
            host_header=_first_value(params, "host"),
            sni=_first_value(params, "sni"),
            alpn=_first_value(params, "alpn"),
            fingerprint=_first_value(params, "fp"),
            public_key="",
            short_id="",
            raw_url=raw_url,
            flow=_first_value(params, "flow"),
            added_by=added_by,
        )
    except (ValueError, TypeError):
        return None


def parse_hysteria2_url(raw_url: str, added_by: str = "") -> ParsedConfig | None:
    raw_url = raw_url.strip()
    lower = raw_url.lower()
    if not (lower.startswith("hysteria2://") or lower.startswith("hy2://")):
        return None

    try:
        parsed = urlparse(raw_url)
        auth = (parsed.username or "").strip()
        host = (parsed.hostname or "").strip()
        port = parsed.port
        if not host or not port:
            return None
        if not (1 <= port <= 65535):
            return None
        if any(bad in host for bad in ("&", "=", "?", "/", " ", "\\", "#", ";")):
            return None
        # Reject Iranian intranet hosts
        if host.lower().endswith(".ir"):
            return None
        # Reject corrupt spam query parameters
        query_lower = parsed.query.lower()
        if any(spam in query_lower for spam in ("---@", "vpsave", "fear_config")):
            return None

        params = parse_qs(parsed.query, keep_blank_values=True)
        sni = _first_value(params, "sni")
        alpn = _first_value(params, "alpn")

        return ParsedConfig(
            protocol="hysteria2",
            uuid=auth,
            host=host,
            port=port,
            remark=unquote(parsed.fragment or "").strip(),
            security="tls",
            network_type="udp",
            path="",
            host_header="",
            sni=sni,
            alpn=alpn,
            fingerprint="",
            public_key="",
            short_id="",
            raw_url=raw_url,
            flow="",
            added_by=added_by,
        )
    except (ValueError, TypeError):
        return None


def parse_any_proxy_url(raw_url: str, added_by: str = "") -> ParsedConfig | None:
    raw_lower = raw_url.lower().strip()
    if raw_lower.startswith("vless://"):
        return parse_vless_url(raw_url, added_by=added_by)
    if raw_lower.startswith("trojan://"):
        return parse_trojan_url(raw_url, added_by=added_by)
    if raw_lower.startswith("hysteria2://") or raw_lower.startswith("hy2://"):
        return parse_hysteria2_url(raw_url, added_by=added_by)
    return None


def parse_proxy_source(text: str, added_by: str = "") -> dict[str, Any]:
    candidates = extract_all_proxy_urls(text)
    parsed_configs: list[ParsedConfig] = []
    skipped_count = 0

    for raw_url in candidates:
        parsed = parse_any_proxy_url(raw_url, added_by=added_by)
        if parsed is None:
            skipped_count += 1
            continue
        parsed_configs.append(parsed)

    return {
        "total_candidates": len(candidates),
        "valid_configs": parsed_configs,
        "valid_count": len(parsed_configs),
        "skipped_count": skipped_count,
    }


# Retain backward compatibility helper
def parse_vless_source(text: str) -> dict[str, Any]:
    return parse_proxy_source(text)


def _download_text_sync(url: str, timeout: int = 20) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ProxySourceError("Unsupported URL.")

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "text/plain,text/html,application/json,*/*",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status >= 400:
                raise ProxySourceError(f"HTTP {response.status}")
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset, errors="replace")
    except Exception as exc:
        raise ProxySourceError(str(exc)) from exc


async def download_proxy_source(url: str, timeout: int = 20) -> str:
    return await asyncio.to_thread(_download_text_sync, url, timeout)


# Retain backward compatibility
async def download_vless_source(url: str, timeout: int = 20) -> str:
    return await download_proxy_source(url, timeout)
