"""
Utilities for extracting and parsing VLESS configs.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen
from uuid import UUID

VLESS_URL_RE = re.compile(r"vless://[^\s<>'\"`]+", re.IGNORECASE)


class VlessSourceError(Exception):
    """Raised when a remote VLESS source cannot be loaded."""


@dataclass(slots=True)
class ParsedVlessConfig:
    uuid: str
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


def _first_value(params: dict[str, list[str]], key: str) -> str:
    values = params.get(key)
    return values[0].strip() if values else ""


def extract_vless_urls(text: str) -> list[str]:
    urls: list[str] = []
    for match in VLESS_URL_RE.findall(text or ""):
        cleaned = match.rstrip(".,);]")
        if cleaned:
            urls.append(cleaned)
    return urls


def parse_vless_url(raw_url: str) -> ParsedVlessConfig | None:
    raw_url = raw_url.strip()
    if not raw_url.lower().startswith("vless://"):
        return None

    try:
        parsed = urlparse(raw_url)
        user_id = parsed.username or ""
        host = parsed.hostname or ""
        port = parsed.port
        if not user_id or not host or not port:
            return None

        UUID(user_id)
        params = parse_qs(parsed.query, keep_blank_values=True)
        return ParsedVlessConfig(
            uuid=user_id,
            host=host,
            port=port,
            remark=unquote(parsed.fragment or "").strip(),
            security=_first_value(params, "security"),
            network_type=_first_value(params, "type"),
            path=unquote(_first_value(params, "path")),
            host_header=_first_value(params, "host"),
            sni=_first_value(params, "sni"),
            alpn=_first_value(params, "alpn"),
            fingerprint=_first_value(params, "fp"),
            public_key=_first_value(params, "pbk"),
            short_id=_first_value(params, "sid"),
            raw_url=raw_url,
        )
    except (ValueError, TypeError):
        return None


def parse_vless_source(text: str) -> dict[str, Any]:
    candidates = extract_vless_urls(text)
    parsed_configs: list[ParsedVlessConfig] = []
    skipped_count = 0

    for raw_url in candidates:
        parsed = parse_vless_url(raw_url)
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


def _download_text_sync(url: str, timeout: int = 20) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; VlessRepoUpdater/1.0)",
            "Accept": "text/plain,*/*",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset, errors="replace")
    except HTTPError as exc:
        raise VlessSourceError(f"HTTP {exc.code}") from exc
    except URLError as exc:
        raise VlessSourceError(str(exc.reason)) from exc
    except OSError as exc:
        raise VlessSourceError(str(exc)) from exc


async def download_vless_source(url: str, timeout: int = 20) -> str:
    return await asyncio.to_thread(_download_text_sync, url, timeout)
