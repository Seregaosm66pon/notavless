"""
Universal proxy protocol parser and utilities.
Supports VLESS, Trojan, and Hysteria 2 (hy2) configs.
"""

from __future__ import annotations

import asyncio
import base64
import html
import ipaddress
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

_REJECTED_HOST_SUFFIXES = (".ir", ".kp", ".local", ".internal", ".localhost", ".arpa")
_REJECTED_EXACT_HOSTS = {"localhost", "localhost.localdomain"}
_PUBLIC_RESOLVER_HOSTS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}
_DUMMY_PASSWORDS = {"password", "password123", "123456", "12345678", "admin", "test", "changeme", "pass"}
_SPAM_QUERY_TOKENS = ("---@", "vpsave", "fear_config", "telegram---")
_VALID_NETWORK_TYPES = {"", "tcp", "raw", "ws", "grpc", "xhttp", "splithttp", "httpupgrade", "h2", "http"}
_BOGON_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)


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
    service_name: str = ""
    mode: str = ""
    extra: str = ""
    allow_insecure: bool = False
    pin_sha256: str = ""
    obfs: str = ""
    obfs_password: str = ""
    header_type: str = ""


# Backward compatibility alias
ParsedVlessConfig = ParsedConfig
VlessSourceError = ProxySourceError


def _first_value(params: dict[str, list[str]], key: str) -> str:
    values = params.get(key)
    return values[0].strip() if values else ""


def _is_ip_literal(value: str) -> bool:
    if not value:
        return False
    cleaned = value.strip("[]")
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False


def _is_invalid_host(host: str) -> bool:
    if not host:
        return True
    if any(bad in host for bad in ("&", "=", "?", "/", " ", "\\", "#", ";", ",")):
        return True
    lower = host.lower().strip("[]")
    if lower in _REJECTED_EXACT_HOSTS or any(lower.endswith(sfx) for sfx in _REJECTED_HOST_SUFFIXES):
        return True
    try:
        ip_obj = ipaddress.ip_address(lower)
        return any(ip_obj in net for net in _BOGON_NETWORKS)
    except ValueError:
        if "." not in lower or lower.startswith(".") or lower.endswith(".") or ".." in lower:
            return True
    return False


def _is_dummy_public_resolver(host: str, auth: str) -> bool:
    return host.strip("[]") in _PUBLIC_RESOLVER_HOSTS and auth.strip().lower() in _DUMMY_PASSWORDS


def _has_spam_query(query: str) -> bool:
    q = (query or "").lower()
    return any(spam in q for spam in _SPAM_QUERY_TOKENS)


def _has_rejected_suffix(value: str) -> bool:
    lower = (value or "").strip().lower().strip("[]")
    return bool(lower) and (
        lower in _REJECTED_EXACT_HOSTS or any(lower.endswith(sfx) for sfx in _REJECTED_HOST_SUFFIXES)
    )


def _resolve_sni(host: str, host_header: str, sni: str) -> str:
    if sni:
        return sni
    if (
        host_header
        and not host_header.startswith("/")
        and "." in host_header
        and not _is_ip_literal(host_header)
    ):
        return host_header
    if "." in host and not _is_ip_literal(host):
        return host
    return ""


def _is_truthy_param(params: dict[str, list[str]], *keys: str) -> bool:
    for k in keys:
        val = _first_value(params, k).lower()
        if val in ("1", "true", "yes"):
            return True
    return False


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
    raw_text = html.unescape(text or "")
    dec = _get_sub_decrypter()

    # Expand encrypted client keys (happ://crypt*, incy://crypt*, v2raytun://import*) if embedded
    if dec is not None:
        key_links = dec.find_key_links(raw_text)
        if key_links:
            expanded_chunks = [raw_text]
            for klink in key_links[:8]:
                try:
                    kind, val = dec.resolve_key(klink)
                    if kind == "text" and val:
                        expanded_chunks.append(val)
                    elif kind == "url" and val.lower().startswith(("http://", "https://")):
                        try:
                            expanded_chunks.append(_download_text_sync(val, timeout=6, retries=0))
                        except Exception:
                            pass
                except Exception:
                    continue
            raw_text = "\n".join(expanded_chunks)

    decoded = decode_maybe_base64(raw_text)
    urls: list[str] = []
    seen_order: set[str] = set()

    for match in ANY_PROXY_URL_RE.findall(decoded):
        cleaned = sanitize_proxy_url(match)
        if cleaned and cleaned not in seen_order:
            seen_order.add(cleaned)
            urls.append(cleaned)

    # Fallback: extract from Clash YAML / Sing-Box JSON / Xray JSON / nested Base64 via Sub-Decrypter
    lower_raw = raw_text.lower()
    if dec is not None and (
        not urls
        or "proxies:" in lower_raw
        or '"outbounds"' in lower_raw
        or '"outbound"' in lower_raw
    ):
        try:
            extra_links = dec.extract_from_content(raw_text)
            for link in extra_links:
                cleaned = sanitize_proxy_url(link)
                if cleaned and cleaned not in seen_order:
                    seen_order.add(cleaned)
                    urls.append(cleaned)
        except Exception:
            pass

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
        if _is_invalid_host(host) or _is_dummy_public_resolver(host, user_id):
            return None
        if _has_spam_query(parsed.query):
            return None

        try:
            UUID(user_id)
        except ValueError:
            if len(user_id) < 8:
                return None

        params = parse_qs(parsed.query, keep_blank_values=True)
        security = _first_value(params, "security").lower()
        public_key = _first_value(params, "pbk")
        if security == "reality" and not public_key:
            return None

        network_type = _first_value(params, "type").lower()
        if network_type not in _VALID_NETWORK_TYPES:
            return None
        sni = _resolve_sni(host, _first_value(params, "host"), _first_value(params, "sni"))
        host_header = _first_value(params, "host")
        if _has_rejected_suffix(sni) or _has_rejected_suffix(host_header):
            return None

        service_name = unquote(_first_value(params, "serviceName") or _first_value(params, "servicename"))
        path = unquote(_first_value(params, "path"))
        if network_type == "grpc" and not path and service_name:
            path = service_name

        return ParsedConfig(
            protocol="vless",
            uuid=user_id,
            host=host,
            port=port,
            remark=unquote(parsed.fragment or "").strip(),
            security=security,
            network_type=network_type,
            path=path,
            host_header=host_header,
            sni=sni,
            alpn=_first_value(params, "alpn"),
            fingerprint=_first_value(params, "fp"),
            public_key=public_key,
            short_id=_first_value(params, "sid"),
            raw_url=raw_url,
            flow=_first_value(params, "flow"),
            added_by=added_by,
            service_name=service_name,
            mode=_first_value(params, "mode").lower(),
            extra=unquote(_first_value(params, "extra")),
            allow_insecure=_is_truthy_param(params, "allowInsecure", "insecure"),
            pin_sha256=_first_value(params, "pcs") or _first_value(params, "pinSHA256"),
            header_type=_first_value(params, "headerType"),
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
        if _is_invalid_host(host) or _is_dummy_public_resolver(host, password):
            return None
        if _has_spam_query(parsed.query):
            return None

        params = parse_qs(parsed.query, keep_blank_values=True)
        security = (_first_value(params, "security") or "tls").lower()
        network_type = (_first_value(params, "type") or "tcp").lower()
        if network_type not in _VALID_NETWORK_TYPES:
            return None
        host_header = _first_value(params, "host")
        sni = _resolve_sni(host, host_header, _first_value(params, "sni"))
        if _has_rejected_suffix(sni) or _has_rejected_suffix(host_header):
            return None

        service_name = unquote(_first_value(params, "serviceName") or _first_value(params, "servicename"))
        path = unquote(_first_value(params, "path"))
        if network_type == "grpc" and not path and service_name:
            path = service_name

        return ParsedConfig(
            protocol="trojan",
            uuid=password,
            host=host,
            port=port,
            remark=unquote(parsed.fragment or "").strip(),
            security=security,
            network_type=network_type,
            path=path,
            host_header=host_header,
            sni=sni,
            alpn=_first_value(params, "alpn"),
            fingerprint=_first_value(params, "fp"),
            public_key="",
            short_id="",
            raw_url=raw_url,
            flow=_first_value(params, "flow"),
            added_by=added_by,
            service_name=service_name,
            mode=_first_value(params, "mode").lower(),
            allow_insecure=_is_truthy_param(params, "allowInsecure", "insecure"),
            pin_sha256=_first_value(params, "pcs") or _first_value(params, "pinSHA256"),
            header_type=_first_value(params, "headerType"),
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
        auth = unquote((parsed.username or "").strip())
        host = (parsed.hostname or "").strip()
        port = parsed.port
        if not host or not port:
            return None
        if not (1 <= port <= 65535):
            return None
        if _is_invalid_host(host) or _is_dummy_public_resolver(host, auth):
            return None
        if _has_spam_query(parsed.query):
            return None

        params = parse_qs(parsed.query, keep_blank_values=True)
        sni = _resolve_sni(host, "", _first_value(params, "sni"))
        if _has_rejected_suffix(sni):
            return None
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
            allow_insecure=_is_truthy_param(params, "insecure", "allowInsecure"),
            pin_sha256=_first_value(params, "pinSHA256") or _first_value(params, "pcs"),
            obfs=_first_value(params, "obfs").lower(),
            obfs_password=unquote(_first_value(params, "obfs-password")),
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


_SUB_DECRYPTER_CACHE: Any = None
_SUB_DECRYPTER_INIT_TRIED = False


def _get_sub_decrypter() -> Any:
    """Lazy-load RKP Sub-Decrypter in silent in-memory mode (no disk side effects)."""
    global _SUB_DECRYPTER_CACHE, _SUB_DECRYPTER_INIT_TRIED
    if _SUB_DECRYPTER_INIT_TRIED:
        return _SUB_DECRYPTER_CACHE
    _SUB_DECRYPTER_INIT_TRIED = True
    try:
        import sub_decrypter

        sub_decrypter.SETTINGS["verbose"] = False
        sub_decrypter.SETTINGS["strip_config_names"] = False
        sub_decrypter.SETTINGS["parse_html"] = False
        sub_decrypter.SETTINGS["retries"] = 0
        sub_decrypter.SETTINGS["timeout"] = 6
        if not sub_decrypter.DEVICE.get("hwid"):
            sub_decrypter.DEVICE.update(sub_decrypter.generate_device())
        _SUB_DECRYPTER_CACHE = sub_decrypter
    except Exception:
        _SUB_DECRYPTER_CACHE = None
    return _SUB_DECRYPTER_CACHE


def is_encrypted_sub_or_wrapper(target: str) -> bool:
    """Return True if target is an encrypted/wrapped client link (happ://, incy://, v2raytun://, sub://) or HTTP URL."""
    t = (target or "").strip().lower()
    return t.startswith(
        (
            "happ://",
            "incy://",
            "v2raytun://",
            "sub://",
            "clash://",
            "v2box://",
            "streisand://",
            "hiddify://",
            "http://",
            "https://",
        )
    )


def decrypt_or_extract_target(target_or_text: str, timeout: int = 8) -> tuple[list[str], str, str]:
    """
    Decrypt happ://crypt*, incy://crypt*, v2raytun://import*, unwrap client links/HTTP subs,
    and extract raw proxy links (VLESS, Trojan, Hysteria 2) with full remark preservation.
    Returns: (proxy_urls, resolved_source, error_msg)
    """
    raw = (target_or_text or "").strip()
    if not raw:
        return [], "", "Empty input"

    dec = _get_sub_decrypter()
    resolved_source = raw
    content = raw

    if dec is not None:
        try:
            klinks = dec.find_key_links(raw)
            if klinks:
                kind, val = dec.resolve_key(klinks[0])
                resolved_source = val
                if kind == "text":
                    content = val
                elif kind == "url" and val.lower().startswith(("http://", "https://")):
                    content = _download_text_sync(val, timeout=timeout, retries=1)
                else:
                    content = val
            else:
                unwrapped = dec.unwrap_client_add(raw)
                target_url = unwrapped or raw
                if target_url.lower().startswith(("http://", "https://")):
                    resolved_source = target_url
                    content = _download_text_sync(target_url, timeout=timeout, retries=1)
        except Exception as exc:
            return [], resolved_source, str(exc)
    elif raw.lower().startswith(("http://", "https://")):
        try:
            content = _download_text_sync(raw, timeout=timeout, retries=1)
        except Exception as exc:
            return [], resolved_source, str(exc)

    urls = extract_all_proxy_urls(content)
    if not urls:
        return [], resolved_source, "No supported configs (vless/trojan/hy2) found"
    return urls, resolved_source, ""


def _download_text_sync(url: str, timeout: int = 20, retries: int = 2) -> str:
    import time
    import urllib.error

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ProxySourceError("Unsupported URL.")

    dec = _get_sub_decrypter()
    hdrs = {
        "User-Agent": (
            dec.happ_user_agent()
            if dec is not None
            else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        ),
        "Accept": "text/plain,text/html,application/json,*/*",
    }
    if dec is not None:
        hdrs.update(dec.device_headers())

    max_bytes = 3 * 1024 * 1024
    last_exc: Exception | None = None
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        use_headers = hdrs if attempt == 0 else {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "*/*",
        }
        req = urllib.request.Request(url, headers=use_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status >= 400:
                    raise ProxySourceError(f"HTTP {response.status}")
                charset = response.headers.get_content_charset() or "utf-8"
                return response.read(max_bytes).decode(charset, errors="replace")
        except urllib.error.HTTPError as exc:
            last_exc = exc
            if exc.code in (403, 418) and attempt + 1 < attempts:
                continue
            if 400 <= exc.code < 500 and exc.code != 429:
                break
        except Exception as exc:
            last_exc = exc
        if attempt + 1 < attempts:
            time.sleep(0.35 * (attempt + 1))
    raise ProxySourceError(str(last_exc or "Download failed")) from last_exc


async def download_proxy_source(url: str, timeout: int = 20, retries: int = 2) -> str:
    return await asyncio.to_thread(_download_text_sync, url, timeout, retries)


# Retain backward compatibility
async def download_vless_source(url: str, timeout: int = 20) -> str:
    return await download_proxy_source(url, timeout)
