#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNIVERSAL VPN PARSER — один файл для Windows / Linux / Android (Termux).

ЧТО УМЕЕТ
  1. Расшифровывать ключи-clients в ссылку-подписку:
       happ://crypt/… , happ://crypt2/… … happ://crypt5/…   (RSA, в т.ч. crypt5 AEAD)
       incy://cryptN/…                                      (AES-256-GCM)
       v2raytun://import/…                                  (base64 / urlencoded / вложенные)
     Ключи RSA/AES ВСТРОЕНЫ в этот файл (см. EMBEDDED_KEYS) — внешние файлы не нужны.
     Поддерживаются вложенные ключи (ключ внутри ключа), ключи в URL-кодировке,
     невидимые символы Telegram и обрывки пунктуации.
  2. Скачивать подписки как Happ: X-HWID + X-Device-* + ?hwid=…, со своим HWID
     или со сгенерированным (сохраняется в device.json РЯДОМ со скриптом).
     Есть запасной браузерный User-Agent, Retry-After для 429, повторы при обрыве.
  3. Разворачивать ЛЮБЫЕ редиректы:
       http(s) → http(s);
       http(s) → happ://add/…, incy://import/…, clash://install-config?url=…,
                  v2box://install-sub?url=…, sub://<base64> и др. обёртки;
       http(s) → ключ клиента (расшифровывается);
       HTML-страницы-редиректоры: meta refresh, JS location, atob(), href-кандидаты.
  4. Извлекать конфиги из ответа всеми способами:
       plain vless/vmess/trojan/ss/shadowsocks/hysteria2/hy2/tuic/socks;
       Base64 любой вложенности; URL-encoded;
       JSON Xray/V2Ray, sing-box, Clash JSON; YAML Clash (с PyYAML или без);
       HTML-страницы; склеенные конфиги; сохранение комментариев после #.
  5. Сохранять результат в <домен>.txt РЯДОМ со скриптом (не в папки устройства).
     Повторные запуски дописывают только новые конфиги.

ЗАПУСК
    python universal_vpn_parser.py              # меню
    python universal_vpn_parser.py "ссылка"     # обработать одну ссылку/ключ
    python universal_vpn_parser.py -b links.txt # пакетный режим (по строке)
    python universal_vpn_parser.py "ключ" --no-menu

ЗАВИСИМОСТИ
    Python 3.8+; для crypt/incy нужна cryptography:
      Windows/Linux:  pip install cryptography
      Termux:         pkg install python && pip install cryptography
    Без cryptography работают v2raytun, загрузка и извлечение конфигов.
    PyYAML не обязателен (если есть — YAML Clash parses точнее).

ФАЙЛЫ РЯДОМ СО СКРИПТОМ
    device.json   — ваш/сгенерированный X-HWID и параметры устройства
    settings.json — настройки из меню
    <домен>.txt   — извлечённые конфиги
    keys/*.json   — НЕОБЯЗАТЕЛЬНО: свежие ключи, если встроенные устареют
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import html as html_mod
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    CRYPTO_OK = True
except Exception:                      # cryptography не установлена
    CRYPTO_OK = False

# ============================================================================
# 0. ПУТИ И КОНСОЛЬ
# ============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEVICE_FILE = os.path.join(BASE_DIR, "device.json")
SETTINGS_FILE = os.path.join(BASE_DIR, "settings.json")
KEYS_DIR = os.path.join(BASE_DIR, "keys")
VERSION = "1.0"

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass

# Встроенные ключи: заполняется при сборке (zlib + base64 от JSON-файлов).
EMBEDDED_KEYS: Dict[str, str] = {
    "happcrypt.json": (
        "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"
    ),
    "happcrypt5.json": (
        "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"
        "l9ZawD2Swvmh5EdlyF+KqmvDe4aIkzm12vyjT4b+MWrcp3vaOAB2igSj934enpG21+tIvafv8Ybttb4kQiK/xX4/fAKBy7+V"
        "iGQDVZRgubUfS9Y4JIie18/+I0E7uRIb6yNEi6TZ3DtInfvWKAij4+1YJMHvNW17xw/YPjtC2V3u/m91aifd1BqJPZkR8+rC"
        "fj67+LcEHv37obF2EvJfU5Iu8bmU8ZJIeZuxN4ZYjzhEmnekOGgc5NOX5THGiREjl3jGKncqLFdakF8fb36cAovp/j5yZZSh"
        "jzy4wub2/RxyvrnLLKQsTr5YfJZQvoCE0hxe59vpNZwYjDYfI5fdDoJyM+3V+iRXds/N9PJ5x22bPtoVZZDNSj+jQFMjamP3"
        "9rq5dMNhbZ4qcyOPL4ybJ1gEjWYiYbeEBdBBompGIp95RQUAD05BAtPIwnlyrQO/2l22hT2VCUgXTK1/gPHruyhtUFA+mc8c"
        "FEPnMQmhqZK5jcfbiqrv/TGdJBG5jsv/vXFIp90aHeyKIhrk2CfRJh5LqKYypPfkEiK7JErXpXmIWp61u14O4uyxjptQcKz8"
        "GK1gDKidLnwPzt17FgXe2iWebnthEVrmJizavSKDTnp76wOFm9B39pv9eM5WpF23Md6wWdmOs/yS5ervIBok5ydAqn/FVpwn"
        "x0jTD/a1069qmvvluN0ZIU+RoV/AVq5NO6QZC43QixuRGZhqlwooQw0VuhIv8l63Un29HAnJn6uWWL+71zfp3OcxeMbEjhSo"
        "keCpjj7GixuZpBBfzGRRHUQdpfP0OT7lJ/k9SzYS5VWNJXdwAgkCZ6GcYWpVm+WKPgov16VmIeqWWTjbKMoWW3ZQsa1DJXtA"
        "JRsqP1ZUs/Xy89cz9ixpC5nFGb69dfz+Cv42VVKuXZRafrUHfwykaYc3ncVZaFO7UK/5l2oFiic3xUoLTN1TJGLZAjCjnfnX"
        "wxqMNNNcC10IuhvzPibq/vYS3LyJR//90Y0yli5QBnufimgkCqBUkyjrDSx06YBekmoed9V1fuJodxR5dL3ccDqYzcStxfbt"
        "zmCxvtQZ7wiqPVU/Sh9P4VCAOTuuNVrQxfWzklDpCDy/pmKq3kKW1w/4Z0zjabSRZ373fYctxcXvUKS/tnUXUBiEMgg4hfrn"
        "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"
    ),
    "incy.json": (
        "eNplusfuNdtyHzbnU3y4IxJNsnOiIQOddqfdeXc0BKJz2p1zCwIoynIABXPikQHP/ADXtAlTIs1nOOcV/CTuc3hJEdTgH3ql"
        "qrVWrQq/qn/zez9+/OZP5zzOuvw3f/Ljv3s+n4af/ref/vbn/+Xn//Gnv/nx85/99Nuf/93P/9NPf/Pzf//8//c//dVP//lp"
        "rvv0+hMQTOdrXPU/egb8u5//4qe/fbr/84/ffwb87U9/89Nf//T//vznP2SdC//gj3/zh79b+P/46e+fVf7uWfPP/+THklZ5"
        "ly8//ui//fGM/7uf//LHs8x/eCb+3c9/8WvjL8v8nz/9/Y+f/q9n2p//Qvyh8p9+tPn14/eTeMkJ7A9/oMiPZ8xvf/pPz4Df"
        "/sEf/hOlf5z7DO7i9U9j8Hf/JP849Q9+AA+9h5e//vl//oXZZ4d/+TQt8Xf90zGe1+UPf+Hq//nxbOdX4j//2c9/8fN/+Kf1"
        "f2Hlrx6W/u9n3p8/fP/lLwN/PbUfjsT8EYIT/80vtP+0qPsyn8e57tcf/9+f/a+/LvfLyfx6mH/783/88fP/8FB/ju5Z488f"
        "Lv7h79/8lyP733899N/+s9P56bc/fv+X6b/s+Jn9N/+M9nMEPx6W/v7XI/mrp+0vn+39A3sP/3/5a9ff/eGPX2n89pcd/fTX"
        "Px6if/3j53//9P32lwnP8P/4x795iP/rXzj4ze8u6RGOf/MPDP165/A/ff8y5J+O7J9E6Nf2X4Tkd9v49TvL8/Gff/9upX/W"
        "siMQQvwxRPzmd03/+h/7fvOP1/inQ1Es+foQgiEE+5fdyX/pRiCM+pfd37x/elDkv1r1af1Nb1VF/i5U/qWpbm5aZv7KU8UE"
        "UFrfVpTtabhm7Y2pMt1iwhY6xGOAvXDkl55RYrSS59DVuZbxMtGHi5Du1Vo83hKFMi+jBlgVZtUqUkxPFpmI0wLt25iD2l/C"
        "Wi2QIw92UUWfM6/wddoRH9I/ySD3OKPcOlxnR4G/TNYNBv+GDQV0cRolv5sFUgf3uk343nOn2zLIkKN5qszlLJasjSyYKAbN"
        "jVIgjaHA93S0QRDG3ZCSqYK6PRonYDGwuTWhiMy4H1tHVufjs5hbj9fE8uouhjOVM8pPB80vxgph9ygD/EJfb99Te5QJDHG2"
        "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"
        "pRCV/kNZ7r/9vV9+/u3v/f8Rp8sG"
    ),
}


def say(text: str = "", *, important: bool = False) -> None:
    """Вывод с учётом настройки verbose (важное печатается всегда)."""
    if important or SETTINGS.get("verbose", True):
        print(text, flush=True)


def warn(text: str) -> None:
    print("[!] " + text, flush=True)


def atomic_write(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ============================================================================
# 1. НАСТРОЙКИ И УСТРОЙСТВО (всё рядом со скриптом)
# ============================================================================

DEFAULT_SETTINGS: Dict[str, Any] = {
    "timeout": 25,                 # таймаут одного HTTP-запроса, сек
    "retries": 2,                  # сколько раз пробовать один и тот же URL
    "max_redirects": 10,           # предел цепочки редиректов/обёрток
    "verify_ssl": True,            # проверять SSL-сертификаты
    "browser_fallback": True,      # пробовать браузерный UA при 403/418/500/503
    "hwid_param": True,            # добавлять ?hwid=… к ссылке
    "base64_levels": 5,            # глубина разворота base64
    "parse_json": True,
    "parse_yaml": True,
    "parse_html": True,
    "strip_config_names": True,    # убрать '#имя' (как в PHS.py)
    "dedupe": True,
    "normalize_schemes": True,     # shadowsocks→ss, hy2/hysteria→hysteria2
    "overwrite_files": False,      # false = дописывать новые конфиги в файл
    "max_response_mb": 32,
    "key_depth": 4,                # вложенность ключ-в-ключе
    "only_protocols": "",          # напр. "vless,ss"; пусто = все
    "verbose": True,
}

SETTINGS: Dict[str, Any] = dict(DEFAULT_SETTINGS)


def load_settings() -> None:
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for key, default in DEFAULT_SETTINGS.items():
                if key not in data:
                    continue
                value = data[key]
                try:
                    if isinstance(default, bool):
                        SETTINGS[key] = str(value).strip().lower() in (
                            "1", "true", "yes", "on", "да", "д", "вкл"
                        ) if not isinstance(value, bool) else value
                    elif isinstance(default, int):
                        SETTINGS[key] = int(value)
                    else:
                        SETTINGS[key] = str(value)
                except (TypeError, ValueError):
                    pass
    except (OSError, ValueError):
        pass


def save_settings() -> None:
    try:
        atomic_write(SETTINGS_FILE,
                     json.dumps(SETTINGS, ensure_ascii=False, indent=2) + "\n")
    except OSError as e:
        warn(f"не удалось сохранить settings.json: {e}")


ANDROID_MODELS = (
    "SM-S931B", "SM-S936B", "SM-S938U", "SM-S921B", "SM-S926U", "SM-A556B",
    "SM-A566B", "SM-A546E", "SM-F956B", "SM-F951U", "Pixel 8", "Pixel 8 Pro",
    "Pixel 9", "Pixel 9 Pro XL", "23127PN0CC", "24129PN0CG", "2412DPC0AG",
    "2312DRA50G", "23049PCD8G", "CPH2653", "CPH2581",
)
ANDROID_OS = ("13", "14", "14", "15", "15", "15", "16", "16", "16")
HAPP_VERSIONS = ("4.8.0", "4.8.0", "4.7.1", "4.7.1", "4.7.0", "4.6.0")


def generate_device() -> Dict[str, str]:
    """Случайное правдоподобное устройство Happ."""
    import random
    return {
        "hwid": f"{random.getrandbits(63) | (1 << 63):016x}",
        "model": random.choice(ANDROID_MODELS),
        "os": random.choice(ANDROID_OS),
        "app": random.choice(HAPP_VERSIONS),
        "ua_number": str(random.getrandbits(63) | (1 << 63)),
    }


def default_device() -> Dict[str, str]:
    d = generate_device()
    d["hwid"] = ""
    d["ua_number"] = ""
    return d


DEVICE: Dict[str, str] = default_device()


def happ_user_agent() -> str:
    app = DEVICE.get("app") or "4.8.0"
    number = DEVICE.get("ua_number", "")
    return f"Happ/{app}/Android/{number}" if number else f"Happ/{app}/Android"


def load_device() -> None:
    global DEVICE
    try:
        with open(DEVICE_FILE, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if isinstance(data, dict):
            DEVICE.update({k: str(data.get(k, "")) for k in
                           ("hwid", "model", "os", "app", "ua_number")})
    except (OSError, ValueError):
        pass


def save_device() -> None:
    try:
        atomic_write(DEVICE_FILE,
                     json.dumps(DEVICE, ensure_ascii=False, indent=2) + "\n")
    except OSError as e:
        warn(f"не удалось сохранить device.json: {e}")


def setup_device(interactive: bool) -> None:
    """Первый запуск: ввести свой HWID или сгенерировать."""
    load_device()
    if os.path.exists(DEVICE_FILE) and DEVICE.get("hwid"):
        return
    if not interactive:
        DEVICE.update(generate_device())
        save_device()
        say(f"[*] HWID сгенерирован автоматически: {DEVICE['hwid']}", important=True)
        return
    print("\n=== УСТРОЙСТВО ДЛЯ ЗАГРУЗКИ ПОДПИСОК ===", flush=True)
    print("Панели с лимитом устройств смотрят на X-HWID. Можно вписать свой")
    print("HWID (из Happ/INCY) или сгенерировать новый.", flush=True)
    while True:
        print("\n  1 — ввести свой HWID и данные устройства")
        print("  2 — сгенерировать устройство (рекомендуется)")
        ans = input("Выбор [1/2]: ").strip()
        if ans == "1":
            DEVICE["hwid"] = input("X-HWID: ").strip()
            if not DEVICE["hwid"]:
                print("HWID не может быть пустым.")
                continue
            DEVICE["model"] = input("Модель (X-Device-Model) [2412DPC0AG]: ").strip() or "2412DPC0AG"
            DEVICE["os"] = input("Версия ОС (X-Ver-OS) [16]: ").strip() or "16"
            DEVICE["app"] = input("Версия Happ [4.8.0]: ").strip() or "4.8.0"
            DEVICE["ua_number"] = input("Число в хвосте User-Agent (Enter — без него): ").strip()
            break
        if ans == "2":
            DEVICE.update(generate_device())
            print(f"Сгенерировано: HWID={DEVICE['hwid']}, модель={DEVICE['model']}, "
                  f"ОС={DEVICE['os']}, Happ={DEVICE['app']}")
            break
    save_device()
    print(f"Сохранено в {DEVICE_FILE}\n", flush=True)


# ============================================================================
# 2. ВСТРОЕННЫЕ КЛЮЧИ И РАСШИФРОВКА
# ============================================================================

class UnsupportedKey(Exception):
    """Ключ не расшифрован (нет ключей, битый payload, не тот формат)."""


INVISIBLE_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u200e\u200f\u202a-\u202e]")
CRYPT_RE = re.compile(
    r'(happ://(?:crypt5|crypt[1-4]|crypt)/[^\s<>"\'(){}|\\^`\[\]]+)', re.I)
INCY_RE = re.compile(
    r'(incy://crypt[0-9]+/[^\s<>"\'(){}|\\^`\[\]]+)', re.I)
V2T_RE = re.compile(
    r'(v2raytun://import/[^\s<>"\'(){}|\\^`\[\]]+)', re.I)
TRAILING_PUNCT = ".,;:!?)]}»«\"'"


def clean_text(s: str) -> str:
    return INVISIBLE_RE.sub("", s or "")


def b64_decode(s: str) -> bytes:
    s = clean_text(s)
    s = "".join(s.split()).replace("-", "+").replace("_", "/").rstrip("=")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def swap_pairs(b: bytes) -> bytes:
    t = bytearray(b)
    for i in range(0, len(t) - 1, 2):
        t[i], t[i + 1] = t[i + 1], t[i]
    return bytes(t)


def block_pair_swap(b: bytes) -> bytes:
    t = bytearray(b)
    n = len(t) - len(t) % 4
    for i in range(0, n, 4):
        t[i], t[i + 2] = t[i + 2], t[i]
        t[i + 1], t[i + 3] = t[i + 3], t[i + 1]
    return bytes(t)


def pem(kind: str, body: str) -> bytes:
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN {kind}-----\n{lines}\n-----END {kind}-----".encode()


def _embedded_json(name: str) -> Optional[Dict[str, Any]]:
    blob = EMBEDDED_KEYS.get(name)
    if not blob:
        return None
    try:
        return json.loads(zlib.decompress(base64.b64decode(blob)).decode("utf-8"))
    except Exception:
        return None


def _external_json(name: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(KEYS_DIR, name)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return None


@lru_cache(maxsize=None)
def _key_data() -> Dict[str, Dict[str, Any]]:
    """Встроенные ключи + (если есть) свежие ключи из keys/ рядом со скриптом."""
    result: Dict[str, Dict[str, Any]] = {}
    for name in ("happcrypt.json", "happcrypt5.json", "incy.json"):
        data = _embedded_json(name)
        if data is not None:
            result[name] = data
    if os.path.isdir(KEYS_DIR):
        for name in sorted(os.listdir(KEYS_DIR)):
            low = name.lower()
            if not low.endswith((".json", ".txt")) or low == "readme.txt":
                continue
            data = _external_json(name)
            if isinstance(data, dict):
                result[name] = data  # внешний файл перекрывает встроенный
    return result


def _require_crypto() -> None:
    if not CRYPTO_OK:
        raise UnsupportedKey(
            "не установлена cryptography: pip install cryptography "
            "(Termux: pkg install python && pip install cryptography)")


def _load_private(body: str):
    _require_crypto()
    last: Optional[Exception] = None
    for kind in ("RSA PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY"):
        try:
            return serialization.load_pem_private_key(pem(kind, body), password=None)
        except Exception as e:
            last = e
    raise UnsupportedKey(f"не удалось загрузить RSA-ключ: {last}")


@lru_cache(maxsize=None)
def _crypt_keys() -> List[Any]:
    data = _key_data().get("happcrypt.json") or {}
    keys = data.get("keys") if isinstance(data, dict) else None
    out = []
    if isinstance(keys, list):
        for item in keys:
            try:
                out.append(_load_private(str(item["key"])))
            except Exception:
                continue
    if not out:
        raise UnsupportedKey("нет ключей happ://crypt..crypt4")
    return out


@lru_cache(maxsize=None)
def _crypt5_keymap() -> Dict[str, str]:
    merged: Dict[str, str] = {}
    for name, data in _key_data().items():
        if not isinstance(data, dict) or "keys" in data:
            continue
        for k, v in data.items():
            if (isinstance(k, str) and isinstance(v, str)
                    and len(k) == 8 and v.startswith("MII")):
                merged.setdefault(k, v)
    if not merged:
        raise UnsupportedKey("нет ключей happ://crypt5")
    return merged


@lru_cache(maxsize=None)
def _crypt5_key(marker: str):
    body = _crypt5_keymap().get(marker)
    if not body:
        raise UnsupportedKey(f"нет crypt5-ключа для маркера {marker!r}")
    return _load_private(body)


def _printable_utf8(b: bytes) -> bool:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(ch.isprintable() or ch in "\r\n\t" for ch in s)


def rsa_decrypt_best(key, blob: bytes, validator=None) -> bytes:
    """OAEP-SHA256 → OAEP-SHA1 → PKCS1v15; проверяем результат валидатором."""
    pads = (
        asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None),
        asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA1()),
                          algorithm=hashes.SHA1(), label=None),
        asym_padding.PKCS1v15(),
    )
    fallback: Optional[bytes] = None
    for pad in pads:
        try:
            out = key.decrypt(blob, pad)
        except Exception:
            continue
        if validator is None:
            return out
        try:
            if validator(out):
                return out
        except Exception:
            pass
        if fallback is None:
            fallback = out
    if fallback is not None:
        return fallback
    raise UnsupportedKey("RSA-расшифровка не удалась")


def decrypt_crypt1to4(ordinal: int, payload: str) -> str:
    cipher = b64_decode(payload)
    keys = _crypt_keys()
    if not cipher or len(cipher) % 256 not in (0,) and all(
            k.key_size // 8 and len(cipher) % (k.key_size // 8) for k in keys):
        raise UnsupportedKey("длина payload не кратна размеру RSA-блока")
    order = (ordinal,) + tuple(i for i in range(len(keys)) if i != ordinal)
    first_err: Optional[Exception] = None
    for idx in order:
        if idx >= len(keys):
            continue
        key = keys[idx]
        size = key.key_size // 8
        if not cipher or len(cipher) % size:
            continue
        chunks = []
        try:
            for i in range(0, len(cipher), size):
                chunks.append(rsa_decrypt_best(key, cipher[i:i + size], _printable_utf8))
            text = b"".join(chunks).decode("utf-8")
            if text.strip():
                return text
        except Exception as e:
            if first_err is None:
                first_err = e
    raise first_err or UnsupportedKey("crypt: не расшифровано")


def _crypt5_body(body: bytes, key, salted: bool) -> str:
    if len(body) < 13:
        raise UnsupportedKey("crypt5: короткое тело")
    nonce = body[:12]
    salt: Optional[bytes] = None
    pos = 12
    if salted:
        if len(body) < 22:
            raise UnsupportedKey("crypt5: короткий salted-заголовок")
        salt = body[14:22]
        pos = 22
    start = pos
    while pos < len(body) and 48 <= body[pos] <= 57:
        pos += 1
    if pos == start or pos - start > 12:
        raise UnsupportedKey("crypt5: нет поля длины")
    seg_len = int(body[start:pos].decode("ascii"))
    packed = body[pos:]
    if not packed or seg_len > len(packed) - 1:
        raise UnsupportedKey("crypt5: сегмент обрезан")
    url_b64 = packed[1:seg_len + 1].decode("utf-8", "replace")
    enc_b64 = packed[seg_len + 1:].decode("utf-8", "replace")

    def valid_rsa(out: bytes) -> bool:
        try:
            return len(b64_decode(swap_pairs(out).decode("latin-1"))) == 32
        except Exception:
            return False

    rsa_plain = rsa_decrypt_best(key, b64_decode(enc_b64), valid_rsa)
    key_material = b64_decode(swap_pairs(rsa_plain).decode("latin-1"))
    if len(key_material) != 32:
        raise UnsupportedKey(f"crypt5: длина ключа {len(key_material)} != 32")
    if salt:
        km = bytearray(key_material)
        for i in range(32):
            km[i] ^= salt[i % len(salt)]
        key_material = bytes(km)
    ct = b64_decode(url_b64)
    text: Optional[bytes] = None
    for aead in (ChaCha20Poly1305(key_material), AESGCM(key_material)):
        try:
            text = aead.decrypt(nonce, ct, None)
            break
        except Exception:
            pass
    if text is None:
        raise UnsupportedKey("crypt5: AEAD-аутентификация не прошла")
    return b64_decode(swap_pairs(text).decode("latin-1")).decode("utf-8", "replace")


def _crypt5_once(payload: str) -> str:
    _require_crypto()
    n = block_pair_swap(payload.encode("utf-8"))
    if len(n) < 8:
        raise UnsupportedKey("crypt5: короткий payload")
    marker = (n[:4] + n[-4:]).decode("latin-1")
    body = n[4:-4]
    try:
        key = _crypt5_key(marker)
    except UnsupportedKey:
        key = None
        if len(_crypt5_keymap()) <= 64:       # перебор, когда маркер не найден
            for mk in _crypt5_keymap():
                try:
                    candidate = _crypt5_key(mk)
                    for s in (False, True):
                        try:
                            _crypt5_body(body, candidate, s)
                            key = candidate
                            break
                        except Exception:
                            pass
                    if key is not None:
                        break
                except Exception:
                    pass
        if key is None:
            raise UnsupportedKey(f"crypt5: нет ключа для маркера {marker!r}")
    salted_auto = len(body) > 12 and not (48 <= body[12] <= 57)
    last: Optional[Exception] = None
    for salted in dict.fromkeys((salted_auto, not salted_auto)):
        try:
            return _crypt5_body(body, key, salted)
        except Exception as e:
            last = e
    raise last or UnsupportedKey("crypt5: не расшифровано")


def decrypt_crypt5(link: str) -> str:
    payload = link.strip()
    for pref in ("happ://crypt5/", "crypt5/", "happ://"):
        if payload.lower().startswith(pref):
            payload = payload[len(pref):]
            break
    payload = payload.strip()
    base = payload.rstrip("=")
    candidates = list(dict.fromkeys(
        [base] + ([base[:-2]] if len(base) > 10 else []) + ([payload] if base != payload else [])
    ))
    last: Optional[Exception] = None
    for cand in candidates:
        try:
            return _crypt5_once(cand)
        except Exception as e:
            last = e
    raise last or UnsupportedKey("crypt5: не расшифровано")


def decrypt_happ(link: str) -> str:
    path = link[7:] if link.lower().startswith("happ://") else link
    low = path.lower()
    if low.startswith("crypt5/"):
        return decrypt_crypt5(path[7:])
    if low.startswith("crypt4/"):
        return decrypt_crypt1to4(3, path[7:])
    if low.startswith("crypt3/"):
        return decrypt_crypt1to4(2, path[7:])
    if low.startswith("crypt2/"):
        return decrypt_crypt1to4(1, path[7:])
    if low.startswith("crypt/"):
        return decrypt_crypt1to4(0, path[6:])
    raise UnsupportedKey("не похоже на happ://cryptN/<payload>")


@lru_cache(maxsize=None)
def _incy_schemes() -> Dict[str, Dict[str, Any]]:
    data = _key_data().get("incy.json") or {}
    schemes: Any = None
    if isinstance(data, dict):
        schemes = data.get("schemes")
        if schemes is None and ("key" in data or "keymat_a" in data):
            schemes = {str(data.get("scheme", "crypt1")): data}
    out: Dict[str, Dict[str, Any]] = {}
    if isinstance(schemes, dict):
        for k, v in schemes.items():
            if isinstance(k, str) and isinstance(v, dict) and k.strip():
                out[k.strip().lower()] = v
    if not out:
        raise UnsupportedKey("нет ключей incy://cryptN")
    return out


@lru_cache(maxsize=None)
def _incy_key(scheme: str) -> bytes:
    _require_crypto()
    cfg = _incy_schemes().get(scheme.lower())
    if cfg is None:
        raise UnsupportedKey(
            f"нет ключей incy://{scheme} (есть: {', '.join(sorted(_incy_schemes()))})")
    if isinstance(cfg.get("key"), str) and cfg["key"].strip():
        key = base64.b64decode("".join(cfg["key"].split()))
    else:
        a = base64.b64decode("".join(str(cfg.get("keymat_a", "")).split()))
        b = base64.b64decode("".join(str(cfg.get("keymat_b", "")).split()))
        off_a = int(cfg.get("keymat_a_offset", 1024))
        off_b = int(cfg.get("keymat_b_offset", 2048))
        klen = int(cfg.get("keymat_len", 32))
        if len(a) < off_a + klen or len(b) < off_b + klen:
            raise UnsupportedKey(f"incy://{scheme}: keymat короче смещений")
        sp = cfg.get("salt_parts")
        salt = (sp.encode("utf-8") if isinstance(sp, str)
                else "".join(str(p) for p in (sp or ())).encode("utf-8"))
        key = hashlib.sha256(salt + a[off_a:off_a + klen] + b[off_b:off_b + klen]).digest()
    if len(key) != 32:
        raise UnsupportedKey(f"incy://{scheme}: ключ {len(key)} байт вместо 32")
    expected = str(cfg.get("key_fingerprint", "")).strip().lower()
    if expected and hashlib.sha256(key).hexdigest() != expected:
        raise UnsupportedKey(f"incy://{scheme}: отпечаток ключа не совпал")
    return key


def decrypt_incy(link: str) -> Tuple[str, Optional[str]]:
    m = re.match(r"(?i)^incy://(crypt[0-9]+)/(.+)$", link.strip())
    if not m:
        raise UnsupportedKey("не похоже на incy://cryptN/<payload>")
    scheme, payload = m.group(1).lower(), m.group(2).rstrip("/")
    payload = re.sub(r"[^A-Za-z0-9_\-]", "", payload)
    if not payload:
        raise UnsupportedKey("incy: пустой payload")
    wire = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    if len(wire) < 12 + 16 + 1:
        raise UnsupportedKey("incy: payload слишком короткий")
    key = _incy_key(scheme)
    try:
        plain = AESGCM(key).decrypt(wire[:12], wire[12:], None)
    except Exception:
        raise UnsupportedKey(f"incy://{scheme}: AES-GCM не прошёл (не тот ключ или битая ссылка)")
    try:
        obj = json.loads(plain.decode("utf-8"))
    except Exception:
        raise UnsupportedKey("incy: внутри не JSON")
    url = obj.get("url") if isinstance(obj, dict) else None
    if not isinstance(url, str) or not url:
        raise UnsupportedKey("incy: внутри нет поля url")
    name = obj.get("n")
    return url, name if isinstance(name, str) and name else None


INNER_PREFIXES = (
    "http://", "https://", "happ://", "incy://", "v2raytun://",
    "vless://", "vmess://", "trojan://", "ss://", "shadowsocks://",
    "hysteria2://", "hysteria://", "hy2://", "tuic://", "socks5://", "socks4://",
)
URL_IN_TEXT_RE = re.compile(r"https?://[^\s<>\"']+")


def unwrap_v2raytun(link: str, depth: int = 0) -> str:
    if not link.lower().startswith("v2raytun://import/"):
        return link
    rest = link[len("v2raytun://import/"):].strip()
    if rest.lower().startswith(INNER_PREFIXES):
        return rest
    cand = urllib.parse.unquote(rest)
    if cand.lower().startswith(INNER_PREFIXES):
        return cand
    cand = re.sub(r"[^A-Za-z0-9+/=_\-]", "", cand)
    if len(cand) < 8:
        return link
    inner = ""
    pad = "=" * (-len(cand) % 4)
    for decoder in (lambda: base64.b64decode(cand.replace("-", "+").replace("_", "/") + pad),
                    lambda: base64.urlsafe_b64decode(cand + pad)):
        try:
            inner = decoder().decode("utf-8", "ignore").strip()
        except Exception:
            inner = ""
        if inner:
            break
    if inner.lower().startswith("v2raytun://import/") and depth < 8:
        return unwrap_v2raytun(inner, depth + 1)
    if inner.lower().startswith(INNER_PREFIXES):
        return inner
    return link


def find_key_links(text: str) -> List[str]:
    """Все ключи в тексте (обычном и URL-закодированном), без повторов."""
    if not text:
        return []
    out: List[str] = []
    seen: set = set()
    variants = [clean_text(text)]
    try:
        unq = clean_text(urllib.parse.unquote(text))
        if unq != variants[0]:
            variants.append(unq)
    except Exception:
        pass
    for t in variants:
        for rx in (CRYPT_RE, INCY_RE, V2T_RE):
            for link in rx.findall(t):
                link = link.rstrip(TRAILING_PUNCT)
                if link and link.lower() not in seen:
                    seen.add(link.lower())
                    out.append(link)
    return out


def unwrap_client_add(link: str) -> Optional[str]:
    """Любая клиентская обёртка → внутренняя http(s)-ссылка.

    happ://add/…, incy://import/…, streisand://import/…, hiddify://import/…,
    clash://install-config?url=…, v2box://install-sub?url=…, sub://<base64>.
    """
    s = clean_text(link).strip()
    if find_key_links(s) or s.lower().startswith(("http://", "https://")):
        return None
    for cand in (s, urllib.parse.unquote(s)):
        m = re.search(r"sub://([A-Za-z0-9_\-+/=]{8,})", cand, re.I)
        if m:
            try:
                inner = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)) \
                            .decode("utf-8", "replace")
                um = URL_IN_TEXT_RE.search(inner)
                if um:
                    return um.group(0).rstrip(TRAILING_PUNCT)
            except Exception:
                pass
        um = URL_IN_TEXT_RE.search(cand)
        if um:
            return um.group(0).rstrip(TRAILING_PUNCT)
    return None


_key_cache: Dict[str, Tuple[str, str]] = {}


def resolve_key(link: str, depth: int = 0) -> Tuple[str, str]:
    """('url', ссылка) | ('text', готовые конфиги)."""
    link = clean_text(link).strip().rstrip(TRAILING_PUNCT)
    if link in _key_cache:
        return _key_cache[link]
    if depth > int(SETTINGS["key_depth"]):
        raise UnsupportedKey("слишком глубокая вложенность ключей")
    low = link.lower()
    if low.startswith("v2raytun://import/"):
        inner = unwrap_v2raytun(link)
        if inner == link:
            raise UnsupportedKey("v2raytun: обёртка не развёрнута")
    elif low.startswith("incy://"):
        inner = decrypt_incy(link)[0]
    elif low.startswith("happ://"):
        inner = decrypt_happ(link)
    else:
        # голый payload без схемы: crypt5/…, crypt2/… и т.п.
        m = re.match(r"(?i)^(crypt5|crypt[1-4]|crypt)/(.+)$", link)
        if not m:
            raise UnsupportedKey("это не ключ happ/incy/v2raytun")
        inner = decrypt_happ("happ://" + link)

    inner = clean_text(inner).strip()
    nested = find_key_links(inner)
    if nested:
        result = resolve_key(nested[0], depth + 1)
    else:
        um = URL_IN_TEXT_RE.search(inner)
        if um:
            url = um.group(0).rstrip(TRAILING_PUNCT)
            wrapped = unwrap_client_add(url)
            result = ("url", wrapped or url)
        elif re.search(r"(?i)(?:vless|vmess|ss|trojan|hysteria2|hy2|tuic)://", inner):
            result = ("text", inner)
        else:
            raise UnsupportedKey("внутри ключа нет ссылки-подписки или конфигов")
    _key_cache[link] = result
    return result


# ============================================================================
# 3. ЗАГРУЗКА ПОДПИСОК (X-HWID, РЕДИРЕКТЫ, HTML-ПЕРЕХОДЫ)
# ============================================================================

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None                      # редиректы разбираем сами


def _build_opener():
    handlers: List[Any] = [_NoRedirect()]
    try:
        proxies = urllib.request.getproxies()
        override = os.getenv("SUBS_PROXY", "").strip()
        if override:
            proxies = {"http": override, "https": override}
        handlers.append(urllib.request.ProxyHandler(proxies))
    except Exception:
        pass
    if SETTINGS.get("verify_ssl", True):
        ctx = ssl.create_default_context()
    else:
        ctx = ssl._create_unverified_context()   # noqa: SLF001
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def device_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if DEVICE.get("hwid"):
        headers["X-HWID"] = DEVICE["hwid"]
        headers["X-Device-OS"] = "Android"
        for key, dev_key in (("X-Ver-OS", "os"),
                             ("X-Device-Model", "model"),
                             ("X-App-Version", "app")):
            if DEVICE.get(dev_key):
                headers[key] = DEVICE[dev_key]
    return headers


def add_hwid(url: str) -> str:
    if not DEVICE.get("hwid") or not SETTINGS.get("hwid_param", True):
        return url
    parts = urllib.parse.urlsplit(url)
    pairs = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
             if k.lower() != "hwid"]
    pairs.append(("hwid", DEVICE["hwid"]))
    return urllib.parse.urlunsplit((
        parts.scheme, parts.netloc, parts.path,
        urllib.parse.urlencode(pairs), parts.fragment))


def decode_body(raw: bytes, charset: Optional[str]) -> str:
    enc = (charset or "utf-8").lower()
    if "gzip" in enc:
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
        enc = "utf-8"
    elif "deflate" in enc:
        try:
            raw = zlib.decompress(raw)
        except Exception:
            pass
        enc = "utf-8"
    for candidate in (enc, "utf-8-sig", "utf-8", "cp1251", "latin-1"):
        try:
            return raw.decode(candidate)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


class FetchResult:
    def __init__(self, kind: str, text: str = "", url: str = "", error: str = ""):
        self.kind = kind                 # "text" | "key" | "error"
        self.text = text
        self.url = url
        self.error = error


def fetch_subscription(target: str, force_browser: bool = False) -> FetchResult:
    """Загрузить подписку. Возвращает текст, найденный ключ или причину ошибки."""
    variants = [add_hwid(target), target] if DEVICE.get("hwid") else [target]
    variants = list(dict.fromkeys(v for v in variants if v))
    last_error = "не удалось получить ответ от сервера"
    opener = _build_opener()
    uas = [ happ_user_agent() ]
    if not DEVICE.get("hwid") or force_browser:
        uas = [BROWSER_UA]
    elif SETTINGS.get("browser_fallback", True) and BROWSER_UA not in uas:
        uas.append(BROWSER_UA)
    limit = int(SETTINGS.get("max_response_mb", 32)) * 1024 * 1024

    for variant in variants:
        for ua in uas:
            current = variant
            hops = 0
            retried_429 = False
            conn_retry = 1
            while hops <= int(SETTINGS["max_redirects"]):
                headers = {
                    "User-Agent": ua,
                    "Accept": "*/*",
                    "Accept-Encoding": "identity",
                    "Connection": "keep-alive",
                }
                headers.update(device_headers())
                req = urllib.request.Request(current, headers=headers, method="GET")
                try:
                    with opener.open(req, timeout=int(SETTINGS["timeout"])) as resp:
                        raw = resp.read(limit + 1)
                        if len(raw) > limit:
                            return FetchResult("error", error="ответ слишком большой")
                        text = decode_body(raw, resp.headers.get_content_charset())
                        say(f"  [+] HTTP {resp.status}, {len(raw)} байт: {current}")
                        return FetchResult("text", text.strip(), resp.geturl() or current)
                except urllib.error.HTTPError as e:
                    if e.code in (301, 302, 303, 307, 308):
                        location = clean_text(e.headers.get("Location", "")).strip()
                        if not location:
                            last_error = f"редирект {e.code} без Location"
                            break
                        nxt = urllib.parse.urljoin(current, location)
                        scheme = urllib.parse.urlsplit(nxt).scheme.lower()
                        if scheme in ("http", "https"):
                            hops += 1
                            say(f"  [*] редирект {e.code} → {nxt[:120]}")
                            current = nxt
                            continue
                        keys = find_key_links(nxt)
                        if keys:
                            return FetchResult("key", keys[0], current)
                        unwrapped = unwrap_client_add(nxt)
                        if unwrapped:
                            hops += 1
                            current = unwrapped
                            continue
                        last_error = f"редирект на неподдерживаемую схему {scheme}://"
                        break
                    if e.code == 429:
                        if retried_429:
                            last_error = "HTTP 429 повторно"
                            break
                        retried_429 = True
                        try:
                            wait = min(max(int(float(e.headers.get("Retry-After", "5"))), 2), 20)
                        except ValueError:
                            wait = 5
                        say(f"  [*] HTTP 429 — жду {wait} сек")
                        time.sleep(wait)
                        continue
                    if e.code >= 400:
                        last_error = f"HTTP {e.code}"
                        if (e.code in (403, 418, 500, 503)
                                and SETTINGS.get("browser_fallback", True)
                                and BROWSER_UA not in uas):
                            say("  [*] пробую браузерный User-Agent")
                            uas.append(BROWSER_UA)
                        break
                except (urllib.error.URLError, TimeoutError, OSError) as e:
                    if conn_retry > 0:
                        conn_retry -= 1
                        say(f"  [*] обрыв связи ({e}), повторяю")
                        time.sleep(1)
                        continue
                    last_error = f"ошибка соединения: {e}"
                    break
            else:
                last_error = "слишком длинная цепочка редиректов"
            if last_error.startswith("HTTP 429") and ua == BROWSER_UA:
                break
    return FetchResult("error", error=last_error)


META_REFRESH_RE = re.compile(
    r'(?is)<meta[^>]+?http-equiv\s*=\s*["\']?refresh["\']?[^>]*?'
    r'content\s*=\s*["\']?[^"\'>]*?url\s*=\s*([^"\'>\s]+)')
JS_LOCATION_RE = re.compile(
    r'(?is)(?:window\.|document\.)?location(?:\.href)?\s*=\s*["\']([^"\']{4,500})["\']'
    r'|location\.replace\(\s*["\']([^"\']{4,500})["\']')
HREF_RE = re.compile(r'(?is)href\s*=\s*["\']([^"\']+)["\']')
HOP_BAD_RE = re.compile(
    r"(?i)\.(css|js|mjs|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|otf|mp4|mp3|zip|rar|7z|exe|apk)(\?|$|#)")
HOP_HINT_RE = re.compile(
    r"(?i)(/sub|/subscri|/api/repos/|/raw/|raw\.githubusercontent\.com|gitverse\.ru|"
    r"hub\.mos\.ru|\.txt(\?|$)|\.yaml|\.yml|token=|/s/[a-z0-9_-]{6,}|/keys/)")


def extract_html_hops(page: str, base_url: str) -> List[str]:
    """meta-refresh / JS-редирект / atob() / href-кандидаты из HTML-страницы."""
    hops: List[str] = []

    def add(u: str) -> None:
        u = clean_text(u).strip().strip("\"'")
        if not u:
            return
        if "%" in u:
            unq = urllib.parse.unquote(u)
            if unq.lower().startswith(("http://", "https://")):
                u = unq
        if find_key_links(u) or u.lower().startswith(("happ://", "incy://", "v2raytun://")):
            unwrapped = unwrap_client_add(u)
            if not unwrapped:
                if u.lower().startswith(("http://", "https://")):
                    pass
                else:
                    return
            else:
                u = unwrapped
        if not u.lower().startswith(("http://", "https://")):
            u = urllib.parse.urljoin(base_url, u)
        if not u.lower().startswith(("http://", "https://")):
            return
        u = u.split("#", 1)[0].rstrip(TRAILING_PUNCT)
        if u and u not in hops:
            hops.append(u)

    texts = [page]
    unq = urllib.parse.unquote(page)
    if unq != page:
        texts.append(unq)
    for t in texts:
        for rx in (META_REFRESH_RE, JS_LOCATION_RE):
            for m in rx.finditer(t):
                add(next((g for g in m.groups() if g), ""))
        for m in re.finditer(r"(?i)atob\(\s*['\"]([A-Za-z0-9+/=_-]{16,2000})['\"]", t):
            try:
                dec = b64_decode(m.group(1)).decode("utf-8", "replace")
                um = URL_IN_TEXT_RE.search(dec)
                if um:
                    add(um.group(0))
            except Exception:
                pass
        for m in HREF_RE.finditer(t):
            href = m.group(1)
            if href.startswith(("#", "javascript:", "mailto:", "tg://")):
                continue
            if HOP_BAD_RE.search(href) or not HOP_HINT_RE.search(href):
                continue
            add(href)
    return hops[:6]


# ============================================================================
# 4. ИЗВЛЕЧЕНИЕ КОНФИГОВ ИЗ ОТВЕТА
# ============================================================================

CONFIG_RE = re.compile(
    r"(?<![\w.\-+])((?:vless|vmess|trojan|shadowsocks|socks5|socks4|ss|"
    r"hysteria2|hy2|tuic)://[^\s<>\"']+)", re.I)
LINE_BULLET_RE = re.compile(r"^[\s\-*•·>\d.)\]\[]*")
SCHEME_BOUNDARY_RE = re.compile(
    r"(?<![\w.\-+])(?=(?:vless|vmess|trojan|shadowsocks|ss|socks5|socks4|"
    r"hysteria2|hysteria|hy2|tuic)://)", re.I)
ALIASES = {"shadowsocks": "ss", "hy2": "hysteria2", "hysteria": "hysteria2"}


def is_json(text: str) -> bool:
    s = text.strip()
    return (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]"))


B64ISH_RE = re.compile(r"^[A-Za-z0-9+/\-_]+={0,2}$")


def looks_b64(s: str) -> bool:
    """Похоже на base64 (в т.ч. urlsafe) — нужно для вложенных слоёв."""
    s = clean_text(s.strip())
    return len(s) >= 8 and bool(B64ISH_RE.match(s))


def try_decode_b64(data: str) -> Optional[str]:
    data = clean_text(data.strip())
    if not data or len(data) < 8:
        return None
    padded = data + "=" * (-len(data) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            text = decoder(padded).decode("utf-8").strip()
        except Exception:
            continue
        if not text or text == data:
            continue
        if (is_json(text) or CONFIG_RE.search(text) or "%3a%2f%2f" in text.lower()
                or re.search(r"(?i)^\s*proxies\s*:", text)
                or (looks_b64(text) and len(text) < len(data))):
            return text
    return None


def find_configs(content: str) -> List[str]:
    """Конфиги из текста; комментарий после # сохраняется целиком в начале строки."""
    found: List[str] = []
    for line in content.splitlines():
        matches = list(CONFIG_RE.finditer(line))
        if not matches:
            continue
        line_start = LINE_BULLET_RE.match(line).end() >= matches[0].start()
        for i, m in enumerate(matches):
            if i == 0 and line_start:
                end = matches[1].start() if len(matches) > 1 else len(line)
                link = line[m.start():end].strip()
            else:
                link = m.group(1)
            link = link.rstrip() if "#" in link else link.rstrip(TRAILING_PUNCT)
            if not link or link.lower().endswith("://"):
                continue
            # развязать склеенные «vmess://AAA,vless://BBB»
            bounds = [p for p in (m.start() for m in SCHEME_BOUNDARY_RE.finditer(link))
                      if p > 10]
            if bounds:
                chunks, prev = [], 0
                for pos in bounds + [len(link)]:
                    if pos > prev:
                        chunks.append(link[prev:pos])
                    prev = pos
                found.extend(chunk.rstrip(TRAILING_PUNCT) for chunk in chunks
                             if chunk.strip())
            else:
                found.append(link)
    return found


def json_to_links(content: str) -> List[str]:
    """Xray / V2Ray JSON → ссылки."""
    try:
        data = json.loads(content)
    except Exception:
        return []
    items = data if isinstance(data, list) else [data]
    links: List[str] = []
    for item in items:
        try:
            if not isinstance(item, dict):
                continue
            remarks = str(item.get("remarks", "Config"))
            for out in item.get("outbounds", []) or []:
                if not isinstance(out, dict):
                    continue
                proto = str(out.get("protocol", "")).lower()
                if proto in ("freedom", "blackhole", "dns"):
                    continue
                stream = out.get("streamSettings") or {}
                net = stream.get("network", "tcp")
                security = stream.get("security", "none")
                if proto == "vless":
                    settings = (out.get("settings") or {}).get("vnext") or [{}]
                    settings = settings[0] if isinstance(settings, list) else settings
                    user = (settings.get("users") or [{}])[0]
                    params: Dict[str, Any] = {"encryption": "none", "type": net,
                                              "security": security}
                    flow = user.get("flow")
                    if flow:
                        params["flow"] = flow
                        if security == "none":
                            params["security"] = "tls"
                    if security == "reality":
                        r = stream.get("realitySettings") or {}
                        params.update({
                            "sni": r.get("serverName"), "pbk": r.get("publicKey"),
                            "sid": r.get("shortId"),
                            "fp": r.get("fingerprint", "chrome")})
                    elif security in ("tls", "xtls"):
                        params["sni"] = (stream.get("tlsSettings") or {}).get("serverName")
                    if net == "grpc":
                        params["serviceName"] = (stream.get("grpcSettings") or {}).get("serviceName")
                    elif net == "ws":
                        ws = stream.get("wsSettings") or {}
                        params["path"] = ws.get("path")
                        params["host"] = (ws.get("headers") or {}).get("Host")
                    elif net == "xhttp":
                        xh = stream.get("xhttpSettings") or {}
                        params.update({"path": xh.get("path"), "host": xh.get("host"),
                                       "mode": xh.get("mode")})
                        if xh.get("extra"):
                            params["extra"] = json.dumps(xh["extra"], separators=(",", ":"),
                                                         ensure_ascii=False)
                    elif net == "tcp":
                        header = (stream.get("tcpSettings") or {}).get("header") or {}
                        if header.get("type") == "http":
                            req = header.get("request") or {}
                            hosts = req.get("headers", {}).get("Host", [])
                            paths = req.get("path", [])
                            if hosts:
                                params["host"] = hosts[0]
                            if paths:
                                params["path"] = paths[0]
                            params["headerType"] = "http"
                    params = {k: v for k, v in params.items() if v not in (None, "")}
                    links.append(
                        f"vless://{user.get('id')}@{settings.get('address')}:"
                        f"{settings.get('port')}?{urllib.parse.urlencode(params)}"
                        f"#{urllib.parse.quote(remarks)}")
                elif proto == "vmess":
                    settings = (out.get("settings") or {}).get("vnext") or [{}]
                    settings = settings[0] if isinstance(settings, list) else settings
                    user = (settings.get("users") or [{}])[0]
                    obj = {"v": "2", "ps": remarks, "add": settings.get("address"),
                           "port": str(settings.get("port", "")), "id": user.get("id"),
                           "aid": str(user.get("alterId", 0)),
                           "scy": user.get("security", "auto"),
                           "net": net, "tls": security, "type": "none"}
                    if net == "ws":
                        ws = stream.get("wsSettings") or {}
                        obj.update({"path": ws.get("path", "/"),
                                    "host": (ws.get("headers") or {}).get("Host", "")})
                    elif net == "xhttp":
                        xh = stream.get("xhttpSettings") or {}
                        obj.update({"path": xh.get("path", "/"), "host": xh.get("host", "")})
                    links.append("vmess://" + base64.b64encode(
                        json.dumps(obj).encode()).decode())
                elif proto in ("trojan", "shadowsocks", "hysteria2", "hy2", "tuic"):
                    settings = (out.get("settings") or {}).get("servers") or [{}]
                    srv = settings[0] if isinstance(settings, list) else settings
                    if proto == "trojan":
                        params = {k: v for k, v in
                                  {"security": security,
                                   "sni": (stream.get("tlsSettings") or {}).get("serverName")}
                                  .items() if v}
                        q = "?" + urllib.parse.urlencode(params) if params else ""
                        links.append(f"trojan://{srv.get('password')}@{srv.get('address')}:"
                                     f"{srv.get('port')}{q}#{urllib.parse.quote(remarks)}")
                    elif proto == "shadowsocks":
                        auth = base64.b64encode(
                            f"{srv.get('method', '')}:{srv.get('password', '')}".encode()).decode()
                        links.append(f"ss://{auth}@{srv.get('address')}:{srv.get('port')}"
                                     f"#{urllib.parse.quote(remarks)}")
                    else:
                        params: Dict[str, Any] = {}
                        sni = (stream.get("tlsSettings") or {}).get("serverName")
                        if sni:
                            params["sni"] = sni
                        obfs = srv.get("obfs") or {}
                        if isinstance(obfs, dict) and obfs.get("type"):
                            params["obfs"] = obfs["type"]
                            if obfs.get("password"):
                                params["obfs-password"] = obfs["password"]
                        if proto == "tuic":
                            cc = srv.get("congestion_control") or srv.get("congestion-control")
                            if cc:
                                params["congestion_control"] = cc
                            user = srv.get("id", "") or (out.get("settings") or {}).get("uuid", "")
                            auth = f"{user}:{srv.get('password', '')}"
                            scheme = "tuic"
                        else:
                            auth = str(srv.get("password", ""))
                            scheme = "hysteria2"
                        q = ("?" + urllib.parse.urlencode(params)) if params else ""
                        links.append(f"{scheme}://{auth}@{srv.get('address')}:"
                                     f"{srv.get('port')}{q}#{urllib.parse.quote(remarks)}")
        except Exception:
            continue
    return links


def singbox_to_links(content: str) -> List[str]:
    """sing-box JSON → ссылки."""
    try:
        data = json.loads(content)
    except Exception:
        return []
    if isinstance(data, dict) and isinstance(data.get("outbounds"), list):
        items = data["outbounds"]
    elif isinstance(data, list):
        items = data
    else:
        return []
    links: List[str] = []
    for ob in items:
        try:
            if not isinstance(ob, dict):
                continue
            typ = str(ob.get("type", "")).lower()
            server, port = ob.get("server"), ob.get("server_port")
            if not server or port in (None, ""):
                continue
            port = int(str(port))
            tag = str(ob.get("tag") or "singbox")
            tls = ob.get("tls") or {}
            reality = tls.get("reality") or {}
            transport = ob.get("transport") or {}
            ttype = str(transport.get("type", "")).lower()
            sni = tls.get("server_name") or ""
            if typ == "vless":
                uuid = ob.get("uuid")
                if not uuid:
                    continue
                params: Dict[str, Any] = {"encryption": "none", "type": ttype or "tcp"}
                if ob.get("flow"):
                    params["flow"] = ob["flow"]
                if tls.get("enabled"):
                    params["security"] = "reality" if reality else "tls"
                elif params["type"] == "tcp":
                    params["security"] = "none"
                if sni:
                    params["sni"] = sni
                if reality.get("public_key"):
                    params["pbk"] = reality["public_key"]
                if reality.get("short_id"):
                    params["sid"] = reality["short_id"]
                fp = (tls.get("utls") or {}).get("fingerprint")
                if fp:
                    params["fp"] = fp
                if ttype == "ws":
                    params["path"] = transport.get("path", "/")
                    host = (transport.get("headers") or {}).get("Host")
                    if isinstance(host, list):
                        host = host[0] if host else None
                    if host:
                        params["host"] = host
                elif ttype == "grpc":
                    if transport.get("service_name"):
                        params["serviceName"] = transport["service_name"]
                elif ttype == "http":
                    params["type"] = "http"
                    if transport.get("host"):
                        params["host"] = transport["host"]
                params = {k: v for k, v in params.items() if v not in (None, "")}
                links.append(f"vless://{uuid}@{server}:{port}?"
                             f"{urllib.parse.urlencode(params)}#{urllib.parse.quote(tag)}")
            elif typ == "vmess":
                uuid = ob.get("uuid")
                if not uuid:
                    continue
                obj = {"v": "2", "ps": tag, "add": server, "port": str(port), "id": uuid,
                       "aid": str(ob.get("alter_id", ob.get("alterId", 0))),
                       "scy": ob.get("security", "auto"), "net": ttype or "tcp",
                       "tls": "tls" if tls.get("enabled") else "", "type": "none"}
                if ttype == "ws":
                    obj["path"] = transport.get("path", "/")
                    host = (transport.get("headers") or {}).get("Host")
                    if isinstance(host, list):
                        host = host[0] if host else ""
                    obj["host"] = host or ""
                links.append("vmess://" + base64.b64encode(json.dumps(obj).encode()).decode())
            elif typ == "trojan":
                pw = ob.get("password")
                if not pw:
                    continue
                params = {"security": "tls", "sni": sni} if tls.get("enabled") and sni else {}
                q = "?" + urllib.parse.urlencode(params) if params else ""
                links.append(f"trojan://{pw}@{server}:{port}{q}#{urllib.parse.quote(tag)}")
            elif typ in ("shadowsocks", "ss"):
                if not ob.get("method") or ob.get("password") is None:
                    continue
                auth = base64.b64encode(f"{ob['method']}:{ob['password']}".encode()).decode()
                links.append(f"ss://{auth}@{server}:{port}#{urllib.parse.quote(tag)}")
            elif typ in ("hysteria2", "hy2"):
                pw = ob.get("password") or ob.get("auth") or ""
                params = {"sni": sni} if sni else {}
                obfs = transport if ttype == "salamander" else (ob.get("obfs") or {})
                if isinstance(obfs, dict) and obfs.get("type"):
                    params["obfs"] = obfs["type"]
                    if obfs.get("password"):
                        params["obfs-password"] = obfs["password"]
                q = "?" + urllib.parse.urlencode(params) if params else ""
                links.append(f"hysteria2://{pw}@{server}:{port}{q}#{urllib.parse.quote(tag)}")
            elif typ == "tuic":
                uuid = ob.get("uuid")
                if not uuid:
                    continue
                params = {"sni": sni} if sni else {}
                if ob.get("congestion_control"):
                    params["congestion_control"] = ob["congestion_control"]
                q = "?" + urllib.parse.urlencode(params) if params else ""
                links.append(f"tuic://{uuid}:{ob.get('password', '')}@{server}:{port}"
                             f"{q}#{urllib.parse.quote(tag)}")
        except Exception:
            continue
    return links


def clash_inline_opts(value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    body = value.strip()
    if body.startswith("{") and body.endswith("}"):
        body = body[1:-1].strip()
        for part in re.split(r",(?![^{}]*\})", body):
            if ":" in part:
                k, v = part.split(":", 1)
                out[k.strip().lower()] = v.strip().strip("'\"")
    return out


def clash_proxies_to_links(proxies: Any) -> List[str]:
    links: List[str] = []
    if not isinstance(proxies, list):
        return links
    for p in proxies:
        try:
            if not isinstance(p, dict):
                continue
            low = {str(k).strip().lower(): v for k, v in p.items() if isinstance(k, str)}
            typ = str(low.get("type", "")).lower()
            name = str(low.get("name") or "clash")
            server, port = low.get("server"), low.get("port")
            if not server or port in (None, ""):
                continue
            port = int(str(port))
            if typ == "vless":
                if not low.get("uuid"):
                    continue
                net = str(low.get("network") or "tcp")
                params: Dict[str, Any] = {"encryption": "none", "type": net}
                if low.get("flow"):
                    params["flow"] = low["flow"]
                reality = low.get("reality-opts")
                if isinstance(reality, dict) and reality:
                    params["security"] = "reality"
                    params["pbk"] = reality.get("public-key") or reality.get("public_key")
                    params["sid"] = reality.get("short-id") or reality.get("short_id")
                elif str(low.get("tls", "")).lower() in ("true", "1", "yes"):
                    params["security"] = "tls"
                sni = low.get("sni") or low.get("servername")
                if sni:
                    params["sni"] = sni
                if low.get("client-fingerprint"):
                    params["fp"] = low["client-fingerprint"]
                if net == "ws" and isinstance(low.get("ws-opts"), dict):
                    wo = low["ws-opts"]
                    params["path"] = wo.get("path", "/")
                    hdr = wo.get("headers")
                    if isinstance(hdr, dict) and hdr.get("Host"):
                        params["host"] = hdr["Host"]
                elif net == "grpc" and isinstance(low.get("grpc-opts"), dict):
                    params["serviceName"] = low["grpc-opts"].get("grpc-service-name")
                params = {k: v for k, v in params.items() if v not in (None, "")}
                links.append(f"vless://{low['uuid']}@{server}:{port}?"
                             f"{urllib.parse.urlencode(params)}#{urllib.parse.quote(name)}")
            elif typ == "vmess":
                if not low.get("uuid"):
                    continue
                net = str(low.get("network") or "tcp")
                obj = {"v": "2", "ps": name, "add": server, "port": str(port),
                       "id": low["uuid"],
                       "aid": str(low.get("alterid", low.get("alter-id", 0)) or 0),
                       "scy": low.get("cipher") or "auto", "net": net,
                       "tls": "tls" if str(low.get("tls", "")).lower() in ("true", "1", "yes")
                       else "", "type": "none"}
                if net == "ws" and isinstance(low.get("ws-opts"), dict):
                    wo = low["ws-opts"]
                    obj["path"] = wo.get("path", "/")
                    hdr = wo.get("headers")
                    if isinstance(hdr, dict) and hdr.get("Host"):
                        obj["host"] = hdr["Host"]
                links.append("vmess://" + base64.b64encode(json.dumps(obj).encode()).decode())
            elif typ == "trojan":
                if not low.get("password"):
                    continue
                sni = low.get("sni") or low.get("servername")
                params = {"security": "tls", "sni": sni} if sni else {}
                q = "?" + urllib.parse.urlencode(params) if params else ""
                links.append(f"trojan://{low['password']}@{server}:{port}{q}"
                             f"#{urllib.parse.quote(name)}")
            elif typ == "ss":
                method = low.get("cipher") or low.get("method")
                if not method or low.get("password") is None:
                    continue
                auth = base64.b64encode(f"{method}:{low['password']}".encode()).decode()
                links.append(f"ss://{auth}@{server}:{port}#{urllib.parse.quote(name)}")
            elif typ in ("hysteria2", "hy2"):
                pw = low.get("password") or low.get("auth") or ""
                params = {}
                sni = low.get("sni") or low.get("servername")
                if sni:
                    params["sni"] = sni
                if low.get("obfs"):
                    params["obfs"] = low["obfs"]
                    if low.get("obfs-password"):
                        params["obfs-password"] = low["obfs-password"]
                q = "?" + urllib.parse.urlencode(params) if params else ""
                links.append(f"hysteria2://{pw}@{server}:{port}{q}#{urllib.parse.quote(name)}")
            elif typ == "tuic":
                if not low.get("uuid"):
                    continue
                params = {}
                sni = low.get("sni") or low.get("servername")
                if sni:
                    params["sni"] = sni
                cc = low.get("congestion-controller") or low.get("congestion-control")
                if cc:
                    params["congestion_control"] = cc
                q = "?" + urllib.parse.urlencode(params) if params else ""
                links.append(f"tuic://{low['uuid']}:{low.get('password', '')}@{server}:{port}"
                             f"{q}#{urllib.parse.quote(name)}")
        except Exception:
            continue
    return links


def clash_to_links(content: str) -> List[str]:
    """Clash YAML → ссылки. Сначала PyYAML (если есть), потом свой разбор."""
    if SETTINGS.get("parse_yaml", True):
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(content)
            if isinstance(data, dict) and isinstance(data.get("proxies"), list):
                links = clash_proxies_to_links(data["proxies"])
                if links:
                    return links
        except ImportError:
            pass
        except Exception:
            pass
    # Свой минимальный разбор (без зависимостей).
    m = re.search(r"(?ms)^\s*proxies\s*:\s*$(.*?)(?=^\s{0,4}[\w-]+\s*:|\Z)", content)
    if not m:
        return []
    block = m.group(1)
    entries: List[Dict[str, Any]] = []
    for mm in re.finditer(r"-\s*\{(.*?)\}", block, re.S):
        text = mm.group(1)
        entry: Dict[str, Any] = {}
        for key in ("reality-opts", "ws-opts", "grpc-opts"):
            km = re.search(rf"(?i){key}\s*:\s*(\{{[^{{}}]*\}})", text)
            if km:
                entry[key] = clash_inline_opts(km.group(1))
                text = text.replace(km.group(0), "")
        for kv in re.finditer(r"([\w-]+)\s*:\s*([^,]+?)(?:,|$)", text):
            entry[kv.group(1).strip().lower()] = kv.group(2).strip().strip("'\"")
        if entry:
            entries.append(entry)
    if not entries:
        key_re = re.compile(r"^\s*-\s+([\w-]+)\s*:\s*(.*?)\s*$|^([\w-]+)\s*:\s*(.*?)\s*$")
        known = {"name", "type", "server", "port", "uuid", "password", "cipher", "method",
                 "sni", "servername", "network", "tls", "flow", "client-fingerprint",
                 "alterid", "alter-id", "obfs", "obfs-password", "congestion-controller",
                 "congestion-control", "auth"}
        current: Dict[str, str] = {}
        for line in block.splitlines():
            km = key_re.match(line)
            if not km:
                continue
            k = (km.group(1) or km.group(3) or "").lower()
            v = (km.group(2) if km.group(2) is not None else km.group(4) or "").strip().strip("'\"")
            if km.group(1) and current:
                entries.append(current)
                current = {}
            if k in known:
                current[k] = v
        if current:
            entries.append(current)
    return clash_proxies_to_links(entries)


def json_links_any(content: str) -> List[str]:
    links: List[str] = []
    if SETTINGS.get("parse_json", True):
        links = json_to_links(content)
        if not links:
            links = singbox_to_links(content)
        if not links:
            try:
                obj = json.loads(content)
                if isinstance(obj, dict) and isinstance(obj.get("proxies"), list):
                    links = clash_proxies_to_links(obj["proxies"])
            except Exception:
                pass
    return links


def finalize(links: List[str]) -> List[str]:
    """Нормализация, дедуп, фильтр протоколов."""
    out: List[str] = []
    seen: set = set()
    only = [p.strip().lower() for p in str(SETTINGS.get("only_protocols", "")).split(",")
            if p.strip()]
    for link in links:
        link = link.strip()
        if not link or link.lower().endswith("://"):
            continue
        m = re.match(r"^([A-Za-z][\w+.-]*://)", link)
        if not m:
            continue
        scheme = m.group(1)[:-3].lower()
        if SETTINGS.get("normalize_schemes", True) and scheme in ALIASES:
            link = ALIASES[scheme] + "://" + link[m.end():]
            scheme = ALIASES[scheme]
        if only and scheme not in only:
            continue
        key = link.split("#", 1)[0] if SETTINGS.get("strip_config_names", True) else link
        if SETTINGS.get("dedupe", True):
            if key in seen:
                continue
            seen.add(key)
        if SETTINGS.get("strip_config_names", True):
            link = key
        out.append(link)
    return out


def extract_from_content(raw: str) -> List[str]:
    """Все методы извлечения: HTML → JSON → Base64*N → URL-decode → YAML → текст."""
    content = clean_text(raw or "").strip()
    if not content:
        return []
    if "<html" in content.lower() and SETTINGS.get("parse_html", True):
        content = html_mod.unescape(re.sub(r"(?is)<script.*?</script>|<style.*?</style>|<[^>]+>",
                                           " ", content)).strip()
    # комментарии перед JSON (gitverse и т.п.)
    if content.startswith("#"):
        stripped = re.sub(r"(?m)^#.*$", "", content).strip()
        if stripped:
            content = stripped
    if is_json(content):
        links = json_links_any(content)
        if links:
            return finalize(links)

    for _ in range(max(1, int(SETTINGS.get("base64_levels", 5)))):
        configs = find_configs(content)
        if configs:
            return finalize(configs)
        unquoted = urllib.parse.unquote(content)
        if unquoted != content:
            configs = find_configs(unquoted)
            if configs:
                return finalize(configs)
            content = unquoted
        decoded = try_decode_b64(content)
        if decoded and decoded != content:
            content = decoded
            if is_json(content):
                links = json_links_any(content)
                if links:
                    return finalize(links)
            continue
        break
    if re.search(r"(?mi)^\s*proxies\s*:", content):
        links = clash_to_links(content)
        if links:
            return finalize(links)
    return finalize(find_configs(content))


# ============================================================================
# 5. КОНВЕЙЕР ОБРАБОТКИ ЦЕЛИ
# ============================================================================

def safe_filename(label: str) -> str:
    try:
        host = urllib.parse.urlsplit(label).netloc or label
    except Exception:
        host = label
    host = host.split("@")[-1].split(":")[0].lower()
    if host.startswith("www."):
        host = host[4:]
    name = re.sub(r"[^a-z0-9._-]+", "_", host).strip("._-")[:80]
    if not name:
        name = "configs_" + hashlib.md5(label.encode()).hexdigest()[:8]
    return name + ".txt"


def process_target(target: str, depth: int = 0, visited: Optional[set] = None,
                   stats: Optional[Dict[str, int]] = None) -> Tuple[List[str], str, str]:
    """Возвращает (конфиги, источник, ошибка). Разворачивает ключи и редиректы."""
    if visited is None:
        visited = set()
    if stats is None:
        stats = {"keys": 0, "hops": 0}
    target = clean_text(target).strip().strip("\"'").rstrip(TRAILING_PUNCT)
    if not target:
        return [], "", "пустая цель"
    if depth > int(SETTINGS["max_redirects"]):
        return [], target, "слишком глубокая вложенность ссылок"

    # 1) ключ клиента
    keys = find_key_links(target)
    if keys:
        try:
            kind, value = resolve_key(keys[0])
            stats["keys"] += 1
            say(f"  [ключ] {keys[0][:60]}… → {kind}")
            say(f"  [*] расшифровано: {value[:160]}")
            if kind == "text":
                return finalize(extract_from_content(value)), keys[0], ""
            return process_target(value, depth + 1, visited, stats)
        except Exception as e:
            return [], target, f"ключ: {e}"

    # 2) клиентская обёртка вокруг http-ссылки
    unwrapped = unwrap_client_add(target)
    if unwrapped and unwrapped.rstrip("/") != target.rstrip("/"):
        say(f"  [обёртка] → {unwrapped[:140]}")
        return process_target(unwrapped, depth + 1, visited, stats)

    # 3) текст с готовыми конфигами
    if not target.lower().startswith(("http://", "https://")):
        configs = extract_from_content(target)
        if configs:
            # имя файла берём из домена первого конфига, а не из слова "text"
            return configs, configs[0].split("#", 1)[0], ""
        return [], target, "это не http(s)-ссылка, ключ или конфиг"

    url = target.split("#", 1)[0]
    if url in visited:
        return [], url, "цикл редиректов"
    visited.add(url)

    # 4) загрузка
    res = fetch_subscription(url)
    if res.kind == "key":
        return process_target(res.text, depth + 1, visited, stats)
    if res.kind == "error":
        return [], url, res.error

    configs = extract_from_content(res.text)
    source = res.url or url
    if not configs and "<html" in res.text.lower() and SETTINGS.get("parse_html", True):
        say("  [*] страница-редиректор: ищу переходы в HTML")
        for hop in extract_html_hops(res.text, res.url or url):
            if hop in visited:
                continue
            stats["hops"] += 1
            got, src, err = process_target(hop, depth + 1, visited, stats)
            if got:
                return got, src, ""
            if err:
                say(f"  [-] переход не сработал: {err}")
    if not configs and DEVICE.get("hwid") and SETTINGS.get("browser_fallback", True):
        say("  [*] конфигов нет — повторяю с браузерным UA")
        retry = fetch_subscription(url, force_browser=True)
        if retry.kind == "text":
            configs = extract_from_content(retry.text)
            source = retry.url or url
        elif retry.kind == "key":
            return process_target(retry.text, depth + 1, visited, stats)
    return configs, source, "" if configs else "конфиги не найдены"


def save_configs(configs: List[str], source: str) -> Tuple[str, int, int]:
    """Записать конфиги в <домен>.txt рядом со скриптом; вернуть (путь, новых, всего)."""
    filename = safe_filename(source or "configs")
    path = os.path.join(BASE_DIR, filename)
    old: List[str] = []
    if os.path.isfile(path) and not SETTINGS.get("overwrite_files", False):
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
                old = [line.strip() for line in f if line.strip()]
        except OSError:
            old = []

    def dedup_key(line: str) -> str:
        return line.split("#", 1)[0] if SETTINGS.get("strip_config_names", True) else line

    seen = {dedup_key(line) for line in old}
    added = [c for c in configs if dedup_key(c) not in seen and not seen.add(dedup_key(c))]
    result = (added if SETTINGS.get("overwrite_files", False) else old + added)
    atomic_write(path, "\n".join(result) + ("\n" if result else ""))
    return path, len(added), len(result)


def process_one(target: str, stats: Optional[Dict[str, int]] = None) -> bool:
    print(f"\n>>> {target[:180]}", flush=True)
    configs, source, err = process_target(target, stats=stats)
    if err:
        warn(f"{err}")
        return False
    path, added, total = save_configs(configs, source)
    print(f"[+] Конфигов: {len(configs)}; добавлено: {added}; всего в файле: {total}")
    print(f"[+] Файл: {path}", flush=True)
    return added > 0 or len(configs) > 0


def run_batch(path: str) -> None:
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            lines = [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError as e:
        warn(f"не удалось прочитать {path}: {e}")
        return
    print(f"Пакетный режим: {len(lines)} целей из {path}", flush=True)
    ok = fail = 0
    for line in lines:
        if process_one(line):
            ok += 1
        else:
            fail += 1
    print(f"\nИтого: успешно {ok}, неудачно {fail}", flush=True)


# ============================================================================
# 6. МЕНЮ
# ============================================================================

def show_device() -> None:
    print("\n--- УСТРОЙСТВО ---")
    for k, title in (("hwid", "X-HWID"), ("model", "Модель"),
                     ("os", "Версия ОС"), ("app", "Версия Happ"),
                     ("ua_number", "Число в User-Agent")):
        print(f"  {title:20} {DEVICE.get(k) or '—'}")
    print(f"  User-Agent: {happ_user_agent()}")
    print(f"  Файл: {DEVICE_FILE}")


def device_menu() -> None:
    while True:
        show_device()
        print("\n  1 — ввести свой HWID")
        print("  2 — сгенерировать новое устройство")
        print("  3 — изменить модель / ОС / версию Happ")
        print("  4 — убрать HWID (загрузка без X-HWID)")
        print("  0 — назад")
        ans = input("Выбор: ").strip()
        if ans == "1":
            hwid = input("X-HWID: ").strip()
            if hwid:
                DEVICE["hwid"] = hwid
                if not DEVICE.get("ua_number"):
                    DEVICE["ua_number"] = str(uuid.uuid4().int % (10 ** 19))
                save_device()
        elif ans == "2":
            DEVICE.update(generate_device())
            save_device()
            print("Сгенерировано и сохранено.")
        elif ans == "3":
            DEVICE["model"] = input(f"Модель [{DEVICE.get('model')}]: ").strip() or DEVICE["model"]
            DEVICE["os"] = input(f"ОС [{DEVICE.get('os')}]: ").strip() or DEVICE["os"]
            DEVICE["app"] = input(f"Happ [{DEVICE.get('app')}]: ").strip() or DEVICE["app"]
            DEVICE["ua_number"] = input(f"UA-число [{DEVICE.get('ua_number')}]: ").strip() or DEVICE["ua_number"]
            save_device()
        elif ans == "4":
            DEVICE["hwid"] = ""
            DEVICE["ua_number"] = ""
            save_device()
            print("HWID удалён.")
        elif ans == "0":
            return


def settings_menu() -> None:
    keys = list(DEFAULT_SETTINGS)
    while True:
        print("\n--- НАСТРОЙКИ ---")
        for i, k in enumerate(keys, 1):
            print(f"  {i:2}. {k:24} = {SETTINGS[k]}")
        print("  0 — назад")
        ans = input("Номер параметра: ").strip()
        if ans == "0":
            save_settings()
            return
        try:
            k = keys[int(ans) - 1]
        except (ValueError, IndexError):
            continue
        default = DEFAULT_SETTINGS[k]
        val = input(f"Новое значение для {k} [{default}] (Enter — оставить): ").strip()
        if not val:
            continue
        try:
            if isinstance(default, bool):
                SETTINGS[k] = val.lower() in ("1", "true", "yes", "on", "да", "д", "вкл")
            elif isinstance(default, int):
                SETTINGS[k] = int(val)
            else:
                SETTINGS[k] = val
        except ValueError:
            warn("некорректное значение")
        save_settings()


def show_info() -> None:
    print("\n--- ИНФОРМАЦИЯ ---")
    print(f"  Версия:          {VERSION}")
    print(f"  Папка скрипта:   {BASE_DIR}")
    print(f"  cryptography:    {'есть' if CRYPTO_OK else 'НЕТ (pip install cryptography)'}")
    try:
        import yaml  # noqa: F401
        print("  PyYAML:          есть (опционально)")
    except ImportError:
        print("  PyYAML:          нет (встроенный разбор Clash YAML)")
    print(f"  Ключей crypt1-4: {len(_crypt_keys()) if CRYPTO_OK else '—'}")
    print(f"  Ключей crypt5:   {len(_crypt5_keymap()) if CRYPTO_OK else '—'}")
    print(f"  Схем INCY:       {len(_incy_schemes()) if CRYPTO_OK else '—'}")
    print(f"  Конфиг:          {SETTINGS_FILE}")
    print(f"  Устройство:      {DEVICE_FILE}")
    print("  Результаты:      <домен>.txt рядом со скриптом")


def main_menu() -> None:
    print("\n=== UNIVERSAL VPN PARSER ===", flush=True)
    while True:
        print("\n  1 — обработать ссылку / ключ")
        print("  2 — пакетный режим (файл со списком)")
        print("  3 — вставить несколько ссылок/ключей")
        print("  4 — устройство / X-HWID")
        print("  5 — настройки")
        print("  6 — информация")
        print("  0 — выход")
        ans = input("\nВыбор: ").strip()
        if ans == "1":
            target = input("Ссылка или ключ: ").strip()
            if target:
                process_one(target)
        elif ans == "2":
            path = input("Путь к файлу со списком: ").strip().strip("\"'")
            if path:
                run_batch(path)
        elif ans == "3":
            print("Вставляйте ссылки/ключи по одной; пустая строка — готово.")
            targets = []
            while True:
                line = input("> ").strip()
                if not line:
                    break
                targets.append(line)
            for target in targets:
                process_one(target)
        elif ans == "4":
            device_menu()
        elif ans == "5":
            settings_menu()
        elif ans == "6":
            show_info()
        elif ans == "0":
            print("До встречи.")
            return


def main() -> None:
    global SETTINGS
    load_settings()
    parser = argparse.ArgumentParser(
        description="Расшифровка happ/incy/v2raytun → подписка → конфиги (Windows/Linux/Termux)")
    parser.add_argument("target", nargs="?", help="ссылка-подписка или ключ клиента")
    parser.add_argument("-b", "--batch", help="файл со списком ссылок/ключей (по строке)")
    parser.add_argument("--no-menu", action="store_true", help="не показывать меню после обработки")
    args = parser.parse_args()

    interactive = bool(sys.stdin.isatty() and not args.target and not args.batch
                       and not args.no_menu)
    setup_device(interactive=interactive)
    if not CRYPTO_OK:
        warn("cryptography не установлена — crypt/incy недоступны; v2raytun и извлечение работают")

    if args.batch:
        run_batch(args.batch)
        return
    if args.target:
        process_one(args.target)
        if args.no_menu:
            return
    if sys.stdin.isatty():
        main_menu()


if __name__ == "__main__":
    main()
