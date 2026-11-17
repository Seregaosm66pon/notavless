"""
Contributor tracking system for Nota Vless.
Keeps track of who added each source and custom proxy node.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from config import REPO_ROOT

CONTRIBUTIONS_FILE = REPO_ROOT / "contributions.json"
logger = logging.getLogger(__name__)

ADDED_BY_RE = re.compile(r"#\s*(?:added_by|by|author)?\s*:?\s*(@?[a-zA-Z0-9_\-]+)", re.IGNORECASE)


def get_default_contributions() -> dict[str, Any]:
    return {
        "version": 1,
        "updated_at": datetime.now().isoformat(),
        "contributors": {},
        "sources": [],
        "custom_nodes": [],
    }


def load_contributions() -> dict[str, Any]:
    if not CONTRIBUTIONS_FILE.exists():
        data = get_default_contributions()
        save_contributions(data)
        return data
    try:
        data = json.loads(CONTRIBUTIONS_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return get_default_contributions()
        data.setdefault("contributors", {})
        data.setdefault("sources", [])
        data.setdefault("custom_nodes", [])
        return data
    except Exception as exc:
        logger.warning("Failed to load %s: %s", CONTRIBUTIONS_FILE, exc)
        return get_default_contributions()


def save_contributions(data: dict[str, Any]) -> None:
    try:
        data["updated_at"] = datetime.now().isoformat()
        CONTRIBUTIONS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to save %s: %s", CONTRIBUTIONS_FILE, exc)


def _normalize_username(username: str) -> str:
    cleaned = (username or "").strip()
    if not cleaned:
        return "@community"
    if not cleaned.startswith("@") and not cleaned.startswith("http"):
        cleaned = f"@{cleaned}"
    return cleaned


def record_source(url: str, added_by: str = "", note: str = "") -> bool:
    url = url.strip()
    if not url or url.startswith("#"):
        return False

    author = _normalize_username(added_by)
    data = load_contributions()

    # Check if already present
    for item in data["sources"]:
        if item.get("url") == url:
            if added_by and item.get("added_by") != author:
                item["added_by"] = author
                save_contributions(data)
            return False

    entry = {
        "url": url,
        "added_by": author,
        "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "note": note.strip(),
    }
    data["sources"].append(entry)

    contribs = data["contributors"]
    contribs[author] = contribs.get(author, 0) + 1

    save_contributions(data)
    return True


def record_custom_node(raw_url: str, added_by: str = "", note: str = "") -> bool:
    raw_url = raw_url.strip()
    if not raw_url:
        return False

    author = _normalize_username(added_by)
    data = load_contributions()

    for item in data["custom_nodes"]:
        if item.get("raw_url") == raw_url:
            return False

    entry = {
        "raw_url": raw_url,
        "added_by": author,
        "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "note": note.strip(),
    }
    data["custom_nodes"].append(entry)

    contribs = data["contributors"]
    contribs[author] = contribs.get(author, 0) + 1

    save_contributions(data)
    return True


def get_custom_nodes() -> list[dict[str, str]]:
    data = load_contributions()
    return data.get("custom_nodes", [])


def read_sources_with_contributors(file_path: Path) -> list[tuple[str, str]]:
    """
    Parse sources file and extract URLs along with contributor attribution.
    Format example:
      https://raw.github.../list.txt # added_by: @serega
    """
    if not file_path.exists():
        return []

    results: list[tuple[str, str]] = []
    lines = file_path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue

        added_by = "@admin"
        if "#" in cleaned:
            parts = cleaned.split("#", 1)
            url_part = parts[0].strip()
            comment_part = parts[1].strip()
            match = ADDED_BY_RE.search("# " + comment_part)
            if match:
                added_by = _normalize_username(match.group(1))
            cleaned = url_part

        if cleaned:
            record_source(cleaned, added_by=added_by)
            results.append((cleaned, added_by))

    return results


def get_contributor_stats() -> dict[str, int]:
    data = load_contributions()
    stats: dict[str, int] = {}
    for src in data.get("sources", []):
        author = src.get("added_by", "@community")
        stats[author] = stats.get(author, 0) + 1
    for node in data.get("custom_nodes", []):
        author = node.get("added_by", "@community")
        stats[author] = stats.get(author, 0) + 1
    return stats


def get_contributors_summary(limit: int = 5) -> str:
    stats = get_contributor_stats()
    if not stats:
        return "@seregaosm66pon, @community"
    sorted_items = sorted(stats.items(), key=lambda x: x[1], reverse=True)[:limit]
    return ", ".join(f"{author} ({cnt})" for author, cnt in sorted_items)
