"""
Text/content loader for templates.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from flask import current_app


def _get_nested(d: dict[str, Any], dotted_key: str) -> Any:
    cur: Any = d
    for part in dotted_key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


@lru_cache(maxsize=8)
def _load_content(lang: str) -> dict[str, Any]:
    # Keep content files inside the app package for easy packaging/deploy.
    path = Path(current_app.root_path) / "content" / f"{lang}.json"
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def t(key: str, default: str | None = None, lang: str = "en", **kwargs) -> str:
    """
    Translate/lookup a text key from app/content/<lang>.json.

    - key: dotted key (e.g. "welcome.header_title")
    - kwargs: formatting placeholders (Python .format)
    """
    try:
        data = _load_content(lang)
        value = _get_nested(data, key)
        if value is None:
            return default if default is not None else key
        if not isinstance(value, str):
            return default if default is not None else key
        try:
            return value.format(**kwargs) if kwargs else value
        except Exception:
            # If formatting fails, return raw string rather than erroring the page.
            return value
    except Exception:
        return default if default is not None else key

