"""
Proxy tracing helpers.

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from __future__ import annotations

from urllib.parse import urlparse

from flask import request

from app.models.app_config import AppConfig


def bg_trace_enabled() -> bool:
    """
    Enable verbose tracing when the client requests it.
    - via ?__bg_trace=1
    - or via cookie __bg_trace=1
    """
    try:
        if request.args.get("__bg_trace") == "1":
            return True
        if request.cookies.get("__bg_trace") == "1":
            return True
    except Exception:
        pass
    return False


def infer_expected_prefixed_url_for_unknown_slug(app_slug: str, path: str) -> str | None:
    """
    When we receive a request like /quizmaster/login (app_slug='quizmaster', path='login')
    but no such app exists, try to infer that the user was *inside* some app (via Referer),
    and the missing prefix should have been: /<ref_app>/<app_slug>/<path>
    """
    try:
        ref = request.referrer
        if not ref:
            return None
        parsed = urlparse(ref)
        ref_path = parsed.path or ""
        segments = [s for s in ref_path.split("/") if s]
        if not segments:
            return None
        ref_app = segments[0]
        if not AppConfig.get_by_slug(ref_app):
            return None
        if path:
            return f"/{ref_app}/{app_slug}/{path}"
        return f"/{ref_app}/{app_slug}"
    except Exception:
        return None

